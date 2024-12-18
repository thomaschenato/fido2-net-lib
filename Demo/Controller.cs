using System.Text;
using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;

namespace Fido2Demo;

[Route("api/[controller]")]
public class MyController : Controller
{
    private IFido2 _fido2;
    public static IMetadataService _mds;
    public static readonly DevelopmentInMemoryStore DemoStorage = new();

    public MyController(IFido2 fido2)
    {
        _fido2 = fido2;
    }

    private string FormatException(Exception e)
    {
        return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
    }

    [HttpPost]
    [Route("/makeCredentialOptions")]
    public JsonResult MakeCredentialOptions([FromForm] string username,
                                            [FromForm] string displayName,
                                            [FromForm] string rpId,
                                            [FromForm] string attType,
                                            [FromForm] string authType,
                                            [FromForm] string residentKey,
                                            [FromForm] string userVerification,
                                            [FromForm] bool applyExclusions = true,
                                            [FromForm] string userAgentHints = null)
    {
        try
        {
            if (string.IsNullOrEmpty(username))
            {
                username = $"{displayName} (Usernameless user created at {DateTime.UtcNow})";
            }

            // 1. Get user from DB by username (in our example, auto create missing users)
            var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            // 2. Get user existing keys by username
            List<PublicKeyCredentialDescriptor> existingKeys;

            if (applyExclusions)
                existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            else
                existingKeys = new List<PublicKeyCredentialDescriptor>();

            List<PublicKeyCredentialHint> credentialHints;

            if (string.IsNullOrWhiteSpace(userAgentHints))
                credentialHints = new List<PublicKeyCredentialHint>();    
            else
                credentialHints = userAgentHints.Split(',').Select(x => x.ToEnum<PublicKeyCredentialHint>()).ToList();
            
            // 3. Create options
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = residentKey.ToEnum<ResidentKeyRequirement>(),
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                CredProps = true,
            };

            var options = _fido2.RequestNewCredential(user, rpId, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), credentialHints, exts);

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            // 5. return options to client
            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeCredential")]
    public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. get the options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            // 2. Create callback so that lib can verify credential id is unique to this user
            IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
            {
                var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                if (users.Count > 0)
                    return false;

                return true;
            };

            // 2. Verify and make the credentials
            var credential = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = callback
            }, cancellationToken: cancellationToken);

            // 3. Store the credentials in db
            DemoStorage.AddCredentialToUser(options.User, new StoredCredential
            {
                CredentialId = Guid.NewGuid(),
                Id = credential.Id,
                PublicKey = credential.PublicKey,
                UserHandle = credential.User.Id,
                SignCount = credential.SignCount,
                AttestationFormat = credential.AttestationFormat,
                RegDate = DateTimeOffset.UtcNow,
                AaGuid = credential.AaGuid,
                Transports = credential.Transports,
                IsBackupEligible = credential.IsBackupEligible,
                IsBackedUp = credential.IsBackedUp,
                AttestationObject = credential.AttestationObject,
                AttestationClientDataJson = credential.AttestationClientDataJson
            });

            var publicKey = Decoder.GetCborDecodedObject(credential.PublicKey);
            
            var attestationClientDataJson = Decoder.GetClientDataJson(credential.AttestationClientDataJson);

            var attestationObjectValues = Decoder.GetCborDecodedObject(credential.AttestationObject);
            var decodedAttestationObject = Decoder.GetDecodedAttestationObject(attestationObjectValues.Single(x=>x.Key.Equals("authData")).Value);
            attestationObjectValues.Add(new("decodedAuthData", decodedAttestationObject));
            var attestationObject = new AttestationObject(attestationObjectValues);
            
            var response = new
            {
                decodedCredential = new
                {
                    attestationObject,
                    publicKey,
                    attestationClientDataJson
                },
                credential,
            };
            
            // 4. return "ok" to the client
            return Json(response);
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/assertionOptions")]
    public ActionResult AssertionOptionsPost(
        [FromForm] string username, 
        [FromForm] string rpId, 
        [FromForm] string userVerification, 
        [FromForm] string userAgentHints = null)
    {
        try
        {
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();

            if (!string.IsNullOrEmpty(username))
            {
                // 1. Get user from DB
                var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                // 2. Get registered credentials from database
                existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
            };
            
            // 3. Create options
            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            
            List<PublicKeyCredentialHint> credentialHints;

            if (string.IsNullOrWhiteSpace(userAgentHints))
                credentialHints = new List<PublicKeyCredentialHint>();    
            else
                credentialHints = userAgentHints.Split(',').Select(x => x.ToEnum<PublicKeyCredentialHint>()).ToList();

            var options = _fido2.GetAssertionOptions(
                existingCredentials,
                uv,
                rpId,
                credentialHints,
                exts
            );

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            // 5. Return options to client
            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeAssertion")]
    public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Get the assertion options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
            var options = AssertionOptions.FromJson(jsonOptions);

            // 2. Get registered credential from database
            var creds = DemoStorage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials");

            // 3. Get credential counter from database
            var storedCounter = creds.SignCount;

            // 4. Create callback to check if the user handle owns the credentialId
            IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
            {
                var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
            };

            // 5. Make the assertion
            var res = await _fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = clientResponse,
                OriginalOptions = options,
                StoredPublicKey = creds.PublicKey,
                StoredSignatureCounter = storedCounter,
                IsUserHandleOwnerOfCredentialIdCallback = callback
            }, cancellationToken: cancellationToken);

            // 6. Store the updated counter
            DemoStorage.UpdateCounter(res.CredentialId, res.SignCount);

            var users = await DemoStorage.GetUsersByCredentialIdAsync(res.CredentialId, new CancellationToken());
            var userName = users.First().Name;
            
            var authenticatorData = Decoder.GetDecodedAuthenticatorData(clientResponse.Response.AuthenticatorData);
            
            var clientDataJson = Decoder.GetClientDataJson(clientResponse.Response.ClientDataJson);
            var userHandle = ASCIIEncoding.ASCII.GetString(clientResponse.Response.UserHandle);
            
            var response = new
            {
                request = new {
                    userName,
                    clientResponse.Response.AuthenticatorData,
                    decodedAuthData = authenticatorData,
                    clientResponse.Response.Signature,
                    clientDataJson,
                    userHandle,
                    clientResponse.ClientExtensionResults
                },
                response = res,
            };
            
            // 7. return OK to client
            return Json(response);
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpGet]
    [Route("/users")]
    public Task<JsonResult> GetUsers()
    {
        try
        {
            var users = DemoStorage.GetAllUsers();
            return Task.FromResult(Json(users));
        }
        catch (Exception e)
        {
            return Task.FromResult(Json(new { Status = "error", ErrorMessage = FormatException(e) }));
        }
    }
    
    [HttpGet]
    [Route("/passkeys")]
    public Task<JsonResult> GetPasskeys()
    {
        try
        {
            var passkeys = DemoStorage.GetAllCredentials();
            return Task.FromResult(Json(passkeys));
        }
        catch (Exception e)
        {
            return Task.FromResult(Json(new { Status = "error", ErrorMessage = FormatException(e) }));
        }
    }

    [HttpDelete]
    [Route("/passkeys/{id}")]
    public Task<JsonResult> DeletePasskey([FromRoute] Guid id)
    {
        try
        {
            DemoStorage.DeleteCredentialById(id);
            return Task.FromResult(Json(new{}));
        }
        catch (Exception e)
        {
            return Task.FromResult(Json(new { Status = "error", ErrorMessage = FormatException(e) }));
        }
    }
}
