using System.Collections;
using System.Formats.Cbor;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using NuGet.Protocol;

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
                                            [FromForm] string userVerification)
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
            var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

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
                CredProps = true
            };

            var options = _fido2.RequestNewCredential(user, rpId, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);

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

            var publicKey = GetCborDecodedObject(credential.PublicKey);
            
            var attestationClientDataJson = GetClientDataJson(credential.AttestationClientDataJson);

            var attestationObjectValues = GetCborDecodedObject(credential.AttestationObject);
            var decodedAttestationObject = GetDecodedAttestationObject(attestationObjectValues.Single(x=>x.Key.Equals("authData")).Value);
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
    public ActionResult AssertionOptionsPost([FromForm] string username, [FromForm] string rpId, [FromForm] string userVerification)
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
                UserVerificationMethod = true
            };

            // 3. Create options
            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            var options = _fido2.GetAssertionOptions(
                existingCredentials,
                uv,
                rpId,
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

            var authenticatorData = GetCborItemValue(CborObject.Decode(clientResponse.Response.AuthenticatorData));
            var clientDataJson = GetClientDataJson(clientResponse.Response.ClientDataJson);
            var userHandle = clientResponse.Response.UserHandle;
            
            var response = new
            {
                userName,
                authenticatorData,
                clientDataJson,
                userHandle,
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
    
    private object GetDecodedAttestationObject(object authData)
    {
        var span = (authData as byte[]).AsSpan();
        
        var rpIdHash = span.Slice(0, 32); 
        span = span.Slice(32);
        
        var flags = new BitArray(span.Slice(0, 1).ToArray()); 
        span = span.Slice(1);

        var counterBuf = span.Slice(0, 4); 
        span = span.Slice(4);
        
        var counter = BitConverter.ToUInt32(counterBuf);
        
        // cred data - AAGUID (16 bytes)
        var aaguid = span.Slice(0, 16); 
        span = span.Slice(16);
        
        // cred data - L (2 bytes, big-endian uint16)
        var credIdLenBuf = span.Slice(0, 2); 
        span = span.Slice(2);
        credIdLenBuf.Reverse();
        var credentialIdLength = BitConverter.ToUInt16(credIdLenBuf);

        // cred data - Credential ID (L bytes)
        var credentialId = span.Slice(0, credentialIdLength);
        span = span.Slice(credentialIdLength);

        var coseStruct = CborObject.Decode(span.ToArray());
        var keyValues = GetCborValues(((CborMap)coseStruct).ToList());
        var key = new CredPublicKey(keyValues);        
        
        return new
        {
            rpIdHash = rpIdHash.ToArray(),
            flags = new
            {
                userPresent = flags[0],
                userVerified = flags[2],
                attestedCredentialData = flags[6],
                extensionDataIncluded = flags[7],
            },
            counter,
            credentialId = credentialId.ToArray(),
            aaguid = Guid.Parse(BitConverter.ToString(aaguid.ToArray()).Replace("-", string.Empty)),
            key
        };
    }

    private object GetClientDataJson(byte[] credentialAttestationClientDataJson)
    {
        try
        {
            return Encoding.Default.GetString(credentialAttestationClientDataJson).FromJson<ClientDataJson>();
        }
        catch (Exception e)
        {
            return $"Could not decode {e.Message}";
        }
    }

    private List<KeyValuePair<string, object>> GetCborDecodedObject(byte[] data)
    {
        List<KeyValuePair<string, object>> decodedItems = new List<KeyValuePair<string, object>>();
        
        try
        {
            var items = ((CborMap)CborObject.Decode(data)).ToList();
            decodedItems = GetCborValues(items);
        }
        catch (Exception e)
        {
            decodedItems.Add(new("Exception", $"Could not decode: {e.Message}"));
        }
        
        return decodedItems;
    }

    private List<KeyValuePair<string, object>> GetCborValues(List<KeyValuePair<CborObject, CborObject>> items)
    {
        List<KeyValuePair<string, object>> decodedItems = new List<KeyValuePair<string, object>>();

        foreach (var item in items)
        {
            string itemKey = null;
            object itemValue = GetCborItemValue(item.Value);

            if (item.Key as CborTextString != null)
                itemKey = ((CborTextString)item.Key).Value;
            else if (item.Key as CborInteger != null)
                itemKey = ((CborInteger)item.Key).Value.ToString();

            decodedItems.Add(new(itemKey, itemValue));
        }

        return decodedItems;
    }

    private object GetCborItemValue(CborObject itemValue)
    {
        if (itemValue as CborInteger != null)
            return ((CborInteger)itemValue).Value;
        
        if (itemValue as CborTextString != null)
            return ((CborTextString)itemValue).Value;
        
        if (itemValue as CborByteString != null)
            return ((CborByteString)itemValue).Value;

        return itemValue;
    }

    private string GetBase64DecodedString(byte[] data)
    {
        try
        {
            return Encoding.Default.GetString(data);
        }
        catch (Exception e)
        {
            return $"Could not decode {e.Message}";
        }
    }
}

public class ClientDataJson
{
    public string Type { get; set; }

    public string Challenge { get; set; }

    public string Origin { get; set; }

    public string CrossOrigin { get; set; }
}

public class CredPublicKey
{ 
    public CredPublicKey(List<KeyValuePair<string, object>> publicKeyValues) // Use of Reflection here
    {
        foreach (var prop in typeof(CredPublicKey).GetProperties())
        {
            var propName = (prop.GetCustomAttributes(typeof(JsonPropertyAttribute)).First() as JsonPropertyAttribute)?.PropertyName;

            var value = publicKeyValues.FirstOrDefault(x => x.Key.Equals(propName)).Value;
            
            prop.SetValue(this, value, null);
        }
    }
    
    [JsonProperty("1")]
    public object KeyType { get; set; }

    [JsonProperty("3")]
    public object Algorithm { get; set; }

    [JsonProperty("-1")]
    public object Curve { get; set; }

    [JsonProperty("-2")]
    public object X { get; set; }

    [JsonProperty("-3")]
    public object Y { get; set; }
}

public class AttestationObject
{ 
    public AttestationObject(List<KeyValuePair<string, object>> attestationObjectValues) // Use of Reflection here
    {
        foreach (var prop in typeof(AttestationObject).GetProperties())
        {
            var propName = (prop.GetCustomAttributes(typeof(JsonPropertyAttribute)).First() as JsonPropertyAttribute)?.PropertyName;

            var value = attestationObjectValues.FirstOrDefault(x => x.Key.Equals(propName)).Value;
            
            prop.SetValue(this, value, null);
        }
    }
    
    //Format
    [JsonProperty("fmt")]
    public object Fmt { get; set; }

    //AttestationObject
    [JsonProperty("attStmt")]
    public object AttStmt { get; set; }

    [JsonProperty("authData")]
    public object AuthData { get; set; }

    [JsonProperty("decodedAuthData")]
    public object DecodedAuthData { get; set; }
}
