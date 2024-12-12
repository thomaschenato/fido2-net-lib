﻿using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public interface IFido2
{
    AssertionOptions GetAssertionOptions(
        IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials,
        UserVerificationRequirement? userVerification,
        string rpId,
        IReadOnlyList<PublicKeyCredentialHint> credentialHint,
        AuthenticationExtensionsClientInputs? extensions = null);

    Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams makeAssertionParams,
        CancellationToken cancellationToken = default);

    Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams makeNewCredentialParams,
        CancellationToken cancellationToken = default);

    CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        string rpId,
        IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials,
        IReadOnlyList<PublicKeyCredentialHint> hints,
        AuthenticationExtensionsClientInputs? extensions = null);

    CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        string rpId,
        IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials,
        AuthenticatorSelection authenticatorSelection,
        AttestationConveyancePreference attestationPreference,
        IReadOnlyList<PublicKeyCredentialHint> hints,
        AuthenticationExtensionsClientInputs? extensions = null);
}
