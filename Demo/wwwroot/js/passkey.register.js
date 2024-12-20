﻿document.getElementById('register').addEventListener('submit', handleRegisterSubmit);

async function handleRegisterSubmit(event) {
    event.preventDefault();

    let username = this.username.value;
    let displayName = this.displayName.value;
    let rpId = this.rpId.value;

    // possible values: none, direct, indirect
    let attestation_type = value("#option-attestation");
    // possible values: <empty>, platform, cross-platform
    let authenticator_attachment = value("#option-authenticator");

    // possible values: preferred, required, discouraged
    let user_verification = value("#option-userverification");

    // possible values: true,false
    let residentKey = value("#option-residentkey");


    // prepare form post data
    var data = new FormData();
    data.append('username', username);
    data.append('displayName', displayName);
    data.append('rpId', rpId);
    data.append('attType', attestation_type);
    data.append('authType', authenticator_attachment);
    data.append('userVerification', user_verification);
    data.append('residentKey', residentKey);

    // send to server for registering
    let makeCredentialOptions;
    
    try {
        makeCredentialOptions = await fetchMakeCredentialOptions(data);

    } catch (e) {
        console.error(e);
        let msg = "Something went really wrong";
        showErrorAlert(msg);
    }


    console.log("Credential Options Object", makeCredentialOptions);

    if (makeCredentialOptions.status === "error") {
        console.log("Error creating credential options");
        console.log(makeCredentialOptions.errorMessage);
        showErrorAlert(makeCredentialOptions.errorMessage);
        return;
    }

    // Turn the challenge back into the accepted format of padded base64
    makeCredentialOptions.challenge = coerceToArrayBuffer(makeCredentialOptions.challenge);
    // Turn ID into a UInt8Array Buffer for some reason
    makeCredentialOptions.user.id = coerceToArrayBuffer(makeCredentialOptions.user.id);

    makeCredentialOptions.excludeCredentials = makeCredentialOptions.excludeCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });

    if (makeCredentialOptions.authenticatorSelection.authenticatorAttachment === null) makeCredentialOptions.authenticatorSelection.authenticatorAttachment = undefined;

    console.log("Credential Options Formatted", makeCredentialOptions);

    let decodedOptionsString  = `{
        "decodedChallenge": "CHALLENGE",
        "decodedId": "ID"
        }`;

    decodedOptionsString = decodedOptionsString
        .replace("CHALLENGE", btoa(makeCredentialOptions.challenge))
        .replace("ID", btoa(makeCredentialOptions.id));
    
    let decodedOptions = JSON.parse(decodedOptionsString);

    const mergedObject = {
        ...decodedOptions,
        ...makeCredentialOptions
    };
    
    let makeCredentialOptionsResult = document.querySelector('#makeCredentialOptionsResult');
    makeCredentialOptionsResult.innerHTML = JSON.stringify(mergedObject, null, "\t");

    Swal.fire({
        title: 'Registering...',
        text: 'Tap your security key to finish registration.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });

    console.log("Creating PublicKeyCredential...");

    let newCredential;
    try {
        newCredential = await navigator.credentials.create({
            publicKey: makeCredentialOptions
        });
    } catch (e) {
        var msg = "Could not create credentials in browser."
        console.error(msg, e);
        showErrorAlert(msg, e);
    }

    console.log("PublicKeyCredential Created", newCredential);

    let authenticatorResult = document.querySelector('#authenticatorResult');
    authenticatorResult.innerHTML = JSON.stringify(newCredential, null, "\t");

    console.log("PublicKeyCredential Created", newCredential);

    try {
        registerNewCredential(newCredential, username);
    } catch (err) {
        showErrorAlert(err.message ? err.message : err);
    }

    return;
}

async function fetchMakeCredentialOptions(formData) {
    let response = await fetch('/makeCredentialOptions', {
        method: 'POST', // or 'PUT'
        body: formData, // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}


// This should be used to verify the auth data with the server
async function registerNewCredential(newCredential, username) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);

    const data = {
        id: newCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: newCredential.type,
        extensions: newCredential.getClientExtensionResults(),
        response: {
            AttestationObject: coerceToBase64Url(attestationObject),
            clientDataJSON: coerceToBase64Url(clientDataJSON),
            transports: newCredential.response.getTransports()
        },
    };

    let response;
    try {
        response = await registerCredentialWithServer(data);
    } catch (e) {
        showErrorAlert(e);
    }

    console.log("Credential Object", response);

    var publicKey = {};
    response.decodedCredential.publicKey.forEach(function(e){
        publicKey[e.key] = e.value
    })
    
    response.decodedCredential.publicKey = publicKey;
    
    let registrationResult = document.querySelector('#registrationResult');
    registrationResult.innerHTML = JSON.stringify(response, null, "\t");

    // show error
    if (response.status === "error") {
        console.log("Error creating credential");
        console.log(response.errorMessage);
        showErrorAlert(response.errorMessage);
        return;
    }

    // show success 
    Swal.fire({
        title: 'Registration Successful!',
        text: username + ' you\'ve registered successfully.',
        type: 'success',
        timer: 2000
    });

    console.log("Create credential response: " + response);

    // redirect to dashboard?
    //window.location.href = "/dashboard/" + state.user.displayName;
}

async function registerCredentialWithServer(formData) {
    let response = await fetch('/makeCredential', {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(formData), // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}
