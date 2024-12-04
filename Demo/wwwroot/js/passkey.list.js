document.getElementById('btnGetCredentials').addEventListener('click', handleLoadCredentials);

async function handleLoadCredentials(event) {
    let registeredPasskeys;
    try {
        var res = await fetch('/passkeys', {
            method: 'GET', // or 'PUT'
            headers: {
                'Accept': 'application/json'
            }
        });

        registeredPasskeys = await res.json();
    } catch (e) {
        showErrorAlert("Request to server failed", e);
    }

    console.log("Registered passkeys:", registeredPasskeys);

    // show error to user
    if (registeredPasskeys.status === "error") {
        console.log("Error loading passkeys");
        console.log(registeredPasskeys.errorMessage);
        showErrorAlert(registeredPasskeys.errorMessage);
        return;
    }

    // remove all current rows
    let credentialsResult = document.querySelector('#tblCredentials');
    const tableHeaderRowCount = 1;
    const rowCount = credentialsResult.rows.length;
    for (let i = tableHeaderRowCount; i < rowCount; i++) {
        credentialsResult.deleteRow(tableHeaderRowCount);
    }
    
    registeredPasskeys.result.forEach(addPasskeyRow);
}

function addPasskeyRow(credential) {
    let credentialsResult = document.querySelector('#tblCredentials');
    let row = credentialsResult.insertRow(-1);
    row.id = credential.credentialId;
    
    // Create table cells
    let regDateCell = row.insertCell(0);
    let userIdCell = row.insertCell(1);
    let userHandleCell = row.insertCell(2);
    let counterCell = row.insertCell(3);
    let aaGuidCell = row.insertCell(4);
    let attestationFormatCell = row.insertCell(5);
    let pkCell = row.insertCell(6);
    let actionCell = row.insertCell(7);

    let publicKey = coerceToBase64Url(credential.publicKey);
    let userId = atob(credential.userId);
    
    // Add data to cells
    regDateCell.innerText = credential.regDate;
    userIdCell.innerText = userId;
    userHandleCell.innerText = atob(credential.userHandle);
    counterCell.innerText = credential.signCount;
    aaGuidCell.innerText = credential.aaGuid;
    attestationFormatCell.innerText = credential.attestationFormat;
    pkCell.innerHTML = "<details><summary>" + publicKey.substring(0, 10).substring(0, 10) + "...</summary>" + publicKey + "</details>";
    actionCell.innerHTML = "<div class='field'><div class='control'><button class='button is-link' onclick=deleteCredential('" + credential.credentialId + "')>Delete</button></div></div>";
}

async function deleteCredential(credentialId)
{
    let deleteResponse;
    try {
        var res = await fetch('/passkeys/' + credentialId, {
            method: 'DELETE',
            headers: {
                'Accept': 'application/json'
            }
        });

        deleteResponse = await res.json();
    } catch (e) {
        showErrorAlert("Request to server failed", e);
    }

    // show error to user
    if (deleteResponse.status === "error") {
        console.log("Error deleting credential: " + credentialId);
        console.log(deleteResponse.errorMessage);
        showErrorAlert(deleteResponse.errorMessage);
        return;
    }

    // remove deleted row
    document.getElementById(credentialId).remove();
    
    Swal.fire({
        title: 'Passkey successfully deleted!',
        text: 'Passkey has been successfully deleted.',
        type: 'success',
        timer: 2000
    });
}