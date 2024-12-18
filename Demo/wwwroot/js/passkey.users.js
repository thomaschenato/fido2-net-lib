document.getElementById('btnGetUsers').addEventListener('click', handleLoadUsers);

async function handleLoadUsers(event) {
    let registeredUsers;
    try {
        var res = await fetch('/users', {
            method: 'GET', // or 'PUT'
            headers: {
                'Accept': 'application/json'
            }
        });

        registeredUsers = await res.json();
    } catch (e) {
        showErrorAlert("Request to server failed", e);
    }

    console.log("Registered users:", registeredUsers);

    // show error to user
    if (registeredUsers.status === "error") {
        console.log("Error loading users");
        console.log(registeredUsers.errorMessage);
        showErrorAlert(registeredUsers.errorMessage);
        return;
    }

    // remove all current rows
    let usersResult = document.querySelector('#tblUsers');
    const tableHeaderRowCount = 1;
    const rowCount = usersResult.rows.length;
    for (let i = tableHeaderRowCount; i < rowCount; i++) {
        usersResult.deleteRow(tableHeaderRowCount);
    }
    
    registeredUsers.result.forEach(addUserRow);
}

function addUserRow(user) {
    let usersResult = document.querySelector('#tblUsers');
    let row = usersResult.insertRow(-1);
    row.id = user.id;
    
    // Create table cells
    let userIdCell = row.insertCell(0);
    let userNameCell = row.insertCell(1);
    let displayNameCell = row.insertCell(2);
    let counterCell = row.insertCell(3);
    let actionCell = row.insertCell(4);

    // Add data to cells
    userIdCell.innerText = user.id;
    userNameCell.innerText = user.name;
    displayNameCell.innerText = user.displayName;
    counterCell.innerText = user.credentialCount;
    actionCell.innerHTML = "<div class='field'><div class='control'><button class='button is-link' onclick=viewUser('" + user.name + "')>View</button></div></div>";
}

async function viewUser(userName)
{
    window.location.href = "/dashboard/" + userName;
}