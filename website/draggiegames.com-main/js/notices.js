/* 

this file is used if we want to make changes without having to go and add them to every page manually
this is fetched in the head of every page

last modified;      23/01/2024 @ 20:21

*/

console.log("There are no notices to display.");

function clearItemFromLocalStorage() {
    console.log("Clearing local storage...");
    var hasBeenCleared = false;
    var hasBeenCleared2 = false;

    if (localStorage.getItem("dgames_sessiontoken")) {
        localStorage.removeItem("dgames_sessiontoken");
        console.log("Cleared session token from local storage.");
        hasBeenCleared = true;
    } else {
        console.log("Session token not found in local storage.");
    }

    if (localStorage.getItem("dgames_sessiontoken_expirey_expected")) {
        localStorage.removeItem("dgames_sessiontoken_expirey_expected");
        console.log("Cleared session token expirey from local storage.");
        hasBeenCleared2 = true;
    } else {
        console.log("Session token expirey not found in local storage.");
    }

    // Use XOR operator 

    if (hasBeenCleared ^ hasBeenCleared2) { // boolean XOR operator - love a level computer science and logic gates
        console.log("Only one of the two items was cleared for some reason.");
        alert("Logged out successfully, but it was weird as only one of the two items was cleared.");
    } else if (hasBeenCleared && hasBeenCleared2) { // else if 1 AND 2 are true
        console.log("Cleared both items from local storage.");
        alert("Logged out successfully.");

        window.location.reload(); // just makes it easier so if the user clicks on the account and it still says signed in, it might look odd for them
    } else { // case for any other clicke
        console.log("no items found in local sotorage to clear");
        alert("It doesn't look like you were signed in, so I couldn't clear your saved credentials");
    }



}

function clearAllLocalStorage() {
    localStorage.clear();
}


/*
// Try and add a logout button to the accounts dropdown menu

var dropdownMenu = document.querySelector('navbarDropdown');

var newListItem = document.createElement('li');
var newAnchor = document.createElement('a');

newAnchor.className = 'dropdown-item';
newAnchor.href = '#'; 
newAnchor.textContent = 'Log out';
newAnchor.id = 'navbarDropdownLogout';

newAnchor.addEventListener('click', function() {
    clearItemFromLocalStorage();
    alert("Logged out successfully.");
});

newListItem.appendChild(newAnchor);
dropdownMenu.appendChild(newListItem);

console.log("Added logout button to the accounts dropdown menu.");
*/