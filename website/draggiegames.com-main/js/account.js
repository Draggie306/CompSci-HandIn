// Last Modified: 02/10/2023 @ 19:49

const token_login_url = "https://client.draggie.games/token_login";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake."); // Necessary for Replit to wake the server up before sending request. See writeup for more info.

async function login() {
    console.log("Checking if session token exists...");
    if (localStorage.getItem("dgames_sessiontoken")) { // The session token exists in the localStorage
        console.log("Session token found, attempting to login...");
        const token = localStorage.getItem("dgames_sessiontoken");
        const response = await fetch(token_login_url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ token })
        });

        const jsonResponse = await response.json();
        console.log(jsonResponse);

        var customJsonString = "";
        var account_good_bool = jsonResponse.account;

        // JSON string to return with {account: true, username: "username", account: "email"} if logged in
        if (account_good_bool) {
            console.log("Logged in.");
            customJsonString = JSON.stringify({ account: true, username: jsonResponse.username, email: jsonResponse.email });
        } else {
            console.log(`Error: ${jsonResponse.error}`);
            customJsonString = JSON.stringify({ account: false, error: jsonResponse.error });
        }

        if (customJsonString) { // yay!
            console.log("Returning success message.");
            return customJsonString;
        } else if (jsonResponse.error) { // server-generated error
            console.log(`Error: ${jsonResponse.error}`);
            return customJsonString;
        } else { // Not sure why this would happen
            console.log("Unknown error occured.");
            return customJsonString;
        }
    } else { // The session token does not exist in localStorage. False means that the invoking function should handle it - enable login button.
        console.log("Session token not found.");
        return false;
    }
}


window.addEventListener("load", async function () {
    console.log("Page loaded Attempting to login...");
    var isLoggedIn = await login();

    // parse JSON string to JSON object
    var isLoggedInObj = JSON.parse(isLoggedIn);
    var isLoggedInBool = isLoggedInObj.account;

    var accountDropdown_login = document.getElementById("navbarDropdownLogin");

    if (isLoggedInBool) {
        console.log("Updating bootstrap dropdown to show account management.");
        accountDropdown_login.innerHTML = `Manage your account: ${isLoggedInObj.username}`;
        // change href to /profile
        accountDropdown_login.href = "profile";
    } else {
        console.log("Not logged in, updating boottstrap to reflect this.");
        accountDropdown_login.innerHTML = "You're not logged in! Click to login";
    }
});