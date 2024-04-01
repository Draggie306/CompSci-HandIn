// Last Modified: 26/06/2023 @ 19:22

// https://alpha.draggiegames.com

x = fetch("https://client.draggie.games/ping");
console.log(`Server ping result: ${x}`);

function getSessionToken() {
    const localStorageSessionToken = localStorage.getItem("dgames_sessiontoken");

    if (localStorageSessionToken) {
        console.log("Session token value:", localStorageSessionToken);
        return localStorageSessionToken;
    } else {
        // if session does not exist, redirect to login page
        console.log("Session token not found");
        window.location.href = "/login";
        return null;
    }
}

if (!getSessionToken()) {
    // This will redirect to login if the session token has value null
    window.location.href = "/login";
}

