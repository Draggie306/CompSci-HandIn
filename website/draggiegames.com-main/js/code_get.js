// Last Modified: 26/06/2023 @ 19:16

// NOTE 15/02/2024: This code is NOT USED in the website, but might be useful.

// TODO: Decide if there is enough time to implement this and associated entitlements feature from the server side
// it is implemented on the server for the auto updater and game downloader/client but not on the website, only redeeming a code is

const key_url = "https://client.draggie.games/api/v1/saturnian/game/gameData/licenses/validation/";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake.");

const handleSubmit = async (event) => {
    const localStorageSessionToken = localStorage.getItem("dgames_sessiontoken");

    if (localStorageSessionToken) {
        console.log("Session token value:", localStorageSessionToken);
    } else {
        // if session does not exist, redirect to login page
        console.log("Session token not found");
    }
    const response = await fetch(key_url, {
        method: "GET",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });
}