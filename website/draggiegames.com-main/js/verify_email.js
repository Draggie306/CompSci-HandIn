// Last Modified: 26/06/2023 @ 19:18

const verifyUrl = "https://client.draggie.games/verify_email";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake.");

const url = new URL(window.location.href);
const searchParams = url.searchParams;
const token = searchParams.get("token"); // get the token from the URL
console.log(token);

const data = {
    token
};

async function verifyEmail() {
    // Send POST request to server which contains the token passed fromthe URL
    const response = await fetch(verifyUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    // receive JSON response from the server
    // this will contain the message 
    const jsonResponse = await response.json();


    if (jsonResponse.error) {
        document.getElementById("verification_string").innerHTML = "Processing response...";
        const errorMessage = jsonResponse.message;

        // append the error message element to the body
        document.getElementById("verification_string").innerHTML = errorMessage;
    }

    else if (jsonResponse.message) {
        document.getElementById("verification_string").innerHTML = "Processing...";

        // append the error message element to the body
        document.getElementById("verification_string").innerHTML = jsonResponse.message;
    }

    else {
        console.log(jsonResponse);
    }

    // if there is "?return_url=" in the URL, redirect to the JSON 
    if (window.location.href.includes("?return_url=")) {
        console.log("Redirecting removed.");
        // Removed redirecting as people were getting confused
        // This was because they were being redirected to the login page which did not have any return URL
        // so they were just being redirected to the home page, rather than the page they were on before
        // and also because the verification token sent in the email did not contain the return URL (too much effort)
    }

    if (jsonResponse.redirect_url) {
        console.log("Redirecting removed.");
        // remove other redirecting even though serer sends it due to above reason
    }
}

verifyEmail();
