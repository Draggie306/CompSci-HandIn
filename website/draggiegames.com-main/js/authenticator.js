// Last Modified: 02/10/2023 @ 15:55

const loginUrl = "https://client.draggie.games/login";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake."); // Necessary for Replit to wake the server up before sending request. See writeup for more info.

function triggerJiggleAnimation() {
    container_id_for_jiggle.classList.add('error_jiggle');

    setTimeout(() => {
        container_id_for_jiggle.classList.remove('error_jiggle');
        container_id_for_jiggle.style.transition = 'background-color 2s ease-out';
    }, 500);
}

// Login with Google. 
// https://developers.google.com/identity/gsi/web/guides/use-one-tap-js-api

window.onload = function () {
    google.accounts.id.initialize({
        client_id: '764536489744-vmj5kubiop5ovlsgrgehvcvur62d7680.apps.googleusercontent.com',
        callback: handleCredentialResponse
    });
    const parent = document.getElementById('google_btn');
    google.accounts.id.renderButton(parent, { theme: "filled_blue" });
    google.accounts.id.prompt();
}

async function handleCredentialResponse(response) {
    console.log("handling", response);
    const data = await fetch('https://client.draggie.games/oauth/v1', {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(response)
    });

    document.getElementById("submit_button").innerHTML = "Processing Google Login...";

    const jsonResponse = await data.json();
    console.log(jsonResponse);
    if (jsonResponse.error) // If the server returns a HANDLED error. (else it will return a 5xx status which won't be caught)
    {
        const errorMessage = jsonResponse.message;

        // create floating window message element
        const errorElement = document.createElement("div");
        errorElement.innerText = errorMessage + "                               ";
        errorElement.style.position = "fixed";
        errorElement.style.top = "20px";
        errorElement.style.left = "50%";
        errorElement.style.transform = "translateX(-50%)";
        errorElement.style.padding = "10px";
        errorElement.style.background = "red";
        errorElement.style.color = "white";
        errorElement.style.borderRadius = "5px";
        errorElement.style.zIndex = "9999";
        errorElement.className = "custom-font-roboto";
        errorElement.style.width = "300px";

        // delete message element after X seconds
        setTimeout(() => {
            errorElement.remove();
        }, 5000);

        // append the error message element to the body
        triggerJiggleAnimation();
        document.getElementById("submit_button").innerHTML = "Log in again...";
        document.getElementById("submit_button").disabled = false;
        document.getElementById("submit_button").classList.remove("noHover");
        document.body.appendChild(errorElement);
    } else if (jsonResponse.account) {
        const successMessage = jsonResponse.message;
        document.getElementById("submit_button").innerHTML = "Processing...";

        // save sesssiontoken to cookie
        // NOTE: This is legacy code, as we now use localstorage instead of cookies.
        const sessionTokenValue = jsonResponse.auth_token;
        document.cookie = `session_token=${sessionTokenValue}; path=/`;

        // save sessiontoken to localstorage
        // Copied from https://www.w3schools.com/jsref/prop_win_localstorage.asp
        if (localStorage.getItem("dgames_sessiontoken")) {
            console.log("Overwriting session token");
        }
        localStorage.setItem("dgames_sessiontoken", sessionTokenValue);
        localStorage.getItem("dgames_sessiontoken");
        // expires in 100 days
        localStorage.setItem("dgames_sessiontoken_expirey_expected", Date.now() + 8640000000); // defined in server code. TODO: get trusted time from server
        console.log("Saved session token to localstorage.");

        // this is needed as we don't want to be sending the password to the server every time a request is made! security!

        // create floating window message element for successes
        const success_element = document.createElement("div");
        success_element.innerText = successMessage + "                               ";
        success_element.style.position = "fixed";
        success_element.style.top = "20px";
        success_element.style.left = "50%";
        success_element.style.transform = "translateX(-50%)"; // set elements to centre of screen
        success_element.style.padding = "10px";
        success_element.style.background = "green";
        success_element.style.color = "white";
        success_element.style.borderRadius = "5px";
        success_element.style.zIndex = "9999"; // make sure it's on top of everything
        success_element.className = "custom-font-roboto";
        success_element.style.width = "300px";
        // TODO: Make it pop down from the top of the screen like a notification

        // delete message element after X seconds
        setTimeout(() => {
            success_element.remove();
        }, 5000);

        // append the error message element to the body
        document.getElementById("submit_button").innerHTML = "Redirecting...";
        document.getElementById("submit_button").disabled = false;
        document.getElementById("submit_button").classList.remove("noHover");
        document.body.appendChild(success_element);

        // if there is "?return_url=" in the URL, redirect to that URL NOT the redirect_url from the server.
        // the redirect_url is the DEFAULT, as it doesn't know if the user URL has a return_url or not.
        if (window.location.href.includes("?return_url=")) {
            const return_url = window.location.href.split("?return_url=")[1];
            window.location.href = `${window.location.origin}/${return_url}`;
        } else

            window.location.href = jsonResponse.redirect_url;
    }

}



const handleSubmit = async (event) => {
    event.preventDefault();

    const formData = new FormData(event.target); // Constructs a series of key/value pairs representing form fields and their values.
    const email = formData.get("email");
    const password = formData.get("password");

    const data = {
        email,
        password
    };

    const response = await fetch(loginUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const jsonResponse = await response.json();
    console.log(jsonResponse);

    if (jsonResponse.account) {
        const successMessage = jsonResponse.message;
        document.getElementById("submit_button").innerHTML = "Processing...";

        // save sesssiontoken to cookie
        // NOTE: This is legacy code, as we now use localstorage instead of cookies.
        const sessionTokenValue = jsonResponse.auth_token;
        document.cookie = `session_token=${sessionTokenValue}; path=/`;

        // save sessiontoken to localstorage
        // Copied from https://www.w3schools.com/jsref/prop_win_localstorage.asp
        if (localStorage.getItem("dgames_sessiontoken")) {
            console.log("Overwriting session token");
        }
        localStorage.setItem("dgames_sessiontoken", sessionTokenValue);
        localStorage.getItem("dgames_sessiontoken");
        // expires in 100 days
        localStorage.setItem("dgames_sessiontoken_expirey_expected", Date.now() + 8640000000); // defined in server code.
        console.log("Saved session token to localstorage.");

        // this is needed as we don't want to be sending the password to the server every time a request is made! security!

        // create floating window message element for successes
        const success_element = document.createElement("div");
        success_element.innerText = successMessage + "                               ";
        success_element.style.position = "fixed";
        success_element.style.top = "20px";
        success_element.style.left = "50%";
        success_element.style.transform = "translateX(-50%)"; // set elements to centre of screen
        success_element.style.padding = "10px";
        success_element.style.background = "green";
        success_element.style.color = "white";
        success_element.style.borderRadius = "5px";
        success_element.style.zIndex = "9999";
        success_element.className = "custom-font-roboto";
        success_element.style.width = "300px";
        // TODO: Make it pop down from the top of the screen like a notification

        // delete message element after X seconds
        setTimeout(() => {
            success_element.remove();
        }, 5000);

        // append the error message element to the body
        document.getElementById("submit_button").innerHTML = "Redirecting...";
        document.getElementById("submit_button").disabled = false;
        document.getElementById("submit_button").classList.remove("noHover");
        document.body.appendChild(success_element);

        // if there is "?return_url=" in the URL, redirect to that URL NOT the redirect_url from the server.
        // the redirect_url is the DEFAULT, as it doesn't know if the user URL has a return_url or not.
        if (window.location.href.includes("?return_url=")) {
            const return_url = window.location.href.split("?return_url=")[1];
            window.location.href = `${window.location.origin}/${return_url}`;
        } else

            window.location.href = jsonResponse.redirect_url;
    }

    else if (jsonResponse.error) // If the server returns a HANDLED error. (else it will return a 5xx status which won't be caught)
    {
        const errorMessage = jsonResponse.message;
        document.getElementById("submit_button").innerHTML = "Processing response...";

        // create floating window message element
        const errorElement = document.createElement("div");
        errorElement.innerText = errorMessage + "                               ";
        errorElement.style.position = "fixed";
        errorElement.style.top = "20px";
        errorElement.style.left = "50%";
        errorElement.style.transform = "translateX(-50%)";
        errorElement.style.padding = "10px";
        errorElement.style.background = "red";
        errorElement.style.color = "white";
        errorElement.style.borderRadius = "5px";
        errorElement.style.zIndex = "9999";
        errorElement.className = "custom-font-roboto";
        errorElement.style.width = "300px";

        // delete message element after X seconds
        setTimeout(() => {
            errorElement.remove();
        }, 5000);

        // append the error message element to the body
        triggerJiggleAnimation();
        document.getElementById("submit_button").innerHTML = "Log in again...";
        document.getElementById("submit_button").disabled = false;
        document.getElementById("submit_button").classList.remove("noHover");
        document.body.appendChild(errorElement);
    }

    else {
        console.log(jsonResponse); // Just log it :)
    }
};


const loginForm = document.querySelector("#login-form");
loginForm.addEventListener("submit", handleSubmit);