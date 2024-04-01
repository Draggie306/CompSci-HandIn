// Last Modified: 02/10/2023 @ 19:49

const token_login_url = "https://client.draggie.games/token_login";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake.");  // Necessary for Replit to wake the server up before sending request. See writeup for more info.

function triggerJiggleAnimation() {
    // TODO: Make this a function that can be called from anywhere and not just this script.
    container_id_for_jiggle.classList.add('error_jiggle');

    setTimeout(() => {
        container_id_for_jiggle.classList.remove('error_jiggle');
        container_id_for_jiggle.style.transition = 'background-color 2s ease-out';
    }, 500);
}

let queried_login_field = document.getElementById("login-form");

async function login() {
    if (localStorage.getItem("dgames_sessiontoken")) {
        // make it grey out the login fields with noinput

        queried_login_field.classList.add("noHoverGreyedLoginButton");

        // change "Log in" button to "Processing..."
        document.getElementById("submit_button").innerHTML = "Processing...";

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

        if (jsonResponse.account) {
            const successMessage = jsonResponse.message;
            document.getElementById("submit_button").innerHTML = "Processing...";

            // save sesssiontoken to cookie
            // NOTE: This is legacy code, as we now use localstorage instead of cookies.
            const sessionTokenValue = jsonResponse.auth_token;
            document.cookie = `session_token=${sessionTokenValue}; path=/`;

            // save sessiontoken to localstorage
            // Copied from https://www.w3schools.com/jsref/prop_win_localstorage.asp
            if (!localStorage.getItem("dgames_sessiontoken")) {
                localStorage.setItem("dgames_sessiontoken", sessionTokenValue);
                localStorage.getItem("dgames_sessiontoken");
                // expires in 100 days
                localStorage.setItem("dgames_sessiontoken_expirey_expected", Date.now() + 8640000000); // defined in server code.
                console.log("Saved session token to localstorage.");
            } else {
                console.log("Session token already exists in localstorage.");
            }

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
            document.getElementById("submit_button").classList.remove("noHoverGreyedLoginButton");
            document.body.appendChild(success_element);

            // if there is "?return_url=" in the URL, redirect to that URL NOT the redirect_url from the server.
            // the redirect_url is the DEFAULT, as it doesn't know if the user URL has a return_url or not.
            if (window.location.href.includes("?return_url=")) {
                const return_url = window.location.href.split("?return_url=")[1];
                window.location.href = `${window.location.origin}/${return_url}`;
            } else

                window.location.href = jsonResponse.redirect_url;
        }

        // Next, if the server returns a HANDLED error. (else it will return a 5xx status which won't be caught)
        else if (jsonResponse.error) {
            queried_login_field.classList.remove("noHoverGreyedLoginButton");
            const errorMessage = jsonResponse.message;
            document.getElementById("submit_button").innerHTML = "Processing response...";

            // create floating window message element
            // there is no css defined for this, create it with JS
            // TODO: add this to the stylesheet
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

            // Timeout to delete message element after X milliseconds (5000 is a good balance)
            setTimeout(() => {
                errorElement.remove();
            }, 5000);


            // Have the red shake animation to show that there's an error
            triggerJiggleAnimation();

            // append the error message element to the body
            // this will display the element with stylesheet's position
            document.getElementById("submit_button").innerHTML = "Log in again...";
            document.getElementById("submit_button").disabled = false;
            document.getElementById("submit_button").classList.remove("noHoverGreyedLoginButton");
            document.body.appendChild(errorElement);
        }

        else {
            queried_login_field.classList.remove("noHoverGreyedLoginButton");
            console.log(jsonResponse); // Just log it :)
        }

        document.getElementById("submit_button").innerHTML = "Log in";
    }
    // Don't process or send data if there is no session token saved, just log it.
    else {
        // In the CSS stylesheet, this is defined as a greyed out button. In order to allow user interaction,
        // change this if the token is not founed to enable submission.
        queried_login_field.classList.remove("noHoverGreyedLoginButton");
        console.log("AutoTokenLogin: No session token found in localstorage.");
    }
}

// Wrap the login function in a function that will be auto called when the page loads.
// This is necessaty for this specific script. Logging in automatically if the token exists is a good idea as it reduces the amount of user clicks, time etc. and also is a better user experience
login();