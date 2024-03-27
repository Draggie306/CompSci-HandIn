const redeemUrl = "https://client.draggie.games/add_code";
const checkUrl = "https://client.draggie.games/check_code";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake.");   // Necessary for Replit to wake the server up before sending request. See writeup for more info.

function change(string) {
    document.getElementById("code_redeem_input_button_submit").innerHTML = string;
}

function triggerJiggleAnimation() {
    container_id_for_jiggle.classList.add('error_jiggle');

    setTimeout(() => {
        container_id_for_jiggle.classList.remove('error_jiggle');
        container_id_for_jiggle.style.backgroundColor = 'transparent'; // reset bg
        // transition back to normal
        container_id_for_jiggle.style.transition = 'background-color 2s ease-out';
        // TODO: fix go to normal colour with transition over time rtather than flash (don't know why it is not working)
    }, 500);
}

const handleSubmit = async (event) => {
    // Should only be called when we are REDEEMING. not checking!
    event.preventDefault();
    change("handlingSubmit");
    function getSessionToken() {
        const localStorageSessionToken = localStorage.getItem("dgames_sessiontoken");

        if (localStorageSessionToken) {
            console.log("Session token value:", localStorageSessionToken);
            return localStorageSessionToken;
        } else {
            // if session does not exist, redirect to login page
            console.log("Session token not found");
            return null;
        }
    }

    const formData = new FormData(event.target);
    const code = formData.get("code");
    change("Redeeming to your account...");
    let token = getSessionToken();

    if (token == null) {
        const errorElement = document.createElement("div");
        errorElement.innerText = "You're not currently logged in to an account.";
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

        // make floating window dismissable
        const closeButton = document.createElement("button");
        closeButton.innerText = " ";
        closeButton.style.position = "absolute";
        closeButton.style.top = "5px";
        closeButton.style.right = "5px";
        closeButton.style.background = "none";
        closeButton.style.border = "none";
        closeButton.style.color = "white";
        closeButton.style.fontSize = "20px";
        closeButton.style.cursor = "pointer";
        closeButton.style.width = "20px";
        closeButton.style.height = "20px";
        closeButton.style.display = "flex"; // flexbox centre icon
        closeButton.style.justifyContent = "center";
        closeButton.style.alignItems = "center";
        errorElement.appendChild(closeButton);
        closeButton.onclick = function () {
            errorElement.remove();
            closeButton.remove();
        };

        // delete message element after X seconds
        setTimeout(() => {
            errorElement.remove();
        }, 5000);

        // append the error message element to the body
        change("Redeem again");
        triggerJiggleAnimation();
        document.getElementById("code_redeem_input_button_submit").classList.remove("noHover");
        document.body.appendChild(errorElement);
        return null;
    }

    const data = {
        token,
        code,
    };

    if (token != "") {
        // catch errors, if there are then open up the url

        let jsonResponse; // declare variables to store json response
        let response;

        try {
            response = await fetch(redeemUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            });
        } catch (error) {
            console.log("Error: " + error);
            window.open(redeemUrl, "_blank");
        }

        jsonResponse = await response.json();

        if (jsonResponse.code_redeem_success) {
            console.log("Using code_redeem_success === true");
            const successMessage = jsonResponse.message;
            change("Processing redemption...");

            // create floating window message element for successes
            const success_element = document.createElement("div");
            success_element.innerText = successMessage + "                               "; // hacky way to have the close button not cover the text
            success_element.style.position = "fixed";
            success_element.style.top = "20px";
            success_element.style.left = "50%";
            success_element.style.transform = "translateX(-50%)";
            success_element.style.padding = "10px";
            success_element.style.background = "green";
            success_element.style.color = "white";
            success_element.style.borderRadius = "5px";
            success_element.style.zIndex = "9999";
            success_element.className = "custom-font-roboto";
            success_element.style.width = "300px";

            // delete message element after X seconds
            setTimeout(() => {
                success_element.remove();
            }, 5000);

            // append the error message element to the body
            document.getElementById("code_redeem_input_button_submit").innerHTML = jsonResponse.message;
            document.getElementById("code_redeem_input_button_submit").disabled = false;
            document.getElementById("code_redeem_input_button_submit").style.display = "inline";
            document.body.appendChild(success_element);


            // open received URL from JSON resp in new tab
            if (jsonResponse.forwarded_url != null) {
                // default HTML: <button id="post_redeem_download_button" class="post_redeem_download_button" style="display: none;">Download!</button>
                document.getElementById("post_redeem_download_button").style.display = "inline";
                document.getElementById("post_redeem_download_button").classList.add("post_redeem_download_button")
                document.getElementById("post_redeem_download_button").onclick = function () {
                    window.open(jsonResponse.forwarded_url, "_blank");
                }
            }

            // Taken from <!-- https://codepen.io/ieatwebsites/pen/KKBvywP https://www.youtube.com/watch?v=tTIaA1Xmzmg -->
            const jsConfetti = new JSConfetti();
            jsConfetti.addConfetti({
                emojis: ['🌈', '⚡️', '💥', '✨', '💫', '🌸', '⚡️', '😂', '💀']
            }).then(() => jsConfetti.addConfetti());


        } else {
            const errorMessage = jsonResponse.message;
            change("Processing response...");

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

            // make floating window dismissable
            const closeButton = document.createElement("button");
            closeButton.innerText = " ";
            closeButton.style.position = "absolute";
            closeButton.style.top = "50px";
            closeButton.style.right = "5px";
            closeButton.style.background = "none";
            closeButton.style.border = "none";
            closeButton.style.color = "white";
            closeButton.style.fontSize = "20px";
            closeButton.style.cursor = "pointer";
            closeButton.style.width = "20px";
            closeButton.style.height = "20px";
            closeButton.style.display = "flex"; // flexbox centre icon
            closeButton.style.justifyContent = "center";
            closeButton.style.alignItems = "center";
            errorElement.appendChild(closeButton);
            closeButton.onclick = function () {
                errorElement.remove();
                closeButton.remove();
            };

            // delete message element after X seconds
            setTimeout(() => {
                errorElement.remove();
            }, 5000);

            // append the error message element to the body
            change("Retry redemption...");
            triggerJiggleAnimation();
            document.getElementById("code_redeem_input_button_submit").disabled = false;
            document.body.appendChild(errorElement);
            // document.body.appendChild(closeButton);
            // this is not needed as else it will not apply relatively within the container
        }

        console.log(jsonResponse);
    }
};


const checkCode = async (event) => {
    event.preventDefault(); // This will make sure that the browser does not go to the url/reload page with the form data inputted as part of the url. 

    function getSessionToken() {
        const localStorageSessionToken = localStorage.getItem("dgames_sessiontoken");

        if (localStorageSessionToken) {
            console.log("Session token value:", localStorageSessionToken);
            return localStorageSessionToken;
        } else {
            // if session does not exist, redirect to login page
            console.log("Session token not found");
            return null;
        }
    }
    let token = getSessionToken();
    if (token == null) {
        const errorElement = document.createElement("div");
        errorElement.innerText = "You're not currently logged in to an account.";
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
        document.body.appendChild(errorElement); // WRITEUP: 09/07/23 add ".body" rather than just document.appendChild (this is for buttons?)
        triggerJiggleAnimation()
        console.log("Generated no token error message, returning");
        return;
    }

    console.log("Checking code...");
    const formData = new FormData(event.target);
    const code = formData.get("code");
    console.log("Checking " + code);

    const data = {
        code,
    };

    let jsonResponse;
    let response;

    try {
        response = await fetch(checkUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });
    } catch (error) {
        console.log("Error: " + error);
        window.open(redeemUrl, "_blank");
    }

    jsonResponse = await response.json();

    if (jsonResponse.code_valid === true) {
        console.log("Code is valid");
        const successMessage = jsonResponse.message;

        // create floating window message element for successes
        const success_element = document.createElement("div");
        success_element.innerText = successMessage + "                               ";
        success_element.style.position = "fixed";
        success_element.style.top = "50px";
        success_element.style.left = "50%";
        success_element.style.transform = "translateX(-50%)";
        success_element.style.padding = "10px";
        success_element.style.background = "green";
        success_element.style.color = "white";
        success_element.style.borderRadius = "5px";
        success_element.style.zIndex = "9999";
        success_element.className = "custom-font-roboto";
        success_element.style.width = "300px";

        // delete message element after X seconds
        setTimeout(() => {
            success_element.remove();
        }, 5000);

        // append the error message element to the body
        document.getElementById("code_redeem_input_button_submit").innerHTML = "Please confirm you would like to redeem this to your account.";
        document.getElementById("code_redeem_input_button_submit").disabled = false;
        document.getElementById("code_redeem_input_button_submit").style.display = "inline";
        document.getElementById("code_redeem_input_button_submit").style.color = "blue";
        document.getElementById('check_code_form').id = 'add_code_form'
        document.body.appendChild(success_element);
        const checkForm = document.querySelector("#add_code_form");
        checkForm.addEventListener("submit", handleSubmit);

    } else {
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

        triggerJiggleAnimation();

        // append the error message element to the body
        document.getElementById("code_redeem_input_button_submit").innerHTML = "Recheck validity";
        document.body.appendChild(errorElement);
        console.log(jsonResponse);
    }
    console.log(jsonResponse);
};

const loginForm = document.querySelector("#check_code_form");
loginForm.addEventListener("submit", checkCode);

// don't navigate away from the page
