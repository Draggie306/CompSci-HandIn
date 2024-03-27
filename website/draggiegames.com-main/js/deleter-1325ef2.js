// Last Modified: 26/06/2023 @ 20:53

const remove_url = "https://client.draggie.games/delete_account";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake."); // Necessary for Replit to wake the server up before sending request. See writeup for more info.

function change(string) {
    document.getElementById("delete_account-button").innerHTML = string;
}

const handleSubmit = async (event) => {
    event.preventDefault();
    change("handlingSubmit");
    function getSessionToken() {
        const localStorageSessionToken = localStorage.getItem("dgames_sessiontoken");

        if (localStorageSessionToken) {
            console.log("Session token value:", localStorageSessionToken);
            return localStorageSessionToken
        } else {
            // if session does not exist, redirect to login page
            console.log("Session token not found");
        }
    }

    // feat: use localStorage to get session token

    const formData = new FormData(event.target);
    const code = formData.get("code");
    change("got code");
    let token = getSessionToken();
    let password = formData.get("password");
    let email = formData.get("email");

    if (token === "") {
        const errorElement = document.createElement("div");
        errorElement.innerText = "You must be logged in first to cofnfirm your identity.";
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
        closeButton.innerText = "❌";
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
        document.getElementById("delete_account-button").innerHTML = "Log in again...";
        document.getElementById("delete_account-button").classList.remove("noHover");
        document.body.appendChild(errorElement);
    }

    const data = {
        token,
        email,
        password,
    };


    if (token != "") { // Hack fix for checking if the token seems to be valid instead of actually checking it
        const response = await fetch(remove_url, {
            method: "DELETE", // The API is RESTful enough
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        const jsonResponse = await response.json();
        if (!jsonResponse.error) {
            const successMessage = jsonResponse.message;
            document.getElementById("delete_account-button").innerHTML = "Processing...";

            // create floating window message element for successes
            const success_element = document.createElement("div");
            success_element.innerText = successMessage + "                               ";
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
            // setTimeout(() => {
            //     success_element.remove();
            // }, 5000);

            // append the error message element to the body
            document.getElementById("delete_account-button").innerHTML = jsonResponse.message;
            document.getElementById("delete_account-button").disabled = true;
            document.getElementById("delete_account-button").classList.add("noHover");
            document.body.appendChild(success_element);
            // document.body.appendChild(closeButton);
            // this is not needed as else it will not apply relatively within the container
        }

        else if (jsonResponse.error) {
            const errorMessage = jsonResponse.message;
            document.getElementById("delete_account-button").innerHTML = "Processing response...";

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

            // append the error message element to the body
            document.getElementById("delete_account-button").innerHTML = "Retry deletion...";
            document.getElementById("delete_account-button").disabled = false;
            document.body.appendChild(errorElement);
            // document.body.appendChild(closeButton);
            // this is not needed as else it will not apply relatively within the container
        }

        else {
            console.log(jsonResponse);
        }
    }
};

const loginForm = document.querySelector("#delete_account-form");
loginForm.addEventListener("submit", handleSubmit);
