// Last Modified: 26/06/2023 @ 19:18

const reset_secure_url = "https://client.draggie.games/secured/synthesis/reset";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake.");

function triggerJiggleAnimation() {
    container_id_for_jiggle.classList.add('error_jiggle');

    setTimeout(() => {
        container_id_for_jiggle.classList.remove('error_jiggle');
        // transition back to normal
        container_id_for_jiggle.style.transition = 'background-color 2s ease-out';
    }, 500);
}


const handleSubmit = async (event) => {
    event.preventDefault();

    function sleep(delay) {
        return new Promise(resolve => setTimeout(resolve, delay));
    }

    const searchParams = new URLSearchParams(window.location.search);
    const email_secure_token = searchParams.get("temp_switch_pass"); // Grab the email_secure_token from the URL.
    console.log(email_secure_token); // Not secure but oh well

    const email = searchParams.get("email");
    console.log(email);

    const formData = new FormData(event.target);
    const newpass = formData.get("password")

    const data = {
        email,
        newpass,
        email_secure_token
    };

    console.log("Got the data");
    console.log(data);

    const response = await fetch(reset_secure_url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const jsonResponse = await response.json();
    console.log(jsonResponse);

    if (jsonResponse.error) // If there's an error. We need to have the dismissable popup to explain.
    {
        triggerJiggleAnimation();
        const errorMessage = jsonResponse.message;

        const loginForm = document.querySelector("#set_new_pw_button")
        loginForm.disabled = false;
        document.getElementById("set_new_pw_button").innerHTML = "Processing...";

        const errorElement = document.createElement("div");
        errorElement.innerText = errorMessage;
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
        errorElement.appendChild(closeButton);
        closeButton.onclick = errorElement.remove();
        closeButton.onclick = closeButton.remove();

        setTimeout(() => {
            errorElement.remove();
        }, 5000);

        document.body.appendChild(errorElement);
        document.getElementById("set_new_pw_button").innerHTML = "Retry resetting";
    }

    else if (jsonResponse.return_url) // new branch for newer redirect code> Popup but not dismissable due to weird CSS and positioning not working correctly
    {
        const successMessage = jsonResponse.message;
        document.getElementById("set_new_pw_button").innerHTML = "Server processing...";
        // sets the submit button to "Server processing..." so that the user knows that the server is doing something

        const successElement = document.createElement("div");
        successElement.innerText = successMessage + ". Redirecting you now!   ";
        successElement.style.position = "fixed";
        successElement.style.top = "20px";
        successElement.style.left = "50%";
        successElement.style.transform = "translateX(-50%)";
        successElement.style.padding = "10px";
        successElement.style.background = "green";
        successElement.style.color = "white";
        successElement.style.borderRadius = "5px";
        successElement.style.zIndex = "9999";
        successElement.className = "custom-font-roboto";

        setTimeout(() => {
            successElement.remove();
        }, 5000);


        document.getElementById("set_new_pw_button").innerHTML = "Redirecting...";
        document.body.appendChild(successElement);
        await sleep(jsonResponse.wait_for); // Block redirect for server response seconds so that the user can read the message
        window.location.href = jsonResponse.return_url;
    }

    else { // this should never happen unless the client has a wacky browser or something like that
        // catch errors
        console.log("I don't know what do do with that data... um...");
        console.log(jsonResponse);
        document.getElementById("set_new_pw_button").innerHTML = "Register";

        const successElement = document.createElement("div");
        successElement.innerText = "I don't know what to do with this data at all...<br>" + jsonResponse;
        successElement.style.position = "fixed";
        successElement.style.top = "20px";
        successElement.style.left = "50%";
        successElement.style.transform = "translateX(-50%)";
        successElement.style.padding = "10px";
        successElement.style.background = "green";
        successElement.style.color = "white";
        successElement.style.borderRadius = "5px";
        successElement.style.zIndex = "9999";
        successElement.className = "custom-font-roboto";

        setTimeout(() => {
            successElement.remove();
        }, 5000);

        document.body.appendChild(successElement);
    }
};

const recovery_button_info = document.querySelector("#set_new_pw_account_form");
recovery_button_info.addEventListener("submit", handleSubmit);
