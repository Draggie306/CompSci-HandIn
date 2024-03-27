// Last Modified: 15/07/2023 @ 23:19

const emailUrl = "https://client.draggie.games/email_forwarding";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake."); // Necessary for Replit to wake the server up before sending request. See writeup for more info.

function triggerJiggleAnimation() {
    container_id_for_jiggle.classList.add('error_jiggle');

    setTimeout(() => {
        container_id_for_jiggle.classList.remove('error_jiggle');
        container_id_for_jiggle.style.transition = 'background-color 2s ease-out';
    }, 500);
}

const handleSubmit = async (event) => {
    event.preventDefault();

    const formData = new FormData(event.target);
    const user_real_email = formData.get("user_real_email");
    const geoguk_email = formData.get("geoguk-email");
    const magicWord = formData.get("magic_word");

    if (magicWord == null) {
        console.log("Null");
    }

    const data = {
        user_real_email,
        geoguk_email,
        magicWord
    };

    const response = await fetch(emailUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const jsonResponse = await response.json();
    console.log(jsonResponse);

    if (!jsonResponse.error) {
        const successMessage = jsonResponse.message;
        document.getElementById("submit_button").innerHTML = "Processing...";

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

        setTimeout(() => {
            success_element.remove();
        }, 10000);

        document.getElementById("submit_button").innerHTML = jsonResponse.message;
        document.body.appendChild(success_element);

    }
    else if (jsonResponse.error) {
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

        setTimeout(() => {
            errorElement.remove();
        }, 5000);

        triggerJiggleAnimation();
        document.getElementById("submit_button").innerHTML = "Try again...";
        document.getElementById("submit_button").disabled = false;
        document.getElementById("submit_button").classList.remove("noHover");
        document.body.appendChild(errorElement);
    }

    else {
        console.log(jsonResponse); // Just log it :)
    }
};


const loginForm = document.querySelector("#emailer-form");
loginForm.addEventListener("submit", handleSubmit);