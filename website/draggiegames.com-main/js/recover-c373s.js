const repair_url = "https://client.draggie.games/recover_account";

fetch("https://client.draggie.games/ping");
console.log("Pinged server to ensure it's awake.");  // Necessary for Replit to wake the server up before sending request. See writeup for more info.

function change(string) {
    document.getElementById("recovery_button").innerHTML = string;
}

const handleSubmit = async (event) => {
    event.preventDefault();
    change("Waiting for server response...");

    const formData = new FormData(event.target);
    let email = formData.get("email_repair");

    const data = {
        email,
    };

    const response = await fetch(repair_url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const jsonResponse = await response.json();
    if (!jsonResponse.error) {
        const successMessage = jsonResponse.message;
        document.getElementById("recovery_button").innerHTML = "Processing...";

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

        // append the error message element to the body
        document.getElementById("recovery_button").innerHTML = jsonResponse.message;
        document.getElementById("recovery_button").disabled = false;
        document.body.appendChild(success_element);
        // document.body.appendChild(closeButton);
        // this is not needed as else it will not apply relatively within the container
    }

    else if (jsonResponse.error) {
        const errorMessage = jsonResponse.message;
        document.getElementById("recovery_button").innerHTML = "Processing response...";

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
        document.getElementById("recovery_button").innerHTML = "Retry recovery";
        document.getElementById("recovery_button").disabled = false;
        document.body.appendChild(errorElement);
        // document.body.appendChild(closeButton);
        // this is not needed as else it will not apply relatively within the container
    }

    else {
        console.log(jsonResponse);
    }
}

const loginForm = document.querySelector("#recover_email");
loginForm.addEventListener("submit", handleSubmit);
