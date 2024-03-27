// Last Modified: 26/06/2023 @ 19:18

const les_choristes_url = "https://client.draggie.games/les_choristes";
const ping_url = "https://client.draggie.games/ping";


function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
    const handleSubmit = async (event) => {
        async function ping_server() {
            const max_retries = 5;
            let curernt_retry_count = 0;
            document.getElementById("status").innerHTML = "Status: Checking if the server is awake...";
            
            while (curernt_retry_count < max_retries) {
                try {
                    // test if the server is awake, if it fails to respond, retry after 10 seconds
                    let response_ping = await fetch(ping_url);

                    if (response_ping.status === 200) {
                        console.log("Pinged server to ensure it's awake.");
                        document.getElementById("status").innerHTML = "Status: The server is online and ready!";
                        break; // exit loop
                    } else {
                        console.log("Server is not awake, retrying in 10 seconds...");
                        document.getElementById("status").innerHTML = "Status: Server is not awake, retrying in 10 seconds...";
                        await sleep(10000);
                    }
                } catch (error) {
                    console.log("Error occurred:", error);
                    curernt_retry_count++; // increment retry count
                    console.log(`Retry attempt ${curernt_retry_count}/${max_retries}`);
                    await sleep(5000); // wait5 sec avant de réessayer
                }
            }
            
            if (curernt_retry_count === max_retries) {
                console.log("Status: Critical! Max retry attempts reached. Unable to ping the server. Refresh the page to try again.");
                document.getElementById("status").innerHTML = "Status: Critical! Max retry attempts reached. Unable to ping the server. Refresh the page to try again.";
            }
        }
          
        ping_server();

        const localStorageSessionToken = localStorage.getItem("dgames_sessiontoken");
    
        if (localStorageSessionToken) {
            console.log("localStorageSessionToken token value:", localStorageSessionToken);
        } else {
            // if session does not exist, redirect to login page
            console.log("localStorageSessionToken token not found");
        }
    
        const data = {
            localStorageSessionToken
        };
    
        console.log(data);
        
        try {
            const response = await fetch(les_choristes_url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            });
            return response;
        } catch (error) {
            document.getElementById("status").innerHTML = "status: Error occurred, retrying in 10 seconds...";
            console.log("Error occurred:", error);
            sleep(10000); // wait 10 sec again
            const response = await fetch(les_choristes_url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            });
            document.getElementById("status").innerHTML = "status: Done!";
            return response;
        }
    
        
    } // end of handleSubmit function

    // test if the server is awake, if it fails to respond, retry after 10 seconds
    let response = await handleSubmit();

    let jsonResponse = await response.json();
    
    let html = jsonResponse.html;
    // console.log(html); // debug
    
    if (jsonResponse.error === false) {
        const successMessage = "Success!";
        document.getElementById("choristes-messageloading-infographic").innerHTML = "parsing data from alpha draggiegames server";
    
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
        setTimeout(() => {
            success_element.remove();
        }, 5000);
    
        // append the error message element to the body
        document.body.appendChild(success_element);
        sleep(1);
    
        console.log("Writing server received HTML to document");
        document.write(html);
        // document.body.appendChild(closeButton);
        // this is not needed as else it will not apply relatively within the container
        } 
    
    else if (jsonResponse.error === true){
        const errorMessage = jsonResponse.message;
        document.getElementById("choristes-messageloading-infographic").innerHTML = `<strong>Error</strong>: ${errorMessage}`;
        document.getElementById("whilst-you-wait").innerHTML = "";
        document.getElementById("loading-message-ellipsis-changing").innerHTML = "Please log in to play Les Choristes.";

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
    
        document.body.appendChild(errorElement);
        // document.body.appendChild(closeButton);
        // this is not needed as else it will not apply relatively within the container
    } 
    
    else {
        console.log(jsonResponse);
    };
}

main();