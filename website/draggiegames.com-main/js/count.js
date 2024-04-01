// Last modified: 04/07/2023 16:59

document.addEventListener("DOMContentLoaded", function () {
    var floatingElement = document.createElement("div");

    floatingElement.style.position = "fixed";
    floatingElement.style.top = "20px";
    floatingElement.style.right = "20px";
    floatingElement.style.backgroundColor = "#00acff";
    floatingElement.style.border = "1px solid #fffff";
    floatingElement.style.padding = "10px";
    // set font + size
    floatingElement.style.fontFamily = "Arial, Helvetica, sans-serif";


    // floatingElement.innerHTML = "Current players in game: " + viewerCount;

    let viewerCount = null;

    function updateViewerCount() {
        const api_url = "https://client.draggie.games/api/players";
        fetch(api_url)
            .then(response => response.json())
            .then(data => {
                viewerCount = data.currentPlayers;
                floatingElement.innerHTML = "Current players in game: " + viewerCount;
            });
    }

    updateViewerCount();
    console.log(viewerCount);
    floatingElement.innerHTML = "Fetching current player data..."
    setInterval(updateViewerCount, 10000);



    document.body.appendChild(floatingElement);
});
