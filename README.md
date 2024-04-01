# Computer Science A Level Project
This is a monorepo containing all 5 main components of my Computer Science A-level NEA.

## How to run
Go to [compsci-handin.pages.dev](https://compsci-project.pages.dev/). From there, navigate to the Games Library and download the Draggie Games Launcher.

All components are accessible through `Launcher.exe`. Download it and follow what it says. It interacts with the server, allows you to install the Auto-Updater and game itself.

## Build from source
All aspects are designed to be built from source too.

### Auto-updater
- Go into the `autoupdater/AutoUpdate-main` folder above.
- Ensure you have Python installed.
- Run `pip install -r autoupdate-requirements.txt`
- Copy and paste the contents of the `pyinstaller-autoupdate.txt` into the terminal
- Watch it build the exe

### Installer
- Go into the `installer/installer-main` folder above.
- Ensure you have Python installed.
- Run `pip install -r installer-requirements.txt`
- Copy and paste the contents of the `pyinstaller-installer.txt` into the terminal
- Watch it build the exe

### Server
- Clone/download the contents of `server/DraggieGamesServer-main`
- Make sure you have Python installed
- Run `python server.py`
  - Note: paths are hardcoded to the username `Draggie`. you will need to update them
- Visit `localhost:<port>` where `port` is the one it shows in the console

### Unity game
- Clone/download the contents of the folder `unity/CS-Project-main`
- Open it with Unity version 2022.3.22f1
- Build and run

### Website
- Download the contents of `website/draggiegames.com-main`
- Open `index.html`

