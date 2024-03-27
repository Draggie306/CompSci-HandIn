# Draggie Games Server - Computer Science Project

This is a Python webserver that responds to requests to the endpoint.

The client-side code is hardcoded to the URL of the webserver at client.draggie.games. 

To run the server, you will need to:
1) Download Python 3.12.2 from https://www.python.org/

2) Change/create (if not already) a virtual environment
```
python3.12 -m venv .venv
```

3) If on Windows, activate the virtual environment using the following powershell script
```ps
source .venv/bin/activate
```

4) Using the requirements.txt file in the root folder of this repository, use the following command to install the requirements:
```bash
pip install -r requirements.txt
```

5) Run the file
```bash
python server.py
```

6) If it doesn't work, modify the paths in the `server.py` file.
