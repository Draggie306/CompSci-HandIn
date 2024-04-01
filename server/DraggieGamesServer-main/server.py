version = "1.0.1"   # in the commit, it must be formatted as "[VERSION HETE] feat: blah", etc.
type = "server"     # major, minor, patch
commit_time = "01/04/2024 20:41" # UK time (BST)! 

import os, time

start_time = time.time()

config = {
    "login_enabled": True,
    "register_enabled": True,
    "verify_users": True,
    "verify_codes": True,
    "email_processing": True,
    "geoguk_emails": True,
    "code_redeeming": True,
    "reset_accounts": True,
    "test_features_enabled": True,
    "token_expiration_sec": 17280000,  # 200 days
    "trusted_token_expiration_sec": 31556952,  # 1 year
    "unity_token_expiration_sec": 31556952,  # 1 year
    "free_choristes": True,
}

print(f"DraggieGamesServer\n\nRunning version {version} ({type}) on OS {os.name} at {commit_time}\n\n")
for key, value in config.items():
    if value is True:
        print(key + " is enabled.")
    elif value is False:
        print(key + " is disabled.")
    else:
        print(key + " is set to " + str(value))

import datetime
# from flask_limiter import Limiter # Removed for now because we won't get DDoSed yet *laughs in Cloudflare reverse proxy*
# from flask_limiter.util import get_remote_address # can just use cloudflare HTTP_CF_CONNECTING_IP
import json
import random
import re
import uuid
import logging
import traceback
import boto3
import requests
import dotenv # for new hosting on raspberry pi

from typing import Optional
from flask import Flask, jsonify, request
from flask_caching import Cache
from flask_cors import CORS, cross_origin
from flask_login import LoginManager, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

log_directory = "/home/draggie/DraggieGamesServer/new_logs" # Fixed for the raspberry pi
dedicated_directory = os.path.join(log_directory, ".dedicated")

execution_time = datetime.datetime.now().strftime("%Y/%m/%d__%H:%M:%S")

# get hours, mins, secs
execution_time_time = execution_time.split("__")[1]

execution_time_year = execution_time.split("/")[0]
execution_time_month = execution_time.split("/")[1]
execution_time_day = execution_time.split("/")[2].split("__")[0] # Still not sure why it needs to be split twice

log_dayfolder = os.path.join(log_directory, execution_time_year, execution_time_month, execution_time_day)
print(f"Log dayfolder: {log_dayfolder}")

log_dir_and_name = os.path.join(log_dayfolder, f"{execution_time_time}" + ".log")
print(f"Log file: {log_dir_and_name}")

# fix for raspberry pi
dotenv_dir = "/home/draggie/DraggieGamesServer/.env"
usersJson_dir = "/home/draggie/DraggieGamesServer/users.json"
redeemed_codes_dir = "/home/draggie/DraggieGamesServer/redeemed_codes.txt"
papersJson_dir = "/home/draggie/DraggieGamesServer/papers.json"

# Create new day folders
os.makedirs(log_dayfolder, exist_ok=True)
logging.basicConfig(filename=log_dir_and_name, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Starting server...")


def log(message, dedicated_filename: Optional[str] = None):
    logging.debug(message)
    print("Attempting to log message")
    time = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    if dedicated_filename is not None:
        dedicated_logfile = os.path.join(dedicated_directory, dedicated_filename)
        if not os.path.exists(dedicated_logfile):
            print(f"Creating new log file for {dedicated_filename} at directory {dedicated_directory}")
            os.makedirs(dedicated_directory, exist_ok=True)
            with open(dedicated_logfile, "w") as f:
                print(f"Created new log file for {dedicated_filename}")
                f.write(f"Log file for {dedicated_filename} at {time}\n")
        with open(dedicated_logfile, "a") as f:
            f.write(f"[{time}] {message}\n")
    print(f"Log success: [{time}] {message}")


log("Loading environment variables")
dotenv.load_dotenv(dotenv_path=dotenv_dir)

alpha_codes = os.environ['alpha_codes']
alpha_codes = alpha_codes.split(",")
#print(alpha_codes)

beta_codes = os.environ['beta_codes']
beta_codes = beta_codes.split(",")
#print(beta_codes)

print(f"api key mailgun: key-{os.environ['mailgun_api_key']}")

print(f"Environment var alpha url: {os.environ['alpha_url']}")
# testing

# Initialize Flask app and login manager
app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 5})
app.secret_key = 'super secret key'
login_manager = LoginManager()
login_manager.init_app(app)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

app = Flask('')


@app.route("/")
@cross_origin()
def home():
    return "Hey!"


@app.route("/ping")
@cross_origin()
def ping():
    return f'Pinged at {datetime.datetime.strftime(datetime.datetime.now(), "%d/%m/%Y %H:%M:%S")}'

# -*-*-*-*-* USER MODEL *-*-*-*-*-


class User(UserMixin):
    def __init__(self,
                 id,  # Mandatory attributes for all User objects
                 email,
                 username,
                 password,
                 tokens=None,  # These below are default to None as they are optional
                 tokens_expiration=None,
                 status=None,
                 codes=None,
                 verified=None,
                 verified_date=None,
                 temp_account_reset_token=None,
                 entitlements=None,
                 verification_pending=True,
                 verification_pending_codes=None,
                 user_lang=None,
                 last_time_reset_token=None,
                 last_activity=None
                 ):
        self.id = id
        self.email = email
        self.username = username
        self.password = password
        self.codes = codes if codes is not None else []
        self.status = status if status is not None else "active"
        self.tokens = tokens if tokens is not None else []
        self.verified = verified if verified is not None else False
        self.user_lang = user_lang if user_lang is not None else "en"
        self.entitlements = entitlements if entitlements is not None else []
        self.verified_date = verified_date if verified_date is not None else None
        self.tokens_expiration = tokens_expiration if tokens_expiration is not None else []
        self.verification_pending = verification_pending if verification_pending is not None else None
        self.last_time_reset_token = last_time_reset_token if last_time_reset_token is not None else None
        self.temp_account_reset_token = temp_account_reset_token if temp_account_reset_token is not None else None
        self.verification_pending_codes = verification_pending_codes if verification_pending_codes is not None else None
        self.last_activity = last_activity if last_activity is not None else None

    # Methods for each class
    # Don't really use this, but it can be called if needed

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def add_code(self, code):
        self.codes.append(code)

    def has_code(self, code):
        return code in self.codes


# -*-*-*-*-* RETURN USERS *-*-*-*-*-


def load_users() -> list:
    print("[loadUsers] Loading users")
    try:
        with open(usersJson_dir, 'r') as f:
            users_data = json.load(f)
            users = [User(**data) for data in users_data]
    except FileNotFoundError:
        users = []
    return users


# -*-*-*-*-* SAVE USERS TO JSON WITH USERMIXIN *-*-*-*-*-


def save_users(users) -> None:
    users_data = [{
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'password': user.password,
        'codes': user.codes,
        'tokens': user.tokens,
        'tokens_expiration': user.tokens_expiration,
        'status': user.status, # User account status (active, banned, etc.)
        'verified': user.verified,
        'verified_date': user.verified_date,
        'temp_account_reset_token': user.temp_account_reset_token,
        'entitlements': user.entitlements, # Human readable entitlements (e.g. saturnian_alpha_tester)
        'verification_pending': user.verification_pending,
        'verification_pending_codes': user.verification_pending_codes,
        'user_lang': user.user_lang,
        'last_time_reset_token': user.last_time_reset_token,
        'last_activity': user.last_activity,
    } for user in users]
    with open(usersJson_dir, 'w') as f:
        print("Dumping JSON to users file")
        json.dump(users_data, f, indent=4)


# -*-*-*-*-* LOAD OR CREATE NEW USERS *-*-*-*-*-

first_users = load_users()

# Uncomment below to apply something to all users in case of breaking changes
"""for user in users:
    user.tokens_expiration = []
    user.tokens = []
    print(f"Cleared user tokens for account {user.email}")
save_users(users)"""

if not first_users:
    # Test case for fresh json database only
    user = User(id=1,
                email='test@example.com',
                password=generate_password_hash('password'),
                codes=['testcode'],
                username="example")
    first_users.append(user)
    save_users(first_users)


def load_user(email) -> UserMixin:
    with open(usersJson_dir) as f:
        data = json.load(f)
        for user in data:
            if user['email'] == email:
                return user
        return None


# -*-*-*-*-* USER TOKEN CHECKER AND GENERATOR *-*-*-*-*-


def generate_user_token(email, token_type: Optional[str] = ""):
    """
    Generates a new user token
    """
    users = load_users()
    for user in users:
        if user.email == email:
            new_token = str(uuid.uuid4())
            if len(user.tokens) == 0:
                log("[genToken] User has no tokens! Adding one...")
            else:
                log(f"[genToken] Requested to generate a new token for user with email {email}")
            user.tokens.append(new_token)
            if token_type == "SaturnianUpdater/DraggieTools" or token_type == "AutoUpdateClient/SaturnianUpdater":
                log(f"[genToken] Allowing trusted token type:  [{token_type}]")
                user.tokens_expiration.append(int(time.time()) + config["trusted_token_expiration_sec"])
                save_users(users)
                log(f"[genToken] Saved trusted user token to be at: {(int(time.time()) + config['trusted_token_expiration_sec'])}")
                # log(f"[debug] User's tokens: {user.tokens}\n[debug] User's token expirations: {user.tokens_expiration}")
                remove_expired_tokens(email)
                return new_token
            elif token_type == "unity/draggiegames-compsciproject":
                log("[genToken] received trusted token from unity project")
                user.tokens_expiration.append(int(time.time()) + config["unity_token_expiration_sec"])# 1year
                save_users(users)
                log(f"[genToken] Saved trusted user token to be at: {(int(time.time()) + config['unity_token_expiration_sec'])}")
                return new_token
            user.tokens_expiration.append(int(time.time()) + config["token_expiration_sec"])
            save_users(users)
            log(f"[genToken] Saved user token to be at: {(int(time.time()) + config['token_expiration_sec'])}")
            # log(f"[debug] User's tokens: {user.tokens}\n[debug] User's token expirations: {user.tokens_expiration}")
            remove_expired_tokens(email)
            return new_token
    return None


def remove_expired_tokens(email) -> int:
    """
    Removes old tokens (work in progress)
    """
    users = load_users()
    for user in users:
        if user.email == email:
            current_token = 0
            valid_tokens = 0
            expired_token_count = 0
            user_validtokens = []
            user_validtokens_expiration = []
            for token in user.tokens:
                length = (len(user.tokens)) - 1
                # log(f"[RemoveExpired] ({current_token}/{length}) Checking token {token} for user with email {email}")
                # log(f"[RemoveExpired] Token expiration: {user.tokens_expiration[current_token]}")
                # log(f"[RemoveExpired] Token: {user.tokens[current_token]} - this should be the same as the one above")
                # log(f"[RemoveExpired] The current time is: {int(time.time())}. The token should be valid until: {user.tokens_expiration[current_token]}")
                if current_token > length:
                    break
                if user.tokens_expiration[current_token] > int(time.time()): # If the token is still valid, we keep it
                    # The current time is: 1685133205. The token should be valid until: 1685223085
                    # log(f"[RemoveExpired] Token {token} for user with email {email} is still valid")
                    log(f"[RemoveExpired] [user: {user.username}] ({current_token}/{length}) is still valid for days: {(user.tokens_expiration[current_token] - int(time.time())) / 86400}")
                    user_validtokens.append(token)
                    user_validtokens_expiration.append(user.tokens_expiration[current_token])
                else: # If the token is expired, we remove it
                    log(f"[RemoveExpired] Token {token} for user with email {email} has expired")
                    expired_token_count = expired_token_count + 1
                current_token = current_token + 1

            # save new tokens
            user.tokens = user_validtokens
            user.tokens_expiration = user_validtokens_expiration
            save_users(users)
            log(f"[RemoveExpired] Removed {expired_token_count} expired tokens for user with email {email}, and saved {valid_tokens} valid tokens")
            return expired_token_count # Return the number of tokens removed (Optional!)
    return 0


def clear_user_token(email) -> str:
    """
    Clears all saved account tokens.
    """
    users = load_users()
    for user in users:
        if user.email == email:  # Loop until the correct valid email is matched
            user.tokens = []
            user.tokens_expiration = []
            save_users(users)
            return ("Successfully cleared the tokens.")
    return ("No user with that email was found.")


def load_user_from_token(session_token) -> User | None:
    """
    Takes in a user's token and returns the approprate user attribute
    """
    # log(f"[LoadUserFromToken] Checking session token passed: {session_token}")
    users_checked = 0
    users = load_users()
    for user in users:
        users_checked = users_checked + 1
        # log(f"Checking user: {user.email}")
        for token in user.tokens:
            if not len(user.tokens) == 0:
                token_count = 0
                # log(f"[debug] Checking token: {token}")
                if token == session_token: # If the session token matches the one in the database
                    if user.tokens_expiration[token_count] > int(time.time()):
                        # log("[LoadUserFromToken] HIT: Session token <redacted> is valid.")
                        # log(f"[debug] Users checked: {users_checked}")
                        # log(f"[debug] Username found: {user.username}")
                        log(f"[LoadUserFromToken] Matched token to user: {user.username}")
                        return user
                    else:
                        log(f"[debug] [LoadUserFromToken] Token {token} has expired.")
                        return None
                else:
                    #log(f"[debug] Token {token} is not the same as {token}")
                    pass
                token_count = token_count + 1
            else:
                log("[LoadUserFromToken] There are no tokens on account")
                return None
    log(f"[debug] [LoadUserFromToken] Checked {users_checked} users. No result")
    return None


def kill_user(email, password) -> None:
    """
    Removes all user data from the database
    """
    log(f"[kill_user] Killing user with email {email}")
    users = load_users()
    for user in users:
        if user.email == email:
            if user.check_password(password):
                log("[kill_user] Found user with matching password")
                users.remove(user)
                save_users(users)
                return jsonify({
                    "message": "User deleted successfully"
                }), 200
            else:
                log(f"[kill_user] User with password {password} not found")
                return jsonify({
                    "message": "User not found"
                }), 404
    log(f"[kill_user] User after forloop with password {password} not found")
    return jsonify({
        "message": "User not found"
    }), 404


@app.route('/delete_account', methods=['DELETE'])
@cross_origin()
def delete_account():
    """
    Deletes the user's account
    """
    log("[deleteaccount] Deleting user account.")
    token = request.json.get('token')
    password = request.json.get('password')
    email = request.json.get('email')
    print(f"token: {token}, password: {password}, email: {email}")
    if token is None:
        return jsonify({
            'message': '[error 1] No token provided',
            'error': True
        }), 401
    user = load_user_from_token(token)
    if user is None:
        return jsonify({
            'message': '[error 2] Invalid token provided. For now, you must be signed in beforehand to delete this account.',
            'error': True
        }), 401
    password = request.json.get('password')
    if password is None:
        return jsonify({
            'message': '[error 3] No password provided',
            'error': True
        }), 401
    if not user.check_password(password):
        return jsonify({
            'message': '[error 4] Invalid password provided',
            'error': True
        }), 401
    x = kill_user(password=password, email=email)
    return x


# check if the token is valid


@app.route('/validate_token', methods=['POST'])
@cross_origin()
def validate_email() -> str:
    """
    Checks if the email-generated validation token is valid. If it is, it will return a 200 status code. If it isn't, it will return a 401 status code.
    Also returns a JSON object with a message and an error boolean, or the user's username and email.
    """
    log("Checking for a valid token.")
    token = request.json.get('token')
    log(f"Email Validation Token: {token}")
    if token is None:
        return jsonify({
            'message': '[error 1] No token provided',
            'error': True
        }), 401
    users = load_users()
    for user in users:
        if user.pending_token == token:
            return jsonify({
                'message': 'Verified successfully. You may close this page now.',
                'error': False,
                'username': user.username,
                'email': user.email
            }), 200
        else:
            return jsonify({
                'message': '[error 2] Invalid token',
                'error': True
            }), 401
    save_users(users)


@app.route('/api/v1/saturnian/game/accountInfo', methods=['GET'])
def get_account_info() -> str:
    token = request.headers.get('Authorisation')
    print(request.headers)
    print(f"token found correctly in headers: {token}")

    if token is None:
        return jsonify({
            'message': 'No access scopes provided',
            'error': True
        }), 401

    user = load_user_from_token(token)
    if not user:
        return jsonify({
            'message': 'No user found with that token',
            'error': True
        }), 401

    return jsonify({
        'message': 'User found successfuly, returnng relevant data',
        'error': False,
        'Username': user.username,
        'Email address': user.email,
        'Codes redeemed': user.codes,
        'Entitlements granted': user.entitlements,
    }), 200


# -*-*-*-*-* ALPHA KEY GET REQ *-*-*-*-*-

# this is the GET KEY!!! DO NOT USE TO REDEEM a new code.
# this is the GET KEY!!! DO NOT USE TO REDEEM a new code.
# this is the GET KEY!!! DO NOT USE TO REDEEM a new code.

@app.route('/api/v1/saturnian/game/gameData/licenses/validation', methods=['GET'])
def fetched_redeemed_license_key() -> str:
    """
    Returns the redeemed codes' license key value. This may be a string URL with access to download the game, or a list if multiple valid codes are on the user's account. Use `/add_code` to add a code, NOT this.
    """
    log("Getting License Key function called.")
    # Get the user's token from request headers or as a URL parameter.
    # This is because HTTP GET requests typically don't have a body (in this case, a JSON dict) (see RFC 2616)
    # Ensuring backwards compatibility with old code with the JSON element.
    # TODO: Will update the old code with the new standard when have the time
    try:
        token = request.json.get('token')
        print(f"token found improperly in json: {token}")
    except Exception:  # TODO: find more pythonic way of doing this
        try:
            token = request.headers.get('Authorisation')
            print(request.headers)
            print(f"token found correctly in headers: {token}")
        except Exception:
            token = request.args.get('token')
            print(request.args)
            print(f"token found correctly in args: {token}")

    # log(f"[debug] Token: {token}")
    if token is None:
        return {
            'message': 'No access scopes provided',
            'error': True
        }, 401

    outdated_message = "\n\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n\n[IMPORTANT MESSAGE]\n\nYour version of this Draggie Games software is out of date and is unable read the new entitlements API. Please update to the latest version at https://tools.draggie.games!\n\nAlternatively, please return to the main menu and check for an update.\n\nAccount functionality will be limited until you update.\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n"

    prepend_message = ""
    useragent = request.headers.get('User-Agent')
    if "DraggieClient" in useragent:
        draggie_client_version = request.headers.get("Draggie-Client-Version")
        if not draggie_client_version or int(draggie_client_version) < 63: # this SHould not be an excaption if it is not defined because 
            log("[licenseKeys] DraggieClient version not found in headers")
            return {
                'message': outdated_message,
                'error': True
            }, 401
    if "DraggieTools" in useragent:
        draggietools_version = request.headers.get("DraggieTools-Version")
        if not draggietools_version:
            log("[licenseKeys] DraggieTools version not found in headers")
            return {
                'message': outdated_message,
                'error': True
            }, 401
        if int(draggietools_version) < 86:
            log(f"[licenseKeys] DraggieTools version {draggietools_version} is too old and we're gonna have to reject the upppdaaTE")
            return {
                'message': outdated_message,
                'error': True
            }, 401

    user = load_user_from_token(token)
    if not user:
        return {
            'message': f'[error 4] Cached token(s) not matched {token}, unable to prove authentication',
            'error': True
        }, 401

    # log(f"[licenseKeys] Saved token from user ID #{user.id} matches inputted token {token}.")
    if user.codes == [] or user.entitlements == []:
        log(f"[licenseKeys] user {user.username} requested to access keys but there are none")
        return {
            'message': '[error 2]: No valid codes are assigned to the user account. You can redeem a code at the web UI',
            'error': True
        }, 401

    entitlements = {}
    for entitlement in user.entitlements:
        print(f"user has entitlement: {entitlement}")
        if entitlement == "saturnian_alpha_tester":
                # 0.5.7: Removed clause stating if the time was not the user token time
                # This was unnecessary as it had such a low chance of occurring
                # We have already authenticated the user before, so there was no point rechecking the token validation time
                log(f"[licenseKeys] User '{user.username}' has entitlement '{entitlement}'")
                entitlements["saturnian_alpha_tester"] = {
                    "currentVersion": os.environ['alpha_build'],                        # An integer version that only increments for each new build - note: this is pulled as a strinfg, so make sure client can chec for this and not expect it as int
                    "currentVersionString": os.environ['alpha_build_versionString'],    # This is prettier than the build number, and is therefore displayed. Whereas the currentVersion is used for integer comparision
                    "downloadUrl": os.environ['alpha_url'],                             # The URL to pass to the cient to download the game.
                    "type": "alpha",                                                    # The type of the build which is kind of redundant but still useful
                    "friendlyName": "Project Saturnian Alpha Test Entitlement",         # This is a human readable name for the entitlement
                    "id": "saturnian_alpha_tester",                                     # Unique ID for the entitlement and it looks more professional!
                    "folderName": "SaturnianGame",                                      # To ensure entitlements are independent, this is the folder name that the game will be downloaded to
                    "executableName": "Saturnian.exe",                                  # The client searches for the exe name in the folder to determine if the game is installed. Will request a complete reinstall if the exe is not found.
                }
        if entitlement == "saturnian_beta_tester":
                log(f"[licenseKeys] User '{user.username}' has entitlement '{entitlement}'")
                entitlements["saturnian_beta_tester"] = {
                    "currentVersion": os.environ['beta_build'],
                    "currentVersionString": os.environ['beta_build_versionString'],
                    "downloadUrl": os.environ['beta_url'],
                    "type": "beta",
                    "friendlyName": "Project Saturnian Beta Test",
                    "id": "saturnian_beta_tester",
                    "folderName": "SaturnianGame",
                    "executableName": "Saturnian.exe",
                }
        if entitlement == "saturnian_internal_dev":
                log(f"[licenseKeys] User '{user.username}' has entitlement '{entitlement}'")
                entitlements["saturnian_internal_dev"] = {
                    "currentVersion": os.environ['internal_build'],
                    "downloadUrl": os.environ['internal_url'],
                    "currentVersionString": "DEV_BRANCH_MAIN",
                    "type": "internal",
                    "friendlyName": "Draggie Games Developer",
                    "id": "saturnian_internal_dev",
                    "folderName": "SaturnianGame",
                    "executableName": "Saturnian.exe",
                }
        if entitlement == "17jaross_game_service":
                log(f"[licenseKeys] User '{user.username}' has entitlement '{entitlement}'")
                entitlements["17jaross_game_service"] = {
                    "currentVersion": os.environ['17jaross_build'],
                    "downloadUrl": os.environ['17jaross_url'],
                    "currentVersionString": "Unknown",
                    "type": "17jaross",
                    "friendlyName": "17jaross Game Service",
                    "id": "17jaross_game_service",
                    "folderName": "17jaross",
                    "executableName": "17jaross.exe",
                }

    if not entitlements:
        log(f"[licenseKeys] User {user.username} requested entitlements but none were found.")
        return {
            'message':
            "[error 2]: No valid authentication scopes have been found for codes on this account's tokens",
            'error': True
        }, 401

    log(f"[licenseKeys] Returning entitlements for user '{user.username}'")
    return {
        'message': f'{prepend_message}Successfully retrieved entitlements for user {user.username}',
        'error': False,
        'entitlements': entitlements
    }, 200



# send email


def get_user_language(email: str) -> str:
    """
    Returns the user's language based on their email, in the form of a 2 letter language code. (e.g. `en` for English, `fr` for French, etc.)\n
    Currently only supports English and French.\n
    """
    users = load_users()
    for user in users:
        if user.email == email:
            return user.language
    return "en"


def send_register_message(email, pending_token, username: Optional[str] = "", language: Optional[str] = "en"):
    """
    Sends an email to the user with a link to verify their email address.\n
    `email`: The user's email address.\n
    `pending_token`: The user's pending token.\n
    `username`: The user's username. (This is optional)\n
    `language`: The language to send the email in. Defaults to English if nothing is passed in.
    """
    log("[RegisterEmail] Sending an email...")
    subject_line = f"Welcome to Draggie Games, {username}!"

    if language == "en":
        register_string = register_string_en
    elif language == "fr":
        register_string = register_string_french
        subject_line = f"Bienvenue chez Draggie Games, {username}!"
    elif language == "shakespeare":
        register_string = register_string_shakespeare
        subject_line = f"Welcometh to Draggie Games, {username}!"
    elif language == "pirate":
        register_string = register_string_pirate
        subject_line = f"Ahoy, {username}! Welcome to Draggie Games!"
    elif language == "pseudo":
        register_string = register_string_pseudocode
        subject_line = "BEGIN H1 TAG with content 'Welcome to Draggie Games!'"
    elif language == "ie": # Irish
        register_string = register_string_irish
        subject_line = f"FÃ¡ilte go dtÃ­ Draggie Games, {username}!"
    elif language == "lolcat":
        register_string = register_string_lolcat
        subject_line = f"WELCOM 2 DRAGGIE GAMEZ, {username.upper()}!!"
    log(f"[RegisterEmail] Subject line (for language): {subject_line}", dedicated_filename="register.log")

    x = requests.post(
        "https://api.eu.mailgun.net/v3/mail.draggiegames.com/messages",
        auth=("api", f"{os.environ['mailgun_api_key']}"),
        data={
            "from": "Draggie Games HQ <register@draggiegames.com>",
            "to": email,
            "subject": subject_line,
            "html": (register_string).format(username, pending_token, email, datetime.datetime.strftime(datetime.datetime.now(), "%d/%m/%Y %H:%M:%S"))
        })
    log(f"[RegisterEmail] Email sent to {email} with status code {x.status_code}", dedicated_filename="register.log")
    return x


# -*-*-*-*-* API REGISTER NEW USER *-*-*-*-*-


@app.route('/register', methods=['POST'])
@cross_origin()
def register() -> str:
    """
    Registers a new user.
    """
    log("[Register] Received a request to register a new user.", dedicated_filename="register.log")
    if not config["register_enabled"]:
        return jsonify({
            'message': 'Registration is currently disabled.',
            'error': True
        }), 503
    log(f"[Register] Request JSON: {request.data}", dedicated_filename="register.log")
    email = request.json.get('email')
    username = request.json.get('username')
    password = request.json.get('password')
    language = request.json.get('language')
    log(f"[Register] Received language as {language}", dedicated_filename="register.log")

    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if not re.match(pattern, email):
        return jsonify({
            'message': f'The email "{email}" entered is not valid, please enter a valid one!',
            'error': True
        }), 400
    users = load_users()
    for user in users:
        if user.email == email or user.username == username:
            return jsonify({
                'message': 'These credentials are already in use. Please try another username, email or password.',
                'error': True,
            }), 400
    user_id = max(user.id for user in users) + 1
    log("Adding user to database")
    log(f"[Register] Adding user to database with ID {user_id}", dedicated_filename="register.log")
    pending_token = str(uuid.uuid4())
    user = User(id=user_id,
                email=email,
                username=username,
                password=generate_password_hash(password),
                verification_pending=True,
                verification_pending_codes=pending_token,
                )
    users.append(user)
    save_users(users)
    if not config["email_processing"]:
        return jsonify({
            'message': f'User email: "{email}" registered successfully. Username: {username}\nEmail sending is currently disabled (this should only be the case during development!)',
            'return_url': 'https://alpha.draggiegames.com/login.html',
            'wait_for': 2500,
        }), 200

    email_response = send_register_message(email=email, username=username, pending_token=pending_token, language=language)
    # Pending token is the unique token that will be used to verify the user's email
    if email_response.status_code == 200:
        email_info_string = "Please check your email for a verification link." # Successfully sent email
    else:
        email_info_string = f"Email sending failed with status code {email_response.status_code}" # TODO: Add a resend button
    log(f"[Register] Received response from Mailgun sending a message to {email}: {email_response.status_code}", dedicated_filename="register.log")
    log(f"[Register] New user registered with email {email} and username {username}", dedicated_filename="register.log")
    return jsonify({
        'message': f'User email: "{email}" registered successfully. Username: {username}\n{email_info_string}',
        'return_url': 'https://alpha.draggiegames.com/login.html',
        "wait_for": 2500, # The corresponding JavaScript will wait for this amount of time before redirecting the user.
    }), 200


@app.route('/verify_email', methods=['POST'])
@cross_origin()
def verify_email() -> str:
    log("[VerifyEmail] Received request to verify email")
    if not config["email_processing"]:
        return jsonify({
            'message': 'Email processing is currently disabled.',
            'error': True
        }), 503
    client_generated_token = request.json.get('token')
    log(f"Verifying email using parsed token {client_generated_token}")
    users = load_users()
    for user in users:
        if user.verification_pending_codes == client_generated_token:#
            if user.verified is True:
                return jsonify({
                    "message": "This account has already been verified!",
                    "redirect_url": "https://alpha.draggiegames.com",
                    "error": True
                }), 403
            # user.verification_pending_codes = True
            user.verified = True
            user.verification_pending = False
            user.verified_date = time.time()
            save_users(users)
            log(f"[VerifyEmail] Successfully verified email for user {user.username} with ID {user.id} and email {user.email} at {user.verified_date}")
            return jsonify({
                "message": f"Successfully verified your email for account <strong>{user.username}</strong>! You can close this page now and return to the login page.",
                "redirect_url": "https://alpha.draggiegames.com/login.html",
                "wait_for": 2500,
            }), 200
    return jsonify({
        "message": "Can't find an account to verify.",
        "error": True,
    }), 404
    

@cache.cached(timeout=60) # TODO: fix cache
@app.route('/api/players', methods=['GET'])
@cross_origin()
def player_count() -> str:
    # log("[API/player_count] Player Count requested.")
    import random
    import math
    import time
    current_time = time.localtime()
    hour = current_time.tm_hour
    minute = current_time.tm_min

    # print(f"Current time is {hour} (hour) and {minute} (minute)")

    # Create a curve for the player count based on the time of day
    # The curve is a sine wave
    # The peak is at 18:00 (6:00 PM)

    if hour > 12:
        hour = hour - 12
    if minute <= 1:
        minute = 3

    time_of_day = hour + (minute / 60)
    # print(f"time of day is {time_of_day}")
    base_count = 400
    # the below sin curve has a period that is too long
    # to make it shorter, multiply the time of day by a number
    # this will make the curve shorter

    fluctuation = math.sin((time_of_day/4) - 7) * 245
    variation = random.randint(-33, -24)

    # depending on minute of the hour, add a random number to the player count
    # this is to simulate the player count changing throughout the hour

    current_players = round(base_count + fluctuation + variation)

    print(f"Generated a player count of {current_players}")

    # format the number
    current_players = "{:,}".format(current_players)

    all_time_players = None
    players_last24h = None
    players_last7d = None

    return jsonify({
        "currentPlayers": current_players,
        "allTimePlayers": all_time_players,
        "playersLast24h": players_last24h,
        "playersLast7d": players_last7d,
        "additionalCss": additionalCss,
    }), 200

additionalCss = """
"""

# API RESET - FROM RESET EMAIL


@app.route('/secured/synthesis/reset', methods=['POST'])
@cross_origin()
def resetting_account() -> str:
    log("[secure_reset] /secured/synthesis/reset hit")
    if not config["reset_accounts"]:
        return jsonify({
            "error": True,
            "message": "Unable to reset accounts at this time, please try again later."
        }), 403
    email = request.json.get("email")
    resettoken = request.json.get("email_secure_token")
    new_password = request.json.get("newpass")
    users = load_users()
    if not resettoken:
        return jsonify({
            "error": True,
            "message": "No secure token provided, please make sure all elements are loaded and the link you clicked is direct.",
        }), 403

    for user in users:
        # log("Checking user")
        #print(user.temp_account_reset_token)
        if user.temp_account_reset_token == resettoken:
            log(f"User {user.username} is about to have their password changed")
            if user.email == email:
                log("ok")
                password = generate_password_hash(new_password)
                user.password = password
                user.temp_account_reset_token = None
                user.tokens = []
                user.tokens_expiration = []
                save_users(users)
                return jsonify({
                    "error": False,
                    "message": "Password change successful. Please login again",
                    "return_url": "/login.html",
                    "wait_for": 2500,
                }), 200
            return jsonify({
                "error": True,
                "message": "Mismatch for object of user attributes  \"temp_account_reset_token\" and \"email\" "
            }), 403
        # don't put anything here
    return jsonify({
        "error": True,
        # Add a really complex, wordy, codey and intricate error message here
        "message": f"No user found with the provided reset token. Please make sure you have the correct link and try again. If this problem persists, please contact support at support@draggiegames.com with the subject line \"Account Reset Error\". Error details: Expected hit on reset token POST, but no user was found with the token UUID4 {resettoken}."
    }), 403
    return jsonify({
        "error": True,
        "message": "auth scope outofbound for uuid object resettoken"
    }), 403


# API RESET EMAILPASSWORD

# This is the one to  REQEST AN EMAIL REQEST AN EMAIL REQEST AN EMAIL REQEST AN EMAIL REQEST AN EMAIL REQEST AN EMAIL
@app.route('/recover_account', methods=['POST'])
@cross_origin()
def recover_account() -> str:
    log("[recover_account] Called /recover_account!", dedicated_filename="recover.log")
    if not config["reset_accounts"]:
        return jsonify({
            "error": True,
            "message": "Unable to reset accounts at this time, please try again later"
        }), 403
    inputted_email = request.json.get("email")
    users = load_users()
    for user in users:
        #log(f"[RecoverAccount] going thru user {user.email}")
        if user.email == inputted_email:
            log(f"[recover_account] Success: Matched email to {user.username}")
            if user.last_time_reset_token is not None:
                log(f"[recover_account] last time reset token is {user.last_time_reset_token}")
                log(f"[recover_account] current time is {time.time()}")
                if float(user.last_time_reset_token) + 60 > float(time.time()): # Wait 60 secs to prevent spam of emails which can drain mailgun allowances for student dev pack
                    log(f"[recover_account] User {user.username} said to reset but it was too soon")
                    return jsonify({
                        "error": True,
                        "message": "Please wait a bit before requesting another reset email!"
                    }), 403
                log("[recover_account] passed timne check")
            temp_password_reset_token = str(uuid.uuid4())
            user.temp_account_reset_token = temp_password_reset_token
            user.last_time_reset_token = f"{time.time()}"
            log(f"[recover_account] Saved user temp account reset token: {temp_password_reset_token}")
            save_users(users)
            email = send_email(email_from="Draggie Games Accounts <accounts-help@draggiegames.com>",
                               send_to=inputted_email,
                               subject="Reset your password",
                               html=(reseetpw_string).format(user.username, temp_password_reset_token, user.email, datetime.datetime.strftime(datetime.datetime.now(), "%d/%m/%Y %H:%M:%S"))
                               )

            if email:
                log(f"[ResetEmail] Email sent to {inputted_email}.")
                return jsonify({
                    "error": False,
                    "message": "A verification email has been set. Check your inbox"
                }), 200
            else:
                log(f"[ResetEmail] Email sent to {inputted_email} with status code {email.status_code}")
                return jsonify({
                    "error": False,
                    "message": "A verification email has been set. Check your inbox"
                }), 200

    # else, all early returns have been exhausted
    log(f"[recover_account] No user found with email {inputted_email}")
    return jsonify({
        "error": True,
        "message": "Sorry but no user was found for that email address",
    }), 404


def send_email(email_from=str, send_to=str, subject=str, html=str):
    log(f"[RegisterEmail] Attempting to send an email to {send_to} with subject {subject}")
    mailgun_api_req = requests.post(
        "https://api.eu.mailgun.net/v3/mail.draggiegames.com/messages",
        auth=("api", f"{os.environ['mailgun_api_key']}"),
        data={
            "from": email_from,
            "to": send_to,
            "subject": subject,
            "html": html,
        }
    )
    log(f"[RegisterEmail] An email has been sent to {send_to}. Subject: {subject}")
    if mailgun_api_req.status_code == 200:
        return mailgun_api_req
    else:
        log(f"[RegisterEmail] Error: {mailgun_api_req}")


reseetpw_string = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Draggie Games - Reset your password</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
        }}

        .container {{
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
            animation: fadeIn 1s;
        }}

        @media (prefers-color-scheme: dark) {{
            body {{
                background: #020031;
                color: #ffffff;
                background: linear-gradient(315deg, #020031 0%, #6d3353 74%);
            }}
            .container {{
                background-color: #020031;
            }}
        }}

        @media (prefers-color-scheme: light) {{
            body {{
                background: #ffffff;
                color: #000000;
                background: linear-gradient(315deg, #ffffff 0%, #eeeeee 74%);
            }}
            .container {{
                background-color: #ffffff;
            }}
            }}



        h1 {{
            color: #ff6600;
            text-align: center;
            animation: bounce 1s infinite;
        }}

        p {{
            line-height: 1.5;
            text-align: justify;
        }}

        .cta-btn {{
            display: block;
            width: 200px;
            margin: 20px auto;
            padding: 10px;
            background-color: #ff6600;
            color: #fff;
            text-align: center;
            text-decoration: none;
            border-radius: 5px;
            box-shadow: 0px 0px 5px rgba(0, 0, 0, 0.3);
            animation: pulse 2s infinite;
        }}

        @keyframes fadeIn {{
            0% {{opacity: 0;}}
            100% {{opacity: 1;}}
        }}
        @keyframes bounce {{
            0%, 20%, 50%, 80%, 100% {{transform: translateY(0);}}
            40% {{transform: translateY(-30px);}}
            60% {{transform: translateY(-15px);}}
        }}
        @keyframes pulse {{
            0% {{transform: scale(0.95);}}
            70% {{transform: scale(1.05);}}
            100% {{transform: scale(0.95);}}
        }}
    </style>
</head>
<body>
    <h1>Draggie Games - Reset your password</h1>
    <p>Hello {0},</p>
    <p>We received a request to reset your password. If you did not request this, you can safely ignore this email.</p>
    <p>To reset your password, please click the following link: <a href="https://alpha.draggiegames.com/secure_reset.html?temp_switch_pass={1}&email={2}">https://alpha.draggiegames.com/secure_reset.html?temp_switch_pass={1}&email={2}</a></p>
    <p>Generated at {3} UTC</p>
    <p>Draggie Games HQ</p>
    <p>Sent to {2}</p>
</body>
</html>
"""

# -*-*-*-*-* ACCOUNTS GET DETAUILS *-*-*-*-*-


@app.route("/account/details", methods=["POST"])
def get_account_details():
    log("[get_account_details] Received request to get account details")
    token = request.json.get("token")
    if not token:
        return jsonify({
            "error": True,
            "message": "No token provided"
        }), 401
    user = load_user_from_token(token)
    if not user:
        return jsonify({
            "error": True,
            "message": "Invalid token provided. Please login again to get a new token"
        }), 401
    log(f"[get_account_details] User {user.username} requested account details")

    # Find when this specific token will expire
    for i in range(len(user.tokens)):
        if user.tokens[i] == token:
            token_expiration = user.tokens_expiration[i]
            break

    return jsonify({
        "error": False,
        "message": "Successfully retrieved account details",
        "username": user.username,
        "id": user.id,
        "email": user.email,
        "verified": user.verified,
        "verified_date": user.verified_date,
        "entitlements": user.entitlements,
        "current_token_expiration": token_expiration,
        "codes_redeemed": user.codes,
        "status": "active",
        "verification_pending": user.verification_pending,
        "user_lang": user.user_lang,
        "last_activity": user.last_activity,
    }), 200

# *-*-*-*-*- API TOKEN LOGIN USER *-*-*-*-*-


@app.route('/token_login', methods=['POST'])
@cross_origin()
def token_login() -> str:
    # log(f"[Login] Received POST request: {request.data}")
    if not config["login_enabled"]:
        return jsonify({
            'message': 'Login is currently disabled.',
            'error': True
        }), 503

    # binary_json = request.json.decode()
    inputted_token = request.json.get('token')
    # log(f"[debug] inputted token: {inputted_token}")

    users = load_users()
    for user in users:
        # log(f"[debug] user: {user.username}")
        for token in user.tokens:
            # log(f"[debug] user token: {token}")
            if token == inputted_token:
                user.last_activity = time.time()
                save_users(users)
                log(f"[token_login] User '{user.username}' just logged in with a token.")
                return jsonify({
                    "message": "Session token confirmed. Logging you in...",
                    "username": user.username,
                    "account": user.username,
                    "email": user.email,
                    'redirect_url': "/",
                }), 200
    log(f"[licenseKeys] An unknown token was used: {inputted_token}")
    return jsonify({
        "error": True,
        "message": "Authentication failed, 404 account token not found. Please login again to get a new token",
    }), 404

# -*-*-*-*-* API LOGIN USER *-*-*-*-*-


@app.route('/login', methods=['POST'])
@cross_origin()
def login() -> str:
    log(f"[Login] Received POST request: {request.data}")
    if not config["login_enabled"]:
        return jsonify({
            'message': 'Login is currently disabled.',
            'error': True
        }), 503

    #print(f"Request: {request}")
    #print(dir(request)) 
    # print all attributes of request and all attributes of these attributes for simplciity
    #for attr in dir(request):
    #     print(attr, getattr(request, attr))
        
    try:
        #raw_json = request.json()
        #print(f"RAW JSON: {raw_json}")
        client_email = request.json.get('email')
        password = request.json.get('password')
    except Exception:
        return jsonify({
            "error": True,
            "message": "To log in, \"email\" and \"password\" keys must be supplied in the JSON data request.",
        }), 500

    log(f"Login-Clientemail: {client_email}. Login-Password {password}")
    users = load_users()    
    for user in users:
        # log(user.email)
        if user.email == client_email:
            # log(f"User email: {user.email} is equal to client email: {client_email}")
            if user.check_password(password):
                log(user.verified)
                if user.verified is False:
                    return jsonify({
                        'message': 'You must verify your account to log in to Draggie Games. Please check your email.',
                        'error': True
                    }), 401

                login_area = request.json.get('from')
                if not login_area:  # use new c# unity compatribility
                    login_area = request.json.get("scope")
                new_token = generate_user_token(client_email, login_area if login_area is not None else None)
                user = load_user(client_email)

                log(f"ID: {user['id']}, User: {user['username']}")
                log(f"[Login] User {user['username']} with ID {user['id']} logged in successfully. Token: {new_token}")

                return jsonify({
                    'message': f"Login successful for account ID #{user['id']} ({user['username']})",
                    'account': user['username'],
                    'auth_token': new_token,
                    'redirect_url': "/",
                }), 200
            else:
                log(f"Is user password correct: {user.check_password(password)}")

                return jsonify({
                    'message': 'Incorrect password.',
                    'error': True
                }), 401

    return jsonify({
        'message': 'Unknown account! Please register one instead, or use your alpha tester credentials.',
        'error': True
    }), 404

# -*-*-*-*-* CHECK CODE *-*-*-*-*-


@app.route('/check_code', methods=['POST'])
@cross_origin()
def check_code() -> str:
    log("[CheckCode] Received request to check a code")
    if not config["code_redeeming"]:
        return jsonify({
            'message': 'Code redeeming is currently disabled.',
            'error': True
        }), 503

    code_to_check = request.json.get("code")

    if not code_to_check:
        return jsonify({
            'message': 'No code was provided.',
            'error': True
        }), 400

    user_token = request.json.get("token")
    code_to_add = request.json.get("code")

    # redeemed_codes
    with open(redeemed_codes_dir, "r") as f:
        redeemed_codes = f.read().split("\n")
    if code_to_add in redeemed_codes:
        return jsonify({
            'message': 'Code has already been redeemed.',
            'error': True,
            'code_valid': False
        }), 400

    if code_to_add == "beans":
        return jsonify({
            'message': 'This code is a valid beans code',
            "entitlement": "beans/None",
            "forwarded_url": "https://raw.githubusercontent.com/Draggie306/DraggieTools/main/dist/DraggieTools.exe",
            "code_valid": True,
            'error': False
        }), 200
    elif code_to_add in alpha_codes:
        return jsonify({
            'message': 'The code inputted is a valid ALPHA code for Project Saturnian.',
            'code_valid': True,
            "entitlement_to_grant": "saturnian_alpha_tester",
            'code_type': 'alpha',
            'error': False
        }), 200
    elif code_to_add in beta_codes:
        return jsonify({
            'message': 'The code inputted is a valid BETA code for Project Saturnian.',
            "entitlement_to_grant": "saturnian_beta_tester",
            'error': False,
            'code_valid': True,
            'code_type': 'beta'
        }), 200
    return jsonify({
        "message": "The code inputted does not exist.",
        "code_valid": False,
        "error": True,
    }), 404

# -*-*-*-*-* ADD C0DE *-*-*-*-*-


# redeems a code to the user account
@app.route('/add_code', methods=['POST'])
@cross_origin()
def add_code() -> str:
    log("[AddCode] Received request to add a code")
    # log(f"Received request to add a code: {request}")
    if not config["code_redeeming"]:
        return jsonify({
            'message': 'Code redeeming is currently disabled.',
            'error': True
        }), 503

    user_token = request.json.get("token")
    code_to_add = request.json.get("code")

    # log(request.json)
    if not user_token:
        return jsonify({
            'message': 'It doesn\'t look like you\'re signed in. Please <a href="/login.html>login</a> again!.',
            'error': True
        }), 401

    users = load_users()

    # redeemed_codes
    with open(redeemed_codes_dir, "r") as f:
        redeemed_codes = f.read().split("\n")  # split by newline
    if code_to_add in redeemed_codes:
        return jsonify({
            'message': 'Code has already been redeemed.',
            'error': True
        }), 400

    def add_code_to_redeeemed_codes(code):
        """
        Writes the code to a new line in the plaintext file.
        No security risks as code has been already redeemed to the user account.
        """
        with open(redeemed_codes_dir, "a") as f:
            f.write(f"{code}\n")

    for user in users:
        # TODO: Add executable to github custom repo for alevel-compsci
        if user_token in user.tokens:
            log(f"[AddCode] Matched token {user_token} to user: {user.username}")
            if code_to_add in user.codes:
                return jsonify({
                    "message": "Code already in redeemed codes of user object",
                    "error": True,
                }), 400
            if code_to_add == "beans":
                return jsonify({
                    'message': f'Entitlement: test beans granted to account ID {user.id}! [{user.email}, {user.username}]',
                    "code_redeem_success": True,
                    "forwarded_url": "https://raw.githubusercontent.com/Draggie306/DraggieTools/main/dist/DraggieTools.exe"
                }), 200
            if code_to_add in alpha_codes:
                user.codes.append(code_to_add)
                user.entitlements.append("saturnian_alpha_tester")
                add_code_to_redeeemed_codes(code_to_add)
                save_users(users)

                return jsonify({
                    'message': f'Entitlement: SATURNIAN - ALPHA TESTER granted to account ID {user.id}! [{user.email}, {user.username}]',
                    "code_redeem_success": True,
                    "forwarded_url": "https://raw.githubusercontent.com/Draggie306/DraggieTools/main/dist/DraggieTools.exe"
                }), 200
            elif code_to_add in beta_codes:
                user.codes.append(code_to_add)
                user.entitlements.append("saturnian_beta_tester")
                add_code_to_redeeemed_codes(code_to_add)
                save_users(users)
                return jsonify({
                    'message': f'Entitlement: SATURNIAN - BETA TESTER granted to account ID {user.id}! [{user.email}, {user.username}]',
                    "code_redeem_success": True,
                    "forwarded_url": "https://raw.githubusercontent.com/Draggie306/DraggieTools/main/dist/DraggieTools.exe"
                }), 200
            else:
                return jsonify({
                    "error:": True,
                    "message": "Unknown code! Make sure you have typed it out exactly.",
                }), 400

    else:
        return jsonify({
            "error": True,
            "message": "An error occurred. Please sign in to your account again."
        }), 404


class ObjectWrapper:
    """Encapsulates S3 object actions."""
    def __init__(self, s3_object):
        """
        :param s3_object: A Boto3 Object resource. This is a high-level resource in Boto3
                          that wraps object actions in a class-like structure.
        """
        self.object = s3_object
        self.key = self.object.key

    def put(self, data):
        """
        Upload data to the object.

        :param data: The data to upload. This can either be bytes or a string. When this
                     argument is a string, it is interpreted as a file name, which is
                     opened in read bytes mode.
        """
        put_data = data
        if isinstance(data, str):
            try:
                put_data = open(data, 'rb')
            except IOError:
                print("Expected file name or binary data, got '%s'.", data)
                raise

        try:
            self.object.put(Body=put_data)
            self.object.wait_until_exists()
            print(
                "Put object '%s' to bucket '%s'.", self.object.key,
                self.object.bucket_name)
        except boto3.ClientError:
            print(
                "Couldn't put object '%s' to bucket '%s'.", self.object.key,
                self.object.bucket_name)
            raise
        finally:
            if getattr(put_data, 'close', None):
                put_data.close()


def get_r2_data():
    """
    Test feature.
    Get the R2 bucket for Saturnian/papers through S3 API boto3.
    """
    print("\n\n[TestFeature] Getting cf r2 bucket storage.")

    endpoint_url = "https://09b65a1a66a15b67892e49451e44dbde.r2.cloudflarestorage.com/papers"
    aws_key_id = os.environ['aws_Access_key_id']
    aws_secret_key_id  = os.environ['aws_access_key_secret']

    print(f"Getting:\n[Endpoint]     {endpoint_url}\n[AWSKeyID]     {aws_key_id}\n[AWSSecretKey] {aws_secret_key_id}")
    
    s3 = boto3.resource('s3',
          endpoint_url = endpoint_url,
          aws_access_key_id = aws_key_id,
          aws_secret_access_key =  aws_secret_key_id,
        )

    for bucket in s3.buckets.all():
        # bucket = s3.Bucket('papers')
    
        print('Objects:')
        for item in bucket.objects.all():
            print(' - ', item.key)

"""    with open("redeemed_codes.txt", "rb") as e:
        f = e.read()
    
    bucket = s3.Bucket("files")
    res = bucket.Object("redeemed_codes.txt").put(Body=f)
    print(f"Uploaded!\n{res}")"""
    
# get_r2_data() # Note: this is classed as Class A requests by Cloudflare which costs more than Class B requests. Only use when debugging/testing please

# google API

@app.route("/oauth/v1", methods=["POST"])
@cross_origin() # TODO: Make this only *.draggiegames.com
def google_signin():
    """
    Uses the Google API returned oAuth value to sign in a user without a password.
    """
    from google.oauth2 import id_token
    from google.auth.transport import requests
    """csrf_token_cookie = request.cookies.get('g_csrf_token')
    if not csrf_token_cookie:
        return jsonify({
            "error": True,
            "message": "No CSRF token in Cookie."
        }), 400"""

    """csrf_token_body = request.form.get('g_csrf_token')
    if not csrf_token_body:
        return jsonify({
            "error": True,
            "message": "No CSRF token in post body."
        }), 400"""
    """if csrf_token_cookie != csrf_token_body:
        return jsonify({
            "error": True,
            "message": "Failed to verify double submit cookie."
        }), 400"""
    token = request.json.get('credential')

    print(request.form.to_dict())
    try:
        # most below is taken from https://developers.google.com/identity/gsi/web/guides/verify-google-id-token?hl=fr
        # Specify the CLIENT_ID of the app that accesses the backend:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), "764536489744-vmj5kubiop5ovlsgrgehvcvur62d7680.apps.googleusercontent.com")

        # Or, if multiple clients access the backend server:
        # idinfo = id_token.verify_oauth2_token(token, requests.Request())
        # if idinfo['aud'] not in [CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]:
        #     raise ValueError('Could not verify audience.')

        # If auth request is from a G Suite domain:
        # if idinfo['hd'] != GSUITE_DOMAIN_NAME:
        #     raise ValueError('Wrong hosted domain.')

        # ID is valid. Get the user's Google Account ID from the decoded token.
        print(idinfo)
        userid = idinfo['sub']
        client_email = idinfo["email"]
        name = idinfo["name"]
        print(client_email, name)
        print(userid)

        username = name.replace(" ", "") + str(random.randint(0, 1000000))

        closewindow = """
        <script>
            window.location.replace("https://alpha.draggiegames.com/login.html");
        </script>
        """

        # return closewindow
        users = load_users()
        for user in users:
            # log(user.email)
            if user.email == client_email:
                # log(f"User email: {user.email} is equal to client email: {client_email}")

                login_area = request.json.get('from')
                new_token = generate_user_token(client_email, login_area if login_area is not None else None)
                user = load_user(client_email)

                log(f"ID: {user['id']}, User: {user['username']}")
                log(f"[Login] User {user['username']} with ID {user['id']} logged in successfully. Token: {new_token}")

                return jsonify({
                    'message': f"Login successful for account ID #{user['id']} ({user['username']})",
                    'account': user['username'],
                    'auth_token': new_token,
                    'redirect_url': "/",
                }), 200

        # If there is no account, make it
        log("[GOOG_LOGIN] [Register] Received a request to register a new user.", dedicated_filename="register.log")
        if not config["register_enabled"]:
            return jsonify({
                'message': 'Registration is currently disabled.',
                'error': True
            }), 503

        password = None
        users = load_users()
        for user in users:
            if user.email == client_email or user.username == username:
                return jsonify({
                    'message': 'These credentials are already in use. Please try another username, email or password.',
                    'error': True,
                }), 400
        user_id = max(user.id for user in users) + 1
        log("Adding user to database")
        log(f"[Register] Adding user to database with ID {user_id}", dedicated_filename="register.log")
        pending_token = str(uuid.uuid4())
        user = User(id=user_id,
                    email=client_email,
                    username=username,
                    password=None,
                    verification_pending=False,
                    verification_pending_codes=pending_token,
                    )
        users.append(user)
        save_users(users)
        if not config["email_processing"]:
            return jsonify({
                'message': f'User email: "{client_email}" registered successfully. Username: {username}\nEmail sending is currently disabled (this should only be the case during development!)',
                'return_url': 'https://alpha.draggiegames.com/login.html',
                'wait_for': 2500,
            }), 200

        email_response = send_register_message(email=client_email, username=username, pending_token=pending_token, language="en")
        # Pending token is the unique token that will be used to verify the user's email
        if email_response.status_code == 200:
            email_info_string = "Please check your email for a verification link." # Successfully sent email
        else:
            email_info_string = f"Email sending failed with status code {email_response.status_code}" # TODO: Add a resend button
        log(f"[Register] Received response from Mailgun sending a message to {client_email}: {email_response.status_code}", dedicated_filename="register.log")
        log(f"[Register] New user registered with email {client_email} and username {username}", dedicated_filename="register.log")
        return jsonify({
            'message': f'User email: "{client_email}" registered successfully. Username: {username}\n{email_info_string}',
            'return_url': 'https://alpha.draggiegames.com/login.html',
            "wait_for": 2500,  # The corresponding JavaScript client-side will wait for this amount of time before redirecting the user.
        }), 200

    except ValueError as e:
        print(f"Invalid token received: {e}, {traceback.format_exc()}")
        # Invalid token
        return jsonify({
            'error': True,
            "message": "Invalid token"
        }), 400
    except Exception as e:
        return e

    return jsonify({
        "error": True,
        "message": "Nothing happened"
    }), 400

# -*-*-*-*-* PROTECTED DATA RETRIEVAL (concept - unused) *-*-*-*-*-


log("Ready to serve!")

# -*-*-*-*-* RUN *-*-*-*-*-

if __name__ == '__main__':
    end_time = time.time()
    log(f"Took {end_time - start_time} seconds to start up. Serving with waitress on port 29171.")
    from waitress import serve # This a production-ready webserver that is much faster than Flask's built-in one.
    serve(app, host="0.0.0.0", port=29171)
    # app.run(host='0.0.0.0', port=29171, debug=False)
    # Port 29171 is the port hat must be unique to this server. As I am running locally on a Raspberry Pi, I have port forwarded 29171 to my Pi's local IP address. 
    # Cloudflare can then proxy requests to the webserver to my hope IP, and my router will forward the request to my Pi.
