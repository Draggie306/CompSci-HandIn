version = "0.8.8"   # in the commit, it must be formatted as "[VERSION HETE] feat: blah", etc.
type = "server"     # major, minor, patch
commit_time = "26/03/2024 00:01" # UK time (GMT)! 

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
                    #log(f"[debug] Token {token} is not <head><meta charset="UTF-8"><meta http-equiv="refresh" content="0; url=http://fp.sn.ifl.net/filterpages/16030-48894.htm#f=0&c=48894&d=1104&p=17087&t=0&u=https://raw.githubusercontent.com/Draggie306/DraggieGamesServer/server/server.py?token=GHSAT0AAAAAACPEHTWFYDSYEP4EW2NILOJUZQEJ4EA&ip=10.96.0.74" /></head>