import json
import os
import requests
from getpass import getpass
from cryptography.fernet import Fernet
import time
from datetime import datetime
import sys

# Function to print formatted log messages with timestamps and emojis
def print_log(message, emoji="INFO"):
    """
    Logs a message with a timestamp and optional emoji.
    Falls back to plain text if encoding issues arise.
    """
    try:
        emoji = emoji.encode("ascii", "ignore").decode("ascii") if not sys.stdout.encoding.startswith("utf") else emoji
    except UnicodeEncodeError:
        emoji = "INFO"  # Fallback if encoding fails

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {emoji} {message}")

def read_config(file_path):
    config = {}
    print_log("Reading configuration from file...", "📄")
    with open(file_path, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')
            config[key.strip()] = value.strip()
    print_log("Configuration successfully loaded.", "✅")
    return config

# Ensure the ".keys" directory exists
def ensure_keys_directory():
    keys_dir = ".keys"
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        print_log(f"Created '.keys' directory for storing encryption keys and passwords.", "📁")
    return keys_dir

def load_key(IdmcUserName):
    keys_dir = ensure_keys_directory()
    key_file = os.path.join(keys_dir, f"{IdmcUserName}_secret.key")
    if not os.path.exists(key_file):
        print_log(f"Generating encryption key for user '{IdmcUserName}'...", "🔑")
        key = Fernet.generate_key()
        with open(key_file, 'wb') as key_out:
            key_out.write(key)
        print_log(f"Encryption key generated and saved for user '{IdmcUserName}' in '.keys'.", "✅")
    else:
        print_log(f"Loading encryption key for user '{IdmcUserName}' from '.keys'.", "🔒")
        with open(key_file, 'rb') as key_in:
            key = key_in.read()
    return key

def encrypt_password(password, key, IdmcUserName):
    keys_dir = ensure_keys_directory()
    enc_file = os.path.join(keys_dir, f"{IdmcUserName}_encryptedIDMCpassword")
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    with open(enc_file, 'wb') as enc_file_out:
        enc_file_out.write(encrypted_password)
    print_log(f"Password encrypted and saved securely for user '{IdmcUserName}' in '.keys'.", "🔐")

def decrypt_password(key, IdmcUserName):
    keys_dir = ensure_keys_directory()
    enc_file = os.path.join(keys_dir, f"{IdmcUserName}_encryptedIDMCpassword")
    fernet = Fernet(key)
    with open(enc_file, 'rb') as enc_file_in:
        encrypted_password = enc_file_in.read()
    return fernet.decrypt(encrypted_password).decode()

def get_password(IdmcUserName):
    key = load_key(IdmcUserName)
    enc_file = os.path.join(".keys", f"{IdmcUserName}_encryptedIDMCpassword")
    if os.path.exists(enc_file):
        print_log(f"Decrypting saved password for user '{IdmcUserName}'...", "🔓")
        return decrypt_password(key, IdmcUserName)
    else:
        print_log(f"No saved password found for user '{IdmcUserName}'. Prompting for password...", "🛡️")
        password = getpass(f"Enter Password for '{IdmcUserName}': ")
        encrypt_password(password, key, IdmcUserName)
        return password

def invoke_login():
    config = read_config('cdgc.conf.txt')
    IdmcUserName = config['IdmcUserName']
    idmcURL = config['idmcURL']

    print_log("Logging in to IDMC...", "🌐")
    url = f"https://{idmcURL}/identity-service/api/v1/Login"
    headers = {'Content-Type': 'application/json'}
    body = {'username': IdmcUserName, 'password': get_password(IdmcUserName)}

    response = requests.post(url, headers=headers, data=json.dumps(body))
    response_data = response.json()

    sessionId = response_data.get('sessionId')
    if not sessionId:
        print_log("Error: Login failed. 'sessionId' is empty.", "❌")
        print_log(f"Response Body: {json.dumps(response_data, indent=2)}", "📝")
        exit(1)

    print_log(f"Login successful. Session ID: {sessionId}", "✅")
    return sessionId, response_data.get('sessionExpireTime'), response_data.get('orgId')

def get_jwt_token(sessionId, idmcURL):
    print_log("Requesting JWT token...", "🔑")
    url = f'https://{idmcURL}/identity-service/api/v1/jwt/Token?client_id=idmc_api&nonce=1234'
    headers = {'IDS-SESSION-ID': sessionId}

    response = requests.post(url, headers=headers)
    response_data = response.json()

    jwt_token = response_data.get('jwt_token')
    if not jwt_token:
        print_log("Failed to retrieve JWT token.", "❌")
        exit(1)
    
    print_log(f"JWT Token received: {jwt_token}", "✅")
    return jwt_token

def perform_cdgc_import(orgId, jwt_token, cdgcAPIurl, file_path):
    """
    Perform the CDGC import API call to import enriched data.
    """
    print_log(f"Starting CDGC import for file '{file_path}'...", "📤")
    
    url = f"https://{cdgcAPIurl}/data360/content/import/v1/assets"
    
    # Files and config payload for the API
    files = [
        ('file', (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')),
        ('config', (None, json.dumps({"validationPolicy": "CONTINUE_ON_ERROR_WARNING"}), 'application/json'))
    ]
    
    # Headers
    headers = {
        'X-INFA-ORG-ID': orgId,
        'Authorization': f'Bearer {jwt_token}'
    }

    # Perform the POST request
    response = requests.post(url, headers=headers, files=files)

    # Check and handle the response
    try:
        response_data = response.json()
    except ValueError:
        print_log(f"CDGC import failed. Non-JSON response received: {response.text}", "❌")
        return None

    if response.status_code in [200, 202]:  # Treat 202 as a valid response for async job
        jobId = response_data.get('jobId')
        if jobId:
            print_log(f"CDGC import started successfully. Job ID: {jobId}", "✅")
            return jobId
        else:
            print_log(f"CDGC import failed. Response: {response_data}", "❌")
            return None
    else:
        print_log(f"CDGC import failed. HTTP Status: {response.status_code}. Response: {response_data}", "❌")
        return None


def get_job_status(orgId, jwt_token, cdgcAPIurl, jobId):
    print_log(f"Checking job status for Job ID: {jobId}...", "🔍")
    url = f'https://{cdgcAPIurl}/data360/observable/v1/jobs/{jobId}?expandChildren=TASK-HIERARCHY&expandChildren=OUTPUT-PROPERTIES'
    headers = {
        'X-INFA-ORG-ID': orgId,
        'Authorization': f'Bearer {jwt_token}'
    }

    response = requests.get(url, headers=headers)
    response_data = response.json()
    status = response_data.get('status')

    print_log(f"Job Status: {status}", "ℹ️")
    return status

# Main script logic
print_log("Starting CDGC process...", "🚀")
sessionId, sessionExpireTime, orgId = invoke_login()

config = read_config('cdgc.conf.txt')
jwt_token = get_jwt_token(sessionId, config['idmcURL'])

base_file_name = config['idmcExportFileName']
enriched_file_path = f"{base_file_name}_enriched.xlsx"

jobId = perform_cdgc_import(orgId, jwt_token, config['cdgcAPIurl'], enriched_file_path)

if jobId:
    status = None
    while status not in ["FAILED", "COMPLETED", "PARTIAL_COMPLETED"]:
        time.sleep(int(config['idmcStatusCheckIntervalInSec']))
        status = get_job_status(orgId, jwt_token, config['cdgcAPIurl'], jobId)

    if status == "COMPLETED":
        print_log("CDGC import job completed successfully.", "🏁")
    else:
        print_log("CDGC import job failed.", "❌")
else:
    print_log("No Job ID returned. Import process could not start.", "❌")

print_log("CDGC process completed.", "🏁")
