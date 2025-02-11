import json
import os
import requests
import sys
from getpass import getpass
from cryptography.fernet import Fernet
import time
from datetime import datetime

# Utility function for logging
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
    """Load the secret key specific to the user from the '.keys' directory or generate it if it doesn't exist."""
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
    """Encrypt the password and save it to a user-specific file in the '.keys' directory."""
    keys_dir = ensure_keys_directory()
    enc_file = os.path.join(keys_dir, f"{IdmcUserName}_encryptedIDMCpassword")
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    with open(enc_file, 'wb') as enc_file_out:
        enc_file_out.write(encrypted_password)
    print_log(f"Password encrypted and saved securely for user '{IdmcUserName}' in '.keys'.", "🔐")

def decrypt_password(key, IdmcUserName):
    """Decrypt the user-specific password from the '.keys' directory."""
    keys_dir = ensure_keys_directory()
    enc_file = os.path.join(keys_dir, f"{IdmcUserName}_encryptedIDMCpassword")
    fernet = Fernet(key)
    with open(enc_file, 'rb') as enc_file_in:
        encrypted_password = enc_file_in.read()
    return fernet.decrypt(encrypted_password).decode()

def get_password(IdmcUserName):
    """Retrieve the user-specific password securely, using the '.keys' directory."""
    key = load_key(IdmcUserName)
    keys_dir = ensure_keys_directory()
    enc_file = os.path.join(keys_dir, f"{IdmcUserName}_encryptedIDMCpassword")
    if os.path.exists(enc_file):
        print_log(f"Decrypting saved password for user '{IdmcUserName}'...", "🔓")
        return decrypt_password(key, IdmcUserName)
    else:
        print_log(f"No saved password found for user '{IdmcUserName}'. Prompting for password...", "🛡️")
        password = getpass(f"Enter Password for '{IdmcUserName}': ")
        encrypt_password(password, key, IdmcUserName)
        return password


def invoke_login():
    print_log("Reading configuration file...", "📄")
    config = read_config('cdgc.conf.txt')
    IdmcUserName = config['IdmcUserName']
    idmcURL = config['idmcURL']

    print_log("Prompting for password...", "🛡️")
    password = get_password(IdmcUserName)

    print_log("Logging in to IDMC...", "🌐")
    url = f"https://{idmcURL}/identity-service/api/v1/Login"
    headers = {'Content-Type': 'application/json'}
    body = {'username': IdmcUserName, 'password': password}

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

def search_export_assets(orgId, jwt_token, cdgcAPIurl, IdmcknowledgeQuery, idmcExportFileName):
    print_log("Initiating export job...", "📦")
    ## url = f'https://{cdgcAPIurl}/data360/search/export/v1/assets?knowledgeQuery={IdmcknowledgeQuery}&segments=summary,customAttributes&fileName={idmcExportFileName}&summaryViews=all'
    url = f'https://{cdgcAPIurl}/data360/search/export/v1/assets?knowledgeQuery={IdmcknowledgeQuery}&segments=all&fileName={idmcExportFileName}'
    headers = {
        'X-INFA-ORG-ID': orgId,
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {jwt_token}'
    }
    data = {"from": 0, "size": 10000}

    response = requests.post(url, headers=headers, data=json.dumps(data))
    response_data = response.json()
    jobId = response_data.get('jobId')
    
    if not jobId:
        print_log("Export job initiation failed.", "❌")
        exit(1)

    print_log(f"Export job initiated successfully. Job ID: {jobId}", "✅")
    return jobId

def get_job_status(orgId, jwt_token, cdgcAPIurl, jobId):
    print_log("Checking job status...", "🔍")
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

def download_exported_file(orgId, jwt_token, cdgcAPIurl, jobId, idmcExportFileName):
    print_log("Downloading exported file...", "📥")
    url = f'https://{cdgcAPIurl}/data360/observable/v1/jobs/{jobId}/outputProperties/files/Export_File'
    headers = {
        'X-INFA-ORG-ID': orgId,
        'Authorization': f'Bearer {jwt_token}'
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        file_name_with_extension = f"{idmcExportFileName}.xlsx"
        with open(file_name_with_extension, 'wb') as file:
            file.write(response.content)
        print_log(f"File downloaded successfully: {file_name_with_extension}", "✅")
    else:
        print_log(f"Failed to download file. HTTP Status: {response.status_code}", "❌")

print_log("Starting CDGC search and export process...", "🚀")
sessionId, sessionExpireTime, orgId = invoke_login()

config = read_config('cdgc.conf.txt')
jwt_token = get_jwt_token(sessionId, config['idmcURL'])
jobId = search_export_assets(orgId, jwt_token, config['cdgcAPIurl'], config['IdmcknowledgeQuery'], config['idmcExportFileName'])

status = None
while status not in ["FAILED", "COMPLETED"]:
    time.sleep(int(config['idmcStatusCheckIntervalInSec']))
    status = get_job_status(orgId, jwt_token, config['cdgcAPIurl'], jobId)

if status == "COMPLETED":
    download_exported_file(orgId, jwt_token, config['cdgcAPIurl'], jobId, config['idmcExportFileName'])

print_log("Process completed.", "🏁")
