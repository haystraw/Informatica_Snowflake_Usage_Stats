import snowflake.connector
import pandas as pd
import os
from cryptography.fernet import Fernet
from getpass import getpass
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

# Function to read configuration from a file
def read_config(file_path):
    """Reads a config file with stanza (INI-like) formatting, preserving multi-line sections."""
    config = {}
    ## print_log("Reading configuration from file...", "📄")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            current_key = None  # Track the last section (e.g., [query])
            current_value = []  # Store multi-line values

            for line in file:
                line = line.rstrip()  # Keep indentation for SQL blocks

                # Skip empty lines and comments (lines starting with # or ;)
                if not line or line.startswith(("#", ";")):
                    continue

                # Detect section headers (e.g., [query])
                if line.startswith("[") and line.endswith("]"):
                    # Save the previous section's content before moving to the next
                    if current_key:
                        config[current_key] = "\n".join(current_value).strip()

                    # Start tracking new section
                    current_key = line[1:-1].strip()  # Remove brackets
                    current_value = []
                    continue

                # Handle key-value pairs (e.g., role=ACCOUNTADMIN)
                if "=" in line and not current_key:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
                    continue

                # If inside a section, append multi-line content
                if current_key:
                    current_value.append(line)

            # Store the last section's content
            if current_key:
                config[current_key] = "\n".join(current_value).strip()

    except FileNotFoundError:
        print_log(f"❌ Error: Config file not found: {file_path}", "‼️")
    except Exception as e:
        print_log(f"❌ Error reading config file: {str(e)}", "‼️")

    try:
        ## Replace tokens in query
        this_database = config['database']
        this_schema = config['schema']
        current_query = config['query']
        new_query = current_query.replace('XXX_DATABASE_XXX', this_database).replace('XXX_SCHEMA_XXX', this_schema)
        config['query'] = new_query
    except:
        pass

    return config





# Function to generate and save encryption key
def generate_key():
    if not os.path.exists("secret.key"):
        print_log("Generating encryption key...", "🔑")
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        print_log("Encryption key generated and saved.", "✅")

# Function to load encryption key
def load_key():
    if not os.path.exists("secret.key"):
        generate_key()
    print_log("Loading encryption key...", "🔒")
    return open("secret.key", "rb").read()

# Function to encrypt a message
def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    print_log("Password encrypted.", "🔐")
    return encrypted_message

# Function to decrypt a message
def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    print_log("Password decrypted.", "🔓")
    return decrypted_message

# Handle password securely per user
def get_password(user):
    password_file = f"{user}_password.enc"
    if os.path.exists(password_file):
        print_log(f"Loading encrypted password for user '{user}'...", "🔄")
        with open(password_file, 'rb') as file:
            encrypted_password = file.read()
        password = decrypt_message(encrypted_password)
        print_log("Password successfully loaded and decrypted.", "✅")
        return password
    else:
        print_log(f"No saved password found for user '{user}'. Prompting for password...", "🛡️")
        password = getpass(f"Enter password for Snowflake user '{user}': ")
        print_log("Encrypting and saving password...", "🔑")
        encrypted_password = encrypt_message(password)
        with open(password_file, 'wb') as file:
            file.write(encrypted_password)
        print_log("Password saved securely.", "✅")
        return password

# Connect to Snowflake
def connect_to_snowflake(config, password):
    print_log("Connecting to Snowflake...", "🌐")
    connection = snowflake.connector.connect(
        account=config['account'],
        user=config['user'],
        password=password,
        warehouse=config['warehouse'],
        database=config['database'],
        schema=config['schema'],
        role=config.get('role')  # Optional
    )
    print_log("Successfully connected to Snowflake.", "✅")
    return connection

# Execute the query and fetch results
def execute_query(connection, query):
    print_log(f"Executing query:\n{query}", "🔍")
    with connection.cursor() as cursor:
        cursor.execute(query)
        result = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        print_log(f"Query executed successfully. Retrieved {len(result)} rows.", "✅")
        return result, columns

# Save results to CSV
def save_to_csv(result, columns, output_file):
    print_log(f"Saving results to {output_file}...", "💾")
    df = pd.DataFrame(result, columns=columns)
    df.to_csv(output_file, index=False)
    print_log(f"Results saved to {output_file}.", "✅")

# Main function
def main():
    print_log("Starting Snowflake query process...", "🚀")
    try:
        # Read configuration
        config = read_config('snowflake.conf.txt')
        
        user = config['user']

        # Get password securely
        password = get_password(user)

        # Connect to Snowflake
        connection = connect_to_snowflake(config, password)

        # Execute the query
        query = config['query']
        result, columns = execute_query(connection, query)

        # Save results to CSV
        output_file = config.get('output_file', 'output.csv')
        save_to_csv(result, columns, output_file)

        # Close the connection
        print_log("Closing Snowflake connection...", "🔗")
        connection.close()
        print_log("Connection closed. Process completed successfully.", "🏁")

    except Exception as e:
        print_log(f"An error occurred: {e}", "❌")

if __name__ == "__main__":
    main()
