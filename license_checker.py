# license_checker.py
import customtkinter
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime

# Same secret key used in create_license.py
key = b'_zyGmWzav0k1Rj3MrJuAYiKnJvFywGU1Xw2-mHCY5gA='
fernet = Fernet(key)

def check_license():
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        LICENSE_PATH = os.path.join(BASE_DIR, "license.lic")

        with open(LICENSE_PATH, "rb") as f:
            encrypted = f.read()
            decrypted = fernet.decrypt(encrypted)

        license_data = json.loads(decrypted)
        expiry = datetime.strptime(license_data["expiry"], "%Y-%m-%d")

        if expiry < datetime.now():
            print("🚫 License expired.")
            return False
        else:
            print("✅ License valid until:", expiry)
            return True
    except Exception as e:
        print("❌ Invalid license:", str(e))
        return False

# Example usage
if not check_license():
    exit("Access denied.")

