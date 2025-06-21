# create_license.py
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import json

# Replace this with your actual key
key = b'_zyGmWzav0k1Rj3MrJuAYiKnJvFywGU1Xw2-mHCY5gA='
fernet = Fernet(key)

license_data = {
    "user": "user@example.com",
    "expiry": (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
}

encrypted = fernet.encrypt(json.dumps(license_data).encode())

with open("license.lic", "wb") as f:
    f.write(encrypted)

print("License file generated successfully.")
