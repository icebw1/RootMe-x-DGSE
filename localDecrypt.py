import os
import re
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


STATIC_IV = base64.b64decode("LJo+0sanl6E3cvCHCRwyIg==")
STATIC_SALT = "s3cr3t_s@lt"


def hash_device_id(model, brand):
    to_hash = f"{model}:{brand}"
    return base64.b64encode(hashlib.sha256(to_hash.encode("utf-8")).digest()).decode()

def derive_key(device_id, salt):
    to_hash = f"{device_id}:{salt}"
    return hashlib.sha256(to_hash.encode("utf-8")).digest()

def decrypt_message(encrypted_b64, model, brand):
    try:
        device_id = hash_device_id(model, brand)
        key = derive_key(device_id, STATIC_SALT)
        cipher = AES.new(key, AES.MODE_CBC, STATIC_IV)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_b64))
        return unpad(decrypted, AES.block_size).decode("utf-8")
    except Exception:
        return None

def load_devices(csv_path):
    devices = []
    seen = set()
    with open(csv_path, "r", encoding="utf-8") as f: # CSV file must be in CSV (UTF-8) format otherwise, try encoding="latin-1"
        for line in f:
            line = line.strip()
            line = line.split(",")
            brand = line[0].strip().lower()
            brand = brand.replace('"', '').replace("'", "")
            brand = re.sub(r'[^a-zA-Z0-9]', '', brand)
            model = line[-1].strip().strip('"')
            model = model.replace('"', '').replace("'", "")
            
            # print(f"line : {line}")
            # print(f"brand : {brand}, model : {model}")
            
            key = f"{brand.lower()}|{model}"
            if key not in seen:
                seen.add(key)
                devices.append((model, brand))
    return devices


if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    CSV_PATH = os.path.join(SCRIPT_DIR, "supported_devices.csv")
    devices = load_devices(CSV_PATH)
    
    print(f"[*] Loaded {len(devices)} unique devices from CSV")

    encrypted_msg = "M2geCVKOzPlyug9p9DvthxPip0oe9BPiT2sDfFhWy7iC3+JQI4SfO7+SLAlFSUmu8LoGj1hrUWil/uNXvc+5mKBMrRNFQT8ijBK14P0Z8qA=" # First encrypted message on the app

    for i, (model, brand) in enumerate(devices):
        result = decrypt_message(encrypted_msg, model, brand)
        if result and "old device credentials" not in result:
            print(f"[+] Found valid combo: {brand} / {model}")
            print(f"    ➤ Message: {result}")
            if "RM{" in result:
                print("🚩 FLAG FOUND : ", result)
            else:
                print("result : ", result)
            break
