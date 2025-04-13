import frida
import time
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(SCRIPT_DIR, "supported_devices.csv")
FRIDA_SCRIPT_PATH = os.path.join(SCRIPT_DIR, "hookedMessage.js")
APP_ID = "Null Vastation"


def load_devices_from_csv(csv_path):
    devices = []
    with open(csv_path, "r", encoding="utf-8") as f: # encoding="latin-1"
        next(f)  # skip header
        for line in f:
            line = line.strip()
            line = line.split(",")
            brand = line[0].strip().lower()
            brand = brand.replace('"', '').replace("'", "")
            model = line[-1].strip().strip('"')
            model = model.replace('"', '').replace("'", "")
            
            if brand and model:
                devices.append({"brand": brand, "model": model})
                
    return devices


def on_message(message, data):
    if message["type"] == "send":
        print("[*] " + message["payload"])
    elif message["type"] == "error":
        print("[!] Error:", message["stack"])


def main():
    print("[*] Loading devices...")
    devices = load_devices_from_csv(CSV_PATH)
    print(f"[*] Loaded {len(devices)} devices from CSV")

    if not devices:
        print("[-] No devices found, exiting.")
        return

    print("[*] Spawning app...")
    device = frida.get_usb_device()
    session = device.attach(APP_ID)

    print("[*] Loading Frida script...")
    with open(FRIDA_SCRIPT_PATH, encoding="utf-8") as f:
        script = session.create_script(f.read())

    script.on("message", on_message)
    script.load()

    # Send devices before resuming the app
    script.exports.loaddevices(devices)
    print("[*] Devices sent to Frida script. ✅")

    print("[*] Script running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Exiting...")


if __name__ == "__main__":
    main()
