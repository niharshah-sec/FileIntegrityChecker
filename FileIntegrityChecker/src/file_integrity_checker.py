import os
import hashlib
import json
import time
from plyer import notification  # 🆕 For desktop notifications

# 🌟 Auto-create test folder and sample files
def setup_test_folder(folder_path):
    if not os.path.exists(folder_path):
        print(f"📂 '{folder_path}' not found. Creating it with sample files...")
        os.makedirs(folder_path)
        with open(os.path.join(folder_path, "file1.txt"), "w") as f:
            f.write("This is file 1.\n")
        with open(os.path.join(folder_path, "file2.txt"), "w") as f:
            f.write("This is file 2.\n")
        print("✅ Sample files created: file1.txt, file2.txt")
    else:
        print(f"📂 '{folder_path}' already exists. Skipping creation.")

# 🌟 Calculate hash
def calculate_hash(file_path, algorithm="sha1"):
    hash_func = getattr(hashlib, algorithm)()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# 🌟 Perform scan and compare hashes
def scan_directory(folder_path, algo, previous_hashes):
    current_hashes = {}

    for root, _, files in os.walk(folder_path):
        for name in files:
            file_path = os.path.join(root, name)
            file_hash = calculate_hash(file_path, algo)
            relative_path = os.path.relpath(file_path, folder_path)
            current_hashes[relative_path] = file_hash

    modified = []
    new = []
    deleted = []

    for file, hash_value in current_hashes.items():
        if file not in previous_hashes:
            new.append(file)
        elif previous_hashes[file] != hash_value:
            modified.append(file)

    for file in previous_hashes:
        if file not in current_hashes:
            deleted.append(file)

    return current_hashes, modified, new, deleted

# 🌟 Save hashes to JSON
def save_hashes(hash_file, hashes):
    with open(hash_file, "w") as f:
        json.dump(hashes, f, indent=4)

# 🌟 Send Windows desktop notification
def send_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        timeout=5  # seconds
    )

# 🌟 On-demand scan
def on_demand_scan(folder_path, algo, hash_file):
    print(f"🔍 Running on-demand scan for {folder_path} using {algo.upper()}...")
    previous_hashes = {}
    if os.path.exists(hash_file):
        with open(hash_file, "r") as f:
            previous_hashes = json.load(f)

    current_hashes, modified, new, deleted = scan_directory(folder_path, algo, previous_hashes)

    if modified or new or deleted:
        print("⚠️ Changes detected:")
        for f in modified:
            print(f"✏️ Modified: {f}")
        for f in new:
            print(f"➕ New: {f}")
        for f in deleted:
            print(f"❌ Deleted: {f}")

        # 🔔 Send notification
        change_summary = f"{len(modified)} modified, {len(new)} new, {len(deleted)} deleted"
        send_notification("File Integrity Checker", f"Changes detected: {change_summary}")
    else:
        print("✅ No changes detected.")
        send_notification("File Integrity Checker", "No changes detected.")

    save_hashes(hash_file, current_hashes)
    print("💾 Hashes updated.")

# 🌟 Real-time monitoring
def real_time_monitoring(folder_path, algo, hash_file, interval=5):
    print(f"👀 Watching {folder_path} every {interval}s for changes using {algo.upper()}...")
    previous_hashes = {}
    if os.path.exists(hash_file):
        with open(hash_file, "r") as f:
            previous_hashes = json.load(f)

    try:
        while True:
            current_hashes, modified, new, deleted = scan_directory(folder_path, algo, previous_hashes)

            if modified or new or deleted:
                print("\n⚡ Real-time change detected!")
                for f in modified:
                    print(f"✏️ Modified: {f}")
                for f in new:
                    print(f"➕ New: {f}")
                for f in deleted:
                    print(f"❌ Deleted: {f}")

                # 🔔 Send notification
                change_summary = f"{len(modified)} modified, {len(new)} new, {len(deleted)} deleted"
                send_notification("File Integrity Checker", f"Real-time change: {change_summary}")

                save_hashes(hash_file, current_hashes)
                previous_hashes = current_hashes
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n🛑 Stopped real-time monitoring.")

# 🌟 Main menu
def main():
    folder_path = input("Enter directory path to monitor (default F:\\TestFolder): ") or "F:\\TestFolder"
    setup_test_folder(folder_path)

    algo = input("Enter hash algorithm (md5/sha1/sha256) [default: sha1]: ").lower() or "sha1"
    if algo not in ["md5", "sha1", "sha256"]:
        print("❌ Invalid algorithm. Using default: sha1")
        algo = "sha1"

    hash_file = "hashes.json"

    print("\nChoose mode:")
    print("1️⃣  On-Demand Scan")
    print("2️⃣  Real-Time Monitoring")
    choice = input("Enter choice (1/2): ").strip()

    if choice == "1":
        on_demand_scan(folder_path, algo, hash_file)
    elif choice == "2":
        interval = input("Enter check interval in seconds [default: 5]: ").strip()
        interval = int(interval) if interval.isdigit() else 5
        real_time_monitoring(folder_path, algo, hash_file, interval)
    else:
        print("❌ Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
