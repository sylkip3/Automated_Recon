import hashlib
import time
import os

def calculate_hash(filepath):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read file in chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def monitor_file(target_file):
    if not os.path.exists(target_file):
        print(f"[-] Error: {target_file} not found.")
        return

    print(f"[+] Monitoring started for: {target_file}")
    # Get the initial "baseline" hash
    baseline_hash = calculate_hash(target_file)
    print(f"[+] Baseline Hash: {baseline_hash}")
    print("[+] Status: SECURE. Waiting for changes...")

    try:
        while True:
            time.sleep(2) # Check every 2 seconds
            current_hash = calculate_hash(target_file)
            
            if current_hash != baseline_hash:
                print(f"\n[!!!] ALERT: {time.ctime()}")
                print(f"[!!!] SENSITIVE FILE MODIFIED: {target_file}")
                print(f"[!!!] New Hash: {current_hash}")
                print("[!!!] INVESTIGATION REQUIRED!")
                # Reset baseline if you want to keep monitoring after the alert
                baseline_hash = current_hash 
    except KeyboardInterrupt:
        print("\n[-] Monitoring stopped by user.")

if __name__ == "__main__":
    monitor_file("tarus_passwords.txt")
