# day4_client.py — Data Encryption & Transmission (Day 4 / Labs 0, 1, 9)
# Encrypts architect_manifesto.txt with Fernet, connects to the server,
# passes MFA credentials, then transmits the encrypted payload.

import socket
import pyotp
from cryptography.fernet import Fernet
from config import HOST, PORT, PASSWORD, TOTP_SECRET, MANIFEST_FILE, FERNET_KEY_FILE


# ── Key management ────────────────────────────────────────────────────────────

def generate_and_save_key() -> bytes:
    """Generate a new Fernet key and persist it so the server can share it."""
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, 'wb') as f:
        f.write(key)
    print(f"[+] New Fernet key saved to: {FERNET_KEY_FILE}")
    return key


def load_key() -> bytes:
    """Load an existing Fernet key, or create one if it does not exist."""
    try:
        with open(FERNET_KEY_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print("[*] No key file found — generating a new one.")
        return generate_and_save_key()


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt_file(key: bytes, filepath: str) -> bytes:
    """Read a file and return its Fernet-encrypted bytes."""
    fernet = Fernet(key)
    with open(filepath, 'rb') as f:
        return fernet.encrypt(f.read())


# ── Transmission ──────────────────────────────────────────────────────────────

def send_evidence() -> None:
    # 1. Encrypt the manifesto
    key            = load_key()
    encrypted_data = encrypt_file(key, MANIFEST_FILE)
    print(f"[+] Manifest encrypted ({len(encrypted_data)} bytes).")

    # 2. Generate the current TOTP token
    totp  = pyotp.TOTP(TOTP_SECRET)
    token = totp.now()
    print(f"[*] OTP generated: {token}")

    # 3. Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")

        # 4. Send credentials as "PASSWORD|OTP" in a single message
        credentials = f"{PASSWORD}|{token}"
        s.sendall(credentials.encode())

        # 5. Wait for MFA result
        response = s.recv(1024)
        if response != b'AUTH_OK':
            print("[-] Authentication failed. Aborting transmission.")
            return

        print("[+] MFA accepted. Sending encrypted payload ...")

        # 6. Transmit the encrypted file
        s.sendall(encrypted_data)
        # Closing the socket signals end-of-stream to the server
        print("[+] Transmission complete.")


if __name__ == '__main__':
    send_evidence()
