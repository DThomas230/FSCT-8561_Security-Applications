# day4_server.py — Receiver & MFA Gateway (Day 4 / Lab 9)
# Listens for an incoming client, enforces MFA, receives the encrypted
# payload, decrypts it, and saves the plain-text manifesto.

import socket
from cryptography.fernet import Fernet
from day2_mfa_gateway import verify_mfa
from config import HOST, PORT, FERNET_KEY_FILE, DECRYPTED_FILE

BUFFER_SIZE = 4096


def load_fernet_key() -> bytes:
    """Load the shared Fernet key from disk."""
    with open(FERNET_KEY_FILE, 'rb') as f:
        return f.read()


def receive_all(conn: socket.socket) -> bytes:
    """Read data from socket until the connection closes."""
    chunks = []
    while True:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
    return b''.join(chunks)


def start_server() -> None:
    key    = load_fernet_key()
    fernet = Fernet(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[*] Server listening on {HOST}:{PORT}")
        print("[*] Waiting for client ...")

        conn, addr = srv.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            # ── Step 1: Receive credentials ───────────────────────────────
            raw_creds = conn.recv(1024).decode()
            if '|' not in raw_creds:
                conn.sendall(b'AUTH_FAIL')
                print("[-] Malformed credentials. Connection refused.")
                return

            password, totp_token = raw_creds.split('|', 1)

            # ── Step 2: Verify MFA ────────────────────────────────────────
            if not verify_mfa(password, totp_token):
                conn.sendall(b'AUTH_FAIL')
                print("[-] MFA failed. Connection refused.")
                return

            conn.sendall(b'AUTH_OK')
            print("[+] MFA verified. Waiting for encrypted payload ...")

            # ── Step 3: Receive encrypted file ────────────────────────────
            encrypted_data = receive_all(conn)
            print(f"[+] Received {len(encrypted_data)} bytes.")

            # ── Step 4: Decrypt and save ──────────────────────────────────
            plain_text = fernet.decrypt(encrypted_data)
            with open(DECRYPTED_FILE, 'wb') as f:
                f.write(plain_text)

            print(f"[+] Decrypted manifesto saved to: {DECRYPTED_FILE}")
            print("\n--- Decrypted Message Preview ---")
            print(plain_text.decode('utf-8')[:300])
            print("----------------------------------")


if __name__ == '__main__':
    start_server()
