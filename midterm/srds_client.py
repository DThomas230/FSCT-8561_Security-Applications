#!/usr/bin/env python3

import socket
import hashlib
import pyotp
import json

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 9999


# ═══════════════════════════════════════════════
# CREDENTIAL & TOTP MODULE
# ═══════════════════════════════════════════════
def compute_proof(password, nonce):
    """
    Build the one-time proof that the Gateway expects.
    Steps:
      1. Hash the raw password with SHA-256 (so plaintext is never kept).
      2. Hash (password_hash + nonce) to bind the credential to this session.
    Security Purpose (Part C - Cryptographic Salt):
      The nonce acts as a salt, making the proof unique per session.
      Even if an adversary captures this proof, it cannot be replayed
      because the next session will use a different nonce.
    """
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    proof = hashlib.sha256((password_hash + nonce).encode()).hexdigest()
    return proof


def generate_totp(secret):
    """
    Generate a 6-digit TOTP code from the shared secret.
    Security Purpose (Part D - Possession Factor):
      This proves the admin physically possesses the TOTP device/secret.
      The code changes every 30 seconds, limiting the window for misuse.
    """
    totp = pyotp.TOTP(secret)
    return totp.now()


# ═══════════════════════════════════════════════
# PYTHON SOCKET CLIENT
# ═══════════════════════════════════════════════
def authenticate(username, password, totp_secret):
    """
    Execute the full 4-step handshake with the SRDS Gateway.
    Follows the SRDS-JSON message format defined in Part C.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the Gateway's public socket
        client.connect((GATEWAY_HOST, GATEWAY_PORT))
        print(f"[*] Connected to Gateway at {GATEWAY_HOST}:{GATEWAY_PORT}\n")

        # STEP 1: Send AUTH_REQ 
        # Tell the Gateway which user wants to authenticate.
        auth_req = json.dumps({
            "version": "1.0",
            "step": "AUTH_REQ",
            "payload": {"user": username},
        })
        client.send(auth_req.encode())
        print(f"Step 1 → AUTH_REQ sent (user='{username}')")

        # STEP 2: Receive CHALLENGE 
        # The Gateway sends back a random nonce (Part C §2, Step 2).
        raw = client.recv(4096).decode("utf-8")
        msg = json.loads(raw)

        # If the Gateway responded with STATUS, something went wrong
        if msg["step"] == "STATUS":
            print(f"[!] Gateway rejected: {msg['payload']['msg']}")
            return False

        nonce = msg["payload"]["nonce"]
        session_id = msg["id"]
        print(f"Step 2 ← CHALLENGE received (nonce={nonce[:12]}...)")

        # STEP 3: Send AUTH_RESP 
        # Compute the hash proof and generate the TOTP code.
        proof = compute_proof(password, nonce)
        mfa_code = generate_totp(totp_secret)

        auth_resp = json.dumps({
            "version": "1.0",
            "step": "AUTH_RESP",
            "payload": {
                "proof": proof,    # SHA-256(SHA-256(password) + nonce)
                "mfa": mfa_code,   # 6-digit TOTP code
            },
            "id": session_id,
        })
        client.send(auth_resp.encode())
        print(f"Step 3 → AUTH_RESP sent (proof + MFA code)")

        # STEP 4: Receive STATUS 
        raw = client.recv(4096).decode("utf-8")
        msg = json.loads(raw)
        code = msg["payload"]["code"]
        message = msg["payload"]["msg"]

        if code == 200:
            print(f"Step 4 ← STATUS: {message}  ✓")
            return True
        else:
            print(f"Step 4 ← STATUS: {message}  ✗  (code {code})")
            return False

    except ConnectionRefusedError:
        print("[!] Cannot connect - is the Gateway running?")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    finally:
        client.close()


# ═══════════════════════════════════════════════
# MAIN - Interactive Client Menu
# ═══════════════════════════════════════════════
def main():
    print("=" * 50)
    print("SRDS ADMIN CLIENT - Challenge-Response Auth")
    print("=" * 50)

    # Collect credentials from the admin user
    username = input("\n  Username : ").strip()
    password = input("  Password : ").strip()
    totp_secret = input("  TOTP Secret: ").strip()

    if not all([username, password, totp_secret]):
        print("[!] All fields are required.")
        return

    print()
    success = authenticate(username, password, totp_secret)

    if success:
        print("\n[+] Session established - you may now issue diagnostic commands.")
    else:
        print("\n[-] Authentication failed.")


if __name__ == "__main__":
    main()
