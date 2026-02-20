#!/usr/bin/env python3

import socket
import hashlib
import pyotp
import json
import os
import time

HOST = "127.0.0.1"
PORT = 9999
NONCE_LIFETIME = 60          # Nonce expires after 60 seconds (Part C, Step 2)
MAX_FAILED_ATTEMPTS = 3      # Lockout threshold (Part D/ Part B threat table)
LOCKOUT_DURATION = 300       # 5-minute lockout window

# ──────────────────────────────────────────────
# Passwords are stored as SHA-256 hashes - never in plaintext.
# ──────────────────────────────────────────────
TOTP_SECRET = pyotp.random_base32()   # Generated once; share with the client

# ──────────────────────────────────────────────
# LOGIN CREDENTIALS (for testing)
# User: admin_01
# Password: SecurePass123
# ──────────────────────────────────────────────
users_db = {
    "admin_01": {
        # hash of "SecurePass123" - raw password is never stored (Part D §1)
        "password_hash": hashlib.sha256("SecurePass123".encode()).hexdigest(),
        "totp_secret": TOTP_SECRET,
    }
}

# ──────────────────────────────────────────────
# RUNTIME STATE (in-memory only - Part D, Data Minimization)
# ──────────────────────────────────────────────
nonce_store = {}        # {session_id: {"nonce": str, "created": float, "user": str}}
failed_attempts = {}    # {username: {"count": int, "last_time": float}}
session_state = {}      # {session_id: current_step}  - enforces strict sequencing


# ═══════════════════════════════════════════════
# NONCE GENERATOR & STORAGE
# ═══════════════════════════════════════════════
def generate_nonce():
    """
    Create a cryptographically secure random nonce.
    Security Purpose: Each login attempt gets a unique nonce so that
    an attacker who captures Step 3 cannot replay it later (Part C).
    """
    return os.urandom(16).hex()   # 32-char hex string


def store_nonce(session_id, nonce, username):
    """Store the nonce with a timestamp so it can expire after 60 seconds."""
    nonce_store[session_id] = {
        "nonce": nonce,
        "created": time.time(),
        "user": username,
    }


def validate_and_consume_nonce(session_id, nonce):
    """
    Check that the nonce exists and has not expired, then DELETE it.
    Security Purpose - Nonce Volatility (Part C):
    Once consumed the nonce can never be reused, defeating replay attacks.
    """
    entry = nonce_store.get(session_id)
    if entry is None:
        return False, "Nonce not found (possible replay)"

    # Check expiration
    if time.time() - entry["created"] > NONCE_LIFETIME:
        del nonce_store[session_id]
        return False, "Nonce expired"

    # Check value matches
    if entry["nonce"] != nonce:
        del nonce_store[session_id]
        return False, "Nonce mismatch"

    # Consume - delete immediately so it cannot be reused
    del nonce_store[session_id]
    return True, "OK"


# ═══════════════════════════════════════════════
# MFA & HASH VERIFIER 
# ═══════════════════════════════════════════════
def verify_proof(username, proof, nonce):
    """
    Verify the SHA-256 proof sent by the client.
    The client hashes (password + nonce) so the raw password is
    never transmitted over the monitored channel (Part C).
    """
    stored_hash = users_db[username]["password_hash"]
    # Recreate the expected proof: SHA-256( password_hash + nonce )
    expected = hashlib.sha256((stored_hash + nonce).encode()).hexdigest()
    return proof == expected


def verify_totp(username, code):
    """
    Verify the 6-digit TOTP code (possession factor).
    Security Purpose: Even if an attacker knows the password, they
    cannot authenticate without the physical TOTP device (Part D).
    A 30-second window is used; old codes are rejected.
    """
    secret = users_db[username]["totp_secret"]
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ═══════════════════════════════════════════════
# ACCOUNT LOCKOUT  (Part B - Brute-Force Mitigation)
# ═══════════════════════════════════════════════
def is_locked_out(username):
    """Return True if the user has exceeded the failed-attempt threshold."""
    record = failed_attempts.get(username)
    if record is None:
        return False
    # Reset after lockout duration
    if time.time() - record["last_time"] > LOCKOUT_DURATION:
        del failed_attempts[username]
        return False
    return record["count"] >= MAX_FAILED_ATTEMPTS


def record_failure(username):
    """Increment the failure counter for brute-force tracking."""
    record = failed_attempts.get(username, {"count": 0, "last_time": 0})
    record["count"] += 1
    record["last_time"] = time.time()
    failed_attempts[username] = record


def reset_failures(username):
    """Clear failures on successful login."""
    failed_attempts.pop(username, None)


# ═══════════════════════════════════════════════
# SRDS-JSON MESSAGE HELPERS  (Part C)
# ═══════════════════════════════════════════════
def build_message(step, payload, session_id=""):
    """Build a protocol-compliant SRDS-JSON message."""
    return json.dumps({
        "version": "1.0",
        "step": step,
        "payload": payload,
        "id": session_id,
    })


# ═══════════════════════════════════════════════
# AUTH MANAGER LOGIC  (Core handler from diagram)
# ═══════════════════════════════════════════════
def handle_client(client_socket, address):
    """
    Manage the full 4-step handshake for one client connection.
    Strict State Sequencing (Part C): the handler expects
    messages to arrive in order - AUTH_REQ then AUTH_RESP.
    """
    session_id = os.urandom(8).hex()       # Unique ID per session
    session_state[session_id] = "IDLE"     # Start in IDLE state
    print(f"[+] New connection from {address}  |  session={session_id}")

    try:
        # STEP 1: Receive AUTH_REQ
        raw = client_socket.recv(4096).decode("utf-8")
        msg = json.loads(raw)

        # Strict sequencing - only accept AUTH_REQ when IDLE
        if msg.get("step") != "AUTH_REQ" or session_state[session_id] != "IDLE":
            client_socket.send(build_message(
                "STATUS", {"code": 400, "msg": "Bad request sequence"}, session_id
            ).encode())
            return

        username = msg["payload"]["user"]
        print(f"Step 1 ← AUTH_REQ from user '{username}'")

        # Check if user exists
        if username not in users_db:
            client_socket.send(build_message(
                "STATUS", {"code": 401, "msg": "Unknown user"}, session_id
            ).encode())
            return

        # Check lockout before issuing a challenge
        if is_locked_out(username):
            client_socket.send(build_message(
                "STATUS", {"code": 403, "msg": "Account locked. Try again later."}, session_id
            ).encode())
            print(f"[!] Account '{username}' is locked out")
            return

        # STEP 2: Send CHALLENGE (nonce)
        nonce = generate_nonce()
        store_nonce(session_id, nonce, username)
        session_state[session_id] = "CHALLENGE_SENT"

        challenge_msg = build_message("CHALLENGE", {"nonce": nonce}, session_id)
        client_socket.send(challenge_msg.encode())
        print(f"Step 2 → CHALLENGE sent  (nonce={nonce[:12]}...)")

        # STEP 3: Receive AUTH_RESP
        raw = client_socket.recv(4096).decode("utf-8")
        msg = json.loads(raw)

        # Strict sequencing - only accept AUTH_RESP after CHALLENGE
        if msg.get("step") != "AUTH_RESP" or session_state[session_id] != "CHALLENGE_SENT":
            client_socket.send(build_message(
                "STATUS", {"code": 400, "msg": "Out-of-order packet dropped"}, session_id
            ).encode())
            print(f"[!] Rejected out-of-order packet")
            return

        proof = msg["payload"]["proof"]
        mfa_code = msg["payload"]["mfa"]
        print(f"Step 3 ← AUTH_RESP received")

        # Validate nonce (consume it to prevent replay)
        nonce_ok, nonce_msg = validate_and_consume_nonce(session_id, nonce)
        if not nonce_ok:
            client_socket.send(build_message(
                "STATUS", {"code": 401, "msg": nonce_msg}, session_id
            ).encode())
            print(f"[!] Nonce validation failed: {nonce_msg}")
            return

        # Verify the hashed proof
        if not verify_proof(username, proof, nonce):
            record_failure(username)
            client_socket.send(build_message(
                "STATUS", {"code": 401, "msg": "Invalid credentials"}, session_id
            ).encode())
            print(f"[!] Proof verification failed")
            return

        # Verify the TOTP code (possession factor)
        if not verify_totp(username, mfa_code):
            record_failure(username)
            attempts = failed_attempts.get(username, {}).get("count", 0)
            client_socket.send(build_message(
                "STATUS", {"code": 401, "msg": f"Invalid MFA ({attempts}/{MAX_FAILED_ATTEMPTS})"}, session_id
            ).encode())
            print(f"[!] TOTP verification failed ({attempts}/{MAX_FAILED_ATTEMPTS})")
            return

        # STEP 4: Send STATUS - Authenticated
        reset_failures(username)
        session_state[session_id] = "AUTHENTICATED"
        client_socket.send(build_message(
            "STATUS", {"code": 200, "msg": "Authenticated"}, session_id
        ).encode())
        print(f"Step 4 → STATUS: Authenticated ✓")

    except (json.JSONDecodeError, KeyError) as e:
        print(f"[!] Malformed message: {e}")
        client_socket.send(build_message(
            "STATUS", {"code": 400, "msg": "Malformed message"}, session_id
        ).encode())
    finally:
        # Clean up session data - Data Minimization (Part D §4)
        session_state.pop(session_id, None)
        nonce_store.pop(session_id, None)
        client_socket.close()


# ═══════════════════════════════════════════════
# SOCKET LISTENER - STATEFUL  (Component from diagram)
# ═══════════════════════════════════════════════
def start_gateway():
    """
    Start the Gateway's socket listener.
    It runs in a continuous loop accepting one connection at a time
    (stateful), as described in the architecture diagram.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print("=" * 55)
    print("SRDS GATEWAY SERVER - Challenge-Response Auth")
    print("=" * 55)
    print(f"[*] Listening on {HOST}:{PORT}")
    print(f"[*] TOTP Secret (share with client): {TOTP_SECRET}")
    print(f"[*] Nonce lifetime: {NONCE_LIFETIME}s  |  Lockout after {MAX_FAILED_ATTEMPTS} failures")
    print()

    try:
        while True:
            client_socket, address = server.accept()
            handle_client(client_socket, address)
    except KeyboardInterrupt:
        print("\n[*] Gateway shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    start_gateway()
