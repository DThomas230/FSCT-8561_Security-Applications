# day2_mfa_gateway.py — Multi-Factor Authentication Gateway (Day 2 / Lab 3)
# Provides password hashing and TOTP verification used by the server.
# Import this module in day4_server.py.

import hashlib
import pyotp
from config import PASSWORD, SALT, TOTP_SECRET


# ── Password helpers ─────────────────────────────────────────────────────────

def hash_password(plain_text: str, salt: bytes) -> str:
    """Return a hex PBKDF2-SHA256 hash of plain_text with the given salt."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        plain_text.encode(),
        salt,
        100_000           # NIST-recommended iteration count
    ).hex()


# Store the expected hash at startup (computed once from config).
STORED_HASH = hash_password(PASSWORD, SALT)


def verify_password(received: str) -> bool:
    """Return True if received password matches the stored hash."""
    return hash_password(received, SALT) == STORED_HASH


# ── TOTP helpers ──────────────────────────────────────────────────────────────

_totp = pyotp.TOTP(TOTP_SECRET)


def verify_totp(token: str) -> bool:
    """Return True if token is a valid current TOTP code."""
    return _totp.verify(token)


# ── Combined MFA check ────────────────────────────────────────────────────────

def verify_mfa(password: str, token: str) -> bool:
    """Return True only when BOTH password AND OTP are valid."""
    return verify_password(password) and verify_totp(token)


# ── Stand-alone demo ──────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=== MFA Gateway Demo ===")
    print(f"Stored hash : {STORED_HASH}")
    current_otp = _totp.now()
    print(f"Current OTP : {current_otp}")

    ok = verify_mfa(PASSWORD, current_otp)
    print(f"MFA result  : {'PASS' if ok else 'FAIL'}")
