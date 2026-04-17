# config.py — Shared configuration for the entire pipeline

# --- Network ---
HOST = '127.0.0.1'
PORT = 9999

# --- Authentication ---
PASSWORD = 'SecurePass123'        # plain-text password (client sends this)
SALT     = b'fsct8561_exam_salt'  # fixed salt used when hashing

# --- TOTP ---
# Both client and server share this secret to generate/verify the OTP.
# Generate a fresh one with: pyotp.random_base32()
TOTP_SECRET = 'JBSWY3DPEHPK3PXP'

# --- File Paths ---
IMAGE_PATH      = 'evidence.png'
MANIFEST_FILE   = 'architect_manifesto.txt'
DECRYPTED_FILE  = 'decrypted_manifesto.txt'
FERNET_KEY_FILE = 'fernet.key'
