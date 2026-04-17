# FSCT 8561 — Final Exam Pipeline
# README.md

## File Overview

| File                  | Day | Purpose                                      |
|-----------------------|-----|----------------------------------------------|
| config.py             | —   | Shared constants (host, port, password, etc.)|
| day1_recon.py         | 1   | nmap scan — pre-flight check                 |
| day2_mfa_gateway.py   | 2   | Password hashing + TOTP (imported by server) |
| day3_steganography.py | 3   | Extract manifesto from evidence.png          |
| day4_server.py        | 4   | Listen, verify MFA, receive & decrypt        |
| day4_client.py        | 4   | Encrypt manifesto, authenticate, transmit    |

---

## Install Dependencies

```bash
pip install python-nmap pyotp cryptography pillow stepic
```

---

## Run Order

### Day 1 — Reconnaissance
```bash
python day1_recon.py
```
Scans localhost:9999 and writes a timestamped `recon_log_*.txt`.

### Day 2 — MFA Demo (optional standalone test)
```bash
python day2_mfa_gateway.py
```
Prints the stored hash and verifies a live OTP. No server needed.

### Day 3 — Steganography
Place `evidence.png` in this folder, then:
```bash
python day3_steganography.py
```
Writes the recovered text to `architect_manifesto.txt`.

### Day 4 — Secure Transmission (two terminals)

**Terminal 1 — start server first:**
```bash
python day4_server.py
```

**Terminal 2 — run client:**
```bash
python day4_client.py
```

The client generates a Fernet key (`fernet.key`), encrypts the manifesto,
authenticates with password + OTP, and sends the encrypted bytes.
The server verifies MFA, receives the bytes, decrypts them, and saves
`decrypted_manifesto.txt`.

> Note: `fernet.key` must be present in the same directory on both
> client and server. In a real deployment this would be shared securely
> out-of-band (e.g., pre-shared key exchange).

---

## Configuration

Edit `config.py` to change:
- `HOST` / `PORT` — target address
- `PASSWORD` — shared secret
- `TOTP_SECRET` — shared TOTP base-32 seed
- File path constants
