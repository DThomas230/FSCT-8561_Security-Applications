#!/usr/bin/env python3
import socket
import hashlib
import pyotp
import json
import time
from datetime import datetime

# Server configuration
HOST = '127.0.0.1'
PORT = 9999
MAX_FAILED_ATTEMPTS = 3

# User database (in production, use a real database)
users_db = {}
failed_attempts = {}


def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(username, password):
    """Create a new user with hashed password and OTP secret"""
    password_hash = hash_password(password)
    otp_secret = pyotp.random_base32()
    
    users_db[username] = {
        'password_hash': password_hash,
        'otp_secret': otp_secret
    }
    
    return otp_secret


def verify_password(username, password):
    """Verify password by comparing hashes"""
    if username not in users_db:
        return False
    
    password_hash = hash_password(password)
    return users_db[username]['password_hash'] == password_hash


def verify_otp(username, otp_code):
    """Verify TOTP code with time window"""
    if username not in users_db:
        return False
    
    otp_secret = users_db[username]['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    
    # Verify with 1-step window to handle clock desynchronization
    return totp.verify(otp_code, valid_window=1)


def check_failed_attempts(username):
    """Check if user has exceeded failed login attempts"""
    if username in failed_attempts:
        count, last_attempt = failed_attempts[username]
        
        # Reset counter after 5 minutes
        if time.time() - last_attempt > 300:
            failed_attempts[username] = (0, time.time())
            return False
        
        if count >= MAX_FAILED_ATTEMPTS:
            return True
    return False


def record_failed_attempt(username):
    """Record a failed login attempt"""
    if username in failed_attempts:
        count, _ = failed_attempts[username]
        failed_attempts[username] = (count + 1, time.time())
    else:
        failed_attempts[username] = (1, time.time())


def reset_failed_attempts(username):
    """Reset failed attempts counter on successful login"""
    if username in failed_attempts:
        del failed_attempts[username]


def handle_client(client_socket, address):
    """Handle client authentication requests"""
    print(f"[*] Connection from {address}")
    
    try:
        # Receive authentication request
        data = client_socket.recv(4096).decode('utf-8')
        request = json.loads(data)
        
        action = request.get('action')
        username = request.get('username')
        
        if action == 'register':
            # User registration
            password = request.get('password')
            
            if username in users_db:
                response = {
                    'status': 'error',
                    'message': 'Username already exists'
                }
            else:
                otp_secret = create_user(username, password)
                response = {
                    'status': 'success',
                    'message': 'User registered successfully',
                    'otp_secret': otp_secret
                }
                print(f"[+] New user registered: {username}")
        
        elif action == 'login':
            # User login
            password = request.get('password')
            otp_code = request.get('otp')
            
            # Check for account lockout
            if check_failed_attempts(username):
                response = {
                    'status': 'error',
                    'message': f'Account locked due to too many failed attempts. Try again later.'
                }
                print(f"[-] Login blocked for {username}: Too many failed attempts")
            
            # Verify username exists
            elif username not in users_db:
                record_failed_attempt(username)
                response = {
                    'status': 'error',
                    'message': 'Invalid username or password'
                }
                print(f"[-] Login failed for {username}: User not found")
            
            # Verify password
            elif not verify_password(username, password):
                record_failed_attempt(username)
                attempts = failed_attempts.get(username, (0, 0))[0]
                response = {
                    'status': 'error',
                    'message': f'Invalid username or password (Attempt {attempts}/{MAX_FAILED_ATTEMPTS})'
                }
                print(f"[-] Login failed for {username}: Incorrect password")
            
            # Verify OTP
            elif not verify_otp(username, otp_code):
                record_failed_attempt(username)
                attempts = failed_attempts.get(username, (0, 0))[0]
                response = {
                    'status': 'error',
                    'message': f'Invalid or expired OTP (Attempt {attempts}/{MAX_FAILED_ATTEMPTS})'
                }
                print(f"[-] Login failed for {username}: Invalid OTP")
            
            # Authentication successful
            else:
                reset_failed_attempts(username)
                response = {
                    'status': 'success',
                    'message': 'Authentication successful! Access granted.'
                }
                print(f"[+] Login successful for {username}")
        
        else:
            response = {
                'status': 'error',
                'message': 'Invalid action'
            }
        
        # Send response
        client_socket.send(json.dumps(response).encode('utf-8'))
    
    except Exception as e:
        error_response = {
            'status': 'error',
            'message': f'Server error: {str(e)}'
        }
        client_socket.send(json.dumps(error_response).encode('utf-8'))
        print(f"[!] Error handling client {address}: {e}")
    
    finally:
        client_socket.close()


def start_server():
    """Start the authentication server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"[*] Authentication Server listening on {HOST}:{PORT}")
    print(f"[*] Waiting for connections...")
    
    try:
        while True:
            client_socket, address = server.accept()
            handle_client(client_socket, address)
    
    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")
    finally:
        server.close()


if __name__ == '__main__':
    start_server()
