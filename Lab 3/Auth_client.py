#!/usr/bin/env python3
import socket
import json
import getpass
import pyotp
import sys

# Server configuration
HOST = '127.0.0.1'
PORT = 9999


def send_request(request):
    """Send request to server and receive response"""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        
        # Send request
        client.send(json.dumps(request).encode('utf-8'))
        
        # Receive response
        response = client.recv(4096).decode('utf-8')
        client.close()
        
        return json.loads(response)
    
    except ConnectionRefusedError:
        print("[!] Error: Cannot connect to server. Make sure the server is running.")
        return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def register_user():
    """Register a new user"""
    print("\n=== USER REGISTRATION ===")
    username = input("Enter username: ").strip()
    
    if not username:
        print("[!] Username cannot be empty")
        return
    
    password = getpass.getpass("Enter password: ")
    
    if not password:
        print("[!] Password cannot be empty")
        return
    
    # Confirm password
    password_confirm = getpass.getpass("Confirm password: ")
    
    if password != password_confirm:
        print("[!] Passwords do not match")
        return
    
    # Send registration request
    request = {
        'action': 'register',
        'username': username,
        'password': password
    }
    
    response = send_request(request)
    
    if response:
        if response['status'] == 'success':
            print(f"\n[+] {response['message']}")
            print(f"\n[*] Your OTP Secret: {response['otp_secret']}")
            print("[*] Save this secret! You'll need it to generate OTP codes.")
        else:
            print(f"\n[-] {response['message']}")


def login_user():
    """Authenticate user with password and OTP"""
    print("\n=== USER LOGIN ===")
    username = input("Enter username: ").strip()
    
    if not username:
        print("[!] Username cannot be empty")
        return
    
    password = getpass.getpass("Enter password: ")
    
    if not password:
        print("[!] Password cannot be empty")
        return
    
    # Get OTP code
    print("\n[*] Enter your OTP code from your authenticator app")
    print("    (or generate it using your OTP secret)")
    otp_code = input("Enter OTP code: ").strip()
    
    if not otp_code or len(otp_code) != 6 or not otp_code.isdigit():
        print("[!] OTP code must be 6 digits")
        return
    
    # Send login request
    request = {
        'action': 'login',
        'username': username,
        'password': password,
        'otp': otp_code
    }
    
    response = send_request(request)
    
    if response:
        if response['status'] == 'success':
            print(f"\n[+] {response['message']}")
            print("[+] Welcome! You have been authenticated successfully.")
        else:
            print(f"\n[-] Authentication Failed: {response['message']}")


def generate_otp():
    """Generate OTP code from secret (helper function)"""
    print("\n=== GENERATE OTP CODE ===")
    print("[*] Use this to generate OTP codes from your secret")
    
    otp_secret = input("Enter your OTP secret: ").strip()
    
    if not otp_secret:
        print("[!] OTP secret cannot be empty")
        return
    
    try:
        totp = pyotp.TOTP(otp_secret)
        current_otp = totp.now()
        
        print(f"\n[+] Current OTP Code: {current_otp}")
        print("[*] This code is valid for 30 seconds")
        
        import time
        remaining = 30 - (int(time.time()) % 30)
        print(f"[*] Time remaining: {remaining} seconds")
    
    except Exception as e:
        print(f"[!] Error generating OTP: {e}")


def display_menu():
    """Display main menu"""
    print("\n" + "="*50)
    print("     SECURE AUTHENTICATION CLIENT")
    print("="*50)
    print("1. Register new user")
    print("2. Login")
    print("3. Generate OTP code")
    print("4. Exit")
    print("="*50)


def main():
    """Main client function"""
    print("[*] Connecting to Authentication Server at {}:{}".format(HOST, PORT))
    
    while True:
        display_menu()
        choice = input("\nSelect an option (1-4): ").strip()
        
        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            generate_otp()
        elif choice == '4':
            print("\n[*] Goodbye!")
            sys.exit(0)
        else:
            print("\n[!] Invalid option. Please try again.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Client terminated by user")
        sys.exit(0)
