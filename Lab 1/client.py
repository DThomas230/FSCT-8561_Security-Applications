import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 12345

def receive_messages(sock):
    """Background thread to receive server responses"""
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[Server disconnected]")
                break
            
            response = data.decode().strip()
            if '|' in response:
                status, msg = response.split('|', 1)
                if status == "OK":
                    print(f"\n✓ {msg}")
                else:
                    print(f"\n✗ {msg}")
            else:
                print(f"\n{response}")
    except:
        pass

def main():
    """Run the client"""
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}\n")
    except:
        print("Failed to connect to server")
        return
    
    # Start receive thread
    thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    thread.start()
    
    print("Commands: HELLO username, MSG message, EXIT")
    print("You must send HELLO first to authenticate!\n")
    
    authenticated = False
    username = None
    
    # Main loop
    try:
        while True:
            prompt = f"{username}> " if authenticated else "guest> "
            msg = input(prompt).strip()
            
            if not msg:
                continue
            
            if msg.lower() in ('exit', 'quit'):
                sock.sendall("EXIT|".encode())
                time.sleep(0.5)  # Wait for server goodbye response
                break
            
            # Parse HELLO command
            if msg.upper().startswith("HELLO "):
                username = msg[6:].strip()
                sock.sendall(f"HELLO|{username}".encode())
                authenticated = True
            
            # Auto-format as MSG if not a command
            elif not msg.startswith(("HELLO|", "MSG|", "EXIT|")):
                sock.sendall(f"MSG|{msg}".encode())
            
            # Send raw command
            else:
                sock.sendall(msg.encode())
    
    except KeyboardInterrupt:
        print("\n\nDisconnected")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
