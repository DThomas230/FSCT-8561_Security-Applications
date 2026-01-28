import socket
import threading
from datetime import datetime

HOST = "127.0.0.1"
PORT = 12345
MAX_LENGTH = 1024

# Session state: {conn: {'username': str, 'authenticated': bool}}
sessions = {}

def log(conn, message):
    """Log with timestamp"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    username = sessions.get(conn, {}).get('username', 'guest')
    print(f"[{timestamp}] [{username}] {message}")

def send(conn, message):
    """Send message to client"""
    try:
        conn.sendall((message + "\n").encode())
    except:
        pass

def handle_client(conn, addr):
    """Handle one client connection"""
    sessions[conn] = {'username': None, 'authenticated': False}
    log(conn, f"Connected from {addr}")
    
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            
            message = data.decode().strip()
            log(conn, f"Received: {message}")
            
            # Validate: empty message
            if not message:
                send(conn, "ERROR|Empty message")
                continue
            
            # Validate: message length
            if len(message) > MAX_LENGTH:
                send(conn, "ERROR|Message too long")
                continue
            
            # Validate: command format
            if '|' not in message:
                send(conn, "ERROR|Invalid format")
                continue
            
            # Parse command
            command, data = message.split('|', 1)
            command = command.upper()
            
            # Handle HELLO
            if command == "HELLO":
                if sessions[conn]['authenticated']:
                    send(conn, "ERROR|Already authenticated")
                elif not data.strip():
                    send(conn, "ERROR|Username required")
                else:
                    sessions[conn]['username'] = data.strip()
                    sessions[conn]['authenticated'] = True
                    log(conn, f"Authenticated as {data.strip()}")
                    send(conn, f"OK|Welcome {data.strip()}")
            
            # Handle EXIT
            elif command == "EXIT":
                log(conn, "Client requested disconnect")
                send(conn, "EXIT|Goodbye")
                break
            
            # Require authentication for other commands
            elif not sessions[conn]['authenticated']:
                log(conn, f"Rejected '{command}' - not authenticated")
                send(conn, "ERROR|Must send HELLO command first")
            
            # Handle MSG
            elif command == "MSG":
                if not data.strip():
                    send(conn, "ERROR|Empty message")
                else:
                    log(conn, f"Message: {data}")
                    send(conn, "OK|Message received")
            
            # Unknown command
            else:
                send(conn, f"ERROR|Unknown command")
    
    except Exception as e:
        log(conn, f"Error: {e}")
    finally:
        log(conn, "Disconnected")
        if conn in sessions:
            del sessions[conn]
        conn.close()

def main():
    """Start server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"Server listening on {HOST}:{PORT}")
    print(f"Max message length: {MAX_LENGTH}\n")
    
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        server.close()

if __name__ == "__main__":
    main()
