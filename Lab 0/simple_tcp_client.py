import socket
import threading
import sys

HOST = "127.0.0.1"
PORT = 12345


def _recv_loop(sock):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("[client] server disconnected")
                break
            print("[server]", data.decode(errors="replace"))
    except Exception as e:
        print("[client] recv error:", e)
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()


def run(host=HOST, port=PORT):
    sock = socket.socket()
    sock.connect((host, port))
    print(f"Connected to {host}:{port}")
    t = threading.Thread(target=_recv_loop, args=(sock,), daemon=True)
    t.start()

    try:
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip().lower() in ("quit", "exit"):
                break
            try:
                sock.sendall(line.encode())
            except Exception as e:
                print("[client] send error:", e)
                break
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("Client shutdown")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    run(host, port)
