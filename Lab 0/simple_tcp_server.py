import socket
import threading
import sys


HOST = "127.0.0.1"
PORT = 12345


def _recv_loop(conn):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                print("[server] client disconnected")
                break
            print("[client]", data.decode(errors="replace"))
    except Exception as e:
        print("[server] recv error:", e)
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()


def run(host=HOST, port=PORT):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    print(f"Server listening on {host}:{port}")
    conn, addr = s.accept()
    print("Accepted", addr)
    t = threading.Thread(target=_recv_loop, args=(conn,), daemon=True)
    t.start()

    try:
        # main thread: read from terminal and send to client
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip().lower() in ("quit", "exit"):
                break
            try:
                conn.sendall(line.encode())
            except Exception as e:
                print("[server] send error:", e)
                break
    finally:
        try:
            conn.close()
        except Exception:
            pass
        s.close()
        print("Server shutdown")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    run(host, port)
