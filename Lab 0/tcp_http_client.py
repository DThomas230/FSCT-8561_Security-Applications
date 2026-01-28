import socket
import time


def fetch(host="example.com", port=80, path="/"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    print("Socket timeout set to 10s")
    print("Import Socket Succesfully")
    try:
        start = time.time()

        s.connect((host, port))
        connect_time = time.time() - start
        print(f"Connectedto {host}:{port}. Connect elapsed: {connect_time:.4f}s")

        local_addr = s.getsockname()
        peer_addr = s.getpeername()
        print("Local socket address:", local_addr)
        print("Peer socket address:", peer_addr)

        req = (  ==
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        print("Sending HTTP GET request...")
        s.sendall(req.encode("ascii"))

        print("Receiving response (read until remote closes)...")
        resp = bytearray()
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp.extend(chunk)

        total_time = time.time() - start
        print(f"Received {len(resp)} bytes in {total_time:.4f}s")

        text = resp.decode("utf-8", errors="replace")
        print("--- Response start ---")
        print(text)
        print("--- Response end ---")

    except Exception as e:
        print("Error:", e)
    finally:
        s.close()
        print("Socket closed.")


if __name__ == "__main__":
    fetch()
