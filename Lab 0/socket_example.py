import socket


def main():
    print("socket module loaded:", socket)
    print("socket.AF_INET =>", socket.AF_INET)
    print("socket.SOCK_STREAM =>", socket.SOCK_STREAM)

    # Create a TCP/IPv4 socket using the constants
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Created socket:", s)

    # Show local hostname and resolved IP
    hostname = socket.gethostname()
    print("Local hostname:", hostname)
    try:
        ip = socket.gethostbyname(hostname)
        print("Resolved local IP:", ip)
    except Exception as e:
        print("Could not resolve local IP:", e)

    s.close()


if __name__ == "__main__":
    main()
