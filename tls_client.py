# tls_client.py

import sys
import socket

import tls1_3.client_hello
import tls1_3.tls_state


def create_socket(state) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((state.hostname, state.port))
    return sock


def main() -> int:
    state = tls1_3.tls_state.tls_state()
    sock = create_socket(state)

    tls1_3.client_hello.send_client_hello(sock, state)

    print("closing socket")
    sock.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
