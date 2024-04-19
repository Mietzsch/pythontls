# tls_client.py

import sys
import socket

import tls1_3.messages.client_hello
import tls1_3.handshake_message_dispatcher
import tls1_3.tls_state
import tls1_3.tls_plaintext
import tls1_3.tls_constants


def create_socket(state) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((state.hostname, state.port))
    return sock


def receive_message(socket) -> bytes:
    out = socket.recv(5)
    content_type = tls1_3.tls_plaintext.ContentType.from_bytes(out[0:1], 'big')
    version = tls1_3.tls_constants.ProtocolVersion.from_bytes(out[1:3], 'big')
    length = int.from_bytes(out[3:5], 'big')
    print("Got " + str(content_type) + ", version: " +
          str(version) + ", length: " + str(length))
    out += socket.recv(length)
    return out


def main() -> int:
    state = tls1_3.tls_state.tls_state()
    sock = create_socket(state)

    tls1_3.messages.client_hello.send_client_hello(sock, state)
    message = receive_message(sock)  # server hello
    tls1_3.handshake_message_dispatcher.handle_from_plaintext(message, state)
    message = receive_message(sock)  # encrypted extensions
    tls1_3.handshake_message_dispatcher.handle_from_ciphertext(message, state)
    message = receive_message(sock)  # server certificate
    tls1_3.handshake_message_dispatcher.handle_from_ciphertext(message, state)
    message = receive_message(sock)  # certificate verify
    tls1_3.handshake_message_dispatcher.handle_from_ciphertext(message, state)
    message = receive_message(sock)  # finished
    tls1_3.handshake_message_dispatcher.handle_from_ciphertext(message, state)

    print("closing socket")
    sock.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
