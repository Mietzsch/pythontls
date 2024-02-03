# client_hello.py

import socket
import random

import tls1_3.tls_state


class client_hello:
    legacy_version: tls1_3.tls_state.ProtocolVersion
    rand: bytes
    legacy_session_id: bytes
    cipher_suites: [tls1_3.tls_state.CipherSuites]
    legacy_compression_method: bytes
    extensions: [tls1_3.tls_state.extension_message]

    def __init__(self, cipher_suites: [tls1_3.tls_state.CipherSuites], extensions: [tls1_3.tls_state.extension_message]):
        self.legacy_version = tls1_3.tls_state.ProtocolVersion.TLS_1_2
        self.rand = random.randbytes(32)
        self.legacy_session_id = random.randbytes(32)
        self.cipher_suites = cipher_suites
        self.legacy_compression_method = bytes([0])
        self.extensions = extensions

    def serialize(self) -> bytes:
        out = int(self.legacy_version).to_bytes(2, 'big')
        out += self.rand
        out += len(self.legacy_session_id).to_bytes(1, 'big')
        out += self.legacy_session_id
        cipher_suits_len = len(self.cipher_suites) * 2
        out += cipher_suits_len.to_bytes(2, 'big')

        for cipher_suite in self.cipher_suites:
            out += int(cipher_suite.value).to_bytes(2, 'big')

        out += len(self.legacy_compression_method).to_bytes(1, 'big')
        out += self.legacy_compression_method
        out += len(self.extensions).to_bytes(2, 'big')

        for extension in self.extensions:
            out += extension.serialize()
        return out


def create_default_cipher_suites() -> [tls1_3.tls_state.CipherSuites]:
    return [tls1_3.tls_state.CipherSuites.TLS_AES_256_GCM_SHA384, tls1_3.tls_state.CipherSuites.TLS_AES_128_GCM_SHA256]


def create_default_extensions() -> [tls1_3.tls_state.extension_message]:
    return []


def send_client_hello(sock: socket.socket, state):
    client_hello_obj = client_hello(
        create_default_cipher_suites(), create_default_extensions())
    handshake_message = tls1_3.tls_state.handshake_message(tls1_3.tls_state.HandshakeType.CLIENT_HELLO, client_hello_obj.serialize()
                                                           )
    serialized = handshake_message.serialize_as_plaintext_record(
        tls1_3.tls_state.ContentType.HANDSHAKE, tls1_3.tls_state.ProtocolVersion.TLS_1_0)
    sock.sendall(serialized)
