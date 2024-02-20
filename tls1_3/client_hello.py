# client_hello.py

import socket
import random

import tls1_3.tls_state
import tls1_3.tls_extensions
import tls1_3.tls_constants
import tls1_3.tls_handshake


class client_hello:
    legacy_version: tls1_3.tls_constants.ProtocolVersion
    rand: bytes
    legacy_session_id: bytes
    cipher_suites: list[tls1_3.tls_constants.CipherSuites]
    legacy_compression_method: bytes
    extensions: list[tls1_3.tls_extensions.extension_message]

    def __init__(self, cipher_suites: list[tls1_3.tls_constants.CipherSuites], extensions: list[tls1_3.tls_extensions.extension_message]):
        self.legacy_version = tls1_3.tls_constants.ProtocolVersion.TLS_1_2
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

        total_extensions = bytes()
        for extension in self.extensions:
            total_extensions += extension.serialize()

        out += len(total_extensions).to_bytes(2, 'big')
        out += total_extensions
        return out


def create_default_cipher_suites() -> list[tls1_3.tls_constants.CipherSuites]:
    return [tls1_3.tls_constants.CipherSuites.TLS_AES_256_GCM_SHA384, tls1_3.tls_constants.CipherSuites.TLS_AES_128_GCM_SHA256]


def create_default_extensions(state: tls1_3.tls_state.tls_state) -> list[tls1_3.tls_extensions.extension_message]:
    supported_versions = tls1_3.tls_extensions.SupportedVersionsExtension(
        [tls1_3.tls_constants.ProtocolVersion.TLS_1_3])
    out = [tls1_3.tls_extensions.extension_message(
        tls1_3.tls_extensions.Extension.SUPPORTED_VERSIONS, supported_versions.serialize())]

    supported_algos = tls1_3.tls_extensions.SignatureAlgorithmsExtension(
        [tls1_3.tls_constants.SignatureScheme.ECDSA_SECP384R1_SHA384]
    )
    out.append(tls1_3.tls_extensions.extension_message(
        tls1_3.tls_extensions.Extension.SIGNATURE_ALOGRITHMS, supported_algos.serialize()))

    groups = [tls1_3.tls_constants.NamedGroup.X25519]

    supported_groups = tls1_3.tls_extensions.SupportedGroupsExtension(groups)
    out.append(tls1_3.tls_extensions.extension_message(
        tls1_3.tls_extensions.Extension.SUPPORTED_GROUPS, supported_groups.serialize()))

    key_share = tls1_3.tls_extensions.KeyShareExtension(groups, state)
    out.append(tls1_3.tls_extensions.extension_message(
        tls1_3.tls_extensions.Extension.KEY_SHARE, key_share.serialize()))

    return out


def send_client_hello(sock: socket.socket, state):
    client_hello_obj = client_hello(
        create_default_cipher_suites(), create_default_extensions(state))
    handshake_message = tls1_3.tls_handshake.HandshakeMessage(tls1_3.tls_handshake.HandshakeType.CLIENT_HELLO, client_hello_obj.serialize()
                                                              )
    serialized = handshake_message.serialize_as_plaintext_record(
        tls1_3.tls_handshake.ContentType.HANDSHAKE, tls1_3.tls_constants.ProtocolVersion.TLS_1_2)
    sock.sendall(serialized)
