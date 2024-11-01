# client_hello.py

import socket
import random

import tls1_3.tls_state
import tls1_3.tls_extensions
import tls1_3.tls_constants
import tls1_3.tls_handshake
import tls1_3.tls_plaintext
import tls1_3.tls_crypto


class client_hello(tls1_3.tls_handshake.HandshakeMessage):
    legacy_version: tls1_3.tls_constants.ProtocolVersion
    rand: bytes
    legacy_session_id: bytes
    cipher_suites: list[tls1_3.tls_constants.CipherSuite]
    legacy_compression_methods: bytes
    extensions: list[tls1_3.tls_extensions.Extension]

    def __init__(self, cipher_suites: list[tls1_3.tls_constants.CipherSuite], extensions: list[tls1_3.tls_extensions.Extension]):
        self.legacy_version = tls1_3.tls_constants.ProtocolVersion.TLS_1_2
        self.rand = random.randbytes(32)
        self.legacy_session_id = random.randbytes(32)
        self.cipher_suites = cipher_suites
        self.legacy_compression_methods = bytes([0])
        self.extensions = extensions

    def getType(self) -> tls1_3.tls_handshake.HandshakeCode:
        return tls1_3.tls_handshake.HandshakeCode.CLIENT_HELLO

    def serialize(self) -> bytes:
        out = int(self.legacy_version).to_bytes(2, 'big')
        out += self.rand
        out += len(self.legacy_session_id).to_bytes(1, 'big')
        out += self.legacy_session_id
        cipher_suits_len = len(self.cipher_suites) * 2
        out += cipher_suits_len.to_bytes(2, 'big')

        for cipher_suite in self.cipher_suites:
            out += int(cipher_suite.value).to_bytes(2, 'big')

        out += len(self.legacy_compression_methods).to_bytes(1, 'big')
        out += self.legacy_compression_methods

        total_extensions = bytes()
        for extension in self.extensions:
            extension_message = tls1_3.tls_extensions.ExtensionMessage(
                extension)
            total_extensions += extension_message.serialize()

        out += len(total_extensions).to_bytes(2, 'big')
        out += total_extensions
        return out

    def update_state(self, state: tls1_3.tls_state.tls_state):
        state.legacy_session_id = self.legacy_session_id
        state.add_proposed_cipher_suites(self.cipher_suites)

        for extension in self.extensions:
            extension.update_state(state)


def create_default_cipher_suites() -> list[tls1_3.tls_constants.CipherSuite]:
    return [tls1_3.tls_constants.CipherSuite.TLS_AES_256_GCM_SHA384,
            tls1_3.tls_constants.CipherSuite.TLS_AES_128_GCM_SHA256
            ]


def create_default_extensions(state: tls1_3.tls_state.tls_state) -> list[tls1_3.tls_extensions.ExtensionMessage]:
    out = []

    server_name = tls1_3.tls_extensions.ServerNameIndicationExtension([
                                                                      'google.com'])
    out.append(server_name)

    supported_versions = tls1_3.tls_extensions.SupportedVersionsExtension(
        [tls1_3.tls_constants.ProtocolVersion.TLS_1_3])
    out.append(supported_versions)

    supported_algos = tls1_3.tls_extensions.SignatureAlgorithmsExtension(
        [tls1_3.tls_constants.SignatureScheme.ECDSA_SECP256R1_SHA256,
            tls1_3.tls_constants.SignatureScheme.ECDSA_SECP384R1_SHA384,
            tls1_3.tls_constants.SignatureScheme.RSA_PSS_RSAE_SHA256
         ]
    )
    out.append(supported_algos)

    groups = [tls1_3.tls_constants.NamedGroup.X25519MLKEM768]

    supported_groups = tls1_3.tls_extensions.SupportedGroupsExtension(
        groups)
    out.append(supported_groups)

    shares = map(lambda group: tls1_3.tls_crypto.generate_key_share(
        group), groups)

    sks, pks = zip(*shares)
    for group, sk in zip(groups, sks):
        state.add_key_share(group, sk)

    key_share = tls1_3.tls_extensions.KeyShareExtension(groups, pks)
    out.append(key_share)

    return out


def send_client_hello(sock: socket.socket, state):
    client_hello_message = client_hello(
        create_default_cipher_suites(), create_default_extensions(state))
    client_hello_message.update_state(state)
    handshake_message = tls1_3.tls_handshake.Handshake.fromHandshakeMessage(
        client_hello_message)
    tls_plaintext = tls1_3.tls_plaintext.TLSPlaintext.fromTLSPlaintext(
        handshake_message, tls1_3.tls_constants.ProtocolVersion.TLS_1_0)
    serialized = tls_plaintext.serialize()
    sock.sendall(serialized)
    state.save_message(
        tls1_3.tls_constants.HandshakeCode.CLIENT_HELLO, handshake_message.serialize())
