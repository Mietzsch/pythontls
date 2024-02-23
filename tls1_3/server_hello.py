# server_hello.py

import tls1_3.tls_plaintext
import tls1_3.tls_handshake
import tls1_3.tls_constants
import tls1_3.tls_state
import tls1_3.tls_extensions


class server_hello(tls1_3.tls_handshake.HandshakeMessage):
    legacy_version: tls1_3.tls_constants.ProtocolVersion
    rand: bytes
    legacy_session_id: bytes
    cipher_suite: tls1_3.tls_constants.CipherSuite
    legacy_compression_method: int
    extensions: list[tls1_3.tls_extensions.Extension]

    def __init__(self, serialized_message):
        ptr = 0
        self.legacy_version = tls1_3.tls_constants.ProtocolVersion.from_bytes(
            serialized_message[ptr:ptr+2], 'big')
        ptr += 2
        self.rand = serialized_message[ptr:ptr+32]
        ptr += 32
        legacy_session_id_len = int.from_bytes(
            serialized_message[ptr:ptr+1], 'big')
        ptr += 1
        self.legacy_session_id = serialized_message[ptr:ptr +
                                                    legacy_session_id_len]
        ptr += legacy_session_id_len
        self.cipher_suite = tls1_3.tls_constants.CipherSuite.from_bytes(
            serialized_message[ptr:ptr+2], 'big')
        ptr += 2
        self.legacy_compression_method = int.from_bytes(
            serialized_message[ptr:ptr+1], 'big')
        ptr += 1
        extensions_len = int.from_bytes(serialized_message[ptr:ptr+2], 'big')
        ptr += 2
        last_byte = ptr + extensions_len
        self.extensions = list()
        while (ptr < last_byte):
            cur_extension_type = tls1_3.tls_extensions.ExtensionCode.from_bytes(
                serialized_message[ptr:ptr+2], 'big')
            ptr += 2
            cur_extension_len = int.from_bytes(
                serialized_message[ptr:ptr+2], 'big')
            ptr += 2
            cur_extension_msg = serialized_message[ptr:ptr+cur_extension_len]

            match cur_extension_type:
                case tls1_3.tls_extensions.ExtensionCode.SUPPORTED_VERSIONS:
                    self.extensions.append(
                        tls1_3.tls_extensions.SupportedVersionsExtension.fromSerializedMessage(cur_extension_msg))

                case tls1_3.tls_extensions.ExtensionCode.KEY_SHARE:
                    self.extensions.append(
                        tls1_3.tls_extensions.KeyShareExtension.fromSerializedMessage(
                            cur_extension_msg)
                    )
            ptr += cur_extension_len

    def getType(self) -> tls1_3.tls_handshake.HandshakeCode:
        return tls1_3.tls_handshake.HandshakeCode.SERVER_HELLO

    def update_state(self, state: tls1_3.tls_state.tls_state):
        if (self.legacy_session_id != state.legacy_session_id):
            raise Exception("Legacy session ID does not match")

        state.add_chosen_cipher_suite(self.cipher_suite)

        for extension in self.extensions:
            extension.update_state(state)


def handle_server_hello(complete_message, state):
    typed_message = tls1_3.tls_plaintext.TLSPlaintext.fromSerializedMessage(
        complete_message)
    if (typed_message.content_type != tls1_3.tls_plaintext.ContentType.HANDSHAKE):
        raise Exception("Not a Handshake Protocol")

    handshake_message = tls1_3.tls_handshake.Handshake.fromSerializedMessage(
        typed_message.message)
    if (handshake_message.type != tls1_3.tls_handshake.HandshakeCode.SERVER_HELLO):
        raise Exception("Not a server hello")

    typed_server_hello = server_hello(handshake_message.msg)
    typed_server_hello.update_state(state)
