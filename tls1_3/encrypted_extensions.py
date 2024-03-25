# encrypted_extensions

import tls1_3.tls_plaintext
import tls1_3.tls_constants
import tls1_3.tls_state
import tls1_3.tls_extensions


class encypted_extensions(tls1_3.tls_handshake.HandshakeMessage):
    extensions: list[tls1_3.tls_extensions.Extension]

    def __init__(self, serialized_message):
        self.extensions = tls1_3.tls_extensions.compile_list_of_extensions(
            serialized_message)

    def getType(self) -> tls1_3.tls_handshake.HandshakeCode:
        return tls1_3.tls_constants.HandshakeCode.ENCRYPTED_EXTENSIONS

    def update_state(self, state: tls1_3.tls_state.tls_state):
        if (len(self.extensions) != 0):
            raise NotImplementedError("Encypted Extensions not implemented")


def handle_encypted_extensions(complete_message, state):
    if complete_message[-1] == 0:
        raise NotImplementedError("Padding not implemented")
    else:
        handshake_type = tls1_3.tls_plaintext.ContentType(complete_message[-1])

    if handshake_type != tls1_3.tls_plaintext.ContentType.HANDSHAKE:
        raise Exception("Not a Handshake Protocol")

    handshake_message = tls1_3.tls_handshake.Handshake.fromSerializedMessage(
        complete_message[:-1])
    if (handshake_message.type != tls1_3.tls_constants.HandshakeCode.ENCRYPTED_EXTENSIONS):
        raise Exception("Not a encrypted extensions message")

    typed_encrypted_extensions = encypted_extensions(handshake_message.msg)
    typed_encrypted_extensions.update_state(state)
