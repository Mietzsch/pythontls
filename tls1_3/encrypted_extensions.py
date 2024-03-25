# encrypted_extensions

import tls1_3.tls_constants
import tls1_3.tls_state
import tls1_3.tls_extensions
import tls1_3.tls_handshake


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
