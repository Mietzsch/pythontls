# finished.py

import tls1_3.tls_constants
import tls1_3.tls_state
import tls1_3.tls_extensions
import tls1_3.tls_handshake


class finished(tls1_3.tls_handshake.HandshakeMessage):
    verify_data: bytes

    def __init__(self, serialized_message):
        self.verify_data = serialized_message

    def getType(self) -> tls1_3.tls_handshake.HandshakeCode:
        return tls1_3.tls_constants.HandshakeCode.FINISHED

    def serialize(self) -> bytes:
        return self.verify_data

    def update_state(self, state: tls1_3.tls_state.tls_state):
        state.verify_finished(self.verify_data)
