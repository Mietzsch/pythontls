# certificate_verify.py

import tls1_3.tls_constants
import tls1_3.tls_state
import tls1_3.tls_extensions
import tls1_3.tls_handshake


class certificate_verify(tls1_3.tls_handshake.HandshakeMessage):
    scheme: tls1_3.tls_constants.SignatureScheme
    signature: bytes

    def __init__(self, serialized_message):
        self.scheme = tls1_3.tls_constants.SignatureScheme.from_bytes(
            serialized_message[0:2], 'big')
        sig_size = int.from_bytes(serialized_message[2:4], 'big')
        self.signature = serialized_message[4:4+sig_size]

    def getType(self) -> tls1_3.tls_handshake.HandshakeCode:
        return tls1_3.tls_constants.HandshakeCode.CERTIFICATE_VERIFY

    def update_state(self, state: tls1_3.tls_state.tls_state):
        state.verify_sig(self.scheme, self.signature)
