# certificate.py

import tls1_3.tls_constants
import tls1_3.tls_state
import tls1_3.tls_extensions
import tls1_3.tls_handshake


class certificate(tls1_3.tls_handshake.HandshakeMessage):
    certificate: bytes

    def __init__(self, serialized_message):
        if (serialized_message[0] != 0):
            raise NotImplementedError("Context not implemented")
        ptr = 1
        certificate_list_len = int.from_bytes(
            serialized_message[ptr:ptr+3], 'big')
        ptr += 3
        last_byte = certificate_list_len + ptr
        cert_count = 0
        while (ptr < last_byte):
            cert_len = int.from_bytes(
                serialized_message[ptr:ptr+3], 'big')
            ptr += 3
            if (cert_len > 0):
                cert_count += 1
                if (cert_count > 1):
                    raise NotImplementedError("Only one cert implemented")
                self.certificate = serialized_message[ptr:ptr+cert_len]
            ptr += cert_len
            extn_len = int.from_bytes(
                serialized_message[ptr:ptr+2], 'big')
            ptr += 2
            if (extn_len != 0):
                raise NotImplementedError("Extensions not implemented")

    def getType(self) -> tls1_3.tls_handshake.HandshakeCode:
        return tls1_3.tls_constants.HandshakeCode.CERTIFICATE

    def update_state(self, state: tls1_3.tls_state.tls_state):
        state.save_cert(self.certificate)
