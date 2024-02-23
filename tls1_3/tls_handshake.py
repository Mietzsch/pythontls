# tls_handshake.py

from enum import IntEnum

import tls1_3.tls_constants
import tls1_3.tls_plaintext


class HandshakeCode(IntEnum):
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    CERTIFICATE_REQUEST = 13,
    CERTIFICATE_VERIFY = 15,
    FINISHED = 20,
    KEY_UPDATE = 24,
    MESSAGE_HASH = 254,
    EMPTY = 255


class HandshakeMessage:
    def getType(self) -> HandshakeCode:
        raise NotImplementedError("Should have implemented this")

    def serialize(self) -> bytes:
        raise NotImplementedError("Should have implemented this")


class Handshake(tls1_3.tls_plaintext.TLSPlaintextMessage):
    type: HandshakeCode
    msg: bytes

    def __init__(self, type, message):
        self.type = type
        self.msg = message

    @classmethod
    def fromHandshakeMessage(cls, message: HandshakeMessage):
        return cls(message.getType(), message.serialize())

    @classmethod
    def fromSerializedMessage(cls, serialized_message: bytes):
        type = HandshakeCode.from_bytes(
            serialized_message[0:1], 'big')
        message_len = int.from_bytes(serialized_message[1:4], 'big')
        message = serialized_message[4:4+message_len]
        return cls(type, message)

    def getType(self) -> tls1_3.tls_plaintext.ContentType:
        return tls1_3.tls_plaintext.ContentType.HANDSHAKE

    def serialize(self) -> bytes:
        out = int(self.type.value).to_bytes(1, 'big')
        out += len(self.msg).to_bytes(3, 'big')
        out += self.msg
        return out
