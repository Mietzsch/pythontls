# tls_plaintext.py

from enum import IntEnum

import tls1_3.tls_constants


class ContentType(IntEnum):
    INVALID = 0,
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    EMPTY = 255


class TLSPlaintextMessage:
    def getType(self) -> ContentType:
        raise NotImplementedError("Should have implemented this")

    def serialize(self) -> bytes:
        raise NotImplementedError("Should have implemented this")


class TLSPlaintext:
    content_type: ContentType
    protocol_version: tls1_3.tls_constants.ProtocolVersion
    message: bytes

    def __init__(self, content_type, protocol_version, message):
        self.content_type = content_type
        self.protocol_version = protocol_version
        self.message = message

    @classmethod
    def fromTLSPlaintext(cls, message: TLSPlaintextMessage, protocol_version=tls1_3.tls_constants.ProtocolVersion.TLS_1_2):
        return cls(message.getType(), protocol_version, message.serialize())

    @classmethod
    def fromSerializedMessage(cls, serialized_message: bytes):
        content_type = tls1_3.tls_plaintext.ContentType.from_bytes(
            serialized_message[0:1], 'big')
        protocol_version = tls1_3.tls_constants.ProtocolVersion.from_bytes(
            serialized_message[1:3], 'big')
        message = serialized_message[5:]
        return cls(content_type, protocol_version, message)

    def serialize(self) -> bytes:
        out = int(self.content_type.value).to_bytes(1, 'big')
        out += int(self.protocol_version.value).to_bytes(2, 'big')
        out += len(self.message).to_bytes(2, 'big')
        out += self.message
        return out
