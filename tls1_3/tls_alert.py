# tls_alert.py

from enum import IntEnum

import tls1_3.tls_plaintext


class AlertLevel(IntEnum):
    WARNING = 1,
    FATAL = 2,
    EMPTY = 255


class AlertDescription(IntEnum):
    CLOSE_NOTIFY = 0,
    UNEXPECTED_MESSAGE = 10,
    BAD_RECORD_MAC = 20,
    RECORD_OVERFLOW = 22,
    HANDSHAKE_FAILURE = 40,
    BAD_CERTIFICATE = 42,
    UNSUPPORTED_CERTIFICATE = 43,
    CERTIFICATE_REVOKED = 44,
    CERTIFICATE_EXPIRED = 45,
    CERTIFICATE_UNKNOWN = 46,
    ILLEGAL_PARAMETER = 47,
    UNKNOWN_CA = 48,
    ACCESS_DENIED = 49,
    DECODE_ERROR = 50,
    DECRYPT_ERROR = 51,
    PROTOCOL_VERSION = 70,
    INSUFFICIENT_SECURITY = 71,
    INTERNAL_ERROR = 80,
    INAPPROPRIATE_FALLBACK = 86,
    USER_CANCELED = 90,
    MISSING_EXTENSION = 109,
    UNSUPPORTED_EXTENSION = 110,
    UNRECOGNIZED_NAME = 112,
    BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    UNKNOWN_PSK_IDENTITY = 115,
    CERTIFICATE_REQUIRED = 116,
    NO_APPLICATION_PROTOCOL = 120,
    EMPTY = 255


class Alert(tls1_3.tls_plaintext.TLSPlaintextMessage):
    level: AlertLevel
    description: AlertDescription

    def __init__(self, level, description):
        self.level = level
        self.description = description

    @classmethod
    def fromSerializedMessage(cls, serialized_message: bytes):
        level = AlertLevel.from_bytes(
            serialized_message[0:1], 'big')
        description = AlertDescription.from_bytes(
            serialized_message[1:2], 'big')
        return cls(level, description)

    def getType(self) -> tls1_3.tls_plaintext.ContentType:
        return tls1_3.tls_plaintext.ContentType.ALERT

    def serialize(self) -> bytes:
        out = int(self.level).to_bytes(1, 'big')
        out += int(self.description).to_bytes(1, 'big')
        return out
