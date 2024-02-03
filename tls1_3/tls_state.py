# tls_state.py

from enum import Enum
from enum import IntEnum


class tls_state:
    hostname = 'localhost'
    port = 44330


class HandshakeType(IntEnum):
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


class ContentType(IntEnum):
    INVALID = 0,
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    EMPTY = 255


class ProtocolVersion(IntEnum):
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304


class CipherSuites(IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302


class Extension(IntEnum):
    SUPPORTED_GROUP = 10


class extension_message:
    type: Extension
    length: int  # as 2 bytes
    extension: bytes

    def __init__(self, type: Extension, message: bytes):
        self.type = type
        self.length = len(message)
        self.message = message

    def serialize(self) -> bytes:
        out = bytes(type.value, 2, 'big')  # as two bytes
        out += self.length.to_bytes(2, 'big')
        out += self.extension


class handshake_message:
    type: HandshakeType
    length: int  # as 3 bytes
    message: bytes

    def __init__(self, type: HandshakeType, message: bytes):
        self.type = type
        self.length = len(message)
        self.message = message

    def serialize_as_plaintext_record(self, content_type: ContentType, protocol_version=ProtocolVersion.TLS_1_3) -> bytes:
        out = int(content_type.value).to_bytes(1, 'big')
        out += int(protocol_version.value).to_bytes(2, 'big')
        total_len = 1 + 3 + len(self.message)
        out += total_len.to_bytes(2, 'big')  # as 2 bytes
        out += int(self.type.value).to_bytes(1, 'little')
        out += self.length.to_bytes(3, 'big')
        out += self.message
        return out
