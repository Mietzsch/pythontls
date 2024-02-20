# tls_extensions.py

from enum import IntEnum

import tls1_3.tls_constants


class Extension(IntEnum):
    SUPPORTED_GROUPS = 10,
    SUPPORTED_VERSIONS = 43


class extension_message:
    type: Extension
    length: int  # as 2 bytes
    message: bytes

    def __init__(self, type: Extension, message: bytes):
        self.type = type
        self.length = len(message)
        self.message = message

    def serialize(self) -> bytes:
        out = int(self.type.value).to_bytes(2, 'big')  # as two bytes
        out += self.length.to_bytes(2, 'big')
        out += self.message
        return out


class SupportedVersionsExtension:
    supported_versions: [tls1_3.tls_constants.ProtocolVersion]

    def __init__(self, versions: [tls1_3.tls_constants.ProtocolVersion]):
        self.supported_versions = versions

    def serialize(self) -> bytes:
        total_len = 2 * len(self.supported_versions)
        out = total_len.to_bytes(1, 'big')
        for version in self.supported_versions:
            out += int(version.value).to_bytes(2, 'big')
        return out
