# tls_extensions.py

from enum import IntEnum

import tls1_3.tls_constants
import tls1_3.tls_crypto
import tls1_3.tls_state


class Extension(IntEnum):
    SUPPORTED_GROUPS = 10,
    SIGNATURE_ALOGRITHMS = 13,
    SUPPORTED_VERSIONS = 43,
    KEY_SHARE = 51


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


class SignatureAlgorithmsExtension:
    supported_algos: [tls1_3.tls_constants.SignatureScheme]

    def __init__(self, algos: [tls1_3.tls_constants.SignatureScheme]):
        self.supported_algos = algos

    def serialize(self) -> bytes:
        total_len = 2 * len(self.supported_algos)
        out = total_len.to_bytes(2, 'big')
        for version in self.supported_algos:
            out += int(version.value).to_bytes(2, 'big')
        return out


class SupportedGroupsExtension:
    supported_groups = [tls1_3.tls_constants.NamedGroup]

    def __init__(self, groups: [tls1_3.tls_constants.NamedGroup]):
        self.supported_groups = groups

    def serialize(self) -> bytes:
        total_len = 2 * len(self.supported_groups)
        out = total_len.to_bytes(2, 'big')
        for group in self.supported_groups:
            out += int(group.value).to_bytes(2, 'big')
        return out


class KeyShareExtension:
    key_shares: dict

    def __init__(self, groups: [tls1_3.tls_constants.NamedGroup], state: tls1_3.tls_state.tls_state):
        self.key_shares = dict()
        for group in groups:
            self.key_shares[group] = tls1_3.tls_crypto.generate_key_share(
                group, state)

    def serialize(self) -> bytes:
        total_shares = bytes()
        for group, share in self.key_shares.items():
            total_shares += int(group.value).to_bytes(2, 'big')
            total_shares += len(share).to_bytes(2, 'big')
            total_shares += share
        total_len = len(total_shares)
        out = total_len.to_bytes(2, 'big')
        out += total_shares
        return out
