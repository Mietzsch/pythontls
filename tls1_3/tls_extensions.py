# tls_extensions.py

from enum import IntEnum

import tls1_3.tls_constants
import tls1_3.tls_crypto
import tls1_3.tls_state


class ExtensionCode(IntEnum):
    SUPPORTED_GROUPS = 10,
    SIGNATURE_ALOGRITHMS = 13,
    SUPPORTED_VERSIONS = 43,
    KEY_SHARE = 51


class Extension:
    def getType(self) -> ExtensionCode:
        raise NotImplementedError("Should have implemented this")

    def serialize(self) -> bytes:
        raise NotImplementedError("Should have implemented this")

    def update_state(self, state: tls1_3.tls_state.tls_state):
        raise NotImplementedError("Should have implemented this")


class ExtensionMessage:
    type: ExtensionCode
    length: int  # as 2 bytes
    message: bytes

    def __init__(self, extension: Extension):
        self.type = extension.getType()
        self.message = extension.serialize()

    def serialize(self) -> bytes:
        out = int(self.type.value).to_bytes(2, 'big')  # as two bytes
        out += len(self.message).to_bytes(2, 'big')
        out += self.message
        return out


class SupportedVersionsExtension(Extension):
    supported_versions: list[tls1_3.tls_constants.ProtocolVersion]

    def __init__(self, versions: list[tls1_3.tls_constants.ProtocolVersion]):
        self.supported_versions = versions

    @classmethod
    def fromSerializedMessage(cls, message: bytes):
        version = tls1_3.tls_constants.ProtocolVersion.from_bytes(
            message, 'big')
        return cls([version])

    def getType(self) -> ExtensionCode:
        return ExtensionCode.SUPPORTED_VERSIONS

    def serialize(self) -> bytes:
        total_len = 2 * len(self.supported_versions)
        out = total_len.to_bytes(1, 'big')
        for version in self.supported_versions:
            out += int(version.value).to_bytes(2, 'big')
        return out

    def update_state(self, state: tls1_3.tls_state.tls_state):
        state.handle_supported_versions(self.supported_versions)


class SignatureAlgorithmsExtension(Extension):
    supported_algos: list[tls1_3.tls_constants.SignatureScheme]

    def __init__(self, algos: list[tls1_3.tls_constants.SignatureScheme]):
        self.supported_algos = algos

    def getType(self) -> ExtensionCode:
        return ExtensionCode.SIGNATURE_ALOGRITHMS

    def serialize(self) -> bytes:
        total_len = 2 * len(self.supported_algos)
        out = total_len.to_bytes(2, 'big')
        for version in self.supported_algos:
            out += int(version.value).to_bytes(2, 'big')
        return out

    def update_state(self, state: tls1_3.tls_state.tls_state):
        pass


class SupportedGroupsExtension(Extension):
    supported_groups = [tls1_3.tls_constants.NamedGroup]

    def __init__(self, groups: list[tls1_3.tls_constants.NamedGroup]):
        self.supported_groups = groups

    def getType(self) -> ExtensionCode:
        return ExtensionCode.SUPPORTED_GROUPS

    def serialize(self) -> bytes:
        total_len = 2 * len(self.supported_groups)
        out = total_len.to_bytes(2, 'big')
        for group in self.supported_groups:
            out += int(group.value).to_bytes(2, 'big')
        return out

    def update_state(self, state: tls1_3.tls_state.tls_state):
        pass


class KeyShareExtension(Extension):
    key_shares: dict

    def __init__(self, groups: list[tls1_3.tls_constants.NamedGroup], shares: list[bytes]):
        self.key_shares = dict()
        for group, share in zip(groups, shares):
            self.key_shares[group] = share

    @classmethod
    def fromSerializedMessage(cls, message: bytes):
        group = tls1_3.tls_constants.NamedGroup.from_bytes(
            message[0:2], 'big')
        len = int.from_bytes(message[2:4], 'big')
        key_share = message[4:4+len]
        return cls([group], [key_share])

    def getType(self) -> ExtensionCode:
        return ExtensionCode.KEY_SHARE

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

    def update_state(self, state: tls1_3.tls_state.tls_state):
        state.handle_key_share(self.key_shares)


def compile_list_of_extensions(message: bytes) -> list[Extension]:
    ptr = 0
    extensions_len = int.from_bytes(message[ptr:ptr+2], 'big')
    ptr += 2
    last_byte = ptr + extensions_len
    extensions = list()
    while (ptr < last_byte):
        cur_extension_type = tls1_3.tls_extensions.ExtensionCode.from_bytes(
            message[ptr:ptr+2], 'big')
        ptr += 2
        cur_extension_len = int.from_bytes(
            message[ptr:ptr+2], 'big')
        ptr += 2
        cur_extension_msg = message[ptr:ptr+cur_extension_len]
        match cur_extension_type:
            case tls1_3.tls_extensions.ExtensionCode.SUPPORTED_VERSIONS:
                extensions.append(
                    tls1_3.tls_extensions.SupportedVersionsExtension.fromSerializedMessage(cur_extension_msg))
            case tls1_3.tls_extensions.ExtensionCode.KEY_SHARE:
                extensions.append(
                    tls1_3.tls_extensions.KeyShareExtension.fromSerializedMessage(
                        cur_extension_msg)
                )
        ptr += cur_extension_len

    return extensions
