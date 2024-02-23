# tls_constants.py

from enum import IntEnum


class CipherSuite(IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303


class NamedGroup(IntEnum):
    SECP256R1 = 0x0017,
    SECP384R1 = 0x0018,
    SECP521R1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E


class ProtocolVersion(IntEnum):
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304


class SignatureScheme(IntEnum):
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
