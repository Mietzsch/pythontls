# tls_constants.py

from enum import IntEnum


class ContentType(IntEnum):
    INVALID = 0,
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    EMPTY = 255


class CipherSuite(IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303


class NamedGroup(IntEnum):
    SECP256R1 = 0x0017,
    SECP384R1 = 0x0018,
    SECP521R1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,
    X25519MLKEM768 = 0x11EC


class ProtocolVersion(IntEnum):
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304


class SignatureScheme(IntEnum):
    RSA_PKCS1_SHA256 = 0x0401,
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
    RSA_PSS_RSAE_SHA256 = 0x0804,
    ED25519 = 0x0807
    RSA_PSS_PSS_SHA256 = 0x0809,


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
