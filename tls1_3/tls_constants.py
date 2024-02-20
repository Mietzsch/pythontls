# tls_constants.py

from enum import IntEnum


class CipherSuites(IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302


class ProtocolVersion(IntEnum):
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304
