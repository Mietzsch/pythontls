# tls_crypto.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
import copy

import tls1_3.tls_constants


def generate_key_share(group: tls1_3.tls_constants.NamedGroup) -> tuple[bytes, bytes]:
    uncompressed_magic_number = 4
    match group:
        case tls1_3.tls_constants.NamedGroup.SECP256R1:
            sk = ec.generate_private_key(ec.SECP256R1)
            out_sk = sk.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            pk = sk.public_key()
            pk_numbers = pk.public_numbers()
            out_pk = uncompressed_magic_number.to_bytes(1, 'big')
            out_pk += pk_numbers.x.to_bytes(32, 'big')
            out_pk += pk_numbers.y.to_bytes(32, 'big')
            return [out_sk, out_pk]
        case tls1_3.tls_constants.NamedGroup.SECP384R1:
            sk = ec.generate_private_key(ec.SECP384R1)
            out_sk = sk.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            pk = sk.public_key()
            pk_numbers = pk.public_numbers()
            out = uncompressed_magic_number.to_bytes(1, 'big')
            out += pk_numbers.x.to_bytes(48, 'big')
            out += pk_numbers.y.to_bytes(48, 'big')
            return [out_sk, out_pk]
        case tls1_3.tls_constants.NamedGroup.SECP521R1:
            sk = ec.generate_private_key(ec.SECP521R1)
            out_sk = sk.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            pk = sk.public_key()
            pk_numbers = pk.public_numbers()
            out = uncompressed_magic_number.to_bytes(1, 'big')
            out += pk_numbers.x.to_bytes(66, 'big')
            out += pk_numbers.y.to_bytes(66, 'big')
            return [out_sk, out_pk]
        case tls1_3.tls_constants.NamedGroup.X25519:
            sk = x25519.X25519PrivateKey.generate()
            out_sk = sk.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            pk = sk.public_key()
            return [out_sk, pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)]
        case tls1_3.tls_constants.NamedGroup.X448:
            sk = x448.X448PrivateKey.generate()
            out_sk = sk.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            pk = sk.public_key()
            return [out_sk, pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)]


def generate_shared_secret(group: tls1_3.tls_constants.NamedGroup, own_secret: bytes, foreign_secret: bytes) -> bytes:
    match group:
        case tls1_3.tls_constants.NamedGroup.X25519:
            sk = x25519.X25519PrivateKey.from_private_bytes(own_secret)
            foreign_pk = x25519.X25519PublicKey.from_public_bytes(
                foreign_secret)
            ss = sk.exchange(foreign_pk)
            return ss


def hdkf_extract(hash: hashes.HashAlgorithm, salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hash)
    h.update(ikm)
    return h.finalize()


def hkdf_expand(hash: hashes.HashAlgorithm, prk: bytes, info: bytes, l: int) -> bytes:
    if len(prk) < hash.digest_size:
        raise "prk too short!"

    if l > hash.digest_size:
        raise "Not implemented!"

    counter = 1

    h = hmac.HMAC(prk, hash)
    h.update(info)
    h.update(counter.to_bytes(1, 'big'))
    return h.finalize()[0:l]


def hkdf_expand_label(hash: hashes.HashAlgorithm, secret: bytes, label: str, context: bytes, l: int) -> bytes:
    h_label = l.to_bytes(2, 'big')
    stringlabel = "tls13 " + label
    h_label += len(stringlabel).to_bytes(1, 'big')
    h_label += stringlabel.encode()
    h_label += len(context).to_bytes(1, 'big')
    h_label += context
    return hkdf_expand(hash, secret, h_label, l)


def derive_secret(hash: hashes.HashAlgorithm, secret: bytes, label: str, messages: list[bytes]) -> bytes:
    h = hashes.Hash(hash)
    for message in messages:
        h.update(message)
    transcript_hash = h.finalize()
    return hkdf_expand_label(hash, secret, label, transcript_hash, hash.digest_size)


class tls_key_schedule:
    hash: hashes.HashAlgorithm
    early_secret: bytes
    handshake_secret: bytes
    master_secret: bytes
    client_handshake_traffic_secret: bytes
    server_handshake_traffic_secret: bytes

    def __init__(self, cipher_suite):
        match cipher_suite:
            case tls1_3.tls_constants.CipherSuite.TLS_AES_128_GCM_SHA256:
                self.hash = hashes.SHA256()
                self.hash
            case tls1_3.tls_constants.CipherSuite.TLS_AES_256_GCM_SHA384:
                self.hash = hashes.SHA384()
            case tls1_3.tls_constants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                self.hash = hashes.SHA256()

    def derive_early_secret(self, psk=bytes()):
        if len(psk) == 0:
            self.early_secret = hdkf_extract(
                self.hash, bytes(self.hash.digest_size), bytes(self.hash.digest_size))
        else:
            self.early_secret = hdkf_extract(
                self.hash, bytes(self.hash.digest_size), psk)

    def derive_handshake_secret(self, ecdh_secret=bytes(), transcript=dict()):
        derived = derive_secret(
            self.hash, self.early_secret, "derived", [bytes()])
        self.handshake_secret = hdkf_extract(
            self.hash, derived, ecdh_secret)

        client_hello = transcript[tls1_3.tls_constants.HandshakeCode.CLIENT_HELLO]
        server_hello = transcript[tls1_3.tls_constants.HandshakeCode.SERVER_HELLO]

        self.client_handshake_traffic_secret = derive_secret(
            self.hash, self.handshake_secret, "c hs traffic", [client_hello, server_hello])
        self.server_handshake_traffic_secret = derive_secret(
            self.hash, self.handshake_secret, "s hs traffic", [client_hello, server_hello])

    def derive_master_secret(self, transcript=dict()):
        pass
        # derive
