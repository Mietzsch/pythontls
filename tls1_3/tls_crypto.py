# tls_crypto.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import serialization

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
