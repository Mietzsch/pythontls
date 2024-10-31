# tls_crypto.py

from cryptography.hazmat.primitives.asymmetric import (ec, rsa)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305, AESGCM)
from cryptography import x509


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


def decrypt_record(suite: tls1_3.tls_constants.CipherSuite, key: bytes, record_no: int, messsage: bytes):
    if (record_no.bit_length() > 64):
        raise Exception("Too many records")
    padded_record_number = record_no.to_bytes(12, 'big')

    match suite:
        case tls1_3.tls_constants.CipherSuite.TLS_AES_128_GCM_SHA256:
            server_write_iv = hkdf_expand_label(
                hashes.SHA256(), key, "iv", bytes(), 12)
            iv = bytes(a ^ b for a, b in zip(
                padded_record_number, server_write_iv))
            peer_write_key = hkdf_expand_label(
                hashes.SHA256(), key, "key", bytes(), 16)
            decryptor = AESGCM(peer_write_key)
        case tls1_3.tls_constants.CipherSuite.TLS_AES_256_GCM_SHA384:
            server_write_iv = hkdf_expand_label(
                hashes.SHA384(), key, "iv", bytes(), 12)
            iv = bytes(a ^ b for a, b in zip(
                padded_record_number, server_write_iv))
            peer_write_key = hkdf_expand_label(
                hashes.SHA384(), key, "key", bytes(), 32)
            decryptor = AESGCM(peer_write_key)
        case tls1_3.tls_constants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            server_write_iv = hkdf_expand_label(
                hashes.SHA256(), key, "iv", bytes(), 12)
            iv = bytes(a ^ b for a, b in zip(
                padded_record_number, server_write_iv))
            peer_write_key = hkdf_expand_label(
                hashes.SHA256(), key, "key", bytes(), 32)
            decryptor = ChaCha20Poly1305(peer_write_key)

    return decryptor.decrypt(iv, messsage[5:], messsage[0:5])


def encrypt_record(suite: tls1_3.tls_constants.CipherSuite, key: bytes, record_no: int, aad: bytes, messsage: bytes):
    if (record_no.bit_length() > 64):
        raise Exception("Too many records")
    padded_record_number = record_no.to_bytes(12, 'big')

    match suite:
        case tls1_3.tls_constants.CipherSuite.TLS_AES_128_GCM_SHA256:
            client_write_iv = hkdf_expand_label(
                hashes.SHA256(), key, "iv", bytes(), 12)
            iv = bytes(a ^ b for a, b in zip(
                padded_record_number, client_write_iv))
            peer_write_key = hkdf_expand_label(
                hashes.SHA256(), key, "key", bytes(), 16)
            encryptor = AESGCM(peer_write_key)
        case tls1_3.tls_constants.CipherSuite.TLS_AES_256_GCM_SHA384:
            client_write_iv = hkdf_expand_label(
                hashes.SHA384(), key, "iv", bytes(), 12)
            iv = bytes(a ^ b for a, b in zip(
                padded_record_number, client_write_iv))
            peer_write_key = hkdf_expand_label(
                hashes.SHA384(), key, "key", bytes(), 32)
            encryptor = AESGCM(peer_write_key)
        case tls1_3.tls_constants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            client_write_iv = hkdf_expand_label(
                hashes.SHA256(), key, "iv", bytes(), 12)
            iv = bytes(a ^ b for a, b in zip(
                padded_record_number, client_write_iv))
            peer_write_key = hkdf_expand_label(
                hashes.SHA256(), key, "key", bytes(), 32)
            encryptor = ChaCha20Poly1305(peer_write_key)

    return encryptor.encrypt(iv, messsage, aad)


def hdkf_extract(hash: hashes.HashAlgorithm, salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hash)
    h.update(ikm)
    return h.finalize()


def hkdf_expand(hash: hashes.HashAlgorithm, prk: bytes, info: bytes, l: int) -> bytes:
    if len(prk) < hash.digest_size:
        raise Exception("prk too short!")

    if l > hash.digest_size:
        raise NotImplementedError("Not implemented!")

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


def derive_secret(hash: hashes.HashAlgorithm, secret: bytes, label: str, transcript: dict) -> bytes:
    h = hashes.Hash(hash)
    for code, message in transcript.items():
        h.update(message)
    transcript_hash = h.finalize()
    return hkdf_expand_label(hash, secret, label, transcript_hash, hash.digest_size)


def check_signature(cipher_suite, scheme, transcript, certificate, signature):
    match cipher_suite:
        case tls1_3.tls_constants.CipherSuite.TLS_AES_128_GCM_SHA256:
            hash = hashes.Hash(hashes.SHA256())
        case tls1_3.tls_constants.CipherSuite.TLS_AES_256_GCM_SHA384:
            hash = hashes.Hash(hashes.SHA384())
        case tls1_3.tls_constants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            hash = hashes.Hash(hashes.SHA256())

    match scheme:
        case tls1_3.tls_constants.SignatureScheme.ECDSA_SECP256R1_SHA256:
            sig_hash = hashes.SHA256()
        case tls1_3.tls_constants.SignatureScheme.RSA_PSS_RSAE_SHA256:
            sig_hash = hashes.SHA256()
        case tls1_3.tls_constants.SignatureScheme.ECDSA_SECP384R1_SHA384:
            sig_hash = hashes.SHA384()
        case tls1_3.tls_constants.SignatureScheme.ECDSA_SECP521R1_SHA512:
            sig_hash = hashes.SHA512()

    for code, message in transcript.items():
        hash.update(message)
    transcript_hash = hash.finalize()

    content = bytes(b'\x20')*64
    content += "TLS 1.3, server CertificateVerify".encode()
    content += b'\x00'
    content += transcript_hash

    cert = x509.load_der_x509_certificate(certificate)
    pk = cert.public_key()
    match scheme:
        case tls1_3.tls_constants.SignatureScheme.ECDSA_SECP256R1_SHA256:
            pk.verify(signature, content, ec.ECDSA(sig_hash))
        case tls1_3.tls_constants.SignatureScheme.RSA_PSS_RSAE_SHA256:
            pk.verify(signature, content, padding.PSS(
                mgf=padding.MGF1(sig_hash), salt_length=padding.PSS.DIGEST_LENGTH), sig_hash)
        case tls1_3.tls_constants.SignatureScheme.ECDSA_SECP384R1_SHA384:
            pk.verify(signature, content, ec.ECDSA(sig_hash))
        case tls1_3.tls_constants.SignatureScheme.ECDSA_SECP521R1_SHA512:
            pk.verify(signature, content, ec.ECDSA(sig_hash))


class tls_key_schedule:
    hash: hashes.HashAlgorithm
    early_secret: bytes
    handshake_secret: bytes
    master_secret: bytes
    client_handshake_traffic_secret: bytes
    server_handshake_traffic_secret: bytes
    client_application_traffic_secret: bytes
    server_application_traffic_secret: bytes

    def __init__(self, cipher_suite):
        match cipher_suite:
            case tls1_3.tls_constants.CipherSuite.TLS_AES_128_GCM_SHA256:
                self.hash = hashes.SHA256()
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
            self.hash, self.early_secret, "derived", dict())
        self.handshake_secret = hdkf_extract(
            self.hash, derived, ecdh_secret)

        self.client_handshake_traffic_secret = derive_secret(
            self.hash, self.handshake_secret, "c hs traffic", transcript)
        self.server_handshake_traffic_secret = derive_secret(
            self.hash, self.handshake_secret, "s hs traffic", transcript)

    def verify_server_finished(self, verify_data, transcript=dict()):
        server_finished_key = hkdf_expand_label(
            self.hash, self.server_handshake_traffic_secret, "finished", bytes(), self.hash.digest_size)
        h = hashes.Hash(self.hash)
        for code, message in transcript.items():
            h.update(message)
        hm = hmac.HMAC(server_finished_key, self.hash)
        hm.update(h.finalize())
        calculated_verify_data = hm.finalize()
        if verify_data != calculated_verify_data:
            raise Exception("Server finished incorrect")

    def calc_client_finished(self, transcript=dict()):
        client_finished_key = hkdf_expand_label(
            self.hash, self.client_handshake_traffic_secret, "finished", bytes(), self.hash.digest_size)
        h = hashes.Hash(self.hash)
        for code, message in transcript.items():
            h.update(message)
        hm = hmac.HMAC(client_finished_key, self.hash)
        hm.update(h.finalize())
        return hm.finalize()

    def derive_master_secret(self, transcript=dict()):
        derived = derive_secret(
            self.hash, self.handshake_secret, "derived", dict())
        self.master_secret = hdkf_extract(
            self.hash, derived, bytes(self.hash.digest_size))

        self.client_application_traffic_secret = derive_secret(
            self.hash, self.master_secret, "c ap traffic", transcript)
        self.server_application_traffic_secret = derive_secret(
            self.hash, self.master_secret, "s ap traffic", transcript)
