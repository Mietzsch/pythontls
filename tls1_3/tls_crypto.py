# tls_crypto.py

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

import tls1_3.tls_constants
import tls1_3.tls_state


def generate_key_share(group: tls1_3.tls_constants.NamedGroup, state: tls1_3.tls_state.tls_state) -> bytes:
    match group:
        case tls1_3.tls_constants.NamedGroup.X25519:
            sk = x25519.X25519PrivateKey.generate()
            state.add_key_share(group, sk.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            pk = sk.public_key()
            return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
