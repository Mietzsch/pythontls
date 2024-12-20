# tls_state.py

from enum import Enum

import tls1_3.tls_constants
import tls1_3.tls_crypto
import tls1_3.tls_handshake


class TLSStep(Enum):
    CLIENT_HELLO = 1
    CLIENT_HELLO_SENT = 2
    SERVER_HELLO_RECEIVED = 3
    SERVER_HANDSHAKE_FINISHED = 4
    SETUP_FINISHED = 5


class tls_state:
    hostname = '142.251.36.238'
    port = 443
    # hostname = 'localhost'
    # port = 44330
    step = TLSStep.CLIENT_HELLO
    legacy_session_id: bytes
    transcript = dict()
    proposed_cipher_suites: list[tls1_3.tls_constants.CipherSuite]
    chosen_cipher_suite: tls1_3.tls_constants.CipherSuite
    offered_versions: list[tls1_3.tls_constants.ProtocolVersion]
    chosen_version: tls1_3.tls_constants.ProtocolVersion
    offered_sig_schemes: list[tls1_3.tls_constants.SignatureScheme]
    server_cert: bytes
    keyshares = dict()
    shared_secret = bytes()
    keys: tls1_3.tls_crypto.tls_key_schedule
    decrypted_records = 0
    encrypted_records = 0

    def add_key_share(self, group: tls1_3.tls_constants.NamedGroup, sk: bytes):
        self.keyshares[group] = sk

    def add_legacy_session_id(self, id: bytes):
        self.legacy_session_id = id

    def add_proposed_cipher_suites(self, suites):
        self.proposed_cipher_suites = suites

    def save_message(self, code, message):
        match code:
            case tls1_3.tls_handshake.HandshakeCode.CLIENT_HELLO:
                self.step = TLSStep.CLIENT_HELLO_SENT
            case tls1_3.tls_handshake.HandshakeCode.SERVER_HELLO:
                self.step = TLSStep.SERVER_HELLO_RECEIVED
            case tls1_3.tls_handshake.HandshakeCode.FINISHED:
                self.step = TLSStep.SERVER_HANDSHAKE_FINISHED

        self.transcript[code] = message

    def add_chosen_cipher_suite(self, suite):
        if (self.proposed_cipher_suites.count(suite) != 1):
            raise Exception("Chosen cipher suite was not offered")
        self.chosen_cipher_suite = suite
        self.keys = tls1_3.tls_crypto.tls_key_schedule(
            self.chosen_cipher_suite)
        self.keys.derive_early_secret()

    def handle_supported_versions(self, versions: list[tls1_3.tls_constants.ProtocolVersion]):
        if self.step == TLSStep.CLIENT_HELLO:
            self.offered_versions = versions
        else:
            if len(versions) != 1:
                raise Exception("The versions list has to have length one")
            chosen_version = versions[0]
            if self.offered_versions.count(chosen_version) != 1:
                raise Exception("Chosen version was not offered")
            self.chosen_version = chosen_version

    def handle_key_share(self, keyshares: dict):
        if self.step == TLSStep.CLIENT_HELLO:
            return
        if len(keyshares) != 1:
            raise Exception("only one key share allowed")

        group, other_share = keyshares.popitem()
        own_share = self.keyshares[group]
        self.shared_secret = tls1_3.tls_crypto.generate_shared_secret(
            group, own_share, other_share)
        self.keys.derive_handshake_secret(self.shared_secret, self.transcript)

    def save_cert(self, certificate):
        self.server_cert = certificate

    def verify_sig(self, scheme, signature):
        if self.offered_sig_schemes.count(scheme) != 1:
            raise Exception("Chosen signature scheme was not offered")
        tls1_3.tls_crypto.check_signature(
            self.chosen_cipher_suite, scheme, self.transcript, self.server_cert, signature)

    def verify_finished(self, verify_data):
        self.keys.verify_server_finished(verify_data, self.transcript)

    def calc_client_finished(self):
        return self.keys.calc_client_finished(self.transcript)

    def decrypt_record(self, tls_ciphertext):
        if self.step == TLSStep.SERVER_HELLO_RECEIVED:
            key = self.keys.server_handshake_traffic_secret
        if self.step == TLSStep.SETUP_FINISHED:
            key = self.keys.server_application_traffic_secret
        decrypted = tls1_3.tls_crypto.decrypt_record(
            self.chosen_cipher_suite, key, self.decrypted_records, tls_ciphertext)
        self.decrypted_records += 1
        return decrypted

    def encrypt_record(self, aad, message):
        if self.step == TLSStep.SERVER_HANDSHAKE_FINISHED:
            key = self.keys.client_handshake_traffic_secret
        if self.step == TLSStep.SETUP_FINISHED:
            key = self.keys.client_application_traffic_secret
        encrypted = tls1_3.tls_crypto.encrypt_record(
            self.chosen_cipher_suite, key, self.encrypted_records, aad, message)
        self.encrypted_records += 1
        return encrypted

    def finish_session_setup(self):
        self.keys.derive_master_secret(self.transcript)
        self.decrypted_records = 0
        self.encrypted_records = 0
        self.step = TLSStep.SETUP_FINISHED
