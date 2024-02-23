# tls_state.py

import tls1_3.tls_constants


class tls_state:
    hostname = 'localhost'
    port = 44330
    legacy_session_id: bytes
    proposed_cipher_suites: list[tls1_3.tls_constants.CipherSuite]
    chosen_cipher_suite: tls1_3.tls_constants.CipherSuite
    keyshares = dict()

    def add_key_share(self, group: tls1_3.tls_constants.NamedGroup, sk: bytes):
        self.keyshares[group] = sk

    def add_legacy_session_id(self, id: bytes):
        self.legacy_session_id = id

    def add_proposed_cipher_suites(self, suites):
        self.proposed_cipher_suites = suites

    def add_chosen_cipher_suite(self, suite):
        if (self.proposed_cipher_suites.count(suite) != 1):
            raise "Chosen cipher suite was not offered"
        self.chosen_cipher_suite = suite
