# tls_state.py

import tls1_3.tls_constants


class tls_state:
    hostname = 'localhost'
    port = 44330
    keyshares = dict()

    def add_key_share(self, group: tls1_3.tls_constants.NamedGroup, sk: bytes):
        self.keyshares[group] = sk
