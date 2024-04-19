# client_finished.py


import tls1_3.tls_handshake
import tls1_3.message_dispatcher
import tls1_3.tls_constants
from tls1_3.messages.finished import finished


def create_client_finished(state):
    finished_message = finished(state.calc_client_finished())
    handshake_message = tls1_3.tls_handshake.Handshake.fromHandshakeMessage(
        finished_message)
    return handshake_message.serialize()


def send_client_finished(sock, state):
    client_finished = create_client_finished(state)
    ct = tls1_3.message_dispatcher.create_handshake_ct(
        client_finished, state)
    sock.sendall(ct)
