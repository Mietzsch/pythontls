# handshake_message_dispatcher.py

import tls1_3.tls_plaintext
import tls1_3.tls_handshake
from tls1_3.tls_constants import HandshakeCode
from tls1_3.tls_state import tls_state
import tls1_3.server_hello
import tls1_3.encrypted_extensions


def handle_from_plaintext(complete_message: bytes, state: tls_state):
    typed_message = tls1_3.tls_plaintext.TLSPlaintext.fromSerializedMessage(
        complete_message)
    if (typed_message.content_type != tls1_3.tls_plaintext.ContentType.HANDSHAKE):
        raise Exception("Not a Handshake Protocol")

    handshake_message = tls1_3.tls_handshake.Handshake.fromSerializedMessage(
        typed_message.message)

    state.save_message(handshake_message.type, typed_message.message)
    handle_typed_message(handshake_message, state)


def handle_from_ciphertext(complete_message: bytes, state: tls_state):
    decrypted_message = state.decrypt_record(complete_message)
    if decrypted_message[-1] == 0:
        raise NotImplementedError("Padding not implemented")
    else:
        content_type = tls1_3.tls_plaintext.ContentType(
            decrypted_message[-1])

    if content_type != tls1_3.tls_plaintext.ContentType.HANDSHAKE:
        raise Exception("Not a Handshake Protocol")

    handshake_message = tls1_3.tls_handshake.Handshake.fromSerializedMessage(
        decrypted_message[:-1])

    state.save_message(handshake_message.type, decrypted_message[:-1])
    handle_typed_message(handshake_message, state)


def handle_typed_message(message: tls1_3.tls_handshake.Handshake, state: tls_state):
    match message.type:
        case HandshakeCode.SERVER_HELLO:
            typed_server_hello = tls1_3.server_hello.server_hello(
                message.msg)
            typed_server_hello.update_state(state)
        case HandshakeCode.ENCRYPTED_EXTENSIONS:
            typed_encrypted_extensions = tls1_3.encrypted_extensions.encypted_extensions(
                message.msg)
            typed_encrypted_extensions.update_state(state)