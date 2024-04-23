# message_dispatcher.py

import socket

from tls1_3.tls_alert import AlertLevel, AlertDescription
import tls1_3.tls_alert
import tls1_3.tls_plaintext
import tls1_3.tls_handshake
from tls1_3.tls_constants import HandshakeCode, ProtocolVersion
from tls1_3.tls_state import tls_state
from tls1_3.messages.server_hello import server_hello
from tls1_3.messages.encrypted_extensions import encypted_extensions
from tls1_3.messages.certificate import certificate
from tls1_3.messages.certificate_verify import certificate_verify
from tls1_3.messages.finished import finished


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

    plain_message = decrypted_message[:-1]
    match content_type:
        case tls1_3.tls_plaintext.ContentType.HANDSHAKE:
            handle_handshake(plain_message, state)
        case tls1_3.tls_plaintext.ContentType.APPLICATION_DATA:
            handle_app_data(plain_message)
        case tls1_3.tls_plaintext.ContentType.ALERT:
            handle_alert(plain_message)
        case _:
            raise Exception("Message type unkown")


def handle_handshake(plain_message, state):
    handshake_message = tls1_3.tls_handshake.Handshake.fromSerializedMessage(
        plain_message)
    handle_typed_message(handshake_message, state)
    state.save_message(handshake_message.type, plain_message)


def handle_app_data(plain_message):
    print(plain_message.decode(), end='')


def handle_alert(plain_message):
    alert = tls1_3.tls_alert.Alert.fromSerializedMessage(plain_message)
    print("Got Alert, level: " + str(alert.level) + ", desciption: " +
          str(alert.description))


def create_ct(complete_message: bytes, state: tls_state, content_type):
    complete_message += int(content_type.value).to_bytes(1, 'big')

    app_data = tls1_3.tls_plaintext.ContentType.APPLICATION_DATA
    legacy_record_version = ProtocolVersion.TLS_1_2
    aad = int(app_data.value).to_bytes(1, 'big')
    aad += int(legacy_record_version.value).to_bytes(2, 'big')
    record_len_with_tag = len(complete_message) + 16
    aad += record_len_with_tag.to_bytes(2, 'big')

    encrypted = state.encrypt_record(aad, complete_message)
    return aad + encrypted


def create_handshake_ct(complete_message: bytes, state: tls_state):
    handshake = tls1_3.tls_plaintext.ContentType.HANDSHAKE
    return create_ct(complete_message, state, handshake)


def send_application_ct(socket, complete_message: bytes, state: tls_state):
    application = tls1_3.tls_plaintext.ContentType.APPLICATION_DATA
    socket.sendall(create_ct(complete_message, state, application))


def close_connection(socket, state):
    alert = tls1_3.tls_alert.Alert(
        AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY)
    socket.sendall(create_ct(alert.serialize(), state,
                   tls1_3.tls_plaintext.ContentType.ALERT))


def handle_typed_message(message: tls1_3.tls_handshake.Handshake, state: tls_state):
    match message.type:
        case HandshakeCode.SERVER_HELLO:
            typed_server_hello = server_hello(message.msg)
            typed_server_hello.update_state(state)
        case HandshakeCode.ENCRYPTED_EXTENSIONS:
            typed_encrypted_extensions = encypted_extensions(message.msg)
            typed_encrypted_extensions.update_state(state)
        case HandshakeCode.CERTIFICATE:
            typed_encrypted_extensions = certificate(message.msg)
            typed_encrypted_extensions.update_state(state)
        case HandshakeCode.CERTIFICATE_VERIFY:
            typed_encrypted_extensions = certificate_verify(message.msg)
            typed_encrypted_extensions.update_state(state)
        case HandshakeCode.FINISHED:
            typed_encrypted_extensions = finished(message.msg)
            typed_encrypted_extensions.update_state(state)
        case _:
            raise NotImplementedError("Not implemented")
