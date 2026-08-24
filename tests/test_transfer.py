import hashlib
import io
import os
import socket
import threading

import pytest

from vaultpipe.vaultpipe import (
    AUTH_PASSWORD,
    AUTH_PINNED,
    CHUNK_SIZE,
    AuthConfig,
    CryptoManager,
    Receiver,
    RecordType,
    Sender,
    SocketWrapper,
    TransferInterrupted,
    partial_path_for,
)

PASSWORD = "correct horse battery staple"


def run_transfer(
    tmp_path,
    data,
    *,
    sender_auth=None,
    receiver_auth=None,
    compress=False,
    resume=False,
    sender_hook=None,
    expect_success=True,
):
    sender_auth = sender_auth or AuthConfig(AUTH_PASSWORD, password=PASSWORD)
    receiver_auth = receiver_auth or AuthConfig(AUTH_PASSWORD, password=PASSWORD)
    left, right = socket.socketpair()
    left.settimeout(10)
    right.settimeout(10)
    source = io.BytesIO(data)
    sender = Sender("unused", 1, "127.0.0.1", sender_auth, 10, compress)
    receiver = Receiver(str(tmp_path), "127.0.0.1", 1, receiver_auth, 10, resume, False)
    errors = {}
    results = {}

    if sender_hook:
        sender_hook(sender, left)

    def send_file():
        try:
            sender.handle_transfer(
                SocketWrapper(left),
                source,
                "payload.bin",
                len(data),
                hashlib.sha256(data).hexdigest(),
            )
        except Exception as error:
            errors["sender"] = error
        finally:
            left.close()

    def receive_file():
        try:
            results["path"] = receiver.handle_transfer(SocketWrapper(right))
        except Exception as error:
            errors["receiver"] = error
        finally:
            right.close()

    threads = [threading.Thread(target=send_file), threading.Thread(target=receive_file)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    assert not any(thread.is_alive() for thread in threads), "transfer deadlocked"

    if expect_success and errors:
        raise AssertionError(f"transfer failed: {errors}")
    if not expect_success:
        assert errors
    return results.get("path"), errors


@pytest.mark.parametrize("compress", [False, True])
def test_encrypted_round_trip_handles_multiple_chunks(tmp_path, compress):
    data = b"EOF" + (b"repetitive-data-" * 9000) + os.urandom(137)
    output, errors = run_transfer(tmp_path, data, compress=compress)

    assert not errors
    assert output.read_bytes() == data


def test_password_mismatch_fails_without_creating_a_file(tmp_path):
    _, errors = run_transfer(
        tmp_path,
        b"sensitive",
        receiver_auth=AuthConfig(AUTH_PASSWORD, password="different password"),
        expect_success=False,
    )

    assert errors
    assert not (tmp_path / "payload.bin").exists()
    assert not list(tmp_path.glob(".vaultpipe-*.part"))


def test_pinned_keys_authenticate_both_peers(tmp_path):
    sender_private, sender_public = CryptoManager.generate_rsa_keypair()
    receiver_private, receiver_public = CryptoManager.generate_rsa_keypair()
    sender_auth = AuthConfig(
        AUTH_PINNED,
        private_key=sender_private,
        peer_public_key=receiver_public,
    )
    receiver_auth = AuthConfig(
        AUTH_PINNED,
        private_key=receiver_private,
        peer_public_key=sender_public,
    )

    output, errors = run_transfer(
        tmp_path,
        b"authenticated with pinned identities",
        sender_auth=sender_auth,
        receiver_auth=receiver_auth,
    )

    assert not errors
    assert output.read_bytes() == b"authenticated with pinned identities"


def test_wrong_pinned_peer_key_fails_closed(tmp_path):
    sender_private, _ = CryptoManager.generate_rsa_keypair()
    receiver_private, receiver_public = CryptoManager.generate_rsa_keypair()
    _, unrelated_public = CryptoManager.generate_rsa_keypair()
    sender_auth = AuthConfig(
        AUTH_PINNED,
        private_key=sender_private,
        peer_public_key=receiver_public,
    )
    receiver_auth = AuthConfig(
        AUTH_PINNED,
        private_key=receiver_private,
        peer_public_key=unrelated_public,
    )

    _, errors = run_transfer(
        tmp_path,
        b"must not arrive",
        sender_auth=sender_auth,
        receiver_auth=receiver_auth,
        expect_success=False,
    )

    assert errors
    assert not (tmp_path / "payload.bin").exists()


def test_matching_partial_file_resumes(tmp_path):
    data = os.urandom(CHUNK_SIZE * 2 + 101)
    expected_hash = hashlib.sha256(data).hexdigest()
    partial = partial_path_for(tmp_path.resolve(), "payload.bin", expected_hash)
    partial.write_bytes(data[:CHUNK_SIZE])

    output, errors = run_transfer(tmp_path, data, resume=True)

    assert not errors
    assert output.read_bytes() == data
    assert not partial.exists()


def test_corrupt_partial_file_restarts_instead_of_appending(tmp_path):
    data = os.urandom(CHUNK_SIZE + 101)
    expected_hash = hashlib.sha256(data).hexdigest()
    partial = partial_path_for(tmp_path.resolve(), "payload.bin", expected_hash)
    partial.write_bytes(b"X" * CHUNK_SIZE)

    output, errors = run_transfer(tmp_path, data, resume=True)

    assert not errors
    assert output.read_bytes() == data


def test_interruption_preserves_partial_file_for_resume(tmp_path):
    data = os.urandom(CHUNK_SIZE * 2 + 101)

    def disconnect_after_first_chunk(sender, sock):
        original = sender.send_record
        sent_chunks = 0

        def send_record(wrapper, record_type, payload, max_payload):
            nonlocal sent_chunks
            if record_type == RecordType.DATA:
                sent_chunks += 1
                if sent_chunks == 2:
                    sock.close()
                    raise TransferInterrupted("simulated interruption")
            return original(wrapper, record_type, payload, max_payload)

        sender.send_record = send_record

    _, errors = run_transfer(
        tmp_path,
        data,
        sender_hook=disconnect_after_first_chunk,
        expect_success=False,
    )
    partials = list(tmp_path.glob(".vaultpipe-*.part"))

    assert errors
    assert len(partials) == 1
    assert partials[0].stat().st_size == CHUNK_SIZE

    output, errors = run_transfer(tmp_path, data, resume=True)
    assert not errors
    assert output.read_bytes() == data


def test_empty_file_round_trip(tmp_path):
    output, errors = run_transfer(tmp_path, b"")

    assert not errors
    assert output.read_bytes() == b""


def test_retry_acknowledges_an_already_installed_matching_file(tmp_path):
    data = b"already complete"
    first_output, first_errors = run_transfer(tmp_path, data)
    second_output, second_errors = run_transfer(tmp_path, data)

    assert not first_errors
    assert not second_errors
    assert first_output == second_output
    assert second_output.read_bytes() == data
