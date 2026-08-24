import hashlib
import json
import os
import pathlib
import socket
import struct

import pytest
from click.testing import CliRunner

from vaultpipe.vaultpipe import (
    AUTH_INSECURE,
    CHUNK_SIZE,
    MAX_FILE_SIZE,
    MAX_HELLO_SIZE,
    MAX_RECORDS,
    AuthConfig,
    AuthenticationError,
    CryptoManager,
    IntegrityError,
    ProtocolError,
    RecordType,
    SocketWrapper,
    TransferInterrupted,
    VaultPipeBase,
    build_auth_config,
    cli,
    decompress_chunk,
    install_keypair,
    validate_filename,
    validate_metadata,
)


def metadata(**overrides):
    value = {
        "filename": "backup.bin",
        "size": 42,
        "hash": hashlib.sha256(b"data").hexdigest(),
        "compress": False,
        "timestamp": "2026-08-24T12:00:00+00:00",
        "version": 2,
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize(
    "filename",
    [
        "",
        ".",
        "..",
        "../secret",
        "..\\secret",
        "/tmp/secret",
        "C:\\secret.txt",
        "\\\\server\\share",
        "file:name",
        "file.txt.",
        "NUL.txt",
        "name\x00.txt",
    ],
)
def test_validate_filename_rejects_unsafe_paths(filename):
    with pytest.raises(ProtocolError):
        validate_filename(filename)


@pytest.mark.parametrize(
    "overrides",
    [
        {"size": -1},
        {"size": True},
        {"hash": "not-a-hash"},
        {"compress": 1},
        {"version": 1},
        {"timestamp": "not-a-date"},
        {"timestamp": "2026-08-24T12:00:00"},
    ],
)
def test_validate_metadata_rejects_malformed_fields(overrides):
    with pytest.raises(ProtocolError):
        validate_metadata(metadata(**overrides))


def test_packet_limit_is_checked_before_body_read():
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(struct.pack(">I", MAX_HELLO_SIZE + 1))
        with pytest.raises(ProtocolError, match="declares"):
            SocketWrapper(receiver).receive_packet(MAX_HELLO_SIZE)
    finally:
        sender.close()
        receiver.close()


def test_truncated_packet_is_an_interruption():
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(struct.pack(">I", 10) + b"short")
        sender.close()
        with pytest.raises(TransferInterrupted):
            SocketWrapper(receiver).receive_packet(10)
    finally:
        receiver.close()


def test_record_tampering_fails_authentication():
    class MemoryWrapper:
        def __init__(self):
            self.packet = b""

        def send_packet(self, data, max_size):
            assert len(data) <= max_size
            self.packet = data

        def receive_packet(self, max_size):
            assert len(self.packet) <= max_size
            return self.packet

    material = b"VP2S" + bytes(range(32)) + b"12345678" + bytes(range(32, 64)) + b"ABCDEFGH"
    sender = VaultPipeBase(AuthConfig(AUTH_INSECURE))
    receiver = VaultPipeBase(AuthConfig(AUTH_INSECURE))
    sender.configure_session(material, sender=True)
    receiver.configure_session(material, sender=False)
    wrapper = MemoryWrapper()
    sender.send_record(wrapper, RecordType.DATA, b"secret payload", 100)
    wrapper.packet = wrapper.packet[:-1] + bytes((wrapper.packet[-1] ^ 1,))

    with pytest.raises(IntegrityError):
        receiver.receive_record(wrapper, (RecordType.DATA,), 100)


def test_decompression_is_bounded():
    import zlib

    compressed = zlib.compress(b"A" * (CHUNK_SIZE + 1))
    with pytest.raises(IntegrityError, match="exceeds"):
        decompress_chunk(compressed, CHUNK_SIZE + 1)


def test_authentication_is_required_by_default():
    with pytest.raises(AuthenticationError, match="Authentication is required"):
        build_auth_config(None, None, None, None, None, False)


def test_metadata_json_cannot_smuggle_a_path():
    value = json.loads(json.dumps(metadata(filename="../../outside.txt")))
    with pytest.raises(ProtocolError):
        validate_metadata(value)


def test_file_size_limit_matches_record_nonce_budget():
    assert MAX_FILE_SIZE == (MAX_RECORDS - 3) * CHUNK_SIZE
    validate_metadata(metadata(size=MAX_FILE_SIZE))
    with pytest.raises(ProtocolError, match="size"):
        validate_metadata(metadata(size=MAX_FILE_SIZE + 1))


def test_keygen_help_supports_declared_click_versions():
    result = CliRunner().invoke(cli, ["keygen", "--help"])

    assert result.exit_code == 0
    assert "2048" in result.output
    assert "3072" in result.output


def test_keygen_creates_a_usable_unprotected_identity(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["keygen", "--out", str(tmp_path), "--bits", "2048", "--no-protect"],
    )

    assert result.exit_code == 0
    private_key = CryptoManager.load_private_key(tmp_path / "vaultpipe_private.pem", None)
    public_key = CryptoManager.load_public_key(tmp_path / "vaultpipe_public.pem")
    assert private_key.public_key().public_numbers() == public_key.public_numbers()


def test_forced_keypair_install_rolls_back_both_files(tmp_path, monkeypatch):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(b"old private")
    public_path.write_bytes(b"old public")
    real_replace = os.replace
    failed = False

    def fail_public_install(source, destination):
        nonlocal failed
        if (
            not failed
            and pathlib.Path(destination) == public_path
            and pathlib.Path(source).suffix == ".tmp"
        ):
            failed = True
            raise OSError("simulated public-key install failure")
        return real_replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_public_install)
    with pytest.raises(OSError, match="simulated"):
        install_keypair(private_path, b"new private", public_path, b"new public", True)

    assert private_path.read_bytes() == b"old private"
    assert public_path.read_bytes() == b"old public"
