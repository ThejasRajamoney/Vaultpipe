#!/usr/bin/env python3
"""Encrypted peer-to-peer file transfer over a versioned TCP protocol."""

from __future__ import annotations

import datetime
import enum
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import socket
import stat
import struct
import sys
import time
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import BinaryIO

try:
    import click
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        DownloadColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )
    from rich.text import Text
except ImportError:
    print("Missing dependencies. Run 'pip install -r requirements.txt'.")
    sys.exit(1)


VERSION = "2.0.0"
PROTOCOL_MAGIC = "vaultpipe"
PROTOCOL_VERSION = 2
DEFAULT_PORT = 57323
DEFAULT_TIMEOUT = 120
CHUNK_SIZE = 64 * 1024
RSA_KEY_SIZE = 2048
NONCE_PREFIX_SIZE = 8
TAG_SIZE = 16
PBKDF2_ITERATIONS = 600_000

AUTH_PASSWORD = "password"
AUTH_PINNED = "pinned-key"
AUTH_INSECURE = "insecure"

MAX_HELLO_SIZE = 2 * 1024
MAX_PUBLIC_KEY_SIZE = 8 * 1024
MAX_AUTH_PROOF_SIZE = 1024
MAX_SESSION_PACKET_SIZE = 1024
MAX_METADATA_SIZE = 8 * 1024
MAX_CONTROL_SIZE = 2 * 1024
MAX_DATA_PAYLOAD = CHUNK_SIZE + 1024
MAX_RECORDS = 1 << 32
MAX_FILE_SIZE = (MAX_RECORDS - 3) * CHUNK_SIZE

SESSION_MAGIC = b"VP2S"
HANDSHAKE_CONTEXT = b"vaultpipe-v2-handshake\x00"
SESSION_CONTEXT = b"vaultpipe-v2-session\x00"
RECORD_CONTEXT = b"vaultpipe-v2-record\x00"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}

console = Console()


class VaultError(Exception):
    """Base exception for expected VaultPipe failures."""


class ProtocolError(VaultError):
    """The peer sent a malformed or unsupported protocol message."""


class AuthenticationError(VaultError):
    """Peer authentication failed."""


class IntegrityError(VaultError):
    """Authenticated data or final file integrity validation failed."""


class TransferInterrupted(VaultError):
    """The network transfer ended before the protocol completed."""


class RecordType(enum.IntEnum):
    METADATA = 1
    RESUME_REQUEST = 2
    RESUME_RESPONSE = 3
    DATA = 4
    END = 5
    ACK = 6


@dataclass(frozen=True)
class AuthConfig:
    mode: str
    password: str | None = None
    private_key: rsa.RSAPrivateKey | None = None
    peer_public_key: rsa.RSAPublicKey | None = None

    def validate(self) -> None:
        if self.mode == AUTH_PASSWORD:
            if not self.password:
                raise AuthenticationError("Password authentication requires a non-empty password")
            if self.private_key or self.peer_public_key:
                raise AuthenticationError("Password and pinned-key modes cannot be combined")
            return

        if self.mode == AUTH_PINNED:
            if not self.private_key or not self.peer_public_key:
                raise AuthenticationError(
                    "Pinned-key mode requires both an identity private key and a peer public key"
                )
            if self.password:
                raise AuthenticationError("Password and pinned-key modes cannot be combined")
            return

        if self.mode == AUTH_INSECURE:
            if self.password or self.private_key or self.peer_public_key:
                raise AuthenticationError("Insecure mode cannot be combined with authentication")
            return

        raise AuthenticationError(f"Unsupported authentication mode: {self.mode}")


@dataclass(frozen=True)
class HandshakeContext:
    local_private_key: rsa.RSAPrivateKey
    peer_public_key: rsa.RSAPublicKey
    transcript: bytes
    auth_key: bytes | None


class CryptoManager:
    """RSA, AES-GCM, signatures, fingerprints, and password derivation."""

    @staticmethod
    def generate_rsa_keypair(
        bits: int = RSA_KEY_SIZE,
    ) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return private_key, private_key.public_key()

    @staticmethod
    def validate_private_key(private_key: object) -> rsa.RSAPrivateKey:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise AuthenticationError("Identity file must contain an RSA private key")
        if not 2048 <= private_key.key_size <= 4096:
            raise AuthenticationError("RSA identity keys must be between 2048 and 4096 bits")
        return private_key

    @staticmethod
    def validate_public_key(public_key: object) -> rsa.RSAPublicKey:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise AuthenticationError("Peer key must be an RSA public key")
        if not 2048 <= public_key.key_size <= 4096:
            raise AuthenticationError("RSA peer keys must be between 2048 and 4096 bits")
        return public_key

    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def deserialize_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        try:
            public_key = serialization.load_pem_public_key(pem_data)
        except (TypeError, ValueError) as error:
            raise AuthenticationError("Peer sent an invalid public key") from error
        return CryptoManager.validate_public_key(public_key)

    @staticmethod
    def load_private_key(path: pathlib.Path, password: bytes | None) -> rsa.RSAPrivateKey:
        try:
            private_key = serialization.load_pem_private_key(path.read_bytes(), password=password)
        except (OSError, TypeError, ValueError) as error:
            raise AuthenticationError(f"Could not load identity key '{path}': {error}") from error
        return CryptoManager.validate_private_key(private_key)

    @staticmethod
    def load_public_key(path: pathlib.Path) -> rsa.RSAPublicKey:
        try:
            return CryptoManager.deserialize_public_key(path.read_bytes())
        except OSError as error:
            raise AuthenticationError(f"Could not load peer key '{path}': {error}") from error

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
            dklen=32,
        )

    @staticmethod
    def compute_hmac(key: bytes, message: bytes) -> bytes:
        return hmac.new(key, message, hashlib.sha256).digest()

    @staticmethod
    def get_fingerprint(public_key: rsa.RSAPublicKey) -> str:
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    @staticmethod
    def sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
        return private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    @staticmethod
    def verify_signature(
        public_key: rsa.RSAPublicKey,
        signature: bytes,
        message: bytes,
    ) -> None:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        except InvalidSignature as error:
            raise AuthenticationError("Peer signature verification failed") from error


class SocketWrapper:
    """Length-prefixed socket framing with strict allocation limits."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send_packet(self, data: bytes, max_size: int) -> None:
        if not data:
            raise ProtocolError("Empty packets are not permitted")
        if len(data) > max_size:
            raise ProtocolError(f"Outgoing packet exceeds the {max_size}-byte limit")
        try:
            self.sock.sendall(struct.pack(">I", len(data)) + data)
        except (TimeoutError, OSError) as error:
            raise TransferInterrupted(f"Could not send data: {error}") from error

    def receive_packet(self, max_size: int) -> bytes:
        header = self.recv_exact(4)
        length = struct.unpack(">I", header)[0]
        if length == 0:
            raise ProtocolError("Empty packets are not permitted")
        if length > max_size:
            raise ProtocolError(
                f"Peer packet declares {length} bytes; the limit is {max_size} bytes"
            )
        return self.recv_exact(length)

    def recv_exact(self, size: int) -> bytes:
        data = bytearray()
        try:
            while len(data) < size:
                packet = self.sock.recv(size - len(data))
                if not packet:
                    raise TransferInterrupted("Peer closed the connection unexpectedly")
                data.extend(packet)
        except TransferInterrupted:
            raise
        except (TimeoutError, OSError) as error:
            raise TransferInterrupted(f"Could not receive data: {error}") from error
        return bytes(data)


def encode_json(value: object, max_size: int, label: str) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProtocolError(f"Could not encode {label}") from error
    if len(encoded) > max_size:
        raise ProtocolError(f"{label.capitalize()} exceeds the {max_size}-byte limit")
    return encoded


def decode_json(data: bytes, max_size: int, label: str) -> object:
    if len(data) > max_size:
        raise ProtocolError(f"{label.capitalize()} exceeds the {max_size}-byte limit")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError(f"Peer sent invalid {label} JSON") from error


def transcript_part(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def build_transcript(
    sender_hello: bytes,
    sender_public_key: bytes,
    receiver_hello: bytes,
    receiver_public_key: bytes,
) -> bytes:
    return HANDSHAKE_CONTEXT + b"".join(
        transcript_part(part)
        for part in (
            sender_hello,
            sender_public_key,
            receiver_hello,
            receiver_public_key,
        )
    )


def validate_hello(value: object, expected_role: str, expected_auth: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProtocolError("Handshake hello must be a JSON object")
    required = {"magic", "version", "role", "auth", "nonce"}
    if not required.issubset(value):
        raise ProtocolError("Handshake hello is missing required fields")
    if value["magic"] != PROTOCOL_MAGIC or value["version"] != PROTOCOL_VERSION:
        raise ProtocolError("Peer uses an unsupported VaultPipe protocol version")
    if value["role"] != expected_role:
        raise ProtocolError(f"Expected a {expected_role} handshake hello")
    if value["auth"] != expected_auth:
        raise AuthenticationError(
            f"Authentication mode mismatch: local={expected_auth}, peer={value['auth']}"
        )
    nonce = value["nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ProtocolError("Handshake nonce is invalid")
    return value


def validate_filename(filename: object) -> str:
    if not isinstance(filename, str) or not filename:
        raise ProtocolError("Metadata filename must be a non-empty string")
    if len(filename.encode("utf-8")) > 240:
        raise ProtocolError("Metadata filename is too long")
    if filename in {".", ".."} or any(
        character in filename for character in ("/", "\\", "\x00", ":")
    ):
        raise ProtocolError("Metadata filename must contain one safe path component")
    if filename.endswith((" ", ".")):
        raise ProtocolError("Metadata filename is not portable across supported platforms")
    stem = filename.split(".", 1)[0].rstrip(" .").upper()
    if stem in WINDOWS_RESERVED_NAMES:
        raise ProtocolError("Metadata filename is reserved on Windows")
    if (
        pathlib.PureWindowsPath(filename).is_absolute()
        or pathlib.PurePosixPath(filename).is_absolute()
    ):
        raise ProtocolError("Absolute metadata filenames are not permitted")
    return filename


def validate_metadata(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProtocolError("Metadata must be a JSON object")
    required = {"filename", "size", "hash", "compress", "timestamp", "version"}
    if not required.issubset(value):
        raise ProtocolError("Metadata is missing required fields")

    filename = validate_filename(value["filename"])
    size = value["size"]
    if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
        raise ProtocolError("Metadata file size is invalid")
    expected_hash = value["hash"]
    if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
        raise ProtocolError("Metadata SHA-256 hash is invalid")
    if type(value["compress"]) is not bool:
        raise ProtocolError("Metadata compression flag is invalid")
    if value["version"] != PROTOCOL_VERSION:
        raise ProtocolError("Encrypted metadata uses an unsupported protocol version")
    timestamp = value["timestamp"]
    if not isinstance(timestamp, str) or len(timestamp) > 64:
        raise ProtocolError("Metadata timestamp is invalid")
    try:
        parsed_timestamp = datetime.datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ProtocolError("Metadata timestamp is invalid") from error
    if parsed_timestamp.tzinfo is None:
        raise ProtocolError("Metadata timestamp must include a timezone")

    return {
        "filename": filename,
        "size": size,
        "hash": expected_hash,
        "compress": value["compress"],
        "timestamp": timestamp,
        "version": PROTOCOL_VERSION,
    }


def validate_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ProtocolError(f"{label} must be a lowercase SHA-256 digest")
    return value


def validate_end_record(payload: bytes, expected_size: int, expected_hash: str) -> None:
    value = decode_json(payload, MAX_CONTROL_SIZE, "end record")
    if not isinstance(value, dict):
        raise ProtocolError("End record must be a JSON object")
    if value.get("size") != expected_size or value.get("hash") != expected_hash:
        raise IntegrityError("End record does not match metadata")


def hash_stream(stream: BinaryIO, length: int | None = None) -> str:
    original_position = stream.tell()
    digest = hashlib.sha256()
    stream.seek(0)
    remaining = length
    try:
        while remaining is None or remaining > 0:
            read_size = CHUNK_SIZE if remaining is None else min(CHUNK_SIZE, remaining)
            block = stream.read(read_size)
            if not block:
                if remaining:
                    raise IntegrityError("File ended while hashing the requested prefix")
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
    finally:
        stream.seek(original_position)
    return digest.hexdigest()


def get_file_hash(filepath: pathlib.Path) -> str:
    with filepath.open("rb") as stream:
        return hash_stream(stream)


def format_size(size: float) -> str:
    amount = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024.0:
            return f"{amount:.1f} {unit}"
        amount /= 1024.0
    return f"{amount:.1f} PB"


def decompress_chunk(payload: bytes, remaining: int) -> bytes:
    maximum = min(CHUNK_SIZE, remaining)
    if maximum <= 0:
        raise ProtocolError("Peer sent file data beyond the declared size")
    decompressor = zlib.decompressobj()
    try:
        data = decompressor.decompress(payload, maximum + 1)
    except zlib.error as error:
        raise IntegrityError("Peer sent an invalid compressed chunk") from error
    if (
        len(data) > maximum
        or decompressor.unconsumed_tail
        or not decompressor.eof
        or decompressor.unused_data
    ):
        raise IntegrityError("Compressed chunk exceeds its allowed output size")
    return data


def partial_path_for(output_dir: pathlib.Path, filename: str, expected_hash: str) -> pathlib.Path:
    identifier = hashlib.sha256(f"{filename}\x00{expected_hash}".encode()).hexdigest()
    return output_dir / f".vaultpipe-{identifier}.part"


def open_partial_file(path: pathlib.Path, resume: bool) -> BinaryIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.parent.is_dir():
        raise VaultError("Output path is not a directory")

    if not resume and os.path.lexists(path):
        if path.is_dir():
            raise VaultError(f"Partial transfer path is a directory: {path}")
        path.unlink()

    binary_flag = getattr(os, "O_BINARY", 0)
    no_follow_flag = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDWR | binary_flag | no_follow_flag
    if os.path.lexists(path):
        if path.is_symlink():
            raise VaultError(f"Refusing to resume from a symbolic link: {path}")
    else:
        flags |= os.O_CREAT | os.O_EXCL

    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise VaultError(f"Could not open partial transfer file '{path}': {error}") from error

    file_stat = os.fstat(descriptor)
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
        os.close(descriptor)
        raise VaultError("Partial transfer target must be a regular, unlinked file")
    return os.fdopen(descriptor, "r+b")


def sync_file(stream: BinaryIO) -> None:
    stream.flush()
    os.fsync(stream.fileno())


def install_completed_file(
    partial_path: pathlib.Path, final_path: pathlib.Path, overwrite: bool
) -> None:
    if final_path.is_dir():
        raise VaultError(f"Destination is a directory: {final_path}")
    if overwrite:
        os.replace(partial_path, final_path)
        return
    try:
        os.link(partial_path, final_path)
    except FileExistsError as error:
        raise VaultError(f"Destination already exists; use --overwrite: {final_path}") from error
    except OSError as error:
        raise VaultError(f"Could not install completed file '{final_path}': {error}") from error
    partial_path.unlink()


class VaultPipeBase:
    """Authenticated handshake and directional encrypted-record handling."""

    def __init__(self, auth: AuthConfig):
        auth.validate()
        self.auth = auth
        self.send_cipher: AESGCM | None = None
        self.receive_cipher: AESGCM | None = None
        self.send_nonce_prefix = b""
        self.receive_nonce_prefix = b""
        self.send_counter = 0
        self.receive_counter = 0
        self.send_direction = b""
        self.receive_direction = b""

    def _local_keypair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        if self.auth.mode == AUTH_PINNED:
            private_key = self.auth.private_key
            if private_key is None:
                raise AuthenticationError("Pinned-key mode has no identity private key")
            return private_key, private_key.public_key()
        return CryptoManager.generate_rsa_keypair()

    def _hello(self, role: str, salt: bytes | None = None) -> bytes:
        value: dict[str, object] = {
            "magic": PROTOCOL_MAGIC,
            "version": PROTOCOL_VERSION,
            "role": role,
            "auth": self.auth.mode,
            "nonce": secrets.token_hex(32),
        }
        if salt is not None:
            value["salt"] = salt.hex()
        return encode_json(value, MAX_HELLO_SIZE, "handshake hello")

    def _verify_pinned_peer(self, peer_public_key: rsa.RSAPublicKey) -> None:
        expected_key = self.auth.peer_public_key
        if expected_key is None:
            raise AuthenticationError("Pinned-key mode has no expected peer key")
        expected = CryptoManager.get_fingerprint(expected_key)
        received = CryptoManager.get_fingerprint(peer_public_key)
        if not hmac.compare_digest(expected, received):
            raise AuthenticationError(
                f"Peer fingerprint mismatch: expected {expected}, received {received}"
            )

    def sender_handshake(self, wrapper: SocketWrapper) -> HandshakeContext:
        local_private, local_public = self._local_keypair()
        local_public_bytes = CryptoManager.serialize_public_key(local_public)
        salt = secrets.token_bytes(16) if self.auth.mode == AUTH_PASSWORD else None
        sender_hello = self._hello("sender", salt)
        wrapper.send_packet(sender_hello, MAX_HELLO_SIZE)
        wrapper.send_packet(local_public_bytes, MAX_PUBLIC_KEY_SIZE)

        receiver_hello = wrapper.receive_packet(MAX_HELLO_SIZE)
        receiver_value = validate_hello(
            decode_json(receiver_hello, MAX_HELLO_SIZE, "handshake hello"),
            "receiver",
            self.auth.mode,
        )
        if "salt" in receiver_value:
            raise ProtocolError("Receiver hello must not contain a password salt")
        peer_public_bytes = wrapper.receive_packet(MAX_PUBLIC_KEY_SIZE)
        peer_public = CryptoManager.deserialize_public_key(peer_public_bytes)
        transcript = build_transcript(
            sender_hello,
            local_public_bytes,
            receiver_hello,
            peer_public_bytes,
        )

        auth_key = None
        if self.auth.mode == AUTH_PASSWORD:
            if salt is None or self.auth.password is None:
                raise AuthenticationError("Password authentication is not configured")
            auth_key = CryptoManager.derive_key(self.auth.password, salt)
            sender_proof = CryptoManager.compute_hmac(auth_key, b"sender-proof\x00" + transcript)
            wrapper.send_packet(sender_proof, MAX_AUTH_PROOF_SIZE)
            receiver_proof = wrapper.receive_packet(MAX_AUTH_PROOF_SIZE)
            expected = CryptoManager.compute_hmac(auth_key, b"receiver-proof\x00" + transcript)
            if not hmac.compare_digest(receiver_proof, expected):
                raise AuthenticationError("Receiver password proof failed")
        elif self.auth.mode == AUTH_PINNED:
            self._verify_pinned_peer(peer_public)
            receiver_proof = wrapper.receive_packet(MAX_AUTH_PROOF_SIZE)
            CryptoManager.verify_signature(
                peer_public,
                receiver_proof,
                b"receiver-proof\x00" + transcript,
            )
            wrapper.send_packet(
                CryptoManager.sign(local_private, b"sender-proof\x00" + transcript),
                MAX_AUTH_PROOF_SIZE,
            )
        else:
            console.print(
                "[yellow]Warning: peer identity is not authenticated (--insecure).[/yellow]"
            )

        return HandshakeContext(local_private, peer_public, transcript, auth_key)

    def receiver_handshake(self, wrapper: SocketWrapper) -> HandshakeContext:
        sender_hello = wrapper.receive_packet(MAX_HELLO_SIZE)
        sender_value = validate_hello(
            decode_json(sender_hello, MAX_HELLO_SIZE, "handshake hello"),
            "sender",
            self.auth.mode,
        )
        sender_public_bytes = wrapper.receive_packet(MAX_PUBLIC_KEY_SIZE)
        peer_public = CryptoManager.deserialize_public_key(sender_public_bytes)

        local_private, local_public = self._local_keypair()
        local_public_bytes = CryptoManager.serialize_public_key(local_public)
        receiver_hello = self._hello("receiver")
        wrapper.send_packet(receiver_hello, MAX_HELLO_SIZE)
        wrapper.send_packet(local_public_bytes, MAX_PUBLIC_KEY_SIZE)
        transcript = build_transcript(
            sender_hello,
            sender_public_bytes,
            receiver_hello,
            local_public_bytes,
        )

        auth_key = None
        if self.auth.mode == AUTH_PASSWORD:
            salt_hex = sender_value.get("salt")
            if not isinstance(salt_hex, str) or not re.fullmatch(r"[0-9a-f]{32}", salt_hex):
                raise ProtocolError("Sender hello has an invalid password salt")
            if self.auth.password is None:
                raise AuthenticationError("Password authentication is not configured")
            auth_key = CryptoManager.derive_key(self.auth.password, bytes.fromhex(salt_hex))
            sender_proof = wrapper.receive_packet(MAX_AUTH_PROOF_SIZE)
            expected = CryptoManager.compute_hmac(auth_key, b"sender-proof\x00" + transcript)
            if not hmac.compare_digest(sender_proof, expected):
                raise AuthenticationError("Sender password proof failed")
            wrapper.send_packet(
                CryptoManager.compute_hmac(auth_key, b"receiver-proof\x00" + transcript),
                MAX_AUTH_PROOF_SIZE,
            )
        elif self.auth.mode == AUTH_PINNED:
            self._verify_pinned_peer(peer_public)
            wrapper.send_packet(
                CryptoManager.sign(local_private, b"receiver-proof\x00" + transcript),
                MAX_AUTH_PROOF_SIZE,
            )
            sender_proof = wrapper.receive_packet(MAX_AUTH_PROOF_SIZE)
            CryptoManager.verify_signature(
                peer_public,
                sender_proof,
                b"sender-proof\x00" + transcript,
            )
        else:
            if "salt" in sender_value:
                raise ProtocolError("Insecure handshake must not contain a password salt")
            console.print(
                "[yellow]Warning: peer identity is not authenticated (--insecure).[/yellow]"
            )

        return HandshakeContext(local_private, peer_public, transcript, auth_key)

    def establish_sender_session(
        self,
        wrapper: SocketWrapper,
        handshake: HandshakeContext,
    ) -> None:
        material = (
            SESSION_MAGIC
            + secrets.token_bytes(32)
            + secrets.token_bytes(NONCE_PREFIX_SIZE)
            + secrets.token_bytes(32)
            + secrets.token_bytes(NONCE_PREFIX_SIZE)
        )
        encrypted_session = handshake.peer_public_key.encrypt(
            material,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        proof_message = SESSION_CONTEXT + handshake.transcript + transcript_part(encrypted_session)
        if self.auth.mode == AUTH_PASSWORD:
            if handshake.auth_key is None:
                raise AuthenticationError("Password session has no authentication key")
            proof = CryptoManager.compute_hmac(handshake.auth_key, proof_message)
        elif self.auth.mode == AUTH_PINNED:
            proof = CryptoManager.sign(handshake.local_private_key, proof_message)
        else:
            proof = b"insecure"
        wrapper.send_packet(encrypted_session, MAX_SESSION_PACKET_SIZE)
        wrapper.send_packet(proof, MAX_AUTH_PROOF_SIZE)
        self.configure_session(material, sender=True)

    def establish_receiver_session(
        self,
        wrapper: SocketWrapper,
        handshake: HandshakeContext,
    ) -> None:
        encrypted_session = wrapper.receive_packet(MAX_SESSION_PACKET_SIZE)
        expected_ciphertext_size = handshake.local_private_key.key_size // 8
        if len(encrypted_session) != expected_ciphertext_size:
            raise ProtocolError("Encrypted session key has an invalid length")
        proof = wrapper.receive_packet(MAX_AUTH_PROOF_SIZE)
        proof_message = SESSION_CONTEXT + handshake.transcript + transcript_part(encrypted_session)
        if self.auth.mode == AUTH_PASSWORD:
            if handshake.auth_key is None:
                raise AuthenticationError("Password session has no authentication key")
            expected = CryptoManager.compute_hmac(handshake.auth_key, proof_message)
            if not hmac.compare_digest(proof, expected):
                raise AuthenticationError("Session-key password proof failed")
        elif self.auth.mode == AUTH_PINNED:
            CryptoManager.verify_signature(handshake.peer_public_key, proof, proof_message)
        elif proof != b"insecure":
            raise ProtocolError("Insecure session marker is invalid")

        try:
            material = handshake.local_private_key.decrypt(
                encrypted_session,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as error:
            raise AuthenticationError("Could not decrypt the session key") from error
        self.configure_session(material, sender=False)

    def configure_session(self, material: bytes, sender: bool) -> None:
        expected_length = len(SESSION_MAGIC) + 2 * (32 + NONCE_PREFIX_SIZE)
        if len(material) != expected_length or not material.startswith(SESSION_MAGIC):
            raise ProtocolError("Session key material is invalid")
        offset = len(SESSION_MAGIC)
        sender_key = material[offset : offset + 32]
        offset += 32
        sender_nonce = material[offset : offset + NONCE_PREFIX_SIZE]
        offset += NONCE_PREFIX_SIZE
        receiver_key = material[offset : offset + 32]
        offset += 32
        receiver_nonce = material[offset : offset + NONCE_PREFIX_SIZE]

        if sender:
            self.send_cipher = AESGCM(sender_key)
            self.send_nonce_prefix = sender_nonce
            self.send_direction = b"sender-to-receiver"
            self.receive_cipher = AESGCM(receiver_key)
            self.receive_nonce_prefix = receiver_nonce
            self.receive_direction = b"receiver-to-sender"
        else:
            self.send_cipher = AESGCM(receiver_key)
            self.send_nonce_prefix = receiver_nonce
            self.send_direction = b"receiver-to-sender"
            self.receive_cipher = AESGCM(sender_key)
            self.receive_nonce_prefix = sender_nonce
            self.receive_direction = b"sender-to-receiver"
        self.send_counter = 0
        self.receive_counter = 0

    @staticmethod
    def _nonce(prefix: bytes, counter: int) -> bytes:
        if len(prefix) != NONCE_PREFIX_SIZE or not 0 <= counter < MAX_RECORDS:
            raise ProtocolError("Encrypted record nonce space is exhausted")
        return prefix + struct.pack(">I", counter)

    @staticmethod
    def _record_aad(direction: bytes, counter: int) -> bytes:
        return RECORD_CONTEXT + direction + struct.pack(">I", counter)

    def send_record(
        self,
        wrapper: SocketWrapper,
        record_type: RecordType,
        payload: bytes,
        max_payload: int,
    ) -> None:
        if self.send_cipher is None:
            raise ProtocolError("Encrypted session is not established")
        if len(payload) > max_payload:
            raise ProtocolError(f"{record_type.name} payload exceeds its limit")
        nonce = self._nonce(self.send_nonce_prefix, self.send_counter)
        plaintext = bytes((record_type,)) + payload
        encrypted = self.send_cipher.encrypt(
            nonce,
            plaintext,
            self._record_aad(self.send_direction, self.send_counter),
        )
        wrapper.send_packet(encrypted, 1 + max_payload + TAG_SIZE)
        self.send_counter += 1

    def receive_record(
        self,
        wrapper: SocketWrapper,
        expected_types: Iterable[RecordType],
        max_payload: int,
    ) -> tuple[RecordType, bytes]:
        if self.receive_cipher is None:
            raise ProtocolError("Encrypted session is not established")
        encrypted = wrapper.receive_packet(1 + max_payload + TAG_SIZE)
        nonce = self._nonce(self.receive_nonce_prefix, self.receive_counter)
        try:
            plaintext = self.receive_cipher.decrypt(
                nonce,
                encrypted,
                self._record_aad(self.receive_direction, self.receive_counter),
            )
        except InvalidTag as error:
            raise IntegrityError("Encrypted record authentication failed") from error
        self.receive_counter += 1
        if not plaintext:
            raise ProtocolError("Encrypted record is empty")
        try:
            record_type = RecordType(plaintext[0])
        except ValueError as error:
            raise ProtocolError("Peer sent an unknown encrypted record type") from error
        allowed = set(expected_types)
        if record_type not in allowed:
            names = ", ".join(item.name for item in allowed)
            raise ProtocolError(f"Expected record type {names}; received {record_type.name}")
        return record_type, plaintext[1:]


class Sender(VaultPipeBase):
    def __init__(
        self,
        filepath: str,
        port: int,
        ip: str,
        auth: AuthConfig,
        timeout: int,
        compress: bool,
    ):
        super().__init__(auth)
        self.filepath = pathlib.Path(filepath)
        self.port = port
        self.ip = ip
        self.timeout = timeout
        self.compress = compress

    def run(self) -> None:
        try:
            source = self.filepath.open("rb")
        except OSError as error:
            raise VaultError(f"Could not open source file '{self.filepath}': {error}") from error

        with source:
            source_stat = os.fstat(source.fileno())
            if not stat.S_ISREG(source_stat.st_mode):
                raise VaultError("Source must be a regular file")
            file_size = source_stat.st_size
            if file_size > MAX_FILE_SIZE:
                raise VaultError("Source file is too large for the protocol")
            file_hash = hash_stream(source)

            console.print(Panel(Text("VAULTPIPE SENDER", justify="center", style="bold green")))
            console.print(f"  File       : [cyan]{self.filepath.name}[/cyan]")
            console.print(f"  Size       : [cyan]{format_size(file_size)}[/cyan]")
            console.print(f"  Listening  : [yellow]{self.ip}:{self.port}[/yellow]")

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.settimeout(self.timeout)
            try:
                server_socket.bind((self.ip, self.port))
                server_socket.listen(1)
                connection, address = server_socket.accept()
            except TimeoutError as error:
                raise TransferInterrupted("Timed out waiting for the receiver") from error
            except OSError as error:
                raise TransferInterrupted(f"Network error: {error}") from error
            finally:
                server_socket.close()

            connection.settimeout(self.timeout)
            with connection:
                console.print(f"  Receiver   : [green]{address[0]}:{address[1]}[/green]")
                self.handle_transfer(
                    SocketWrapper(connection),
                    source,
                    self.filepath.name,
                    file_size,
                    file_hash,
                )

    def handle_transfer(
        self,
        wrapper: SocketWrapper,
        source: BinaryIO,
        filename: str,
        file_size: int,
        file_hash: str,
    ) -> None:
        filename = validate_filename(filename)
        validate_hash(file_hash, "File hash")
        handshake = self.sender_handshake(wrapper)
        self.establish_sender_session(wrapper, handshake)
        console.print("  Session    : [green]authenticated encryption established[/green]")

        metadata = {
            "filename": filename,
            "size": file_size,
            "hash": file_hash,
            "compress": self.compress,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "version": PROTOCOL_VERSION,
        }
        self.send_record(
            wrapper,
            RecordType.METADATA,
            encode_json(metadata, MAX_METADATA_SIZE, "metadata"),
            MAX_METADATA_SIZE,
        )

        _, resume_payload = self.receive_record(
            wrapper,
            (RecordType.RESUME_REQUEST,),
            MAX_CONTROL_SIZE,
        )
        resume_request = decode_json(resume_payload, MAX_CONTROL_SIZE, "resume request")
        if not isinstance(resume_request, dict):
            raise ProtocolError("Resume request must be a JSON object")
        offset = resume_request.get("offset")
        prefix_hash = validate_hash(resume_request.get("prefix_hash"), "Resume prefix hash")
        if type(offset) is not int or not 0 <= offset <= file_size:
            raise ProtocolError("Resume offset is outside the source file")

        accepted_offset = 0
        if offset == 0:
            if prefix_hash != EMPTY_SHA256:
                raise ProtocolError("Zero-byte resume prefix has an invalid hash")
        elif hmac.compare_digest(hash_stream(source, offset), prefix_hash):
            accepted_offset = offset

        self.send_record(
            wrapper,
            RecordType.RESUME_RESPONSE,
            encode_json({"offset": accepted_offset}, MAX_CONTROL_SIZE, "resume response"),
            MAX_CONTROL_SIZE,
        )
        source.seek(accepted_offset)

        start_time = time.time()
        sent_bytes = accepted_offset
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Sending", total=file_size, completed=accepted_offset)
            while sent_bytes < file_size:
                read_size = min(CHUNK_SIZE, file_size - sent_bytes)
                data = source.read(read_size)
                if not data:
                    raise IntegrityError("Source file changed or ended during transfer")
                payload = zlib.compress(data, level=6) if self.compress else data
                self.send_record(wrapper, RecordType.DATA, payload, MAX_DATA_PAYLOAD)
                sent_bytes += len(data)
                progress.update(task, advance=len(data))

        end_payload = encode_json(
            {"size": file_size, "hash": file_hash},
            MAX_CONTROL_SIZE,
            "end record",
        )
        self.send_record(wrapper, RecordType.END, end_payload, MAX_CONTROL_SIZE)
        _, acknowledgement_payload = self.receive_record(
            wrapper,
            (RecordType.ACK,),
            MAX_CONTROL_SIZE,
        )
        acknowledgement = decode_json(
            acknowledgement_payload,
            MAX_CONTROL_SIZE,
            "acknowledgement",
        )
        if not isinstance(acknowledgement, dict):
            raise ProtocolError("Acknowledgement must be a JSON object")
        if (
            acknowledgement.get("status") != "ok"
            or acknowledgement.get("size") != file_size
            or acknowledgement.get("hash") != file_hash
        ):
            raise IntegrityError("Receiver did not confirm the completed file")

        duration = time.time() - start_time
        transferred = sent_bytes - accepted_offset
        speed = transferred / duration if duration > 0 else 0
        console.print("  SHA-256    : [green]receiver verified[/green]")
        console.print(
            f"  Transferred: [cyan]{format_size(transferred)}[/cyan] in "
            f"[cyan]{duration:.1f}s[/cyan] (avg [cyan]{format_size(speed)}/s[/cyan])"
        )
        console.print("  Status     : [bold green]transfer complete[/bold green]")


class Receiver(VaultPipeBase):
    def __init__(
        self,
        output_dir: str,
        host: str,
        port: int,
        auth: AuthConfig,
        timeout: int,
        resume: bool,
        overwrite: bool,
    ):
        super().__init__(auth)
        self.output_dir = pathlib.Path(output_dir)
        self.host = host
        self.port = port
        self.timeout = timeout
        self.resume = resume
        self.overwrite = overwrite

    def run(self) -> None:
        self.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.output_dir.is_dir():
            raise VaultError("Output path is not a directory")

        console.print(Panel(Text("VAULTPIPE RECEIVER", justify="center", style="bold blue")))
        console.print(f"  Host       : [yellow]{self.host}:{self.port}[/yellow]")
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_client.settimeout(self.timeout)
        try:
            socket_client.connect((self.host, self.port))
        except ConnectionRefusedError as error:
            raise TransferInterrupted("Connection refused; is the sender running?") from error
        except TimeoutError as error:
            raise TransferInterrupted("Connection timed out") from error
        except OSError as error:
            raise TransferInterrupted(f"Network error: {error}") from error

        try:
            self.handle_transfer(SocketWrapper(socket_client))
        finally:
            socket_client.close()

    def acknowledge_existing_file(
        self,
        wrapper: SocketWrapper,
        final_path: pathlib.Path,
        expected_size: int,
        expected_hash: str,
    ) -> pathlib.Path:
        if final_path.is_symlink() or not final_path.is_file():
            raise VaultError(f"Destination is not a regular file: {final_path}")
        try:
            with final_path.open("rb") as existing:
                existing_stat = os.fstat(existing.fileno())
                matches = (
                    stat.S_ISREG(existing_stat.st_mode)
                    and existing_stat.st_size == expected_size
                    and hmac.compare_digest(hash_stream(existing), expected_hash)
                )
        except OSError as error:
            raise VaultError(
                f"Could not verify existing destination '{final_path}': {error}"
            ) from error
        if not matches:
            raise VaultError(f"Destination already exists; use --overwrite: {final_path}")

        self.send_record(
            wrapper,
            RecordType.RESUME_REQUEST,
            encode_json(
                {"offset": expected_size, "prefix_hash": expected_hash},
                MAX_CONTROL_SIZE,
                "resume request",
            ),
            MAX_CONTROL_SIZE,
        )
        _, response_payload = self.receive_record(
            wrapper,
            (RecordType.RESUME_RESPONSE,),
            MAX_CONTROL_SIZE,
        )
        response = decode_json(response_payload, MAX_CONTROL_SIZE, "resume response")
        if not isinstance(response, dict) or response.get("offset") != expected_size:
            raise IntegrityError("Sender did not accept the existing completed file")
        _, end_payload = self.receive_record(
            wrapper,
            (RecordType.END,),
            MAX_CONTROL_SIZE,
        )
        validate_end_record(end_payload, expected_size, expected_hash)
        self.send_record(
            wrapper,
            RecordType.ACK,
            encode_json(
                {"status": "ok", "size": expected_size, "hash": expected_hash},
                MAX_CONTROL_SIZE,
                "acknowledgement",
            ),
            MAX_CONTROL_SIZE,
        )
        console.print("  Status     : [bold green]existing verified file acknowledged[/bold green]")
        return final_path

    def handle_transfer(self, wrapper: SocketWrapper) -> pathlib.Path:
        handshake = self.receiver_handshake(wrapper)
        self.establish_receiver_session(wrapper, handshake)
        console.print("  Session    : [green]authenticated encryption established[/green]")

        _, metadata_payload = self.receive_record(
            wrapper,
            (RecordType.METADATA,),
            MAX_METADATA_SIZE,
        )
        metadata = validate_metadata(decode_json(metadata_payload, MAX_METADATA_SIZE, "metadata"))
        filename = str(metadata["filename"])
        expected_size = int(metadata["size"])
        expected_hash = str(metadata["hash"])
        compressed = bool(metadata["compress"])

        output_dir = self.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        final_path = output_dir / filename
        partial_path = partial_path_for(output_dir, filename, expected_hash)
        if final_path.is_dir():
            raise VaultError(f"Destination is a directory: {final_path}")

        console.print(f"  File       : [cyan]{filename}[/cyan]")
        console.print(f"  Size       : [cyan]{format_size(expected_size)}[/cyan]")
        if compressed:
            console.print("  Compression: [green]enabled (bounded zlib chunks)[/green]")
        if os.path.lexists(final_path) and not self.overwrite:
            return self.acknowledge_existing_file(
                wrapper,
                final_path,
                expected_size,
                expected_hash,
            )

        requested_offset = 0
        accepted_offset = 0
        remove_empty_partial = False
        committed = False
        try:
            with open_partial_file(partial_path, self.resume) as output:
                output.seek(0, os.SEEK_END)
                requested_offset = output.tell() if self.resume else 0
                if requested_offset > expected_size:
                    output.seek(0)
                    output.truncate()
                    requested_offset = 0
                prefix_hash = hash_stream(output, requested_offset)
                self.send_record(
                    wrapper,
                    RecordType.RESUME_REQUEST,
                    encode_json(
                        {"offset": requested_offset, "prefix_hash": prefix_hash},
                        MAX_CONTROL_SIZE,
                        "resume request",
                    ),
                    MAX_CONTROL_SIZE,
                )

                _, response_payload = self.receive_record(
                    wrapper,
                    (RecordType.RESUME_RESPONSE,),
                    MAX_CONTROL_SIZE,
                )
                response = decode_json(response_payload, MAX_CONTROL_SIZE, "resume response")
                if not isinstance(response, dict) or type(response.get("offset")) is not int:
                    raise ProtocolError("Resume response is invalid")
                accepted_offset = response["offset"]
                if accepted_offset not in {0, requested_offset}:
                    raise ProtocolError("Sender returned an invalid resume offset")
                if accepted_offset == 0:
                    output.seek(0)
                    output.truncate()
                output.seek(accepted_offset)
                received_bytes = accepted_offset
                if accepted_offset:
                    console.print(
                        f"  Resuming   : [yellow]from {format_size(accepted_offset)}[/yellow]"
                    )
                elif requested_offset:
                    console.print(
                        "  Resuming   : [yellow]partial file did not match; restarting[/yellow]"
                    )

                start_time = time.time()
                try:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        DownloadColumn(),
                        TransferSpeedColumn(),
                        TimeRemainingColumn(),
                        console=console,
                    ) as progress:
                        task = progress.add_task(
                            "Receiving",
                            total=expected_size,
                            completed=accepted_offset,
                        )
                        while True:
                            record_type, payload = self.receive_record(
                                wrapper,
                                (RecordType.DATA, RecordType.END),
                                MAX_DATA_PAYLOAD,
                            )
                            if record_type == RecordType.END:
                                validate_end_record(payload, expected_size, expected_hash)
                                break

                            remaining = expected_size - received_bytes
                            if compressed:
                                data = decompress_chunk(payload, remaining)
                            else:
                                if not payload or len(payload) > min(CHUNK_SIZE, remaining):
                                    raise ProtocolError(
                                        "File chunk is empty or exceeds the declared file size"
                                    )
                                data = payload
                            output.write(data)
                            received_bytes += len(data)
                            progress.update(task, advance=len(data))

                    if received_bytes != expected_size:
                        raise IntegrityError(
                            f"Received {received_bytes} bytes; expected {expected_size}"
                        )
                    sync_file(output)
                    actual_hash = hash_stream(output)
                    if not hmac.compare_digest(actual_hash, expected_hash):
                        raise IntegrityError("Completed file SHA-256 does not match metadata")
                except TransferInterrupted:
                    sync_file(output)
                    raise
                except (VaultError, OSError, zlib.error):
                    output.seek(accepted_offset)
                    output.truncate()
                    sync_file(output)
                    remove_empty_partial = accepted_offset == 0
                    raise

            install_completed_file(partial_path, final_path, self.overwrite)
            committed = True
            self.send_record(
                wrapper,
                RecordType.ACK,
                encode_json(
                    {"status": "ok", "size": expected_size, "hash": expected_hash},
                    MAX_CONTROL_SIZE,
                    "acknowledgement",
                ),
                MAX_CONTROL_SIZE,
            )
        except TransferInterrupted as error:
            if committed:
                raise TransferInterrupted(
                    f"File was verified and installed at '{final_path}', but the acknowledgement "
                    "could not be delivered; retry to confirm it"
                ) from error
            raise TransferInterrupted(
                f"Transfer interrupted; partial data retained at '{partial_path}'"
            ) from error
        except Exception:
            if remove_empty_partial and os.path.lexists(partial_path):
                partial_path.unlink()
            raise

        duration = time.time() - start_time
        transferred = expected_size - accepted_offset
        speed = transferred / duration if duration > 0 else 0
        console.print("  SHA-256    : [green]verified[/green]")
        console.print(
            f"  Transferred: [cyan]{format_size(transferred)}[/cyan] in "
            f"[cyan]{duration:.1f}s[/cyan] (avg [cyan]{format_size(speed)}/s[/cyan])"
        )
        console.print("  Status     : [bold green]transfer complete[/bold green]")
        return final_path


def read_password_file(path: pathlib.Path, binary: bool = False) -> str | bytes:
    try:
        if binary:
            value = path.read_bytes().rstrip(b"\r\n")
        else:
            value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as error:
        raise AuthenticationError(f"Could not read password file '{path}': {error}") from error
    if not value:
        raise AuthenticationError(f"Password file is empty: {path}")
    return value


def build_auth_config(
    password: str | None,
    password_file: pathlib.Path | None,
    identity: pathlib.Path | None,
    peer_key: pathlib.Path | None,
    identity_password_file: pathlib.Path | None,
    insecure: bool,
) -> AuthConfig:
    if password and password_file:
        raise AuthenticationError("Use either --password or --password-file, not both")
    if password_file:
        loaded_password = read_password_file(password_file)
        if not isinstance(loaded_password, str):
            raise AuthenticationError("Shared password file is invalid")
        password = loaded_password

    if insecure:
        if password or identity or peer_key:
            raise AuthenticationError("--insecure cannot be combined with authentication options")
        config = AuthConfig(AUTH_INSECURE)
        config.validate()
        return config

    if identity or peer_key:
        if not identity or not peer_key:
            raise AuthenticationError("Use --identity and --peer-key together")
        if password:
            raise AuthenticationError("Choose password or pinned-key authentication, not both")
        identity_password = None
        if identity_password_file:
            loaded_identity_password = read_password_file(identity_password_file, binary=True)
            if not isinstance(loaded_identity_password, bytes):
                raise AuthenticationError("Identity password file is invalid")
            identity_password = loaded_identity_password
        config = AuthConfig(
            AUTH_PINNED,
            private_key=CryptoManager.load_private_key(identity, identity_password),
            peer_public_key=CryptoManager.load_public_key(peer_key),
        )
        config.validate()
        return config

    if identity_password_file:
        raise AuthenticationError("--identity-password-file requires --identity")
    if password:
        config = AuthConfig(AUTH_PASSWORD, password=password)
        config.validate()
        return config
    raise AuthenticationError(
        "Authentication is required: use --password-file, pinned keys, or explicit --insecure"
    )


def stage_key_file(path: pathlib.Path, data: bytes, mode: int) -> pathlib.Path:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
    except Exception:
        if os.path.lexists(temporary):
            temporary.unlink()
        raise
    return temporary


def install_keypair(
    private_path: pathlib.Path,
    private_data: bytes,
    public_path: pathlib.Path,
    public_data: bytes,
    force: bool,
) -> None:
    targets = ((private_path, private_data, 0o600), (public_path, public_data, 0o644))
    if not force:
        for target, _, _ in targets:
            if os.path.lexists(target):
                raise VaultError(f"Key file already exists; use --force to replace it: {target}")

    staged: list[tuple[pathlib.Path, pathlib.Path, int]] = []
    backups: dict[pathlib.Path, pathlib.Path] = {}
    installed: list[pathlib.Path] = []
    try:
        for target, data, mode in targets:
            staged.append((stage_key_file(target, data, mode), target, mode))

        if force:
            for target, _, _ in targets:
                if os.path.lexists(target):
                    backup = target.with_name(f".{target.name}.{secrets.token_hex(8)}.bak")
                    os.replace(target, backup)
                    backups[target] = backup
            for temporary, target, _ in staged:
                os.replace(temporary, target)
                installed.append(target)
        else:
            for temporary, target, mode in staged:
                os.link(temporary, target)
                installed.append(target)
                os.chmod(target, mode)
    except Exception:
        for target in installed:
            if os.path.lexists(target):
                target.unlink()
        for target, backup in backups.items():
            if os.path.lexists(backup):
                os.replace(backup, target)
        raise
    else:
        for backup in backups.values():
            if os.path.lexists(backup):
                backup.unlink()
    finally:
        for temporary, _, _ in staged:
            if os.path.lexists(temporary):
                temporary.unlink()


def run_command(action) -> None:
    try:
        action()
    except VaultError as error:
        raise click.ClickException(str(error)) from error


def auth_options(function):
    options = [
        click.option(
            "--insecure",
            is_flag=True,
            help="Explicitly allow an unauthenticated connection (MITM-vulnerable).",
        ),
        click.option(
            "--identity-password-file",
            type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
            help="File containing the identity private-key passphrase.",
        ),
        click.option(
            "--peer-key",
            type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
            help="Pinned public key expected from the peer.",
        ),
        click.option(
            "--identity",
            type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
            help="Persistent RSA private key used to authenticate this peer.",
        ),
        click.option(
            "--password-file",
            type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
            help="File containing the shared transfer password.",
        ),
        click.option(
            "--password",
            envvar="VAULTPIPE_PASSWORD",
            help="Shared password. Prefer --password-file or VAULTPIPE_PASSWORD.",
        ),
    ]
    for option in reversed(options):
        function = option(function)
    return function


@click.group()
@click.version_option(VERSION)
def cli() -> None:
    """Encrypted peer-to-peer file transfer."""


@cli.command()
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option("--port", default=DEFAULT_PORT, type=click.IntRange(1, 65535), show_default=True)
@click.option("--ip", default="0.0.0.0", show_default=True, help="IP address to bind.")
@click.option("--timeout", default=DEFAULT_TIMEOUT, type=click.IntRange(1), show_default=True)
@click.option("--compress", is_flag=True, help="Compress each plaintext chunk before encryption.")
@auth_options
def send(
    filepath: str,
    port: int,
    ip: str,
    timeout: int,
    compress: bool,
    password: str | None,
    password_file: pathlib.Path | None,
    identity: pathlib.Path | None,
    peer_key: pathlib.Path | None,
    identity_password_file: pathlib.Path | None,
    insecure: bool,
) -> None:
    """Listen for one receiver and send FILEPATH."""

    def action() -> None:
        auth = build_auth_config(
            password,
            password_file,
            identity,
            peer_key,
            identity_password_file,
            insecure,
        )
        Sender(filepath, port, ip, auth, timeout, compress).run()

    run_command(action)


@cli.command()
@click.argument("output_dir", type=click.Path(file_okay=False))
@click.option("--host", required=True, help="Sender host or IP address.")
@click.option("--port", default=DEFAULT_PORT, type=click.IntRange(1, 65535), show_default=True)
@click.option("--timeout", default=DEFAULT_TIMEOUT, type=click.IntRange(1), show_default=True)
@click.option("--resume", is_flag=True, help="Resume a verified matching partial transfer.")
@click.option(
    "--overwrite", is_flag=True, help="Replace an existing destination after verification."
)
@auth_options
def receive(
    output_dir: str,
    host: str,
    port: int,
    timeout: int,
    resume: bool,
    overwrite: bool,
    password: str | None,
    password_file: pathlib.Path | None,
    identity: pathlib.Path | None,
    peer_key: pathlib.Path | None,
    identity_password_file: pathlib.Path | None,
    insecure: bool,
) -> None:
    """Connect to a sender and receive a file into OUTPUT_DIR."""

    def action() -> None:
        auth = build_auth_config(
            password,
            password_file,
            identity,
            peer_key,
            identity_password_file,
            insecure,
        )
        Receiver(output_dir, host, port, auth, timeout, resume, overwrite).run()

    run_command(action)


@cli.command()
@click.option(
    "--out",
    default=str(pathlib.Path.home() / ".vaultpipe"),
    type=click.Path(file_okay=False, path_type=pathlib.Path),
    show_default=True,
)
@click.option(
    "--bits",
    default="2048",
    type=click.Choice(("2048", "3072", "4096")),
    show_default=True,
)
@click.option("--protect/--no-protect", default=True, show_default=True)
@click.option("--force", is_flag=True, help="Replace an existing keypair.")
def keygen(out: pathlib.Path, bits: str, protect: bool, force: bool) -> None:
    """Generate a persistent RSA identity keypair."""

    def action() -> None:
        out.mkdir(parents=True, exist_ok=True)
        if not out.is_dir():
            raise VaultError("Key output path is not a directory")
        private_key, public_key = CryptoManager.generate_rsa_keypair(int(bits))
        if protect:
            passphrase = click.prompt(
                "Private key passphrase",
                hide_input=True,
                confirmation_prompt=True,
            )
            if not passphrase:
                raise AuthenticationError("Private key passphrase cannot be empty")
            encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        else:
            encryption = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        public_pem = CryptoManager.serialize_public_key(public_key)
        private_path = out / "vaultpipe_private.pem"
        public_path = out / "vaultpipe_public.pem"
        install_keypair(private_path, private_pem, public_path, public_pem, force)
        console.print(f"[green]Keypair generated in {out}[/green]")
        console.print(
            f"  Public fingerprint: [cyan]{CryptoManager.get_fingerprint(public_key)}[/cyan]"
        )

    run_command(action)


@cli.command()
@click.argument(
    "public_key_path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
def fingerprint(public_key_path: pathlib.Path) -> None:
    """Print the SHA-256 fingerprint of an RSA public key."""

    def action() -> None:
        public_key = CryptoManager.load_public_key(public_key_path)
        console.print(f"Fingerprint: [cyan]{CryptoManager.get_fingerprint(public_key)}[/cyan]")

    run_command(action)


if __name__ == "__main__":
    cli()
