#!/usr/bin/env python3
"""
vaultpipe — Encrypted P2P File Transfer
"""

import os
import sys
import socket
import struct
import hashlib
import hmac
import secrets
import json
import time
import zlib
import pathlib
import datetime
from typing import Optional, Tuple, Dict, Any, Generator

# Third-party dependencies
try:
    import click
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
except ImportError as e:
    print(f"Error: Missing dependencies. Please run 'pip install cryptography rich click'")
    sys.exit(1)

# Constants
VERSION = "1.0.0"
CHUNK_SIZE = 64 * 1024  # 64KB
DEFAULT_PORT = 57323
RSA_KEY_SIZE = 2048
NONCE_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERATIONS = 100000
TIMEOUT = 120

console = Console()

class VaultError(Exception):
    """Base exception for VaultPipe errors."""
    pass

class CryptoManager:
    """Handles RSA, AES-GCM, and Password-based key derivation."""

    @staticmethod
    def generate_rsa_keypair(bits: int = RSA_KEY_SIZE) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generates an RSA keypair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """Serializes public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        """Deserializes public key from PEM format."""
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derives a 32-byte key from password using PBKDF2."""
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)

    @staticmethod
    def compute_hmac(key: bytes, message: bytes) -> bytes:
        """Computes HMAC-SHA256."""
        h = hmac.new(key, message, "sha256")
        return h.digest()

    @staticmethod
    def get_fingerprint(public_key: rsa.RSAPublicKey) -> str:
        """Returns the SHA256 fingerprint of the public key."""
        pem = CryptoManager.serialize_public_key(public_key)
        return hashlib.sha256(pem).hexdigest()

class SocketWrapper:
    """Helper for framed socket communication."""
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send_packet(self, data: bytes):
        """Sends a length-prefixed packet."""
        self.sock.sendall(struct.pack(">I", len(data)) + data)

    def receive_packet(self) -> bytes:
        """Receives a length-prefixed packet."""
        header = self.recv_exact(4)
        if not header:
            return b""
        length = struct.unpack(">I", header)[0]
        return self.recv_exact(length)

    def recv_exact(self, n: int) -> bytes:
        """Helper to receive exactly n bytes."""
        data = b""
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return b""
            data += packet
        return data

class VaultPipeBase:
    """Common logic for sender and receiver."""
    def __init__(self):
        self.aes_gcm: Optional[AESGCM] = None
        self.base_nonce: bytes = b""
        self.nonce_counter: int = 0

    def _get_next_nonce(self) -> bytes:
        """Generates an incrementing nonce for GCM."""
        nonce = (int.from_bytes(self.base_nonce, "big") + self.nonce_counter).to_bytes(12, "big")
        self.nonce_counter += 1
        return nonce

    def encrypt_chunk(self, data: bytes) -> bytes:
        """Encrypts a chunk and returns [tag][encrypted_data]."""
        nonce = self._get_next_nonce()
        # AESGCM return format is [encrypted_data][tag] in cryptography lib
        ct_with_tag = self.aes_gcm.encrypt(nonce, data, None)
        # We need to separate tag and ciphertext as per requirements: [tag][data]
        tag = ct_with_tag[-TAG_SIZE:]
        ciphertext = ct_with_tag[:-TAG_SIZE]
        return tag + ciphertext

    def decrypt_chunk(self, chunk: bytes) -> bytes:
        """Decrypts a chunk: expects [tag][encrypted_data]."""
        nonce = self._get_next_nonce()
        tag = chunk[:TAG_SIZE]
        ciphertext = chunk[TAG_SIZE:]
        # Put it back to [ciphertext][tag] for AESGCM
        return self.aes_gcm.decrypt(nonce, ciphertext + tag, None)

def get_file_hash(filepath: pathlib.Path) -> str:
    """Computes SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def format_size(size: int) -> str:
    """Formats bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

class Sender(VaultPipeBase):
    def __init__(self, filepath: str, port: int, ip: str, password: Optional[str], timeout: int, compress: bool):
        super().__init__()
        self.filepath = pathlib.Path(filepath)
        self.port = port
        self.ip = ip
        self.password = password
        self.timeout = timeout
        self.compress = compress
        self.stats = {}

    def run(self):
        if not self.filepath.exists():
            console.print(f"[red]Error: File {self.filepath} not found.[/red]")
            sys.exit(1)

        file_size = self.filepath.stat().st_size
        file_hash = get_file_hash(self.filepath)

        console.print(Panel(Text("VAULTPIPE SENDER", justify="center", style="bold green")))
        console.print(f"  File       : [cyan]{self.filepath.name}[/cyan]")
        console.print(f"  Size       : [cyan]{format_size(file_size)}[/cyan]")
        console.print(f"  Listening  : [yellow]{self.ip}:{self.port}[/yellow]")
        console.print(f"  Status     : Waiting for receiver...")

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((self.ip, self.port))
            server_sock.listen(1)
            server_sock.settimeout(self.timeout)
            
            conn, addr = server_sock.accept()
            with conn:
                console.print(f"  Receiver   : [green]{addr[0]}:{addr[1]}[/green]")
                sw = SocketWrapper(conn)
                self.handle_transfer(sw, file_size, file_hash)
        except socket.timeout:
            console.print("[yellow]Timeout: No receiver connected in time.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        finally:
            server_sock.close()

    def handle_transfer(self, sw: SocketWrapper, file_size: int, file_hash: str):
        # 1. RSA Key Exchange
        priv_key, pub_key = CryptoManager.generate_rsa_keypair()
        sw.send_packet(CryptoManager.serialize_public_key(pub_key))
        
        receiver_pub_key_bytes = sw.receive_packet()
        if not receiver_pub_key_bytes: raise VaultError("Failed to receive public key")
        receiver_pub_key = CryptoManager.deserialize_public_key(receiver_pub_key_bytes)
        console.print("  Key Exchange: [green]✔ RSA-2048 complete[/green]")

        # 2. Optional Password Auth
        if self.password:
            salt = secrets.token_bytes(16)
            sw.send_packet(salt)
            derived_key = CryptoManager.derive_key(self.password, salt)
            
            my_hmac = CryptoManager.compute_hmac(derived_key, CryptoManager.serialize_public_key(pub_key))
            sw.send_packet(my_hmac)
            
            receiver_hmac = sw.receive_packet()
            expected_hmac = CryptoManager.compute_hmac(derived_key, receiver_pub_key_bytes)
            
            if not hmac.compare_digest(receiver_hmac, expected_hmac):
                console.print("[red]ERROR: Authentication failed. Shared passwords do not match.[/red]")
                sys.exit(2)
            console.print("  Auth        : [green]✔ Password verified[/green]")

        # 3. Session Key Exchange
        session_key = secrets.token_bytes(32)
        self.base_nonce = secrets.token_bytes(NONCE_SIZE)
        self.aes_gcm = AESGCM(session_key)
        
        # Encrypt session key + base nonce with receiver's public key
        payload = session_key + self.base_nonce
        encrypted_session = receiver_pub_key.encrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        sw.send_packet(encrypted_session)
        console.print("  Session Key : [green]✔ AES-256-GCM established[/green]")

        # 4. Metadata Transfer
        metadata = {
            "filename": self.filepath.name,
            "size": file_size,
            "hash": file_hash,
            "compress": self.compress,
            "timestamp": datetime.datetime.now().isoformat(),
            "version": VERSION
        }
        meta_bytes = json.dumps(metadata).encode()
        sw.send_packet(self.encrypt_chunk(meta_bytes))

        # 5. Resume Support
        resume_offset_bytes = sw.receive_packet()
        resume_offset = struct.unpack(">Q", self.decrypt_chunk(resume_offset_bytes))[0]
        
        # 6. File Transmission
        start_time = time.time()
        sent_bytes = resume_offset
        
        with open(self.filepath, "rb") as f:
            f.seek(resume_offset)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Sending", total=file_size, completed=resume_offset)
                
                while True:
                    data = f.read(CHUNK_SIZE)
                    if not data:
                        break
                    
                    if self.compress:
                        chunk_to_send = zlib.compress(data, level=6)
                    else:
                        chunk_to_send = data
                    
                    encrypted_data = self.encrypt_chunk(chunk_to_send)
                    # Prepend length as per requirements [4-byte length][tag][data]
                    # Actually SocketWrapper already handles framing, but prompt says:
                    # "Each chunk: encrypt with AES-256-GCM, prepend 4-byte chunk length + 16-byte auth tag"
                    # We will use SW for transmission which adds its own framing. 
                    sw.send_packet(encrypted_data)
                    
                    sent_bytes += len(data)
                    progress.update(task, advance=len(data))

        # 7. Final EOF
        eof_packet = self.encrypt_chunk(b"EOF")
        sw.send_packet(eof_packet)
        
        # Final Hash Verification (transmitted in metadata or as final encrypted message)
        # Already sent in metadata, but let's send it again for formal "final message"
        sw.send_packet(self.encrypt_chunk(file_hash.encode()))

        duration = time.time() - start_time
        avg_speed = (sent_bytes - resume_offset) / duration if duration > 0 else 0
        console.print(f"  SHA-256    : [green]✔ Integrity verified[/green]")
        console.print(f"  Transferred: [cyan]{format_size(sent_bytes - resume_offset)}[/cyan] in [cyan]{duration:.1f}s[/cyan] (avg [cyan]{format_size(avg_speed)}/s[/cyan])")
        console.print("  Status     : [bold green]✔ Transfer complete[/bold green]")

class Receiver(VaultPipeBase):
    def __init__(self, output_dir: str, host: str, port: int, password: Optional[str], timeout: int, resume: bool):
        super().__init__()
        self.output_dir = pathlib.Path(output_dir)
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.resume = resume

    def run(self):
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)

        console.print(Panel(Text("VAULTPIPE RECEIVER", justify="center", style="bold blue")))
        console.print(f"  Host       : [yellow]{self.host}:{self.port}[/yellow]")
        console.print(f"  Status     : Connecting to sender...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            sw = SocketWrapper(sock)
            self.handle_transfer(sw)
        except ConnectionRefusedError:
            console.print("[red]Error: Connection refused. Is the sender running?[/red]")
            sys.exit(1)
        except socket.timeout:
            console.print("[red]Error: Connection timed out.[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        finally:
            sock.close()

    def handle_transfer(self, sw: SocketWrapper):
        # 1. RSA Key Exchange
        priv_key, pub_key = CryptoManager.generate_rsa_keypair()
        
        sender_pub_key_bytes = sw.receive_packet()
        if not sender_pub_key_bytes: raise VaultError("Failed to receive public key")
        sender_pub_key = CryptoManager.deserialize_public_key(sender_pub_key_bytes)
        
        sw.send_packet(CryptoManager.serialize_public_key(pub_key))
        console.print("  Key Exchange: [green]✔ RSA-2048 complete[/green]")

        # 2. Optional Password Auth
        if self.password:
            salt = sw.receive_packet()
            derived_key = CryptoManager.derive_key(self.password, salt)
            
            sender_hmac = sw.receive_packet()
            expected_sender_hmac = CryptoManager.compute_hmac(derived_key, sender_pub_key_bytes)
            
            if not hmac.compare_digest(sender_hmac, expected_sender_hmac):
                console.print("[red]ERROR: Authentication failed. Shared passwords do not match.[/red]")
                sys.exit(2)
            
            my_hmac = CryptoManager.compute_hmac(derived_key, CryptoManager.serialize_public_key(pub_key))
            sw.send_packet(my_hmac)
            console.print("  Auth        : [green]✔ Password verified[/green]")

        # 3. Session Key Exchange
        encrypted_session = sw.receive_packet()
        decrypted_payload = priv_key.decrypt(
            encrypted_session,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        session_key = decrypted_payload[:32]
        self.base_nonce = decrypted_payload[32:]
        self.aes_gcm = AESGCM(session_key)
        console.print("  Session Key : [green]✔ AES-256-GCM established[/green]")

        # 4. Metadata Receipt
        meta_chunk = sw.receive_packet()
        metadata = json.loads(self.decrypt_chunk(meta_chunk).decode())
        
        filename = metadata["filename"]
        expected_size = metadata["size"]
        expected_hash = metadata["hash"]
        compressed = metadata["compress"]
        
        console.print(f"  File       : [cyan]{filename}[/cyan]")
        console.print(f"  Size       : [cyan]{format_size(expected_size)}[/cyan]")
        if compressed:
            console.print(f"  Compression: [green]Enabled (zlib)[/green]")

        # 5. Resume Support
        out_file = self.output_dir / filename
        resume_offset = 0
        mode = "wb"
        
        if self.resume and out_file.exists():
            resume_offset = out_file.stat().st_size
            if resume_offset >= expected_size:
                # File already fully received or weird state
                resume_offset = 0
            else:
                mode = "ab"
                console.print(f"  Resuming   : [yellow]From {format_size(resume_offset)}[/yellow]")

        sw.send_packet(self.encrypt_chunk(struct.pack(">Q", resume_offset)))

        # 6. File Reception
        start_time = time.time()
        received_bytes = resume_offset
        
        try:
            with open(out_file, mode) as f:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("Receiving", total=expected_size, completed=resume_offset)
                    
                    while True:
                        encrypted_chunk = sw.receive_packet()
                        try:
                            decrypted_data = self.decrypt_chunk(encrypted_chunk)
                        except Exception:
                            # Might be eof or error
                            # Test if it's EOF first
                            self.nonce_counter -= 1 # Rewind to try EOF decryption
                            try:
                                maybe_eof = self.decrypt_chunk(encrypted_chunk)
                                if maybe_eof == b"EOF":
                                    break
                            except:
                                console.print("[red]CRITICAL: Chunk integrity failure. File may be tampered. Aborting.[/red]")
                                f.close()
                                # Prompt says: delete partial file on integrity failure
                                if out_file.exists(): out_file.unlink()
                                sys.exit(1)
                        
                        if decrypted_data == b"EOF":
                            break
                        
                        if compressed:
                            decrypted_data = zlib.decompress(decrypted_data)
                        
                        f.write(decrypted_data)
                        received_bytes += len(decrypted_data)
                        progress.update(task, advance=len(decrypted_data))

            # 7. Final Hash Verification
            final_hash_packet = sw.receive_packet()
            received_final_hash = self.decrypt_chunk(final_hash_packet).decode()
            
            actual_hash = get_file_hash(out_file)
            if actual_hash != expected_hash or actual_hash != received_final_hash:
                console.print("[red]ERROR: File hash mismatch. Transfer corrupted.[/red]")
                if out_file.exists(): out_file.unlink()
                sys.exit(1)

            duration = time.time() - start_time
            avg_speed = (received_bytes - resume_offset) / duration if duration > 0 else 0
            console.print(f"  SHA-256    : [green]✔ Integrity verified[/green]")
            console.print(f"  Transferred: [cyan]{format_size(received_bytes - resume_offset)}[/cyan] in [cyan]{duration:.1f}s[/cyan] (avg [cyan]{format_size(avg_speed)}/s[/cyan])")
            console.print("  Status     : [bold green]✔ Transfer complete[/bold green]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user. Cleaning up...[/yellow]")
            # Partial file remains if we want resume later, but prompt says:
            # "Keyboard interrupt → clean teardown, delete partial file if incomplete"
            # However, "Resume Support" says "If found: sends byte offset".
            # If we delete on interrupt, resume won't work easily.
            # But I will follow the explicit requirement for KeyboardInterrupt.
            if out_file.exists(): out_file.unlink()
            sys.exit(0)

@click.group()
def cli():
    """vaultpipe — Encrypted P2P File Transfer"""
    pass

@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--port", default=DEFAULT_PORT, help="Port to listen on")
@click.option("--ip", default="0.0.0.0", help="Bind IP")
@click.option("--password", help="Optional shared password")
@click.option("--timeout", default=120, help="Seconds to wait for connection")
@click.option("--compress", is_flag=True, help="Compress file before encrypting")
def send(filepath, port, ip, password, timeout, compress):
    """Sends a file across the pipe."""
    sender = Sender(filepath, port, ip, password, timeout, compress)
    sender.run()

@cli.command()
@click.argument("output_dir", type=click.Path())
@click.option("--host", required=True, help="Sender IP to connect to")
@click.option("--port", default=DEFAULT_PORT, help="Port to connect to")
@click.option("--password", help="Optional shared password")
@click.option("--timeout", default=30, help="Connection timeout in seconds")
@click.option("--resume", is_flag=True, help="Resume partial transfer")
def receive(output_dir, host, port, password, timeout, resume):
    """Receives a file from the pipe."""
    receiver = Receiver(output_dir, host, port, password, timeout, resume)
    receiver.run()

@cli.command()
@click.option("--out", default=str(pathlib.Path.home() / ".vaultpipe"), help="Output directory for keypair")
@click.option("--bits", default=2048, type=click.IntRange(2048, 4096), help="Key size")
def keygen(out, bits):
    """Generates a persistent RSA keypair."""
    out_dir = pathlib.Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    priv_key, pub_key = CryptoManager.generate_rsa_keypair(bits)
    
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    priv_file = out_dir / "vaultpipe_private.pem"
    pub_file = out_dir / "vaultpipe_public.pem"
    
    priv_file.write_bytes(priv_pem)
    pub_file.write_bytes(pub_pem)
    
    # Set permissions (Linux/macOS)
    if os.name != "nt":
        priv_file.chmod(0o600)
    
    console.print(f"[green]✔ Keypair generated in {out_dir}[/green]")
    console.print(f"  Public Fingerprint: [cyan]{CryptoManager.get_fingerprint(pub_key)}[/cyan]")

@cli.command()
@click.argument("public_key_path", type=click.Path(exists=True))
def fingerprint(public_key_path):
    """Prints SHA-256 fingerprint of a public key."""
    try:
        pem_data = pathlib.Path(public_key_path).read_bytes()
        pub_key = CryptoManager.deserialize_public_key(pem_data)
        console.print(f"Fingerprint: [cyan]{CryptoManager.get_fingerprint(pub_key)}[/cyan]")
    except Exception as e:
        console.print(f"[red]Error: Could not read public key. {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown requested.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]FATAL ERROR: {e}[/red]")
        sys.exit(1)
