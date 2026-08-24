# VaultPipe

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](#installation)
[![CI](https://github.com/ThejasRajamoney/Vaultpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/ThejasRajamoney/Vaultpipe/actions/workflows/ci.yml)

VaultPipe is a command-line tool for authenticated, encrypted file transfer over a direct TCP
connection. It streams one file at a time without uploading it to a relay or cloud service.

## Why VaultPipe?

- **Direct transfer:** Files move directly between sender and receiver without intermediate
  storage, a relay service, or a cloud upload.
- **Authenticated encryption:** Password proofs or mutually pinned identity keys authenticate
  the session before file data is transferred.
- **Streaming design:** Files are processed in bounded 64 KiB chunks, keeping memory use stable
  for large transfers.
- **Recoverable transfers:** Interrupted downloads retain authenticated chunks and can resume
  only after the existing prefix is verified against the source.

## How It Works

The sender listens for one receiver, both peers authenticate a versioned handshake, and the
file travels through a directional AES-256-GCM session over direct TCP.

```text
[Sender] -- authenticated handshake --> [Receiver]
[Sender] ===== AES-256-GCM / TCP =====> [Receiver]
```

## Features

- **Direct peer-to-peer transfer:** No VaultPipe server, relay, account, or cloud storage.
- **AES-256-GCM encryption:** Independent directional keys provide confidentiality and
  per-record tamper detection.
- **RSA identity and key exchange:** RSA-OAEP-SHA256 protects session material, while RSA-PSS
  proves ownership of mutually pinned identity keys.
- **Password authentication:** Ephemeral sessions support PBKDF2-HMAC-SHA256 with 600,000
  iterations and transcript-bound proofs.
- **SHA-256 integrity verification:** The receiver verifies the complete file before installing
  it and acknowledges the verified digest to the sender.
- **Validated resume:** A partial transfer resumes only when its byte offset and SHA-256 prefix
  match the sender's source file.
- **Chunked compression:** Optional bounded zlib compression is applied independently to each
  64 KiB plaintext chunk before encryption.
- **Safe output handling:** Portable filename validation, bounded packet sizes, bounded
  decompression, atomic installation, and explicit overwrite behavior.
- **Identity tools:** Generate protected persistent RSA keypairs and inspect public-key
  fingerprints from the CLI.
- **Terminal UI:** Rich progress bars show transfer progress, speed, remaining time, and final
  integrity status.
- **Cross-platform support:** Runs on Windows, Linux, and macOS with Python 3.10 or newer;
  Windows and Linux are exercised in CI.
- **Multiple entry points:** Use the installed `vaultpipe` command, `python -m vaultpipe`, or the
  original `python vaultpipe/vaultpipe.py` script path.

## Installation

VaultPipe requires Python 3.10 or newer.

```bash
git clone https://github.com/ThejasRajamoney/Vaultpipe.git
cd Vaultpipe
python -m pip install -e .
vaultpipe --help
```

The original script entry point remains available as `python vaultpipe/vaultpipe.py`.

## Password Mode

Create a password file through a secure local method and give the same file to both peers.
VaultPipe removes one trailing line ending when reading it.

Start the sender:

```bash
vaultpipe send backup.zip --password-file transfer-password.txt --compress
```

Connect from the receiver:

```bash
vaultpipe receive ./downloads \
  --host 192.168.1.15 \
  --password-file transfer-password.txt \
  --resume
```

`--password` and the `VAULTPIPE_PASSWORD` environment variable are also supported, but a
command-line password may be exposed through shell history or process inspection.

## Pinned-Key Mode

Generate one identity on each peer. Private keys are encrypted by default.

```bash
vaultpipe keygen --out ./sender-identity
vaultpipe keygen --out ./receiver-identity
```

Exchange the two public keys through a trusted channel and compare their fingerprints:

```bash
vaultpipe fingerprint ./receiver-identity/vaultpipe_public.pem
```

Each peer supplies its private key and the other peer's public key. Put the private-key
passphrase in a local file when running a non-interactive transfer.

```bash
vaultpipe send backup.zip \
  --identity ./sender-identity/vaultpipe_private.pem \
  --identity-password-file ./sender-passphrase.txt \
  --peer-key ./receiver-identity/vaultpipe_public.pem

vaultpipe receive ./downloads --host 192.168.1.15 \
  --identity ./receiver-identity/vaultpipe_private.pem \
  --identity-password-file ./receiver-passphrase.txt \
  --peer-key ./sender-identity/vaultpipe_public.pem
```

Unauthenticated transfers are rejected by default. `--insecure` is available for controlled
testing, but it is vulnerable to man-in-the-middle attacks and must be selected by both peers.

## Resume And Overwrite

`--resume` uses an application-owned partial file in the output directory. The receiver sends
the partial length and prefix hash; the sender resumes only when that prefix matches the source.
An interrupted transfer keeps authenticated chunks for a later attempt.

VaultPipe refuses to replace an existing destination unless the receiver passes `--overwrite`.
The final name is installed only after size and SHA-256 verification.

If an acknowledgement is lost after installation, retrying the transfer verifies the existing
file and sends a new acknowledgement without replacing it. The output directory should not be
writable by untrusted local users.

## Security Notes

- Shared-password proofs can be tested offline by an attacker who captures a handshake. Use a
  high-entropy password exchanged over a separate secure channel.
- Pinned-key mode depends on checking public-key fingerprints out of band.
- Direct TCP does not hide peer IP addresses, timing, or transfer size.
- Persistent RSA identities do not provide a forward-secrecy guarantee.
- This project has not received an independent security audit. Do not treat it as a substitute
  for an audited transfer protocol in high-risk environments.

See [the protocol specification](docs/protocol.md) for message flow, limits, and threat scope.

## Development

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
python -m pytest
```

The test suite covers packet limits, malformed metadata, output-path confinement,
authenticated records, compression bounds, password mismatch, pinned identities, encrypted
round trips, corrupted partial files, and interrupted resume.

## Contributing

Bug reports and pull requests are welcome.

1. Fork the repository.
2. Create a focused feature branch.
3. Add or update tests for behavioral changes.
4. Run the formatting, lint, and test commands above.
5. Open a pull request describing the change and verification performed.

## License

MIT
