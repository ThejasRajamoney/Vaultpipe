# VaultPipe

VaultPipe is a command-line tool for authenticated, encrypted file transfer over a direct TCP
connection. It streams one file at a time without uploading it to a relay or cloud service.

## Highlights

- AES-256-GCM authenticated encryption with independent keys in each direction
- Password-authenticated ephemeral sessions or mutually pinned RSA identities
- RSA-OAEP-SHA256 session-key transport and RSA-PSS identity proofs
- Bounded 64 KiB chunks with optional bounded zlib compression
- Resume validation using the SHA-256 hash of the existing partial-file prefix
- Strict packet, metadata, filename, decompression, and total-size limits
- Atomic final-file installation and explicit overwrite behavior
- Linux and Windows CI across supported Python versions

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

## License

MIT
