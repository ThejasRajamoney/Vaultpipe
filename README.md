# 🔒 VaultPipe

Secure, peer-to-peer file transfer tool designed for direct, encrypted communication between machines.

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

## Why VaultPipe?

- **Direct & Private**: Files move directly between peers without intermediate servers, cloud storage, or third-party tracking.
- **Zero-Knowledge Architecture**: Everything is encrypted end-to-end; your data remains your data, invisible to anyone but the intended recipient.
- **High Performance**: Built with chunked AES-256-GCM encryption and optional compression for fast, secure, and resource-efficient transfers.

## How it works

The connection is established directly between the sender and receiver. No servers. No cloud. Just you and them.

```text
[Sender]──AES-256-GCM──▶ [Direct TCP] ──▶ [Receiver]
```

## Installation

Get up and running in seconds by installing the required dependencies:

```bash
pip install cryptography rich click
```

## Usage

VaultPipe provides a clean CLI interface for managing your secure transfers.

### 1. Send a File
Start a listening server to send a file. You can optionally add a password for extra security.
```bash
python vaultpipe.py send backup.zip --password "super-secret-pass" --compress
```

### 2. Receive a File
Connect to a sender to retrieve a file. Use the `--resume` flag to continue an interrupted transfer.
```bash
python vaultpipe.py receive ./downloads --host 192.168.1.15 --password "super-secret-pass" --resume
```

### 3. Generate Keys
Generate a persistent RSA-2048 keypair for verifying identity across multiple transfers.
```bash
python vaultpipe.py keygen --out ./keys --bits 2048
```

### 4. Check Fingerprint
Verify the authenticity of a public key by checking its cryptographic fingerprint.
```bash
python vaultpipe.py fingerprint ./keys/vaultpipe_public.pem
```

## Security

VaultPipe is built on industry-standard cryptographic primitives to ensure your data is safe:

- **RSA-2048**: Used for secure ephemeral or persistent key exchange to establish the encrypted tunnel.
- **AES-256-GCM**: Provides high-performance authenticated encryption for all file data, ensuring both secrecy and tamper-proof integrity.
- **PBKDF2**: When a password is used, it is hardened with 100,000 iterations to protect against brute-force attacks.

## Features

- ✔ RSA-2048 Asymmetric Key Exchange
- ✔ AES-256-GCM Session Encryption
- ✔ SHA-256 Integrity Verification
- ✔ Optional Password Authentication (PBKDF2)
- ✔ Automatic Resume for Interrupted Transfers
- ✔ Built-in Chunked Compression (zlib)
- ✔ Beautiful Terminal UI with Progress Bars

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request on GitHub.

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'Add amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License.
