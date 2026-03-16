# vaultpipe

Encrypted peer-to-peer file transfer over a direct TCP socket connection with zero servers in the middle.

## Features
- **RSA-2048 Key Exchange**: Secure ephemeral or persistent key exchange.
- **AES-256-GCM Encryption**: High-performance authenticated encryption for file data.
- **Integrity Verification**: SHA-256 hashing of the original file.
- **Resume Support**: Pick up where you left off if a transfer is interrupted.
- **Compression**: Optional zlib compression to save bandwidth.
- **Password Auth Layer**: Optional secondary authentication using PBKDF2-HMAC-SHA256.
- **Modern UI**: Beautiful terminal interface using `rich`.

## Installation
```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate Persistence Keys (Optional)
```bash
python vaultpipe.py keygen --bits 2048
```

### 2. Send a File
```bash
python vaultpipe.py send /path/to/file --password "secret"
```

### 3. Receive a File
```bash
python vaultpipe.py receive /output/dir --host <SENDER_IP> --password "secret" --resume
```

### 4. Check Key Fingerprint
```bash
python vaultpipe.py fingerprint ~/.vaultpipe/vaultpipe_public.pem
```

## Security Architecture
- **No Servers**: Direct peer-to-peer connection.
- **Zero-Knowledge**: Keys are ephemeral or local; no metadata ever leaves your network.
- **Chunked Encryption**: Files are processed in 64KB chunks to maintain low memory footprint.
- **Tamper-Proof**: AES-GCM tags ensure every chunk is authentic.
