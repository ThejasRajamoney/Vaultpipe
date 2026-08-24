# VaultPipe Protocol v2

VaultPipe v2 is a single-file transfer protocol over a direct TCP connection. This document
describes the security boundaries and wire-level state transitions. Version 2 intentionally
does not interoperate with the original unversioned protocol.

## Framing

Every handshake and encrypted record is framed as a four-byte unsigned big-endian length
followed by that number of bytes. The receiver validates a message-specific maximum before
allocating or reading the body. Zero-length packets are invalid.

## Authentication Modes

Each peer includes its role, protocol version, authentication mode, a random 32-byte nonce,
and RSA public key in the handshake transcript. Both peers must select the same mode.

### Shared Password

The sender contributes a random 16-byte salt. Both peers derive a 256-bit key with
PBKDF2-HMAC-SHA256 using 600,000 iterations and prove knowledge of it with role-separated
HMACs over the complete transcript. The sender also authenticates the encrypted session-key
packet, preventing session-key substitution.

This mode prevents an active attacker who does not know the password from changing the
handshake. Captured proofs still permit offline password guesses, so users must choose a
high-entropy password and exchange it through a separate secure channel.

### Pinned Keys

Each peer loads a persistent RSA private key and an out-of-band copy of the expected peer
public key. Received keys are compared by SHA-256 fingerprint. Both peers prove private-key
ownership with RSA-PSS signatures over the transcript, and the sender signs the encrypted
session-key packet.

### Insecure

No peer authentication is performed. This mode is vulnerable to man-in-the-middle attacks
and must be selected explicitly with `--insecure` on both peers.

## Session

The sender creates independent AES-256-GCM keys and random 64-bit nonce prefixes for each
direction. The 84-byte session payload is encrypted to the receiver with RSA-OAEP-SHA256.
Each record nonce is its direction-specific prefix followed by a 32-bit record counter.
Direction and sequence are included as AES-GCM associated data.

The connection must close before a direction reaches 2^32 records. At the default 64 KiB
chunk size this limit is far beyond the practical single-file limit.

## Transfer State Machine

1. Sender and receiver complete the authenticated handshake.
2. Sender establishes the directional encrypted session.
3. Sender sends authenticated metadata containing a safe basename, size, SHA-256 hash,
   compression flag, timestamp, and protocol version.
4. Receiver reports a partial-file offset and SHA-256 hash of that prefix.
5. Sender accepts the offset only when the source prefix matches, otherwise it requests a
   restart from byte zero.
6. Sender transmits typed `DATA` records followed by one typed `END` record.
7. Receiver enforces chunk and total-size limits, verifies the completed SHA-256 hash, and
   atomically installs the file.
8. Receiver sends an encrypted `ACK`. The sender reports success only after validating it.

Compression operates independently on each plaintext chunk. The receiver bounds every
decompression operation to one plaintext chunk and the remaining declared file size.

## Filesystem Rules

Received names must be a single portable path component. Absolute paths, separators, drive
prefixes, NULs, Windows reserved names, and trailing spaces or periods are rejected.

Incomplete data is stored under an application-generated `.vaultpipe-<digest>.part` name in
the selected output directory. A network interruption preserves fully authenticated chunks.
Protocol or integrity failures roll back data written during that connection. Final files are
installed only after size and hash verification, and existing destinations require the
explicit `--overwrite` option. The output directory must not be writable by untrusted local
users; local filesystem race resistance is limited by the host operating system, especially
Windows reparse-point semantics.

## Security Scope

The protocol protects file confidentiality and integrity in authenticated modes. It does not
hide peer IP addresses, transfer timing, or total byte count. It provides no relay, discovery,
NAT traversal, anonymity, multi-peer service, or forward-secrecy guarantee for persistent RSA
identities. The protocol has not received an independent security audit.
