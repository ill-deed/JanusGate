<p align="center">
  <img src="logo.png" alt="JanusGate" width="300">
</p>

# JanusGate

**JanusGate** is a Python-based, end-to-end encrypted (E2EE) communications relay framework designed for secure, compartmentalized message exchange over untrusted networks.  
It implements channel isolation, tamper-evident transport, replay protection, and strict input sanitization — with no client-side history or persistent logs — to meet mission profiles requiring high confidentiality and minimal metadata exposure.

---

## Features

- **Channel-Based Compartmentalization**  
  Each channel is cryptographically bound to a shared passphrase-derived identifier. Clients in the same channel can communicate; those in other channels cannot access or decrypt traffic.

- **End-to-End Encryption (AES-256-GCM)**  
  All encryption and decryption occur on the client. The relay server never sees plaintext message data or keys.

- **Tamper-Evident Transport**  
  Authenticated Associated Data (AAD) binds the channel ID, sender identity, and message counter to each ciphertext, preventing undetected modification.

- **Replay Protection**  
  Per-sender monotonic counters ensure received messages are fresh, dropping replays or out-of-order packets.

- **Strict Input Sanitization**  
  All control characters and ANSI escape sequences are stripped before encryption and after decryption, preventing cursor movement or terminal injection attacks.

- **Zero History Mode**  
  No command history or local storage of past messages; once displayed, messages exist only in volatile memory.

- **Robust Relay Security**  
  Frame size limits, connection rate-limiting, and broadcast buffer caps prevent resource exhaustion and abuse.

---

## Architecture Overview

### 1. **Relay (Host)**
- Maintains persistent TCP server.
- Routes encrypted messages only to clients within the same channel.
- Enforces limits on frame size, channel count, per-client rate, and write buffer size.
- Operates in a *zero-trust* model — blind to message contents.

### 2. **Client**
- Derives a 256-bit symmetric key from the passphrase using scrypt.
- Encrypts messages with AES-256-GCM, using random nonces and AAD for integrity.
- Tracks highest message counter per remote sender to block replays.
- Sanitizes outgoing and incoming messages to prevent terminal-based exploits.

---

## Usage

### Requirements
- Python 3.8+
- `cryptography` library

### Install dependencies:
```bash
pip install cryptography
```

### Start the Relay (Host)
```bash
python3 host.py
```

Defaults to 0.0.0.0:8765. Modify HOST and PORT in the source as needed.

### Connect a Client
```bash
python3 client.py
```

Prompts:
1. **Host** – IP or hostname of the relay server.
2. **Port** – TCP port (default: 8765).
3. **Nickname** – Your display name in the channel.
4. **Passphrase** – Shared secret for your channel (hidden input).

All clients using the same passphrase join the same secure channel.

---

## Security Model
- **Confidentiality:** Relay never sees plaintext; all content is encrypted on the client.
- **Integrity:** Messages are bound to channel, sender, and counter; tampering breaks authentication.
- **Compartmentalization:** Separate passphrases create fully isolated channels.
- **Replay Defense:** Duplicate or out-of-order messages are discarded.
- **Metadata Exposure:** Relay sees only channel IDs (derived from passphrase), nicknames, and message sizes — not plaintext.

---

## Threat Considerations
JanusGate defends against:
- Passive interception of relay traffic.
- Malicious relay operator tampering with ciphertext.
- Injection of control sequences or terminal exploits.
- Replay of old messages.

It does not defend against:
- Compromised client devices.
- Passphrase disclosure by channel participants.

---

## Disclaimer
For authorized research and operational use only.

---

## License
MIT License
