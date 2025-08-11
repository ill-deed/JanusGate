#!/usr/bin/env python3
import asyncio
import base64
import getpass
import json
import os
import re
import time
from dataclasses import dataclass
from hashlib import blake2b
from typing import Optional, Dict

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 8765

# ---------- Control/ANSI sanitization ----------
ANSI_CSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
ANSI_OSC = re.compile(r'\x1b\][^\x07\x1b]*?(?:\x07|\x1b\\)')

def sanitize_text(s: str) -> str:
    s = ANSI_CSI.sub('', s)
    s = ANSI_OSC.sub('', s)
    return ''.join(ch for ch in s if ch == '\n' or ch == '\t' or 32 <= ord(ch) <= 126)

# ---------- Crypto helpers ----------
def channel_id_from_passphrase(passphrase: str) -> str:
    return blake2b(passphrase.encode("utf-8"), digest_size=32).hexdigest()

def derive_key_from_passphrase(passphrase: str) -> bytes:
    # Deterministic salt from passphrase; host never learns passphrase
    salt = blake2b(b"salt:" + passphrase.encode("utf-8"), digest_size=16).digest()
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_message(key: bytes, plaintext: bytes, aad: bytes) -> (bytes, bytes):
    nonce = os.urandom(12)  # 96-bit GCM nonce
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, associated_data=aad)
    return nonce, ct

def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> Optional[bytes]:
    aead = AESGCM(key)
    try:
        return aead.decrypt(nonce, ciphertext, associated_data=aad)
    except Exception:
        return None

# ---------- Client state ----------
@dataclass
class ClientState:
    channel_id: str
    key: bytes
    nickname: str
    send_ctr: int = 0                    # monotonic per-sender counter
    recv_ctr: Dict[str, int] = None      # highest seen per remote sender

    def __post_init__(self):
        if self.recv_ctr is None:
            self.recv_ctr = {}

MAX_BODY_BYTES = 4000  # hard cap per message body

def build_aad(channel_id: str, sender: str, ctr: int) -> bytes:
    # Bind metadata so server cannot tamper with it without breaking auth
    meta = {"channel": channel_id, "from": sender, "ctr": ctr}
    return json.dumps(meta, separators=(",", ":")).encode("utf-8")

async def send_join(writer: asyncio.StreamWriter, state: ClientState):
    frame = {"op": "join", "channel_id": state.channel_id, "nickname": state.nickname}
    writer.write((json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8"))
    await writer.drain()

async def send_encrypted_text(writer: asyncio.StreamWriter, state: ClientState, text: str):
    text = sanitize_text(text)
    if not text:
        return
    b = text.encode("utf-8")
    if len(b) > MAX_BODY_BYTES:
        print("[warn] message too long; truncated")
        b = b[:MAX_BODY_BYTES]
        text = b.decode("utf-8", errors="ignore")

    state.send_ctr += 1
    payload = {"from": state.nickname, "body": text, "ts": int(time.time()), "ctr": state.send_ctr}
    pt = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    aad = build_aad(state.channel_id, state.nickname, state.send_ctr)
    nonce, ct = encrypt_message(state.key, pt, aad)

    frame = {
        "op": "msg",
        "channel_id": state.channel_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "ctr": state.send_ctr,  # redundant but helps receivers prebuild AAD
        "from": state.nickname  # redundant; integrity-protected via AAD/tag
    }
    writer.write((json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8"))
    await writer.drain()

async def reader_task(reader: asyncio.StreamReader, state: ClientState):
    while True:
        line = await reader.readline()
        if not line:
            print("Disconnected.")
            break
        try:
            msg = json.loads(line.decode("utf-8").strip())
        except Exception:
            continue

        op = msg.get("op")
        if op == "info":
            print(f"[server] {msg.get('msg')}")
        elif op == "error":
            print(f"[error] {msg.get('msg')}")
        elif op == "notice":
            print(f"[notice] {msg.get('msg')}")
        elif op == "msg":
            if msg.get("channel_id") != state.channel_id:
                continue
            try:
                nonce = base64.b64decode(msg["nonce"])
                ct = base64.b64decode(msg["ciphertext"])
                sender = str(msg.get("from", "?"))
                ctr = int(msg.get("ctr", -1))
            except Exception:
                continue

            # Replay/ordering guard (strictly increasing)
            last = state.recv_ctr.get(sender, 0)
            if ctr <= last:
                # Drop replay/old packets
                continue

            aad = build_aad(state.channel_id, sender, ctr)
            pt = decrypt_message(state.key, nonce, ct, aad)
            if pt is None:
                continue
            try:
                payload = json.loads(pt.decode("utf-8"))
            except Exception:
                continue

            # Advance replay window only after successful auth/decrypt
            state.recv_ctr[sender] = ctr

            nick = payload.get("from", sender)
            body = sanitize_text(payload.get("body", ""))
            print(f"[{nick}] {body}")
        else:
            pass

async def writer_task(writer: asyncio.StreamWriter, state: ClientState):
    loop = asyncio.get_running_loop()
    while True:
        text = await loop.run_in_executor(None, input)  # no history; plain stdin
        text = text.strip()
        if not text:
            continue
        if text.lower() in ("/quit", "/exit"):
            break
        await send_encrypted_text(writer, state, text)

async def main():
    print("JanusGate client (secure, no history)")
    host = input(f"Host [{HOST}]: ").strip() or HOST
    port_s = input(f"Port [{PORT}]: ").strip() or str(PORT)
    port = int(port_s)

    nickname = input("Nickname: ").strip()
    while not nickname:
        nickname = input("Nickname: ").strip()

    # Passphrase for both channel selection + key derivation
    passphrase = getpass.getpass("Passphrase (channel key): ").strip()
    while not passphrase:
        passphrase = getpass.getpass("Passphrase (channel key): ").strip()

    channel_id = channel_id_from_passphrase(passphrase)
    key = derive_key_from_passphrase(passphrase)

    # Best-effort scrubbing of passphrase reference
    del passphrase

    state = ClientState(channel_id=channel_id, key=key, nickname=nickname)

    reader, writer = await asyncio.open_connection(host, port)
    await send_join(writer, state)

    try:
        await asyncio.gather(reader_task(reader, state), writer_task(writer, state))
    finally:
        writer.close()
        await writer.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
