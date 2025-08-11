#!/usr/bin/env python3
import asyncio
import json
import signal
import time
from collections import deque, defaultdict
from typing import Dict, Set, Tuple

HOST = "0.0.0.0"
PORT = 8765

# Security/robustness limits
MAX_LINE_BYTES = 16_384          # hard cap on any inbound frame
MAX_CHANNELS_PER_HOST = 50_000
MAX_NICK_LEN = 48
MAX_CHANNEL_ID_LEN = 64          # blake2b-256 hex is 64
MAX_BROADCAST_QUEUE = 10_000
# simple token bucket: 30 frames / 10s per connection
RATE_WINDOW_SEC = 10
RATE_MAX_FRAMES = 30

Channels = Dict[str, Set[Tuple[asyncio.StreamWriter, str]]]
channels: Channels = {}
peer_info: Dict[asyncio.StreamWriter, Tuple[str, str]] = {}
rate_window: Dict[asyncio.StreamWriter, deque] = defaultdict(deque)

WELCOME = {"op": "info", "msg": "Connected. Send JOIN to enter a channel."}
JOIN_OK = {"op": "info", "msg": "Joined."}

def safe_json_decode(b: bytes):
    try:
        return json.loads(b.decode("utf-8").strip())
    except Exception:
        return None

async def broadcast_channel(channel_id: str, payload: dict, exclude: asyncio.StreamWriter = None):
    if channel_id not in channels:
        return
    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    dead = []
    # minimal backpressure protection
    for w, _nick in list(channels[channel_id]):
        if exclude is not None and w is exclude:
            continue
        try:
            if w.transport.get_write_buffer_size() > MAX_BROADCAST_QUEUE:
                # messy peer; drop it
                dead.append(w)
                continue
            w.write(data)
            await w.drain()
        except Exception:
            dead.append(w)
    for w in dead:
        await drop_writer(w)

async def drop_writer(writer: asyncio.StreamWriter):
    info = peer_info.pop(writer, None)
    if info:
        cid, nick = info
        members = channels.get(cid)
        if members:
            members = {t for t in members if t[0] is not writer}
            if members:
                channels[cid] = members
            else:
                channels.pop(cid, None)
        # plaintext notice (metadata is not secret in this model)
        await broadcast_channel(cid, {"op": "notice", "msg": f"{nick} left."})
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    rate_window.pop(writer, None)

def rate_ok(writer: asyncio.StreamWriter) -> bool:
    now = time.time()
    q = rate_window[writer]
    q.append(now)
    while q and now - q[0] > RATE_WINDOW_SEC:
        q.popleft()
    return len(q) <= RATE_MAX_FRAMES

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    writer.write((json.dumps(WELCOME) + "\n").encode("utf-8"))
    await writer.drain()

    channel_id = None
    nickname = None

    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                # oversized frame = drop
                break

            if not rate_ok(writer):
                # rate exceeded
                writer.write(b'{"op":"error","msg":"rate-limit"}\n')
                await writer.drain()
                break

            msg = safe_json_decode(line)
            if not msg or not isinstance(msg, dict):
                continue

            op = msg.get("op")
            if op == "join":
                cid = msg.get("channel_id")
                nick = msg.get("nickname")

                if (not isinstance(cid, str) or not isinstance(nick, str) or
                    not cid or not nick or
                    len(cid) > MAX_CHANNEL_ID_LEN or
                    len(nick) > MAX_NICK_LEN):
                    writer.write(b'{"op":"error","msg":"invalid-join"}\n')
                    await writer.drain()
                    continue

                if len(channels) >= MAX_CHANNELS_PER_HOST and cid not in channels:
                    writer.write(b'{"op":"error","msg":"channel-limit"}\n')
                    await writer.drain()
                    continue

                channel_id = cid
                nickname = nick
                peer_info[writer] = (channel_id, nickname)
                channels.setdefault(channel_id, set()).add((writer, nickname))
                writer.write((json.dumps(JOIN_OK) + "\n").encode("utf-8"))
                await writer.drain()
                await broadcast_channel(channel_id, {"op": "notice", "msg": f"{nickname} joined."}, exclude=writer)

            elif op == "msg":
                # relay E2E blob as-is (server is blind to contents)
                cid = msg.get("channel_id")
                if not channel_id or cid != channel_id:
                    writer.write(b'{"op":"error","msg":"not-in-channel"}\n')
                    await writer.drain()
                    continue
                # minimal sanity checks to reduce abuse
                if not isinstance(msg.get("nonce"), str) or not isinstance(msg.get("ciphertext"), str):
                    writer.write(b'{"op":"error","msg":"bad-frame"}\n')
                    await writer.drain()
                    continue
                await broadcast_channel(channel_id, msg)

            elif op == "ping":
                writer.write(b'{"op":"pong"}\n')
                await writer.drain()
            else:
                writer.write(b'{"op":"error","msg":"unknown-op"}\n')
                await writer.drain()

    except asyncio.CancelledError:
        pass
    except Exception:
        pass
    finally:
        await drop_writer(writer)

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"JanusGate host running on {HOST}:{PORT}")
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    async with server:
        await asyncio.gather(server.serve_forever(), stop.wait())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
