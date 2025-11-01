# utils.py
import os
import json
import time
from pathlib import Path

LOG_DIR = Path('logs')
LOG_DIR.mkdir(exist_ok=True)

def now_iso():
    return time.strftime('%Y-%m-%dT%H:%M:%S%z')

def write_log(entry: dict, filename='logs/events.log'):
    Path(filename).parent.mkdir(parents=True, exist_ok=True)
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def bytes_to_bits(data: bytes) -> list:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits) -> bytes:
    b = bytearray()
    # pad bits to multiple of 8 (should not be necessary if data is complete)
    rem = len(bits) % 8
    if rem != 0:
        bits = bits + [0] * (8 - rem)
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        b.append(byte)
    return bytes(b)

def int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')
