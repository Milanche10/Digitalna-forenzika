# stego.py
"""
LSB embedding / extraction with internal package format.

FORMAT:
- MAGIC: 4B b"STG0"
- VERSION: 1B
- META_LEN: 4B (big-endian)
- META_JSON: META_LEN bytes (UTF-8)
- PAYLOAD_LEN: 8B (big-endian)
- PAYLOAD: PAYLOAD_LEN bytes

All concatenated and embedded bitwise into LSBs of RGB channels (alpha untouched).
"""
import json
from PIL import Image
import os
from utils import bytes_to_bits, bits_to_bytes, int_to_bytes, bytes_to_int, write_log, now_iso

MAGIC = b'STG0'
VERSION = b'\x01'

def build_package(metadata: dict, payload: bytes) -> bytes:
    meta_json = json.dumps(metadata, ensure_ascii=False).encode('utf-8')
    meta_len = int_to_bytes(len(meta_json), 4)
    payload_len = int_to_bytes(len(payload), 8)
    package = MAGIC + VERSION + meta_len + meta_json + payload_len + payload
    return package

def parse_package(data: bytes):
    if len(data) < 9:
        raise ValueError('Paket premalen')
    if data[0:4] != MAGIC:
        raise ValueError('Ne postoji magic header (nije STG)')
    # version = data[4]
    meta_len = bytes_to_int(data[5:9])
    meta_start = 9
    meta_end = meta_start + meta_len
    meta_json = data[meta_start:meta_end]
    metadata = json.loads(meta_json.decode('utf-8'))
    payload_len = bytes_to_int(data[meta_end:meta_end+8])
    payload_start = meta_end + 8
    payload_end = payload_start + payload_len
    payload = data[payload_start:payload_end]
    return metadata, payload

def embed_bytes_into_image(image_path: str, out_path: str, data: bytes):
    img = Image.open(image_path)
    img = img.convert('RGBA')
    pixels = list(img.getdata())

    # Flatten RGB values (ignore alpha)
    channels = []
    for pix in pixels:
        r, g, b, a = pix
        channels.extend([r, g, b])

    bits = bytes_to_bits(data)
    capacity = len(channels)
    if len(bits) > capacity:
        raise ValueError(f'Poruka prevelika za ovu sliku. Kapacitet (bitova): {capacity}, potrebno: {len(bits)}')

    # Embed bits
    for i, bit in enumerate(bits):
        channels[i] = (channels[i] & ~1) | bit

    # Rebuild pixels
    new_pixels = []
    it = iter(channels)
    for r, g, b, a in pixels:
        try:
            nr = next(it)
            ng = next(it)
            nb = next(it)
        except StopIteration:
            # no more channel data — keep remaining channels as-is (shouldn't happen if capacity checked)
            nr, ng, nb = r, g, b
        new_pixels.append((nr, ng, nb, a))

    out_img = Image.new('RGBA', img.size)
    out_img.putdata(new_pixels)
    out_img.save(out_path, 'PNG')

    write_log({'time': now_iso(), 'event': 'embed', 'image_in': image_path, 'image_out': out_path, 'bytes_embedded': len(data)})

def extract_bytes_from_image(image_path: str) -> tuple[dict, bytes]:
    img = Image.open(image_path)
    img = img.convert('RGBA')
    pixels = list(img.getdata())

    channels = []
    for pix in pixels:
        r, g, b, a = pix
        channels.extend([r, g, b])

    bits = []
    for ch in channels:
        bits.append(ch & 1)
    data = bits_to_bytes(bits)

    # Try parse package: need to find exact total length via meta/payload len
    # First check basic header and meta length presence
    if len(data) < 9:
        raise ValueError('Nedovoljno podataka u slici')
    if data[0:4] != MAGIC:
        raise ValueError('Magic header nije prisutan')
    meta_len = int.from_bytes(data[5:9], 'big')
    total_header_len = 9 + meta_len + 8  # 9 bytes before meta, meta_len, 8 bytes payload_len
    if len(data) < total_header_len:
        raise ValueError('Slika ne sadrži dovoljan broj bitova za kompletan header')
    payload_len = int.from_bytes(data[9+meta_len:9+meta_len+8], 'big')
    total_needed = total_header_len + payload_len
    if len(data) < total_needed:
        raise ValueError('Slika ne sadrži dovoljan broj bitova za ceo paket')
    full = data[:total_needed]
    metadata, payload = parse_package(full)

    write_log({'time': now_iso(), 'event': 'extract', 'image': image_path, 'bytes_extracted': len(payload), 'metadata': metadata})
    return metadata, payload

def embed_file(image_path: str, infile: str, out_path: str, metadata_extra: dict = None):
    with open(infile, 'rb') as f:
        payload = f.read()
    metadata = metadata_extra or {}
    metadata.setdefault('original_filename', os.path.basename(infile))
    metadata.setdefault('payload_size', len(payload))
    package = build_package(metadata, payload)
    embed_bytes_into_image(image_path, out_path, package)

def extract_to_file(image_path: str, out_dir: str):
    metadata, payload = extract_bytes_from_image(image_path)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    fname = metadata.get('original_filename', 'extracted.bin')
    out_path = os.path.join(out_dir, fname)
    with open(out_path, 'wb') as f:
        f.write(payload)
    return metadata, out_path
