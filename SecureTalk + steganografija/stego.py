import json
from PIL import Image
import os
from utils import bytes_to_bits, bits_to_bytes, int_to_bytes, bytes_to_int, write_log, now_iso
from crypto_utils import encrypt_payload_aes_gcm, decrypt_payload_aes_gcm

MAGIC = b'STG0'
VERSION = b'\x01'

# ----- Pakovanje i raspakivanje -----
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

# ----- Steganografija -----
def embed_bytes_into_image(image_path: str, out_path: str, data: bytes):
    img = Image.open(image_path).convert('RGBA')
    pixels = list(img.getdata())
    channels = []
    for pix in pixels:
        r, g, b, a = pix
        channels.extend([r, g, b])

    bits = bytes_to_bits(data)
    if len(bits) > len(channels):
        raise ValueError(f'Poruka prevelika za sliku. Kapacitet: {len(channels)}, potrebno: {len(bits)}')

    for i, bit in enumerate(bits):
        channels[i] = (channels[i] & ~1) | bit

    new_pixels = []
    it = iter(channels)
    for r, g, b, a in pixels:
        try:
            nr = next(it)
            ng = next(it)
            nb = next(it)
        except StopIteration:
            nr, ng, nb = r, g, b
        new_pixels.append((nr, ng, nb, a))

    out_img = Image.new('RGBA', img.size)
    out_img.putdata(new_pixels)
    out_img.save(out_path, 'PNG')

    write_log({'time': now_iso(), 'event': 'embed', 'image_in': image_path, 'image_out': out_path, 'bytes_embedded': len(data)})

def extract_bytes_from_image(image_path: str):
    img = Image.open(image_path).convert('RGBA')
    pixels = list(img.getdata())
    channels = []
    for pix in pixels:
        r, g, b, a = pix
        channels.extend([r, g, b])
    bits = [ch & 1 for ch in channels]
    data = bits_to_bytes(bits)
    if len(data) < 9 or data[0:4] != MAGIC:
        raise ValueError('Nevalidna ili premala stego slika')
    meta_len = int.from_bytes(data[5:9], 'big')
    payload_len = int.from_bytes(data[9+meta_len:9+meta_len+8], 'big')
    total_needed = 9 + meta_len + 8 + payload_len
    full = data[:total_needed]
    metadata, payload = parse_package(full)
    write_log({'time': now_iso(), 'event': 'extract', 'image': image_path, 'bytes_extracted': len(payload), 'metadata': metadata})
    return metadata, payload

# ----- File embed/extract -----
def embed_file(image_path: str, infile: str, out_path: str, encrypt_password: str = None):
    with open(infile, 'rb') as f:
        payload = f.read()
    metadata = {'original_filename': os.path.basename(infile), 'payload_size': len(payload)}
    if encrypt_password:
        salt, iv, ct = encrypt_payload_aes_gcm(payload, encrypt_password)
        metadata.update({'crypto': 'AES-GCM', 'salt': salt.hex(), 'iv': iv.hex()})
        payload = ct
    package = build_package(metadata, payload)
    embed_bytes_into_image(image_path, out_path, package)

def extract_to_file(image_path: str, out_dir: str, decrypt_password: str = None):
    metadata, payload = extract_bytes_from_image(image_path)
    if metadata.get('crypto') == 'AES-GCM':
        if not decrypt_password:
            raise ValueError('Slika je enkriptovana, potrebna je lozinka')
        salt = bytes.fromhex(metadata['salt'])
        iv = bytes.fromhex(metadata['iv'])
        payload = decrypt_payload_aes_gcm(payload, decrypt_password, salt, iv)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    fname = metadata.get('original_filename', 'extracted.bin')
    out_path = os.path.join(out_dir, fname)
    with open(out_path, 'wb') as f:
        f.write(payload)
    return metadata, out_path

# ----- Direktna enk/dek funkcija -----
def embed_message(image_path: str, message: str, out_path: str, password: str = None):
    payload = message.encode('utf-8')
    metadata = {'original_filename': 'msg.txt', 'payload_size': len(payload)}
    if password:
        salt, iv, ct = encrypt_payload_aes_gcm(payload, password)
        metadata.update({'crypto': 'AES-GCM', 'salt': salt.hex(), 'iv': iv.hex()})
        payload = ct
    package = build_package(metadata, payload)
    embed_bytes_into_image(image_path, out_path, package)

def extract_message(image_path: str, password: str = None) -> str:
    metadata, payload = extract_bytes_from_image(image_path)
    if metadata.get('crypto') == 'AES-GCM':
        if not password:
            raise ValueError('Poruka je enkriptovana, potrebna je lozinka')
        salt = bytes.fromhex(metadata['salt'])
        iv = bytes.fromhex(metadata['iv'])
        payload = decrypt_payload_aes_gcm(payload, password, salt, iv)
    return payload.decode('utf-8')
