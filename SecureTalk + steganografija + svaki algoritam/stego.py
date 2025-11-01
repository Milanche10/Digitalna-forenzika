# stego.py
import json
import os
import base64
from PIL import Image
import numpy as np
from utils import bytes_to_bits, bits_to_bytes, int_to_bytes, bytes_to_int, write_log, now_iso
from crypto_utils import encrypt_payload_aes_gcm, decrypt_payload_aes_gcm

# DCT imports (scipy required)
try:
    from scipy.fftpack import dct, idct
    HAVE_SCIPY = True
except Exception:
    HAVE_SCIPY = False

MAGIC = b'STG0'   # 4 bytes
VERSION = b'\x01' # 1 byte

# ----- package format helpers -----
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
    meta_len = int.from_bytes(data[5:9], 'big')
    meta_start = 9
    meta_end = meta_start + meta_len
    meta_json = data[meta_start:meta_end]
    metadata = json.loads(meta_json.decode('utf-8'))
    payload_len = int.from_bytes(data[meta_end:meta_end+8], 'big')
    payload_start = meta_end + 8
    payload_end = payload_start + payload_len
    payload = data[payload_start:payload_end]
    return metadata, payload

# ---------------- LSB functions ----------------
def embed_bytes_lsb(image_path: str, out_path: str, data: bytes):
    img = Image.open(image_path).convert('RGBA')
    pixels = list(img.getdata())
    channels = []
    for pix in pixels:
        r, g, b, a = pix
        channels.extend([r, g, b])

    bits = bytes_to_bits(data)
    capacity = len(channels)
    if len(bits) > capacity:
        raise ValueError(f'Poruka prevelika za LSB kapacitet: {capacity} bitova, potrebno: {len(bits)}')

    for i, bit in enumerate(bits):
        channels[i] = (channels[i] & ~1) | bit

    new_pixels = []
    it = iter(channels)
    for r, g, b, a in pixels:
        nr = next(it, r)
        ng = next(it, g)
        nb = next(it, b)
        new_pixels.append((nr, ng, nb, a))

    out_img = Image.new('RGBA', img.size)
    out_img.putdata(new_pixels)
    out_img.save(out_path, 'PNG')
    write_log({'time': now_iso(), 'event': 'embed_lsb', 'image_in': image_path, 'image_out': out_path, 'bytes_embedded': len(data)})

def extract_bytes_lsb(image_path: str):
    img = Image.open(image_path).convert('RGBA')
    pixels = list(img.getdata())
    channels = []
    for pix in pixels:
        r, g, b, a = pix
        channels.extend([r, g, b])
    bits = [ch & 1 for ch in channels]
    data = bits_to_bytes(bits)
    # try parse
    if len(data) < 9 or data[0:4] != MAGIC:
        raise ValueError('Nevalidna ili premala stego slika (LSB)')
    meta_len = int.from_bytes(data[5:9], 'big')
    total_needed = 9 + meta_len + 8
    payload_len = int.from_bytes(data[9+meta_len:9+meta_len+8], 'big')
    total_needed = total_needed + payload_len
    full = data[:total_needed]
    metadata, payload = parse_package(full)
    write_log({'time': now_iso(), 'event': 'extract_lsb', 'image': image_path, 'bytes_extracted': len(payload), 'metadata': metadata})
    return metadata, payload

# ---------------- DCT functions ----------------
def _dct2(block):
    # 2D DCT type-II orthonormal
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def _idct2(block):
    return idct(idct(block.T, norm='ortho').T, norm='ortho')

def _ycbcr_to_array(img: Image.Image):
    ycbcr = img.convert('YCbCr')
    arr = np.array(ycbcr, dtype=np.float32)
    return arr  # shape (h,w,3)

def _array_to_image(arr: np.ndarray):
    arr_clipped = np.clip(arr, 0, 255).astype(np.uint8)
    img = Image.fromarray(arr_clipped, mode='YCbCr').convert('RGBA')
    return img

def embed_bytes_dct(image_path: str, out_path: str, data: bytes):
    if not HAVE_SCIPY:
        raise RuntimeError('DCT embedding zahteva scipy (pip install scipy).')
    img = Image.open(image_path)
    arr = _ycbcr_to_array(img)
    Y = arr[..., 0]
    h, w = Y.shape
    # pad to multiple of 8
    pad_h = (8 - (h % 8)) % 8
    pad_w = (8 - (w % 8)) % 8
    Yp = np.pad(Y, ((0, pad_h), (0, pad_w)), mode='constant', constant_values=0)
    H, W = Yp.shape
    nblocks_h = H // 8
    nblocks_w = W // 8

    # choose mid-frequency positions
    mask_positions = [(u, v) for u in range(8) for v in range(8) if not (u==0 and v==0)]
    mask_positions = [(u, v) for (u, v) in mask_positions if 2 <= (u + v) <= 6]

    capacity = nblocks_h * nblocks_w * len(mask_positions)
    bits = bytes_to_bits(data)
    if len(bits) > capacity:
        raise ValueError(f'Poruka prevelika za DCT kapacitet: {capacity} bitova, potrebno: {len(bits)}')

    # scale factor -> kvantizacija radi stabilnijeg LSB upisa
    SCALE = 100.0

    outY = np.copy(Yp)
    bit_iter = iter(bits)
    finished = False
    for by in range(nblocks_h):
        if finished:
            break
        for bx in range(nblocks_w):
            y0 = by*8; x0 = bx*8
            block = Yp[y0:y0+8, x0:x0+8]
            block = block - 128.0
            C = _dct2(block)
            # embed u kvantizovanom prostoru
            for (u, v) in mask_positions:
                try:
                    bit = next(bit_iter)
                except StopIteration:
                    finished = True
                    break
                coeff = C[u, v]
                ival = int(np.round(coeff * SCALE))
                ival = (ival & ~1) | (bit & 1)
                # zapamti kao float, vratimo deljenjem za IDCT
                C[u, v] = float(ival) / SCALE
            block_rec = _idct2(C) + 128.0
            outY[y0:y0+8, x0:x0+8] = block_rec
            if finished:
                break

    outY = outY[:h, :w]
    out_arr = np.copy(arr)
    out_arr[..., 0] = outY
    out_img = _array_to_image(out_arr)
    out_img.save(out_path, 'PNG')
    write_log({'time': now_iso(), 'event': 'embed_dct', 'image_in': image_path, 'image_out': out_path, 'bytes_embedded': len(data)})

def extract_bytes_dct(image_path: str):
    if not HAVE_SCIPY:
        raise RuntimeError('DCT extraction zahteva scipy (pip install scipy).')
    img = Image.open(image_path)
    arr = _ycbcr_to_array(img)
    Y = arr[..., 0]
    h, w = Y.shape
    pad_h = (8 - (h % 8)) % 8
    pad_w = (8 - (w % 8)) % 8
    Yp = np.pad(Y, ((0, pad_h), (0, pad_w)), mode='constant', constant_values=0)
    H, W = Yp.shape
    nblocks_h = H // 8
    nblocks_w = W // 8

    mask_positions = [(u, v) for u in range(8) for v in range(8) if not (u==0 and v==0)]
    mask_positions = [(u, v) for (u, v) in mask_positions if 2 <= (u + v) <= 6]

    bits = []
    SCALE = 100.0
    for by in range(nblocks_h):
        for bx in range(nblocks_w):
            y0 = by*8; x0 = bx*8
            block = Yp[y0:y0+8, x0:x0+8]
            block = block - 128.0
            C = _dct2(block)
            for (u, v) in mask_positions:
                ival = int(np.round(C[u, v] * SCALE))
                bits.append(ival & 1)

    data = bits_to_bytes(bits)
    # now try to parse package safely
    try:
        if len(data) < 9 or data[0:4] != MAGIC:
            raise ValueError('Ne postoji magic header (nije STG)')
        meta_len = int.from_bytes(data[5:9], 'big')
        payload_len = int.from_bytes(data[9+meta_len:9+meta_len+8], 'big')
        total_needed = 9 + meta_len + 8 + payload_len
        full = data[:total_needed]
        metadata, payload = parse_package(full)
    except UnicodeDecodeError as ude:
        # metadata decoding failed -> more robust message for caller
        raise ValueError(f'Metadata decoding failed (utf-8): {ude}')
    except Exception as e:
        # generic failure (no header, truncated, etc.)
        raise RuntimeError(str(e))

    write_log({'time': now_iso(), 'event': 'extract_dct', 'image': image_path, 'bytes_extracted': len(payload), 'metadata': metadata})
    return metadata, payload

# ---------------- PVD stub (for completeness) ----------------
def embed_bytes_pvd(image_path: str, out_path: str, data: bytes):
    # Placeholder simple implementation: fallback to LSB for now
    # (You can implement a full PVD embedding later)
    return embed_bytes_lsb(image_path, out_path, data)

def extract_bytes_pvd(image_path: str):
    # Placeholder: same as LSB extraction
    return extract_bytes_lsb(image_path)

# ---------------- Generic dispatchers ----------------
ALGORITHMS = {
    'LSB': (embed_bytes_lsb, extract_bytes_lsb),
    'DCT': (embed_bytes_dct, extract_bytes_dct),
    'PVD': (embed_bytes_pvd, extract_bytes_pvd),
}

def embed_bytes_into_image(image_path: str, out_path: str, data: bytes, algorithm: str = 'LSB'):
    alg = algorithm.upper()
    if alg not in ALGORITHMS:
        raise ValueError(f'Nepoznat algoritam: {algorithm}')
    embed_func = ALGORITHMS[alg][0]
    print(f"[STEGO] Embedding using {alg}: {image_path} -> {out_path}, bytes={len(data)}")
    return embed_func(image_path, out_path, data)

def extract_bytes_from_image(image_path: str, algorithm: str = None):
    # if algorithm hint provided, try that first, else try all
    if algorithm:
        alg = algorithm.upper()
        if alg not in ALGORITHMS:
            raise ValueError(f'Nepoznat algoritam: {algorithm}')
        try:
            print(f"[STEGO] Attempting extraction with hinted algorithm: {alg}")
            return ALGORITHMS[alg][1](image_path)
        except Exception as e:
            raise RuntimeError(f'Extraction with {alg} failed: {e}')
    # try all algorithms in order
    errs = {}
    for alg_name, (_enc, dec) in ALGORITHMS.items():
        try:
            print(f"[STEGO] Attempting autodetect extraction with {alg_name}")
            return dec(image_path)
        except Exception as e:
            errs[alg_name] = str(e)
            continue
    raise RuntimeError(f'No stego package found. Errors: {errs}')

# ------- File helpers using above -------
def embed_file(image_path: str, infile: str, out_path: str, algorithm: str = 'LSB', encrypt_password: str = None, metadata_extra: dict = None):
    with open(infile, 'rb') as f:
        payload = f.read()
    metadata = metadata_extra or {}
    metadata.setdefault('original_filename', os.path.basename(infile))
    metadata.setdefault('payload_size', len(payload))
    metadata['stego_algorithm'] = algorithm.upper()
    metadata['crypto'] = 'NONE'
    if encrypt_password:
        salt, iv, ct = encrypt_payload_aes_gcm(payload, encrypt_password)
        # store base64 in metadata
        metadata['crypto'] = 'AES-GCM'
        metadata['salt'] = base64.b64encode(salt).decode('utf-8')
        metadata['iv'] = base64.b64encode(iv).decode('utf-8')
        payload_to_embed = ct
    else:
        payload_to_embed = payload
    package = build_package(metadata, payload_to_embed)
    embed_bytes_into_image(image_path, out_path, package, algorithm=algorithm)

def extract_to_file(image_path: str, out_dir: str, algorithm_hint: str = None, decrypt_password: str = None):
    metadata, payload = extract_bytes_from_image(image_path, algorithm=algorithm_hint)
    if metadata.get('crypto') == 'AES-GCM':
        if not decrypt_password:
            raise ValueError('Slika je enkriptovana, potrebna je lozinka')
        salt = base64.b64decode(metadata['salt'])
        iv = base64.b64decode(metadata['iv'])
        payload = decrypt_payload_aes_gcm(payload, decrypt_password, salt, iv)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    fname = metadata.get('original_filename', 'extracted.bin')
    out_path = os.path.join(out_dir, fname)
    with open(out_path, 'wb') as f:
        f.write(payload)
    return metadata, out_path
