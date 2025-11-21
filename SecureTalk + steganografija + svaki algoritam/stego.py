# stego.py
import json
import os
import base64
from PIL import Image
import numpy as np
import math
from utils import int_to_bytes, bytes_to_int, write_log, now_iso
from crypto_utils import encrypt_payload_aes_gcm, decrypt_payload_aes_gcm
import gc  # Dodato za memorijsko čišćenje

# DCT imports (scipy required)
try:
    from scipy.fftpack import dct, idct
    HAVE_SCIPY = True
except Exception:
    HAVE_SCIPY = False

# DWT imports (pywt required for new algorithm)
try:
    import pywt
    HAVE_PYWT = True
except Exception:
    HAVE_PYWT = False

MAGIC = b'STG0'   # 4 bytes
VERSION = b'\x01' # 1 byte

# ---------------- Bit helpers ----------------
def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

def bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# ---------------- Package helpers ----------------
def build_package(metadata: dict, payload: bytes) -> bytes:
    meta_json = json.dumps(metadata, ensure_ascii=False).encode('utf-8')
    meta_len = int_to_bytes(len(meta_json), 4)
    payload_len = int_to_bytes(len(payload), 8)
    return MAGIC + VERSION + meta_len + meta_json + payload_len + payload

def parse_package(data: bytes):
    try:
        if len(data) < 13 or data[0:4] != MAGIC:
            raise ValueError('Ne postoji magic header (nije STG)')
        meta_len = bytes_to_int(data[5:9])
        meta_start = 9
        meta_end = meta_start + meta_len
        if meta_end > len(data):
            raise ValueError('Nedovoljno bajtova za metadata')
        meta_json = data[meta_start:meta_end]
        metadata = json.loads(meta_json.decode('utf-8'))
        payload_len = bytes_to_int(data[meta_end:meta_end+8])
        payload_start = meta_end + 8
        payload_end = payload_start + payload_len
        if payload_end > len(data):
            raise ValueError('Nedovoljno bajtova za payload')
        payload = data[payload_start:payload_end]
        return metadata, payload
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'parse_error', 'error': str(e)})
        raise

# ---------------- LSB ----------------
def estimate_capacity_lsb(image_path: str) -> int:
    img = Image.open(image_path).convert('RGBA')
    pixels = list(img.getdata())
    return len(pixels) * 3  # 3 bita po pikselu (RGB)

def embed_bytes_lsb(image_path: str, out_path: str, data: bytes):
    try:
        bits = bytes_to_bits(data)
        capacity = estimate_capacity_lsb(image_path)
        if len(bits) > capacity:
            raise ValueError(f'Poruka prevelika za LSB kapacitet: {len(bits)} > {capacity}')
        
        img = Image.open(image_path).convert('RGBA')
        pixels = list(img.getdata())
        channels = [ch for pix in pixels for ch in pix[:3]]

        for i, bit in enumerate(bits):
            channels[i] = (channels[i] & ~1) | int(bit)

        it = iter(channels)
        new_pixels = [(next(it), next(it), next(it), a) for r,g,b,a in pixels]
        out_img = Image.new('RGBA', img.size)
        out_img.putdata(new_pixels)
        out_img.save(out_path, 'PNG')
        write_log({'time': now_iso(), 'event': 'embed_lsb', 'image_in': image_path,
                   'image_out': out_path, 'bytes_embedded': len(data), 'bits': len(bits), 'capacity': capacity})
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'embed_lsb_error', 'error': str(e)})
        raise RuntimeError('LSB embedding failed') from e

def extract_bytes_lsb(image_path: str):
    try:
        img = Image.open(image_path).convert('RGBA')
        pixels = list(img.getdata())
        channels = [ch for pix in pixels for ch in pix[:3]]
        bits = [ch & 1 for ch in channels]
        data = bits_to_bytes(''.join(str(b) for b in bits))
        metadata, payload = parse_package(data)
        write_log({'time': now_iso(), 'event': 'extract_lsb', 'image': image_path,
                   'bytes_extracted': len(payload), 'metadata': metadata})
        return metadata, payload
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'extract_lsb_error', 'error': str(e)})
        raise RuntimeError('LSB extraction failed') from e

# ---------------- New: LSB2 (2 LSB bits per channel) ----------------
def estimate_capacity_lsb2(image_path: str) -> int:
    img = Image.open(image_path).convert('RGBA')
    pixels = list(img.getdata())
    return len(pixels) * 3 * 2  # 6 bita po pikselu (2 po RGB kanalu)

def embed_bytes_lsb2(image_path: str, out_path: str, data: bytes):
    try:
        bits = bytes_to_bits(data)
        capacity = estimate_capacity_lsb2(image_path)
        if len(bits) > capacity:
            raise ValueError(f'Poruka prevelika za LSB2 kapacitet: {len(bits)} > {capacity}')
        
        img = Image.open(image_path).convert('RGBA')
        pixels = list(img.getdata())
        channels = [ch for pix in pixels for ch in pix[:3]]

        bit_idx = 0
        for i in range(len(channels)):
            if bit_idx + 2 > len(bits):
                break
            channels[i] = (channels[i] & ~3) | (int(bits[bit_idx:bit_idx+2], 2))
            bit_idx += 2

        it = iter(channels)
        new_pixels = [(next(it), next(it), next(it), a) for r,g,b,a in pixels]
        out_img = Image.new('RGBA', img.size)
        out_img.putdata(new_pixels)
        out_img.save(out_path, 'PNG')
        write_log({'time': now_iso(), 'event': 'embed_lsb2', 'image_in': image_path,
                   'image_out': out_path, 'bytes_embedded': len(data), 'bits': len(bits), 'capacity': capacity})
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'embed_lsb2_error', 'error': str(e)})
        raise RuntimeError('LSB2 embedding failed') from e

def extract_bytes_lsb2(image_path: str):
    try:
        img = Image.open(image_path).convert('RGBA')
        pixels = list(img.getdata())
        channels = [ch for pix in pixels for ch in pix[:3]]
        bits = []
        for ch in channels:
            bits.extend(f'{ch & 3:02b}')
        data = bits_to_bytes(''.join(bits))
        metadata, payload = parse_package(data)
        write_log({'time': now_iso(), 'event': 'extract_lsb2', 'image': image_path,
                   'bytes_extracted': len(payload), 'metadata': metadata})
        return metadata, payload
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'extract_lsb2_error', 'error': str(e)})
        raise RuntimeError('LSB2 extraction failed') from e

# ---------------- DCT helpers ----------------
def _dct2(block): return dct(dct(block.T, norm='ortho').T, norm='ortho')
def _idct2(block): return np.round(idct(idct(block.T, norm='ortho').T, norm='ortho'))  # Dodata round za bolju preciznost

def _pad_image_edge_reflect(arr):
    h, w, c = arr.shape
    pad_h, pad_w = (8 - h % 8) % 8, (8 - w % 8) % 8
    return np.pad(arr, ((0,pad_h),(0,pad_w),(0,0)), mode='reflect')

def estimate_capacity_dct(image_path: str) -> int:
    if not HAVE_SCIPY:
        raise RuntimeError('DCT requires scipy')
    img = Image.open(image_path).convert('RGB')
    arr = np.array(img, dtype=np.float32)
    arr_padded = _pad_image_edge_reflect(arr)
    H, W, _ = arr_padded.shape
    nblocks_h, nblocks_w = H//8, W//8
    mask_positions = [(u,v) for u in range(8) for v in range(8) if 2 <= u+v <= 5]
    return nblocks_h * nblocks_w * len(mask_positions) * 3  # Bitovi

# ---------------- DCT RGB embedding (Ispravljeno sa većim scale i boljim clampingom) ----------------
def embed_bytes_dct_rgb_auto(image_path: str, out_path: str, data: bytes, scale=50.0):  # Povećan scale na 50 da se bitovi bolje detektuju
    if not HAVE_SCIPY:
        raise RuntimeError('DCT embedding requires scipy')
    try:
        bits = bytes_to_bits(data)
        capacity = estimate_capacity_dct(image_path)
        if len(bits) > capacity:
            raise ValueError(f'Data too large for DCT: {len(bits)} > capacity {capacity}')
        
        img = Image.open(image_path).convert('RGB')
        arr = np.array(img, dtype=np.float32)
        arr_padded = _pad_image_edge_reflect(arr)
        H, W, C = arr_padded.shape
        mask_positions = [(u, v) for u in range(8) for v in range(8) if 2 <= u + v <= 5]
        bit_index = 0
        clamping_errors = 0
        for y in range(0, H, 8):
            for x in range(0, W, 8):
                for c in range(C):
                    block = arr_padded[y:y+8, x:x+8, c]
                    dct_block = _dct2(block)
                    for u, v in mask_positions:
                        if bit_index >= len(bits):
                            break
                        coeff = dct_block[u, v]
                        bit = int(bits[bit_index])
                        if coeff > 0:
                            coeff = math.ceil(coeff / scale) * scale + (scale / 2 if bit else 0)
                        else:
                            coeff = math.floor(coeff / scale) * scale - (scale / 2 if bit else 0)
                        dct_block[u, v] = coeff
                        bit_index += 1
                    idct_block = _idct2(dct_block)
                    clamped = np.clip(idct_block, 0, 255)
                    if not np.allclose(idct_block, clamped, atol=1e-5):  # Proveri clamping
                        clamping_errors += 1
                    arr_padded[y:y+8, x:x+8, c] = clamped
        if clamping_errors > 0:
            write_log({'time': now_iso(), 'event': 'dct_clamping_warning', 'errors': clamping_errors})
        arr_out = arr_padded[:img.size[1], :img.size[0], :].astype(np.uint8)
        out_img = Image.fromarray(arr_out, 'RGB')
        out_img.save(out_path, 'PNG')
        write_log({'time': now_iso(), 'event': 'embed_dct', 'image_in': image_path,
                   'image_out': out_path, 'bytes_embedded': len(data), 'bits': len(bits), 'capacity': int(capacity)})
        gc.collect()  # Čišćenje memorije
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'embed_dct_error', 'error': str(e)})
        raise RuntimeError('DCT embedding failed') from e

def extract_bytes_dct_rgb_auto(image_path: str):
    if not HAVE_SCIPY:
        raise RuntimeError('DCT extraction requires scipy')
    try:
        img = Image.open(image_path).convert('RGB')
        arr = np.array(img, dtype=np.float32)
        arr_padded = _pad_image_edge_reflect(arr)
        H, W, C = arr_padded.shape
        mask_positions = [(u, v) for u in range(8) for v in range(8) if 2 <= u + v <= 5]
        bits = []
        for y in range(0, H, 8):
            for x in range(0, W, 8):
                for c in range(C):
                    block = arr_padded[y:y+8, x:x+8, c]
                    dct_block = _dct2(block)
                    for u, v in mask_positions:
                        coeff = dct_block[u, v]
                        bit = 1 if coeff > 0 else 0
                        bits.append(bit)
        data_bytes = bits_to_bytes(''.join(str(b) for b in bits))
        metadata, payload = parse_package(data_bytes)
        write_log({'time': now_iso(), 'event': 'extract_dct', 'image': image_path,
                   'bytes_extracted': len(payload), 'metadata': metadata})
        return metadata, payload
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'extract_dct_error', 'error': str(e)})
        raise RuntimeError('DCT extraction failed') from e

# ---------------- PVD helpers (Ispravljeno sa boljim clampingom) ----------------
def _get_pvd_range(diff):
    if diff <= 1: return 0, 0, 0
    elif diff <= 3: return 2, 3, 1
    elif diff <= 7: return 4, 7, 2
    elif diff <= 15: return 8, 15, 3
    elif diff <= 31: return 16, 31, 4
    elif diff <= 63: return 32, 63, 5
    elif diff <= 127: return 64, 127, 6
    else: return 128, 255, 7

def estimate_capacity_pvd(image_path: str) -> int:
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img.getdata())
    capacity = 0
    for i in range(0, len(pixels)-1, 2):
        p1, p2 = pixels[i], pixels[i+1]
        for c in range(3):
            diff = abs(p1[c] - p2[c])
            _, _, nbits = _get_pvd_range(diff)
            capacity += nbits
    return capacity

# ---------------- PVD embedding (Ispravljeno: Dodat fallback za clamping) ----------------
def embed_bytes_pvd(image_path: str, out_path: str, data: bytes):
    try:
        bits = bytes_to_bits(data)
        capacity = estimate_capacity_pvd(image_path)
        if len(bits) > capacity:
            raise ValueError(f'Data too large for PVD: {len(bits)} > capacity {capacity}')
        
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())
        new_pixels = []
        bit_index = 0
        clamping_warnings = 0
        for i in range(0, len(pixels)-1, 2):
            p1, p2 = list(pixels[i]), list(pixels[i+1])
            np1, np2 = p1.copy(), p2.copy()
            for c in range(3):
                if bit_index >= len(bits): break
                diff = abs(p1[c] - p2[c])
                lower, upper, nbits = _get_pvd_range(diff)
                if nbits == 0: continue
                to_embed = bits[bit_index:bit_index + nbits].ljust(nbits, '0')
                m = int(to_embed, 2)
                new_diff = lower + m
                if p1[c] >= p2[c]:
                    np1[c] = p1[c] + math.ceil((new_diff - diff) / 2)
                    np2[c] = p2[c] - math.floor((new_diff - diff) / 2)
                else:
                    np1[c] = p1[c] - math.floor((new_diff - diff) / 2)
                    np2[c] = p2[c] + math.ceil((new_diff - diff) / 2)
                # Clamp
                np1[c] = max(0, min(255, np1[c]))
                np2[c] = max(0, min(255, np2[c]))
                actual_diff = abs(np1[c] - np2[c])
                if actual_diff != new_diff:
                    # Fallback: Reduce nbits and skip if can't
                    clamping_warnings += 1
                    write_log({'time': now_iso(), 'event': 'pvd_clamp_warning', 'original_diff': diff, 'new_diff': new_diff})
                    # Skip embedding for this channel to avoid corruption
                    continue  # Ne povećavaj bit_index, pokušaj sljedeći
                bit_index += nbits
            new_pixels.extend([tuple(np1), tuple(np2)])
        if len(pixels) % 2 != 0: new_pixels.append(pixels[-1])
        out_img = Image.new('RGB', img.size)
        out_img.putdata(new_pixels)
        out_img.save(out_path, 'PNG')
        if clamping_warnings > 0:
            write_log({'time': now_iso(), 'event': 'pvd_clamping_summary', 'warnings': clamping_warnings})
        write_log({'time': now_iso(), 'event': 'embed_pvd', 'image_in': image_path,
                   'image_out': out_path, 'bits_embedded': bit_index, 'capacity': capacity})
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'embed_pvd_error', 'error': str(e)})
        raise RuntimeError('PVD embedding failed') from e

def extract_bytes_pvd(image_path: str):
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())
        bits = []
        for i in range(0, len(pixels)-1, 2):
            p1, p2 = pixels[i], pixels[i+1]
            for c in range(3):
                diff = abs(p1[c] - p2[c])
                lower, _, nbits = _get_pvd_range(diff)
                if nbits == 0: continue
                k = diff - lower
                bits.extend(list(f'{k:0{nbits}b}'))
        data_bytes = bits_to_bytes(''.join(bits))
        metadata, payload = parse_package(data_bytes)
        write_log({'time': now_iso(), 'event': 'extract_pvd', 'image': image_path,
                   'bytes_extracted': len(payload), 'metadata': metadata})
        return metadata, payload
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'extract_pvd_error', 'error': str(e)})
        raise RuntimeError('PVD extraction failed') from e

# ---------------- New: DWT (Discrete Wavelet Transform) ----------------
def pad_for_dwt(arr):
    h, w, c = arr.shape
    pad_h = (2 - h % 2) % 2
    pad_w = (2 - w % 2) % 2
    return np.pad(arr, ((0, pad_h), (0, pad_w), (0, 0)), mode='reflect'), pad_h, pad_w

def estimate_capacity_dwt(image_path: str) -> int:
    if not HAVE_PYWT:
        raise RuntimeError('DWT requires pywt')
    img = Image.open(image_path).convert('RGB')
    arr = np.array(img, dtype=np.float32)
    arr_padded, _, _ = pad_for_dwt(arr)
    coeffs = pywt.dwt2(arr_padded[:,:,0], 'haar')
    return np.prod(coeffs[1][0].shape) * 3 * 3  # 3 subbands * 3 channels

def embed_bytes_dwt(image_path: str, out_path: str, data: bytes, alpha=0.01):
    if not HAVE_PYWT:
        raise RuntimeError('DWT embedding requires pywt')
    try:
        bits = bytes_to_bits(data)
        capacity = estimate_capacity_dwt(image_path)
        if len(bits) > capacity:
            raise ValueError(f'Data too large for DWT: {len(bits)} > capacity {capacity}')
        
        img = Image.open(image_path).convert('RGB')
        arr = np.array(img, dtype=np.float32)
        arr_padded, pad_h, pad_w = pad_for_dwt(arr)
        bit_idx = 0
        for c in range(3):
            coeffs = pywt.dwt2(arr_padded[:,:,c], 'haar')
            cA, (cH, cV, cD) = coeffs
            # Embed in detail coefficients
            for subband in [cH, cV, cD]:
                flat = subband.flatten()
                for i in range(len(flat)):
                    if bit_idx >= len(bits):
                        break
                    bit = int(bits[bit_idx])
                    flat[i] += alpha * (2 * bit - 1) * np.abs(flat[i])
                    bit_idx += 1
                subband[:] = flat.reshape(subband.shape)
            recon = pywt.idwt2((cA, (cH, cV, cD)), 'haar')
            arr_padded[:,:,c] = recon
        arr_out = arr_padded[:arr.shape[0], :arr.shape[1], :]
        arr_out = np.clip(arr_out, 0, 255).astype(np.uint8)
        out_img = Image.fromarray(arr_out, 'RGB')
        out_img.save(out_path, 'PNG')
        write_log({'time': now_iso(), 'event': 'embed_dwt', 'image_in': image_path,
                   'image_out': out_path, 'bytes_embedded': len(data), 'bits': len(bits), 'capacity': int(capacity)})
        gc.collect()
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'embed_dwt_error', 'error': str(e)})
        raise RuntimeError('DWT embedding failed') from e

def extract_bytes_dwt(image_path: str):
    if not HAVE_PYWT:
        raise RuntimeError('DWT extraction requires pywt')
    try:
        img = Image.open(image_path).convert('RGB')
        arr = np.array(img, dtype=np.float32)
        arr_padded, _, _ = pad_for_dwt(arr)
        bits = []
        for c in range(3):
            coeffs = pywt.dwt2(arr_padded[:,:,c], 'haar')
            _, (cH, cV, cD) = coeffs
            for subband in [cH, cV, cD]:
                flat = subband.flatten()
                for val in flat:
                    bit = 1 if val > 0 else 0  # Simple threshold
                    bits.append(bit)
        data_bytes = bits_to_bytes(''.join(str(b) for b in bits))
        metadata, payload = parse_package(data_bytes)
        write_log({'time': now_iso(), 'event': 'extract_dwt', 'image': image_path,
                   'bytes_extracted': len(payload), 'metadata': metadata})
        return metadata, payload
    except Exception as e:
        write_log({'time': now_iso(), 'event': 'extract_dwt_error', 'error': str(e)})
        raise RuntimeError('DWT extraction failed') from e

# ---------------- Dispatchers ----------------
ALGORITHMS = {
    'LSB': (embed_bytes_lsb, extract_bytes_lsb),
    'DCT': (embed_bytes_dct_rgb_auto, extract_bytes_dct_rgb_auto),
    'PVD': (embed_bytes_pvd, extract_bytes_pvd),
    'LSB2': (embed_bytes_lsb2, extract_bytes_lsb2),
    'DWT': (embed_bytes_dwt, extract_bytes_dwt),
}

def embed_bytes_into_image(image_path: str, out_path: str, data: bytes, algorithm: str='LSB'):
    alg = algorithm.upper()
    if alg not in ALGORITHMS: raise ValueError(f'Nepoznat algoritam: {algorithm}')
    write_log({'time': now_iso(), 'event': 'embed_dispatch', 'algorithm': alg, 'image_in': image_path})
    return ALGORITHMS[alg][0](image_path, out_path, data)

def extract_bytes_from_image(image_path: str, algorithm: str=None):
    if algorithm:
        alg = algorithm.upper()
        if alg not in ALGORITHMS: raise ValueError(f'Nepoznat algoritam: {algorithm}')
        return ALGORITHMS[alg][1](image_path)
    # try all
    for alg, (_, dec) in ALGORITHMS.items():
        try:
            res = dec(image_path)
            write_log({'time': now_iso(), 'event': 'autodetect_success', 'algorithm': alg})
            return res
        except:
            continue
    raise RuntimeError('No valid stego package found.')

# ---------------- File helpers ----------------
def embed_file(image_path: str, infile: str, out_path: str, algorithm: str='LSB',
               encrypt_password: str=None, metadata_extra: dict=None):
    with open(infile,'rb') as f: payload = f.read()
    metadata = metadata_extra or {}
    metadata.setdefault('original_filename', os.path.basename(infile))
    metadata.setdefault('payload_size', len(payload))
    metadata['stego_algorithm'] = algorithm.upper()
    metadata['crypto'] = 'NONE'
    if encrypt_password:
        salt, iv, ct = encrypt_payload_aes_gcm(payload, encrypt_password)
        metadata['crypto'] = 'AES-GCM'
        metadata['salt'] = base64.b64encode(salt).decode('utf-8')
        metadata['iv'] = base64.b64encode(iv).decode('utf-8')
        payload_to_embed = ct
    else:
        payload_to_embed = payload
    package = build_package(metadata, payload_to_embed)
    embed_bytes_into_image(image_path, out_path, package, algorithm=algorithm)

def extract_to_file(image_path: str, out_dir: str, algorithm_hint: str=None, decrypt_password: str=None):
    metadata, payload = extract_bytes_from_image(image_path, algorithm=algorithm_hint)
    if metadata.get('crypto')=='AES-GCM':
        if not decrypt_password: raise ValueError('Password required for encrypted image')
        salt = base64.b64decode(metadata['salt'])
        iv = base64.b64decode(metadata['iv'])
        payload = decrypt_payload_aes_gcm(payload, decrypt_password, salt, iv)
    os.makedirs(out_dir, exist_ok=True)
    fname = metadata.get('original_filename','extracted.bin')   
    out_path = os.path.join(out_dir, fname)
    with open(out_path,'wb') as f: f.write(payload)
    return metadata, out_path