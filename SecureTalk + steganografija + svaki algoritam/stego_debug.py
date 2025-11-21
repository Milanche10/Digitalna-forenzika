# stego_debug.py
import sys
import json
from PIL import Image
import numpy as np
import binascii

# Proveri SciPy za DCT (opcionalno, ali potrebno za DCT debug)
try:
    from scipy.fftpack import dct, idct
    HAVE_SCIPY = True
except ImportError:
    HAVE_SCIPY = False

# Proveri pywt za DWT
try:
    import pywt
    HAVE_PYWT = True
except ImportError:
    HAVE_PYWT = False

# Helper funkcije iz utils.py i stego.py (kopirane za samostalnost)

def bits_to_bytes(bits_str: str) -> bytes:
    """
    Pretvara string bitova (npr. '101010...') u bajtove.
    Ako broj bitova nije višestruki od 8, dopunjuje nulama.
    """
    b = bytearray()
    rem = len(bits_str) % 8
    if rem != 0:
        bits_str += '0' * (8 - rem)
    for i in range(0, len(bits_str), 8):
        byte = int(bits_str[i:i+8], 2)
        b.append(byte)
    return bytes(b)

# MAGIC i VERSION iz stego.py
MAGIC = b'STG0'  # 4 bajta magic headera
VERSION = b'\x01'  # 1 bajt verzije

def parse_package(data: bytes):
    """
    Parsuje stego paket: MAGIC + VERSION + meta_len (4 bajta) + metadata (JSON) + payload_len (8 bajta) + payload.
    Baca grešku ako struktura nije validna.
    """
    try:
        if len(data) < 13 or data[0:4] != MAGIC:
            raise ValueError('Ne postoji magic header (nije STG paket)')
        meta_len = int.from_bytes(data[5:9], 'big')
        meta_start = 9
        meta_end = meta_start + meta_len
        if meta_end > len(data):
            raise ValueError('Nedovoljno bajtova za metadata')
        meta_json = data[meta_start:meta_end]
        metadata = json.loads(meta_json.decode('utf-8'))
        payload_len = int.from_bytes(data[meta_end:meta_end+8], 'big')
        payload_start = meta_end + 8
        payload_end = payload_start + payload_len
        if payload_end > len(data):
            raise ValueError('Nedovoljno bajtova za payload')
        payload = data[payload_start:payload_end]
        return metadata, payload
    except Exception as e:
        print(f"Parse error details: {str(e)}")  # Dodat detaljan print za debug
        raise

# PVD range helper iz stego.py
def _get_pvd_range(diff):
    """
    Vraća lower, upper i broj bitova (nbits) za datu diff u PVD.
    """
    if diff <= 1: return 0, 0, 0
    elif diff <= 3: return 2, 3, 1
    elif diff <= 7: return 4, 7, 2
    elif diff <= 15: return 8, 15, 3
    elif diff <= 31: return 16, 31, 4
    elif diff <= 63: return 32, 63, 5
    elif diff <= 127: return 64, 127, 6
    else: return 128, 255, 7

def hexdump(b, n=64):
    """
    Vraća hex reprezentaciju prvih n bajtova.
    """
    return ' '.join(f"{x:02x}" for x in b[:n])

# Padding helper za DCT iz stego.py
def _pad_image_edge_reflect(arr):
    """
    Padding slike do višestrukog od 8, koristeći reflect mode.
    """
    h, w, c = arr.shape
    pad_h, pad_w = (8 - h % 8) % 8, (8 - w % 8) % 8
    return np.pad(arr, ((0, pad_h), (0, pad_w), (0, 0)), mode='reflect')

# DCT helper
def _dct2(block):
    """
    2D DCT transformacija bloka.
    """
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

# Debug funkcija za LSB
def debug_lsb(path):
    """
    Debug za LSB: Ekstrahuje raw bitove iz LSB RGB kanala, konvertuje u bajtove,
    traži MAGIC, i pokušava parsovanje.
    """
    try:
        img = Image.open(path).convert('RGBA')
        pixels = list(img.getdata())
        channels = [ch for pix in pixels for ch in pix[:3]]  # RGB kanali
        bits = [ch & 1 for ch in channels]  # LSB bitovi
        bits_count = len(bits)
        bits_str = ''.join(str(b) for b in bits)
        data = bits_to_bytes(bits_str)
        print("LSB extracted bits:", bits_count, "bytes:", bits_count // 8)
        print("LSB first 64 bytes:", hexdump(data, 64))
        magic_offsets = [i for i in range(len(data) - len(MAGIC) + 1) if data[i:i+len(MAGIC)] == MAGIC]
        print("MAGIC offsets in LSB-stream:", magic_offsets)
        for idx in magic_offsets:
            try:
                md, payload = parse_package(data[idx:])
                print(f"Parsed package from LSB at offset {idx}")
                print("Metadata:", md)
                print("Payload length:", len(payload))
                print("Payload first 32 bytes (hex):", hexdump(payload, 32))  # Dodat detalj
            except Exception as e:
                print(f"Parse failed at offset {idx}: {e}")
    except Exception as e:
        print("LSB debug failed:", e)

# Debug za LSB2 (novi)
def debug_lsb2(path):
    try:
        img = Image.open(path).convert('RGBA')
        pixels = list(img.getdata())
        channels = [ch for pix in pixels for ch in pix[:3]]
        bits = []
        for ch in channels:
            bits.extend(f'{ch & 3:02b}')
        bits_count = len(bits)
        bits_str = ''.join(bits)
        data = bits_to_bytes(bits_str)
        print("LSB2 extracted bits:", bits_count, "bytes:", bits_count // 8)
        print("LSB2 first 64 bytes:", hexdump(data, 64))
        magic_offsets = [i for i in range(len(data) - len(MAGIC) + 1) if data[i:i+len(MAGIC)] == MAGIC]
        print("MAGIC offsets in LSB2-stream:", magic_offsets)
        for idx in magic_offsets:
            try:
                md, payload = parse_package(data[idx:])
                print(f"Parsed package from LSB2 at offset {idx}")
                print("Metadata:", md)
                print("Payload length:", len(payload))
                print("Payload first 32 bytes (hex):", hexdump(payload, 32))
            except Exception as e:
                print(f"Parse failed at offset {idx}: {e}")
    except Exception as e:
        print("LSB2 debug failed:", e)

# Kompletna debug funkcija za DCT
def debug_dct(path):
    """
    Debug za DCT: Ekstrahuje bitove iz DCT koeficijenata (znak >0 ili <0),
    konvertuje u bajtove, traži MAGIC, i pokušava parsovanje.
    """
    if not HAVE_SCIPY:
        print("DCT debug skipped (SciPy not installed or import failed)")
        return
    try:
        img = Image.open(path).convert('RGB')
        arr = np.array(img, dtype=np.float32)
        arr_padded = _pad_image_edge_reflect(arr)
        H, W, C = arr_padded.shape
        mask_positions = [(u, v) for u in range(8) for v in range(8) if 2 <= u + v <= 5]  # Srednje frekvencije
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
        bits_count = len(bits)
        bits_str = ''.join(str(b) for b in bits)
        data = bits_to_bytes(bits_str)
        print("DCT extracted bits:", bits_count, "bytes:", bits_count // 8)
        print("DCT first 64 bytes:", hexdump(data, 64))
        magic_offsets = [i for i in range(len(data) - len(MAGIC) + 1) if data[i:i+len(MAGIC)] == MAGIC]
        print("MAGIC offsets in DCT-stream:", magic_offsets)
        for idx in magic_offsets:
            try:
                md, payload = parse_package(data[idx:])
                print(f"Parsed package from DCT at offset {idx}")
                print("Metadata:", md)
                print("Payload length:", len(payload))
                print("Payload first 32 bytes (hex):", hexdump(payload, 32))  # Dodat detalj
            except Exception as e:
                print(f"Parse failed at offset {idx}: {e}")
    except Exception as e:
        print("DCT debug failed:", e)

# Debug funkcija za PVD
def debug_pvd(path):
    """
    Debug za PVD: Ekstrahuje varijabilne bitove iz razlika susednih piksela,
    konvertuje u bajtove, traži MAGIC, i pokušava parsovanje.
    """
    try:
        img = Image.open(path).convert('RGB')
        pixels = list(img.getdata())
        bits = []
        for i in range(0, len(pixels) - 1, 2):
            p1, p2 = pixels[i], pixels[i + 1]
            for c in range(3):
                diff = abs(p1[c] - p2[c])
                lower, _, nbits = _get_pvd_range(diff)
                if nbits == 0:
                    continue
                k = diff - lower
                bits.extend(list(f'{k:0{nbits}b}'))
        bits_count = len(bits)
        bits_str = ''.join(bits)
        data = bits_to_bytes(bits_str)
        print("PVD extracted bits:", bits_count, "bytes:", bits_count // 8)
        print("PVD first 64 bytes:", hexdump(data, 64))
        magic_offsets = [i for i in range(len(data) - len(MAGIC) + 1) if data[i:i+len(MAGIC)] == MAGIC]
        print("MAGIC offsets in PVD-stream:", magic_offsets)
        for idx in magic_offsets:
            try:
                md, payload = parse_package(data[idx:])
                print(f"Parsed package from PVD at offset {idx}")
                print("Metadata:", md)
                print("Payload length:", len(payload))
                print("Payload first 32 bytes (hex):", hexdump(payload, 32))  # Dodat detalj
            except Exception as e:
                print(f"Parse failed at offset {idx}: {e}")
    except Exception as e:
        print("PVD debug failed:", e)

# Debug za DWT (novi)
def debug_dwt(path):
    if not HAVE_PYWT:
        print("DWT debug skipped (pywt not installed or import failed)")
        return
    try:
        img = Image.open(path).convert('RGB')
        arr = np.array(img, dtype=np.float32)
        bits = []
        for c in range(3):
            coeffs = pywt.dwt2(arr[:,:,c], 'haar')
            _, (cH, cV, cD) = coeffs
            for subband in [cH, cV, cD]:
                flat = subband.flatten()
                for val in flat:
                    bit = 1 if val > 0 else 0
                    bits.append(bit)
        bits_count = len(bits)
        bits_str = ''.join(str(b) for b in bits)
        data = bits_to_bytes(bits_str)
        print("DWT extracted bits:", bits_count, "bytes:", bits_count // 8)
        print("DWT first 64 bytes:", hexdump(data, 64))
        magic_offsets = [i for i in range(len(data) - len(MAGIC) + 1) if data[i:i+len(MAGIC)] == MAGIC]
        print("MAGIC offsets in DWT-stream:", magic_offsets)
        for idx in magic_offsets:
            try:
                md, payload = parse_package(data[idx:])
                print(f"Parsed package from DWT at offset {idx}")
                print("Metadata:", md)
                print("Payload length:", len(payload))
                print("Payload first 32 bytes (hex):", hexdump(payload, 32))
            except Exception as e:
                print(f"Parse failed at offset {idx}: {e}")
    except Exception as e:
        print("DWT debug failed:", e)

def main():
    """
    Glavna funkcija: Čita putanju do slike iz argumenata, i pokreće debug za svaki algoritam.
    """
    if len(sys.argv) < 2:
        print("Usage: python stego_debug.py path/to/stego.png")
        print("Primer: python stego_debug.py stego_pvd.png")
        return
    path = sys.argv[1]
    print("DEBUG za sliku:", path)
    print("\n--- LSB pokušaj ---")
    debug_lsb(path)
    print("\n--- LSB2 pokušaj ---")
    debug_lsb2(path)
    print("\n--- DCT pokušaj ---")
    debug_dct(path)
    print("\n--- PVD pokušaj ---")
    debug_pvd(path)
    print("\n--- DWT pokušaj ---")
    debug_dwt(path)
    print("\nDebug završen. Proveri output za greške u parsovanju da vidiš korupciju podataka.")

if __name__ == "__main__":
    main()