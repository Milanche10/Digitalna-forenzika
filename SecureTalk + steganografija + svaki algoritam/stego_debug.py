# stego_debug.py
import sys
from stego import MAGIC, extract_bytes_lsb, extract_bytes_dct, parse_package, now_iso
from stego import embed_bytes_lsb, embed_bytes_dct
from utils import bits_to_bytes, bytes_to_int
from PIL import Image
import binascii

def hexdump(b, n=64):
    return ' '.join(f"{x:02x}" for x in b[:n])

def debug_lsb(path):
    data, bits = extract_bytes_lsb(path)
    print("LSB capacity bits:", bits, "bytes:", bits//8)
    print("LSB first 64 bytes:", hexdump(data, 64))
    idx = data.find(MAGIC)
    print("MAGIC offsets in LSB-stream:", [i for i in range(len(data)) if data.startswith(MAGIC, i)])
    if idx != -1:
        try:
            md, payload = parse_package(data[idx:])
            print("Parsed package from LSB at offset", idx)
            print("Metadata:", md)
            print("Payload length:", len(payload))
        except Exception as e:
            print("Parse failed:", e)

def debug_dct(path):
    try:
        data_dct, bits = extract_bytes_dct(path)
        print("DCT extracted bits:", bits, "bytes:", bits//8)
        print("DCT first 64 bytes:", hexdump(data_dct, 64))
        idx = data_dct.find(MAGIC)
        print("MAGIC offsets in DCT-stream:", [i for i in range(len(data_dct)) if data_dct.startswith(MAGIC, i)])
        if idx != -1:
            try:
                md, payload = parse_package(data_dct[idx:])
                print("Parsed package from DCT at offset", idx)
                print("Metadata:", md)
                print("Payload length:", len(payload))
            except Exception as e:
                print("Parse failed:", e)
    except Exception as e:
        print("DCT debug skipped (missing libs?)", e)

def main():
    if len(sys.argv) < 2:
        print("Usage: python stego_debug.py path/to/stego.png")
        return
    path = sys.argv[1]
    print("DEBUG:", path)
    debug_lsb(path)
    print("--- DCT attempt ---")
    debug_dct(path)

if __name__ == "__main__":
    main()
