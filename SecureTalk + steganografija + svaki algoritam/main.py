# main.py
import argparse
from server import run_server
from client import run_gui
from stego import embed_file, extract_to_file, build_package, embed_bytes_into_image
from crypto_utils import encrypt_payload_aes_gcm, decrypt_payload_aes_gcm
import base64
import os

def cmd_embed(args):
    if args.password:
        with open(args.infile, 'rb') as f:
            payload = f.read()
        salt, iv, ct = encrypt_payload_aes_gcm(payload, args.password)
        metadata = {
            'sender_id': args.sender or 'cli',
            'stego_algorithm': 'LSB',
            'crypto': 'AES-GCM',
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'original_filename': os.path.basename(args.infile),
            'payload_size': len(ct)
        }
        package = build_package(metadata, ct)
        embed_bytes_into_image(args.image, args.out, package, algorithm='LSB')
    else:
        embed_file(args.image, args.infile, args.out, algorithm='LSB')
    print("[OK] Embed complete")

def cmd_extract(args):
    metadata, out_path = extract_to_file(args.image, args.out, algorithm_hint=args.algorithm, decrypt_password=args.password)
    print("Metadata:", metadata)
    print("Extracted to:", out_path)

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()

    p = sub.add_parser('embed')
    p.add_argument('--image', required=True)
    p.add_argument('--infile', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--password', required=False)
    p.add_argument('--sender', required=False)
    p.set_defaults(func=cmd_embed)

    p2 = sub.add_parser('extract')
    p2.add_argument('--image', required=True)
    p2.add_argument('--out', required=True)
    p2.add_argument('--algorithm', required=False, help='Optional algorithm hint (LSB/DCT/PVD)')
    p2.add_argument('--password', required=False)
    p2.set_defaults(func=cmd_extract)

    p3 = sub.add_parser('server')
    p3.add_argument('--port', type=int, default=8765)
    p3.set_defaults(func=lambda args: run_server(args.port))

    p4 = sub.add_parser('gui')
    p4.add_argument('--username', required=True)
    p4.add_argument('--host', default='127.0.0.1')
    p4.add_argument('--port', type=int, default=8765)
    p4.set_defaults(func=lambda args: run_gui(args.username, args.host, args.port))

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
