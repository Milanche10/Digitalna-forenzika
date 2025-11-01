# main.py
import argparse
from stego import embed_file, extract_to_file, build_package
from crypto_utils import encrypt_payload_aes_gcm, decrypt_payload_aes_gcm
import json
import os
from chat import start_server, send_image
from utils import write_log, now_iso
import base64

def cmd_embed(args):
    metadata = {
        'sender_id': args.sender or 'unknown',
        'stego_algorithm': 'LSB',
        'crypto': 'NONE'
    }
    if args.password:
        # read payload bytes
        with open(args.infile, 'rb') as f:
            payload = f.read()
        salt, iv, ct = encrypt_payload_aes_gcm(payload, args.password)
        # build metadata and embed ciphertext as payload
        metadata['crypto'] = 'AES-GCM'
        metadata['salt'] = base64.b64encode(salt).decode('utf-8')
        metadata['iv'] = base64.b64encode(iv).decode('utf-8')
        metadata['original_filename'] = os.path.basename(args.infile)
        metadata['payload_size'] = len(ct)
        package = build_package(metadata, ct)
        # embed raw package bytes
        from stego import embed_bytes_into_image
        embed_bytes_into_image(args.image, args.out, package)
    else:
        metadata['original_filename'] = os.path.basename(args.infile)
        metadata['payload_size'] = os.path.getsize(args.infile)
        embed_file(args.image, args.infile, args.out, metadata)
    print('Embed complete')

def cmd_extract(args):
    metadata, out_path = extract_to_file(args.image, args.out)
    print('Metadata:', metadata)
    if metadata.get('crypto') == 'AES-GCM':
        pw = args.password or input('Unesi lozinku za dekriptovanje: ')
        # read ciphertext from extracted file
        with open(out_path, 'rb') as f:
            ciphertext = f.read()
        salt = base64.b64decode(metadata['salt'])
        iv = base64.b64decode(metadata['iv'])
        try:
            pt = decrypt_payload_aes_gcm(ciphertext, pw, salt, iv)
            real_name = metadata.get('original_filename', 'extracted')
            final_path = os.path.join(args.out, real_name)
            with open(final_path, 'wb') as f:
                f.write(pt)
            os.remove(out_path)
            print('Decrypted saved to', final_path)
        except Exception as e:
            print('Decryption failed:', e)
    else:
        print('Extracted saved to', out_path)

def cmd_server(args):
    start_server(host=args.host, port=args.port, save_dir=args.save_dir)

def cmd_send(args):
    meta = {
        'sender_id': args.sender,
        'filename': os.path.basename(args.image)
    }
    resp = send_image(args.host, args.port, args.image, meta)
    print('Server response:', resp)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()

    p = sub.add_parser('embed')
    p.add_argument('--image', required=True, help='Path to cover image (PNG/BMP)')
    p.add_argument('--infile', required=True, help='File to hide')
    p.add_argument('--out', required=True, help='Output stego image path')
    p.add_argument('--password', required=False, help='Optional password for AES-GCM encryption')
    p.add_argument('--sender', required=False, help='Sender id')
    p.set_defaults(func=cmd_embed)

    p2 = sub.add_parser('extract')
    p2.add_argument('--image', required=True, help='Stego image to extract from')
    p2.add_argument('--out', required=True, help='Output directory to store extracted file')
    p2.add_argument('--password', required=False, help='Password if message encrypted')
    p2.set_defaults(func=cmd_extract)

    p3 = sub.add_parser('server')
    p3.add_argument('--host', default='0.0.0.0')
    p3.add_argument('--port', type=int, default=9000)
    p3.add_argument('--save_dir', default='output/received')
    p3.set_defaults(func=cmd_server)

    p4 = sub.add_parser('send')
    p4.add_argument('--host', required=True)
    p4.add_argument('--port', type=int, required=True)
    p4.add_argument('--image', required=True)
    p4.add_argument('--sender', default='cli-user')
    p4.set_defaults(func=cmd_send)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
