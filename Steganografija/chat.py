# chat.py
import socket
import json
import struct
import os
from pathlib import Path
from utils import write_log, now_iso

def start_server(host: str = '0.0.0.0', port: int = 9000, save_dir: str = 'output/received'):
    save_dir = Path(save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f'Server sluša na {host}:{port}...')
    try:
        while True:
            conn, addr = s.accept()
            print('Povezan:', addr)
            handle_conn(conn, addr, save_dir)
    finally:
        s.close()

def handle_conn(conn, addr, save_dir: Path):
    try:
        raw = conn.recv(8)
        if len(raw) < 8:
            print('Greška pri prijemu meta-len')
            return
        meta_len = struct.unpack('>Q', raw)[0]
        meta = b''
        while len(meta) < meta_len:
            chunk = conn.recv(min(4096, meta_len - len(meta)))
            if not chunk:
                break
            meta += chunk
        metadata = json.loads(meta.decode('utf-8'))

        raw = conn.recv(8)
        img_len = struct.unpack('>Q', raw)[0]
        img = b''
        while len(img) < img_len:
            chunk = conn.recv(min(8192, img_len - len(img)))
            if not chunk:
                break
            img += chunk

        fname = metadata.get('filename', f'stego_{now_iso()}.png')
        path = save_dir / fname
        with open(path, 'wb') as f:
            f.write(img)

        write_log({'time': now_iso(), 'event': 'received_image', 'from': addr[0], 'save_path': str(path), 'metadata': metadata})
        print('Sačuvano:', path)
        conn.sendall(b'OK')
    except Exception as e:
        print('Greška:', e)
    finally:
        conn.close()

def send_image(host: str, port: int, image_path: str, metadata: dict):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    with open(image_path, 'rb') as f:
        img = f.read()
    meta_bytes = json.dumps(metadata).encode('utf-8')
    s.sendall(struct.pack('>Q', len(meta_bytes)))
    s.sendall(meta_bytes)
    s.sendall(struct.pack('>Q', len(img)))
    s.sendall(img)
    resp = s.recv(16)
    s.close()
    return resp
