import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key_from_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)

def encrypt_payload_aes_gcm(payload: bytes, password: str):
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, payload, None)
    return salt, iv, ct

def decrypt_payload_aes_gcm(ciphertext: bytes, password: str, salt: bytes, iv: bytes) -> bytes:
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(iv, ciphertext, None)
    return pt
