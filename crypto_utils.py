# crypto_utils.py
import random
import hashlib
import time
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

P = 23
G = 5

def generate_key_pair():
    private_key = random.randint(1, P - 2)
    public_key = pow(G, private_key, P)
    return (P, G, public_key), private_key

def elgamal_encrypt(public_key, message):
    p, g, y = public_key
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(private_key, ciphertext, p):
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p

def hash_data(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

def aes_encrypt(key, plaintext):
    """Encrypt text with AES-256, key can be string or bytes."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    iv = b'16bytesiv1234567'
    # Ensure key is bytes
    key_bytes = key.encode() if isinstance(key, str) else key
    cipher = Cipher(algorithms.AES(key_bytes[:32]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(key, ciphertext):
    """Decrypt AES-256 text, key can be string or bytes."""
    iv = ciphertext[:16]
    # Ensure key is bytes
    key_bytes = key.encode() if isinstance(key, str) else key
    cipher = Cipher(algorithms.AES(key_bytes[:32]), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def serialize(data):
    return json.dumps(data, default=str).encode()

def deserialize(data):
    return json.loads(data.decode())

def send_message(conn, data, is_bytes=False):
    if is_bytes:
        length = len(data)
        conn.send(length.to_bytes(4, 'big'))
        conn.send(data)
    else:
        encoded = serialize(data)
        length = len(encoded)
        conn.send(length.to_bytes(4, 'big'))
        conn.send(encoded)

def receive_message(conn, expect_bytes=False):
    length = int.from_bytes(conn.recv(4), 'big')
    data = conn.recv(length)
    if expect_bytes:
        return data
    return deserialize(data)

perf_times = {}
def measure_time(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        perf_times[func.__name__] = end - start
        return result
    return wrapper

@measure_time
def generate_key_pair_timed():
    return generate_key_pair()

@measure_time
def hash_data_timed(*args):
    return hash_data(*args)
