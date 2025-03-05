# crypto_utils.py
import random
import hashlib
import time
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# For ElGamal: a small prime and generator (simple for learning)
P = 23  # A small prime number
G = 5   # A generator that works with P

def generate_key_pair():
    """Make a public and private key for ElGamal."""
    private_key = random.randint(1, P - 2)  # Random number between 1 and 21
    public_key = pow(G, private_key, P)     # G^private_key mod P
    return (P, G, public_key), private_key  # Return both keys

def elgamal_encrypt(public_key, message):
    """Encrypt a number using ElGamal."""
    p, g, y = public_key  # Unpack public key
    k = random.randint(1, p - 2)  # Random temporary key
    c1 = pow(g, k, p)       # c1 = g^k mod p
    c2 = (message * pow(y, k, p)) % p  # c2 = message * y^k mod p
    return (c1, c2)         # Return encrypted pair

def elgamal_decrypt(private_key, ciphertext, p):
    """Decrypt an ElGamal ciphertext."""
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p

def hash_data(data):
    """Create a hash (fingerprint) of any data."""
    return hashlib.sha256(str(data).encode()).hexdigest()

def aes_encrypt(key, plaintext):
    """Encrypt text with AES-256."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    iv = b'16bytesiv1234567'  # 16 bytes for AES-CBC
    cipher = Cipher(algorithms.AES(key.encode()[:32]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(key, ciphertext):
    """Decrypt AES-256 text."""
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key.encode()[:32]), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# For sending data over sockets
def serialize(data):
    """Turn data into a string we can send."""
    return json.dumps(data, default=str).encode()

def deserialize(data):
    """Turn received string back into data."""
    return json.loads(data.decode())

def send_message(conn, data):
    """Send a message with its length first."""
    encoded = serialize(data)
    length = len(encoded)
    conn.send(length.to_bytes(4, 'big'))  # Send length as 4 bytes
    conn.send(encoded)  # Send the actual data

def receive_message(conn):
    """Receive a message by reading its length first."""
    length = int.from_bytes(conn.recv(4), 'big')  # Get length
    data = conn.recv(length)  # Get exactly that much data
    return deserialize(data)

# To measure how long things take
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

# Test it
if __name__ == "__main__":
    pub, priv = generate_key_pair_timed()
    print(f"Public Key: {pub}, Private Key: {priv}")
    hashed = hash_data_timed("Hello")
    print(f"Hash of 'Hello': {hashed}")
    print(f"Performance times: {perf_times}")