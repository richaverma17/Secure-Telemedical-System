import socket
import json
from Crypto.Util.number import getPrime
from Crypto.Hash import SHA256
from Crypto.Random.random import randint

# ------------------ Key Generation ------------------

def generate_keypair(bits=512):
    """Generate ElGamal key pair (private and public keys)."""
    p = getPrime(bits)
    g = randint(2, p - 1)
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return {"public": (p, g, y), "private": x}

doctor_keys = generate_keypair()
print("[SERVER] Doctor's Public Key:", doctor_keys["public"])

# ------------------ Encryption & Decryption ------------------

def elgamal_encrypt(message, pub_key):
    """Encrypt a message using ElGamal."""
    p, g, y = pub_key
    k = randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(ciphertext, priv_key, pub_key):
    """Decrypt ElGamal ciphertext."""
    p, g, y = pub_key
    c1, c2 = ciphertext
    s = pow(c1, priv_key, p)
    s_inv = pow(s, p - 2, p)  # Modular inverse
    message = (c2 * s_inv) % p
    return message

def sign_message(message, private_key, p):
    """Sign a message using SHA256 and ElGamal."""
    h = SHA256.new(message.encode())
    signature = pow(int.from_bytes(h.digest(), "big"), private_key, p)
    return signature

def verify_signature(message, signature, pub_key):
    """Verify signature using SHA256 and ElGamal."""
    p, g, y = pub_key
    h = SHA256.new(message.encode())
    h_int = int.from_bytes(h.digest(), "big")
    return pow(signature, g, p) == h_int

# ------------------ Server Function ------------------

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 9999))
    server.listen(5)
    print("[SERVER] Listening for patient connections...")

    while True:
        client, addr = server.accept()
        print(f"[SERVER] Connected to {addr}")

        # Receive authentication request
        data = client.recv(4096).decode()
        auth_request = json.loads(data)
        print("[SERVER] Received authentication request:", auth_request)

        # Decrypt session key
        decrypted_key = elgamal_decrypt(auth_request["EncryptedKey"], doctor_keys["private"], doctor_keys["public"])
        print("[SERVER] Decrypted session key:", decrypted_key)

        # Sign and send response
        response = {
            "TS": 987654321,
            "EncryptedKey": elgamal_encrypt(decrypted_key, auth_request["PublicKey"]),
            "Signature": sign_message(str(decrypted_key), doctor_keys["private"], doctor_keys["public"][0])
        }
        client.send(json.dumps(response).encode())

        client.close()
        print("[SERVER] Response sent and connection closed.")

def main():
    start_server()

if __name__ == "__main__":
    main()

