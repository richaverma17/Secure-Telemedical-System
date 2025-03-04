import socket
import json
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime
from Crypto.Random.random import randint

# ------------------ Key Generation ------------------

def generate_keypair(bits=512):
    """Generate ElGamal key pair (private and public keys)."""
    p = getPrime(bits)
    g = randint(2, p - 1)
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return {"public": (p, g, y), "private": x}

patient_keys = generate_keypair()
print("[CLIENT] Patient's Public Key:", patient_keys["public"])

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

# ------------------ Client Function ------------------

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9999))
    print("[CLIENT] Connected to Doctor (Server).")

    # Generate session key
    session_key = randint(2, patient_keys["public"][0] - 1)

    # Encrypt session key using doctor's public key
    doctor_public_key = (141619356738121, 2, 2938457389271)  # Replace with actual doctor public key
    encrypted_session_key = elgamal_encrypt(session_key, doctor_public_key)

    # Sign authentication request
    signature = sign_message(str(session_key), patient_keys["private"], patient_keys["public"][0])

    # Send authentication request
    auth_request = {
        "TS": 123456789,
        "EncryptedKey": encrypted_session_key,
        "Signature": signature,
        "PublicKey": patient_keys["public"]
    }
    client.send(json.dumps(auth_request).encode())

    # Receive and process server response
    data = client.recv(4096).decode()
    doctor_response = json.loads(data)
    print("[CLIENT] Received response:", doctor_response)

    # Decrypt session key
    decrypted_key = elgamal_decrypt(doctor_response["EncryptedKey"], patient_keys["private"], patient_keys["public"])
    print("[CLIENT] Decrypted session key:", decrypted_key)

    # Verify doctor's signature
    is_valid_signature = verify_signature(str(decrypted_key), doctor_response["Signature"], doctor_public_key)
    print("[CLIENT] Doctor's signature valid:", is_valid_signature)

    client.close()


def main():
    start_client()

if __name__ == "__main__":
    main()
