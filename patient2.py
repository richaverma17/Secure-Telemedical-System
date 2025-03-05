# patient_2.py
import socket
import time
from crypto_utils import *

ID_D1 = "2"
ID_GWN = "Doctor"
HOST = 'localhost'
PORT = 5000
DELTA_TS = 5

public_keys = {}
session_key = None
group_key = None

def init_patient():
    global public_key, private_key, conn
    public_key, private_key = generate_key_pair_timed()
    public_keys[ID_D1] = public_key
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))
    send_message(conn, ID_D1)
    send_message(conn, public_key)
    public_keys[ID_GWN] = receive_message(conn)
    print(f"Patient 2 ready with public key: {public_key}")
    print(f"Received Doctor’s public key: {public_keys[ID_GWN]}")

def send_auth_request():
    global ts_i, rn_i, k_d1_gwn
    ts_i = time.time()
    rn_i = random.randint(1, 1000)
    k_d1_gwn = random.randint(10, 20)
    encrypted_key = elgamal_encrypt(public_keys[ID_GWN], k_d1_gwn)
    request = [10, ts_i, rn_i, ID_GWN, encrypted_key]
    send_message(conn, request)
    print(f"Patient 2 sent auth request: TS={ts_i}, RN={rn_i}, Encrypted Key={encrypted_key}")

def receive_auth_response(response):
    global session_key, ts_gwn, rn_gwn
    opcode, ts_gwn, rn_gwn, id_d1, encrypted_key = response
    ts_gwn_star = time.time()
    if abs(ts_gwn_star - ts_gwn) > DELTA_TS:
        print("Patient 2 discarded response: Timestamp too old")
        return
    k_d1_gwn_dec = elgamal_decrypt(private_key, encrypted_key, P)
    print(f"Patient 2 received response: TS={ts_gwn}, RN={rn_gwn}, Decrypted Session Key={k_d1_gwn_dec}")
    session_key = hash_data_timed(f"{k_d1_gwn_dec}{ts_i}{ts_gwn}{rn_i}{rn_gwn}{ID_D1}{ID_GWN}")
    print(f"Patient 2 computed session key: {session_key[:10]}...")
    send_session_verifier()

def send_session_verifier():
    ts_i_prime = time.time()
    skv = hash_data(f"{session_key}{ts_i_prime}")
    verifier = [10, skv, ts_i_prime]
    send_message(conn, verifier)
    print(f"Patient 2 sent verifier: TS={ts_i_prime}, SKV={skv[:10]}...")

def receive_group_key(encrypted_gk):
    global group_key
    group_key = aes_decrypt(session_key, encrypted_gk)
    print(f"Patient 2 received group key: {group_key[:10]}...")

def receive_broadcast(encrypted_msg):
    msg = aes_decrypt(group_key, encrypted_msg)
    print(f"Patient 2 received broadcast: {msg.decode()}")

def start_patient():
    init_patient()
    send_auth_request()
    while True:
        try:
            message = receive_message(conn)
            if message[0] == "DISCARD":
                print(f"Patient 2 discarded message: {message[1]}")
                break
            opcode = message[0]
            if opcode == 20:
                receive_auth_response(message)
            elif opcode == 30:
                encrypted_gk = receive_message(conn, expect_bytes=True)
                receive_group_key(encrypted_gk)
            elif opcode == 40:
                encrypted_msg = receive_message(conn, expect_bytes=True)
                receive_broadcast(encrypted_msg)
                break
        except Exception as e:
            print(f"Patient 2 error: {e}")
            break
    conn.close()

if __name__ == "__main__":
    start_patient()