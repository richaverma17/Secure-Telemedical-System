# doctor.py
import socket
import threading
import time
from crypto_utils import *

ID_GWN = "Doctor"
PORT = 5000
DELTA_TS = 5

public_keys = {}
patients = {}
session_keys = {}

def init_doctor():
    """Set up the doctor's keys."""
    global public_key, private_key
    public_key, private_key = generate_key_pair_timed()
    public_keys[ID_GWN] = public_key
    print(f"Doctor ready with public key: {public_key}")

def elgamal_decrypt(private_key, ciphertext, p):
    """Decrypt an ElGamal ciphertext."""
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p

def handle_patient(conn, addr):
    """Handle a patient connection."""
    patient_id = receive_message(conn)
    public_keys[patient_id] = receive_message(conn)
    send_message(conn, public_key)
    print(f"Doctor connected to {patient_id} at {addr}")

    while True:
        try:
            message = receive_message(conn)
            if message[0] == 10:
                if len(message) == 5:  # Auth request
                    ts_i, rn_i, id_gwn, encrypted_key = message[1:]
                    ts_i_star = time.time()
                    if abs(ts_i_star - ts_i) > DELTA_TS:
                        print(f"Timestamp too old from {patient_id}")
                        continue
                    k_d1_gwn = elgamal_decrypt(private_key, encrypted_key, P)
                    print(f"Doctor received auth from {patient_id}: TS={ts_i}, RN={rn_i}, Session Key={k_d1_gwn}")
                    patients[patient_id] = {"ts_i": ts_i, "rn_i": rn_i, "k_d1_gwn": k_d1_gwn, "conn": conn}

                    ts_gwn = time.time()
                    rn_gwn = random.randint(1, 1000)
                    encrypted_key_response = elgamal_encrypt(public_keys[patient_id], k_d1_gwn)
                    response = [20, ts_gwn, rn_gwn, patient_id, encrypted_key_response]
                    send_message(conn, response)
                    print(f"Doctor sent response to {patient_id}: TS={ts_gwn}, RN={rn_gwn}")
                elif len(message) == 3:  # Verifier
                    skv_d1_gwn, ts_i_prime = message[1:]
                    ts_i_star_prime = time.time()
                    if abs(ts_i_star_prime - ts_i_prime) > DELTA_TS:
                        print(f"Verifier timestamp too old from {patient_id}")
                        continue
                    patient = patients[patient_id]
                    sk_gwn_d1 = hash_data_timed(f"{patient['k_d1_gwn']}{patient['ts_i']}{ts_gwn}{patient['rn_i']}{rn_gwn}{patient_id}{ID_GWN}")
                    skv_gwn_d1 = hash_data(f"{sk_gwn_d1}{ts_i_prime}")
                    if skv_gwn_d1 == skv_d1_gwn:
                        session_keys[patient_id] = sk_gwn_d1
                        print(f"Doctor verified session key with {patient_id}: {sk_gwn_d1[:10]}...")
        except:
            break

    conn.close()
    print(f"Disconnected from {patient_id}")

def broadcast_message():
    """Broadcast a message to all patients."""
    group_key = hash_data("".join(session_keys.values()) + str(private_key))
    for patient_id, sk in session_keys.items():
        encrypted_gk = [30, aes_encrypt(sk, group_key)]  # Opcode 30: GROUP_KEY
        send_message(patients[patient_id]["conn"], encrypted_gk)
        print(f"Doctor sent group key to {patient_id}")
    msg = "Doctor unavailable from 10-11 AM"
    encrypted_msg = [40, aes_encrypt(group_key, msg)]  # Opcode 40: ENC_MSG
    for patient_id in session_keys:
        send_message(patients[patient_id]["conn"], encrypted_msg)
    print(f"Doctor broadcasted: {msg}")

def start_server():
    """Start the server to listen for patients."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', PORT))
    server.listen(5)
    print(f"Doctor listening on port {PORT}")
    
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_patient, args=(conn, addr)).start()

if __name__ == "__main__":
    init_doctor()
    threading.Thread(target=start_server).start()
    time.sleep(5)  # Wait for patients to connect
    broadcast_message()