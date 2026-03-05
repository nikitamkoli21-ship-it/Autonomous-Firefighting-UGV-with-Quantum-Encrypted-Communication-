# laptop.py
import socket, threading, struct, hashlib, random, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

HOST = '127.0.0.1'  # change to your PC IP if simulating across Wi-Fi
PORT = 50000

def recvall(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def bb84_receiver(conn):
    """
    Simulated BB84 receiver side. Protocol (over same socket):
    1) Receive N from sender, then receive N bits and N bases (as bytes).
    2) Choose random measuring bases, compute measured bits (if base matches, same; else random).
    3) Send your chosen bases back.
    4) Sender will reply which bases matched; both sift to create raw key.
    5) They reveal a small sample for error check and then hash to produce final key.
    """
    # 1. receive N
    data = recvall(conn, 4)
    if data is None:
        return None
    N = struct.unpack('!I', data)[0]
    # receive bits and bases
    bits = recvall(conn, N)
    bases = recvall(conn, N)
    bits = list(bits)
    bases = list(bases)
    my_bases = [random.choice([0,1]) for _ in range(N)]
    # simulate measurement: if bases match, measured bit = sent bit; else random bit
    measured = []
    for i in range(N):
        if my_bases[i] == bases[i]:
            measured.append(bits[i])
        else:
            measured.append(random.choice([0,1]))
    # send my_bases back
    conn.send(bytes(my_bases))
    # receive indices of matched bases
    matched_len_data = recvall(conn, 4)
    if matched_len_data is None:
        return None
    M = struct.unpack('!I', matched_len_data)[0]
    matched_indices_data = recvall(conn, 4 * M)
    matched = list(struct.unpack('!' + 'I'*M, matched_indices_data))
    # construct raw key
    raw_key_bits = bytes([measured[i] for i in matched])
    # receive sample positions to check error rate
    sample_len_data = recvall(conn, 4)
    sample_len = struct.unpack('!I', sample_len_data)[0]
    sample_positions_data = recvall(conn, 4 * sample_len)
    sample_positions = list(struct.unpack('!' + 'I'*sample_len, sample_positions_data))
    # send sample bits for the sample positions
    sample_bits = bytes([raw_key_bits[pos] for pos in sample_positions])
    conn.send(struct.pack('!I', sample_len) + sample_bits)
    # now receive final hash length and value (privacy amplification)
    hash_len_data = recvall(conn, 4)
    hlen = struct.unpack('!I', hash_len_data)[0]
    final_hash = recvall(conn, hlen)
    # derive final key ourselves by hashing raw_key_bits
    # (privacy amplification simulated: sender already applied a chosen hash)
    our_key = hashlib.sha256(raw_key_bits).digest()
    # Now check: if sender's hash matches our hash, accept our key (we'll trust)
    if final_hash == hashlib.sha256(raw_key_bits).digest():
        print("[BB84] Key agreement successful. Key length:", len(our_key))
        return our_key
    else:
        print("[BB84] Key mismatch or tampering detected.")
        return None

def handle_client(conn, addr):
    print("Connected by", addr)
    key = bb84_receiver(conn)
    if key is None:
        print("Key agreement failed. Closing.")
        conn.close()
        return
    aesgcm = AESGCM(key[:32])
    while True:
        hdr = recvall(conn, 4)
        if not hdr:
            print("Connection closed.")
            break
        msglen = struct.unpack('!I', hdr)[0]
        payload = recvall(conn, msglen)
        if not payload:
            break
        # payload layout: nonce_len(1) | nonce | ciphertext
        nonce_len = payload[0]
        nonce = payload[1:1+nonce_len]
        ct = payload[1+nonce_len:]
        try:
            pt = aesgcm.decrypt(nonce, ct, None)
            # first byte indicates message type: 1=alert text, 2=jpeg image
            mtype = pt[0]
            body = pt[1:]
            if mtype == 1:
                print("[UGV ALERT]:", body.decode('utf-8'))
            elif mtype == 2:
                # save image
                fname = f"received_{int(time.time())}.jpg"
                with open(fname, 'wb') as f:
                    f.write(body)
                print(f"[UGV IMAGE] saved {fname}")
            else:
                print("[UGV] unknown message type")
        except Exception as e:
            print("Decryption/Integrity failed:", e)
    conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print("Laptop listening on", HOST, PORT)
    conn, addr = s.accept()
    handle_client(conn, addr)

if __name__ == '__main__':
    main()
