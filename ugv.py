# ugv.py (Updated version)
import socket, struct, random, time, cv2, numpy as np, hashlib, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'  # same as laptop
PORT = 50000

def sendall(conn, b):
    totalsent = 0
    while totalsent < len(b):
        sent = conn.send(b[totalsent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        totalsent += sent

def bb84_sender(conn, N=1024):
    bits = [random.choice([0,1]) for _ in range(N)]
    bases = [random.choice([0,1]) for _ in range(N)]
    sendall(conn, struct.pack('!I', N))
    sendall(conn, bytes(bits))
    sendall(conn, bytes(bases))
    rec_bases = conn.recv(N)
    rec_bases = list(rec_bases)
    matched = [i for i in range(N) if bases[i] == rec_bases[i]]
    M = len(matched)
    sendall(conn, struct.pack('!I', M))
    if M > 0:
        sendall(conn, struct.pack('!' + 'I'*M, *matched))
    raw_key_bits = bytes([bits[i] for i in matched])

    # sample error check
    sample_size = min(min(20, len(raw_key_bits)//5), 10)
    sample_positions = random.sample(range(len(raw_key_bits)), sample_size) if sample_size>0 else []
    sendall(conn, struct.pack('!I', len(sample_positions)))
    if sample_size>0:
        sendall(conn, struct.pack('!' + 'I'*len(sample_positions), *sample_positions))
        sample_len_data = conn.recv(4)
        sample_len = struct.unpack('!I', sample_len_data)[0]
        sample_bits = conn.recv(sample_len)
        mismatches = sum(sample_bits[i] != raw_key_bits[sample_positions[i]] for i in range(sample_size))
        err_rate = mismatches / sample_size if sample_size>0 else 0.0
        print(f"[BB84] sample error rate: {err_rate:.3f}")
        if err_rate > 0.2:
            print("[BB84] Error too high -> aborting.")
            return None

    final_hash = hashlib.sha256(raw_key_bits).digest()
    sendall(conn, struct.pack('!I', len(final_hash)))
    sendall(conn, final_hash)
    print("[BB84] Key generated. Length:", len(final_hash))
    return final_hash

def pack_and_send_encrypted(conn, aesgcm, message_text):
    nonce = os.urandom(12)
    pt = bytes([1]) + message_text.encode('utf-8')  # type 1=text
    ct = aesgcm.encrypt(nonce, pt, None)
    block = bytes([len(nonce)]) + nonce + ct
    sendall(conn, struct.pack('!I', len(block)) + block)

def fire_detect(frame):
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
    lower = np.array([5, 120, 120])
    upper = np.array([40, 255, 255])
    mask = cv2.inRange(hsv, lower, upper)
    kernel = np.ones((5,5), np.uint8)
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel)
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    fire_found = False
    for c in contours:
        area = cv2.contourArea(c)
        if area > 2000:  # threshold area for fire
            x, y, w, h = cv2.boundingRect(c)
            cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 0, 255), 3)
            fire_found = True
    return fire_found, frame

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to laptop...")
    s.connect((HOST, PORT))
    print("Connected. Running BB84 to agree key...")
    key = bb84_sender(s)
    if key is None:
        print("BB84 failed.")
        s.close()
        return
    aesgcm = AESGCM(key[:32])

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Cannot open webcam. Exiting.")
        s.close()
        return

    last_alert_time = 0
    alert_interval = 5  # seconds between alerts

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break

            fire_found, frame = fire_detect(frame)
            if fire_found and time.time() - last_alert_time > alert_interval:
                print("[UGV] FIRE DETECTED! sending alert.")
                msg = f"🔥 FIRE DETECTED at {time.asctime()}"
                pack_and_send_encrypted(s, aesgcm, msg)
                last_alert_time = time.time()

            cv2.imshow('UGV Camera Feed', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
    finally:
        cap.release()
        cv2.destroyAllWindows()
        s.close()

if __name__ == '__main__':
    main()
