import os
import sys
import threading
import struct
from scapy.all import sniff, IP, ICMP, Raw, send
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib

LISTEN_IFACE = "eth0" #CHANGE_THIS
OUTPUT_FILE = "received.txt"
PASSPHRASE = "mypassword"  
ICMP_ID = 0x1337

received_chunks = {}     
received_encrypted = {}  
received_salt = None
expected_hash = None
start_received = False
end_received = False
lock = threading.Lock()

def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def derive_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations)

def handle_packet(pkt):
    global received_salt, expected_hash, start_received, end_received

    if not pkt.haslayer(ICMP) or pkt[ICMP].type != 8:  
        return

    src = pkt[IP].src
    seq = pkt[ICMP].seq
    pkt_id = pkt[ICMP].id
    data = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

    ack = IP(dst=src)/ICMP(type=0, id=pkt_id, seq=seq)
    send(ack, verbose=0)

    with lock:
        if seq == 0 and data.startswith(b"START"):
            received_salt = data[len(b"START"):]
            start_received = True
            print(f"[*] START marker received from {src}. Salt length {len(received_salt)}")
            return

        if seq == 65534 and data.startswith(b"HASH"):
            expected_hash = data[len(b"HASH"):]
            print(f"[*] HASH marker received (sha256).")
            return

        if seq == 65535 and data == b"END":
            end_received = True
            print("[*] END marker received. Reconstructing file.")
            try:
                reconstruct_and_verify()
            except Exception as e:
                print("[!] Error during reconstruction:", e)
            return

        if len(data) < 2 + 16:
            print(f"[!] Received chunk seq {seq} too small ({len(data)} bytes). Ignoring.")
            return
        try:
            ct_len = struct.unpack("!H", data[0:2])[0]
        except struct.error:
            print(f"[!] Failed to unpack length for seq {seq}. Ignoring.")
            return
        if len(data) < 2 + 16 + ct_len:
            print(f"[!] Incomplete chunk seq {seq}: expected {2+16+ct_len} bytes, got {len(data)}. Ignoring.")
            return
        iv = data[2:18]
        ct = data[18:18+ct_len]
        received_encrypted[seq] = (iv, ct)
        print(f"[*] Received chunk seq {seq}, ciphertext {ct_len} bytes, payload {len(data)} bytes")

def reconstruct_and_verify():
    global received_encrypted, received_salt, expected_hash, start_received
    if not start_received or received_salt is None:
        raise RuntimeError("Missing START/salt; cannot derive key.")

    key = derive_key(PASSPHRASE, received_salt)

    ordered_seqs = sorted(k for k in received_encrypted.keys())
    plaintext_parts = []
    for seq in ordered_seqs:
        iv, ct = received_encrypted[seq]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ct)
        try:
            part = pkcs7_unpad(padded)
        except ValueError as e:
            raise RuntimeError(f"Invalid padding for seq {seq}: {e}")
        plaintext_parts.append(part)

    full_plaintext = b"".join(plaintext_parts)

    with open(OUTPUT_FILE, "wb") as f:
        f.write(full_plaintext)
    print(f"[+] File written to {OUTPUT_FILE} ({len(full_plaintext)} bytes)")

    if expected_hash is not None:
        actual_hash = hashlib.sha256(full_plaintext).digest()
        if actual_hash == expected_hash:
            print("[+] SHA256 verification SUCCESS (file integrity confirmed).")
        else:
            print("[!] SHA256 verification FAILED!")
            print("    expected:", expected_hash.hex())
            print("    actual:  ", actual_hash.hex())
    else:
        print("[*] No HASH marker received; skipping integrity check.")

def main():
    print("[*] Receiver starting. Listening for ICMP Echo Requests...")
    sniff(filter="icmp and icmp[icmptype] == icmp-echo", prn=handle_packet, iface=LISTEN_IFACE)

if __name__ == "__main__":
    main()
   
