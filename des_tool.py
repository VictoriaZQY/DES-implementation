#!/usr/bin/env python3
"""
This Python script implements the DES encryption algorithm according to the official FIPS PUB 46-3 specification.

It provides both encryption and decryption operations,
includes all permutation and substitution tables (IP, FP, E, PC1, PC2, etc.),
and demonstrates the standard test case.

Features:
- DES core per FIPS: IP, FP, E, S-boxes, P, PC-1, PC-2, shifts.
- Block encrypt/decrypt for 8-byte blocks.
- Key derivation from any-length user key material (SHA-256 -> 8 bytes -> set odd parity).
- PKCS#7 padding for arbitrary-length plaintext.
- ECB and CBC modes.
- Simple Tkinter GUI to load/save files, enter text, run encrypt/decrypt independently (key needed for both).
"""


import hashlib, sys, os
from tkinter import Tk, filedialog, ttk, Text, Button, Label, Scrollbar, Entry, StringVar, Frame, END
from tkinter.messagebox import showinfo, showerror
from os import urandom

# ---------- FIPS tables ----------\
# Define the data used in the DES algorithm.

# Initial Permutation (IP)
IP = [58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7]

# Final Permutation (FP)
FP = [40,8,48,16,56,24,64,32,
      39,7,47,15,55,23,63,31,
      38,6,46,14,54,22,62,30,
      37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,
      35,3,43,11,51,19,59,27,
      34,2,42,10,50,18,58,26,
      33,1,41,9,49,17,57,25]

# Expansion table (E) to expand 32 bits to 48 bits
E = [32,1,2,3,4,5,
     4,5,6,7,8,9,
     8,9,10,11,12,13,
     12,13,14,15,16,17,
     16,17,18,19,20,21,
     20,21,22,23,24,25,
     24,25,26,27,28,29,
     28,29,30,31,32,1]

# S-boxes (8 boxes, each 4x16 table)
SBOX = [
# S1
[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
 [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
 [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
 [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
# S2
[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
 [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
 [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
 [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
# S3
[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
 [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
 [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
 [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
# S4
[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
 [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
 [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
 [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
# S5
[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
 [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
 [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
 [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
# S6
[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
 [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
 [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
 [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8]],
# S7
[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
 [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
 [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
 [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
# S8
[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
 [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
 [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
 [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]


P = [16,7,20,21,29,12,28,17,
     1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,
     19,13,30,6,22,11,4,25]

# Permuted Choice 1 and 2 (PC1, PC2) for key scheduling
PC1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,
       3,28,15,6,21,10,
       23,19,12,4,26,8,
       16,7,27,20,13,2,
       41,52,31,37,47,55,
       30,40,51,45,33,48,
       44,49,39,56,34,53,
       46,42,50,36,29,32]

# Left shift schedule for 16 rounds
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# ---------- Bit helpers ----------
# Convert bytes to a list of bits (0/1)
def bytes_to_bits(bs):
    bits = []
    for b in bs:
        for i in range(8):
            bits.append((b >> (7-i)) & 1)
    return bits

# Convert a list of bits back to bytes
def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i+j]
        out.append(byte)
    return bytes(out)

# Perform bit permutation according to a table
def permute(bits, table):
    return [bits[i-1] for i in table]

# Left rotate a list of bits by n positions
def left_rotate(bits, n):
    return bits[n:] + bits[:n]

# XOR two bit lists
def xor_bits(a,b):
    return [x ^ y for x,y in zip(a,b)]

# ---------- Core DES building blocks ----------

# S-box substitution (48 bits → 32 bits)
def sbox_substitution(bits48):
    out = []
    for i in range(8):
        block6 = bits48[i*6:(i+1)*6]
        row = (block6[0] << 1) | block6[5]
        col = (block6[1] << 3) | (block6[2] << 2) | (block6[3] << 1) | block6[4]
        val = SBOX[i][row][col]
        for j in range(4):
            out.append((val >> (3-j)) & 1)
    return out


def f_function(R, subkey48):
    expanded = permute(R, E)        # 48 bits
    x = xor_bits(expanded, subkey48) # 48 bits
    sboxed = sbox_substitution(x)    # 32 bits
    pboxed = permute(sboxed, P)      # 32 bits
    return pboxed

def generate_subkeys(key8):
    # key8: 8 bytes (64 bits including parity)
    key_bits = bytes_to_bits(key8)
    pc1_out = permute(key_bits, PC1)  # 56 bits
    C = pc1_out[:28]; D = pc1_out[28:]
    subkeys = []
    for s in SHIFTS:
        C = left_rotate(C, s); D = left_rotate(D, s)
        CD = C + D
        subkeys.append(permute(CD, PC2))  # 48 bits
    return subkeys

def des_encrypt_block(block8, subkeys):
    bits = bytes_to_bits(block8)
    ip = permute(bits, IP)
    L = ip[:32]; R = ip[32:]
    for i in range(16):
        f_out = f_function(R, subkeys[i])
        newL = R
        newR = xor_bits(L, f_out)
        L, R = newL, newR
    preout = R + L
    cipher_bits = permute(preout, FP)
    return bits_to_bytes(cipher_bits)

def des_decrypt_block(block8, subkeys):
    bits = bytes_to_bits(block8)
    ip = permute(bits, IP)
    L = ip[:32]; R = ip[32:]
    for i in range(15, -1, -1):
        f_out = f_function(L, subkeys[i])
        newR = L
        newL = xor_bits(R, f_out)
        L, R = newL, newR
    preout = L + R
    plain_bits = permute(preout, FP)
    return bits_to_bytes(plain_bits)

# ---------- Key derivation (arbitrary length -> 64-bit DES key + odd parity) ----------
def set_odd_parity(byte_val):
    # Make least-significant bit parity bit (odd parity across 8 bits)
    b = byte_val & 0xFE
    ones = bin(b).count("1")
    if ones % 2 == 0:
        b |= 1
    return b

def derive_key_from_bytes(material: bytes):
    # Deterministic: SHA-256(material) -> take first 8 bytes -> set odd parity per byte
    h = hashlib.sha256(material).digest()
    k = bytearray(h[:8])
    for i in range(8):
        k[i] = set_odd_parity(k[i])
    return bytes(k)

# ---------- Padding (PKCS#7 for blocksize 8) ----------
def pkcs7_pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len])*pad_len

def pkcs7_unpad(data):
    if len(data) == 0:
        return data
    pad = data[-1]
    if pad < 1 or pad > 8:
        raise ValueError("Invalid padding")
    if data[-pad:] != bytes([pad])*pad:
        raise ValueError("Invalid padding bytes")
    return data[:-pad]

# ---------- High level operations: ECB and CBC ----------
def des_encrypt(data: bytes, user_key_bytes: bytes, mode='ECB', iv: bytes = None):
    # derive a working 8-byte DES key from arbitrary-length material
    key8 = derive_key_from_bytes(user_key_bytes)
    subkeys = generate_subkeys(key8)
    if mode == 'CBC' and iv is None:
        iv = bytes(8)
    padded = pkcs7_pad(data)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        if mode == 'CBC':
            block = bytes(a^b for a,b in zip(block, prev))
        cblock = des_encrypt_block(block, subkeys)
        out.extend(cblock)
        if mode == 'CBC':
            prev = cblock
    return bytes(out), (iv if iv is not None else bytes(8))

def des_decrypt(cipher: bytes, user_key_bytes: bytes, mode='ECB', iv: bytes = None):
    key8 = derive_key_from_bytes(user_key_bytes)
    subkeys = generate_subkeys(key8)
    if mode == 'CBC' and iv is None:
        iv = bytes(8)
    out = bytearray()
    prev = iv
    for i in range(0, len(cipher), 8):
        block = cipher[i:i+8]
        pblock = des_decrypt_block(block, subkeys)
        if mode == 'CBC':
            pblock = bytes(a^b for a,b in zip(pblock, prev))
            prev = block
        out.extend(pblock)
    return pkcs7_unpad(bytes(out))

# ---------- Small CLI utilities ----------
def hexify(b: bytes) -> str:
    return b.hex().upper()

def unhex(s: str) -> bytes:
    return bytes.fromhex(s.strip())

# ---------- Simple Tkinter GUI (file/text input, encrypt/decrypt) ----------
def start_gui():
    root = Tk()
    root.title("DES Tool (FIPS 46-3) - Encrypt / Decrypt")

    # Top frame: input controls
    frame = Frame(root)
    frame.pack(padx=8, pady=8, fill='x')

    Label(frame, text="Mode:").grid(row=0, column=0, sticky='w')
    mode_var = StringVar(value='CBC')
    mode_box = ttk.Combobox(frame, textvariable=mode_var, values=['ECB','CBC'], width=6)
    mode_box.grid(row=0, column=1, sticky='w')

    Label(frame, text="Key (any length):").grid(row=1, column=0, sticky='w')
    key_entry = Entry(frame, width=64)
    key_entry.grid(row=1, column=1, columnspan=3, sticky='we')

    Label(frame, text="Input (text or file):").grid(row=2, column=0, sticky='nw')
    txt = Text(root, height=12, width=80)
    txt.pack(padx=8, pady=4)

    btn_frame = Frame(root)
    btn_frame.pack(padx=8, pady=4, fill='x')
    def load_file():
        fname = filedialog.askopenfilename()
        if fname:
            with open(fname,'rb') as f:
                data = f.read()
            # show file as hex in the text box (user-friendly)
            try:
                txt.delete('1.0', END)
                txt.insert(END, data.decode('utf-8'))
            except:
                txt.delete('1.0', END)
                txt.insert(END, data.hex())

    def save_output(out_bytes):
        fname = filedialog.asksaveasfilename(defaultextension=".bin")
        if fname:
            with open(fname,'wb') as f:
                f.write(out_bytes)
            showinfo("Saved", f"Output saved to {fname}")

    def do_encrypt():
        mode = mode_var.get()
        key_mat = key_entry.get().encode('utf-8')
        txt_content = txt.get('1.0', END).rstrip('\n')
        # read as bytes (try text, else hex)
        try:
            data = txt_content.encode('utf-8')
        except:
            data = bytes.fromhex(txt_content.strip())
        iv = None
        if mode == 'CBC':
            iv = urandom(8)
            ct, _iv = des_encrypt(data, key_mat, mode='CBC', iv=iv)
            # We'll display IV + ciphertext in hex so user can copy-paste for decrypt
            display = "IV (hex):\n" + iv.hex().upper() + "\n\nCiphertext (hex):\n" + ct.hex().upper()
        else:
            ct, _ = des_encrypt(data, key_mat, mode='ECB')
            display = "Ciphertext (hex):\n" + ct.hex().upper()
        txt.delete('1.0', END)
        txt.insert(END, display)

    def do_decrypt():
        mode = mode_var.get()
        key_mat = key_entry.get().encode('utf-8')
        raw = txt.get('1.0', END).strip()
        # If CBC: expect an IV line + ciphertext; else just ciphertext
        if mode == 'CBC':
            # allow either two-line format or just hex with IV concatenated
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            if len(lines) >= 2 and len(lines[0]) in (16,): # likely iv hex
                iv = bytes.fromhex(lines[0])
                ct_hex = ''.join(lines[1:])
            else:
                # If hex length > 16, assume first 16 hex chars are IV (8 bytes)
                rawhex = raw.replace('\n','').replace(' ','')
                iv = bytes.fromhex(rawhex[:16])
                ct_hex = rawhex[16:]
            ct = bytes.fromhex(ct_hex)
            try:
                pt = des_decrypt(ct, key_mat, mode='CBC', iv=iv)
            except Exception as e:
                showerror("Error", f"Decryption failed: {e}")
                return
            # try to decode as text for display
            try:
                txt.delete('1.0', END); txt.insert(END, pt.decode('utf-8'))
            except:
                txt.delete('1.0', END); txt.insert(END, pt.hex().upper())
        else:
            rawhex = raw.replace('\n','').replace(' ','')
            ct = bytes.fromhex(rawhex)
            try:
                pt = des_decrypt(ct, key_mat, mode='ECB')
            except Exception as e:
                showerror("Error", f"Decryption failed: {e}")
                return
            try:
                txt.delete('1.0', END); txt.insert(END, pt.decode('utf-8'))
            except:
                txt.delete('1.0', END); txt.insert(END, pt.hex().upper())

    Button(btn_frame, text="Load file", command=load_file).pack(side='left', padx=4)
    Button(btn_frame, text="Encrypt", command=do_encrypt).pack(side='left', padx=4)
    Button(btn_frame, text="Decrypt", command=do_decrypt).pack(side='left', padx=4)
    Button(btn_frame, text="Save output...", command=lambda: save_output(txt.get('1.0', END).encode('utf-8'))).pack(side='left', padx=4)

    root.mainloop()

# ---------- If run as script ----------
if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == '--nogui':
        # quick CLI test: run canonical test vector
        pt = bytes.fromhex("0123456789ABCDEF")
        k = bytes.fromhex("133457799BBCDFF1")
        subkeys = generate_subkeys(k)  # use exact 8-byte key with parity for canonical test
        ct = des_encrypt_block(pt, subkeys)
        print("Canonical single-block test")
        print("Plaintext: 0123456789ABCDEF")
        print("Key:       133457799BBCDFF1")
        print("Cipher:    ", ct.hex().upper())
        print("Expected:  85E813540F0AB405")
        sys.exit(0)
    else:
        start_gui()
