#!/usr/bin/env python3
"""
Dechiffre la reponse du C2 stage 2 (schema AES-256-CBC / scrypt retrouve par
emulation dans stage1_dropper_raw.js).

Cle = scrypt(uid, salt="salt", N=16384, r=8, p=1, dklen=32)
Corps de reponse HTTP = "<iv_base64>:<ciphertext_base64>", padding PKCS7.

Usage : python3 decrypt_stage2.py <uid> reponse_c2.bin stage2_decrypted.js
"""
import base64
import hashlib
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

uid, infile, outfile = sys.argv[1], sys.argv[2], sys.argv[3]

data = open(infile, 'rb').read()
iv_b64, ct_b64 = data.split(b':', 1)
iv = base64.b64decode(iv_b64)
ct = base64.b64decode(ct_b64)

key = hashlib.scrypt(uid.encode(), salt=b'salt', n=16384, r=8, p=1, dklen=32)

decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
padded = decryptor.update(ct) + decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(padded) + unpadder.finalize()

open(outfile, 'wb').write(plaintext)
print(f"[+] cle AES : {key.hex()}")
print(f"[+] {len(plaintext)} octets dechiffres -> {outfile}")
