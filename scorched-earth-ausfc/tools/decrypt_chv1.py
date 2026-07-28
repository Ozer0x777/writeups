#!/usr/bin/env python3
"""
decrypt_chv1.py : dechiffreur pour le format "chv1" du ransomware Prinz
Eugen (nom de projet Go interne "scorched-earth-ausfc").

Le mot de passe est code en dur dans le binaire fc.exe analyse dans cette
investigation (constante ASCII de 32 caracteres retrouvee dans .rdata,
utilisee pour TOUS les fichiers chiffres par ce binaire precis). Voir
writeup.md §7 pour le detail de la retro-ingenierie du format et de la
localisation du mot de passe.

La valeur reelle du mot de passe n'est pas publiee dans ce depot (voir
writeup.md §7) : remplacer HARDCODED_PASSWORD ci-dessous par la valeur
reelle avant usage, ou passer --password via restore_all.py.

Usage : decrypt_chv1.py FICHIER.prinzeugen [FICHIER_SORTIE]
"""
import sys
import struct
import hashlib

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

HARDCODED_PASSWORD = b"SUPERCLEDEMORTQUITUE"  # placeholder, voir writeup.md §7
HKDF_INFO = b"scorched-earth key v1"
HEADER_SIZE = 0x35  # 53 octets


def derive_key(password: bytes, salt: bytes) -> bytes:
    argon2_out = hash_secret_raw(
        secret=password, salt=salt,
        time_cost=3, memory_cost=262144, parallelism=2,
        hash_len=32, type=Type.ID,
    )
    material = hashlib.sha256(argon2_out).digest()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO)
    return hkdf.derive(material)


def decrypt_file(path: str, out_path: str, password: bytes = HARDCODED_PASSWORD) -> None:
    data = open(path, "rb").read()
    if len(data) < HEADER_SIZE:
        sys.exit("fichier trop court pour contenir un header chv1")
    if data[0:4] != b"CHV1":
        sys.exit("magic invalide, ce n'est pas un fichier chv1")
    version = data[4]
    kdf_id = data[5]
    argon2_mem = struct.unpack("<I", data[6:10])[0]
    argon2_time = struct.unpack("<I", data[10:14])[0]
    argon2_par = struct.unpack("<I", data[14:18])[0]
    salt_len = data[18]
    salt = data[19:19 + salt_len]
    off = 19 + salt_len
    cipher_id = data[off]
    nonce_len = data[off + 1]
    base_nonce = data[off + 2: off + 2 + nonce_len]
    off += 2 + nonce_len
    chunk_size = struct.unpack("<I", data[off:off + 4])[0]
    orig_size = struct.unpack("<Q", data[off + 4:off + 12])[0]
    off += 12

    print(f"version={version} kdf_id={kdf_id} argon2(mem={argon2_mem}KiB,time={argon2_time},par={argon2_par})")
    print(f"salt={salt.hex()} cipher_id={cipher_id} base_nonce={base_nonce.hex()}")
    print(f"chunk_size={chunk_size} orig_size={orig_size}")

    key = derive_key(password, salt)
    aead = ChaCha20Poly1305(key)

    plaintext = b""
    chunk_index = 0
    remaining = orig_size
    while remaining > 0 or off < len(data):
        if off + 4 > len(data):
            break
        ct_len = struct.unpack("<I", data[off:off + 4])[0]
        off += 4
        ct = data[off:off + ct_len]
        off += ct_len
        nonce = base_nonce + struct.pack("<Q", chunk_index)
        pt = aead.decrypt(nonce, ct, None)
        plaintext += pt
        remaining -= len(pt)
        chunk_index += 1
        if remaining <= 0:
            break

    if len(plaintext) != orig_size:
        print(f"ATTENTION : taille dechiffree ({len(plaintext)}) != taille originale attendue ({orig_size})")

    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"OK -> {out_path} ({len(plaintext)} octets)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else inp.rsplit(".", 1)[0]
    decrypt_file(inp, out)
