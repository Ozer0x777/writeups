#!/usr/bin/env python3
"""
Dechiffrement XOR des 7 payloads Efimer depuis data_p002/.
Cle : Is8xqLVw7pTB (12 octets, repetee).

Usage:
  python3 xor_decrypt.py <dossier_data_p002> <dossier_sortie>
  python3 xor_decrypt.py data_p002/ decrypted/
"""
import sys
import os

XOR_KEY = b'Is8xqLVw7pTB'

EXPECTED_MAGICS = {
    'uusd.exe':  (b'MZ',    'PE32+ executable (Tor daemon)'),
    '002_n.js':  (b'var',   'JavaScript WScript (clipper)'),
    '002_b.js':  (b'var',   'JavaScript WScript (bruteforcer WP)'),
    '002a.txt':  (None,     'Liste adresses BTC/TRX/XMR'),
    '002w.txt':  (b'aban',  'Liste BIP39'),
    '002.xml':   (b'\xff\xfe', 'XML UTF-16 LE (tache planifiee)'),
    'pack.js':   (b'func',  'Template JavaScript'),
}


def xor_decrypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_dir> <output_dir>")
        sys.exit(1)

    indir  = sys.argv[1]
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    files = sorted(os.listdir(indir))
    if not files:
        print(f"[!] Aucun fichier dans {indir}")
        sys.exit(1)

    print(f"[*] Cle XOR : {XOR_KEY.decode()}")
    print(f"[*] {len(files)} fichier(s) a dechiffrer\n")

    for fname in files:
        inpath  = os.path.join(indir, fname)
        outpath = os.path.join(outdir, fname)

        with open(inpath, 'rb') as f:
            raw = f.read()

        decrypted = xor_decrypt(raw, XOR_KEY)

        with open(outpath, 'wb') as f:
            f.write(decrypted)

        magic   = decrypted[:4].hex()
        size    = len(decrypted)
        descr   = ''
        warning = ''

        if fname in EXPECTED_MAGICS:
            expected_magic, descr = EXPECTED_MAGICS[fname]
            if expected_magic and not decrypted.startswith(expected_magic):
                warning = '  [!] magic inattendu'

        print(f"  {fname:<20}  {size:>10} octets  magic={magic}  {descr}{warning}")

    print(f"\n[+] Fichiers dechiffres dans : {outdir}")


if __name__ == '__main__':
    main()
