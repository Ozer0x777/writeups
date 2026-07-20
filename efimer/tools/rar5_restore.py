#!/usr/bin/env python3
"""
Restauration de l'archive RAR5 corrompue de campus.py.

L'archive a subi une transformation cp1252->UTF-8 avant d'etre encodee en base64.
Ce script annule exactement cette transformation et corrige le byte 7 du magic RAR5.

Deux pieges identifies lors de l'analyse :
  1. Patcher uniquement le byte 7 ne suffit pas (erreur initiale).
  2. errors='replace' remplace 5 code points cp1252 non definis par '?' (0x3F),
     ce qui corrompt les blocs RAR. Le handler personnalise retourne l'octet brut
     (cp & 0xFF) pour ces cas, ce qui annule exactement la transformation originale.

Usage:
  python3 rar5_restore.py campus.py campus_restored.rar
"""
import sys
import base64
import codecs
import re


def cp1252_raw_handler(exc):
    start, end = exc.start, exc.end
    result = bytes([ord(exc.object[i]) & 0xFF for i in range(start, end)])
    return result, end


codecs.register_error('cp1252_raw', cp1252_raw_handler)

RAR5_MAGIC    = b'Rar!\x1a\x07\x01\x00'
RAR5_MAGIC_HEX_EXPECTED = '526172211a070100'


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} campus.py output.rar")
        sys.exit(1)

    infile  = sys.argv[1]
    outfile = sys.argv[2]

    print(f"[*] Lecture de {infile}...")
    with open(infile, 'r', encoding='utf-8') as f:
        src = f.read()

    m = re.search(r'data\s*=\s*["\']([A-Za-z0-9+/=\n\r\s]+)["\']', src, re.DOTALL)
    if not m:
        print("[!] Variable 'data' introuvable dans le fichier source")
        sys.exit(1)

    b64_data = re.sub(r'\s+', '', m.group(1))
    print(f"[*] Base64 extrait : {len(b64_data)} caracteres")

    raw = base64.b64decode(b64_data)
    print(f"[*] Decode : {len(raw)} octets")
    print(f"[*] Magic brut : {raw[:8].hex()}")

    raw_str  = raw.decode('utf-8')
    restored = raw_str.encode('cp1252', errors='cp1252_raw')
    print(f"[*] Apres reversal cp1252 : {len(restored)} octets (reduit de {len(raw) - len(restored)} octets)")

    restored_arr = bytearray(restored)

    if restored_arr[:7] == RAR5_MAGIC[:7] and restored_arr[7] != 0x00:
        print(f"[*] Byte 7 avant correction : {hex(restored_arr[7])}")
        restored_arr[7] = 0x00
        print("[+] Byte 7 corrige (-> 0x00)")
    elif restored_arr[:8] == RAR5_MAGIC:
        print("[+] Magic RAR5 deja valide, aucune correction necessaire")
    else:
        print(f"[!] Magic inattendu : {restored_arr[:8].hex()}, correction tentee quand meme")
        restored_arr[7] = 0x00

    magic_final = bytes(restored_arr[:8]).hex()
    if magic_final == RAR5_MAGIC_HEX_EXPECTED:
        print(f"[+] Magic RAR5 valide : {magic_final}")
    else:
        print(f"[!] Magic final : {magic_final} (attendu {RAR5_MAGIC_HEX_EXPECTED})")

    with open(outfile, 'wb') as f:
        f.write(bytes(restored_arr))

    print(f"[+] Archive restauree : {outfile} ({len(restored_arr)} octets)")
    print(f"[*] Extraction : 7z e {outfile} -o extracted/")
    print(f"[*] Note : seuls les 2 premiers fichiers s'extraient correctement (CRC invalide sur les suivants)")


if __name__ == '__main__':
    main()
