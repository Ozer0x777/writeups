#!/usr/bin/env python3
"""Extract and decrypt the stage-2 payload hidden in the stage-1 AgentTesla
loader's .NET manifest resource.

Chain (traced statically, verified by hand — see Partie 1 du writeup) :
1. The resource `Genitalk.klaoxao.tiff` is a plain .NET manifest resource,
   extractable with `ilspycmd --resource "Genitalk.klaoxao.tiff"`.
2. Its bytes are stored reversed (`Array.Reverse`).
3. AES-128-CBC, with the same 16 bytes reused as both key and IV (a real
   implementation weakness of the malware itself, not of this script).

Usage: python3 decrypt_stage2_resource.py Genitalk.klaoxao.tiff stage2.dll
Requires: pycryptodome (pip install pycryptodome)
"""
import sys

from Crypto.Cipher import AES

KEY_IV = bytes([228, 169, 49, 203, 110, 32, 67, 34, 218, 13, 26, 48, 217, 70, 99, 59])


def decrypt(resource_bytes: bytes) -> bytes:
    reversed_bytes = resource_bytes[::-1]
    cipher = AES.new(KEY_IV, AES.MODE_CBC, iv=KEY_IV)
    return cipher.decrypt(reversed_bytes)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <resource_in> <stage2_out>")
        sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]

    data = open(src, "rb").read()
    plain = decrypt(data)

    print(f"Ressource source : {len(data)} octets")
    print(f"Dechiffre        : {len(plain)} octets")
    print(f"Magic PE (MZ)?   : {plain[:2] == b'MZ'}")

    open(dst, "wb").write(plain)
    print(f"Ecrit : {dst}")


if __name__ == "__main__":
    main()
