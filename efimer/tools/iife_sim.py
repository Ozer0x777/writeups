#!/usr/bin/env python3
"""
Simulation de l'IIFE obfuscator.io en Python.

Resout la rotation du tableau de chaines de 002_n.js et 002_b.js,
puis remplace tous les appels _0xXXXX(0xNN) par leur valeur en clair.

Deux bugs identifies lors de l'analyse :
  1. La regex initiale cherchait while(![]) (single negation).
     Le code utilise while(!![]) (double negation, valeur truthy). Corrige.
  2. parseInt() en JavaScript retourne NaN pour une chaine non numerique,
     ce qui contribue 0 a la somme. int() Python levait ValueError. Corrige
     avec safe_int() qui retourne 0 sur echec.

Usage:
  python3 iife_sim.py 002_n.js 002_n_resolved.js
  python3 iife_sim.py 002_b.js 002_b_resolved.js
"""
import sys
import re


def safe_int(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def extract_string_array(src):
    m = re.search(r'(var\s+(_0x[0-9a-f]+)\s*=\s*\[)((?:[^\]\\]|\\.)*)\]', src, re.DOTALL)
    if not m:
        return None, None

    arr_name  = m.group(2)
    raw_items = m.group(3)

    strings = []
    for match in re.finditer(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", raw_items):
        val = match.group(1) if match.group(1) is not None else match.group(2)
        val = (val
               .replace("\\'", "'")
               .replace('\\"', '"')
               .replace('\\\\', '\\')
               .replace('\\n', '\n')
               .replace('\\r', '\r')
               .replace('\\t', '\t'))
        strings.append(val)

    return arr_name, strings


def find_iife_target(src):
    # Pattern : l'IIFE se termine par }(_0xNAME, 0xTARGET))
    m = re.search(r'\}\s*\(\s*_0x[0-9a-f]+\s*,\s*(0x[0-9a-f]+)\s*\)', src)
    if m:
        return int(m.group(1), 16)
    return None


def compute_rotation(strings, target):
    n = len(strings)
    target_32 = target & 0xFFFFFFFF

    for rot in range(n):
        rotated = strings[rot:] + strings[:rot]
        total = 0
        for s in rotated:
            total += safe_int(s)
            if (total & 0xFFFFFFFF) == target_32:
                return rot

    return None


def resolve_calls(src, arr_name, rotated):
    pattern = re.compile(re.escape(arr_name) + r'\s*\(\s*(0x[0-9a-f]+)\s*\)')
    count   = [0]

    def replacer(m):
        idx = int(m.group(1), 16)
        if 0 <= idx < len(rotated):
            count[0] += 1
            val = rotated[idx]
            safe_val = val.replace("'", "\\'")
            return f"'{safe_val}'"
        return m.group(0)

    resolved = pattern.sub(replacer, src)
    return resolved, count[0]


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.js> <output.js>")
        sys.exit(1)

    infile  = sys.argv[1]
    outfile = sys.argv[2]

    with open(infile, 'r', encoding='utf-8', errors='replace') as f:
        src = f.read()

    arr_name, strings = extract_string_array(src)
    if not strings:
        print("[!] Tableau de chaines obfuscator.io introuvable")
        sys.exit(1)

    print(f"[+] Tableau '{arr_name}' : {len(strings)} chaines")

    target = find_iife_target(src)
    if target is None:
        print("[!] Valeur cible de l'IIFE introuvable")
        sys.exit(1)

    print(f"[+] Cible IIFE : {hex(target)}")

    rotation = compute_rotation(strings, target)
    if rotation is None:
        print("[!] Rotation introuvable par accumulation partielle, essai somme totale...")
        for rot in range(len(strings)):
            rotated_try = strings[rot:] + strings[:rot]
            if sum(safe_int(s) for s in rotated_try) % (2**32) == target & 0xFFFFFFFF:
                rotation = rot
                break

    if rotation is None:
        print("[!] Rotation introuvable. Verifier que le fichier est un bundle obfuscator.io standard.")
        sys.exit(1)

    print(f"[+] Rotation : {rotation}")

    rotated = strings[rotation:] + strings[:rotation]

    resolved, count = resolve_calls(src, arr_name, rotated)

    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(resolved)

    print(f"[+] {count} appels remplaces -> {outfile}")

    remaining = len(re.findall(re.escape(arr_name) + r'\s*\(', resolved))
    if remaining > 0:
        print(f"[?] {remaining} appels non resolus (index hors tableau ?)")


if __name__ == '__main__':
    main()
