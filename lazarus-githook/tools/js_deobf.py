#!/usr/bin/env python3
"""
Desobfuscation obfuscator.io pour les stages JS de lazarus-githook.

Gere deux formats de declaration du tableau de chaines :
  - var _0xNAME = ['...', '...']          (format efimer)
  - function NAME(){const J=['...'];...}  (format lazarus)

Les strings sont encodees avec un custom base64 : meme algorithme que
le base64 standard mais avec un alphabet ou minuscules et majuscules
sont inversees. Decodage = swapcase des lettres + base64 standard.

Usage :
  python3 js_deobf.py <input.js> <output.js>
  python3 js_deobf.py <input.js> <output.js> --dump-array   # affiche le tableau resolu
"""

import sys
import re
import base64
import warnings
from urllib.parse import unquote

# Supprimer les SyntaxWarnings generees par eval() lors du test des rotations
# (backslashes dans les strings decodees pour des rotations incorrectes)
warnings.filterwarnings('ignore', category=SyntaxWarning)


# ---------------------------------------------------------------------------
# Decodage custom base64
# ---------------------------------------------------------------------------

def custom_b64_decode(s):
    """
    Decode une string avec l'alphabet obfuscator.io lazarus :
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
    Equivalent a : swapcase des lettres puis base64 standard.
    """
    swapped = ''.join(c.swapcase() if c.isalpha() else c for c in s)
    # Ajouter le padding si necessaire
    pad = (4 - len(swapped) % 4) % 4
    swapped += '=' * pad
    try:
        raw = base64.b64decode(swapped)
        # Equivalent JS : chaque octet -> '%XX' -> decodeURIComponent
        pct = ''.join(f'%{b:02x}' for b in raw)
        return unquote(pct, encoding='utf-8', errors='replace')
    except Exception:
        return s  # fallback : retourner la chaine brute


def is_meaningful(s):
    """Heuristique : string dechiffree qui ressemble a du code/texte."""
    if not s or len(s) < 2 or len(s) > 80:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) < 127)
    return printable / len(s) >= 0.85


# ---------------------------------------------------------------------------
# Extraction du tableau de chaines
# ---------------------------------------------------------------------------

def extract_string_array(src):
    """
    Cherche le tableau principal, deux patterns :
      1) var _0xNAME = ['...']
      2) function NAME(){const/var J=['...']; NAME=function(){return J;} ...}
    Retourne (array_fn_name, lookup_fn_name, base_offset, raw_strings).
    """
    # Pattern 1 : var _0xNAME = [...]
    m = re.search(
        r'var\s+(_0x[0-9a-f]+)\s*=\s*\[((?:[^\]\\]|\\.)*)\]',
        src, re.DOTALL
    )
    if m:
        arr_name = m.group(1)
        raw_items = m.group(2)
        strings = _parse_string_list(raw_items)
        # Chercher la fonction de lookup qui reference arr_name
        lookup, offset = _find_lookup(src, arr_name)
        return arr_name, lookup, offset, strings

    # Pattern 2 : function NAME(){const J=[...]; NAME=function(){return J;}}
    m = re.search(
        r'function\s+(\w+)\s*\(\s*\)\s*\{[^{]*(?:const|var)\s+\w+\s*=\s*\['
        r'((?:[^\]\\]|\\.)*)\]',
        src, re.DOTALL
    )
    if m:
        arr_name = m.group(1)
        raw_items = m.group(2)
        strings = _parse_string_list(raw_items)
        lookup, offset = _find_lookup(src, arr_name)
        return arr_name, lookup, offset, strings

    return None, None, 0, []


def _parse_string_list(raw):
    strings = []
    for match in re.finditer(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", raw):
        val = match.group(1) if match.group(1) is not None else match.group(2)
        val = (val
               .replace("\\'", "'").replace('\\"', '"')
               .replace('\\\\', '\\').replace('\\n', '\n')
               .replace('\\r', '\r').replace('\\t', '\t'))
        strings.append(val)
    return strings


def _find_lookup(src, arr_name):
    """
    Cherche la fonction de lookup qui applique une soustraction de base.
    Retourne (lookup_fn_name, base_offset).

    Gere aussi les aliases : const ALIAS = LOOKUP_FN declare en haut
    du fichier avant la definition de LOOKUP_FN.
    """
    # Pattern general : function NAME(PARAM,...){PARAM=PARAM-0xOFFSET;...}
    m = re.search(
        r'function\s+(\w+)\s*\((\w+)[^)]*\)\s*\{\s*\2\s*=\s*\2\s*-\s*(0x[0-9a-f]+)',
        src
    )
    if m:
        defined_name = m.group(1)
        offset = int(m.group(3), 16)

        # Chercher TOUS les aliases vers cette fonction et prendre le + utilise.
        # On exclut les appels (const c=W(0x...)) avec un lookahead negatif sur '('
        aliases = re.findall(
            r'(?:const|let|var)\s+(\w+)\s*=\s*' + re.escape(defined_name) + r'\b(?!\s*\()',
            src
        )
        if aliases:
            # Compter les appels avec hex pour chaque alias
            hex_call_counts = {
                a: len(re.findall(re.escape(a) + r'\s*\(\s*0x', src))
                for a in aliases
            }
            best = max(aliases, key=lambda a: hex_call_counts.get(a, 0))
            return best, offset

        return defined_name, offset

    # Fallback : chercher un appel indirect via const/let
    m = re.search(
        r'(?:const|let|var)\s+(\w+)\s*=\s*\w+\s*=>\s*\{[^}]*-\s*(0x[0-9a-f]+)',
        src
    )
    if m:
        return m.group(1), int(m.group(2), 16)

    return None, 0


# ---------------------------------------------------------------------------
# Detection de la rotation
# ---------------------------------------------------------------------------

def safe_int(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def find_iife_target(src):
    # Pattern : }(NAME, 0xTARGET))
    m = re.search(r'\}\s*\(\s*\w+\s*,\s*(0x[0-9a-f]+)\s*\)', src)
    if m:
        return int(m.group(1), 16)
    return None


def js_parseint(s):
    """Simule parseInt() JavaScript : lit le prefixe numerique entier."""
    m = re.match(r'^-?\d+', str(s))
    return float(m.group()) if m else float('nan')


def find_rotation(strings, target, decode_fn, src=None, base_offset=0):
    """
    Cherche la rotation en evaluant directement la formule IIFE.
    Fallback : heuristique intelligibilite.
    """
    n = len(strings)

    # Methode principale : evaluer la formule IIFE pour chaque rotation
    if target is not None and src is not None and base_offset > 0:
        rot = _find_rotation_by_iife(src, strings, target, decode_fn, base_offset)
        if rot is not None:
            return rot, 'formule-iife'

    # Methode cumul (efimer-style, fonctionne si les strings brutes sont numeriques)
    if target is not None:
        target_32 = target & 0xFFFFFFFF
        for rot in range(n):
            rotated = strings[rot:] + strings[:rot]
            total = 0
            for s in rotated:
                total += safe_int(s)
                if (total & 0xFFFFFFFF) == target_32:
                    return rot, 'cumul-brut'

    # Fallback : heuristique intelligibilite
    best_rot, best_score = 0, -1
    for rot in range(n):
        rotated = strings[rot:] + strings[:rot]
        sample = [decode_fn(s) for s in rotated[:min(30, n)]]
        score = sum(1 for s in sample if is_meaningful(s))
        if score > best_score:
            best_score = score
            best_rot = rot

    return best_rot, f'heuristique (score={best_score}/{min(30,n)})'


def _find_rotation_by_iife(src, strings, target, decode_fn, base_offset):
    """
    Extrait les indices de la formule IIFE (apres expansion des constantes),
    puis teste chaque rotation en evaluant la formule avec Python floats.
    """
    expanded = expand_const_objects(src)

    # Trouver le corps du IIFE : (function(...){...}(NAME, 0xTARGET)[)]?)
    # Le nombre de ')' de fermeture varie selon le contexte (1 ou 2)
    m = re.search(
        r'\(function\s*\(\w+\s*,\s*\w+\s*\)\s*\{(.*?)\}\s*\(\s*\w+\s*,\s*0x[0-9a-f]+\s*\)\s*\)?',
        expanded, re.DOTALL
    )
    if not m:
        return None

    iife_body = m.group(1)

    # Trouver la formule : const M = EXPR avec parseInt(...)
    fm = re.search(r'const\s+\w+\s*=\s*(-?parseInt\b.+?);', iife_body, re.DOTALL)
    if not fm:
        return None
    formula_str = fm.group(1).strip()

    # Extraire les indices W(0xNN) utilises dans la formule
    lookup_fn_in_iife = re.findall(r'parseInt\s*\(\s*(\w+)\s*\(\s*0x[0-9a-f]+\s*\)', formula_str)
    if not lookup_fn_in_iife:
        return None
    lookup_fn_name = lookup_fn_in_iife[0]

    # Reconstruire la formule Python :
    # remplacer parseInt(LOOKUP(0xNN)) par _PI(LOOKUP(0xNN))
    formula_py = re.sub(
        r'parseInt\s*\(\s*(' + re.escape(lookup_fn_name) + r'\s*\(\s*0x[0-9a-f]+\s*\))\s*\)',
        r'_PI(\1)',
        formula_str
    )
    # Remplacer les expressions 0xNN hex (JS) - Python les comprend nativement

    n = len(strings)

    for rot in range(n):
        # Construire un namespace avec LOOKUP(0xNN) -> decoded string
        ns = {'_PI': js_parseint, '__builtins__': {}}
        lookup_calls = {}

        for raw_idx_str in re.findall(
            re.escape(lookup_fn_name) + r'\s*\(\s*(0x[0-9a-f]+)\s*\)', formula_py
        ):
            raw_idx = int(raw_idx_str, 16)
            idx = (raw_idx - base_offset + rot) % n
            decoded = decode_fn(strings[idx])
            lookup_calls[raw_idx_str] = decoded

        # Remplacer LOOKUP(0xNN) par la valeur decodee dans la formule
        # On utilise repr() pour eviter les problemes d'echappement (backslashes, etc.)
        formula_eval = formula_py
        for hex_str, decoded_val in lookup_calls.items():
            formula_eval = re.sub(
                re.escape(lookup_fn_name) + r'\s*\(\s*' + re.escape(hex_str) + r'\s*\)',
                repr(decoded_val),
                formula_eval
            )

        try:
            M = eval(formula_eval, ns)
            if isinstance(M, (int, float)) and abs(M - target) < 0.01:
                return rot
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Expansion des constantes objets hex
# ---------------------------------------------------------------------------

def expand_const_objects(src):
    """
    Remplace les acces a des constantes objets par leurs valeurs hex litterales.
    Exemple : const C={a:0xf2,X:0xe4}; W(C.a) => W(0xf2)

    Gere uniquement les objets dont toutes les valeurs sont des litteraux
    hex (0xNN) ou decimaux entiers.
    """
    obj_map = {}

    # Trouver toutes les declarations d'objets avec valeurs numeriques.
    # Couvre const/let/var X={...} et les multi-declarations X={...},Y={...}
    # En cherchant directement WORD={KEY:0xNN,...}
    for decl in re.finditer(r'(\w+)\s*=\s*\{([^}]+)\}', src):
        obj_name = decl.group(1)
        body = decl.group(2)
        props = {}
        for prop in re.finditer(r'(\w+)\s*:\s*(0x[0-9a-f]+|\d+)', body):
            props[prop.group(1)] = int(prop.group(2), 0)
        # Valide seulement si toutes les cles ont des valeurs numeriques
        total_keys = len(re.findall(r'\w+\s*:', body))
        if props and total_keys == len(props):
            obj_map[obj_name] = props

    if not obj_map:
        return src

    # Remplacer OBJ.PROP par la valeur hex
    def replacer(m):
        obj = m.group(1)
        prop = m.group(2)
        if obj in obj_map and prop in obj_map[obj]:
            return hex(obj_map[obj][prop])
        return m.group(0)

    names = '|'.join(re.escape(n) for n in obj_map)
    pattern = re.compile(r'\b(' + names + r')\.(\w+)\b')
    return pattern.sub(replacer, src)


# ---------------------------------------------------------------------------
# Resolution des appels
# ---------------------------------------------------------------------------

def resolve_calls(src, lookup_fn, rotated_decoded, base_offset):
    """Remplace toutes les occurrences lookup_fn(0xNN) par la string decodee."""
    if not lookup_fn:
        return src, 0

    pattern = re.compile(re.escape(lookup_fn) + r'\s*\(\s*(0x[0-9a-f]+)\s*\)')
    count = [0]

    def replacer(m):
        raw_idx = int(m.group(1), 16)
        idx = raw_idx - base_offset
        if 0 <= idx < len(rotated_decoded):
            count[0] += 1
            val = rotated_decoded[idx]
            safe_val = val.replace('\\', '\\\\').replace("'", "\\'")
            return f"'{safe_val}'"
        return m.group(0)

    resolved = pattern.sub(replacer, src)
    return resolved, count[0]


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.js> <output.js> [--dump-array]")
        sys.exit(1)

    infile   = sys.argv[1]
    outfile  = sys.argv[2]
    dump_arr = '--dump-array' in sys.argv

    with open(infile, 'r', encoding='utf-8', errors='replace') as f:
        src = f.read()

    arr_name, lookup_fn, base_offset, strings = extract_string_array(src)

    if not strings:
        print("[!] Tableau de strings introuvable")
        sys.exit(1)

    print(f"[+] Tableau '{arr_name}' : {len(strings)} entrees")
    print(f"[+] Lookup  '{lookup_fn}' avec offset base {hex(base_offset)}")

    target = find_iife_target(src)
    if target is not None:
        print(f"[+] Cible IIFE : {hex(target)}")
    else:
        print("[?] Cible IIFE introuvable, fallback heuristique")

    rotation, method = find_rotation(strings, target, custom_b64_decode, src=src, base_offset=base_offset)
    print(f"[+] Rotation : {rotation} (methode : {method})")

    rotated = strings[rotation:] + strings[:rotation]
    decoded = [custom_b64_decode(s) for s in rotated]

    if dump_arr:
        print("\n--- Tableau resolu ---")
        for i, (raw, dec) in enumerate(zip(rotated, decoded)):
            print(f"  [{i:3d}] raw={raw!r:30s}  dec={dec!r}")
        print("--- Fin tableau ---\n")

    # Etape 1 : expanser les constantes objets (W(C.a) -> W(0xf2))
    expanded = expand_const_objects(src)
    n_expanded = len(re.findall(re.escape(lookup_fn) + r'\s*\(\s*0x', expanded)) if lookup_fn else 0
    n_before   = len(re.findall(re.escape(lookup_fn) + r'\s*\(\s*0x', src)) if lookup_fn else 0
    if n_expanded > n_before:
        print(f"[+] Expansion constantes : {n_expanded - n_before} appels supplementaires resolus")
        src = expanded

    resolved, count = resolve_calls(src, lookup_fn, decoded, base_offset)

    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(resolved)

    print(f"[+] {count} appels remplaces -> {outfile}")

    remaining = len(re.findall(re.escape(lookup_fn) + r'\s*\(', resolved)) if lookup_fn else 0
    if remaining:
        print(f"[?] {remaining} appels non resolus (index hors tableau ou lookup different)")

    # Apercu des 10 premieres strings decodees
    print("\n--- Apercu (10 premieres strings decodees) ---")
    for i, d in enumerate(decoded[:10]):
        print(f"  [{hex(base_offset + i)}] {d!r}")


if __name__ == '__main__':
    main()
