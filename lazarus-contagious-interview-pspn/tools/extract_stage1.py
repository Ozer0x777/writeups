#!/usr/bin/env python3
"""
Extrait le payload JS obfusque cache dans server/controllers/userController.js
(pspn-main), injecte apres un faux commentaire en ligne 8.

Usage : python3 extract_stage1.py userController.js stage1_dropper_raw.js
"""
import re
import sys

infile, outfile = sys.argv[1], sys.argv[2]
line = open(infile, encoding='utf-8').readlines()[7]  # ligne 8, index 0-based

m = re.search(r'\*/\s*(.*)', line, re.DOTALL)
if not m:
    sys.exit("Marqueur de fin de commentaire '*/' introuvable en ligne 8")

code = m.group(1)
open(outfile, 'w', encoding='utf-8').write(code)
print(f"[+] {len(code)} octets extraits -> {outfile}")
