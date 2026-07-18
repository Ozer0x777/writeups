# Runbook — reproduction pas à pas (Parties 1 à 4)

Ce fichier regroupe tous les logs de manipulation (commande / pourquoi / retour brut / ce qu'on en retient) des quatre parties de l'enquête StealC, dans l'ordre chronologique où elles ont été exécutées. Les parties `0X-*.md` restent le récit analytique (constats, hypothèses, conclusions) ; ce fichier est la preuve de travail et le mode d'emploi pour rejouer chaque étape à l'identique.

Les scripts complets (`deobfuscate.py`, `validate_crossref.py`, `decode_chrw.py`) ne sont pas dupliqués ici : ils vivent dans [`tools/`](tools/) et sont invoqués tels quels ci-dessous.

---

## Partie 1 — Extraction du stub IExpress et du loader AutoIt

*(récit analytique correspondant : [writeup.md §1–4](writeup.md#4-le-stub-iexpress--analyse-statique))*

### A. Création de l'arborescence de travail

**Commande :**
```
mkdir -p ~/ctf-reverse/{binaries,writeups,tools} && ls -la ~/ctf-reverse
```

**Pourquoi :** séparer proprement l'échantillon, les outils et les writeups avant de commencer.

**Retour :**
```
total 0
drwxr-xr-x 1 ozer ozer   42 13 juil. 11:53 .
drwx------ 1 ozer ozer 1030 13 juil. 11:53 ..
drwxr-xr-x 1 ozer ozer    0 13 juil. 11:53 binaries
drwxr-xr-x 1 ozer ozer    0 13 juil. 11:53 tools
drwxr-xr-x 1 ozer ozer    0 13 juil. 11:53 writeups
```

**Ce qu'on en retient :** les trois dossiers existent, on peut y ranger le sample, les outils et les writeups au fur et à mesure.

### B. Installation des outils d'analyse statique

**Commande :**
```
python3 -m venv ~/ctf-reverse/tools/venv && ~/ctf-reverse/tools/venv/bin/pip install --quiet --upgrade pip flare-capa flare-floss pefile
~/ctf-reverse/tools/venv/bin/capa --version 2>&1
~/ctf-reverse/tools/venv/bin/floss --version 2>&1
~/ctf-reverse/tools/venv/bin/python -c "import pefile; print('pefile OK', pefile.__version__)"
```

**Pourquoi :** le `pip` système est bloqué (environnement Python "externally-managed" sur Arch/Garuda) ; un environnement virtuel dédié isole ces dépendances sans toucher au système. La vérification de version confirme que les outils sont bien installés avant de s'en servir.

**Retour :**
```
capa 9.4.0
floss 3.1.1
pefile OK 2024.8.26
```

**Ce qu'on en retient :** les trois outils sont opérationnels, on peut passer à l'acquisition du sample.

### C. Recherche de l'échantillon sur MalwareBazaar

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_siginfo&signature=StealC&limit=10"
```

**Pourquoi :** les hashs de la campagne Malwarebytes citée en Partie 1 §1 ne sont pas indexés sur MalwareBazaar (échantillon trop récent), donc on élargit la recherche à tous les échantillons récents portant la signature `StealC`. Toute requête à cette API nécessite un header `Auth-Key` (clé gratuite via [auth.abuse.ch](https://auth.abuse.ch/), remplacée par `****` ci-dessous).

**Retour :** (10 entrées renvoyées, extrait)
```
{
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da",
            "md5_hash": "dc8db3908bec45fc19bfb4d2c4514474",
            "first_seen": "2026-07-13 06:38:36",
            "file_size": 2195968,
            "file_type": "exe",
            "file_format": "PE",
            "file_arch": "I386",
            "reporter": "Bitsight",
            "signature": "Stealc",
            "imphash": "646167cce332c1c252cdcb1839e0cf48",
            "tags": ["D", "dropped-by-gcleaner", "EU0.file", "exe", "Stealc"]
        },
        [... 9 autres entrées similaires ...]
    ]
}
```

**Ce qu'on en retient :** 10 échantillons récents disponibles. On retient le premier, SHA256 `afbeeeaa...`, représentatif (imphash partagé avec plusieurs autres entrées de la liste).

### D. Téléchargement de l'échantillon

**Commande :**
```
cd ~/ctf-reverse/binaries && curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
    -H "Auth-Key: ****" \
    -d "query=get_file&sha256_hash=afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da" \
    -o stealc_afbeeeaa.zip
file stealc_afbeeeaa.zip; ls -la stealc_afbeeeaa.zip
```

**Pourquoi :** récupérer le binaire réel identifié à l'étape C.

**Retour :**
```
stealc_afbeeeaa.zip: Zip archive data, made by v6.3 UNIX, extract using at least v5.1, last modified Jul 13 2026 10:06:28, uncompressed size 2195968, method=AES Encrypted
-rw-r--r-- 1 ozer ozer 2146500 13 juil. 12:06 stealc_afbeeeaa.zip
```

**Ce qu'on en retient :** taille conforme à celle annoncée par l'API (2 195 968 octets décompressés), et surtout un chiffrement **AES**, ce qui détermine l'outil d'extraction à utiliser ensuite.

### E. Extraction et vérification du hash

**Commande :**
```
cd ~/ctf-reverse/binaries && 7z x -pinfected stealc_afbeeeaa.zip -y
sha256sum *.exe
```

**Pourquoi :** le zip est chiffré en AES (mot de passe standard `infected`) ; l'`unzip` classique ne supporte que l'ancien chiffrement ZipCrypto, donc `7z` est utilisé directement. Le hash est ensuite recalculé pour vérifier qu'il correspond bien à celui annoncé par MalwareBazaar.

**Retour :**
```
Extracting archive: stealc_afbeeeaa.zip
Everything is Ok
Size:       2195968
Compressed: 2146500
afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da  afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da.exe
```

**Ce qu'on en retient :** hash identique à celui annoncé par l'API, le fichier est intact et c'est bien le bon échantillon.

### F. Retrait des droits d'exécution + identification

**Commande :**
```
cd ~/ctf-reverse/binaries && chmod -x *.exe && file *.exe
```

**Pourquoi :** le sample ne sera jamais exécuté (analyse strictement statique) ; retirer le bit d'exécution évite tout lancement accidentel. `file` confirme le type réel du binaire.

**Retour :**
```
afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da.exe: PE32 executable for MS Windows 6.00 (GUI), Intel i386, 5 sections
```

**Ce qu'on en retient :** un exécutable PE32 Windows classique, seulement 5 sections, cohérent avec un petit stub, pas avec un payload complet.

### G. Parsing des headers PE

**Commande :**
```python
import pefile
pe = pefile.PE('afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da.exe')
print('Entry point:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('Image base:', hex(pe.OPTIONAL_HEADER.ImageBase))
print('Compile timestamp:', pe.FILE_HEADER.TimeDateStamp)
for s in pe.sections:
    print(f'  {s.Name.decode().strip(chr(0)):10s} VirtAddr={hex(s.VirtualAddress):10s} VirtSize={hex(s.Misc_VirtualSize):10s} RawSize={hex(s.SizeOfRawData):10s} entropy={s.get_entropy():.2f}')
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f'  {entry.dll.decode()} ({len(entry.imports)} funcs)')
```

**Pourquoi :** obtenir la structure interne du fichier (sections, entropie, imports) sans le désassembler entièrement, une première vue d'ensemble avant d'aller plus loin.

**Retour :**
```
Entry point: 0x6ce0
Image base: 0x400000
Compile timestamp: 2215452883

Sections:
  .text      VirtAddr=0x1000     VirtSize=0x662c     RawSize=0x6800     entropy=6.26
  .data      VirtAddr=0x8000     VirtSize=0x1aa0     RawSize=0x200      entropy=4.97
  .idata     VirtAddr=0xa000     VirtSize=0x1052     RawSize=0x1200     entropy=5.03
  .rsrc      VirtAddr=0xc000     VirtSize=0x20f68a   RawSize=0x20f800   entropy=7.99
  .reloc     VirtAddr=0x21c000   VirtSize=0x888      RawSize=0xa00      entropy=6.26

Imports:
  ADVAPI32.dll (14 funcs)
  KERNEL32.dll (81 funcs)
  GDI32.dll (1 funcs)
  USER32.dll (30 funcs)
  msvcrt.dll (20 funcs)
  COMCTL32.dll (1 funcs)
  Cabinet.dll (4 funcs)
  VERSION.dll (3 funcs)
```

**Ce qu'on en retient :** `.rsrc` fait à elle seule ~95% du binaire avec une entropie de 7.99/8 (quasi-maximale), un signe fort d'un payload packé/chiffré caché en ressource plutôt que dans `.text`. L'import `Cabinet.dll` renforce l'hypothèse d'une extraction de CAB au runtime.

### H. Conversion du timestamp suspect

**Commande :**
```
python3 -c "import datetime; print(datetime.datetime.utcfromtimestamp(2215452883))"
```

**Pourquoi :** le timestamp de compilation brut relevé à l'étape G (`2215452883`) paraît anormalement grand, on vérifie à quelle date ça correspond réellement.

**Retour :**
```
2040-03-15 19:34:43
```

**Ce qu'on en retient :** date de compilation falsifiée (15/03/2040), une technique d'anti-analyse classique pour perturber le tri chronologique de certains outils et sandbox.

### I. Analyse de capacités avec capa

**Commande :**
```
curl -sL -o capa-rules.zip https://github.com/mandiant/capa-rules/archive/refs/heads/master.zip
unzip -q capa-rules.zip && mv capa-rules-master capa-rules

FLOSS_SIGS=$(find ~/ctf-reverse/tools/venv/lib -type d -path "*/floss/sigs")

capa -r ~/ctf-reverse/tools/capa-rules --signatures "$FLOSS_SIGS" \
     -j afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da.exe > capa_out.json

python3 -c "
import json
d = json.load(open('capa_out.json'))
rules = d.get('rules', {})
print(f'Total capabilities matched: {len(rules)}')
for name, info in rules.items():
    ns = info.get('meta', {}).get('namespace', '')
    print(f'- {name}  [{ns}]')
"
```

**Pourquoi :** capa reconnaît automatiquement des comportements connus (persistance, anti-VM, technique d'installeur...) à partir d'une base de règles, bien plus vite qu'une lecture manuelle du désassemblage. Il faut au préalable son pack de règles officiel et des signatures FLIRT, non fournis par défaut avec le paquet pip, donc celles livrées avec `floss` sont réutilisées. La commande `find` évite de coder en dur le numéro de version de Python du venv (`python3.14` chez moi, mais ce sera différent selon l'environnement). Le résultat est exporté en JSON pour être parcouru proprement.

**Retour :**
```
Total capabilities matched: 47
- link function at runtime on Windows  [linking/runtime-linking]
- modify access privileges  [host-interaction/process/modify]
- create or open mutex on Windows  [host-interaction/mutex]
[... 41 autres, voir Partie 1 §5 pour le détail commenté ...]
- packaged as an IExpress self-extracting archive  [executable/installer/iexpress]
- persist via Run registry key  [persistence/registry/run]
- reference anti-VM strings targeting Xen  [anti-analysis/anti-vm/vm-detection]
- reference analysis tools strings  [anti-analysis]
```

**Ce qu'on en retient :** le fichier est un installeur IExpress, avec persistance via clé `Run`, chaînes anti-VM ciblant Xen, et des indices de détection d'outils d'analyste (détail commenté en Partie 1 §5).

### J. Extraction de chaînes avec floss

**Commande :**
```
timeout 240 floss --no static -q afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da.exe
```

**Pourquoi :** floss cherche spécifiquement les chaînes cachées, décodées en mémoire ou construites dynamiquement, le genre de chaînes qu'un `strings` classique raterait.

**Retour :**
```
i386
\advpack
TMP4351$.TMP
\advapi32.dll
```

**Ce qu'on en retient :** quasiment rien remonté. La logique réelle n'est donc pas dans le code de ce binaire, elle doit être ailleurs (dans les ressources, très volumineuses d'après l'étape G).

### K. Listing des ressources PE

**Commande :**
```python
import pefile
pe = pefile.PE('afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da.exe')
pe.parse_data_directories()
for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    name = rt.name if rt.name else rt.struct.Id
    print('Type:', name)
    for res in rt.directory.entries:
        for e in res.directory.entries:
            data = pe.get_data(e.data.struct.OffsetToData, e.data.struct.Size)
            print('  entry size:', len(data), 'first bytes:', data[:8])
```

**Pourquoi :** confirmer où se trouve exactement le contenu qui gonfle `.rsrc`, repéré à l'étape G.

**Retour :**
```
Type: AVI
  entry size: 11802 first bytes: b'RIFF\x12.\x00\x00'
Type: 3
  [... icônes/dialogues ...]
Type: 10
  entry size: 1979115 first bytes: b'MSCF\x00\x00\x00\x00'
  [...]
  entry size: 25 first bytes: b'"AutoIt3'
Type: 24
  entry size: 2018 first bytes: b'<?xml ve'
```

**Ce qu'on en retient :** une des ressources (type 10, RCDATA) commence par la signature `MSCF` (Microsoft Cabinet). C'est le fichier caché qu'on cherchait.

### L. Extraction du CAB depuis la ressource PE

**Commande :**
```python
import pefile
pe = pefile.PE('afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da.exe')
pe.parse_data_directories()
for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    name = rt.name if rt.name else rt.struct.Id
    if name == 10:
        for res in rt.directory.entries:
            for e in res.directory.entries:
                data = pe.get_data(e.data.struct.OffsetToData, e.data.struct.Size)
                if data[:4] == b'MSCF':
                    open('extracted/payload.cab', 'wb').write(data)
                    print('CAB written, size:', len(data))
```

**Pourquoi :** isoler ce CAB dans un fichier à part pour pouvoir le décompresser avec un outil dédié.

**Retour :**
```
CAB written, size: 1979115
extracted/payload.cab: Microsoft Cabinet archive data, many, 1979115 bytes, 2 files, "Quotes.a3x" last modified Jul 12 2026 16:52:18, "AutoIt3.exe" last modified Jul 12 2026 16:52:40
```

**Ce qu'on en retient :** le CAB contient deux fichiers, `Quotes.a3x` et `AutoIt3.exe`, datés du 12/07/2026, soit la veille de l'analyse.

### M. Extraction du CAB (cabextract)

**Commande :**
```
cd ~/ctf-reverse/binaries/extracted && cabextract payload.cab
sha256sum Quotes.a3x AutoIt3.exe
```

**Pourquoi :** obtenir les deux fichiers en clair pour les identifier et les traiter séparément.

**Retour :**
```
Extracting cabinet: payload.cab
  extracting Quotes.a3x
  extracting AutoIt3.exe
All done, no errors.

49ded704632abe3642b76c32c60d46ab99402495624921787e0c57a85f83327d  Quotes.a3x
92c6531a09180fae8b2aae7384b4cea9986762f0c271b35da09b4d0e733f9f45  AutoIt3.exe
```

**Ce qu'on en retient :** `AutoIt3.exe` est l'interpréteur AutoIt légitime (abusé comme LOLBin) ; `Quotes.a3x` est un script AutoIt compilé, c'est là que se trouve la logique malveillante réelle.

### N. Décompilation du script AutoIt

**Commande :**
```
chmod -x ~/ctf-reverse/binaries/extracted/AutoIt3.exe
pip install --quiet autoit-ripper

cd ~/ctf-reverse/binaries/extracted && autoit-ripper --verbose --ea guess Quotes.a3x ../../decompiled
```

**Pourquoi :** `Quotes.a3x` est un bytecode compilé, illisible tel quel ; `autoit-ripper` sait le décompresser et le reconvertir en script source `.au3`. `AutoIt3.exe` ne sera pas non plus exécuté, mêmes précautions qu'à l'étape F.

**Retour :**
```
DEBUG:autoit_ripper.autoit_unpack:Found a new autoit string: >>>AUTOIT NO CMDEXECUTE<<<
DEBUG:autoit_ripper.autoit_unpack:Found a new autoit string: >>>AUTOIT SCRIPT<<<
DEBUG:autoit_ripper.decompress:decompress: found a correct EA06 compressed blob
INFO:root:Storing result in ../../decompiled/script.au3
```

**Ce qu'on en retient :** décompilation réussie, un fichier `script.au3` en clair est généré.

### O. Inspection du script décompilé

**Commande :**
```
wc -l ~/ctf-reverse/decompiled/script.au3
grep -oE "Func [A-Za-z0-9_]+" ~/ctf-reverse/decompiled/script.au3 | sort -u
```

**Pourquoi :** avoir un premier aperçu de la taille et de la structure du script avant de l'analyser en détail (Partie 2).

**Retour :**
```
17593 /home/ozer/ctf-reverse/decompiled/script.au3

Func BATHROOMREWARDLIVED
Func B_EGYPTAGENCIESADDED
Func BEN_ELECTRON_COSTUMES_HERBAL
[... 23 fonctions au total ...]
```

**Ce qu'on en retient :** script volumineux (17 593 lignes), 23 fonctions aux noms aléatoires, clairement obfusqué. L'analyse détaillée de cette obfuscation fait l'objet de la [§5 du writeup](writeup.md#5-déobfuscation-du-loader-autoit-quotesa3x).

---

## Partie 2 — Déobfuscation du loader AutoIt (Quotes.a3x)

*(récit analytique correspondant : [writeup.md §5–6](writeup.md#5-déobfuscation-du-loader-autoit-quotesa3x))*

### Reproductibilité de bout en bout

Pour rejouer les Parties 1 et 2 à partir de zéro il faut 3 choses :

1. **Le sample** : SHA256 `afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da`, récupérable sur MalwareBazaar (compte gratuit et clé API requis, voir étapes C-D ci-dessus).
2. **Les outils** : `pefile`, `capa`+`capa-rules`, `floss`, `cabextract`, `autoit-ripper` (tous installables via `pip` ou un gestionnaire de paquets, voir étapes B et I ci-dessus).
3. **Le script [`deobfuscate.py`](tools/deobfuscate.py)**, aucune dépendance externe, Python standard uniquement (Python 3.10+, utilise `list[str]`/`tuple[...]` en annotation).

Séquence complète :
```
# Partie 1 : obtenir script.au3
MalwareBazaar (download) → 7z (extraction AES) → pefile (extraction ressource CAB)
  → cabextract (CAB → AutoIt3.exe + Quotes.a3x) → autoit-ripper (Quotes.a3x → script.au3)

# Partie 2 : déobfusquer
python3 deobfuscate.py script.au3 deobfuscated.au3
grep/analyse manuelle sur deobfuscated.au3
```

Aucune étape ne nécessite l'exécution du binaire ni un environnement Windows. Tout est reproductible sur Linux, en analyse 100% statique.

### 1. Exécution du déobfuscateur

**Commande :**
```
cd ~/ctf-reverse/decompiled && python3 ~/ctf-reverse/tools/deobfuscate.py script.au3 deobfuscated.au3
```

**Pourquoi :** appliquer les deux passes du script ([`deobfuscate.py`](tools/deobfuscate.py) : déchiffrement des chaînes `BATHROOMREWARDLIVED` puis résolution des blocs `Switch` aplatis) sur le fichier décompilé en Partie 1.

**Retour :**
```
[pass1] decrypted 11698 BATHROOMREWARDLIVED string(s)
[pass2] resolved 354 Switch block(s), 0 ambiguous/unresolved
Wrote deobfuscated.au3 (3188 lines, was 17594)
```

**Ce qu'on en retient :** le fichier `deobfuscated.au3` est maintenant lisible et 5 fois plus court (3 188 lignes contre 17 594).

### 2. Recherche d'IOC réseau/registre dans le script déobfusqué

**Commande :**
```
cd ~/ctf-reverse/decompiled
grep -oE '"[a-zA-Z0-9.-]+\.(com|net|org|ru|xyz|top|shop|info|io|cc)[^"]*"' deobfuscated.au3 | sort -u
grep -oE '"https?://[^"]*"' deobfuscated.au3 | sort -u
grep -oE '"(HKEY|SOFTWARE|Software)[^"]*"' deobfuscated.au3 | sort -u
grep -ioE '"[a-zA-Z0-9_-]*[Mm]utex[a-zA-Z0-9_-]*"' deobfuscated.au3 | sort -u
```

**Pourquoi :** maintenant que les chaînes sont en clair, chercher directement les indicateurs classiques (domaines, URLs, clés de registre, mutex) avant d'aller plus loin.

**Retour :**
```
"microsoft.com"

(rien pour http(s), registry paths, mutex)
```

**Ce qu'on en retient :** aucun C2 ni mutex en clair. On regarde alors du côté des appels système, souvent plus parlants sur la vraie fonction d'un loader.

### 3. Extraction des cibles DllCall

**Commande :**
```
cd ~/ctf-reverse/decompiled
grep -oE 'DllCall \( "[^"]*"( , "[a-z_]+" , "[A-Za-z0-9_]+")?' deobfuscated.au3 | sort | uniq -c | sort -rn
```

**Pourquoi :** lister toutes les API Windows appelées par le script, pour repérer un éventuel schéma cohérent (ici, manipulation de processus et de mémoire).

**Retour :**
```
      9 DllCall ( "kernel32.dll" , "bool" , "TerminateProcess"
      9 DllCall ( "kernel32.dll" , "bool" , "CloseHandle"
      8 DllCall ( "kernel32.dll" , "dword" , "GetCurrentProcessId"
      6 DllCall ( "ntdll.dll" , "long" , "NtProtectVirtualMemory"
      6 DllCall ( "kernel32.dll" , "handle" , "GetCurrentProcess"
      6 DllCall ( "kernel32.dll" , "dword" , "GetTickCount"
      5 DllCall ( "user32.dll" , "hwnd" , "GetDesktopWindow"
      5 DllCall ( "kernel32.dll" , "handle" , "OpenProcess"
      5 DllCall ( "kernel32.dll" , "bool" , "IsProcessorFeaturePresent"
      4 DllCall ( "user32.dll" , "int" , "GetSystemMetrics"
      4 DllCall ( "user32.dll" , "bool" , "IsWindow"
      4 DllCall ( "kernel32.dll" , "dword" , "GetLastError"
      4 DllCall ( "kernel32.dll" , "bool" , "InitializeProcThreadAttributeList"
      3 DllCall ( "shlwapi.dll" , "bool" , "PathIsDirectoryW"
      3 DllCall ( "ntdll.dll" , "long" , "NtWow64ReadVirtualMemory64"
      3 DllCall ( "ntdll.dll" , "long" , "NtReadVirtualMemory"
      3 DllCall ( "kernel32.dll" , "ptr" , "VirtualAllocExNuma"
      3 DllCall ( "kernel32.dll" , "dword" , "GetActiveProcessorCount"
      2 DllCall ( "user32.dll" , "bool" , "IsWindowVisible"
      2 DllCall ( "ntdll.dll" , "bool" , "NtWriteVirtualMemory"
      2 DllCall ( "kernel32.dll" , "uint" , "SetErrorMode"
      2 DllCall ( "kernel32.dll" , "ptr" , "HeapAlloc"
      2 DllCall ( "kernel32.dll" , "ptr" , "GetProcAddress"
      2 DllCall ( "kernel32.dll" , "ptr" , "GetModuleHandleA"
      2 DllCall ( "kernel32.dll" , "dword" , "GetCurrentThreadId"
      2 DllCall ( "kernel32.dll" , "bool" , "UpdateProcThreadAttribute"
      2 DllCall ( "kernel32.dll" , "bool" , "QueryPerformanceCounter"
      2 DllCall ( "Kernel32.dll"
      1 DllCall ( "psapi.dll" , "dword" , "GetModuleFileNameExW"
      1 DllCall ( "ntdll.dll" , "uint" , "RtlGetCompressionWorkSpaceSize"
      1 DllCall ( "ntdll.dll" , "long" , "NtWow64QueryInformationProcess64"
      1 DllCall ( "ntdll.dll" , "long" , "NtUnmapViewOfSection"
      1 DllCall ( "ntdll.dll" , "long" , "NtQueryInformationProcess"
      1 DllCall ( "ntdll.dll" , "long" , "NtOpenSection"
      1 DllCall ( "ntdll.dll" , "long" , "NtMapViewOfSection"
      1 DllCall ( "ntdll.dll" , "long" , "NtClose"
      1 DllCall ( "ntdll.dll" , "int" , "RtlDecompressFragment"
      1 DllCall ( "ntdll.dll" , "int" , "NtFreeVirtualMemory"
      1 DllCall ( "ntdll.dll" , "dword" , "NtResumeThread"
      1 DllCall ( "ntdll.dll" , "bool" , "NtSetContextThread"
```

**Ce qu'on en retient :** la présence conjointe de `Nt*Section`, `Nt*VirtualMemory`, `NtSetContextThread` et `NtResumeThread` est la signature classique d'un process hollowing.

### 4. Localisation de la séquence de process hollowing

**Commande :**
```
cd ~/ctf-reverse/decompiled
grep -n "NtUnmapViewOfSection\|NtMapViewOfSection\|NtSetContextThread\|NtResumeThread\|NtWriteVirtualMemory\|CreateProcess" deobfuscated.au3
```

**Pourquoi :** retrouver les lignes exactes de ces appels pour reconstituer l'ordre réel des opérations.

**Retour :**
```
555:  $RELOCATIONINJECTIONSEALQUIZZES = DllCall ( "kernel32.dll" , "bool" , "CreateProcessW" , "wstr" , Null , "wstr" , $RAP_STUFFED & " " & $FIBERLYINGPOWERPOINTARMS , [...] )
1035: $RELOCATIONINJECTIONSEALQUIZZES = DllCall ( "ntdll.dll" , "bool" , "NtSetContextThread" , "handle" , $N_CONFUSIONALTERNATIVEGAUGE , "ptr" , DllStructGetPtr ( $FORMULATEMPLELIVE ) )
1151: $RELOCATIONINJECTIONSEALQUIZZES = DllCall ( "ntdll.dll" , "bool" , "NtWriteVirtualMemory" , "handle" , $PACIFIC_ED , "ptr" , $LUGGAGEALA , "ptr" , $M_RECORDREVIEWERCONTRIBUTIONS , "dword_ptr" , $ADMISSIONSFASTSORTS , "dword_ptr*" , 0 )
1178: $RELOCATIONINJECTIONSEALQUIZZES = DllCall ( "ntdll.dll" , "bool" , "NtWriteVirtualMemory" , "handle" , $PACIFIC_ED , "ptr" , $REST_RISKS_ROUTERS_MARKING , "ptr" , DllStructGetPtr ( $BRISTOL_TONE ) , "dword_ptr" , DllStructGetSize ( $BRISTOL_TONE ) , "dword_ptr*" , 0 )
1233: $RELOCATIONINJECTIONSEALQUIZZES = DllCall ( "ntdll.dll" , "dword" , "NtResumeThread" , "handle" , $N_CONFUSIONALTERNATIVEGAUGE , "long*" , 0 )
1929: DllCall ( "ntdll.dll" , "long" , "NtMapViewOfSection" , "handle" , $GOTTENRULEDDIVERSITYWHETHER , "handle" , + 4294967295 , "ptr" , DllStructGetPtr ( $THINKPADBOUTIQUELABOR ) , "ulong_ptr" , 0 , "ulong_ptr" , 0 , "ptr" , 0 , "ptr" , DllStructGetPtr ( $INTENDTALKSOCKSOFFSET ) , "dword" , 1 , "dword" , 0 , "dword" , 2 )
2045: DllCall ( "ntdll.dll" , "long" , "NtUnmapViewOfSection" , "handle" , + 4294967295 , "ptr" , $IMPLEMENTINGHOCKEY )
```

**Ce qu'on en retient :** remises dans l'ordre, ces lignes donnent exactement la séquence décrite en Partie 2 §5.1 : création du process suspendu, démappage puis mappage de section, écriture mémoire, puis redirection et reprise du thread.

### Validation croisée de la résolution des `Switch`

**Commande :**
```
python3 ~/ctf-reverse/tools/validate_crossref.py ~/ctf-reverse/decompiled/script.au3
```

**Pourquoi :** calculer, pour chaque bloc `Switch` du fichier, la réponse de la méthode arithmétique et celle de la méthode `ExitLoop`/`Return` de façon totalement indépendante l'une de l'autre, puis comparer les deux sur l'ensemble des 354 blocs plutôt que sur les 2 exemples montrés en Partie 2 §2. Script complet : [`validate_crossref.py`](tools/validate_crossref.py).

**Retour :**
```
Total Switch blocks found: 354
Both methods gave a unique answer: 351
  - agree:    351
  - disagree: 0
Only method A (arithmetic) resolved: 1
Only method B (ExitLoop/Return) resolved: 1
Neither method resolved: 1
```

**Ce qu'on en retient :** sur les 351 blocs où les deux méthodes donnent chacune une réponse unique, elles concordent dans 100% des cas, sans un seul désaccord. C'est une validation croisée systématique de l'hypothèse de réinterprétation des grandes constantes, pas juste un recoupement anecdotique sur quelques exemples choisis à la main.

Correction apportée après la première exécution : la recherche de l'expression d'initialisation ne regardait que 5 lignes en arrière, ce qui a produit 3 blocs faussement classés "non résolus" alors que leur assignation se trouvait 6 lignes plus haut (à cheval sur un bloc `If`/`Else`). `deobfuscate.py` et `validate_crossref.py` incluent désormais la correction (fenêtre élargie à 60 lignes). Un de ces 3 blocs, une fois relu, s'est révélé intéressant : voir [writeup.md §7.5](writeup.md#75-gestion-explicite-des-deux-architectures-context-x86x64).

### Identification du crypter par recherche d'imphash

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_imphash&imphash=646167cce332c1c252cdcb1839e0cf48&limit=50"
```

**Pourquoi :** l'imphash (`646167cce332c1c252cdcb1839e0cf48`) est partagé entre plusieurs échantillons soumis à MalwareBazaar. Interroger cette API remonte tous les échantillons avec le même imphash, avec leurs tags communautaires, ce qui peut révéler un nom de crypter déjà identifié par d'autres analystes.

**Retour :** (extrait, 50 échantillons, tags uniques agrégés)
```
Tags observés across all: ['87-120-104-81', 'ACRStealer', 'Amadey', 'AsgardProtector',
'ClickFix', 'D', 'DeerStealer', ..., 'LummaStealer', 'MaskGramStealer', 'NjRAT',
'PureLogsStealer', 'QuasarRAT', 'RemusStealer', 'Stealc', ..., 'dropped-by-gcleaner',
'dropped-by-amadey', ..., 'vidar']
```

**Ce qu'on en retient :** deux choses, détaillées en Partie 2 §5.4 et Partie 1 §1 — le tag `AsgardProtector` apparaît sur plusieurs échantillons partageant cet imphash (piste d'attribution du crypter), et ce même imphash est aussi partagé par des familles n'ayant rien à voir avec StealC (Amadey, LummaStealer, Vidar, QuasarRAT, NjRAT...), ce qui confirme qu'il fingerprinte le stub du crypter, pas StealC spécifiquement.

---

## Partie 3 — Persistance et évasion anti-AV du loader AutoIt

*(récit analytique correspondant : [writeup.md §7](writeup.md#7-persistance-et-évasion-anti-av))*

### 1. Décodage des `ChrW` calculés

**Commande :**
```
python3 ~/ctf-reverse/tools/decode_chrw.py ~/ctf-reverse/decompiled/deobfuscated.au3 ~/ctf-reverse/decompiled/deobfuscated_chrw.au3
```

**Pourquoi :** une inspection du mécanisme de persistance a révélé des appels `ChrW(<expression>)` non concernés par le déchiffrement de la Partie 2. [`decode_chrw.py`](tools/decode_chrw.py) les résout indépendamment.

**Retour :**
```
Decoded 16 ChrW(...) call(s)
Wrote deobfuscated_chrw.au3
```

**Ce qu'on en retient :** seulement 16 occurrences dans tout le fichier, ce qui reste gérable à relire à la main une fois décodées.

### 2. Recherche d'un gros blob de payload embarqué

**Commande :**
```
cd ~/ctf-reverse/decompiled
awk '{ print length, NR }' deobfuscated.au3 | sort -rn | head -15
grep -oE '"0x[0-9A-Fa-f]{200,}"' deobfuscated.au3 | awk '{print length}' | sort -rn | head -5
```

**Pourquoi :** les appels `RtlGetCompressionWorkSpaceSize`/`RtlDecompressFragment` trouvés en Partie 2 impliquent qu'un payload compressé existe quelque part. Avant de chercher plus loin, on vérifie s'il est embarqué directement dans le script sous forme de chaîne.

**Retour :** aucune chaîne de plus de ~2,2 Ko trouvée (le plus gros blob fait environ 1,1 Ko une fois décodé en binaire).

**Ce qu'on en retient :** rien d'assez gros pour être un exécutable StealC complet (plusieurs centaines de Ko à quelques Mo en général). Le payload final n'est donc pas embarqué en clair dans ce script : soit il est téléchargé au runtime par une étape ultérieure, soit il provient d'un mécanisme non couvert par cette analyse statique. (La Partie 4 confirme via une source tierce qu'il est livré/injecté séparément.)

### 3. Inventaire des vérifications anti-AV

**Commande :**
```
grep -n 'ProcessExists' ~/ctf-reverse/decompiled/deobfuscated.au3
```

**Pourquoi :** cataloguer systématiquement toutes les vérifications de processus plutôt que de s'arrêter aux deux ou trois trouvées par hasard en cherchant autre chose.

**Retour :**
```
404:If ProcessExists ( "vmtoolsd.exe" ) = True Or ProcessExists ( "VboxTray.exe" ) = True Or ProcessExists ( "SandboxieRpcSs.exe" ) Then Exit
433:   ... ProcessExists ( "explorer.exe" ) ...
551: If ProcessExists ( "avp.exe" ) Then $KNIFEMINACIDCLASSROOM = 134217732
1279: ( Call ( "ProcessExists" , "avastui.exe" ) ) ? LOPEZFUNDING ( ( 19980 + 20 ) ) : ( Opt ( "TrayIconHide" , 13175634 / 13175634 ) )
1555: If ProcessExists ( "AvastUI.exe" ) Or ProcessExists ( "AVGUI.exe" ) Or ProcessExists ( "bdagent.exe" ) Or ProcessExists ( "SophosHealth.exe" ) Then $BASSBROKECONVERTIBLEPOPULATIONS = ...
1586: If ProcessExists ( "AvastUI.exe" ) Or ProcessExists ( "AVGUI.exe" ) Or ProcessExists ( "SophosHealth.exe" ) Then $SURPLUSESTABLISH = ...
1589: If ProcessExists ( "bdagent.exe" ) Then $YEN_SHERIFF = "cscript"
1721:   ... ProcessExists ( "explorer.exe" ) ...
3226: If ProcessExists ( "bdagent.exe" ) Then LOPEZFUNDING ( ( 794769 + 4294332527 ) )
```

**Ce qu'on en retient :** 8 occurrences au total, formant l'inventaire complet présenté en Partie 3 §4, plus le kill switch VM/sandbox et le ciblage `explorer.exe` pour le spoofing de PPID.

### 4. Décodage des durées de pause liées aux AV

**Commande :**
```python
def fix32(v):
    v = v % (2**32)
    return v - 2**32 if v >= 2**31 else v
print(fix32(19980 + 20))
print(fix32(794769 + 4294332527))
```

**Pourquoi :** convertir les arguments passés à `LOPEZFUNDING()` en durées lisibles pour confirmer les temps de pause exacts.

**Retour :**
```
20000
160000
```

**Ce qu'on en retient :** 20 secondes pour Avast, 160 secondes pour Bitdefender. Le deuxième calcul a d'abord été fait avec la règle de réinterprétation simplifiée de la Partie 2 (plage `[2^31,2^32[`) et donnait un résultat faux, la somme dépassant légèrement `2^32`. La correction (modulo 2^32 avant de re-signer) est documentée en Partie 3 §5.

### 5. Correction de la fenêtre de recherche et nouvelle exécution

**Commande :**
```
cd ~/ctf-reverse/decompiled
python3 ~/ctf-reverse/tools/deobfuscate.py script.au3 deobfuscated.au3
python3 ~/ctf-reverse/tools/validate_crossref.py script.au3
```

**Pourquoi :** après avoir élargi à 60 lignes la fenêtre de recherche de l'expression d'initialisation (fixée à 5 lignes à l'origine, voir Partie 3 §7), régénérer le fichier déobfusqué et revalider les statistiques de résolution.

**Retour :**
```
[pass1] decrypted 11698 BATHROOMREWARDLIVED string(s)
[pass2] resolved 354 Switch block(s), 0 ambiguous/unresolved
Wrote deobfuscated.au3 (3188 lines, was 17594)

Total Switch blocks found: 354
Both methods gave a unique answer: 351
  - agree:    351
  - disagree: 0
Only method A (arithmetic) resolved: 1
Only method B (ExitLoop/Return) resolved: 1
Neither method resolved: 1
```

**Ce qu'on en retient :** `deobfuscate.py` résout maintenant les 354 blocs sans laisser de branche ambiguë dans le fichier final. Les 3 blocs où les deux méthodes ne donnent pas chacune une réponse indépendante ne sont pas de vraies ambiguïtés : ce sont de petits `Switch` de type table de correspondance (dont celui décrit en Partie 3 §7), sans `ExitLoop`, ce qui est normal pour ce genre de bloc et a été confirmé à la main.

---

## Partie 4 — Confirmation externe et infrastructure de campagne

*(récit analytique correspondant : [writeup.md §8](writeup.md#8-confirmation-externe-et-infrastructure-de-campagne))*

### 1. Lecture complète de la fiche MalwareBazaar de l'échantillon

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_info&hash=afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da"
```

**Pourquoi :** les analyses précédentes n'avaient regardé que quelques champs de cette réponse (hash, tags, imphash). Relire la réponse complète pour voir ce qui avait été manqué (commentaires, sandbox tiers, vendor intel).

**Retour :** (extrait pertinent)
```
"comment": "url: http://158.94.209.95/service",
"file_information": [{"context": "dropped_by_malware", "value": "Gcleaner"}, ...],
"vendor_intel": {
    "Triage": {
        "malware_family": "stealc",
        "link": "https://tria.ge/reports/260713-hewm3sey3t/",
        "tags": ["family:stealc", "botnet:euromix", ...],
        "malware_config": [{"extraction": "c2", "family": "stealc",
                             "c2": "http://160.20.109.75/d19ca32cb5a444ac8b87.php"}]
    }, ...
}
```

**Ce qu'on en retient :** un rapport de sandbox dynamique public existe déjà pour ce hash exact, avec la config C2 extraite automatiquement — par un tiers (Triage), pas par nous.

### 2. Vérification indépendante du C2 sur ThreatFox

**Commande :**
```
curl -s -X POST https://threatfox-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d '{"query":"search_ioc","search_term":"160.20.109.75"}'
```

**Pourquoi :** confirmer le C2 extrait par Triage via une deuxième source indépendante, et voir depuis quand/à quelle fréquence il est observé.

**Retour :**
```
"ioc": "http://160.20.109.75/d19ca32cb5a444ac8b87.php",
"malware_printable": "Stealc",
"confidence_level": 75,
"first_seen": "2026-07-07 23:55:49 UTC",
"last_seen": "2026-07-13 11:28:24 UTC",
"sightings": 431
```

**Ce qu'on en retient :** C2 actif depuis au moins une semaine, 431 observations, dernière vue le jour même de cette analyse.

### 3. Recherche du deuxième échantillon lié

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_info&hash=8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52"
```

**Pourquoi :** ce hash apparaissait dans la référence ThreatFox du C2 ; vérifier s'il partage d'autres traits avec notre échantillon.

**Retour :** mêmes commentaire de livraison et tag `dropped-by-GCleaner`, même C2 confirmé par un rapport Triage distinct, mais imphash et architecture différents.

**Ce qu'on en retient :** deux builds distincts de la même infrastructure de campagne, pas un doublon du même fichier.

### 4. Vérification passive de l'activité du C2 (sans s'y connecter)

**Commande :**
```
curl -s "https://internetdb.shodan.io/160.20.109.75"
```

**Pourquoi :** savoir si le serveur répond toujours sans jamais lui envoyer de requête directement (Shodan a déjà fait le scan de son côté ; on ne fait qu'interroger leur base).

**Retour :**
```
"ports": [22, 80],
"cpes": ["cpe:/a:f5:nginx:1.24.0", "cpe:/a:openbsd:openssh:9.6p1", ...],
"tags": ["eol-product"]
```

**Ce qu'on en retient :** port 80 ouvert, cohérent avec un panel C2 HTTP toujours en service. Pas une preuve à 100% que l'endpoint précis répond encore, mais une bonne indication combinée à la dernière observation ThreatFox du jour même.

*(Note : une tentative de soumettre un scan à urlscan.io, qui aurait fourni une confirmation plus directe via leur propre infrastructure de crawl, a échoué faute de clé API. Piste laissée ouverte si besoin d'aller plus loin.)*
