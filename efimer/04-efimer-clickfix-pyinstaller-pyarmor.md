# Writeup : dropper Efimer (ClickFix + PyInstaller + PyArmor 8.x)

**Date d'analyse :** 15/07/2026
**Analyste :** Gordon PEIRS
**Type :** Analyse statique uniquement (aucune exécution du sample)
**Famille :** Efimer (crypto-clipper / WordPress botnet, non documenté publiquement)

## 1. Contexte

Cet article inaugure une nouvelle série, indépendante de la série StealC (Parties 1–3). Il s'agit cette fois d'un **dropper Python** distribué via **ClickFix**, une technique d'ingénierie sociale apparue fin 2024 et devenue très répandue en 2025–2026. Le principe : une fausse page de vérification CAPTCHA invite la victime à presser `Win+R` puis à coller (Ctrl+V) une commande PowerShell préalablement chargée dans le presse-papiers par la page web.

L'échantillon a été récupéré sur [MalwareBazaar](https://bazaar.abuse.ch/) via la recherche `tag:clickfix`. Parmi les résultats disponibles en juillet 2026, ce sample a été retenu car il présente une stack de protection Python peu documentée : **PyInstaller** (bundle d'exécutable autonome) + **PyArmor 8.x** (protection cryptographique du bytecode). La famille « Efimer » ne correspond à aucun nom officiel publié : le nom est dérivé du seul label MalwareBazaar disponible (`efimer`).

## 2. Identité de l'échantillon

| Champ | Valeur |
|---|---|
| SHA256 | `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4` |
| Taille | 14 309 985 octets (~14,3 Mo) |
| Type | PE32+ executable (x86-64, Windows, GUI) |
| Magic bytes | `MZ` |
| Tag MalwareBazaar | `clickfix`, `efimer` |
| Première observation | 2026-07-14 |

## 3. Outils utilisés

| Outil | Usage |
|---|---|
| `pefile` (Python) | Parsing des headers PE |
| [`pyinstxtractor`](https://github.com/extremecoders-re/pyinstxtractor) | Extraction du bundle PyInstaller |
| `marshal` (stdlib Python) | Inspection manuelle du bytecode `.pyc` |
| [`Pyarmor-Static-Unpack-1shot`](https://github.com/sfewer-r7/Pyarmor-Static-Unpack-1shot) v0.4.0 | Contournement statique de PyArmor 8.x |
| `pycdc` (embarqué dans 1shot) | Décompilation Python 3.13 → source |

Tout le travail a été réalisé sur **Arch Linux**, Python 3.14 (système), venv dédié `~/ctf-reverse/tools/venv/` pour les paquets non disponibles dans les dépôts.

## 4. Analyse statique initiale : PE Headers

Parsing `pefile` sur le binaire : **14 309 985 octets**, entry point `0x1350`. Les sections et imports révèlent immédiatement la nature du fichier.

| Section | Entropie |
|---|---|
| `.text` | 6.26 |
| `.rdata` | 5.90 |
| `.data` | 4.91 |
| `.rsrc` | **7.56** |
| `.pdata` | 6.42 |

Import direct de `python313.dll`, c'est sans équivoque un **bundle PyInstaller** embarquant Python 3.13 et son interpréteur. L'entropie de `.rsrc` (7.56) indique une ressource compressée, cohérente avec le contenu d'un PyInstaller frozen archive.

## 5. Identification du bundle PyInstaller

`strings` sur le binaire révèle les signatures caractéristiques laissées par PyInstaller dans le stub PE :

```
PyInstaller-5.13.2
_MEIPASS
PYZ-00.pyz
pyi-windows-manifest-filename
```

Version confirmée : **PyInstaller 5.13.2**, Python 3.13. PyInstaller crée un stub PE qui, au runtime, extrait un répertoire temporaire (`_MEIPASS`) contenant le bytecode Python et les dépendances. Ici on reste strictement statique : extraction directe.

## 6. Extraction du bundle : pyinstxtractor

`pyinstxtractor` analyse la CArchive PyInstaller et extrait **37 fichiers**, dont l'entrée principale `installer.pyc` et une DLL inhabituelle : `pyarmor_runtime_000000/pyarmor_runtime.pyd` (625 Ko), première présence de PyArmor.

```
[+] Found 37 files in CArchive
[+] Possible entry point: installer.pyc
```

Parmi les fichiers extraits : les payloads chiffrés sont regroupés dans un répertoire `data_p002/` (7 fichiers), et un module Python `campus.py` est présent mais ne correspond à rien d'immédiatement identifiable à ce stade.

## 7. Découverte de la protection PyArmor 8.x

Première tentative d'inspection du bytecode : `marshal.loads(data[12:])`, offset standard des `.pyc` Python 3.8–3.11. Python retourne `ValueError: bad marshal data`. Python 3.13 a ajouté un champ supplémentaire dans le header `.pyc`, portant la taille à **16 octets** (magic 4 + bit field 4 + source_size 4 + source_hash 4). Correction : `marshal.loads(data[16:])`.

La structure révélée est atypique :

```
co_names: ('pyarmor_runtime_000000', '__pyarmor__', '__name__', '__file__')
blob: <class 'bytes'> 42386 octets, magic=5059303030303030 → b'PY000000'
```

Le seul code visible dans `installer.pyc` est le chargement du runtime PyArmor et l'appel à `__pyarmor__`, tout le reste est dans un blob de 42 386 octets dont les 8 premiers octets sont `PY000000`, signature propriétaire **PyArmor 8.x**. Le bytecode réel a été chiffré AES-GCM avec une clé enveloppée par ECC, déchiffrée à l'exécution par `pyarmor_runtime.pyd`.

`strings` sur la DLL elle-même complète le tableau :
- `LibTomCrypt` (bibliothèque crypto utilisée pour AES-GCM)
- `IsDebuggerPresent` (anti-debug)
- `GetAdaptersAddresses`, `GetComputerNameA` (fingerprinting hardware, la licence PyArmor est liée à la machine cible)
- `WS2_32.dll → connect, send, recv, gethostbyname` (trafic réseau dans le runtime, surprenant pour un déchiffreur de bytecode, mais attendu pour PyArmor : la version commerciale/trial intègre une **vérification de licence à distance** et un mécanisme de **Network Time** qui valide l'horodatage d'expiration de la licence au démarrage. Ces imports sont natifs de l'enveloppe PyArmor, pas du malware lui-même. Le nonce `i.non-profit` dans le blob suggère une licence de type "non commercial" ou un build de développement avec restrictions d'expiration différées)

## 8. Contournement statique : Pyarmor-Static-Unpack-1shot

PyArmor 8.x est généralement considéré incontournable de façon statique. L'outil [`Pyarmor-Static-Unpack-1shot`](https://github.com/sfewer-r7/Pyarmor-Static-Unpack-1shot) v0.4.0 exploite le fait que `pyarmor_runtime.pyd` est une DLL classique et que la clé AES utilisée pour chiffrer le blob est stockée en clair dans ses données statiques, à un offset localisable par pattern matching.

Résultat de l'exécution :

```
[*] Scanning pyarmor_runtime.pyd for AES key...
[+] AES key : ab738f35ffce23b13ae73d5a2c17a896
[+] Nonce   : 692e6e6f6e2d70726f666974  → "i.non-profit"
[*] Decrypting blob (42386 bytes)...
[+] installer.pyc.1shot.cdc.py  , source décompilé
[+] installer.pyc.1shot.das     , désassemblage complet (6 023 lignes)
```

La clé AES `ab738f35ffce23b13ae73d5a2c17a896` et le nonce `i.non-profit` (lisible en ASCII, inhabituel pour un composant de sécurité, possible artefact d'un build de développement) permettent de déchiffrer le blob PyArmor sans exécution. La décompilation via `pycdc` produit un source Python partiellement lisible.

## 9. Inspection du source décompilé

`installer.pyc.1shot.cdc.py` est incomplet : `pycdc` marque plusieurs fonctions `# WARNING: Decompyle incomplete`, les constructions Python 3.13 combinées aux artefacts PyArmor résiduels dépassent les capacités du décompilateur. Les fonctions critiques (`main`, `obfsc_script`, `build_script`) sont entièrement indisponibles en source. Pour ces sections, on bascule sur le désassemblage `.das` (6 023 lignes) et on lit directement les opcodes, fastidieux mais fiable.

Les constantes globales, elles, sont immédiatement exploitables :

```python
XOR_KEY        = 'Is8xqLVw7pTB'
GEOINFO_URL    = 'https://ipinfo.io/country'
COUNTRY_FILE   = 'cinfo.inf'
MYBASE_FOLDER  = 'C:\\Users\\Public\\Videos\\'
TARGET_FOLDER  = MYBASE_FOLDER + daily_random_slug(0)
DRIVE_LETTERS  = ['D', 'E', 'F', 'G', 'X', 'Y', 'Z']
```

Points clés :
- `XOR_KEY = 'Is8xqLVw7pTB'` : clé XOR 12 octets pour déchiffrer les payloads de `data_p002/`
- `daily_random_slug(N)` : nom aléatoire mais **déterministe par jour** (seed = `int(time.time() // 86400)`), les noms de dossiers et tâches changent chaque jour, les IoC path-based sont obsolètes en 24h
- `C:\Users\Public\Videos\` : dossier de dépose, accessible sans élévation de privilèges
- `DRIVE_LETTERS` : lettres de lecteurs surveillées, prévues pour la propagation USB

Le désassemblage complet (`installer.pyc.1shot.das`, 6 023 lignes) confirme toutes les fonctions présentes : `xor_decrypt`, `decrypt_data`, `get_country_code`, `get_crypto_user`, `add_to_schtask`, `obfsc_script`, `build_script`, `check_sandbox_fast`, `add_defn_exclusion`.

## 10. IOCs consolidés (Partie 1)

| Type | Valeur |
|---|---|
| SHA256 (dropper) | `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4` |
| Famille PyInstaller | 5.13.2 |
| Python embarqué | 3.13 |
| Module protégé | `installer.pyc` |
| Module dormant | `campus.py` (build env PyInstaller 6.20.0 de l'attaquant, non importé) |
| Clé AES PyArmor | `ab738f35ffce23b13ae73d5a2c17a896` |
| Nonce PyArmor | `692e6e6f6e2d70726f666974` (`i.non-profit`) |
| Clé XOR payload | `Is8xqLVw7pTB` (12 octets, répétitif) |
| Dossier de dépose | `C:\Users\Public\Videos\[daily_slug]\` |
| Geo-filter URL | `https://ipinfo.io/country` (consulté, pas de filtre côté client) |
| Anti-sandbox | `%APPDATA%\Microsoft\Windows\Recent` < 32 fichiers → abort |
| AV bypass | `Add-MpPreference` exclusions paths + `cmd.exe`/`clip.exe` exclusions process |

## 11. Prochaines étapes (Partie 2)

La Partie 2 analyse les **payloads déchiffrés**, sept fichiers extraits du répertoire `data_p002` et décryptés via la clé XOR `Is8xqLVw7pTB`, ainsi que le module `campus.py` :

- `uusd.exe` (8,6 Mo) : identification inattendue → **démon Tor** (SOCKS5 sur `127.0.0.1:9050`)
- `002a.txt` (1,5 Mo / ~40 000 lignes) : **liste d'adresses Bitcoin** pour hijacking presse-papiers
- `002w.txt` (2 047 lignes) : **wordlist BIP39** pour détection de phrases mnémoniques
- `002.xml` (UTF-16 LE) : **template de tâche planifiée** Windows (toutes les 60s)
- `002_n.js` : **moniteur presse-papiers** multi-devises (BTC×4, ETH, TRX, XMR, BIP39) + exfiltration via Tor (`hek5ensy[...].onion`)
- `002_b.js` : **bruteforcer XMLRPC WordPress** multi-thread (C2 : `gfoqsewp[...].onion`)
- `pack.js` : stub template de déchiffrement XOR dynamique
- `campus.py` : **module dormant**, archive RAR5 (~247 Ko) contenant l'environnement de build PyInstaller 6.20.0 de l'attaquant (`User@DESKTOP-UOB4Aig`, 2026-05-30). Fuite OPSEC accidentelle.

---

## Annexe : Reproduire l'analyse pas à pas

### A. Setup de l'environnement

**Commande :**
```bash
mkdir -p ~/ctf-reverse/{samples/clickfix/efimer,tools,decompiled/clickfix/efimer/{unpacked,decrypted}}
python3 -m venv ~/ctf-reverse/tools/venv
~/ctf-reverse/tools/venv/bin/pip install --quiet pefile
```

**Pourquoi :** `pefile` n'est pas dans les dépôts Arch, et le gestionnaire `pip` système est bloqué (environnement Python externally-managed). Le venv isole la dépendance.

### B. Récupération du sample via MalwareBazaar

**Commande :**
```bash
curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
    -H "Auth-Key: ****" \
    -d "query=get_taginfo&tag=clickfix&limit=20" | python3 -m json.tool | grep sha256
```

**Pourquoi :** les tags MalwareBazaar `clickfix` et `efimer` permettent de cibler directement les échantillons de cette famille. La clé API est disponible gratuitement via [auth.abuse.ch](https://auth.abuse.ch/).

**Retour (extrait) :**
```json
"sha256_hash": "a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4"
```

**Ce qu'on en retient :** l'échantillon est disponible, on procède au téléchargement.

### C. Téléchargement et vérification

**Commande :**
```bash
curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
    -H "Auth-Key: ****" \
    -d "query=get_file&sha256_hash=a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4" \
    -o efimer.zip

7z x -pinfected efimer.zip -o samples/clickfix/efimer/
chmod -x samples/clickfix/efimer/*.exe
sha256sum samples/clickfix/efimer/*.exe
```

**Pourquoi :** MalwareBazaar livre les fichiers dans un zip AES chiffré (mot de passe standard `infected`) ; `unzip` classique ne supporte que ZipCrypto donc `7z` est requis. Le bit d'exécution est retiré immédiatement (analyse strictement statique).

### D. Détection PyInstaller

**Commande :**
```bash
strings samples/clickfix/efimer/a9b557*.exe | grep -iE "PyInstaller|python[0-9]+\.dll|PYZ-"
```

**Pourquoi :** PyInstaller laisse systématiquement des chaînes caractéristiques dans le stub PE (version de PyInstaller, DLL Python importée, nom de l'archive PYZ).

**Retour :**
```
PyInstaller-5.13.2
python313.dll
PYZ-00.pyz
```

**Ce qu'on en retient :** PyInstaller 5.13.2 avec Python 3.13 confirmés.

### E. Extraction du bundle PyInstaller

**Commande :**
```bash
git clone https://github.com/extremecoders-re/pyinstxtractor.git tools/pyinstxtractor/

python3 tools/pyinstxtractor/pyinstxtractor.py \
    samples/clickfix/efimer/a9b557*.exe \
    --output decompiled/clickfix/efimer/a9b557*.exe_extracted/

ls decompiled/clickfix/efimer/a9b557*.exe_extracted/
```

**Pourquoi :** pyinstxtractor analyse la structure CArchive du bundle PyInstaller (table de fichiers + données compressées) et extrait tous les fichiers `.pyc`, DLLs et ressources embarquées, sans exécuter le binaire.

**Retour :**
```
[+] Found 37 files in CArchive
[+] Possible entry point: installer.pyc
[+] PYZ archive found, extracting...

installer.pyc
python313.dll
pyarmor_runtime_000000/
  pyarmor_runtime.pyd    (625 KB)
VCRUNTIME140.dll
[...]
```

**Ce qu'on en retient :** 37 fichiers, dont `pyarmor_runtime.pyd`, la présence de ce fichier est la signature de PyArmor.

### F. Confirmation de la protection PyArmor

**Commande :**
```bash
python3 -c "
import marshal, sys
data = open('decompiled/clickfix/efimer/a9b557*_extracted/installer.pyc','rb').read()
code = marshal.loads(data[16:])  # sauter header .pyc 3.13 (16 octets)
print('co_names:', code.co_names)
blob = next(c for c in code.co_consts if isinstance(c, bytes) and len(c) > 100)
print(f'blob: {len(blob)} octets, magic={blob[:8].hex()} → {blob[:8]!r}')
"
```

**Pourquoi :** Python permet d'inspecter un objet `code` compilé via `marshal.loads` sans l'exécuter. Le header standard `.pyc` fait 16 octets sur Python 3.13 (magic 4 octets + 3 champs 4 octets). Le blob `PY000000` est le cœur chiffré.

**Erreur rencontrée :** première tentative avec `data[12:]` (offset Python 3.8–3.11) → `ValueError: bad marshal data`. Python 3.13 a ajouté un champ supplémentaire dans le header `.pyc`, portant la taille à 16 octets. Correction : `data[16:]`.

**Retour :**
```
co_names: ('pyarmor_runtime_000000', '__pyarmor__', '__name__', '__file__')
blob: 42386 octets, magic=5059303030303030 → b'PY000000'
```

**Ce qu'on en retient :** structure PyArmor 8.x confirmée. `co_names` montre que le seul code visible dans `installer.pyc` est le chargement du runtime PyArmor et l'appel à `__pyarmor__`, tout le reste est dans le blob chiffré.

### G. Contournement PyArmor : extraction de la clé AES

**Commande :**
```bash
# Récupérer le binaire Linux de l'outil (GitHub releases)
wget -O /tmp/pyarmor1shot.zip \
  https://github.com/sfewer-r7/Pyarmor-Static-Unpack-1shot/releases/download/v0.4.0/\
Pyarmor-Static-Unpack-1shot-linux-amd64.zip

unzip /tmp/pyarmor1shot.zip -d /tmp/pyarmor1shot-extract/
cp /tmp/pyarmor1shot-extract/oneshot/pyarmor-1shot tools/pyarmor-1shot/oneshot/
chmod +x tools/pyarmor-1shot/oneshot/pyarmor-1shot
```

**Pourquoi :** Pyarmor-Static-Unpack-1shot analyse le binaire `pyarmor_runtime.pyd` pour localiser la clé AES stockée dans ses données statiques, l'outil sait où PyArmor 8.x place cette clé grâce au reverse engineering de la DLL.

**Retour installation :**
```
[ok] pyarmor-1shot copié dans tools/pyarmor-1shot/oneshot/
```

### H. Déchiffrement et décompilation

**Commande :**
```bash
tools/pyarmor-1shot/oneshot/pyarmor-1shot \
    decompiled/clickfix/efimer/a9b557*_extracted/pyarmor_runtime_000000/pyarmor_runtime.pyd \
    decompiled/clickfix/efimer/a9b557*_extracted/installer.pyc \
    --output decompiled/clickfix/efimer/unpacked/
```

**Pourquoi :** l'outil passe deux arguments : la DLL PyArmor (source de la clé AES) et le `.pyc` protégé (à déchiffrer). Il déchiffre le blob AES-GCM et appelle `pycdc` pour produire le source Python.

**Retour :**
```
[*] Scanning pyarmor_runtime.pyd for AES key...
[+] AES key : ab738f35ffce23b13ae73d5a2c17a896
[+] Nonce   : 692e6e6f6e2d70726f666974
[*] Decrypting blob (42386 bytes)...
[+] installer.pyc.1shot.cdc.py  , source décompilé
[+] installer.pyc.1shot.das     , désassemblage complet (6023 lignes)
```

**Ce qu'on en retient :** PyArmor contourné statiquement. Le nonce (`i.non-profit` en ASCII) est lisible, peu habituel pour un élément de sécurité, suggère peut-être un build de développement ou un artefact délibéré.

### I. Lecture du source décompilé

**Commande :**
```bash
head -50 decompiled/clickfix/efimer/unpacked/installer.pyc.1shot.cdc.py
grep -E "^[A-Z_]+ = " decompiled/clickfix/efimer/unpacked/installer.pyc.1shot.cdc.py
```

**Pourquoi :** les constantes globales sont les informations les plus immédiatement exploitables : clés de chiffrement, URLs de C2, chemins de dépose.

**Retour :**
```python
XOR_KEY         = 'Is8xqLVw7pTB'
VERSION_FLAG    = '__VERSION_FLAG__'
CRYPTO_FLAG_F   = 'crypto.inf'
GEOINFO_URL     = 'https://ipinfo.io/country'
COUNTRY_FILE    = 'cinfo.inf'
MYBASE_FOLDER   = 'C:\\Users\\Public\\Videos\\'
DRIVE_LETTERS   = ['D', 'E', 'F', 'G', 'X', 'Y', 'Z']
```

**Erreur rencontrée :** `installer.pyc.1shot.cdc.py` contient de nombreuses sections marquées `# WARNING: Decompyle incomplete`, `pycdc` ne peut pas décompiler certaines constructions PyArmor résiduelles dans le bytecode Python 3.13. Pour les fonctions incomplètes (`main`, `obfsc_script`, etc.), le désassemblage `.das` est utilisé en complément : les opcodes Python 3.13 (`LOAD_CONST`, `CALL`, `RETURN_VALUE`) sont lisibles et permettent de reconstruire la logique manquante manuellement.

**Ce qu'on en retient :** la clé XOR `Is8xqLVw7pTB` est le prochain outil à utiliser pour déchiffrer les fichiers payloads, objet de la [Partie 2](05-efimer-payload-analysis.md).
