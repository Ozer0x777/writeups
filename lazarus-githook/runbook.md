# Runbook — Lazarus githook (DEV#POPPER)

Étapes reproductibles pour cette analyse. Nécessite Python 3.10+ et les samples dans le répertoire courant.

---

## 1. Identification initiale

```bash
# Vérifier le type des fichiers
file a129de4f*.sh 02e6fbf7*.unknown a3f41333*.js 683a1607*.js b34aa84e*.py cd3b606d*.py
# Résultats attendus :
# .sh     : ASCII text (POSIX shell script)
# .unknown: ASCII text (JavaScript sur une ligne, obfuscator.io)
# .js     : idem
# .py     : Python script, CRLF line terminators

# Compter les lignes
wc -l *.js *.unknown *.py
# Les .js doivent être sur 1 ligne (minifiés)

# Vérifier les hashes
sha256sum a129de4f*.sh 02e6fbf7*.unknown a3f41333*.js 683a1607*.js b34aa84e*.py cd3b606d*.py
```

---

## 2. Lecture du git hook

```bash
cat a129de4f*.sh
# Révèle 3 endpoints OS-spécifiques sur 144.172.103.226
# Format : curl/wget | sh pour Linux/macOS, | cmd pour Windows
```

---

## 3. Désobfuscation des 3 stages JS

L'outil [`tools/js_deobf.py`](tools/js_deobf.py) gère les trois stages. Il détecte automatiquement le nom du tableau, la fonction de lookup, sa rotation et son offset.

```bash
# Stage 1 (.unknown)
python3 tools/js_deobf.py \
  02e6fbf7*.unknown \
  tools/02e6fbf7_resolved.js \
  --dump-array

# Stage 2
python3 tools/js_deobf.py \
  a3f41333*.js \
  tools/a3f41333_resolved.js \
  --dump-array

# Stage 3
python3 tools/js_deobf.py \
  683a1607*.js \
  tools/683a1607_resolved.js \
  --dump-array
```

Résultats attendus :

| Stage | Tableau | Entrees | Lookup | Rotation | Appels remplacés |
|---|---|---|---|---|---|
| 1 (.unknown) | `a3a` | 370 | `ay` (alias a3b) | 112 | 185 |
| 2 | `D` | 57 | `W` | 46 | 75 |
| 3 | `j` | 220 | `Q` (alias k) | 70 | 40 |

---

## 4. Extraction de l'IP C2 (stage 2)

L'IP est encodée dans `O = 'LjEwMi4xOTUuMjE3Mzg='`. La fonction `j()` la décode en 3 étapes :

```python
import base64

O = 'LjEwMi4xOTUuMjE3Mzg='
w = O
M, u, v = '', '', ''
for k in range(4):
    M += w[2*k] + w[2*k+1]
    u += w[8+2*k] + w[9+2*k]
    v += w[16+k]

# Recolle : u+M+v
combined = u + M + v  # 'OTUuMjE3LjEwMi4xMzg='
ip = base64.b64decode(combined).decode('utf-8')
print(ip)  # -> 95.217.102.138

# URL complète
m = '30620700'  # campaign ID hardcodé
print(f"http://{ip}:1144/s/{m}")
# -> http://95.217.102.138:1144/s/30620700
```

---

## 5. Reconstruction des URLs Cloudflare R2 (stage 3)

Les fragments dans le tableau stage 3 (rotation 70) reconstituent les URL R2 :

```bash
# Vérifier les fragments dans tools/683a1607_resolved.js :
grep -o "r2\.dev[^']*\|pub-[0-9a-f]*" tools/683a1607_resolved.js

# Résultats :
# Windows : https://pub-acf013a9b65140b7b58cc3c104ee7105.r2.dev/p.zip
# Linux   : https://pub-06714264305c44ea94491c0c8d961a87.r2.dev/plinux.tar.gz
# macOS   : https://pub-06714264305c44ea94491c0c8d961a87.r2.dev/pmac.tar.gz
```

---

## 6. Analyse des Python backdoors

```bash
# === b34aa84 : browser stealer ===

# IoCs réseau
grep -n 'HOST\|PORT\|http\|credit_cards\|Chrome Safe' b34aa84e*.py
# -> HOST = '95.216.64.240', PORT = 1224
# -> credit_cards (vol de cartes bancaires via SQLite Login Data)

# Navigateurs ciblés
grep 'class.*BrowserVersion\|base_name' b34aa84e*.py
# -> Chrome, Brave, Opera, Yandex, MsEdge

# Exfiltration
grep '/keys\|/uploads' b34aa84e*.py
# -> POST /keys (credentials), POST /uploads (fichiers)

# === cd3b606d : RAT complet ===

# Deux C2 distincts
grep 'HOST\|PORT' cd3b606d*.py
# -> HOST = '95.216.64.240', PORT = 1224    (HTTP beacon)
# -> HOST0 = '69.197.164.135', PORT0 = 2245 (TCP RAT canal persistant)

# Protocole TCP
grep 'HEARTBEAT_CODE\|MAX_PAYLOAD\|FRAME_DEADLINE' cd3b606d*.py
# -> HEARTBEAT_CODE = 98 (ping/pong), MAX_PAYLOAD_SIZE = 16MB

# Table des commandes RAT
grep 'ssh_obj\|ssh_cmd\|ssh_clip\|ssh_run\|ssh_upload\|ssh_kill\|ssh_env\|ssh_eval\|ssh_conn\|ssh_inject' cd3b606d*.py
# -> codes 1-11 : shell, kill, clipboard, browser stealer, upload, .env, eval Python, conn

# Keylogger Windows
grep 'pynput\|e_buf\|on_press\|on_click\|pyperclip' cd3b606d*.py
# -> présent (Windows uniquement, via pynput + win32gui)

# Répertoire de travail RAT
grep '\.n2\|flist\|bow' cd3b606d*.py
# -> ~/.n2/flist (journal uploads), ~/.n2/bow (browser stealer téléchargé)

# Version / build
grep "'v':" cd3b606d*.py
# -> 'v': 260715  (vraisemblablement date de build AAMMJJ = 2026-07-15)

# Auto-upload crypto commenté
grep -A2 'def auto_up' cd3b606d*.py
# -> fpatten('*mnemonic*'), fpatten('*metamask*') ... tous commentés
```

---

## 6b. Constantes RAT cd3b606d — mode root et version build

```bash
# Version build (format AAMMJJ)
grep "'v':" cd3b606d*.py
# -> 'v': 260715  (2026-07-15)

# Mode gType="root" (hostname sans préfixe campagne)
grep -A5 "gType.*root" cd3b606d*.py
# -> if gType == "root": A.hostname = node()
# -> else: A.hostname = gType + "_" + node()  (normal: "700_<hostname>")

# ssh_inject stub mort (NameError à l'exécution)
grep -A8 "def ssh_inject" cd3b606d*.py
# -> A.send_n(D, 11, out)  <- NameError: 'out' non défini
```

## 7. Vérification OSINT réseau

```bash
# Vérification passive des IPs C2 (hors connexion directe)
# Ne pas contacter ces IPs depuis un système de production

# Via ThreatFox (aucun résultat pour 69.197.164.135 au 2026-07-20 — IP non signalée) :
curl -s -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H 'Content-Type: application/json' \
  -d '{"query":"search_ioc","search_term":"69.197.164.135"}'

# Via Shodan InternetDB (sans clé) :
curl -s https://internetdb.shodan.io/69.197.164.135
# -> ports 80, 443 (Apache 2.4.58, PHP 8.1.25, OpenSSL 3.1.3, self-signed SSL)
# -> port 2245 absent : non indexé, probablement filtré par l'attaquant

# WHOIS / ASN :
whois 69.197.164.135
# -> AS32097 WholeSale Internet, Inc. — Cloud Clusters Inc — Kansas City MO US
# -> CIDR 69.197.164.128/25

# Via URLHaus (no key needed) :
curl -s -X POST https://urlhaus-api.abuse.ch/v1/host/ \
  -d 'host=69.197.164.135'
# -> no_result

# Via MalwareBazaar (Auth-Key nécessaire) :
curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
  -H 'Auth-Key: <CLE>' \
  -d 'query=search_hash&hash=a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27'
```

**Résultat OSINT 69.197.164.135 :** IP absente de toutes les bases threat intel consultées. Infrastructure générique d'hébergement (Cloud Clusters Inc, Kansas City US). Port 2245 (canal RAT TCP) non visible depuis l'internet public — probablement limité par firewall aux connexions sortantes du malware. Trouver dans les logs réseau les connexions TCP sortantes persistantes sur ce port.

---

## 7a. Stage 1 — analyse stealer crypto (second pass)

Stage 1 contient un stealer complet ciblant les wallets crypto, révélé par un second pass de désobfuscation (182 alias locaux résolus).

```bash
python3 tools/js_deobf.py \
  02e6fbf7*.unknown \
  tools/02e6fbf7_full_resolved.js \
  --second-pass
```

Vérifications après second pass :

```bash
# Extensions Chrome ciblées (22 IDs dans l'array a1)
python3 - <<'EOF'
import re
f = open('tools/02e6fbf7_full_resolved.js').read()
m = re.search(r'a1=\[([^\]]+)\]', f)
print(m.group(1) if m else 'not found')
EOF

# IDs confirmés :
# nkbihfbeogaeaoehlefnkodbefgpgknn = MetaMask
# fhbohimaelbohpjbbldcngcnapndodjp = Binance Chain Wallet
# bfnaelmomeimhlpmgjnjophhpkkoljpa = Phantom (Solana)

# Répertoire de staging stage 1
grep "\.n3" tools/02e6fbf7_full_resolved.js

# URL d'upload (même serveur que Python stealer)
grep "uploads\|1224" tools/02e6fbf7_full_resolved.js
# -> http://95.216.64.240:1224/uploads

# Cible Solana CLI keypair
grep "solana" tools/02e6fbf7_full_resolved.js
# -> ~/.config/solana/id.json

# Cibles Exodus wallet
grep -i "exodus" tools/02e6fbf7_full_resolved.js
```

## 7b. Stage 3 — désobfuscation complète (second pass)

Le premier pass résout les 40 appels `Q(0xNN)` globaux. Un second pass résout les 98 alias locaux (`R`, `T`, `U`, `V`, `W`, `Z`, `a3`, `a4`, `a6`, `ac`, `af`) pour exposer complètement la logique de persistance.

```bash
python3 tools/js_deobf.py \
  683a1607*.js \
  tools/683a1607_full_resolved.js \
  --second-pass
# (ou utiliser le script inline du runbook section 3 avec le resolver de second pass)
```

Vérifications après second pass :

```bash
# Persistance Linux (XDG autostart .desktop)
grep -o 'Desktop Entry.*enabled=true' tools/683a1607_full_resolved.js

# Persistance macOS (bloc ~/.zprofile)
grep -o 'bootstrap.*bootstrap' tools/683a1607_full_resolved.js

# Payload Linux exact
grep 'plinux' tools/683a1607_full_resolved.js
# -> /plinux.tar.xz  (pas .tar.gz)

# Vérification Gradle (ciblage développeurs Java/Android)
grep 'gradle' tools/683a1607_full_resolved.js
# -> gradle-7-bin (vérification de l'environnement de build)
```

## 8. Validation des règles YARA

```bash
# Tester les règles sur les samples (6 règles, 6 fichiers)
yara -r lazarus_githook.yar .

# Résultat attendu :
# Lazarus_DEV_POPPER_GitHook         a129de4f...sh
# Lazarus_DEV_POPPER_Stage1_JS       02e6fbf7...unknown
# Lazarus_DEV_POPPER_Stage2_JS       a3f41333...js
# Lazarus_DEV_POPPER_Stage3_JS       683a1607...js
# Lazarus_DEV_POPPER_Python_Stealer  b34aa84e...py
# Lazarus_DEV_POPPER_Python_RAT      cd3b606d...py
```
