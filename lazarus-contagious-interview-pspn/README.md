# Lazarus Contagious Interview : dropper caché dans un faux projet de test technique (pspn-main)

Analyse d'un dépôt GitHub trojanisé livré via une fausse offre d'emploi LinkedIn (mode opératoire Lazarus Group / DEV#POPPER, campagne "Contagious Interview"). Un dashboard web3 crédible (`pspn-frontend`, paris UFC/PulseChain) cache un dropper JavaScript obfusqué dans son code serveur, déclenché automatiquement au premier `npm start`.

## Fichiers

| Fichier | Rôle |
|---|---|
| [`writeup.md`](writeup.md) | Récit analytique complet : leurre, dropper, récupération et déchiffrement du stage 2, quatre sous-modules, infrastructure C2, méthodologie d'émulation |
| [`runbook.md`](runbook.md) | Étapes reproductibles (extraction, émulation sûre, déchiffrement, vérification) |
| [`tools/harness.js`](tools/harness.js) | Bac à sable Node.js (module `vm`) : `require`/`fs`/`child_process`/réseau interceptés et journalisés, jamais exécutés réellement |
| [`tools/extract_stage1.py`](tools/extract_stage1.py) | Extraction du payload caché dans `userController.js` |
| [`tools/decrypt_stage2.py`](tools/decrypt_stage2.py) | Déchiffrement AES-256-CBC / scrypt de la réponse du C2 |
| [`tools/stage1_dropper_raw.js`](tools/stage1_dropper_raw.js) | Stage 1 brut (obfusqué), tel qu'extrait de `userController.js` |
| [`tools/stage2_decrypted.js`](tools/stage2_decrypted.js) | Stage 2 déchiffré (lanceur des 4 sous-modules) |
| [`tools/stage3_scdata_rat.js`](tools/stage3_scdata_rat.js) | Sous-module RAT / shell interactif + tunnel SSH |
| [`tools/stage3_ldata_browser_stealer.js`](tools/stage3_ldata_browser_stealer.js) | Sous-module voleur de données navigateur |
| [`tools/stage3_file_grabber.js`](tools/stage3_file_grabber.js) | Sous-module moissonneur de fichiers |
| [`tools/stage3_clipboard_monitor.js`](tools/stage3_clipboard_monitor.js) | Sous-module espion de presse-papiers |

## Chaîne résumée

```
Faux recruteur LinkedIn → dépôt GitHub "test technique" (pspn-main, dashboard web3 crédible)
  → npm start (instruction du README) → server/controllers/userController.js
    → dropper JS caché (obfuscator.io, après un faux commentaire, ligne 8)
      → npm install axios socket.io-client (camouflage : deps déjà légitimes)
      → GET http://147.189.172.105/api/service/<uid> → réponse chiffrée AES-256-CBC/scrypt
        → stage 2 déchiffré (lanceur)
          → /tmp/scdata : RAT Socket.IO (147.189.172.105:7861) + ssh2 + node-pty
          → /tmp/ldata : voleur de données navigateur (Chrome/Edge/Brave)
          → script inline : moissonneur de fichiers (home + /mnt)
          → script inline : espion de presse-papiers
```

## IoCs clés

| Type | Valeur |
|---|---|
| C2 (distribution + télémétrie) | `147.189.172.105` (HTTP, port 80, `/api/service/<uid>` et `/api/service/makelog`) |
| C2 (RAT interactif) | `147.189.172.105:7861` (Socket.IO) |
| Identifiant de service / mot de passe de dérivation de clé | `99cef4b32f24dcc475a4e7be8d2423c4` |
| Schéma de chiffrement stage 2 | AES-256-CBC, clé = `scrypt(uid, salt="salt", N=16384, r=8, p=1, dklen=32)` |
| Fichier verrou RAT | `/tmp/.npm/vhost.ctl` |
| Dépendances forcées (self-bootstrap) | `axios`, `socket.io-client`, `ssh2`, `node-pty` |

## Méthodologie

Aucune exécution réelle du payload : tout tourne dans un bac à sable Node.js (`tools/harness.js`) où `require`/`fs`/`child_process`/réseau sont interceptés et journalisés. Seule interaction avec l'infrastructure réelle : une requête HTTP GET en lecture seule pour récupérer le stage 2 chiffré, jamais exécuté, seulement déchiffré et relu statiquement dans le même bac à sable.
