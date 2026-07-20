# Analyse Efimer : d'un leurre ClickFix à un clipper crypto, un botnet WordPress et une machine de développement identifiée par accident

Reverse engineering statique complet d'un dropper Python distribué par ClickFix : contournement statique de PyArmor 8.x, désobfuscation d'un clipper JavaScript et d'un bruteforcer WordPress XML-RPC, fuite OPSEC de la machine de build de l'attaquant trouvée dans un module Python jamais appelé, remontée blockchain jusqu'à des exchanges soumis aux obligations KYC, et reconstruction d'un algorithme de nommage journalier permettant la prédiction des IoCs futurs sans exécuter le malware.

**Analyste :** Gordon PEIRS ([@ozer0x777](https://github.com/ozer0x777)) · **Période :** juillet 2026 · **Méthode :** analyse statique uniquement (aucune exécution du sample, aucune connexion à l'infrastructure C2) + OSINT blockchain vérifié en direct contre des sources tierces indépendantes (mempool.space, Tronscan, MalwareBazaar).

## Résumé exécutif

Un dropper Python (PyInstaller 5.13.2 + PyArmor 8.x) distribué par ClickFix, une fausse page CAPTCHA qui pousse la victime à coller elle-même une commande PowerShell, installe simultanément un clipper crypto et un bruteforcer WordPress, deux canaux de monétisation indépendants sur trois hidden services Tor distincts. La clé AES de PyArmor a été extraite statiquement depuis la DLL runtime (`pyarmor_runtime.pyd`), le nonce `i.non-profit` identifiant au passage une licence PyArmor non-commerciale (gratuite), utilisée pour protéger un logiciel malveillant. Le bytecode déchiffré révèle la clé XOR des sept payloads et l'algorithme `daily_random_slug()`, reconstruit opcode par opcode depuis le désassemblage brut parce que le décompilateur refusait cette fonction.

Le clipper (`002_n.js`, obfuscator.io) couvre BTC toutes variantes, TRX et XMR, avec une subtilité notable : les mots d'une phrase mnémonique BIP39 sont accumulés sur des événements de copie successifs, pas nécessairement en un seul bloc. La correspondance de suffixes de `MakeREPL` (2 à 4 derniers caractères) rend le remplacement d'adresse visuellement indétectable pour une victime qui vérifie ses adresses à la main. Le bruteforcer WordPress (`002_b.js`) n'est pas déposé à l'installation mais livré sélectivement par le C2 via une commande `EVAL`.

Un module Python bundlé mais jamais appelé depuis l'installeur principal (`campus.py`) contient, par accident, l'archive de build du bootloader PyInstaller recompilé par l'attaquant. L'archive était corrompue par une transformation d'encodage (cp1252 vers UTF-8), restaurée manuellement. Les deux premiers fichiers extraits révèlent le hostname de la machine (`DESKTOP-UOB4Aig`), un processeur Arrow Lake (Intel Core Ultra 200, achat récent), le chemin de développement (`C:\Users\User\Desktop\`) et la date de compilation (2026-05-30).

Le traçage blockchain des wallets hardcodés remonte jusqu'à deux exchanges soumis au KYC (inputs de deux transactions de retrait distincts), un hot wallet FixedFloat identifié publiquement, et quatre wallets activateurs TRON actifs depuis 2021 à 2023, indiquant une infrastructure qui précède la campagne actuelle. L'algorithme `daily_random_slug()` permet de précomputer les noms de dossier, de tâche planifiée et de fichier JS pour n'importe quelle date future à partir du seul algorithme reconstitué.

**Chiffres clés :** clé AES PyArmor + clé XOR extraites sans exécution · algorithme `daily_random_slug()` reconstitué opcode par opcode, table d'IoCs prédictifs calculée pour juillet 2026 · 3 clés ed25519 des C2 Tor vérifiées depuis les adresses `.onion` · chaîne blockchain tracée jusqu'à 2 exchanges KYC et 1 exchange no-KYC, avec 4 wallets activateurs TRX d'ancienneté confirmée.

## Chaîne reconstituée

```
ClickFix (page CAPTCHA piégée) → commande PowerShell collée par la victime
  → dropper PyInstaller 5.13.2 + PyArmor 8.x (nonce i.non-profit, clé AES extraite statiquement)
    → installer.pyc déchiffré (pycdc) → clé XOR Is8xqLVw7pTB, daily_random_slug()
      → payloads XOR déchiffrés (data_p002/)
        → uusd.exe (démon Tor embarqué)
        → 002_n.js (clipper BTC/TRX/XMR, accumulation BIP39, MakeREPL)
        → 002_b.js (bruteforcer WordPress XMLRPC, livraison sélective par C2)
        → 002a.txt (40 000 adresses de remplacement), 002w.txt (BIP39), 002.xml (tâche planifiée)
          → persistance toutes les 60 secondes + clé Run, nommage journalier prédictible
          → campus.py (non appelé) : fuite OPSEC build machine → DESKTOP-UOB4Aig, Arrow Lake, 2026-05-30
          → OSINT blockchain : wallets hardcodés → exchanges KYC → FixedFloat → signalements
```

## Writeups

| Document | Contenu |
|---|---|
| [writeup.md](writeup.md) | Analyse complète en 16 sections : identification du sample, contournement PyArmor 8.x, reconstruction de `daily_random_slug()`, déchiffrement des payloads, analyse du clipper et du bruteforcer, installeur Python (anti-sandbox, Defender bypass, géo-filtre), fuite OPSEC `campus.py`, intelligence de campagne MalwareBazaar, OSINT blockchain complet, killswitch, attribution, limites, IOCs consolidés, guide de reproduction |
| [runbook.md](runbook.md) | Log de reproduction complet (commande / pourquoi / sortie brute) pour rejouer chaque étape de l'analyse |

## Outils

Scripts Python écrits pour cette analyse, dans [`tools/`](tools/) :

- [`tools/daily_slug.py`](tools/daily_slug.py), calcul du slug journalier pour une date donnée (N=0 dossier, N=1 tâche, N=2 script JS) et génération de tables d'IoCs sur une plage de dates
- [`tools/xor_decrypt.py`](tools/xor_decrypt.py), déchiffrement des sept payloads de `data_p002/` avec la clé `Is8xqLVw7pTB`
- [`tools/rar5_restore.py`](tools/rar5_restore.py), restauration de l'archive RAR5 corrompue de `campus.py` (inversion de la transformation cp1252-vers-UTF-8 avec handler personnalisé)
- [`tools/iife_sim.py`](tools/iife_sim.py), simulation de l'IIFE obfuscator.io en Python pour résoudre la rotation du tableau de chaînes de `002_n.js` et `002_b.js`

## Ce que ce dossier ne contient pas (volontairement)

Aucun binaire, aucun sample n'est versionné ici. L'échantillon est identifié par son SHA256 (`a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4`) et récupérable sur [MalwareBazaar](https://bazaar.abuse.ch/) (tag `efimer`, clé API gratuite requise).
