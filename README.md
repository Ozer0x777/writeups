# Writeups

Analyses de reverse engineering / threat intel, un dossier par sujet. Chaque dossier est autonome (writeups + outils + éventuel runbook de reproduction).

**Auteur :** Gordon PEIRS ([@ozer0x777](https://github.com/Ozer0x777))

## Sommaire

| Analyse | Sujet | Résumé |
|---|---|---|
| [`stealc-autoit-killchain/`](stealc-autoit-killchain/) | StealC (infostealer) | Analyse statique complète d'un dropper StealC : stub IExpress → crypter AutoIt (Asgard Protector) → déobfuscation (control-flow flattening défait, validation croisée automatisée) → process hollowing → confirmation OSINT d'un C2 actif. |
| [`agenttesla-netreactor-killchain/`](agenttesla-netreactor-killchain/) | AgentTesla (infostealer) | Loader .NET (leurre naval) → déchiffrement AES → stage 2 protégé Eziriz .NET Reactor → déobfuscation d'un control-flow flattening réel (1 891 cases, outils dédiés) → séquence d'injection tracée → confirmation OSINT (exfiltration FTP active). |
| [`efimer/`](efimer/) | Efimer (ClickFix + clipper BTC/TRX/XMR + botnet WordPress) | Contournement statique PyArmor 8.x (clé AES extraite sans exécution), reconstruction de `daily_random_slug()` opcode par opcode, fuite OPSEC build machine (`DESKTOP-UOB4Aig`, Arrow Lake) via module bundlé jamais appelé, traçage blockchain jusqu'à 2 exchanges KYC et FixedFloat. |
| [`deepseek-browser-ransomware/`](deepseek-browser-ransomware/) | InfernoGrabber v9.0 (ransomware/stealer Python généré par le LLM DeepSeek) | Serveur Flask monofichier, leurre « AI Discord Avatar Upscaler », abus de la File System Access API (une seule autorisation = accès récursif complet), commentaires de code en russe, opérateur russophone relié via l'avatar Discord du leurre, webhook d'exfiltration retrouvé et confirmé mort. Lecture directe partielle du code réel (assumée) + règles YARA. |
| [`saferrat-android/`](saferrat-android/) | SaferRAT Android Banking Trojan (opérateur Diabloo) | RAT bancaire Android complet : overlay de phishing dynamique, VNC d'accessibilité, proxy SOCKS inversé, capture de PIN avec coordonnées, exfiltration automatique de la pellicule, 5 mécanismes de persistance distincts, attribution opérateur via tag hardcodé. |
| [`wskmon-whql-backdoor/`](wskmon-whql-backdoor/) | wskmon.sys (backdoor kernel WFP, signé WHQL) | Driver kernel x64 signé WHQL, backdoor réseau passif (WFP `FWPM_LAYER_STREAM_V4`), déclenchement par 4 octets magiques + HMAC-SHA256, injection dans `svchost.exe` SYSTEM via reconstruction manuelle de la SSDT, 3 samples liés par le même certificat compromis. |
| [`lazarus-githook/`](lazarus-githook/) | Lazarus DEV#POPPER (git hook + chaîne JS multi-stages + Python backdoors) | Chaîne d'infection ciblant les développeurs via dépôt git piégé : hook shell OS-aware → 3 stages JS obfuscator.io (rotation IIFE vérifiée, custom-b64) → dropper Cloudflare R2 → backdoor Python stealer (Chrome/Brave/Edge) + module comms C2 ; 3 IPs C2 distinctes, persistance multi-OS (registre/LaunchAgent/viminf), désobfuscateur dédié fourni. |

## Conventions de ce repo

- Chaque dossier de writeup contient son propre `README.md` d'index et ses propres outils dans un sous-dossier `tools/`.
- Aucun binaire ni sample malveillant n'est versionné, uniquement des hashes et des liens vers des sources publiques (MalwareBazaar, ThreatFox, etc.), conformément à la pratique standard en recherche malware.
- Les scripts publiés sont ceux réellement utilisés pendant l'analyse, sans nettoyage a posteriori qui masquerait le raisonnement réel.
