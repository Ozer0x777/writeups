# Writeups

Analyses de reverse engineering / threat intel, un dossier par sujet. Chaque dossier est autonome (writeups + outils + éventuel runbook de reproduction).

**Auteur :** Gordon PEIRS ([@ozer0x777](https://github.com/ozer0x777))

## Sommaire

| Analyse | Sujet | Résumé |
|---|---|---|
| [`stealc-autoit-killchain/`](stealc-autoit-killchain/) | StealC (infostealer) | Analyse statique complète d'un dropper StealC : stub IExpress → crypter AutoIt (Asgard Protector) → déobfuscation (control-flow flattening défait, validation croisée automatisée) → process hollowing → confirmation OSINT d'un C2 actif. |
| [`agenttesla-netreactor-killchain/`](agenttesla-netreactor-killchain/) | AgentTesla (infostealer) | Loader .NET (leurre naval) → déchiffrement AES → stage 2 protégé Eziriz .NET Reactor → déobfuscation d'un control-flow flattening réel (1 891 cases, outils dédiés) → séquence d'injection tracée → confirmation OSINT (exfiltration FTP active). |

## Conventions de ce repo

- Chaque dossier de writeup contient son propre `README.md` d'index et ses propres outils dans un sous-dossier `tools/`.
- Aucun binaire ni sample malveillant n'est versionné — uniquement des hashes et des liens vers des sources publiques (MalwareBazaar, ThreatFox, etc.), conformément à la pratique standard en recherche malware.
- Les scripts publiés sont ceux réellement utilisés pendant l'analyse, sans nettoyage a posteriori qui masquerait le raisonnement réel.
