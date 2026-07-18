# Analyse AgentTesla : d'un leurre naval à un exfil FTP, à travers un control-flow flattening réel de 1 891 cases

Reverse engineering statique complet d'un loader AgentTesla .NET : d'un faux outil de dimensionnement de structure navale jusqu'à la confirmation d'une exfiltration FTP active, en passant par la déobfuscation d'un control-flow flattening réel (Eziriz .NET Reactor) — deux outils maison construits et validés à la main, une fausse piste identifiée et corrigée avant publication, et deux tentatives documentées d'automatisation du déchiffrement final.

**Analyste :** Gordon PEIRS ([@ozer0x777](https://github.com/ozer0x777)) · **Période :** juillet 2026 · **Méthode :** analyse statique jusqu'en Partie 4 (aucune exécution du binaire par l'auteur), fermée par corrélation OSINT sur des sandboxes tierces (ANY.RUN, Triage, VMRay) pour la Partie 4.

## Résumé exécutif

Un exécutable .NET (`CTM.exe`) se fait passer pour un vrai outil métier de dimensionnement de structures navales — interface fonctionnelle, vocabulaire technique réel (CSR, raidisseurs, plans de tôle), pas un leurre minimal. Il déchiffre une ressource embarquée (inversion d'octets + AES-128 à clé fixe) pour charger un second assembly .NET en mémoire par réflexion, en évitant systématiquement les appels d'API littéraux (`Assembly.Load`, noms d'API Windows découpés en morceaux) pour échapper aux scanners de chaînes statiques.

Ce second stage est protégé par **Eziriz .NET Reactor** (identifié via une chaîne de licence trouvée en clair, confirmé indépendamment ensuite par ANY.RUN), avec un vrai **control-flow flattening** — contrairement au cas StealC où une seule branche par bloc était réelle, ici les 1 891 `case` répartis sur 24 dispatcheurs sont tous du code réel, chaînés par des branchements conditionnels. Deux outils Python ont été construits pour reconstruire ce graphe, avec deux bugs trouvés et corrigés par vérification manuelle en cours de route. Une hypothèse d'auto-injection a été formulée puis **invalidée avant publication** en vérifiant que la ressource native déclenchante n'existe pas dans le binaire ; le vrai chemin d'exécution a ensuite été retrouvé et tracé à 97% de couverture, révélant une séquence d'injection mémoire (OpenProcess/VirtualAlloc/WriteProcessMemory/VirtualProtect) avec des arguments concrets vérifiés.

Le contenu exact du payload final (une ressource de 92 Ko toujours chiffrée) n'a pas pu être déchiffré manuellement malgré deux tentatives documentées — un outil maison (format de sérialisation trop dispersé pour être isolé simplement) et un outil spécialisé, NETReactorSlayer, recompilé depuis la source avec un correctif jamais publié, qui cible en réalité un mécanisme différent de .NET Reactor. La question a été fermée par recoupement OSINT plutôt que par un acharnement technique sans fin : trois sandboxes tierces confirment indépendamment la famille AgentTesla, et Triage a extrait une configuration d'exfiltration FTP active.

## Chaîne reconstituée

```
CTM.exe (leurre : outil de dimensionnement de structure navale)
  → ressource .NET chiffrée (inversion d'octets + AES-128, clé=IV en dur)
    → stage 2 : protégé Eziriz .NET Reactor (confirmé en clair, puis indépendamment par ANY.RUN)
      → control-flow flattening réel (1 891 cases, 24 dispatcheurs), outils dédiés construits et validés
        → fausse piste d'auto-injection identifiée et corrigée avant publication
          → vrai chemin tracé à 97% : OpenProcess/VirtualAlloc/WriteProcessMemory/VirtualProtect
            → payload final chiffré (non extrait manuellement)
              → AgentTesla confirmé (3 sandboxes indépendantes), hollowing classique (SetThreadContext, vu dynamiquement)
                → exfiltration FTP vers ftp.piovau.com, vol de données Outlook
```

## Writeups

| Document | Contenu |
|---|---|
| [writeup.md](writeup.md) | Analyse complète en un seul document, organisée en 14 sections : acquisition et leurre applicatif du stage 1, chaîne de chargement AES vers le stage 2 · identification du protecteur (Eziriz .NET Reactor, correction d'une hypothèse ConfuserEx erronée) · control-flow flattening réel de 1 891 cases (deux outils maison, deux bugs trouvés et corrigés) · séquence d'injection tracée, fausse piste d'auto-injection identifiée et corrigée avant publication · vrai chemin d'exécution couvert à 97% · deux tentatives documentées d'automatisation du déchiffrement final · confirmation externe OSINT (ANY.RUN, Triage, VMRay) |
| [runbook.md](runbook.md) | Log de reproduction complet (commande / pourquoi / sortie brute) pour rejouer chaque étape des 4 parties |

## Outils

- [`tools/decrypt_stage2_resource.py`](tools/decrypt_stage2_resource.py) — déchiffrement AES de la ressource stage1→stage2 (inversion d'octets + AES-128 clé=IV)
- [`tools/deflatten_cs.py`](tools/deflatten_cs.py) — extraction du graphe de contrôle d'un control-flow flattening C# réel (pas juste "1 branche vraie + leurres") : linéaire/branchant/terminal/donnée-dépendant, avec détection `goto case`/`goto label`
- [`tools/linearize_cs.py`](tools/linearize_cs.py) — parcours du graphe depuis un point d'entrée détecté, reconstruction en ordre de lecture, détection de point d'entrée bornée par la méthode englobante

## Ce que ce dossier ne contient pas (volontairement)

Aucun binaire, aucun sample, aucune ressource déchiffrée n'est versionné ici. Les échantillons sont identifiés par hash SHA256 et récupérables gratuitement sur [MalwareBazaar](https://bazaar.abuse.ch/) — pratique standard en recherche malware : partager les indicateurs, pas le binaire fonctionnel.
