# Analyse StealC : d'un dropper GCleaner à un C2 actif, sans exécuter le binaire

Reverse engineering statique complet d'un échantillon StealC (infostealer, MaaS) : du stub IExpress jusqu'à la confirmation d'un C2 actif, en passant par la déobfuscation d'un loader AutoIt protégé par un control-flow flattening commercial (Asgard Protector) et la reconstitution d'une chaîne de process hollowing via les API `Nt*`.

**Analyste :** Gordon PEIRS ([@ozer0x777](https://github.com/ozer0x777)) · **Période :** juillet 2026 · **Méthode :** analyse statique uniquement (aucune exécution du binaire par l'auteur) + corrélation OSINT sur des sources tierces déjà publiques (MalwareBazaar, ThreatFox, Shodan InternetDB, rapport sandbox Triage).

## Résumé exécutif

Un stub IExpress protégé par le crypter **Asgard Protector** extrait un interpréteur AutoIt légitime et un script compilé fortement obfusqué (noms aléatoires, control-flow flattening, chaînes chiffrées). En remarquant que certaines constantes du script étaient des entiers négatifs mal réinterprétés comme positifs par le décompilateur, j'ai pu résoudre automatiquement la logique réelle cachée derrière l'obfuscation, puis valider cette hypothèse de façon croisée et indépendante sur l'intégralité du fichier plutôt que sur quelques exemples choisis à la main.

Le script déobfusqué révèle un loader qui : adapte son comportement selon l'antivirus détecté (Kaspersky, Avast, AVG, Bitdefender, Sophos), s'arrête immédiatement en présence d'outils de sandbox/VM (VMware, VirtualBox, Sandboxie), s'installe en persistance via un raccourci de démarrage, puis injecte le vrai payload dans `explorer.exe` par process hollowing (traçage complet des handles et structures Windows impliqués, pas une simple lecture de noms d'API). Le payload final et sa configuration C2 n'apparaissant jamais en clair dans ce loader (par design), j'ai fermé cette dernière inconnue en corrélant des sources OSINT publiques (MalwareBazaar, ThreatFox, un rapport de sandbox tiers, un scan passif Shodan) — confirmant un C2 StealC actif avec 431 observations, sans jamais m'y connecter moi-même.

**Chiffres clés :** 354 blocs de logique obfusquée résolus (351 validés par deux méthodes indépendantes, 100% d'accord) · 11 698 chaînes chiffrées déchiffrées · script réduit de 81% après déobfuscation (17 593 → 3 188 lignes) · 2 échantillons distincts reliés à la même infrastructure de campagne.

L'ensemble de l'investigation (Parties 1 à 4 ci-dessous) reste **100% statique** jusqu'à la Partie 4, où la confirmation finale s'appuie explicitement sur l'exécution qu'un tiers (le sandbox Triage) a faite de l'échantillon — jamais sur une exécution ou une connexion réalisée par moi-même.

## Chaîne reconstituée

```
GCleaner (delivery)
  → Stub IExpress protégé par Asgard Protector
    → AutoIt3.exe (interpréteur légitime abusé) + Quotes.a3x (script compilé)
      → déobfusqué : control-flow flattening défait, 11 698 chaînes XOR déchiffrées
        → anti-VM, anti-AV multi-vendeurs, persistance VBS/Startup
          → process hollowing (Nt*Section / Nt*VirtualMemory / NtSetContextThread)
            → StealC réel, botnet "euromix"/"eu1"
              → C2 actif (confirmé indépendamment, 431 sightings)
```

## Writeups

| Document | Contenu |
|---|---|
| [writeup.md](writeup.md) | Analyse complète en un seul document, organisée en 12 sections : identification du stub IExpress et extraction du loader AutoIt · déobfuscation (défaite du control-flow flattening par réinterprétation d'entiers signés, validation croisée automatisée sur 354 blocs, déchiffrement des chaînes) · process hollowing tracé de bout en bout · persistance VBS/Startup et adaptations anti-AV par vendeur détecté · confirmation externe OSINT (MalwareBazaar, ThreatFox, Shodan) du payload et du C2 |
| [runbook.md](runbook.md) | Log de reproduction complet (commande / pourquoi / sortie brute) pour rejouer chaque étape des 4 parties |

## Outils

Scripts Python autonomes (sans dépendance externe), écrits pour cette analyse :

- [`tools/deobfuscate.py`](tools/deobfuscate.py) — déchiffrement des chaînes XOR + résolution des blocs `Switch` aplatis
- [`tools/validate_crossref.py`](tools/validate_crossref.py) — validation croisée indépendante de l'hypothèse de résolution des `Switch`
- [`tools/decode_chrw.py`](tools/decode_chrw.py) — décodage des caractères construits via `ChrW(<expression>)`

## Ce que ce dossier ne contient pas (volontairement)

Aucun binaire, aucun sample, aucun script AutoIt décompilé n'est versionné ici. Les échantillons sont identifiés par hash SHA256 et récupérables gratuitement sur [MalwareBazaar](https://bazaar.abuse.ch/) (voir Partie 1, Annexe C-D du runbook) — c'est la pratique standard en recherche malware : partager les indicateurs, pas le binaire fonctionnel.
