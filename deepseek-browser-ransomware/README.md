# Analyse InfernoGrabber v9.0 : un ransomware "navigateur" généré de bout en bout par DeepSeek

Analyse d'un malware entièrement généré par un LLM (DeepSeek) à partir d'un prompt évitant la terminologie explicite "ransomware"/"malware", le premier cas documenté (Check Point Research, 01/07/2026) où un modèle IA a construit seul une chaîne d'attaque fonctionnelle combinant un risque jusque-là théorique (ransomware "navigateur", sans binaire natif) avec une vraie capacité Chromium (File System Access API).

**Analyste :** Gordon PEIRS ([@ozer0x777](https://github.com/ozer0x777)) · **Période :** juillet 2026 · **Méthode :** analyse par métadonnées + comportement de sandbox tiers (VirusTotal), avec des extraits substantiels du code source réel récupérés via un canal détourné, le fichier complet n'a pas été téléchargé.

## Résumé exécutif

Le point de départ (Check Point Research, 01/07/2026) : sur la douzaine de capacités que le code généré par DeepSeek tente d'implémenter (keylogging, vol de tokens Discord, cartes bancaires, seed phrases crypto, webcam/micro, persistance...), **seules quatre fonctionneraient réellement** selon leur rapport (énumération de fichiers, lecture, chiffrement, overlay de rançon), le reste étant des "hallucinations IA" irréalisables dans le bac à sable du navigateur.

**En creusant nous-mêmes** (le téléchargement direct du fichier étant bloqué par le tier gratuit VirusTotal, mais un canal alternatif trouvé via les rapports de sandbox individuels a donné accès à plusieurs milliers de caractères de vrai code source), deux nuances importantes au narratif repris par la presse généraliste :
- Le fichier importe de vraies bibliothèques Python **natives** (`pyautogui`, `pyperclip`, `browser_cookie3`, `selenium`), ce n'est pas "sans binaire natif" comme les titres le suggèrent, c'est un script Python complet avec de vraies capacités système, dont on ne sait pas encore si elles sont effectivement invoquées
- Les commentaires du code sont en **russe**, ça nuance "un modèle IA a agi seul, sans aide humaine"

Le rapport comportemental de sandbox tiers de VirusTotal a aussi révélé un **vrai webhook Discord d'exfiltration** (confirmé mort par une requête de vérification) et un schéma de base de données locale (`inferno.db`) bien plus ambitieux que ce que la liste de capacités de Check Point suggère (champs dédiés à la prise de contrôle complète de comptes Discord : billing, abonnements, codes de sauvegarde).

## Chaîne reconstituée

```
Prompt DeepSeek évitant la terminologie "ransomware/malware"
  → Flask app Python + HTML/JS embarqué ("InfernoGrabber v9.0", auto-nommé)
    → leurre : fausse interface "AI Discord Avatar Upscaler"
      → showDirectoryPicker() : autorisation d'accès à un dossier (ex. Photos)
        → énumération + lecture + chiffrement in-place (fonctionnel)
          → overlay de rançon + tentatives non fonctionnelles (keylog, tokens, wallets, webcam...)
            → exfiltration vers un webhook Discord (mort au moment de la vérification)
```

## Documents

| Document | Contenu |
|---|---|
| [writeup.md](writeup.md) | Récit complet : contexte, ce qui a pu/n'a pas pu être récupéré, tableau capacités réelles vs hallucinées, découvertes du rapport comportemental VT, plan de reprise |
| [runbook.md](runbook.md) | Log de reproduction (commande / pourquoi / sortie brute) |
| [infernograbber.yar](infernograbber.yar) | Règles YARA (ossature InfernoDB + schéma SQLite + imports natifs + commentaires russes, et IOC du webhook connu), validées : matchent le code réel, zéro faux positif testé, uniquement des chaînes vérifiées |
| [fsapi-demo.html](fsapi-demo.html) | Démonstration pédagogique isolée de la File System Access API (énumération récursive en lecture seule d'un dossier jetable, sans chiffrement ni exfiltration) |
| [remediation.md](remediation.md) | Mesures de détection et de durcissement |

## Ce que ce dossier ne contient pas (volontairement)

Le fichier complet n'a pas pu être téléchargé directement (réservé aux comptes VirusTotal premium), mais des extraits substantiels du vrai code source ont été lus via un canal alternatif (rapport de sandbox CAPE Linux), voir writeup.md §2.1 et §6bis. Le fichier n'est pas versionné ici, seuls les extraits cités dans le writeup.
