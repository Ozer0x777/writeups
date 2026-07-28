# Guide de détection et remédiation : compromission StealC via Asgard Protector (IExpress + AutoIt)

Destiné à quelqu'un qui doit vérifier ou nettoyer une machine, pas à un public d'analystes. Basé sur les constats de [`writeup.md`](writeup.md) ; les points non confirmés directement sont marqués comme tels.

## 1. Suis-je concerné ?

La chaîne commence par un stub IExpress : un PE Windows avec extension `.exe`, pesant entre 1 et 3 Mo, dont l'essentiel du volume est dans la section `.rsrc` (archive CAB compressée). À l'exécution, il extrait un interpréteur AutoIt3 rebaptisé `InnoCoder.exe` et un script compilé `.a3x`.

### Vérification rapide

```powershell
# Chercher un processus InnoCoder ou AutoIt3 hors de son chemin légitime
Get-Process | Where-Object { $_.Name -like "InnoCoder" -or $_.Name -like "AutoIt3" }

# Chercher le dossier de dépôt
Test-Path "$env:LOCALAPPDATA\CodeInnovate Technologies Co"

# Chercher le LNK de persistance dans le dossier de démarrage
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\" | Where-Object { $_.Name -like "InnoCoder*" }

# Vérifier les entrées RunOnce
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
```

La règle YARA fournie ([`stealc_asgard.yar`](stealc_asgard.yar)) sur le dossier de téléchargements ou le répertoire temp confirme la présence du dropper.

## 2. Signes d'infection active

- **Processus `InnoCoder.exe`** (ou `AutoIt3.exe`) dans `%LOCALAPPDATA%\CodeInnovate Technologies Co\`, pas dans `%ProgramFiles%`
- **Raccourci `InnoCoder.lnk`** dans `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
- **Script `InnoCoder.vbs`** dans le même dossier de dépôt (relance l'interpréteur à chaque connexion)
- **Entrée RunOnce** dans `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` pointant vers un chemin dans `%LOCALAPPDATA%`
- **Connexions réseau sortantes** vers `160.20.109.75` (C2 StealC, actif au moment de l'analyse, 2026-07)
- **Processus creux** : un exécutable Windows légitime (notepad.exe, svchost.exe ou autre) dont la plage mémoire principale contient un PE différent de l'image sur disque, avec permissions `RWX`

## 3. Nettoyage

1. Couper l'accès réseau avant toute autre action si une connexion vers `160.20.109.75` est active.
2. Tuer le processus `InnoCoder.exe` ou `AutoIt3.exe` suspect.
3. Tuer tout processus creux identifié.
4. Supprimer le raccourci `InnoCoder.lnk` dans le dossier de démarrage.
5. Supprimer l'entrée RunOnce concernée dans le registre.
6. Supprimer le dossier `%LOCALAPPDATA%\CodeInnovate Technologies Co\` et son contenu.
7. Supprimer le fichier IExpress d'origine s'il est encore sur disque.

## 4. Évaluation de la compromission

StealC est un **infostealer MaaS** dont l'objectif est l'exfiltration silencieuse de données, pas le chiffrement. Le payload s'injecte dans un processus légitime et tourne sans fenêtre visible.

**Données à risque si le payload StealC a tourné, même brièvement :**

- Mots de passe et cookies de tous les navigateurs Chromium (Chrome, Edge, Brave, Opera) et Firefox
- Sessions Discord, Telegram desktop, Signal desktop
- Fichiers de portefeuilles crypto (`wallet.dat`, extensions MetaMask, Exodus)
- Sessions VPN et clients FTP (FileZilla, WinSCP)
- Fichiers récents sur le bureau et dans Documents (StealC liste et exfiltre les fichiers par extension)

**Actions systématiques :**

- Révoquer et renouveler tous les mots de passe stockés dans les navigateurs depuis un appareil sain
- Révoquer les sessions actives (banque, exchange crypto, messagerie professionnelle)
- Notifier l'équipe sécurité si la machine est un poste d'entreprise

## 5. Réduction de surface d'attaque

- Bloquer les connexions sortantes vers `160.20.109.75` en périphérie réseau
- Ajouter `stealc_asgard.yar` à la solution EDR/SIEM pour détection sur téléchargements et pièces jointes
- Soumettre le hash `afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da` à ThreatFox si non encore présent
