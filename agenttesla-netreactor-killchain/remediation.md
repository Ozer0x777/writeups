# Guide de détection et remédiation : AgentTesla via loader .NET (Eziriz .NET Reactor)

Destiné à quelqu'un qui doit vérifier ou nettoyer une machine, pas à un public d'analystes. Basé sur les constats de [`writeup.md`](writeup.md) ; les points non confirmés directement sont marqués comme tels.

## 1. Suis-je concerné ?

Un loader .NET distribué sous couvert d'un document maritime déchiffre et charge en mémoire un stage 2 AgentTesla protégé par Eziriz .NET Reactor. La clé AES (`e4a931cb6e204322da0d1a30d946633b`) est hardcodée dans le loader et extractible statiquement.

### Vérification rapide

```powershell
# Connexions FTP sortantes actives
Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -eq 21 }

# Résolution DNS vers le C2 FTP
Resolve-DnsName "ftp.piovau.com" -ErrorAction SilentlyContinue

# Fichier loader encore sur disque (nom variable, chercher par hash)
Get-ChildItem -Path $env:TEMP, $env:APPDATA, "$env:USERPROFILE\Downloads" -Recurse -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256 | Where-Object { $_.Hash -eq "BC6D86CEF1B7404823C1D830387B2C9B1289C453620482FC1749DD5D2ADE3897" }
```

La règle YARA fournie ([`agenttesla_netreactor.yar`](agenttesla_netreactor.yar)) sur le dossier de téléchargements confirme la présence du loader ou du stage 2.

## 2. Signes d'infection active

- **Connexions FTP sortantes** vers `ftp.piovau.com:21` (canal d'exfiltration actif au moment de l'analyse, 2026-07)
- **Processus .NET** à la durée de vie anormalement longue, chargé depuis un document ou un dossier temporaire
- **Accès fichiers** sur les profils Outlook (`%APPDATA%\Microsoft\Outlook\`) ou Thunderbird, signalé par des logs d'accès fichier si l'EDR les produit
- Aucune fenêtre visible : AgentTesla tourne entièrement en mémoire après injection

## 3. Nettoyage

1. Couper le réseau avant toute autre action si une connexion vers `ftp.piovau.com:21` est active.
2. Identifier et tuer le processus .NET porteur. Sur les machines sans EDR mémoire, chercher un processus dont la liste des modules inclut des assemblies chargées depuis `byte[]` (pas depuis un chemin disque).
3. Supprimer le fichier loader original (le `.exe` ou `.doc` de leurre reçu).
4. Scanner la machine avec `agenttesla_netreactor.yar` pour repérer d'éventuelles copies.

## 4. Évaluation de la compromission

AgentTesla est un **infostealer commercial** ciblant en priorité les clients de messagerie, les navigateurs, et les clients FTP/SSH. L'exfiltration part vers un serveur FTP tiers contrôlé par l'attaquant.

**Données à risque :**

- Comptes email Outlook, Thunderbird, Windows Mail (identifiants SMTP/IMAP en clair dans les profils)
- Mots de passe enregistrés dans Chrome, Firefox, Edge, Opera
- Identifiants FileZilla, WinSCP, PuTTY
- Contenu du presse-papier au moment de l'exfiltration (seed phrases crypto si copiées-collées à ce moment)

**Actions systématiques :**

- Changer tous les mots de passe email et clients FTP depuis un appareil sain
- Révoquer les sessions actives sur les services cloud liés aux comptes email compromis
- Signaler l'infrastructure FTP (`ftp.piovau.com`, port 21) à l'hébergeur et à ThreatFox

## 5. Réduction de surface d'attaque

- Bloquer les connexions sortantes vers `ftp.piovau.com` (port 21 et 990) en périphérie réseau
- Activer la MFA sur tous les comptes email de la machine
- Soumettre les hashes `bc6d86cef1b7404823c1d830387b2c9b1289c453620482fc1749dd5d2ade3897` (loader) et `39fdba7a439cb09842f26d34f84606e3cc7f685b407deceb49ee7cb71271ebcd` (stage 2) à ThreatFox si non encore présents
