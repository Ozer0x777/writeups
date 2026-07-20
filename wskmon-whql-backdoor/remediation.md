# Guide de détection et remédiation : wskmon.sys (backdoor kernel WFP, signé WHQL)

Destiné à quelqu'un qui doit vérifier ou nettoyer un système Windows, pas à un public d'analystes. Basé sur les constats de [`writeup.md`](writeup.md) et du rapport MSRC [`02-wskmon-msrc-report.md`](02-wskmon-msrc-report.md).

## 1. Suis-je concerné ?

`wskmon.sys` est un driver kernel Windows x64 signé WHQL. Il ne crée aucune persistance propre : son chargement dépend d'un composant externe (vraisemblablement `devhost.sys`, analysé dans [`writeup.md`](writeup.md) §12). Le certificat WHQL était valide sans révocation au moment de l'analyse (vérifié en direct sur la CRL Microsoft, 2026-07).

### Vérification

```powershell
# Chercher les trois drivers de la famille sur le système de fichiers
Get-ChildItem C:\Windows\System32\drivers\ -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @("wskmon.sys","devhost.sys","844ljfpvz.sys") }

# Chercher dans d'autres emplacements (drivers hors System32 sont rares mais possibles)
Get-ChildItem C:\ -Recurse -Filter "wskmon.sys" -ErrorAction SilentlyContinue

# Vérifier les drivers kernel chargés en mémoire
driverquery /fo csv | findstr /i "wskmon devhost"

# Lister les services de type driver avec un nom ou chemin inhabituel
Get-WmiObject Win32_SystemDriver | Where-Object {
    $_.PathName -notlike "*Windows\System32*" -and $_.PathName -notlike "*Windows\SysWOW64*"
}
```

La règle YARA [`wskmon.yar`](wskmon.yar) sur le dossier `drivers\` ou sur un disque suspect confirme la présence du driver ou d'un membre de la famille.

## 2. Ce que fait le backdoor

**Comportement entièrement passif** : le driver n'initie aucune connexion sortante, ne crée aucune clé de registre, ne dépose aucun fichier. Il attend en silence sur le flux TCP IPv4 via WFP (`FWPM_LAYER_STREAM_V4`).

Un paquet entrant déclenche le backdoor uniquement s'il commence par les 4 octets magiques `7F 4E 54 46` et passe la validation HMAC-SHA256 avec la clé XOR de 32 octets du driver (détail dans [`writeup.md`](writeup.md) §6-7).

Sur déclenchement réussi, le driver peut injecter du code dans n'importe quel processus `svchost.exe` tournant sous `NT AUTHORITY\SYSTEM`, en reconstruisant manuellement la SSDT via le MSR `IA32_LSTAR` (pas d'API documentée utilisée, technique de rootkit).

**Conséquence :** aucune détection antivirus classique au moment de l'analyse (Kaspersky : "Clean", YOROI : "Legit File", 1/23 sur ReversingLabs).

## 3. Nettoyage

```cmd
REM Nécessite des privilèges administrateur élevés
sc stop wskmon
sc delete wskmon
del /f /q "C:\Windows\System32\drivers\wskmon.sys"

REM Répéter pour les drivers apparentés si présents
sc stop devhost
sc delete devhost
del /f /q "C:\Windows\System32\drivers\devhost.sys"
```

Redémarrer après suppression pour confirmer l'absence de chargement en mémoire résiduelle.

Si le driver résiste à la suppression (protection par un autre driver ou par SecureBoot), démarrer en mode de récupération Windows (WinPE) et supprimer les fichiers depuis là.

## 4. Évaluation de la compromission

Le backdoor étant passif, il est impossible sans logs réseau de déterminer si et quand un attaquant l'a déclenché.

**Chercher dans les logs réseau (SIEM, pare-feu, IDS) :**

- Connexions TCP entrantes vers la machine sur n'importe quel port, dont les premiers octets de charge utile correspondent à `7F 4E 54 46`
- Activité réseau inhabituelle de processus `svchost.exe` tournant sous `NT AUTHORITY\SYSTEM` après la date de présence connue du driver

**Si une activation est suspectée :** l'injection dans `svchost.exe` SYSTEM donne un contrôle total sur la machine. Considérer une réinstallation complète du système et une rotation de toutes les clés et secrets présents.

## 5. Signalement et réduction de surface

- **Signalement Microsoft MSRC** : voir [`02-wskmon-msrc-report.md`](02-wskmon-msrc-report.md) -- le certificat WHQL (serial `330000013c4a61fb3578d2b6dd00000000013c`) doit être révoqué par Microsoft pour neutraliser les trois samples de la famille
- Soumettre les trois hashes à ThreatFox sous les tags `rootkit` et `byovd` :
  - `wskmon.sys` : `495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979`
  - `devhost.sys` : `ee8844ffd3879190fb389b0f613cb2dcdcd83375cf0a6994170a648c5ca8c479`
  - `844ljfpvz.sys` : `1d9224a72e64bb2aad289edc81ea0720c764511c3e2b5beb5d0d5ce82a719abd`
- Activer **HVCI (Hypervisor-Protected Code Integrity)** si pas encore fait : empêche le chargement de drivers non approuvés, limite l'impact du Bring Your Own Vulnerable Driver
- Le serial du certificat compromis peut être ajouté aux listes de blocage EDR en attendant la révocation officielle Microsoft
