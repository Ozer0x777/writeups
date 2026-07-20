# Analyse SaferRAT : un trojan bancaire Android à double étage avec prise de contrôle façon VNC

Analyse statique d'un trojan bancaire/RAT Android (famille SaferRAT, documentée par Zimperium zLabs) livré en deux étages, un dropper anodin qui embarque le vrai payload comme ressource, lequel implémente une prise de contrôle à distance complète via abus de l'API Accessibility (service littéralement nommé `VncAccessibilityService`, avec keylogger, moniteur de presse-papier et capture/rejeu de PIN intégrés), du streaming d'écran/caméra/micro, de l'exfiltration en masse de la pellicule photo/vidéo, de l'interception SMS bancaire, et 5 mécanismes de persistance distincts dont un watchdog mutuel entre deux services.

**Analyste :** Gordon PEIRS ([@ozer0x777](https://github.com/ozer0x777)) · **Période :** juillet 2026 · **Méthode :** analyse statique uniquement (aucune installation/exécution sur appareil ou émulateur Android), via `androguard` (manifest, décompilation DEX) et `quark-engine` (triage complémentaire).

## Résumé exécutif

Confirmé, hash pour hash, que le fichier `Strawberry.apk` (dropper, package `com.example.nestedinstaller`) embarque en ressource (`assets/nested_app.apk`) le vrai payload malveillant, qui s'affiche lui-même sous le label "Strawberry" une fois installé, une architecture à deux étages vérifiée par extraction et hash, pas supposée depuis les noms de fichiers.

La décompilation complète du payload (`androguard decompile`) a permis de trouver **quatre services réseau distincts sur deux hébergeurs** : le panel HTTP en clair `gorila-panel.xyz` (VDSINA, VPS russe), un WebSocket de contrôle temps réel et un service d'upload photo/vidéo en masse sur la même IP (`94.103.89.12`, ports différents), et un proxy SOCKS inversé complet chez un hébergeur distinct (Global Connectivity Solutions), présent dans le code mais confirmé non démarré sur ce build. Trois IOC neufs jamais documentés sur ThreatFox, et une trouvaille d'attribution concrète : un tag opérateur codé en dur, **`"Diabloo"`**, envoyé dans chaque enregistrement de bot au panel, jamais documenté publiquement ailleurs. L'analyse confirme aussi composant par composant les capacités décrites par Zimperium zLabs (`VncAccessibilityService` pour la prise de contrôle à distance, streaming caméra/micro/écran, interception SMS complète, 5 mécanismes de persistance), révèle un assistant de configuration très abouti (`DeveloperActivity`) avec des contournements dédiés pour 5 familles d'OEM Android entièrement en russe, et confirme (comparaison ligne à ligne) qu'un module keylogger apparemment dupliqué (`KeyLoggerService`) est en réalité le prototype abandonné d'un keylogger bien plus riche, intégré directement dans le service d'accessibilité actif.

## Chaîne reconstituée

```
Strawberry.apk (dropper, com.example.nestedinstaller)
  → assets/nested_app.apk (embarqué, hash confirmé identique)
    → payload réel : s3zse.f01pdoi.ohnrb2, se présente comme "Strawberry"
      → DeveloperActivity : assistant de contournement OEM (5 marques), tout en russe
        → VncAccessibilityService (contrôle à distance, keylogger, capture/rejeu de PIN)
          → BotHeartbeatService ↔ GuardService : watchdog mutuel, canal de commandes par polling HTTP
            → streaming écran/caméra/micro + exfiltration photos/vidéos/contacts/appels en masse
              → interception SMS (OTP bancaire) + overlay phishing chargé depuis le C2
                → BotRegister → gorila-panel.xyz (VDSINA, VPS russe), tag opérateur "Diabloo"
                  → 3 canaux réseau supplémentaires : WebSocket ATS, upload photo/vidéo, proxy SOCKS inversé (dormant)
```

## Documents

| Document | Contenu |
|---|---|
| [writeup.md](writeup.md) | Récit complet (FR) : contexte, architecture à deux étages confirmée par hash, décompilation complète, C2 en clair, tag d'attribution "Diabloo", plan de reprise |
| [writeup.en.md](writeup.en.md) | Traduction anglaise complète du writeup, pour partage externe (signalements, portfolio) |
| [runbook.md](runbook.md) | Log de reproduction (commande / pourquoi / sortie brute) |

## Ce que ce dossier ne contient pas (volontairement)

Les APK ne sont pas versionnés ici, identifiés par hash SHA256, récupérables sur MalwareBazaar (voir writeup.md §8 pour les IOCs).
