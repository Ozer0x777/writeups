# Guide de détection et remédiation : SaferRAT Android Banking Trojan (opérateur Diabloo)

Destiné à quelqu'un qui doit vérifier ou nettoyer un appareil Android, pas à un public d'analystes. Basé sur les constats de [`writeup.md`](writeup.md).

## 1. Suis-je concerné ?

Le dropper (`com.example.nestedinstaller`, SHA256 `d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4`) se présente comme une app légitime et installe en silence le payload (`com.example.safeservice`).

### Vérification

```bash
# Nécessite ADB avec débogage USB activé sur l'appareil
adb shell pm list packages | grep -E "nestedinstaller|safeservice"

# Lister les services d'accessibilité actifs
adb shell settings get secure enabled_accessibility_services
```

La présence de `com.example.safeservice.vnc.VncAccessibilityService` dans la liste des services d'accessibilité actifs confirme le payload en fonctionnement.

Sans ADB : Paramètres > Accessibilité > Services téléchargés. La présence d'un service inconnu ou portant un nom générique (ex. "System Service", "VNC") est suspecte.

## 2. Ce que le RAT fait activement

Ces comportements ont été confirmés par lecture directe du code source décompilé (détail dans [`writeup.md`](writeup.md)) :

- **Capture des frappes clavier et du presse-papier** via `VncAccessibilityService`
- **Capture des codes PIN** avec coordonnées exactes (tap sur chaque chiffre, horodatage, rejouable à distance)
- **Exfiltration automatique de la pellicule photo/vidéo** au premier lancement, dès l'octroi des permissions de stockage
- **Suppression silencieuse des notifications** d'apps bancaires et de codes 2FA sélectionnées par l'opérateur
- **Overlay de phishing plein écran** par-dessus les apps bancaires (page web chargée depuis le C2)
- **Envoi de codes USSD** arbitraires (renvoi d'appels, consultation de solde)
- **Insertion de faux contacts** dans le carnet d'adresses (vishing)

Le C2 est actif sur `gorila-panel.xyz` / `91.184.247.166` et `94.103.89.12`. L'opérateur est identifiable via le tag `Diabloo` hardcodé dans `BotRegister.java`.

## 3. Nettoyage

**Méthode recommandée : réinitialisation d'usine.** Les 5 mécanismes de persistance combinés (watchdog mutuel, alarme réveil anti-Doze, account sync framework, widget d'écran d'accueil, lecture multimédia silencieuse) rendent le nettoyage manuel peu fiable.

1. Avant la réinitialisation : noter les comptes connectés pour audit après nettoyage.
2. Réinitialisation d'usine complète : Paramètres > Système > Réinitialisation > Effacer toutes les données.
3. Restaurer depuis une sauvegarde antérieure à l'installation du dropper, si disponible.
4. En l'absence de sauvegarde saine : reconfigurer l'appareil à zéro sans restauration automatique.

**Si la réinitialisation n'est pas possible immédiatement :**

1. Désactiver le service d'accessibilité : Paramètres > Accessibilité > désactiver `VncAccessibilityService`.
2. Couper le réseau (mode avion) pour interrompre les communications C2.
3. Via ADB : `adb uninstall com.example.safeservice && adb uninstall com.example.nestedinstaller`
4. Ces étapes perturbent le RAT mais ne garantissent pas une élimination complète des 5 mécanismes de persistance.

## 4. Évaluation de la compromission

Toutes les transactions bancaires effectuées depuis l'appareil pendant la période d'infection sont à considérer comme potentiellement interceptées ou rejouables par l'attaquant.

**Actions prioritaires depuis un appareil sain :**

- Changer les mots de passe de toutes les apps bancaires et de paiement
- Contacter les banques pour signaler une compromission d'appareil mobile et surveiller les transactions récentes
- Révoquer les sessions Signal, WhatsApp, Telegram (chaque app a une option "Déconnecter tous les appareils")
- Changer les PIN bancaires si des saisies ont été effectuées sur l'appareil compromis
- La totalité de la pellicule photo/vidéo est à considérer comme exfiltrée dès l'octroi des permissions de stockage

## 5. Signalement et réduction de surface

- Signaler `gorila-panel.xyz` et `94.103.89.12` à ThreatFox (via le portail web abuse.ch)
- Signalement abuse hébergeur : VDSINA (`abuse@vdsina.ru`) pour les deux IPs C2
- La règle YARA [`saferrat.yar`](saferrat.yar) permet de détecter le package sur un fichier APK extrait
- Ne jamais activer les "sources inconnues" (installation hors Play Store) sans raison claire et vérifiée
- Ne jamais activer un service d'accessibilité demandé par une app qui n'a pas de fonction d'accessibilité déclarée
- Sur Android 12+ : le point orange dans la barre de statut indique un accès actif au microphone ou à la caméra
