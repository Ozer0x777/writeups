# Analyse SaferRAT : un trojan bancaire Android à double étage avec prise de contrôle façon VNC

**Analyste :** Gordon PEIRS
**Date d'analyse :** 19/07/2026
**Type :** Analyse statique uniquement (aucune installation ni exécution des APK sur un appareil ou émulateur Android). Manifest, structure de paquet et code source complet décompilé via `androguard`.
**Famille :** SaferRAT (trojan bancaire/RAT Android, MaaS), documenté par Zimperium zLabs (juin 2026) dans le cadre d'une vague de 4 campagnes (RecruitRat, SaferRat, Astrinox, Massiv)

---

## 1. Contexte et choix du sujet

Recherché comme sujet "plus complexe", avec une leçon retenue en amont : **vérifier la disponibilité réelle du sample avant de s'engager**, pour éviter tout blocage d'acquisition.

[Zimperium zLabs](https://zimperium.com/blog/android-bankers-4-campaigns-in-a-row) documente SaferRAT parmi 4 campagnes actives ciblant plus de 800 applications bancaires/crypto/réseaux sociaux. Vérifié disponible sur **MalwareBazaar avant de commencer** : 2 échantillons taggés `SaferRAT`, tous deux téléchargeables intégralement et gratuitement.

## 2. Identité des échantillons

| Champ | Dropper | Payload réel |
|---|---|---|
| Nom de fichier (MalwareBazaar) | `Strawberry.apk` | `nested_app.apk` |
| SHA256 | `d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4` | `c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b` |
| Taille | 15 138 871 octets | 8 558 466 octets |
| Package Android | `com.example.nestedinstaller` | `s3zse.f01pdoi.ohnrb2` (nom obfusqué) |
| Label affiché | (icône générique) | **"Strawberry"** |
| Premier vu (MalwareBazaar) | 27/06/2026 | 27/06/2026 |
| Reporter | BastianHein_ | BastianHein_ |
| Signature MalwareBazaar | SaferRAT | SaferRAT |

**Point de nommage à ne pas confondre** : le fichier nommé `Strawberry.apk` sur MalwareBazaar est en réalité le **dropper** (package `nestedinstaller`), tandis que le fichier nommé `nested_app.apk` est le **vrai payload malveillant**, qui s'affiche lui-même sous le label "Strawberry" une fois installé. Les noms de fichiers de soumission ne reflètent pas la structure réelle, vérifié plutôt que supposé (§3).

## 3. Architecture à deux étages, confirmée octet pour octet

**Hypothèse de départ** (à partir des noms de fichiers) : un dropper "nested installer" qui embarque un second APK.

**Vérification directe** :
```bash
unzip -l Strawberry.apk | grep assets
# → assets/nested_app.apk, 8558466 octets
unzip -o Strawberry.apk assets/nested_app.apk
sha256sum assets/nested_app.apk
# → c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b
```

**Confirmé** : l'APK `assets/nested_app.apk` embarqué dans `Strawberry.apk` est, hash pour hash, exactement le second fichier téléchargé séparément depuis MalwareBazaar. Ce n'est pas une inférence depuis les noms, l'extraction et le hash le confirment de façon certaine.

```
Strawberry.apk (dropper, com.example.nestedinstaller)
  REQUEST_INSTALL_PACKAGES + QUERY_ALL_PACKAGES
  → assets/nested_app.apk (embarqué, identique hash pour hash au payload)
    → installé via NestedInstallerApp / InstallStatusReceiver
      → payload réel : s3zse.f01pdoi.ohnrb2, se présente comme "Strawberry"
```

Technique reconnue : livrer le vrai malware comme ressource embarquée d'un installeur à l'apparence anodine, plutôt que comme l'APK principal, limite ce que les scanners qui n'inspectent que le point d'entrée visible peuvent détecter.

## 4. Permissions et composants du payload réel : confirmation directe du rapport Zimperium

Le manifest du payload (`s3zse.f01pdoi.ohnrb2`) contient une liste de permissions et de composants qui recoupe précisément, point par point, les capacités décrites par Zimperium, mais avec les noms de classe réels, pas seulement une description :

| Capacité décrite par Zimperium | Composant confirmé dans le manifest |
|---|---|
| Prise de contrôle à distance / streaming en direct | `com.example.safeservice.vnc.VncAccessibilityService` (service d'accessibilité, littéralement nommé "Vnc") |
| Streaming caméra | `camera.CameraStreamActivity` + `camera.CameraStreamService` (`FOREGROUND_SERVICE_CAMERA`, `CAPTURE_VIDEO_OUTPUT`) |
| Streaming microphone | `microphone.MicrophoneStreamService` (`FOREGROUND_SERVICE_MICROPHONE`, `RECORD_AUDIO`) |
| Overlay de phishing via WebView distante | `InjectWebActivity` (`SYSTEM_ALERT_WINDOW`) |
| Interception SMS (OTP bancaire) | `SMSReceiver`, `MmsReceiver` (`RECEIVE_SMS`, `READ_SMS`, `SEND_SMS`, `BROADCAST_WAP_PUSH`), + prise de rôle app SMS par défaut (`DefaultSMSAppChooserActivity`, `HeadlessSmsSendService`) |
| Anti-suppression | `MyDeviceAdminReceiver` (`BIND_DEVICE_ADMIN`) |
| C2 | Trois canaux confirmés, pas un seul : panel HTTP (`gorila-panel.xyz`), WebSocket de contrôle temps réel (`VncWebSocketClient`), et `ProxyWebSocketService`, un proxy SOCKS inversé complet. Détail au §5.9 |

**Persistance, 5 mécanismes distincts trouvés**, plus que ce que Zimperium détaille : `KeepAliveJobService` (JobScheduler), `KeepAliveAlarmReceiver` (AlarmManager), `AlarmClockKeepAlive$AlarmClockReceiver` (abus d'alarme réveil, technique connue pour survivre au Doze mode), `KeepAliveWidget` (widget d'écran d'accueil qui redéclenche le service). Aussi : `sync.StubContentProvider` + `sync.AuthenticatorService`, abus du framework de comptes/synchronisation Android, une technique de persistance plus rare. Cinquième mécanisme confirmé en lisant `BotHeartbeatService`/`GuardService` en entier (§5.11) : un **watchdog mutuel**, chaque service relance l'autre s'il est tué.

**Piste ouverte notable** : une activité `com.example.safeservice.DeveloperActivity` (`exported=false`), nom suggérant un écran de debug/développeur laissé dans le build de production. **[OUVERT]**, pas encore inspecté son contenu, piste à suivre pour une éventuelle erreur OPSEC du développeur (§7).

## 5. Décompilation complète : le C2 en clair, et une vraie trouvaille d'attribution

`androguard decompile` sur le payload produit l'intégralité du code Java/Kotlin décompilé (des centaines de classes, y compris les bibliothèques tierces embarquées : OkHttp, Kotlin coroutines). Classes propres au malware toutes dans `com.example.safeservice` : `BotCallLogExporter`, `BotHeartbeatService`, `BotRegister`, `BotSmsExporter`, `CallListener`, `CallLogSender`, `ContactsFetcher`, `InjectConfigManager`, `InstalledAppsSender`, `KeyLoggerService`, `LocationSender`, `NotificationListener`, `PermissionsManager`, `PhotosExporter`, `ServerConfig`, `SilentAudioPlayer`, `SmsSender`, `UssdSender`, `vnc/VncAccessibilityService`, `vnc/VncWebSocketClient`, `vnc/ScreenCastService`, `vnc/MicrophoneStreamer`, un niveau de complétude et de modularité largement au-dessus d'un stealer commodity.

### 5.1 Le C2 en clair, trouvé dans `ServerConfig.java`

Contrairement à une config codée en dur dans le bytecode, le C2 est chargé au runtime depuis une **ressource JSON embarquée** (`res/raw/servers.json`), avec un mécanisme de rotation entre plusieurs serveurs de secours (`ServerConfig.next()`) :

```bash
unzip -p nested_app.apk res/raw/servers.json
```
```json
{
  "servers": [
    "https://gorila-panel.xyz"
  ]
}
```

**Vérification passive** (DNS + whois, aucune connexion au panel) :

| Champ | Valeur |
|---|---|
| Domaine | `gorila-panel.xyz` |
| IP résolue | `91.184.247.166` |
| Registrar | NameCheap, Inc. |
| Serveurs de noms | `NS1-4.VDSINA.RU`, **VDSINA, hébergeur VPS russe** |
| Créé | 13/11/2025, expire 13/11/2026 |
| ThreatFox / Shodan | Aucune entrée existante (IOC neuf, jamais documenté publiquement à ce jour) |

Ce domaine confirme, cette fois via de la vraie infrastructure (pas juste des commentaires de code), une piste russophone : hébergement chez VDSINA, un hébergeur VPS russe.

### 5.2 `DeveloperActivity` lue en entier : pas un vestige de debug, un assistant de configuration complet

Contrairement à l'hypothèse initiale ("débogage oublié"), le contenu réel montre un **écran d'assistant de mise en route** très abouti, avec des boutons dédiés par constructeur pour contourner les restrictions batterie/autostart des surcouches chinoises les plus agressives :

- Xiaomi/MIUI (`AutoStartManagementActivity`, `HiddenAppsConfigActivity`)
- Huawei/EMUI (`ProtectActivity`, `StartupNormalAppListActivity`)
- Samsung (`BatteryActivity`)
- OPPO/OnePlus/Realme/ColorOS (`StartupAppListActivity`)
- Vivo (`BgStartUpManagerActivity`)

Plus les demandes de permissions standards (overlay, notifications, batterie, SMS par défaut, caméra, localisation, micro, stockage) et un bouton d'accès direct aux réglages de réinitialisation d'usine (`openFactoryResetSettings`). **Tous les textes affichés sont en russe** ("✅ Разрешение камеры уже выдано", "Перейдите: Система → Сброс настроек"...), confirmation étendue (UI fonctionnelle complète, pas juste un commentaire) d'un développement russophone.

**Conclusion sur cette piste** : ce n'est pas une erreur OPSEC au sens propre (pas de fuite d'identité), mais ça révèle un niveau d'ingénierie et de polish (gestion différenciée de 5 familles d'OEM Android) cohérent avec un produit MaaS professionnel plutôt qu'un outil bricolé.

### 5.3 La liste des banques ciblées n'est pas statique : confirmé, pas supposé

`InjectConfigManager.java` confirme que la table `pkg → url_de_phishing` est peuplée exclusivement via `updateFromJson()`, reçue depuis le C2, **rien de statique à extraire de l'APK sur ce point**, cohérent avec le mécanisme "WebView chargée à distance" déjà décrit par Zimperium. Limite architecturale réelle, pas un manque de recherche.

### 5.4 Trouvaille d'attribution : le tag opérateur "Diabloo"

`BotRegister.java` construit la charge d'enregistrement envoyée au C2 (`POST /api/register_bot.php`) :

```java
v3_1.put("tag", p13);           // device ID (ANDROID_ID)
v3_1.put("phone", p14);          // numéro de téléphone de la victime
v3_1.put("worker", "Diabloo");   // <-- identifiant codé en dur
v3_1.put("sim_info", this.getSimInfo());  // opérateur, slot SIM, numéro
```

**`"Diabloo"` est un identifiant en dur**, très probablement le tag d'un opérateur/client spécifique dans un modèle MaaS (chaque acheteur du builder SaferRAT recevrait un build avec son propre tag "worker" pour que le panel distingue les infections de chaque client), ou une signature du développeur du build. Recherche web : **aucune occurrence publique documentée de "Diabloo"** en lien avec ce malware ou un builder connu, soit un tag privé jamais publié ailleurs, soit un pseudo sans lien avec une campagne déjà documentée. C'est la trouvaille la plus concrète en termes d'attribution.

### 5.5 Protocole complet de contrôle à distance (`VncWebSocketClient.handleCommand`)

Lecture directe du dispatcher de commandes confirme, exhaustivement, un système ATS (Automated Transfer System) complet, pas seulement du contrôle manuel façon VNC :

**Contrôle tactile temps réel** : `tap`, `touch_move`, `long_press`, `reset_touch`, `set_touch_mode` (bascule un mode "realTime"), `swipe_up`/`swipe_up_fast`/`swipe_up_menu`, `back`/`home` (actions système globales).

**Automatisation sans supervision** : `autopin`, l'opérateur envoie un PIN et une séquence de coordonnées (`sequence: [{x,y}, ...]`), rejouée automatiquement par `VncAccessibilityService.autoInputPin()`. Vraisemblablement utilisé pour ressaisir automatiquement un code PIN capturé au préalable (overlay de phishing ou keylogger) sans intervention manuelle de l'opérateur. `uidump` renvoie la hiérarchie d'accessibilité de l'écran (texte/structure), permettant une navigation automatisée sans dépendre du flux vidéo.

**Furtivité pendant l'opération** : `show_overlay_black` (overlay noir plein écran, technique connue pour masquer l'activité du bot à la victime pendant qu'il agit en arrière-plan), `volume_mute`/`volume_set`/`volume_get` (couper le son pour ne pas alerter la victime).

**Streaming** : `start_stream`/`stop_stream` (capture d'écran via `MediaProjection`), `start_camera`/`stop_camera`, `start_microphone`.

**Confirmation directe et exacte du rapport Zimperium** : les commandes `enable_anti_delete`/`disable_anti_delete` (§4) sont retrouvées telles quelles dans le dispatcher, avec le flag `VncAccessibilityService.isAntiDeleteEnabled`, recoupement précis, pas une simple ressemblance.

**Autres** : `unlock`/`lock_screen`, `toggle_injection`/`update_injection` (contrôle à distance de l'overlay de phishing, cohérent avec §5.3), `download_file`, `request_projection`.

### 5.6 Modules supplémentaires lus : exfiltration de notifications avec masquage, USSD, et un keylogger dupliqué mais inactif

**`NotificationListener`** (`NotificationListenerService`) exfiltre le titre et le texte de **chaque notification de chaque app** vers `/api/log_notification.php`, avec le tag `bot_tag` (ANDROID_ID). Le C2 fournit en retour une liste de "packages bloqués" (`GET /api/not_block_list.php?bot_tag=...`) : toute notification d'une app présente dans cette liste est à la fois exfiltrée **et supprimée silencieusement** de l'écran de la victime via `cancelNotification()`. C'est le mécanisme classique pour cacher les alertes bancaires ou les notifications de code 2FA à la victime tout en les captant côté attaquant, confirmé ici précisément par la lecture du code (la liste elle-même reste server-side, donc les packages réellement ciblés ne sont pas visibles statiquement, cohérent avec §5.3).

**`UssdSender`** confirme une capacité d'envoi de codes USSD arbitraires (via une intention `CALL` sur une URI `tel:*...#`), déclenchable à distance. Le code USSD réel envoyé viendrait du C2, pas de l'APK. Utilisation typique pour ce genre de fonction chez les trojans bancaires : activer un renvoi d'appel vers un numéro de l'attaquant (pour intercepter les OTP par appel vocal) ou consulter un solde.

**Correction par rapport à une lecture partielle antérieure** : `KeyLoggerService` (classe séparée, elle aussi une sous-classe `AccessibilityService`) contient bien un keylogger et un moniteur de presse-papier fonctionnels, envoyés à `/api/log_keystrokes.php`, mais **cette classe n'est déclarée nulle part dans le manifest** (seul `VncAccessibilityService` a l'intent-filter `android.accessibilityservice.AccessibilityService` requis pour qu'Android l'active), donc son code ne tourne pas sur ce build précis. **Mais le keylogging fonctionne bien sur ce build**, pas via cette classe séparée : la lecture complète de `VncAccessibilityService.java` (§5.7) montre que le service actif embarque son propre keylogger et son propre moniteur de presse-papier, indépendants de `KeyLoggerService`. La question ouverte n'est donc plus "le keylogging tourne-t-il", mais pourquoi le code dupliqué de `KeyLoggerService` a été laissé de côté, plutôt supprimé ou fusionné : vraisemblablement un reliquat d'une itération antérieure du framework MaaS, ou un module partagé entre builds dont celui-ci n'a pas besoin.

**`KeyLoggerService` lu intégralement (39 lignes utiles), comparé ligne à ligne avec `VncAccessibilityService`** : ce n'est pas une implémentation indépendante, c'est un ancêtre direct du même code. La preuve la plus nette : la ligne de log du moniteur de presse-papier, `"📋 Скопировано в буфер: "`, apparaît **verbatim, caractère pour caractère, emoji compris**, dans les deux classes, un copier-coller, pas une réécriture. Mais `KeyLoggerService` est une version bien plus rudimentaire : pas de bufferisation ni de délai de 1 seconde avant envoi (chaque `TYPE_VIEW_TEXT_CHANGED` part immédiatement en HTTP), aucune gestion de `TYPE_VIEW_CLICKED`, donc **aucune capture de PIN par coordonnées**, aucune intégration avec le `VncWebSocketClient` (uniquement du HTTP `POST` direct vers le même endpoint `/api/log_keystrokes.php`), et aucun des à-côtés d'un service d'accessibilité complet (pas de `setServiceInfo`, pas de notification de premier plan, pas de canal WorkManager). Conclusion la plus probable : `KeyLoggerService` est le prototype à partir duquel le keylogger et le moniteur de presse-papier ont été copiés puis étendus (bufferisation, capture de PIN, canal WebSocket) directement dans `VncAccessibilityService`, au moment où les fonctionnalités ont été consolidées dans un seul service d'accessibilité (Android ne permet d'en lier proprement qu'un seul à la fois). La classe d'origine a été laissée dans le code, non déclarée, plutôt que supprimée, un reliquat de refactoring, pas un module désactivable par client comme envisagé plus tôt.

### 5.7 `VncAccessibilityService` lu intégralement : keylogger et moniteur de presse-papier actifs, avec capture et rejeu de PIN

La lecture complète de `VncAccessibilityService.java` (1039 lignes) et de son `Companion` confirme, code à l'appui, que le service réellement actif fait tout le travail que `KeyLoggerService` aurait pu faire, avec en plus un pipeline de capture de code PIN bien plus élaboré que le simple keylogging générique.

**Keylogger générique** : `onAccessibilityEvent()` capture les événements `TYPE_VIEW_TEXT_CHANGED` (saisie dans un champ de texte) sur n'importe quelle app au premier plan, bufferise le texte, et l'envoie après 1 seconde d'inactivité (`inputDelay`) à `sendKeystrokeToServer()`, qui `POST` vers `/api/log_keystrokes.php` avec `bot_tag` (Android ID), nom de l'app et texte.

**Moniteur de presse-papier** : câblé directement dans `onServiceConnected()` via `clipboardManager.addPrimaryClipChangedListener(...)`, envoie le contenu copié au même endpoint, taggé `"clipboard"`.

**Capture de code PIN, avec coordonnées exactes et horodatage** : `onAccessibilityEvent()` capture aussi les événements `TYPE_VIEW_CLICKED` (tap sur un bouton). Si le texte du bouton cliqué est un chiffre unique (regex `^\d{1}$`), typiquement une touche de clavier PIN à l'écran, le service route l'événement vers `trackPinClickWithCoords()` plutôt que vers le keylogger générique : cette méthode calcule le centre exact du bouton tapé (`getBoundsInScreen()`), horodate le tap, l'accumule dans une séquence (`pinTouchSequence`), et envoie immédiatement au C2 en WebSocket brut un message `{"type":"pin_click","data":{"digit","x","y","timestamp"}}`. Après 3 secondes sans nouveau chiffre, `trackPinClickWithCoords$lambda$13` vérifie si l'écran est déverrouillé (`KeyguardManager.isKeyguardLocked()`) : si oui, ce qui signifie que le PIN saisi a bien débloqué l'appareil, il envoie un second message `{"type":"pin_verified","bot_tag","pin","timestamp","sequence":[...]}` via `sendVerifiedPin()`, la séquence complète de taps (chiffre + x + y + horodatage) incluse. Le texte des boutons non numériques cliqués (labels, contenu-description) est aussi loggé, tagué `"[PIN] "`, dans le même flux keylogger générique mais marqué différemment du texte de champ classique.

Ce mécanisme explique directement la commande `autopin` déjà identifiée au §5.5 : la séquence de taps capturée avec ses coordonnées exactes est exactement le format que `autoInputPin()` attend en retour pour rejouer la saisie plus tard sur un autre écran de verrouillage (par exemple après un redémarrage forcé de l'appareil).

**`autoInputPin()` (rejeu), implémentation confirmée** : pour chaque paire de coordonnées reçue du C2, un `Handler.postDelayed()` est programmé avec un délai de `index * 400` millisecondes, donc un tap toutes les 400 ms, dans l'ordre, avant d'appeler `performTap(x, y)` sur chaque position. Ce séquencement volontairement lent (au lieu d'un rejeu instantané) simule un rythme de frappe humain plausible plutôt qu'une saisie automatisée trop rapide qui attirerait l'attention ou déclencherait une détection anti-bot côté banque.

**`dumpUiHierarchy()`, implémentation confirmée** : parcourt réellement l'arbre d'accessibilité depuis `getRootInActiveWindow()` (traversée récursive de tous les enfants), construit un tableau JSON avec classe, limites à l'écran et texte de chaque noeud visible, et l'envoie en direct au C2 via WebSocket sous la forme `{"type":"uidump","data":[...]}`. Confirme que la navigation à distance peut s'appuyer sur la structure réelle de l'écran plutôt que sur un flux vidéo interprété à l'oeil, une capacité d'automatisation plus fiable qu'un simple contrôle façon VNC manuel.

**`showOverlayWeb()`, implémentation confirmée** : crée une vraie `android.webkit.WebView`, avec `setJavaScriptEnabled(true)`, `setDomStorageEnabled(true)`, et charge l'URL reçue du C2 (`loadUrl(p12)`), affichée en overlay plein écran par-dessus l'app active via `WindowManager`. Confirme, au niveau du code et pas seulement de la description Zimperium, que l'overlay de phishing est une page web complète et interactive chargée à distance, pas une simple image statique.

### 5.8 Injection tactile confirmée au niveau de la vraie API Android, pas un stub

`performTap()`, `performInitialLongPress()`, `processRealtimePoints()` et `finishRealtimeGesture()` utilisent tous la véritable API d'accessibilité Android pour l'injection tactile : construction d'un `android.graphics.Path`, encapsulation dans un `GestureDescription.StrokeDescription` (avec durée réelle : 100 ms pour un tap simple, 300 ms pour un appui long, continu par segments de 30 ms en mode temps réel), puis appel à `AccessibilityService.dispatchGesture()`, l'API officielle Android pour simuler des gestes utilisateur depuis un service d'accessibilité. Ce n'est donc pas une injection d'événements bas niveau ou un exploit, mais un usage légitime (au sens API) et documenté de l'accessibilité, détourné à des fins malveillantes, cohérent avec l'ensemble du modèle d'abus de ce malware (voir aussi le contournement anti-suppression au §4, qui utilise la même API `performGlobalAction`).

### 5.9 Trois canaux C2 distincts, sur deux hébergeurs différents

La lecture complète de `onServiceConnected()`, de `ProxyWebSocketService.java` et de `BotHeartbeatService.java` révèle que ce payload ne parle pas à un seul C2, mais à quatre services réseau séparés sur deux hébergeurs, chacun avec son propre rôle :

| Service | Endpoint | Rôle | Hébergeur |
|---|---|---|---|
| Panel HTTP | `gorila-panel.xyz` (`91.184.247.166`) | Tous les endpoints `/api/*.php` : enregistrement, exfiltration keylogger/notifications/PIN/contacts/appels, réception de la liste d'injection (§5.3), **et polling de commandes** (`GET /api/get_bot_commands.php`, toutes les 10 secondes, voir §5.11) | VDSINA (VPS russe) |
| WebSocket de contrôle temps réel | `ws://94.103.89.12:8765`, codé en dur dans `onServiceConnected()` | Commandes ATS en direct (`tap`, `autopin`, `uidump`, streaming, voir §5.5), capture PIN en direct (`pin_click`/`pin_verified`, §5.7) | VDSINA (même IP, port différent du suivant) |
| Upload photo/vidéo en masse | `http://94.103.89.12:9000/upload_photo`, codé en dur dans `PhotosExporter` | Réception de ZIP multipart contenant l'intégralité de la pellicule photo/vidéo de la victime (§5.11) | VDSINA (même IP que le contrôle temps réel, port distinct : service HTTP séparé, pas le même processus WebSocket) |
| `ProxyWebSocketService` | `ws://89.185.80.124:55332/socks/<bot_id>`, codé en dur | Proxy SOCKS inversé complet, **présent dans le code et fonctionnel, mais jamais démarré sur ce build** (voir correction ci-dessous) | Global Connectivity Solutions (Royaume-Uni/Danemark), hébergeur distinct des trois autres |

**Le proxy SOCKS inversé, confirmé par lecture de `handleTextMessage()`/`handleBinaryMessage()`** : le C2 envoie une commande texte `connId:host:port`, et le téléphone infecté ouvre une vraie `java.net.Socket` TCP vers cette destination, depuis le réseau et l'adresse IP de la victime. Les données binaires sont ensuite relayées dans les deux sens sur la connexion WebSocket, préfixées par la longueur et la valeur de `connId` pour multiplexer plusieurs connexions simultanées. C'est la technique classique de "proxy résidentiel involontaire" utilisée par les trojans bancaires pour faire transiter une session frauduleuse par l'IP et l'empreinte réseau de la victime, contournant ainsi les contrôles anti-fraude basés sur la géolocalisation ou la liaison IP/appareil côté banque. Détail cosmétique notable : la notification de premier plan de ce service affiche "Antivirus" / "System heart", un déguisement pour rassurer la victime si elle consulte la liste des notifications persistantes.

**Correction, honnêteté méthodologique** : la lecture de `BotHeartbeatService.onCreate()` (§5.11) montre un log explicite, `"🛑 Режим прокси отключён, ProxyWebSocketService не будет запущен"` ("mode proxy désactivé, ProxyWebSocketService ne sera pas démarré"), et une recherche exhaustive de tous les points d'appel (`grep` sur l'ensemble du code décompilé) ne trouve **aucun autre endroit** où ce service est instancié ou démarré. Même situation que `KeyLoggerService` (§5.6) : du code réel, complet et fonctionnel, mais dormant sur ce build précis. Le canal reste un IOC valide (l'URL est bien codée en dur et le code est prêt à s'exécuter si jamais activé), mais ce n'est pas un canal actif observé en fonctionnement sur cet échantillon.

Aucune des deux nouvelles IP (`94.103.89.12`, `89.185.80.124`) n'a d'entrée ThreatFox ou Shodan existante, deux IOC neufs supplémentaires.

### 5.10 Triage structuré complémentaire (`quark-engine`)

`quark-engine` (v26.7.1, règles à jour au 19/07/2026) classe le payload **"High Risk"** (score cumulé 0.97 au seuil de confiance 60%), avec plus de 130 comportements reconnus à 60% de confiance ou plus. Aucune capacité nouvelle par rapport à la lecture manuelle de code (§5.1-§5.9) : les signatures les mieux pondérées recoupent exactement ce qui a déjà été confirmé ligne à ligne, invocation dynamique par réflexion (poids 3.01), envoi HTTP POST (1.96), résolution de champ par réflexion (1.79), lecture du presse-papier, dispatch de gestes, création d'overlay, accès à l'arbre d'accessibilité par texte/ID/racine de fenêtre, lecture de SMS/journal d'appels/contacts, requête de localisation. Utile comme validation indépendante et automatisée du périmètre de capacités déjà établi, mais n'apporte pas d'élément d'attribution ou de C2 supplémentaire, la lecture manuelle du code reste la source de tous les IOC et détails de protocole de ce document.

### 5.11 Les six derniers modules lus : orchestration, streaming d'écran réel, et exfiltration de masse de la pellicule

**`BotHeartbeatService`, le vrai chef d'orchestre**, plus central que son nom ne le suggère. Trois apports majeurs :

- **Un canal de commandes supplémentaire, par polling HTTP** (`GET /api/get_bot_commands.php?tag=<bot_tag>`, sur le même panel `gorila-panel.xyz`, toutes les 10 secondes), avec son propre jeu de commandes, différent de celui du WebSocket temps réel (§5.5) : `export_sms`/`export_call_log` (déclenchent `BotSmsExporter`/`BotCallLogExporter`, export en masse), `send_sms` (avec délai et choix de slot SIM configurables), `send_ussd`, `show_notification` (affiche une fausse notification système avec titre/texte fournis par le C2, un déclencheur d'ingénierie sociale à la demande), et **`add_contact`** : insère un faux contact directement dans le carnet d'adresses de la victime via `ContentProviderOperation` sur `ContactsContract`, nom et numéro fournis par le C2. Utilisation la plus probable : faire apparaître un faux numéro de "support bancaire" comme contact légitime pour du vishing (l'appel entrant semble alors venir d'un contact enregistré plutôt que d'un inconnu).
- **Un cinquième mécanisme de persistance, un watchdog mutuel** : `BotHeartbeatService` démarre `GuardService` et vérifie toutes les 60 secondes qu'il tourne encore ; `GuardService`, de son côté, relance `BotHeartbeatService` toutes les 30 secondes (`checkMainProcess()`). Chaque service ressuscite l'autre s'il est tué, notification de `GuardService` volontairement invisible (`setSilent(true)`, priorité minimale, pas de badge). `onTaskRemoved()` sur `BotHeartbeatService` relance aussi immédiatement le service si l'utilisateur swipe l'app hors des apps récentes.
- Démarre aussi `SilentAudioPlayer` (ci-dessous) et confirme, par un log explicite, que `ProxyWebSocketService` (§5.9) n'est pas démarré sur ce build.

**`SilentAudioPlayer`** : joue en boucle une piste audio silencieuse embarquée (`res/raw/silent`), volume à zéro, avec `setWakeMode`, redémarrage automatique en cas d'erreur (`OnErrorListener`). Technique connue pour maintenir un processus Android en vie : une session de lecture multimédia active bénéficie d'exemptions de restrictions batterie/Doze que le service lui-même n'aurait pas seul.

**`ScreenCastService`**, le vrai streaming d'écran confirmé au niveau implémentation : capture via `MediaProjection` + `ImageReader` + `VirtualDisplay`, chaque frame convertie en `Bitmap`, compressée en JPEG (qualité 60), encodée en Base64, envoyée en direct sur **le même canal WebSocket que le contrôle temps réel** (`ws://94.103.89.12:8765`, §5.9) sous la forme `{"type":"screencast","image":"data:image/jpeg;base64,..."}`. Confirme précisément le mécanisme de streaming déjà décrit par Zimperium, avec le protocole exact.

**`PhotosExporter`, exfiltration automatique de toute la pellicule, pas seulement sur commande** : parcourt `MediaStore` (images et vidéos), traite par lots de 100 fichiers, compresse les images (JPEG qualité 75, redimensionnées à 1920x1080 maximum) et copie les vidéos telles quelles, empaquette chaque lot en ZIP, et l'envoie en `multipart/form-data` vers **un quatrième service réseau distinct**, `http://94.103.89.12:9000/upload_photo` (même IP que le WebSocket de contrôle, port et protocole différents, un serveur HTTP séparé). Point important confirmé en cherchant tous les appelants : `exportPhotosAndUpload()` est déclenché **automatiquement depuis `MainActivity`**, à plusieurs endroits liés à l'octroi des permissions de stockage/médias au premier lancement, pas sur commande du C2. Dès que l'app obtient l'accès à la galerie, l'exfiltration complète des photos et vidéos démarre sans action de l'opérateur.

**`ContactsFetcher`, confirmé actif** (pas juste présent) : contrôlé par le flag `ENABLE_CONTACTS_FETCH`, une constante `true` codée en dur dans `MainActivity` et réaffirmée dans un gestionnaire `onActivityResult`, donc bien active sur ce build, contrairement à la prudence affichée initialement dans le plan de reprise. Exfiltre nom + numéro de chaque contact vers `/api/upload_contacts.php`, avec un flag `SharedPreferences` pour ne le faire qu'une seule fois par installation.

**`CallLogSender`, un flux distinct de `BotCallLogExporter`** : alors que la commande `export_call_log` (ci-dessus) déclenche un export en masse de l'historique d'appels sur demande, `CallLogSender.sendCallLog()` envoie **chaque appel entrant individuellement et en temps réel** vers `/api/log_call.php` dès qu'il se produit (déclenché par `CallListener`, un écouteur d'état téléphonique enregistré par `BotHeartbeatService`). Deux mécanismes de surveillance des appels, l'un continu, l'autre à la demande, pas redondants.

## 6. Ce qui reste à faire (plan de reprise)

1. ~~Lire le code complet de `VncAccessibilityService`/`VncWebSocketClient`~~, fait intégralement (1039 lignes + Companion) : confirme un keylogger et un moniteur de presse-papier actifs directement dans ce service (§5.7), un pipeline de capture et rejeu de PIN avec coordonnées exactes (§5.7), et une injection tactile réelle via `dispatchGesture`/`GestureDescription` (§5.8).
2. ~~Vérifier si le dropper et le payload partagent le même certificat de signature APK~~, fait : **non**, les deux sont signés avec le keystore de debug Android générique (`CN=Android Debug`), donc pas de certificat personnalisé exploitable pour l'attribution. Détail retenu : la clé du payload date de mars 2025, celle du dropper de juin 2026, ~15 mois d'écart, suggérant une réutilisation d'environnement de build sur la durée.
3. ~~Chercher d'autres échantillons SaferRAT sur MalwareBazaar avec un tag "worker" différent~~, fait : **aucun autre sample disponible**, seulement les 2 déjà en main. Hypothèse multi-opérateurs non testable avec les données publiques actuelles.
4. ~~Lire `ProxyWebSocketService`, `BotHeartbeatService`, `ScreenCastService`, `ContactsFetcher`, `PhotosExporter`, `CallLogSender`, `SilentAudioPlayer` en entier~~, fait (voir §5.9/§5.11) : un cinquième mécanisme de persistance (watchdog mutuel `BotHeartbeatService`/`GuardService`), un canal de commandes supplémentaire par polling HTTP avec son propre jeu de commandes (`add_contact`, `show_notification`, `send_ussd`...), un quatrième service réseau dédié à l'exfiltration en masse de la pellicule photo/vidéo, et la confirmation que `ProxyWebSocketService` n'est en réalité jamais démarré sur ce build.
5. ~~Comprendre pourquoi `KeyLoggerService` existe en doublon du keylogger déjà intégré à `VncAccessibilityService`~~, fait par comparaison ligne à ligne (voir §5.6) : le texte de log du moniteur de presse-papier est identique caractère pour caractère entre les deux classes, un copier-coller confirmé, pas une réécriture indépendante. `KeyLoggerService` est le prototype plus simple à partir duquel le keylogger a été copié puis étendu (bufferisation, capture de PIN, canal WebSocket) dans `VncAccessibilityService` au moment de la consolidation en un seul service d'accessibilité, laissé en place non déclaré plutôt que supprimé.
6. ~~Installer `quark-engine` pour un triage de capacités structuré complémentaire~~, fait (voir §5.10) : classe le payload "High Risk", confirme la même surface de capacités déjà établie par lecture manuelle, aucun élément nouveau.
7. Soumission manuelle à ThreatFox via leur portail web (la soumission par API a échoué, voir §7) de quatre IOC désormais : `gorila-panel.xyz`, `94.103.89.12:8765`, `94.103.89.12:9000` et `89.185.80.124:55332`, et signalement des deux hébergeurs concernés (VDSINA, abuse@vdsina.ru ; Global Connectivity Solutions, abuse@globconnex.com), préparés, envoi laissé à l'utilisateur

## 7. Limites et honnêteté méthodologique (état actuel)

- L'attribution "Diabloo" est une observation brute (chaîne en dur), pas une identité confirmée, pourrait être un tag de build, un pseudo, ou autre chose.
- Aucune confirmation indépendante (sandbox tierce type Triage/ANY.RUN) consultée.
- **Tentative de soumission à ThreatFox via API échouée** (`user_unknown`) : la clé Auth-Key valide pour les recherches MalwareBazaar/ThreatFox n'est pas reconnue pour la soumission d'IOC, qui semble nécessiter un compte connecté sur le portail web abuse.ch. Reste à faire manuellement par l'utilisateur.
- `ProxyWebSocketService` (proxy SOCKS inversé) est confirmé présent et fonctionnel dans le code, mais confirmé **non démarré** sur ce build précis (§5.9) : IOC valide (URL codée en dur), mais pas un canal observé en fonctionnement actif sur cet échantillon.

## 8. IOCs consolidés (état actuel)

| Type | Valeur |
|---|---|
| SHA256 dropper (`Strawberry.apk`) | `d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4` |
| SHA256 payload (`nested_app.apk`, embarqué et confirmé identique) | `c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b` |
| Package dropper | `com.example.nestedinstaller` |
| Package payload | `s3zse.f01pdoi.ohnrb2` |
| Label affiché du payload | Strawberry |
| **C2 panel HTTP** | `gorila-panel.xyz` (`91.184.247.166`) |
| Hébergement C2 panel (NS) | VDSINA (VPS russe) |
| **C2 WebSocket de contrôle temps réel** | `ws://94.103.89.12:8765`, codé en dur, VDSINA également |
| **Service d'upload photo/vidéo en masse** | `http://94.103.89.12:9000/upload_photo`, codé en dur, même IP que le WebSocket de contrôle, port et protocole distincts |
| **C2 proxy SOCKS inversé (présent, non démarré sur ce build)** | `ws://89.185.80.124:55332/socks/<bot_id>`, codé en dur, hébergeur distinct (Global Connectivity Solutions, UK/DK) |
| Endpoints C2 HTTP confirmés | `POST /api/register_bot.php`, `POST /api/log_notification.php`, `GET /api/not_block_list.php`, `POST /api/log_keystrokes.php`, `POST /api/log_call.php`, `POST /api/upload_contacts.php`, `GET /api/get_bot_commands.php` (polling, 10s) |
| Commandes reçues via polling HTTP confirmées | `export_sms`, `send_sms`, `export_call_log`, `show_notification`, `send_ussd`, `add_contact` (voir §5.11) |
| Messages WebSocket bot vers C2 confirmés | `pin_click`, `pin_verified`, `uidump`, `volume_info`, `screencast` (voir §5.7, §5.11) |
| Tag opérateur/build | `Diabloo` |
| Service VNC/accessibilité (actif, keylogger + presse-papier + capture PIN intégrés) | `com.example.safeservice.vnc.VncAccessibilityService` |
| Keylogger dupliqué (code présent, service non déclaré, inactif sur ce build, fonction déjà assurée par `VncAccessibilityService`) | `com.example.safeservice.KeyLoggerService` |
| Watchdog mutuel (5e mécanisme de persistance) | `com.example.safeservice.BotHeartbeatService` ↔ `com.example.safeservice.GuardService` |
| SHA256 certificat de signature (dropper) | `a7434275...` (keystore debug Android générique) |
| SHA256 certificat de signature (payload) | `c3fcf873...` (keystore debug Android générique, différent du dropper) |
| Famille | SaferRAT |
| Rapport source | [Zimperium zLabs, juin 2026](https://zimperium.com/blog/android-bankers-4-campaigns-in-a-row) |

## 9. Reproduire l'analyse

Log détaillé dans [`runbook.md`](runbook.md).
