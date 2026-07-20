# SaferRAT Analysis: A Two-Stage Android Banking Trojan with VNC-Style Remote Control

**Analyst:** Gordon PEIRS
**Analysis date:** 19/07/2026
**Type:** Static analysis only (the APKs were never installed or executed on a device or emulator). Manifest, package structure and full decompiled source via `androguard`.
**Family:** SaferRAT (Android banking trojan/RAT, Malware-as-a-Service), documented by Zimperium zLabs (June 2026) as part of a wave of 4 campaigns (RecruitRat, SaferRat, Astrinox, Massiv)

> English translation of the full French writeup ([`writeup.md`](writeup.md)), same content, prepared for external sharing (submission references, outreach).

---

## 1. Context and why this sample

Picked as a "harder" subject, with a lesson retained upfront: **verify real sample availability before committing**, to avoid any acquisition blocker.

[Zimperium zLabs](https://zimperium.com/blog/android-bankers-4-campaigns-in-a-row) documents SaferRAT as one of 4 active campaigns targeting over 800 banking/crypto/social-media apps. Verified available on **MalwareBazaar before starting**: 2 samples tagged `SaferRAT`, both fully and freely downloadable.

## 2. Sample identity

| Field | Dropper | Real payload |
|---|---|---|
| File name (MalwareBazaar) | `Strawberry.apk` | `nested_app.apk` |
| SHA256 | `d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4` | `c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b` |
| Size | 15,138,871 bytes | 8,558,466 bytes |
| Android package | `com.example.nestedinstaller` | `s3zse.f01pdoi.ohnrb2` (obfuscated) |
| Displayed label | (generic icon) | **"Strawberry"** |
| First seen (MalwareBazaar) | 2026-06-27 | 2026-06-27 |
| Reporter | BastianHein_ | BastianHein_ |
| MalwareBazaar signature | SaferRAT | SaferRAT |

**Naming trap, worth flagging explicitly**: the file named `Strawberry.apk` on MalwareBazaar is actually the **dropper** (package `nestedinstaller`), while the file named `nested_app.apk` is the **real malicious payload**, which displays itself under the label "Strawberry" once installed. Submission filenames don't reflect the real structure, verified rather than assumed (§3).

## 3. Two-stage architecture, confirmed byte-for-byte

**Starting hypothesis** (from the file names alone): a "nested installer" dropper embedding a second APK.

**Direct verification**:
```bash
unzip -l Strawberry.apk | grep assets
# → assets/nested_app.apk, 8558466 bytes
unzip -o Strawberry.apk assets/nested_app.apk
sha256sum assets/nested_app.apk
# → c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b
```

**Confirmed**: the `assets/nested_app.apk` embedded in `Strawberry.apk` is, hash for hash, exactly the second file downloaded separately from MalwareBazaar. Not an inference from naming, extraction and hashing confirm it with certainty.

```
Strawberry.apk (dropper, com.example.nestedinstaller)
  REQUEST_INSTALL_PACKAGES + QUERY_ALL_PACKAGES
  → assets/nested_app.apk (embedded, hash-identical to the real payload)
    → installed via NestedInstallerApp / InstallStatusReceiver
      → real payload: s3zse.f01pdoi.ohnrb2, presents itself as "Strawberry"
```

Recognized technique: ship the real malware as an embedded resource of an innocuous-looking installer rather than as the main APK, limits what scanners that only inspect the visible entry point can catch.

## 4. Real payload permissions and components: direct confirmation of the Zimperium report

The real payload's manifest (`s3zse.f01pdoi.ohnrb2`) lists permissions and components that match, point for point, the capabilities described by Zimperium, but with the actual class names, not just a description:

| Capability described by Zimperium | Component confirmed in the manifest |
|---|---|
| Remote control / live streaming | `com.example.safeservice.vnc.VncAccessibilityService` (accessibility service, literally named "Vnc") |
| Camera streaming | `camera.CameraStreamActivity` + `camera.CameraStreamService` (`FOREGROUND_SERVICE_CAMERA`, `CAPTURE_VIDEO_OUTPUT`) |
| Microphone streaming | `microphone.MicrophoneStreamService` (`FOREGROUND_SERVICE_MICROPHONE`, `RECORD_AUDIO`) |
| Phishing overlay via remote WebView | `InjectWebActivity` (`SYSTEM_ALERT_WINDOW`) |
| SMS interception (banking OTP) | `SMSReceiver`, `MmsReceiver` (`RECEIVE_SMS`, `READ_SMS`, `SEND_SMS`, `BROADCAST_WAP_PUSH`), plus default-SMS-app role hijacking (`DefaultSMSAppChooserActivity`, `HeadlessSmsSendService`) |
| Anti-removal | `MyDeviceAdminReceiver` (`BIND_DEVICE_ADMIN`) |
| C2 | Three confirmed channels, not one: HTTP panel (`gorila-panel.xyz`), real-time control WebSocket (`VncWebSocketClient`), and `ProxyWebSocketService`, a full reverse SOCKS proxy. Detail in §5.9 |

**Persistence, 5 distinct mechanisms found**, more than Zimperium details: `KeepAliveJobService` (JobScheduler), `KeepAliveAlarmReceiver` (AlarmManager), `AlarmClockKeepAlive$AlarmClockReceiver` (alarm-clock abuse, a known technique to survive Doze mode), `KeepAliveWidget` (home-screen widget that re-triggers the service). Also: `sync.StubContentProvider` + `sync.AuthenticatorService`, abuse of Android's account/sync framework, a rarer persistence technique. A fifth mechanism, confirmed by fully reading `BotHeartbeatService`/`GuardService` (§5.11): a **mutual watchdog**, each service restarts the other if killed.

**Notable open lead**: an activity `com.example.safeservice.DeveloperActivity` (`exported=false`), a name suggesting a debug/developer screen left in the production build. **[OPEN]**, content not yet inspected at the time this thread was first raised, followed up in §5.2.

## 5. Full decompilation: the C2 in plaintext, and a real attribution lead

`androguard decompile` on the payload produces the full decompiled Java/Kotlin source (hundreds of classes, including bundled third-party libraries: OkHttp, Kotlin coroutines). Malware-specific classes, all under `com.example.safeservice`: `BotCallLogExporter`, `BotHeartbeatService`, `BotRegister`, `BotSmsExporter`, `CallListener`, `CallLogSender`, `ContactsFetcher`, `InjectConfigManager`, `InstalledAppsSender`, `KeyLoggerService`, `LocationSender`, `NotificationListener`, `PermissionsManager`, `PhotosExporter`, `ServerConfig`, `SilentAudioPlayer`, `SmsSender`, `UssdSender`, `vnc/VncAccessibilityService`, `vnc/VncWebSocketClient`, `vnc/ScreenCastService`, `vnc/MicrophoneStreamer`, a level of completeness and modularity well above commodity stealer code.

### 5.1 The C2 in plaintext, found in `ServerConfig.java`

Rather than a hardcoded string in the bytecode, the C2 is loaded at runtime from an **embedded JSON resource** (`res/raw/servers.json`), with a rotation mechanism across fallback servers (`ServerConfig.next()`):

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

**Passive verification** (DNS + whois, no connection made to the panel):

| Field | Value |
|---|---|
| Domain | `gorila-panel.xyz` |
| Resolved IP | `91.184.247.166` |
| Registrar | NameCheap, Inc. |
| Name servers | `NS1-4.VDSINA.RU`, **VDSINA, a Russian VPS host** |
| Created | 2025-11-13, expires 2026-11-13 |
| ThreatFox / Shodan | No existing entry (fresh IOC, not publicly documented as of this writing) |

This domain confirms, this time via real infrastructure rather than just code comments, a Russian-speaking lead: hosted at VDSINA, a Russian VPS provider.

### 5.2 `DeveloperActivity` read in full: not debug leftovers, a complete onboarding assistant

Contrary to the initial hypothesis ("forgotten debug screen"), the real content is a fully-featured **setup wizard**, with dedicated buttons per OEM to bypass the most aggressive battery/autostart restrictions on Chinese Android skins:

- Xiaomi/MIUI (`AutoStartManagementActivity`, `HiddenAppsConfigActivity`)
- Huawei/EMUI (`ProtectActivity`, `StartupNormalAppListActivity`)
- Samsung (`BatteryActivity`)
- OPPO/OnePlus/Realme/ColorOS (`StartupAppListActivity`)
- Vivo (`BgStartUpManagerActivity`)

Plus the standard permission requests (overlay, notifications, battery, default SMS app, camera, location, mic, storage) and a direct shortcut to factory-reset settings (`openFactoryResetSettings`). **Every displayed string is in Russian** ("✅ Camera permission already granted", "Go to: System → Factory reset"...), extensive confirmation (a full functional UI, not just a comment) of Russian-speaking development.

**Conclusion on this lead**: not an OPSEC mistake in the strict sense (no identity leak), but it reveals a level of engineering polish (differentiated handling of 5 Android OEM families) consistent with a professional MaaS product rather than a hacked-together tool.

### 5.3 The targeted bank list is not static: confirmed, not assumed

`InjectConfigManager.java` confirms that the `pkg → phishing_url` table is populated exclusively via `updateFromJson()`, received from the C2, **nothing static to extract from the APK on this point**, consistent with the "remotely-loaded WebView" mechanism already described by Zimperium. A real architectural limit, not a research gap.

### 5.4 Attribution lead: the "Diabloo" operator tag

`BotRegister.java` builds the registration payload sent to the C2 (`POST /api/register_bot.php`):

```java
v3_1.put("tag", p13);           // device ID (ANDROID_ID)
v3_1.put("phone", p14);          // victim's phone number
v3_1.put("worker", "Diabloo");   // <-- hardcoded identifier
v3_1.put("sim_info", this.getSimInfo());  // carrier, SIM slot, number
```

**`"Diabloo"` is a hardcoded identifier**, most likely a tag for a specific operator/customer in a MaaS model (each buyer of the SaferRAT builder would get a build with their own "worker" tag so the panel can separate each customer's infections), or a signature of whoever built this specific sample. Web search: **no public occurrence of "Diabloo"** tied to this malware or any known builder, either a private tag never published elsewhere, or a handle unrelated to any already-documented campaign. This is the most concrete attribution finding of this investigation.

### 5.5 Full remote-control protocol (`VncWebSocketClient.handleCommand`)

Direct reading of the command dispatcher confirms, exhaustively, a complete ATS (Automated Transfer System), not just manual VNC-style control:

**Real-time touch control**: `tap`, `touch_move`, `long_press`, `reset_touch`, `set_touch_mode` (toggles a "realTime" mode), `swipe_up`/`swipe_up_fast`/`swipe_up_menu`, `back`/`home` (global system actions).

**Unsupervised automation**: `autopin`, the operator sends a PIN and a coordinate sequence (`sequence: [{x,y}, ...]`), automatically replayed by `VncAccessibilityService.autoInputPin()`. Likely used to automatically re-enter a PIN captured beforehand (phishing overlay or keylogger) without manual operator intervention. `uidump` returns the screen's accessibility hierarchy (text/structure), enabling automated navigation without relying on the video feed.

**Stealth during operation**: `show_overlay_black` (full-screen black overlay, a known technique to hide the bot's activity from the victim while it operates in the background), `volume_mute`/`volume_set`/`volume_get` (mute sound so as not to alert the victim).

**Streaming**: `start_stream`/`stop_stream` (screen capture via `MediaProjection`), `start_camera`/`stop_camera`, `start_microphone`.

**Direct, exact confirmation of the Zimperium report**: the `enable_anti_delete`/`disable_anti_delete` commands (§4) are found verbatim in the dispatcher, tied to the `VncAccessibilityService.isAntiDeleteEnabled` flag, a precise match, not just a resemblance.

**Other commands**: `unlock`/`lock_screen`, `toggle_injection`/`update_injection` (remote control of the phishing overlay, consistent with §5.3), `download_file`, `request_projection`.

### 5.6 Additional modules read: notification exfiltration with hiding, USSD, and a duplicated-but-dormant keylogger

**`NotificationListener`** (`NotificationListenerService`) exfiltrates the title and text of **every notification from every app** to `/api/log_notification.php`, tagged with `bot_tag` (ANDROID_ID). The C2 returns a "blocked packages" list (`GET /api/not_block_list.php?bot_tag=...`): any notification from an app on that list is both exfiltrated **and silently removed** from the victim's screen via `cancelNotification()`. This is the classic mechanism to hide banking alerts or 2FA notifications from the victim while still capturing them, confirmed here directly from the code (the actual list itself stays server-side, so the real targeted packages aren't visible statically, consistent with §5.3).

**`UssdSender`** confirms a capability to send arbitrary USSD codes (via a `CALL` intent on a `tel:*...#` URI), triggerable remotely. The real USSD code would come from the C2, not the APK. Typical use for banking trojans: enable call forwarding to an attacker number (to intercept voice-call OTPs) or check a balance.

**Correction relative to an earlier, partial reading**: `KeyLoggerService` (a separate class, also an `AccessibilityService` subclass) does contain a functional keylogger and clipboard monitor, sent to `/api/log_keystrokes.php`, but **this class isn't declared anywhere in the manifest** (only `VncAccessibilityService` has the `android.accessibilityservice.AccessibilityService` intent-filter Android requires to activate it), so its code doesn't run on this build. **But keylogging does run on this build**, just not via this separate class: the full reading of `VncAccessibilityService.java` (§5.7) shows the active service carries its own keylogger and its own clipboard monitor, independent of `KeyLoggerService`. The open question is no longer "does keylogging run", but why the duplicated `KeyLoggerService` code was left aside rather than deleted or merged: most likely a leftover from an earlier iteration of the MaaS framework, or a module shared across builds that this one doesn't need.

**`KeyLoggerService` read in full (39 useful lines), diffed line by line against `VncAccessibilityService`**: this isn't an independent implementation, it's a direct ancestor of the same code. The clearest proof: the clipboard-monitor log line, `"📋 Скопировано в буфер: "`, appears **verbatim, character for character, emoji included**, in both classes, a copy-paste, not a rewrite. But `KeyLoggerService` is a far more rudimentary version: no buffering or 1-second delay before sending (every `TYPE_VIEW_TEXT_CHANGED` fires an immediate HTTP request), no handling of `TYPE_VIEW_CLICKED` at all, so **no coordinate-based PIN capture**, no integration with `VncWebSocketClient` (only direct HTTP `POST` to the same `/api/log_keystrokes.php` endpoint), and none of the trappings of a full accessibility service (no `setServiceInfo`, no foreground notification, no WorkManager channel). Most likely conclusion: `KeyLoggerService` is the prototype the keylogger and clipboard monitor were copied from and then extended (buffering, PIN capture, WebSocket channel) directly into `VncAccessibilityService`, at the point where features were consolidated into a single accessibility service (Android only lets one be cleanly bound at a time). The original class was left in the code, undeclared, rather than deleted, a refactoring leftover, not a per-customer toggleable module as first suspected.

### 5.7 `VncAccessibilityService` read in full: active keylogger and clipboard monitor, with PIN capture and replay

The full reading of `VncAccessibilityService.java` (1039 lines) and its `Companion` confirms, code in hand, that the actually-active service does everything `KeyLoggerService` could have done, plus a PIN-capture pipeline far more elaborate than plain generic keylogging.

**Generic keylogger**: `onAccessibilityEvent()` captures `TYPE_VIEW_TEXT_CHANGED` events (text field input) across whatever app is in the foreground, buffers the text, and sends it after 1 second of inactivity (`inputDelay`) to `sendKeystrokeToServer()`, which `POST`s to `/api/log_keystrokes.php` with `bot_tag` (Android ID), app name and text.

**Clipboard monitor**: wired directly in `onServiceConnected()` via `clipboardManager.addPrimaryClipChangedListener(...)`, sends copied content to the same endpoint, tagged `"clipboard"`.

**PIN capture, with exact coordinates and timestamps**: `onAccessibilityEvent()` also captures `TYPE_VIEW_CLICKED` events (a tap on a button). If the tapped button's text is a single digit (regex `^\d{1}$`), typically an on-screen PIN keypad key, the service routes the event to `trackPinClickWithCoords()` instead of the generic keylogger: this method computes the exact center of the tapped button (`getBoundsInScreen()`), timestamps the tap, accumulates it in a sequence (`pinTouchSequence`), and immediately sends a raw WebSocket message to the C2, `{"type":"pin_click","data":{"digit","x","y","timestamp"}}`. After 3 seconds with no new digit, `trackPinClickWithCoords$lambda$13` checks whether the screen is unlocked (`KeyguardManager.isKeyguardLocked()`): if so, meaning the entered PIN did unlock the device, it sends a second message, `{"type":"pin_verified","bot_tag","pin","timestamp","sequence":[...]}` via `sendVerifiedPin()`, including the full tap sequence (digit + x + y + timestamp). Non-numeric clicked button text (labels, content descriptions) is also logged, tagged `"[PIN] "`, in the same generic keylogger stream but marked differently from plain field text.

This mechanism directly explains the `autopin` command already identified in §5.5: the tap sequence captured with its exact coordinates is exactly the format `autoInputPin()` expects back to replay the entry later on another lock screen (for instance after a forced device reboot).

**`autoInputPin()` (replay), implementation confirmed**: for each coordinate pair received from the C2, a `Handler.postDelayed()` is scheduled with a delay of `index * 400` milliseconds, so one tap every 400ms, in order, before calling `performTap(x, y)` at each position. This deliberately slow pacing (instead of an instant replay) mimics a plausible human typing rhythm rather than an automated entry fast enough to draw attention or trigger anti-bot detection on the bank's side.

**`dumpUiHierarchy()`, implementation confirmed**: genuinely walks the accessibility tree from `getRootInActiveWindow()` (recursive traversal of all children), builds a JSON array with class, on-screen bounds and text of every visible node, and sends it live to the C2 over WebSocket as `{"type":"uidump","data":[...]}`. Confirms that remote navigation can rely on the screen's real structure rather than a visually-interpreted video feed, a more reliable automation capability than plain manual VNC-style control.

**`showOverlayWeb()`, implementation confirmed**: creates a real `android.webkit.WebView`, with `setJavaScriptEnabled(true)`, `setDomStorageEnabled(true)`, and loads the URL received from the C2 (`loadUrl(p12)`), displayed as a full-screen overlay on top of the active app via `WindowManager`. Confirms, at code level and not just from the Zimperium description, that the phishing overlay is a full interactive web page loaded remotely, not a static image.

### 5.8 Touch injection confirmed at the level of the real Android API, not a stub

`performTap()`, `performInitialLongPress()`, `processRealtimePoints()` and `finishRealtimeGesture()` all use the genuine Android accessibility API for touch injection: building an `android.graphics.Path`, wrapping it in a `GestureDescription.StrokeDescription` (with real durations: 100ms for a simple tap, 300ms for a long press, continuous 30ms segments in real-time mode), then calling `AccessibilityService.dispatchGesture()`, the official Android API for simulating user gestures from an accessibility service. So this isn't low-level event injection or an exploit, but a legitimate (API-wise) and documented use of accessibility, abused for malicious ends, consistent with this malware's overall abuse model (see also the anti-removal bypass in §4, which uses the same `performGlobalAction` API).

### 5.9 Four network services, on two different hosting providers

The full reading of `onServiceConnected()`, `ProxyWebSocketService.java` and `BotHeartbeatService.java` reveals that this payload doesn't talk to a single C2, but to four separate network services across two hosting providers, each with its own role:

| Service | Endpoint | Role | Hosting |
|---|---|---|---|
| HTTP panel | `gorila-panel.xyz` (`91.184.247.166`) | Every `/api/*.php` endpoint: registration, keylogger/notification/PIN/contacts/call exfiltration, injection-list delivery (§5.3), **and command polling** (`GET /api/get_bot_commands.php`, every 10 seconds, see §5.11) | VDSINA (Russian VPS) |
| Real-time control WebSocket | `ws://94.103.89.12:8765`, hardcoded in `onServiceConnected()` | Live ATS commands (`tap`, `autopin`, `uidump`, streaming, see §5.5), live PIN capture (`pin_click`/`pin_verified`, §5.7) | VDSINA (same IP, different port from the next row) |
| Bulk photo/video upload | `http://94.103.89.12:9000/upload_photo`, hardcoded in `PhotosExporter` | Receives multipart ZIP archives containing the victim's entire photo/video gallery (§5.11) | VDSINA (same IP as the control WebSocket, distinct port: a separate HTTP service, not the same WebSocket process) |
| `ProxyWebSocketService` | `ws://89.185.80.124:55332/socks/<bot_id>`, hardcoded | Full reverse SOCKS proxy, **present in code and functional, but never started on this build** (see correction below) | Global Connectivity Solutions (UK/Denmark), a provider distinct from the other three |

**The reverse SOCKS proxy, confirmed by reading `handleTextMessage()`/`handleBinaryMessage()`**: the C2 sends a text command `connId:host:port`, and the infected phone opens a real `java.net.Socket` TCP connection to that destination, from the victim's own network and IP address. Binary data is then relayed both ways over the WebSocket connection, prefixed with the length and value of `connId` to multiplex several simultaneous connections. This is the classic "unwitting residential proxy" technique used by banking trojans to route a fraudulent session through the victim's IP and network fingerprint, bypassing bank-side anti-fraud checks based on geolocation or IP/device binding. Notable cosmetic detail: this service's foreground notification displays "Antivirus" / "System heart", a disguise meant to reassure the victim if they check the persistent notification list.

**Correction, methodological honesty**: reading `BotHeartbeatService.onCreate()` (§5.11) shows an explicit log line, `"🛑 Режим прокси отключён, ProxyWebSocketService не будет запущен"` ("proxy mode disabled, ProxyWebSocketService will not be started"), and an exhaustive search of every call site (`grep` across the entire decompiled codebase) finds **no other place** where this service is instantiated or started. Same situation as `KeyLoggerService` (§5.6): real, complete, functional code, but dormant on this specific build. The channel remains a valid IOC (the URL really is hardcoded and the code is ready to run if ever enabled), but it isn't a channel observed actively running on this sample.

Neither of the two new IPs (`94.103.89.12`, `89.185.80.124`) has an existing ThreatFox or Shodan entry, two additional fresh IOCs.

### 5.10 Complementary structured triage (`quark-engine`)

`quark-engine` (v26.7.1, rules current as of 19/07/2026) classifies the payload **"High Risk"** (cumulative score 0.97 at the 60% confidence threshold), with over 130 behaviors recognized at 60% confidence or above. No new capability compared to manual code reading (§5.1-§5.9): the highest-weighted signatures line up exactly with what was already confirmed line by line, dynamic reflection invocation (weight 3.01), HTTP POST (1.96), field resolution via reflection (1.79), clipboard reading, gesture dispatch, overlay creation, accessibility-tree access by text/ID/window root, SMS/call-log/contacts reading, location requests. Useful as an independent, automated validation of the already-established capability surface, but doesn't add any attribution or C2 element, manual code reading remains the source of every IOC and protocol detail in this document.

### 5.11 The last six modules read: orchestration, real screen streaming, and bulk gallery exfiltration

**`BotHeartbeatService`, the actual orchestrator**, more central than its name suggests. Three major contributions:

- **An additional command channel, via HTTP polling** (`GET /api/get_bot_commands.php?tag=<bot_tag>`, on the same `gorila-panel.xyz` panel, every 10 seconds), with its own command set, different from the real-time WebSocket one (§5.5): `export_sms`/`export_call_log` (trigger `BotSmsExporter`/`BotCallLogExporter`, bulk export), `send_sms` (with configurable delay and SIM slot), `send_ussd`, `show_notification` (displays a fake system notification with a title/text supplied by the C2, an on-demand social-engineering trigger), and **`add_contact`**: inserts a fake contact directly into the victim's address book via `ContentProviderOperation` on `ContactsContract`, name and number supplied by the C2. Most likely use: making a fake "bank support" number appear as a legitimate saved contact for vishing (the incoming call then looks like it's from a saved contact rather than a stranger).
- **A fifth persistence mechanism, a mutual watchdog**: `BotHeartbeatService` starts `GuardService` and checks every 60 seconds that it's still running; `GuardService`, in turn, restarts `BotHeartbeatService` every 30 seconds (`checkMainProcess()`). Each service resurrects the other if killed, `GuardService`'s notification deliberately invisible (`setSilent(true)`, minimum priority, no badge). `BotHeartbeatService`'s `onTaskRemoved()` also immediately restarts the service if the user swipes the app away from recent tasks.
- Also starts `SilentAudioPlayer` (below) and confirms, via an explicit log line, that `ProxyWebSocketService` (§5.9) is not started on this build.

**`SilentAudioPlayer`**: loops a bundled silent audio track (`res/raw/silent`), volume at zero, with `setWakeMode`, automatic restart on error (`OnErrorListener`). A known technique for keeping an Android process alive: an active media playback session gets battery/Doze restriction exemptions the service wouldn't have on its own.

**`ScreenCastService`**, real screen streaming confirmed at implementation level: captured via `MediaProjection` + `ImageReader` + `VirtualDisplay`, each frame converted to a `Bitmap`, compressed as JPEG (quality 60), Base64-encoded, sent live over **the same WebSocket channel as real-time control** (`ws://94.103.89.12:8765`, §5.9) as `{"type":"screencast","image":"data:image/jpeg;base64,..."}`. Confirms precisely the streaming mechanism already described by Zimperium, with the exact protocol.

**`PhotosExporter`, automatic exfiltration of the entire gallery, not just on command**: walks `MediaStore` (images and videos), processes in batches of 100 files, compresses images (JPEG quality 75, downscaled to a 1920x1080 maximum) and copies videos as-is, packages each batch as a ZIP, and uploads it as `multipart/form-data` to **a fourth, distinct network service**, `http://94.103.89.12:9000/upload_photo` (same IP as the control WebSocket, different port and protocol, a separate HTTP server). Important point confirmed by searching every call site: `exportPhotosAndUpload()` is triggered **automatically from `MainActivity`**, at several points tied to storage/media permission grants on first launch, not on C2 command. As soon as the app gets gallery access, full photo and video exfiltration starts without any operator action.

**`ContactsFetcher`, confirmed active** (not just present): gated by the `ENABLE_CONTACTS_FETCH` flag, a `true` constant hardcoded in `MainActivity` and reasserted in an `onActivityResult` handler, so genuinely active on this build, contrary to the caution expressed earlier in the follow-up plan. Exfiltrates name + number for every contact to `/api/upload_contacts.php`, with a `SharedPreferences` flag to only do it once per install.

**`CallLogSender`, a stream distinct from `BotCallLogExporter`**: while the `export_call_log` command (above) triggers a bulk export of the call history on demand, `CallLogSender.sendCallLog()` sends **every incoming call individually and in real time** to `/api/log_call.php` as it happens (triggered by `CallListener`, a phone-state listener registered by `BotHeartbeatService`). Two call-monitoring mechanisms, one continuous, one on-demand, not redundant with each other.

## 6. What's left (next steps)

1. ~~Read the full source of `VncAccessibilityService`/`VncWebSocketClient`~~, done in full (1039 lines + Companion): confirms an active keylogger and clipboard monitor directly in this service (§5.7), a PIN capture/replay pipeline with exact coordinates (§5.7), and real touch injection via `dispatchGesture`/`GestureDescription` (§5.8).
2. ~~Check whether the dropper and payload share the same APK signing certificate~~, done: **no**, both are signed with the generic Android debug keystore (`CN=Android Debug`), so no custom certificate usable for attribution. Notable detail: the payload's key dates back to March 2025, the dropper's to June 2026, a ~15-month gap, suggesting reuse of build infrastructure over time.
3. ~~Look for other SaferRAT samples on MalwareBazaar with a different "worker" tag~~, done: **no other sample available**, only the 2 already in hand. The multi-operator hypothesis isn't testable with currently public data.
4. ~~Read `ProxyWebSocketService`, `BotHeartbeatService`, `ScreenCastService`, `ContactsFetcher`, `PhotosExporter`, `CallLogSender`, `SilentAudioPlayer` in full~~, done (see §5.9/§5.11): a fifth persistence mechanism (mutual watchdog `BotHeartbeatService`/`GuardService`), an additional HTTP-polling command channel with its own command set (`add_contact`, `show_notification`, `send_ussd`...), a fourth network service dedicated to bulk photo/video gallery exfiltration, and confirmation that `ProxyWebSocketService` is in fact never started on this build.
5. ~~Understand why `KeyLoggerService` exists as a duplicate of the keylogger already integrated into `VncAccessibilityService`~~, done via line-by-line comparison (see §5.6): the clipboard-monitor log text is character-for-character identical between the two classes, a confirmed copy-paste, not an independent rewrite. `KeyLoggerService` is the simpler prototype the keylogger was copied from and then extended (buffering, PIN capture, WebSocket channel) into `VncAccessibilityService` at the point of consolidation into a single accessibility service, left in place undeclared rather than removed.
6. ~~Install `quark-engine` for a complementary structured capability triage~~, done (see §5.10): classifies the payload "High Risk", confirms the same capability surface already established by manual reading, nothing new.
7. Manual submission to ThreatFox via their web portal (API submission failed, see §7) of four IOCs now: `gorila-panel.xyz`, `94.103.89.12:8765`, `94.103.89.12:9000` and `89.185.80.124:55332`, and abuse reports to the two hosting providers involved (VDSINA, abuse@vdsina.ru; Global Connectivity Solutions, abuse@globconnex.com), drafted, sending left to the reader/analyst

## 7. Limitations and methodological honesty (current state)

- The "Diabloo" attribution is a raw observation (a hardcoded string), not a confirmed identity, could be a build tag, a handle, or something else entirely.
- No independent third-party sandbox confirmation (e.g. Triage, ANY.RUN) consulted.
- **ThreatFox API submission attempt failed** (`user_unknown`): the Auth-Key that works for MalwareBazaar/ThreatFox searches isn't recognized for IOC submission, which appears to require a logged-in abuse.ch web account. Left as a manual step.
- `ProxyWebSocketService` (reverse SOCKS proxy) is confirmed present and functional in the code, but confirmed **not started** on this specific build (§5.9): a valid IOC (hardcoded URL), but not a channel observed actively running on this sample.

## 8. Consolidated IOCs

| Type | Value |
|---|---|
| SHA256 dropper (`Strawberry.apk`) | `d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4` |
| SHA256 payload (`nested_app.apk`, embedded and confirmed identical) | `c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b` |
| Dropper package | `com.example.nestedinstaller` |
| Payload package | `s3zse.f01pdoi.ohnrb2` |
| Payload display label | Strawberry |
| **HTTP C2 panel** | `gorila-panel.xyz` (`91.184.247.166`) |
| C2 panel hosting (NS) | VDSINA (Russian VPS) |
| **Real-time control C2 WebSocket** | `ws://94.103.89.12:8765`, hardcoded, VDSINA as well |
| **Bulk photo/video upload service** | `http://94.103.89.12:9000/upload_photo`, hardcoded, same IP as the control WebSocket, distinct port and protocol |
| **Reverse SOCKS proxy C2 (present, not started on this build)** | `ws://89.185.80.124:55332/socks/<bot_id>`, hardcoded, distinct hosting (Global Connectivity Solutions, UK/DK) |
| Confirmed HTTP C2 endpoints | `POST /api/register_bot.php`, `POST /api/log_notification.php`, `GET /api/not_block_list.php`, `POST /api/log_keystrokes.php`, `POST /api/log_call.php`, `POST /api/upload_contacts.php`, `GET /api/get_bot_commands.php` (polling, 10s) |
| Confirmed commands received via HTTP polling | `export_sms`, `send_sms`, `export_call_log`, `show_notification`, `send_ussd`, `add_contact` (see §5.11) |
| Confirmed bot-to-C2 WebSocket messages | `pin_click`, `pin_verified`, `uidump`, `volume_info`, `screencast` (see §5.7, §5.11) |
| Operator/build tag | `Diabloo` |
| VNC/accessibility service (active, keylogger + clipboard + PIN capture built in) | `com.example.safeservice.vnc.VncAccessibilityService` |
| Duplicated keylogger (code present, service undeclared, inactive on this build, function already covered by `VncAccessibilityService`) | `com.example.safeservice.KeyLoggerService` |
| Mutual watchdog (5th persistence mechanism) | `com.example.safeservice.BotHeartbeatService` ↔ `com.example.safeservice.GuardService` |
| Signing cert SHA256 (dropper) | `a7434275...` (generic Android debug keystore) |
| Signing cert SHA256 (payload) | `c3fcf873...` (generic Android debug keystore, different from dropper) |
| Family | SaferRAT |
| Source report | [Zimperium zLabs, June 2026](https://zimperium.com/blog/android-bankers-4-campaigns-in-a-row) |

## 9. Reproducing the analysis

Detailed log in [`runbook.md`](runbook.md) (French; command-level content is language-agnostic).
