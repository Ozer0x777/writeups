# Runbook : reproduction pas à pas

Log de manipulation (commande / pourquoi / retour brut / ce qu'on en retient) de l'analyse d'InfernoGrabber v9.0.

---

## A. Recherche de sources publiques sur le sujet

**Commande :** `WebSearch` sur "AI-Generated Browser Ransomware Chromium API DeepSeek technical report" et "browser ransomware File System Access API proof of concept 2026"

**Retour :** identification du rapport source, [Check Point Research](https://research.checkpoint.com/2026/browser-only-ransomware-from-llm-hallucinations-to-a-practical-attack-technique/), publié le 01/07/2026, et du sample `deepseek_python_20260125_da0631.py`.

**Ce qu'on en retient :** point de départ solide, mais le rapport ne reproduit aucun extrait de code, juste une description du mécanisme.

## B. Récupération du rapport Check Point complet

**Commande :** `WebFetch` sur l'URL du rapport, prompt ciblé sur hash, mécanisme technique, architecture Flask, capacités réelles vs tentées.

**Retour :** SHA256 `07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5`, tableau des capacités fonctionnelles vs "hallucinations IA" (voir writeup.md §5).

## C. Recherche du sample sur MalwareBazaar et Triage

**Commande :**
```bash
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $(cat ~/ctf-reverse/.mb_api_key)" -d "query=get_info&hash=07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5"
curl -s "https://tria.ge/api/v0/search?query=sha256:07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5"
```

**Retour :** MalwareBazaar → `{"query_status": "hash_not_found"}`. Triage → `{"error":"UNAUTHORIZED"}` (clé API requise, indisponible).

**Ce qu'on en retient :** aucune des deux sources habituelles n'a ce sample. Passage à VirusTotal (nouvelle clé API créée pour ce projet par l'utilisateur).

## D. Métadonnées VirusTotal

**Commande :**
```bash
curl -s "https://www.virustotal.com/api/v3/files/07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5" \
  -H "x-apikey: $VT_KEY"
```

**Retour :** métadonnées complètes (taille, type, 26/61 détections, noms de fichiers, classification `TrojanRansom`), voir writeup.md §3.

## E. Tentative de téléchargement du fichier réel

**Commande :**
```bash
curl -s -w "\nHTTP_CODE:%{http_code}\n" \
  "https://www.virustotal.com/api/v3/files/07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5/download" \
  -H "x-apikey: $VT_KEY" -o deepseek_sample.py
```

**Retour :** `HTTP_CODE:403`, `{"error": {"code": "ForbiddenError", "message": "You are not authorized to perform the requested operation"}}`

**Ce qu'on en retient :** le téléchargement du fichier brut nécessite un compte VT premium, pas accessible avec la clé gratuite. Voir writeup.md §2 pour la conséquence méthodologique.

## F. Détections par vendeur

**Commande :** extraction de `last_analysis_results` depuis la réponse de D (script Python inline, filtre sur les résultats non vides).

**Retour :** liste complète en writeup.md §3 (Microsoft, Kaspersky, ESET, TrendMicro, BitDefender, etc.)

## G. Rapport comportemental sandbox (behaviour_summary)

**Commande :**
```bash
curl -s "https://www.virustotal.com/api/v3/files/07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5/behaviour_summary" \
  -H "x-apikey: $VT_KEY"
```

**Pourquoi :** VT exécute automatiquement les samples soumis dans ses propres sandboxes (Linux et Windows), accès à un comportement dynamique réel sans avoir à exécuter le fichier nous-mêmes.

**Retour :** processus créés (`xterm`+`python` sur Linux, `python.exe` sur Windows), signatures comportementales (`reads_files`, `writes_files`, YARA `TrojanRansom` détecté en mémoire), URLs en mémoire (webhook Discord, bibliothèques tierces, sons d'intimidation), détail complet en writeup.md §6.

**Ce qu'on en retient :** riche malgré l'absence du code source, le comportement dynamique révèle des éléments (webhook réel, bibliothèques chargées) qu'une simple lecture du rapport Check Point n'aurait pas donnés.

## H. Vérification indépendante du webhook Discord

**Commande :**
```bash
curl -s "https://discord.com/api/webhooks/1465066143516459277/g5X5V-ehzLCWP_S1kOkR4-EL2fdhev3xznUV3OtVUNJ0sNA"
```

**Pourquoi :** une requête GET sur un webhook Discord est en lecture seule (renvoie les métadonnées du webhook), ne poste rien sur le canal, contrairement à un POST.

**Retour :** `{"message": "Unknown Webhook", "code": 10015}`

**Ce qu'on en retient :** webhook déjà désactivé/supprimé, pas de canal actif à signaler pour l'instant. Voir writeup.md §6.1.

---

# Recherche d'autres canaux et lecture de code réel

## I. Recherche d'autres canaux d'acquisition

**Commande :** `WebSearch` sur le nom du fichier et "InfernoGrabber v9.0 sample source code github pastebin" ; test direct de vx-underground, Hybrid Analysis, MalShare.

```bash
curl -s -A "Mozilla/5.0" "https://vx-underground.org/Samples"   # 403
curl -s "https://www.hybrid-analysis.com/api/v2/search/hash" -d "hash=..."   # 301/redirect, nécessite clé
curl -s "https://malshare.com/api.php?api_key=&action=details&hash=..."   # "No API Key Supplied"
```

**Retour :** aucun de ces canaux n'a fonctionné sans authentification.

## J. Découverte des rapports de sandbox individuels via l'API VT

**Commande :**
```bash
curl -s "https://www.virustotal.com/api/v3/files/07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5/behaviours" -H "x-apikey: $VT_KEY"
```

**Pourquoi :** l'endpoint `behaviour_summary` (déjà utilisé plus haut) est une vue agrégée ; `/behaviours` liste les rapports individuels par moteur de sandbox, potentiellement plus détaillés.

**Retour :** deux rapports, `CAPE Linux` et `Zenbox`.

## K. Récupération des rapports HTML complets

**Commande :**
```bash
id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5_CAPE Linux'))")
curl -sL "https://www.virustotal.com/api/v3/file_behaviours/$id/html" -H "x-apikey: $VT_KEY" -o cape_linux_report.html
# idem pour Zenbox
```

**Pourquoi :** chaque rapport de sandbox individuel a un rapport HTML détaillé (`has_html_report: true` dans les métadonnées), potentiellement plus riche que le résumé agrégé. Le PCAP (`has_pcap: true`) a aussi été tenté mais renvoie 403 (réservé premium).

**Retour :** `cape_linux_report.html` (914 lignes), `zenbox_report_full.html` (1844 lignes).

## L. Découverte du code source réel dans le rapport CAPE Linux

**Commande :**
```bash
grep -io "def \|import flask\|showDirectoryPicker\|encrypt\|webhook" cape_linux_report.html
python3 -c "
import re
html = open('cape_linux_report.html', encoding='utf-8', errors='replace').read()
for kw in ['import Flask', 'def ', 'ENCRYPT', 'WEBHOOK']:
    for m in re.finditer(re.escape(kw), html):
        print(repr(html[max(0,m.start()-150):m.end()+150]))
"
```

**Retour :** extraits substantiels de vrai code Python (imports, config webhook/chiffrement, classe `InfernoDB`, schéma SQL complet), voir writeup.md §6bis. Webhook complet (non tronqué) découvert : `.../g5X5V-ehzLCWP_S1kOkR4-EL2fdhev3xznUV3OtVUNJ0sNAkrLhs-_dQZaAIILDSq8m2`.

## M. Extraction élargie du dump de code

**Commande :**
```bash
python3 -c "
html = open('cape_linux_report.html', encoding='utf-8', errors='replace').read()
idx = html.find('import string')
print(html[idx:idx+16000])
"
```

**Retour :** ~10 Ko de code lisible (imports jusqu'au schéma complet des tables `victims`/`discord_tokens`/`credit_cards`/`screenshots`/`webcam_captures`/`microphone_captures`), puis troncature côté CAPE (« &lt;truncated&gt; ») suivie du HTML de l'interface du rapport lui-même.

**Ce qu'on en retient :** lecture de code réel, mais partielle, le fichier fait 160 Ko, on n'en a lu qu'une fraction. Voir writeup.md §6bis pour l'analyse complète (bibliothèques natives réelles, commentaires russes, portée du schéma DB).

## N. Vérification du webhook complet (non tronqué)

**Commande :**
```bash
curl -s "https://discord.com/api/webhooks/1465066143516459277/g5X5V-ehzLCWP_S1kOkR4-EL2fdhev3xznUV3OtVUNJ0sNAkrLhs-_dQZaAIILDSq8m2"
```

**Retour :** `{"message": "Unknown Webhook", "code": 10015}`, confirmé mort, même avec le token complet (la version testée plus haut était tronquée).

## O. Vérification de l'activité réseau dans les deux rapports

**Commande :**
```bash
grep -c "Nothing to display\|No HTTP" zenbox_report_full.html
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" zenbox_report_full.html | sort -u
curl -s "https://internetdb.shodan.io/150.171.22.17"
```

**Retour :** CAPE Linux : tous les onglets réseau vides. Zenbox : deux IP (`8.8.8.8`, `150.171.22.17`). Shodan confirme `150.171.22.17` = `skypeecs-prod-edge-b.trafficmanager.net` (Microsoft, télémétrie Windows), pas l'infrastructure de l'attaquant.

**Ce qu'on en retient :** aucune activité réseau réelle capturée dans aucune des deux sandboxes, cohérent avec un script qui plante avant d'atteindre sa logique réseau (dépendances manquantes dans l'environnement sandbox).

---

# Confrontation des pistes ouvertes aux artefacts

## P. Cartographie exacte de la troncature CAPE et absence de code côté Zenbox

**Commande :**
```bash
python3 -c "html=open('cape_linux_report.html',errors='replace').read();
[print(repr(kw),html.find(kw)) for kw in ['import os','CREATE TABLE','&lt;truncated']]"
grep -c -iE 'import flask|InfernoDB|CREATE TABLE|browser_cookie3' zenbox_report_full.html
```

**Retour :** dans CAPE, le bloc de code va de l'offset ≈ 3 571 516 (`import os`) au marqueur `&lt;truncated&gt;` à ≈ 3 579 705, coupé au milieu de la table `microphone_captures`. Zenbox : `0` occurrence des mots-clés de code.

**Ce qu'on en retient :** la portion lisible plafonne à ≈ 8 Ko (imports + config + classe `InfernoDB`), et Zenbox n'offre aucun aperçu source alternatif. Le reste du fichier reste inaccessible par ces canaux.

## Q. Recherche de bibliothèques natives réellement invoquées

**Commande :**
```bash
grep -ohE 'pyautogui\.[a-z_]+|browser_cookie3\.[a-z_]+|pyperclip\.[a-z_]+|webdriver\.[A-Za-z]+|\.screenshot\(|\.paste\(' \
  cape_linux_report.html zenbox_report_full.html vt_behaviour_summary.json | sort | uniq -c
```

**Retour :** seules occurrences = `webdriver.support` et `webdriver.common` (lignes `import`). Aucun appel de méthode. Fonctions définies visibles : `__init__`, `init_tables` uniquement.

**Ce qu'on en retient :** ces libs sont importées mais jamais invoquées dans l'extrait ; le code qui les utiliserait est au-delà de la troncature. Voir writeup.md §6bis.1.

## R. Décodage des snowflakes Discord (ID avatar et webhook)

**Commande :**
```bash
python3 -c "from datetime import datetime,timezone;
print(datetime.fromtimestamp(((int('422811769203851274')>>22)+1420070400000)/1000,tz=timezone.utc));
print(datetime.fromtimestamp(((int('1465066143516459277')>>22)+1420070400000)/1000,tz=timezone.utc))"
```

**Retour :** avatar `422811769203851274` → compte créé **2018-03-12 17:43 UTC** ; webhook `1465066143516459277` → **2026-01-25 19:29 UTC** (jour de l'upload VT, cohérent avec `20260125` dans le nom du fichier).

**Ce qu'on en retient :** avatar = compte ancien (2018), webhook = créé le jour de la génération du sample. Voir writeup.md §6.1 et §6.2.

## S. Vérification que l'avatar CDN résout encore (lecture seule)

**Commande :**
```bash
curl -s -I "https://cdn.discordapp.com/avatars/422811769203851274/3a2ee1c7e9297563376cc2f3ad88c79a.webp"
```

**Retour :** `HTTP/2 200`, `content-type: image/webp`, `content-length: 3088`.

**Ce qu'on en retient :** l'avatar existe toujours. Résolution du pseudo faite à l'étape suivante via un service de lookup public (pas besoin d'un token bot personnel).

## S bis. Résolution de l'ID Discord en profil (username)

**Commande :**
```bash
curl -s "https://japi.rest/discord/v1/user/422811769203851274" | python3 -m json.tool
```

**Pourquoi :** un service de lookup public interroge l'API Discord (`GET /users/{id}`) avec son propre bot, ce qui évite d'avoir à créer un token. Endpoints équivalents : `discordlookup.com`, `lookup.guru`, ou son propre bot avec `Authorization: Bot <token>`.

**Retour :** username `bogatov`, nom d'affichage `ТОТ САМЫЙ` (russe), créé le 12/03/2018 (concorde avec le snowflake de l'étape R), utilisateur Nitro (bannière animée), clan/tag de serveur `ST` (guild `1049805573190864916`). Le hash d'avatar renvoyé correspond à celui du leurre, confirmant le bon compte.

**Ce qu'on en retient :** convergence avec les commentaires russes du code ; renforce l'hypothèse d'un opérateur russophone sans la prouver (l'avatar a pu être emprunté). Voir writeup.md §6.2.

**Serveur `ST` (`1049805573190864916`) :** `curl https://discord.com/api/guilds/1049805573190864916/widget.json` → `Widget Disabled` (code 50004) ; `widget.png` en 404 ; badge de clan présent sur le CDN (`clan-badges/.../8e228078...png` → 200). Serveur réel et établi (créé 06/12/2022) mais non résoluble par l'ID seul sans code d'invite ni bot présent.

## T. Validation base58check des candidats "adresses Bitcoin"

**Commande :** validation du double-SHA256 checksum sur les chaînes base58 extraites par regex (`grep -oE '[13][...]{25,34}'`), + inspection du contexte ±80 caractères.

**Retour :** les trois candidats CAPE (`18xiUs3...`, `3uZj1W5...`, `3zd2zRd3...`) ont un **checksum invalide** et apparaissent **à l'intérieur de blobs base64** (dumps mémoire/images), pas dans du code. Aucune adresse Bitcoin valide dans aucun artefact.

**Ce qu'on en retient :** pas d'IOC financier récupérable ; l'adresse de rançon (si présente) est dans la portion non lue. Voir writeup.md §7 point 6.

## U. Re-lecture du rapport Check Point sur la langue du prompt et l'attribution

**Commande :** `WebFetch` ciblé sur langue du prompt, attribution géographique, mention de commentaires russes ; `WebSearch` sur la couverture presse.

**Retour :** Check Point écrit *"We do not have the prompt submitted to the AI model that produced this sample"* ; aucune mention de commentaires russes ni d'attribution géographique. Couverture presse (dont une source russophone, xakep.ru) qui reprend le rapport sans attribution nationale.

**Ce qu'on en retient :** l'observation des commentaires russes est indépendante de Check Point ; conclusion resserrée à "opérateur vraisemblablement russophone". Voir writeup.md §6bis.2.

## V. Démonstration pédagogique de la File System Access API

**Livrable :** [`../deepseek-browser-ransomware/fsapi-demo.html`](fsapi-demo.html), page autonome qui appelle `showDirectoryPicker({mode:'read'})` et énumère récursivement un dossier choisi, en lecture seule, pour illustrer qu'une seule autorisation donne un accès récursif complet. Aucun chiffrement, aucune écriture, aucun réseau (vérifiable dans l'onglet réseau des devtools).

---

Suite : voir writeup.md §7 (plan de reprise mis à jour).
