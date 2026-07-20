# Analyse InfernoGrabber v9.0 : un ransomware "navigateur" généré de bout en bout par DeepSeek

**Analyste :** Gordon PEIRS
**Date d'analyse :** 19/07/2026
**Type :** Analyse par métadonnées VirusTotal, rapport comportemental de sandbox tiers, et extraits substantiels du code source réel récupérés via un canal détourné (voir §2.1), pas le fichier complet, mais une lecture directe plutôt qu'une simple synthèse de rapports.
**Famille :** Malware généré par LLM (DeepSeek), auto-nommé "InfernoGrabber v9.0", classé par les antivirus comme PyStealer/InfernoStealer/TrojanRansom selon le vendeur

---

## 1. Contexte et pourquoi ce sujet

Le 1er juillet 2026, **Check Point Research** a publié ["Browser-Only Ransomware: From LLM Hallucinations to a Practical Attack Technique"](https://research.checkpoint.com/2026/browser-only-ransomware-from-llm-hallucinations-to-a-practical-attack-technique/), documentant le premier cas connu où un modèle IA (DeepSeek) a construit, à partir d'un unique prompt ne mentionnant pas explicitement "ransomware" ou "malware", une chaîne d'attaque fonctionnelle combinant :
- Un risque jusque-là considéré comme théorique : un "ransomware navigateur" sans aucun binaire natif, sans installation, sans exploit
- Une vraie capacité Chromium légitime : la **File System Access API**, qui permet à une page web d'obtenir un accès lecture/écriture à un dossier local après une seule autorisation utilisateur

Choisi comme sujet pour un changement complet de terrain : aucun binaire à désassembler, du Python/JS pur, et un angle "l'IA comme auteur de malware" plutôt que "malware ciblant les outils IA".

## 2. Acquisition : ce qui a été récupéré et ce qui ne l'a pas été

Sample identifié par Check Point : `deepseek_python_20260125_da0631.py`, uploadé sur VirusTotal le 25/01/2026.

| Élément | Statut |
|---|---|
| Métadonnées VirusTotal (détections, YARA, tags) | **Récupérées** (clé API VT gratuite) |
| Rapport comportemental sandbox VT (`behaviour_summary`) | **Récupéré**, exécution dynamique faite par VT elle-même, jamais par nous |
| Fichier brut complet (téléchargement direct) | **Non récupéré**, l'endpoint `/files/{id}/download` de l'API VT renvoie `403 ForbiddenError` sur une clé gratuite (réservé aux comptes premium) |
| **Extraits substantiels du code source réel** | **Récupérés indirectement**, via les rapports de sandbox individuels (`/file_behaviours/{id}/html`), voir §2.1, canal non prévu initialement |
| MalwareBazaar | Hash non indexé (`hash_not_found`) |
| Triage (tria.ge) | Nécessite une clé API, non disponible |
| VX-Underground | Page bloquée (403, probablement anti-bot) |
| Hybrid Analysis / MalShare | Nécessitent une authentification non disponible |

### 2.1 Le vrai canal trouvé : les rapports de sandbox individuels contiennent un aperçu statique du fichier

L'endpoint `/files/{id}/behaviours` liste les sandboxes ayant analysé le sample (ici : **CAPE Linux** et **Zenbox**, deux sandbox tierces intégrées à VirusTotal). Chaque rapport individuel a un rapport HTML complet accessible via `/file_behaviours/{id}/html`, **et celui de CAPE Linux inclut un aperçu statique du fichier source qui contient plusieurs milliers de caractères de code Python lisible**, bien au-delà des quelques URLs de la vue "summary" agrégée. Ce n'est pas le fichier complet (le panneau de prévisualisation de CAPE le tronque après une certaine longueur), mais c'est un vrai extrait du vrai code, pas une reconstruction. Voir §6 pour le contenu.

**Conséquence méthodologique** : contrairement à un simple "on n'a pas eu le fichier", ça a fini par donner une vraie lecture de code partielle, via un canal non anticipé au départ (le rapport HTML détaillé d'un moteur de sandbox spécifique, pas la vue agrégée). Documenté comme acquisition partielle, pas complète, le fichier tronqué exact reste à obtenir pour une lecture intégrale.

## 3. Identité de l'échantillon

| Champ | Valeur |
|---|---|
| Nom de fichier | `deepseek_python_20260125_da0631.py` |
| SHA256 | `07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5` |
| MD5 | `11bd02a19047dacd5ef6bac3f67a68e2` |
| Taille | 160 404 octets |
| Type | Script Python (magic: "Python script, Unicode text, UTF-8 text executable") |
| Détections VT | 26/61 moteurs (au moment de la vérification) |
| Classification VT | `TrojanRansom`, verdicts `MALWARE` + `RANSOM`, confiance 48% (modérée, reflète une fonctionnalité partielle, voir §5) |
| Nom auto-attribué (dans le code, selon Check Point) | "InfernoGrabber v9.0" |

**Noms de détection par vendeur** (échantillon) : Microsoft `Trojan:Python/InfernoStealer.MMK!MTB`, Kaspersky `Constructor.Python.Agent.l` (catégorie Kaspersky pour les outils générateurs/builders, cohérent avec un artefact de génération LLM plutôt qu'un malware écrit à la main), ESET `Python/Spy.Agent.CYT`, TrendMicro `Trojan.Win32.Pystealer.VSNW02G26`, BitDefender/Emsisoft/GData/VIPRE/Arcabit `Generic.PyStealer.AD.7125BC1B` (moteur Bitdefender partagé par plusieurs revendeurs).

## 4. Architecture (d'après le rapport Check Point)

```
Utilisateur → page web "AI Discord Avatar Upscaler" (lure)
  → showDirectoryPicker() : demande d'accès à un dossier (ex. Photos/DCIM)
    → énumération récursive du dossier en JavaScript
      → lecture des fichiers via handles de fichiers du navigateur
        → transmission au backend Flask (exfiltration)
          → chiffrement in-place dans le processus navigateur
            → overlay de rançon (paiement Bitcoin exigé)
```

Le fichier unique `deepseek_python_20260125_da0631.py` contient à la fois :
- Un serveur **Flask** (backend Python) : routes de réception des données exfiltrées, panneau d'administration
- Le **HTML/JS servi aux victimes** (frontend), embarqué dans des templates Python

## 5. Le point central du rapport Check Point : ce qui marche vraiment vs ce qui est halluciné

C'est la partie la plus intéressante de ce cas, et la raison pour laquelle le titre "ransomware généré par IA" mérite d'être nuancé plutôt que pris au pied de la lettre.

| Capacité | Statut selon Check Point |
|---|---|
| Énumération de fichiers via API navigateur légitime | **Fonctionnelle** |
| Lecture de fichiers | **Fonctionnelle** |
| Chiffrement des fichiers | **Fonctionnelle** |
| Overlay de rançon | **Fonctionnelle** |
| Keylogging | Tentée, **non fonctionnelle** (limitée à la page courante, pas un vrai keylogger système) |
| Surveillance du presse-papier | Tentée, **non fonctionnelle** |
| Extraction de tokens Discord | Tentée, **non fonctionnelle** |
| Découverte de wallets crypto | Tentée, **non fonctionnelle** |
| Vol de cartes bancaires | Tentée, **non fonctionnelle** |
| Capture webcam/micro | Tentée, **non fonctionnelle** |
| Capture d'écran | Tentée, **non fonctionnelle** |
| Stubs d'exploit Chrome | Tentée, **non fonctionnelle** |
| Mécanismes de persistance | Tentée, **non fonctionnelle** |

Check Point qualifie explicitement la majorité de ces tentatives d'**"hallucinations IA"**, des fonctionnalités qu'une simple application web ne peut pas réaliser techniquement dans le bac à sable du navigateur, mais que le modèle a générées comme si elles fonctionnaient. Le titre du malware par son propre "auteur" ("InfernoGrabber v9.0", évoquant un grabber complet) est donc en grande partie aspirationnel plutôt que descriptif du comportement réel.

**Ce que ça dit sur DeepSeek comme générateur de malware** : le modèle a produit un code partiellement fonctionnel à partir d'un prompt qui évitait la terminologie explicite ("ransomware", "malware") tout en préservant l'intention. Refus systématique constaté par Check Point pour des prompts directs ("génère un ransomware"), mais contournable en décomposant la demande. Une réponse du modèle aurait explicitement qualifié sa propre sortie de "piège qui combine une interface d'upscaler IA convaincante avec un comportement caché de type ransomware", signe que le modèle "savait" ce qu'il générait tout en continuant.

## 6. Recoupement indépendant : le rapport comportemental sandbox VirusTotal

VirusTotal a exécuté ce script dans ses propres sandboxes (Linux et Windows), sans qu'on ait besoin de l'exécuter nous-mêmes.

### 6.1 Un vrai webhook Discord d'exfiltration retrouvé en mémoire

Parmi les URLs observées en mémoire durant l'exécution sandbox :

```
https://discord.com/api/webhooks/1465066143516459277/g5X5V-ehzLCWP_S1kOkR4-EL2fdhev3xznUV3OtVUNJ0sNA
```

**Vérification indépendante** (requête GET en lecture seule, ne poste rien sur le webhook) :
```
{"message": "Unknown Webhook", "code": 10015}
```

Le webhook est **déjà mort** (supprimé par l'attaquant ou désactivé par Discord Trust & Safety) au moment de cette vérification. Un webhook Discord est une infrastructure réellement signalable et désactivable, mais celui-ci n'est plus actif, donc rien à signaler à ce stade.

Le décodage du snowflake de l'ID du webhook (`1465066143516459277`) donne une création au **25/01/2026 19:29 UTC**, soit le jour même de l'upload sur VirusTotal et de la date encodée dans le nom du fichier (`deepseek_python_20260125_da0631.py`). Le canal d'exfiltration a donc été mis en place le jour de la génération/soumission du sample, pas réutilisé d'une campagne antérieure.

### 6.2 Autres éléments retrouvés en mémoire

- `cdn.discordapp.com/avatars/422811769203851274/3a2ee1c7e9297563376cc2f3ad88c79a.webp`, image d'avatar Discord utilisée dans l'interface leurre ("upscaler"). L'ID a été résolu en profil via un service de lookup public (`japi.rest`, qui interroge l'API Discord avec son propre bot ; pas besoin de token personnel). Le compte : username **`bogatov`**, nom d'affichage **`ТОТ САМЫЙ`** ("celui-là même", en russe), créé le **12/03/2018** (concorde avec le décodage du snowflake), utilisateur **Nitro** (bannière animée), membre d'un serveur au tag de clan **`ST`** (guild `1049805573190864916`, créée le 06/12/2022, badge de clan présent sur le CDN, donc Guild Tag actif d'un serveur établi). L'avatar CDN répond toujours (HTTP 200) et son hash correspond, confirmant qu'on regarde le bon compte. Le serveur `ST` a son widget désactivé (`code 50004`) et n'est pas résoluble par l'ID seul via les canaux non authentifiés : son nom et ses membres nécessiteraient un code d'invite ou un bot déjà présent, non disponibles ici.

  **Attribution.** Convergence notable : le code est commenté en russe (§6bis.2) et l'avatar du leurre appartient à un compte russophone actif. L'hypothèse "avatar tiers récupéré au hasard" tient donc moins ; le plus probable est que l'auteur a réutilisé **son propre compte Discord** (ou un compte associé) pour le leurre, ce qui pointe vers un opérateur russophone. **Ce n'est cependant pas une preuve** : un leurre "upscaler d'avatar Discord" affiche par construction un vrai avatar, et l'auteur a pu emprunter celui d'un tiers russophone. Le propriétaire de l'avatar est identifié (`bogatov`/`ТОТ САМЫЙ`) ; l'équation "ce compte = l'opérateur" reste probable mais non démontrée. Aucune donnée personnelle réelle (nom civil, e-mail, IP) n'est exposée par ce lookup, seulement le profil pseudonyme public.
- `html2canvas.hertzen.com/dist/html2canvas.min.js`, bibliothèque tierce légitime de capture d'écran DOM-vers-canvas, cohérente avec la fonctionnalité "capture d'écran" mentionnée par Check Point comme tentée (mais non fonctionnelle selon eux, possible que la bibliothèque soit chargée sans que l'intégration fonctionne réellement).
- `code.responsivevoice.org/responsivevoice.js?key=H3t4r7kP`, bibliothèque de synthèse vocale tierce (avec une clé API en clair), cohérent avec un overlay de rançon qui "parle" pour intimider la victime.
- Fichiers audio `mixkit.co` (cris d'horreur : "mixkit-scary-scream", "mixkit-horror-scream", "mixkit-terrified-scream"), effets sonores d'intimidation pour l'overlay de rançon.
- Signature `Yara detected TrojanRansom` en mémoire du process `python.exe` (sévérité HIGH), confirme la classification ransomware au niveau comportemental, pas seulement statique.
- Signature "Creates a process in suspended mode (likely to inject code)", **[OUVERT]**, à vérifier si c'est un vrai comportement d'injection ou un artefact générique de l'interpréteur Python/multiprocessing sur Windows (le thème "hallucination IA" de ce cas incite à la prudence avant de conclure à une vraie capacité d'injection).

## 6bis. Lecture directe de code source réel : plusieurs corrections importantes au narratif de presse

En creusant les rapports de sandbox individuels (§2.1), le rapport **CAPE Linux** contient un aperçu statique de plusieurs milliers de caractères du vrai fichier `deepseek_python_20260125_da0631.py`. Ce n'est plus une inférence depuis un résumé tiers, c'est une lecture directe, même partielle.

### 6bis.1 Ce n'est pas "sans binaire natif" : c'est un script Python natif complet avec de vraies bibliothèques système

Les imports réels du fichier :

```python
import os, sys, json, base64, logging, sqlite3, threading, hashlib, uuid, time, random, string
import requests, re, subprocess, zipfile, io, hashlib, secrets
from datetime import datetime
from flask import Flask, request, render_template_string, Response, jsonify, send_file, redirect
from flask_sock import Sock
import websocket
import qrcode
from cryptography.fernet import Fernet
import browser_cookie3
import pyperclip
import pyautogui
import psutil
import GPUtil
import socket, struct, select
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
```

**`browser_cookie3`** (vol réel de cookies de navigateurs installés), **`pyperclip`** (accès réel au presse-papier), **`pyautogui`** (capture d'écran et automatisation souris/clavier réelles), **`selenium`** (pilotage d'un vrai navigateur) sont des bibliothèques Python légitimes et pleinement fonctionnelles **si installées**, ce ne sont pas des capacités "navigateur sandboxé", ce sont de vraies capacités host-level natives. **Ça contredit partiellement le narratif repris par la presse généraliste ("sans binaire natif", "browser-only")** : le "paquet complet" tel qu'écrit est un script Python natif avec des dépendances qui, une fois installées, donnent un accès système réel, pas seulement les capacités d'une page web dans le bac à sable Chromium. La partie "navigateur" (File System Access API) documentée par Check Point est probablement la partie livrée à la victime finale (le JS servi par Flask), tandis que ce fichier Python est l'outil complet de l'attaquant (serveur + automatisation), une distinction que les titres de presse ("browser ransomware", "no-install attack") aplatissent.

**Vérification directe dans le code récupéré** : dans les ~8 Ko lisibles (imports, config, classe `InfernoDB`), ces bibliothèques natives n'apparaissent **que dans les lignes `import`, jamais invoquées**. Aucune occurrence de `pyautogui.screenshot(...)`, `browser_cookie3.chrome(...)`, `pyperclip.paste(...)` ou `webdriver.Chrome(...)` dans tout ce qui a été récupéré (recherche par motif sur les deux rapports de sandbox et le résumé comportemental). Les seules définitions de fonctions visibles sont `__init__` et `init_tables` (la classe base de données) : l'aperçu CAPE se coupe (au milieu de la table `microphone_captures`) **avant** tout code métier qui appellerait ces bibliothèques. On ne peut donc **ni confirmer ni infirmer** leur usage réel à partir de l'extrait ; l'affirmation "capacités natives réelles" reste au niveau des imports, pas des appels. Aucune des deux sandboxes VT n'a réussi à faire tourner le script jusqu'au bout (§6bis.3), donc pas non plus de confirmation dynamique de ces capacités précises.

### 6bis.2 Des commentaires en russe : signal d'attribution qui nuance "l'IA a agi seule"

Les commentaires du code (décodés depuis un encodage mojibake dans le rapport HTML) sont en **russe** :

| Commentaire original (mal encodé) | Traduction |
|---|---|
| `Ð\x91Ð\x90Ð\x97Ð\x90 Ð\x94Ð\x90Ð\x9dÐ\x9dÐ«Ð¥ Ð\x90Ð\x94Ð\x90` | БАЗА ДАННЫХ АДА, "Base de données de l'Enfer" (Inferno) |
| `Ð\x98Ð\x9dÐ\x98Ð¦Ð\x98Ð\x90Ð\x9bÐ\x98Ð\x97Ð\x90Ð¦Ð\x98Ð¯` | ИНИЦИАЛИЗАЦИЯ, "Initialisation" |
| `Ð\x96ÐµÑ\x80Ñ\x82Ð²Ñ\x8b` | Жертвы, "Victimes" |
| `Ð\x9aÐ\x9eÐ\x9dÐ¤Ð\x98Ð\x93 Ð\x90Ð\x94Ð\x90` | КОНФИГ АДА, "Config de l'Enfer" (Inferno) |

Liste complète des commentaires cyrilliques de l'extrait : `КОНФИГ АДА` (config de l'Enfer), `ИНИЦИАЛИЗАЦИЯ` (initialisation), `Логирование всего` (journalisation de tout), `БАЗА ДАННЫХ АДА` (base de données de l'Enfer), puis les en-têtes de tables `Жертвы` (victimes), `Discord токены`, `Банковские карты` (cartes bancaires), `Крипто кошельки` (portefeuilles crypto), `Кейлоггер`, `Скриншоты`, `Вебкамера`, `Микрофон`. Le thème "Ад/Enfer" (le mot `Ада` est le génitif de "enfer") est cohérent avec le nom auto-attribué "InfernoGrabber".

**Ce que ça dit, et ce que ça ne dit pas.** Ces commentaires **n'apparaissent pas dans le rapport Check Point**, qui précise par ailleurs explicitement *"We do not have the prompt submitted to the AI model that produced this sample"* : la langue du prompt leur est inconnue, et l'observation du russe est ici indépendante de leur analyse. Point logique à ne pas surinterpréter : des commentaires russes sont **autant compatibles avec un prompt rédigé en russe** (auquel cas le modèle a bien généré le code, commentaires compris, sans édition humaine) **qu'avec une retouche par un opérateur russophone**. Ils ne prouvent donc pas une "édition humaine post-génération", contrairement à ce qu'une lecture rapide pourrait conclure. Ce qu'ils établissent de plus solide, c'est un **opérateur vraisemblablement russophone** (côté prompt ou côté édition), ce qui nuance surtout le raccourci de presse "l'IA anglophone a tout fait seule", sans permettre d'attribution géographique certaine (un prompt traduit, ou un opérateur non russophone s'appuyant sur un modèle multilingue, restent possibles). Ce signal russophone est **renforcé indépendamment** par le compte Discord dont l'avatar sert au leurre, résolu en `bogatov` / `ТОТ САМЫЙ` (nom d'affichage russe), voir §6.2. **[OUVERT]** : impossible de trancher prompt-en-russe vs édition-humaine depuis l'extrait seul.

### 6bis.3 Portée du projet révélée par le schéma de base de données

Le schéma SQLite (`InfernoDB`) définit des tables bien plus détaillées que ce que suggère la liste de capacités de Check Point : `victims` (fingerprinting matériel complet : GPU/CPU/RAM/disques/polices/logiciels installés/interfaces réseau/MAC), `discord_tokens` (avec des champs pour `billing`, `payment_sources`, `subscriptions`, `gift_codes`, `backup_codes`, visant clairement une prise de contrôle complète de compte, pas juste un token), `credit_cards`, une table de tracking souris/scroll/fenêtre en temps réel, `screenshots`, `webcam_captures`, `microphone_captures` (avec échantillonnage audio détaillé). Que ces tables soient effectivement remplies par du code fonctionnel ou restent vides (cohérent avec les "hallucinations" de Check Point) n'est pas vérifiable depuis cet extrait seul, mais l'**ambition de conception** est bien plus large que "ransomware avec un peu de vol de données".

**Aucune activité réseau capturée dans les deux sandboxes VT** (`CAPE Linux` : tous les onglets réseau vides, "Nothing to display" ; `Zenbox` : deux IP vues, `8.8.8.8` = simple vérification de connectivité, `150.171.22.17` = serveur Microsoft Skype/Teams, confirmé via Shodan InternetDB comme télémétrie de la VM sandbox, pas l'infrastructure de l'attaquant). Cohérent avec l'hypothèse que le script a planté tôt (dépendances manquantes comme `selenium`/`pyautogui`/`GPUtil` non installées dans l'environnement sandbox) avant d'atteindre la logique réseau, ce qui expliquerait aussi pourquoi le webhook Discord n'a jamais reçu de vraie requête POST de test.

## 7. Ce qui reste à faire (plan de reprise)

Point d'étape sur les pistes ouvertes précédemment :

1. **Récupérer le reste du fichier au-delà de la troncature CAPE** : reste **le vrai blocage**. Vérifié depuis : la troncature CAPE tombe au milieu de la table `microphone_captures` (bloc utile ≈ 8 Ko sur 160 Ko), et le rapport `Zenbox` ne contient **aucun aperçu de code** (zéro occurrence des mots-clés `import flask`/`InfernoDB`/`CREATE TABLE`/`browser_cookie3`), sa structure HTML ne comporte pas de panneau de prévisualisation source. Pistes restantes non essayées : compte VT premium/partenaire (le `/download` gratuit reste en 403), contacter Check Point Research directement.
2. **Capacités réelles vs hallucinées** : partiellement tranché (§6bis.1). Dans le code récupéré, `browser_cookie3`/`pyperclip`/`pyautogui`/`selenium` ne sont **qu'importés, jamais invoqués** ; le code qui les appellerait est au-delà de la troncature. Ni confirmé ni infirmé, ça reste conditionné à l'obtention du fichier complet (point 1).
3. **Attribution de l'ID Discord `422811769203851274`** : avancé (§6.2). Snowflake décodé = compte de mars 2018, avatar CDN toujours en ligne ; interprétation orientée "avatar tiers réutilisé pour le leurre" plutôt que compte de l'attaquant. Résolution du pseudo bloquée sans token bot Discord.
4. **Piste "commentaires russes"** : traité (§6bis.2). Check Point ne mentionne pas ces commentaires et n'a pas le prompt ; conclusion resserrée à "opérateur vraisemblablement russophone", sans attribution géographique certaine.
5. **Reproduction pédagogique File System Access API** : fait, voir [`fsapi-demo.html`](fsapi-demo.html) (énumération récursive en lecture seule d'un dossier jetable, sans chiffrement ni exfiltration, pour illustrer la propriété "une seule autorisation, accès récursif complet").
6. **Autres webhooks / adresses Bitcoin dans les artefacts** : vérifié (§6.1 et ci-dessous). Aucune adresse Bitcoin valide (les candidats base58 détectés ont tous un checksum invalide et sont en réalité des fragments de blobs base64 en mémoire) ; aucun autre webhook que celui déjà connu (versions tronquée et complète du même).

## 8. Limites et honnêteté méthodologique (état actuel)

- **Le code source n'a été lu que partiellement** (extrait tronqué via l'aperçu statique de CAPE Linux, pas le fichier complet), documenté comme lecture partielle, pas une lecture intégrale.
- L'affirmation "la plupart des capacités sont des hallucinations non fonctionnelles" vient de Check Point, partiellement nuancée par notre propre lecture (les imports de bibliothèques réelles comme `pyautogui`/`selenium` suggèrent une ambition plus native que "browser-only"), mais pas tranchée : on n'a pas vu le code qui les *utilise*, seulement les imports.
- **Aucune des deux sandboxes VT n'a réussi à faire tourner le script jusqu'à une activité réseau**, donc aucune confirmation dynamique indépendante du webhook Discord en action, ni des capacités natives listées en §6bis.1. Tout repose sur la lecture statique du code + l'affirmation de Check Point.
- Le webhook Discord retrouvé (version complète et tronquée, les deux testées) est confirmé mort par nous-mêmes, mais on ne sait pas depuis quand ni par qui il a été désactivé.
- Aucune confirmation qu'un ID Discord retrouvé dans les URLs correspond à l'attaquant plutôt qu'à un avatar d'exemple.
- La piste "commentaires en russe" est une observation brute, pas une attribution, pourrait aussi refléter un prompt traduit, un opérateur non-russophone utilisant un outil de traduction, ou tout autre scénario. Présentée comme nuance au narratif presse, pas comme attribution géographique certaine.
- Le comportement "process en mode suspendu" pourrait être un faux positif générique de sandbox plutôt qu'une vraie capacité d'injection, non tranché.

## 9. IOCs consolidés (état actuel)

| Type | Valeur |
|---|---|
| Nom de fichier | `deepseek_python_20260125_da0631.py` |
| SHA256 | `07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5` |
| MD5 | `11bd02a19047dacd5ef6bac3f67a68e2` |
| Webhook Discord d'exfiltration (mort, vérifié en version complète et tronquée ; snowflake créé le 25/01/2026, jour de l'upload VT) | `discord.com/api/webhooks/1465066143516459277/g5X5V-ehzLCWP_S1kOkR4-EL2fdhev3xznUV3OtVUNJ0sNAkrLhs-_dQZaAIILDSq8m2` |
| ID Discord dans l'avatar du leurre, résolu en `bogatov` / `ТОТ САМЫЙ` (russophone, Nitro, compte de 2018, clan `ST`) ; avatar CDN encore en ligne, "compte = opérateur" probable mais non prouvé | `422811769203851274` |
| Base de données locale attaquant | `inferno.db` (SQLite), tables `victims`/`discord_tokens`/`credit_cards`/`screenshots`/`webcam_captures`/`microphone_captures` |
| Classification VT | `TrojanRansom` / `MALWARE`+`RANSOM`, confiance 48% |
| Nom auto-attribué | InfernoGrabber v9.0 |
| Source de génération | DeepSeek (LLM), commentaires de code en russe |
| Rapport source | [Check Point Research, 01/07/2026](https://research.checkpoint.com/2026/browser-only-ransomware-from-llm-hallucinations-to-a-practical-attack-technique/) |
| Sandboxes VT ayant analysé le sample | CAPE Linux (aperçu code statique, aucune activité réseau), Zenbox (Windows, aucune activité réseau pertinente) |

## 10. Reproduire l'analyse

Log détaillé dans [`runbook.md`](runbook.md).

Démonstration pédagogique isolée du mécanisme côté client (File System Access API) : [`fsapi-demo.html`](fsapi-demo.html). À ouvrir dans un navigateur Chromium, sur un **dossier de test jetable**. La page se limite à l'énumération récursive en lecture seule pour illustrer la primitive centrale (une seule autorisation utilisateur donne un accès récursif à tout le dossier) ; elle ne reproduit ni le chiffrement ni l'exfiltration du malware.
