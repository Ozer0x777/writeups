# Runbook — reproduction pas à pas (Parties 1 à 4)

Ce fichier regroupe les logs de manipulation (commande / pourquoi / retour brut / ce qu'on en retient) des quatre parties de l'enquête AgentTesla, dans l'ordre chronologique. Les parties `0X-*.md` restent le récit analytique ; ce fichier est la preuve de travail et le mode d'emploi pour rejouer chaque étape.

Prérequis : `pefile`, `capa`+règles, `ilspycmd` (`dotnet tool install -g ilspycmd`), `.NET SDK` 10.0, `pycryptodome`, une clé API MalwareBazaar (voir [`../stealc-autoit-killchain/runbook.md`](../stealc-autoit-killchain/runbook.md) pour l'installation de la base commune, déjà en place pour cette analyse).

---

## Partie 1 — Loader stage 1

### 1. Recherche d'un candidat .NET récent taggé ConfuserEX

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_taginfo&tag=ConfuserEX&limit=1000"
```

**Pourquoi :** valider qu'il existe des échantillons AgentTesla récents avec ce tag communautaire avant de creuser plus loin.

**Retour :** seulement 3 résultats au total pour ce tag précis, le plus récent datant de 2025-07-29 — pas assez récent ni assez représentatif pour servir de base de recherche.

**Ce qu'on en retient :** élargir la recherche directement par signature `AgentTesla` plutôt que par tag de protecteur, et filtrer ensuite sur les vrais binaires `.NET/CIL`.

### 2. Recherche par signature AgentTesla, filtrage sur les vrais binaires .NET

**Commande :**
```python
# query=get_siginfo&signature=AgentTesla&limit=1000, puis filtrage cote client :
rows = [r for r in data if r['file_type'] in ('exe','dll')]
rows = [r for r in rows if any('.NET' in t or 'MSIL' in t or 'CIL' in t for t in r['trid'])]
rows.sort(key=lambda r: r['first_seen'], reverse=True)
```

**Pourquoi :** la majorité du flux du jour est constituée de scripts `.js`/`.vbs` de première étape (droppers), pas des binaires .NET compilés eux-mêmes — filtrer pour ne garder que les vrais CIL.

**Retour :** plusieurs candidats du 14/07/2026, dont `CTM.exe` (1 320 960 octets) et `RFQ013072026,PDF.exe` (993 792 octets), tous deux avec une bonne couverture sandbox tierce (CAPE, ANY.RUN, Triage, VMRay, UnpacMe).

**Ce qu'on en retient :** `CTM.exe` retenu (le plus gros des deux, donc probablement le plus riche en logique).

### 3. Téléchargement, extraction, vérification (méthode identique StealC)

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_file&sha256_hash=bc6d86cef1b7404823c1d830387b2c9b1289c453620482fc1749dd5d2ade3897" -o sample.zip
7z x -pinfected sample.zip -y
sha256sum *.exe
chmod -x *.exe
file *.exe
```

**Retour :** hash vérifié conforme, `PE32 executable for MS Windows 6.00 (GUI), Intel i386 Mono/.Net assembly, 3 sections`.

**Ce qu'on en retient :** échantillon confirmé .NET, prêt pour décompilation.

### 4. capa

**Commande :**
```
capa -r tools/capa-rules --signatures <floss-sigs> -j CTM.exe > capa_out.json
```

**Retour :** 12 capacités, dont `compiled to the .NET platform`, `access .NET resource`, `decrypt data using AES via .NET`, `invoke .NET assembly method`.

**Ce qu'on en retient :** hypothèse initiale — loader .NET, ressource + AES + réflexion.

### 5. Décompilation ilspycmd

**Commande :**
```
ilspycmd -o decompiled/ CTM.exe
wc -l decompiled/*.cs
grep -oE "class [A-Za-z0-9_<>.]+" decompiled/*.cs | sort -u | wc -l
```

**Retour :** 16 811 lignes, 64 classes, identifiants aléatoires courts (`0fdPNa5xi7Z`...).

**Ce qu'on en retient :** obfuscation d'identifiants confirmée, protecteur non identifié à ce stade (hypothèse ConfuserEx par analogie seulement, non vérifiée).

### 6. Localisation du point d'entrée et vérification de la porte factice

**Commande :**
```
grep -n "STAThread" decompiled/*.cs
# puis lecture manuelle du corps de la methode juste apres, et de Xf8i0tdBN4k()
```

**Retour :** point d'entrée `4Rzepd2M9()` marqué `[STAThread]` ; `Xf8i0tdBN4k()` → `return true;` inconditionnel.

**Ce qu'on en retient :** pas un vrai kill switch, vestige ou porte factice.

### 7. Recherche du leurre applicatif

**Commande :**
```
grep -n "MessageBox.Show\|DrawString" decompiled/*.cs
```

**Retour :** chaînes de dimensionnement de structure navale ("Stiffener optimization algorithm...", "STRENGTH DECK"...).

**Ce qu'on en retient :** leurre applicatif complet, pas un template vide.

### 8. Traçage de la chaîne de chargement

**Commande :**
```
grep -n "Assembly.Load\|GetExecutingAssembly\|EntryPoint.Invoke\|Invoke(null" decompiled/*.cs
grep -n "GetManifestResourceStream\|GetManifestResourceNames" decompiled/*.cs
grep -nE "Aes|CryptoStream" decompiled/*.cs
```

**Retour :** chargement par réflexion (`methodInfo.Invoke`, pas `Assembly.Load` littéral), lecture de ressource via `GetManifestResourceStream`, pipeline `Aes.Create()`+`CryptoStream`.

**Ce qu'on en retient :** hypothèse capa confirmée par lecture de code, reste à localiser la clé et le nom de ressource exacts.

### 9. Localisation de la clé AES et de la ressource

**Commande :**
```
# lecture manuelle de la fonction de dechiffrement trouvee via le pipeline CryptoStream ci-dessus
ilspycmd --list-resources CTM.exe
```

**Retour :** ressource `Genitalk.klaoxao.tiff` (parmi les ressources icônes/dialogues), clé AES-128 en dur `e4a931cb6e204322da0d1a30d946633b`, réutilisée comme IV.

**Ce qu'on en retient :** tous les ingrédients réunis pour extraire et déchiffrer.

### 10. Extraction et déchiffrement du stage 2

**Commande :**
```
ilspycmd --resource "Genitalk.klaoxao.tiff" -o . CTM.exe
python3 tools/decrypt_stage2_resource.py Genitalk.klaoxao.tiff stage2.dll
sha256sum stage2.dll
```

**Retour :**
```
Ressource source : 459024 octets
Dechiffre        : 459024 octets
Magic PE (MZ)?   : True
SHA256 (stage2)  : 39fdba7a439cb09842f26d34f84606e3cc7f685b407deceb49ee7cb71271ebcd
```

**Ce qu'on en retient :** stage 2 extrait avec succès, entièrement en statique, sans jamais exécuter le binaire.

### 11. Vérification MalwareBazaar du stage 2

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_info&hash=39fdba7a439cb09842f26d34f84606e3cc7f685b407deceb49ee7cb71271ebcd"
```

**Retour :** `{"query_status": "hash_not_found"}`.

**Ce qu'on en retient :** stage 2 non indexé publiquement au moment de l'analyse — aucun rapport tiers à croiser à ce stade.

---

## Partie 2 — Identification du protecteur et control-flow flattening

### 1. Décompilation stage 2 et repérage du protecteur

**Commande :**
```
ilspycmd -o decompiled_stage2/ stage2.dll
grep -n "protected by an unregistered version" decompiled_stage2/*.cs
```

**Retour :** chaîne de licence trial Eziriz .NET Reactor trouvée en clair dans un `case` du dispatcher.

**Ce qu'on en retient :** protecteur identifié avec certitude — correction de l'hypothèse ConfuserEx non vérifiée de la Partie 1.

### 2. Mesure de l'ampleur du control-flow flattening

**Commande :**
```
grep -c "switch (" decompiled_stage2/*.cs
grep -c "case [0-9]\+:" decompiled_stage2/*.cs
```

**Retour :** 142 `switch` (dont 79 avec ≥5 cases, les vrais dispatchers), 1 891 `case` au total ; le plus gros bloc (ligne 8965) fait 747 cases sur 4 621 lignes.

**Ce qu'on en retient :** ampleur nettement supérieure à AsgardProtector/StealC (354 blocs, ~1 branche réelle chacun) — nécessite un outil dédié adapté à un vrai graphe de contrôle, pas juste "trouver la bonne constante".

### 3. Construction et débogage de `deflatten_cs.py`

**Commande :**
```
python3 tools/deflatten_cs.py decompiled_stage2/stage2.decompiled.cs
```

**Retour (première version)** : 0 non-résolu apparent, mais vérification manuelle du plus petit bloc (6 cases, celui du message ".NET Reactor") révèle des `goto case 0;`/`goto end_IL_0014;` complètement absents de l'analyse.

**Correction appliquée** : détection de `goto case N` (arête `CASE`) et `goto Label` (arête `EXIT`), en plus des réaffectations littérales.

**Retour après correction, vérifié à la main sur ce même bloc :**
```
case [None] (default): default=('EXIT','return') branch=[('EXIT','goto end_IL_0014'), ('CASE', 0)]
case [3]: default=('CASE', 10) branch=[('CASE', 1)]
case [0]: default=('EXIT','throw') branch=[] TERMINAL
```
Correspond exactement à la source relue à la main.

**Ce qu'on en retient :** ne jamais faire confiance à "0 non-résolu" sans vérification manuelle indépendante — la métrique peut être fausse par omission plutôt que par erreur de calcul.

### 4. Construction et débogage de `linearize_cs.py`

**Commande :**
```
python3 tools/linearize_cs.py decompiled_stage2/stage2.decompiled.cs stage2_linearized.txt
grep "point d'entree\|Etats atteints" stage2_linearized.txt
```

**Retour (première version)** : couverture quasi nulle sur la plupart des 24 dispatchers (souvent 0-2 états sur 5-45).

**Diagnostic** : le vrai littéral d'entrée (`int num = 299;`) est à 114 lignes du `switch` principal, hors de la fenêtre de recherche fixe (60 lignes) reprise par réflexe de l'expérience StealC. De plus, la regex de suivi de chaîne de copie ne gérait pas le préfixe de type d'une déclaration (`int num2 = num;` vs `num2 = num;`).

**Correction appliquée** : recherche bornée par la signature de méthode englobante plutôt qu'un nombre de lignes fixe ; regex acceptant le préfixe de type.

**Retour après correction :**
```
switch(num3) @ ligne source 8965 -- 649 cases
point d'entree detecte: etat 299
Etats atteints depuis l'entree: 415/673
```

**Ce qu'on en retient :** une fenêtre fixe qui a fonctionné sur un projet (StealC) ne se transpose pas automatiquement à un autre — vérifier la distance réelle plutôt que réutiliser une constante par habitude.

### 5. Traçage de la séquence d'API avec arguments réels

**Commande :**
```
grep -n "ValidateDetachedFunction(\|StructAdvancedQueue(\|ValidateAutomatedCollection(\|SendField(\|ValidateJoinedList(" stage2_linearized.txt
# puis remontee des trampolines (ExecuteSharer, DestroyDetailedRole, InstantiateSegmentedStrategy, InstantiateTransformableFinalizer)
# et lecture de leurs corps pour reconstruire les vrais noms d'API (LoadLibrary/GetProcAddress + concatenation de chaines)
```

**Retour :** séquence `FindResourceA`/`OpenProcess(0x38,...)`/`VirtualAlloc(NULL,...)`/`WriteProcessMemory`/`VirtualProtect`/`CloseHandle` avec arguments concrets.

**Ce qu'on en retient :** confirme la manipulation mémoire de process suspectée par capa dès la Partie 1, avec des valeurs d'arguments vérifiables (`0x38` = droits minimaux d'injection).

### 6. Traçage de la source du PID et découverte de la fausse piste

**Commande :**
```
grep -n "StoreConfiguration\|CompareFlexibleVerifier\|DestroySegmentedProxy" decompiled_stage2/*.cs
# lecture des corps de fonction correspondants
```

**Retour :** `StoreConfiguration()` = `Process.GetCurrentProcess()` ; `DestroySegmentedProxy(P_0,P_1)` = `P_0 != P_1` (simple test d'inégalité).

**Ce qu'on en retient :** hypothèse d'auto-injection formée, à vérifier avant publication (étape suivante).

### 7. Vérification de la fausse piste (ressource native absente)

**Commande :**
```python
import pefile
pe = pefile.PE('CTM.exe')  # puis stage2.dll
pe.parse_data_directories()
for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    print(rt.name if rt.name else rt.struct.Id, [...])
```

**Retour :** seules des ressources `RT_ICON`(3)/`RT_GROUP_ICON`(14)/`RT_VERSION`(16) présentes dans les deux binaires — aucune `RT_RCDATA`(10) nommée `"__"`.

**Ce qu'on en retient :** la séquence d'auto-injection tracée n'est jamais empruntée sur cet échantillon — corrigé avant d'être présenté comme le comportement réel. Le vrai chemin part ailleurs (Partie 3).

---

## Partie 3 — Vrai chemin et tentatives d'outillage

### 1. Traçage du vrai chemin (état 28)

**Commande :**
```python
# reutilisation directe de deflatten_cs.py (find_switch_blocks, split_cases, analyze_case)
# DFS depuis l'entree 28 au lieu de 299, sur le meme graphe deja extrait
```

**Retour :** 417/673 états atteints, avec à l'état 30 la lecture de la ressource `"ObjectRequester.ScopeObject"` (une des 4 ressources .NET réellement présentes).

**Ce qu'on en retient :** le vrai chemin d'exécution identifié, distinct de la fausse piste corrigée en Partie 2.

### 2. Point fixe sur les points d'entrée en cascade

**Commande :**
```python
# extension du script precedent : a chaque noeud "TERMINAL" qui reaffecte
# la variable EXTERNE 'num', collecter cette valeur comme nouveau point
# d'entree a explorer, repeter jusqu'a stabilisation
```

**Retour :**
```
Points d'entree externes decouverts au total : 79 valeurs distinctes
Etats du switch(num3) couverts (union de toutes les entrees) : 653/673
```

**Ce qu'on en retient :** 97% de couverture sans nouvel outil, juste un usage différent (itératif) des scripts déjà construits.

### 3. Extraction des 4 ressources chiffrées

**Commande :**
```
ilspycmd --resource "ObjectRequester.ScopeObject" -o . stage2.dll
ilspycmd --resource "ScheduledObject.ObjectParser" -o . stage2.dll
ilspycmd --resource "DecryptorCompressor.ControllableObject" -o . stage2.dll
ilspycmd --resource "AuditorMap.LocalObject" -o . stage2.dll
file ObjectRequester.ScopeObject ScheduledObject.ObjectParser DecryptorCompressor.ControllableObject AuditorMap.LocalObject
```

**Retour :** 92 079 / 256 / 132 597 / 4 080 octets respectivement, toutes `data` (haute entropie, aucun en-tête reconnaissable).

**Ce qu'on en retient :** confirmées chiffrées, prêtes à être attaquées si un algorithme de déchiffrement est isolé.

### 4. Vérification publique avant d'investir plus d'heures à la main

**Commande (WebSearch) :**
```
"Eziriz .NET Reactor method decryption mechanism embedded resource reverse engineering internals"
```

**Retour :** confirmation que .NET Reactor stocke son bytecode de VM et ses métadonnées de protection directement dans des ressources d'assembly (source : deepwiki.com/void-stack/VMAttack).

**Ce qu'on en retient :** le mécanisme tracé est probablement générique au protecteur, pas spécifique au malware — pivot vers un outil spécialisé plutôt que de continuer à la main.

### 5. Première tentative NETReactorSlayer (binaire officiel)

**Commande :**
```
curl -s "https://api.github.com/repos/SychicBoy/NETReactorSlayer/releases/latest"
curl -sL -o slayer.zip "https://github.com/SychicBoy/NETReactorSlayer/releases/download/v6.4.0.0/NETReactorSlayer.CLI-net6.0-linux64.zip"
unzip -q slayer.zip && chmod +x NETReactorSlayer.CLI
./NETReactorSlayer.CLI stage2.dll --no-pause True
```

**Retour :**
```
751 Methods decrypted.
999 Equations resolved.
Anti tamper removed.
Anti debugger removed.
[ERROR] An unexpected error occurred during decrypting resources. Object reference not set to an instance of an object.
185 Calls to obfuscator types removed.
567 Methods inlined.
```

**Ce qu'on en retient :** progrès global réel, mais échec sur le déchiffrement de ressources spécifiquement, et la méthode d'injection reste flattened après nettoyage.

### 6. Recherche du bug et compilation depuis la source

**Commande (WebSearch puis git) :**
```
git clone https://github.com/SychicBoy/NETReactorSlayer.git
cd NETReactorSlayer
git log -1 --format="%H %ad %s"
dotnet build NETReactorSlayer.CLI/NETReactorSlayer.CLI.csproj -c Release -f net6.0
DOTNET_ROLL_FORWARD=LatestMajor dotnet bin/Release/net6.0/NETReactorSlayer.CLI.dll stage2.dll --no-pause True
```

**Retour :** commit `"Improve resource decrypter. Resolve #54"` daté du 15/12/2022, 3 jours après la release v6.4.0.0 testée à l'étape précédente — jamais publié dans un binaire. Compilation réussie (avertissements EOL sur les cibles net6.0/netcoreapp3.1, ignorables), exécution réussie via roll-forward vers le runtime .NET 10 installé. **Même erreur exacte malgré le correctif.**

**Ce qu'on en retient :** le correctif de 2022 ne couvre pas ce cas précis — creuser plus loin dans le code source plutôt que supposer que "la dernière version" suffit.

### 7. Diagnostic par lecture du code source

**Commande :**
```
cat NETReactorSlayer.Core/Stages/ResourceResolver.cs
```

**Retour :** le stage cible spécifiquement un pattern "assembly-en-ressource chargé via `AppDomain.AssemblyResolve`" (recherche d'une méthode de signature `(object, ResolveEventArgs)`), différent du mécanisme réellement utilisé par ce sample (`GetManifestResourceStream` direct depuis le code flattened).

**Ce qu'on en retient :** ce n'est pas un bug à corriger, c'est un outil qui répond à un mécanisme différent de .NET Reactor — conclusion honnête plutôt que de continuer à chercher un correctif qui n'existe pas pour ce cas.

---

## Partie 4 — Confirmation externe

### 1. Lecture complète du vendor_intel MalwareBazaar

**Commande :**
```
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: ****" -d "query=get_info&hash=bc6d86cef1b7404823c1d830387b2c9b1289c453620482fc1749dd5d2ade3897"
```

**Retour (extrait pertinent) :**
```json
"ANY.RUN": [{"malware_family": "agenttesla", "tags": ["netreactor","stealer","ip-check","evasion","agenttesla","ftp","exfiltration"]}]
"Triage": {"malware_family": "agenttesla", "link": "https://tria.ge/reports/260714-kt4y4scs2z/"}
"VMRay": {"malware_family": "AgentTesla"}
"UnpacMe": [5 hashs lies, dont un avec detections "win_agent_tesla_g2", "triage_agenttesla_infostealer"]
```

**Ce qu'on en retient :** famille confirmée indépendamment par 3 sandboxes, protecteur confirmé indépendamment par ANY.RUN (`netreactor`), 5 artefacts d'unpacking automatique référencés.

### 2. Lecture du rapport Triage complet

**Commande (WebFetch) :**
```
https://tria.ge/reports/260714-kt4y4scs2z/
```

**Retour :** config extraite — exfiltration FTP vers `ftp.piovau.com:21`, identifiants en clair dans le rapport ; comportements : accès profils Outlook, consultation IP externe, usage de `SetThreadContext`.

**Ce qu'on en retient :** `SetThreadContext`, jamais vu dans notre traçage statique (Parties 2-3), confirme que le hollowing classique se passe dans le payload final non extrait — referme la chaîne complète sans déchiffrement manuel.

### 3. Tentative de consultation UnpacMe (non aboutie)

**Commande (WebFetch) :**
```
https://www.unpac.me/results/aea68fba-c3e3-4816-ab82-370ea9b491ef/
```

**Retour :** page rendue en JavaScript (SPA), contenu non extractible par récupération simple de page.

**Ce qu'on en retient :** piste laissée ouverte pour une prochaine session (accès direct au hash via API si disponible), pas bloquante pour les conclusions déjà établies via Triage/ANY.RUN.
