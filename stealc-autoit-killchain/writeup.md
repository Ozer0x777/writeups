# Analyse StealC : d'un dropper GCleaner à un C2 actif, sans exécuter le binaire

**Analyste :** Gordon PEIRS
**Date d'analyse :** 13/07/2026
**Type :** Analyse statique uniquement (aucune exécution du binaire par l'auteur) — voir la note de méthode en §8 pour la seule étape reposant sur l'exécution d'un tiers.
**Famille :** StealC (infostealer, MaaS)

> Ce document regroupe l'intégralité du récit analytique (constats, hypothèses, conclusions) des quatre volets de l'enquête. La **preuve de travail reproductible** (commande / pourquoi / sortie brute) vit séparément dans [`runbook.md`](runbook.md), organisé selon les mêmes quatre parties. Les scripts autonomes sont dans [`tools/`](tools/).

---

## 1. Contexte et choix de l'échantillon

Échantillon récupéré via [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch), recherche par signature `Stealc`.

Ce sample n'est pas directement lié à une campagne précise documentée publiquement. Il a été choisi comme représentatif d'un build courant (imphash partagé avec plusieurs autres soumissions récentes du même reporter), première observation le 13/07/2026, tag `dropped-by-gcleaner`.

Précision apportée après coup (voir §6.4) : cet imphash s'est révélé partagé par des échantillons de familles totalement différentes (Amadey, LummaStealer, Vidar, QuasarRAT...). Il ne caractérise donc pas StealC spécifiquement, mais le crypter (Asgard Protector, voir §6.4) qui protège indifféremment des payloads de familles variées. Le rattachement à StealC repose uniquement sur le tag `signature: Stealc` assigné par MalwareBazaar/le reporter, jamais vérifié par observation directe d'un comportement de vol de données (le vrai payload injecté n'a jamais été obtenu, voir §6.3 et §8).

## 2. Identité de l'échantillon

| Champ | Valeur |
|---|---|
| SHA256 | `afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da` |
| MD5 | `dc8db3908bec45fc19bfb4d2c4514474` |
| Type | PE32 executable, Intel i386, GUI |
| Taille | 2 195 968 octets |
| Imphash | `646167cce332c1c252cdcb1839e0cf48` |
| Reporter (MalwareBazaar) | Bitsight |
| Tags | `dropped-by-gcleaner`, `Stealc`, `exe` |

## 3. Outillage

- `file`, `pefile` (Python), pour l'identification et le parsing PE
- [`capa`](https://github.com/mandiant/capa) 9.4.0 + règles officielles `capa-rules`, pour la détection de capacités
- [`floss`](https://github.com/mandiant/flare-floss) 3.1.1, pour l'extraction de chaînes cachées/décodées
- `cabextract`, pour l'extraction d'archive CAB embarquée
- [`autoit-ripper`](https://github.com/nazywam/AutoIt-Ripper), pour la décompilation de bytecode AutoIt compilé (`.a3x`)

Tout le travail a été réalisé en local, sans exécution du binaire (pas d'environnement sandbox isolé disponible pour cette session, donc analyse strictement statique).

## 4. Le stub IExpress : analyse statique

### 4.1 En-têtes PE

- **Entry point** : `0x6ce0`, **Image base** : `0x400000`
- **Timestamp de compilation falsifié** : valeur brute `2215452883`, ce qui correspond au `15/03/2040`. Technique d'anti-analyse classique (perturbe le tri chronologique et certains outils de sandboxing).
- **Sections** :

| Section | Taille virtuelle | Entropie |
|---|---|---|
| `.text` | 0x662c | 6.26 |
| `.data` | 0x1aa0 | 4.97 |
| `.idata` | 0x1052 | 5.03 |
| `.rsrc` | **0x20f68a** | **7.99** |
| `.reloc` | 0x888 | 6.26 |

`.rsrc` représente à elle seule ~95% du binaire avec une entropie quasi-maximale (7.99/8), ce qui suggère fortement un payload packé/chiffré planqué en ressource plutôt qu'en `.text`.

- **Imports notables** : `Cabinet.dll` (4 fonctions), un indice fort d'une extraction de CAB au runtime, cohérent avec l'hypothèse ci-dessus.

### 4.2 Capa — capacités détectées

Capa classe directement le binaire comme **installeur** (`(internal) installer file limitation`), avec 47 capacités remontées, dont les plus significatives :

- **`packaged as an IExpress self-extracting archive`** : confirme le mécanisme. IExpress est un outil natif Windows de création d'auto-extractibles, ce qui explique l'import `Cabinet.dll` et l'entropie de `.rsrc`.
- **`persist via Run registry key`** : persistance via `Software\Microsoft\Windows\CurrentVersion\RunOnce` (clé observée à plusieurs offsets : `0x4020DC`, `0x402167`, `0x40237D`).
- **`reference anti-VM strings targeting Xen`** : chaînes `"XeN:"`, `"XeNa"`, `"xeNe"` trouvées respectivement à `file+0x61FC5`, `file+0x1D11CE`, `file+0x49D41`. Détection d'hyperviseur Xen (utilisé par certains sandbox d'analyse).
- **`reference analysis tools strings`** : indices de détection d'outils d'analyste (détaillé en §6).
- Collecte système : disque, version OS, énumération de fichiers/registre, cohérent avec du fingerprinting de machine avant déploiement du payload final.

### 4.3 Floss

**Floss** ne remonte quasiment aucune chaîne cachée/décodée dans le code du stub lui-même (`--no static`), ce qui confirme que la logique réelle n'est pas dans ce binaire mais dans la ressource packée.

### 4.4 Extraction de la ressource — CAB puis AutoIt

Parsing des ressources PE (`pefile`) : la ressource de type **10 (RCDATA)**, taille **1 979 115 octets**, commence par la signature `MSCF` (Microsoft Cabinet File).

```
extracted/payload.cab: Microsoft Cabinet archive data, many, 1979115 bytes, 2 files,
  "Quotes.a3x" (last modified 2026-07-12 16:52:18)
  "AutoIt3.exe" (last modified 2026-07-12 16:52:40)
```

Extraction (`cabextract`), on obtient deux fichiers :

| Fichier | SHA256 | Nature |
|---|---|---|
| `AutoIt3.exe` | `92c6531a09180fae8b2aae7384b4cea9986762f0c271b35da09b4d0e733f9f45` | Interpréteur AutoIt **légitime**, abusé comme LOLBin |
| `Quotes.a3x` | `49ded704632abe3642b76c32c60d46ab99402495624921787e0c57a85f83327d` | Script AutoIt **compilé**, logique malveillante réelle |

Technique reconnue : livrer l'interpréteur AutoIt légitime (souvent whitelisté / signé) accompagné d'un script compilé (`.a3x`) contenant la charge utile. Le stub IExpress extrait les deux fichiers puis lance `AutoIt3.exe Quotes.a3x`. Fichiers datés du 12/07/2026, soit la veille de l'analyse.

### 4.5 Décompilation du script AutoIt

`autoit-ripper` a réussi à décompresser le bytecode (`EA06 compressed blob`) en script source (`.au3`), **2 724 886 octets**, 17 593 lignes.

Le script est **fortement obfusqué** :
- Noms de fonctions/variables : concaténations de mots anglais aléatoires (`VIICONSUMPTIONHOLOCAUST`, `BATHROOMREWARDLIVED`...)
- **Control-flow flattening** : boucle `While` + `Switch` sur une variable d'état numérique, une seule branche réellement exécutée par itération, le reste noyé dans du code mort (appels à `Beep`, `WinExists`, `ControlGetHandle` sur des arguments factices)
- Constantes cassées via `BitXOR` et arithmétique 32-bit (ex. `867661 + 4294100107`)
- **Déchiffrement de chaînes** via une fonction dédiée (`BATHROOMREWARDLIVED($hex, $clé)`) : décode des blobs hexadécimaux avec une clé, appelée systématiquement pour toute chaîne sensible (noms d'API, chemins, etc.)

Exemple représentatif (extrait brut, non résolu) :
```
DllCall ( BATHROOMREWARDLIVED ( "0x1E291E013D1A4A5C65270609" , "uLloXvynKCjexQ" ) ,
          BATHROOMREWARDLIVED ( "0x033A29053D" , "gMFwYpqLOwfKme" ) ,
          BATHROOMREWARDLIVED ( "0x302711180F36072713031830" , "wBeTnEsbaq" ) )
```

Ce niveau d'obfuscation (machine à états + junk code + chiffrement systématique des chaînes) correspond à la sortie d'un **crypter/obfuscateur AutoIt commercial** typique des services de "protection" vendus aux opérateurs de malware-as-a-service, cohérent avec le modèle StealC.

---

## 5. Déobfuscation du loader AutoIt (`Quotes.a3x`)

### 5.1 Le problème

Le script décompilé (`script.au3`, 17 593 lignes) est protégé par un obfuscateur/crypter AutoIt de type commercial :
- Noms d'identifiants : concaténations de mots anglais aléatoires
- **Control-flow flattening** : chaque bloc réel est noyé dans un `While(vrai) / Switch $etat / Case ...` où une seule branche par bloc est réellement exécutée, le reste étant du code mort (junk API calls sur arguments factices)
- Toutes les chaînes sensibles (noms d'API, chemins, clés de registre) sont chiffrées et décodées à la volée via une fonction dédiée : `BATHROOMREWARDLIVED(hex, clé)`

### 5.2 Découverte clé : les "grandes constantes" sont des entiers négatifs mal signés

En analysant à la main `BATHROOMREWARDLIVED` (la fonction de déchiffrement elle-même obfusquée), on remarque que l'état initial d'un `Switch` ne correspond à aucune valeur de `Case` en arithmétique naïve, sauf si on réinterprète les constantes proches de 2³² (et 2⁶⁴) comme des **entiers signés 32-bit (ou 64-bit) mal réinterprétés par le décompileur** `autoit-ripper` :

| Constante brute | Réinterprétée comme |
|---|---|
| `4294967295` | `-1` (0xFFFFFFFF en int32 signé) |
| `4294966729` | `-567` |
| `18446743537125786376` | `-536583240` (proche de 2^64) |

Vérification manuelle sur le premier bloc de `BATHROOMREWARDLIVED` :
- État initial : `349894 + 38 = 349932`
- `Case (363652 + 4294960973 + 4294959899)`, en réinterprétant chaque grande constante comme négative : `363652 + (-6323) + (-7397) = 349932`. C'est un match exact, et cette branche contient justement un `ExitLoop` (les branches "mortes" n'en contiennent jamais), ce qui confirme le raisonnement.

Cet exemple est un cas isolé vérifié à la main. Pour ne pas se contenter d'une poignée d'exemples choisis, la même vérification a été automatisée et appliquée à **tous** les blocs `Switch` du fichier (voir §10 et le runbook) : sur 354 blocs, deux méthodes complètement indépendantes (le calcul arithmétique d'un côté, la présence d'`ExitLoop`/`Return` de l'autre) donnent chacune une réponse unique pour 351 d'entre eux, et ces deux réponses concordent dans les 351 cas, sans un seul désaccord. Pour les 3 blocs restants, un seul des deux signaux est disponible (certains petits `Switch` servent de simple table de correspondance et ne contiennent jamais d'`ExitLoop`, ce qui est normal et ne remet rien en cause) ; les trois ont été relus à la main et confirmés corrects (l'un d'eux est détaillé en §7.5). Ce n'est plus une inférence sur 2 exemples : c'est une validation croisée systématique sur la totalité du fichier.

### 5.3 L'algorithme de déchiffrement des chaînes

En isolant les deux branches réellement exécutées de `BATHROOMREWARDLIVED`, l'algorithme se résume à un **XOR à clé répétée**, octet par octet :

```python
def decrypt(hexstr, key):
    data = bytes.fromhex(hexstr)
    return "".join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(data))
```

### 5.4 Script de déobfuscation

Outil : [`tools/deobfuscate.py`](tools/deobfuscate.py), en deux passes :
1. Déchiffre chaque appel `BATHROOMREWARDLIVED("0xHEX","clé")` inline.
2. Pour chaque bloc `Switch`, réévalue l'expression initiale et celle de chaque `Case` (avec réinterprétation des grandes constantes), ne garde que la branche correspondante (avec vérification croisée via présence de `ExitLoop`/`Return`).

**Résultats sur `script.au3` :**
```
[pass1] decrypted 11698 BATHROOMREWARDLIVED string(s)
[pass2] resolved 354 Switch block(s), 0 ambiguous/unresolved
Wrote deobfuscated.au3 (3188 lines, was 17594)
```

Résultat : ~81% de lignes en moins, quasiment tout le code mort éliminé, et 11 698 chaînes en clair.

> Note sur le décompte de lignes : `wc -l script.au3` renvoie **17 593** (il compte les sauts de ligne), tandis que `deobfuscate.py` affiche « was 17594 » car il compte les éléments de `text.split('\n')`, qui inclut le segment après le dernier saut de ligne (fichier terminé par un newline). Les deux chiffres décrivent le même fichier ; c'est la convention de comptage qui diffère.

---

## 6. Ce que révèle le script déobfusqué (`deobfuscated.au3`)

### 6.1 Chaîne d'appels : process hollowing / RunPE

La séquence d'API remontée est celle d'un **process hollowing classique** :

| Étape | API |
|---|---|
| 1. Création du process cible (suspendu) | `CreateProcessW` |
| 2. Démappage de l'image d'origine | `NtUnmapViewOfSection` |
| 3. Mapping de la nouvelle image (payload réel) | `NtMapViewOfSection` |
| 4. Écriture en mémoire | `NtWriteVirtualMemory` (x2 occurrences distinctes) |
| 5. Redirection du point d'entrée du thread | `NtSetContextThread` |
| 6. Reprise d'exécution | `NtResumeThread` |

Complété par :
- `RtlGetCompressionWorkSpaceSize` / `RtlDecompressFragment` : le payload final est **stocké compressé** et décompressé en mémoire juste avant l'injection.
- `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` : attributs de création de process avancés, cohérent avec du spoofing de PPID ou du blocage de politique DLL (évasion EDR).
- `VirtualAllocExNuma`, `NtWow64ReadVirtualMemory64`, `NtWow64QueryInformationProcess64` : primitives d'allocation/lecture distante, y compris variante WOW64 (process 32-bit manipulant un process 64-bit ou inversement).

**Ce paragraphe se limitait initialement à lire les noms d'API dans l'ordre. Pour vérifier que ce n'est pas qu'une coïncidence de séquence, chaque variable a été retracée jusqu'à sa définition dans le script déobfusqué :**

- `$KNIFEMINACIDCLASSROOM` (le flag de création passé à `CreateProcessW`) vaut `134742020`, soit `0x08080004` en hexadécimal. Le bit `0x4` correspond exactement à `CREATE_SUSPENDED`. Le process est donc bien créé suspendu, ce n'est pas une supposition.
- Juste avant, le script fait `If ProcessExists("avp.exe") Then $KNIFEMINACIDCLASSROOM = 134217732`. `avp.exe` est le nom de process de Kaspersky Anti-Virus. Si Kaspersky tourne, la valeur passe à `0x08000004` : toujours `CREATE_SUSPENDED`, mais sans le bit `EXTENDED_STARTUPINFO_PRESENT` (`0x80000`). C'est un contournement anti-AV concret et nommé, pas une simple "détection d'outils d'analyste" générique.
- La structure passée en dernier argument à `CreateProcessW` est `$KNIGHTANALYSTSTREAMTWENTY = DllStructCreate("ptr Process; ptr Thread; dword ProcessId; dword ThreadId")`, une réplique champ pour champ de la structure Windows `PROCESS_INFORMATION`. Juste après l'appel, `$PACIFIC_ED` et `$N_CONFUSIONALTERNATIVEGAUGE` (utilisés ensuite dans `NtWriteVirtualMemory`, `NtSetContextThread`, `NtResumeThread`) sont lus directement dans les champs `"Process"` et `"Thread"` de cette structure. Ce n'est donc pas juste un nom de variable qui y ressemble : ce sont bien, structurellement, les handles process et thread renvoyés par la création du process cible.
- Le handle de section utilisé dans `NtMapViewOfSection` (`$GOTTENRULEDDIVERSITYWHETHER`) vient de `$YARNFUN = DllCall("ntdll.dll", "long", "NtOpenSection", "handle*", 0, ...)`, puis `$GOTTENRULEDDIVERSITYWHETHER = $YARNFUN[1]` (en AutoIt, l'index 1 d'un retour `DllCall` correspond au premier paramètre passé par référence, ici le handle de section ouvert). La chaîne `NtOpenSection` → `NtMapViewOfSection` → `NtWriteVirtualMemory` est donc tracée de bout en bout, pas seulement observée dans l'ordre d'apparition.
- Point important qui affine la conclusion initiale : dans l'appel `NtMapViewOfSection`, le handle de process passé est bien `+4294967295` (soit `-1`, le pseudo-handle du process courant), donc cette étape mappe la section dans le process du loader **lui-même**, pas dans le process enfant. L'écriture vers le process cible (`$PACIFIC_ED`) se fait ensuite via `NtWriteVirtualMemory`. Autrement dit : la technique n'est pas un hollowing "à l'ancienne" (VirtualAllocEx + WriteProcessMemory), mais une variante basée sur une section mappée localement puis copiée vers le process distant, une méthode bien documentée pour ce type de loader.

### 6.2 Anti-sandbox / anti-analyse

- `GetTickCount`, `QueryPerformanceCounter` : détection de ralentissement (timing checks, patchs de sandbox/debugger)
- `GetSystemMetrics` : résolution d'écran (les VMs ont souvent des résolutions atypiques)
- `IsProcessorFeaturePresent` : cohérence des features CPU (détection de CPU virtualisé)
- Chaînes anti-VM ciblant Xen, déjà identifiées en §4.2
- Détection explicite du process `avp.exe` (Kaspersky), voir §6.1 : le comportement du loader change concrètement selon qu'il est présent ou non

### 6.3 Ce qu'on n'a pas trouvé

Aucune URL de C2 ni domaine en clair après déchiffrement complet des 11 698 chaînes (seule occurrence : `microsoft.com`, probablement un leurre ou une référence légitime, par exemple dans un User-Agent ou une vérification de connectivité). C'est cohérent avec l'hypothèse que **ce binaire est uniquement le loader** : sa fonction est de décompresser et injecter le vrai payload StealC (récupéré ou embarqué ailleurs), qui contiendra lui-même la config C2. C'est une logique de séparation des responsabilités typique des crypters StealC, le loader ne porte jamais les IOCs réseau, pour limiter la détection.

### 6.4 Sur l'identité du crypter : Asgard Protector

La §4 qualifiait cet obfuscateur de "crypter commercial typique" sans plus de précision, puis une première recherche avait avancé l'hypothèse **CypherIT**, écartée depuis : le style d'identifiants publié pour CypherIT ne correspondait pas à celui observé ici.

Une piste plus solide est apparue en interrogeant MalwareBazaar sur les autres échantillons partageant le même imphash (`646167cce332c1c252cdcb1839e0cf48`, voir §10 et le runbook) : plusieurs sont tagués **`AsgardProtector`**. Ce tag correspond à un crypter documenté par SpyCloud Labs (source : [spycloud.com, "Asgard Protector - Malware Crypter Analysis"](https://spycloud.com/blog/asgard-protector-crypter-analysis/)), et la correspondance technique est nettement plus solide que l'hypothèse précédente :

| Élément décrit par SpyCloud | Observé dans cet échantillon |
|---|---|
| Script AutoIt utilisant "a basic state machine and string hiding" | Confirmé : control-flow flattening + `BATHROOMREWARDLIVED` (§5.1–5.3) |
| Décompilation via `autoit-ripper` | Même outil utilisé dans cette analyse |
| Décompression via `RtlDecompressFragment` et LZNT1 | Mêmes API observées (§6.1) |
| Injection dans `explorer.exe` pour évader la détection | Correspond à la cible du spoofing de PPID identifiée en §7.3 |
| Vérifications de processus incluant `SophosHealth`, `AvastUI`, `AVGUI` (via un script batch en amont) | Mêmes noms de processus retrouvés dans les checks `ProcessExists` (§7.3), à ceci près que nos vérifications sont faites directement en AutoIt, pas dans un `.bat` préalable |
| Service "AUTOcrypt" avec stub généré automatiquement via un bot Telegram | Non vérifiable statiquement sur cet échantillon seul, mais cohérent avec le modèle crypter-as-a-service déjà supposé |

Une différence notée honnêtement : SpyCloud décrit une détection de sandbox par ping vers des domaines qui ne devraient jamais répondre. Une recherche des API réseau habituelles (`Ping`, `DnsQuery`, `gethostbyname`, `getaddrinfo`) dans `deobfuscated.au3` ne remonte rien de tel : soit cette version/ce build n'inclut pas cette vérification précise, soit elle est absente de ce stage particulier. Le reste de la correspondance (RtlDecompressFragment/LZNT1, cible explorer.exe, mêmes AV, mêmes outils d'analyse utilisés par des chercheurs indépendants) est suffisamment spécifique pour considérer l'attribution à **Asgard Protector** comme solide, sans pour autant l'affirmer à 100% (on n'a pas de sample de référence identique bit à bit à comparer).

---

## 7. Persistance et évasion anti-AV

Cette partie creuse deux aspects laissés de côté jusqu'ici : le mécanisme de persistance exact, et l'inventaire complet des comportements conditionnés par la présence d'un antivirus. Toujours en analyse 100% statique.

### 7.1 Une couche d'obfuscation supplémentaire : `ChrW` calculé

En cherchant le contenu exact du mécanisme de persistance, une deuxième technique d'obfuscation de chaînes apparaît, différente de `BATHROOMREWARDLIVED` : certains caractères sont produits individuellement via `ChrW(<expression arithmétique>)`, avec la même astuce de grandes constantes réinterprétées comme négatives. Un script dédié, [`decode_chrw.py`](tools/decode_chrw.py), repère chaque appel `ChrW(...)` par appariement de parenthèses, évalue l'expression et substitue le caractère obtenu.

Sur `deobfuscated.au3`, seuls 16 appels de ce type existent dans tout le fichier, concentrés dans la routine qui écrit le script VBS de relance (voir §7.2).

### 7.2 Chaîne de persistance complète

En traçant les variables qui construisent les chemins et le contenu du VBS, la chaîne complète est la suivante :

| Élément | Valeur |
|---|---|
| Dossier de dépôt | `%LocalAppData%\CodeInnovate Technologies Co\` |
| Copie de l'interpréteur | `InnoCoder.exe` (ou `AutoIt3.exe`, voir §7.3) |
| Copie du script compilé | `q` (ou `q.a3x`, voir §7.3) |
| Script de relance | `InnoCoder.vbs` |
| Persistance | Raccourci `.lnk` dans `%StartupDir%`, nommé `InnoCoder.lnk`, pointant vers `InnoCoder.vbs` |

Le dépôt des copies (lignes 2255 et 2280 de `deobfuscated.au3`) se fait en lisant le fichier du script en cours d'exécution (`@ScriptFullPath`) et le véritable interpréteur (`@AutoItExe`), puis en les réécrivant tels quels aux emplacements ci-dessus, uniquement s'ils n'existent pas déjà à cet endroit.

Le contenu du fichier `InnoCoder.vbs`, une fois les `ChrW` décodés et les concaténations recomposées à la main :

```vbs
Set InnoCoder = CreateObject("Wscript."+"Shell")
InnoCoder.CurrentDirectory = "<LocalAppData>\CodeInnovate Technologies Co"
InnoCoder.Exec """InnoCoder.exe"" ""q"""
```

(le découpage `"Wscript."+"Shell"` et le triple jeu de guillemets dans `Exec` servent à éviter que la chaîne littérale `Wscript.Shell` ou le nom des fichiers déposés n'apparaissent tels quels dans le code source, sans changer le résultat : la ligne s'exécute comme un `CreateObject("Wscript.Shell")` classique suivi d'un lancement de la copie de l'interpréteur avec la copie du script en argument).

Le raccourci `InnoCoder.lnk` dans le dossier de démarrage Windows garantit que cette relance se produit à chaque connexion, sans dépendre de la clé de registre `Run` déjà identifiée en §4.2 (les deux mécanismes de persistance semblent donc coexister).

### 7.3 Inventaire complet des vérifications anti-AV

Une recherche de tous les appels `ProcessExists` dans le fichier déobfusqué (voir le runbook) remonte 4 comportements distincts déclenchés par la présence de logiciels de sécurité, en plus des vérifications anti-VM déjà connues :

| Processus détecté | Éditeur | Effet |
|---|---|---|
| `avp.exe` | Kaspersky | Change le flag de création de `CreateProcessW` (retire `EXTENDED_STARTUPINFO_PRESENT`, voir §6.1) |
| `AvastUI.exe`, `AVGUI.exe`, `bdagent.exe`, `SophosHealth.exe` | Avast, AVG, Bitdefender, Sophos | La copie de l'interpréteur est déposée sous le nom `AutoIt3.exe` au lieu de `InnoCoder.exe` |
| `AvastUI.exe`, `AVGUI.exe`, `SophosHealth.exe` | Avast, AVG, Sophos | La copie du script compilé est déposée sous le nom `q.a3x` au lieu de `q` |
| `bdagent.exe` | Bitdefender | Définit `$YEN_SHERIFF = "cscript"` au lieu de `"wscript"` (voir note ci-dessous) |
| `avastui.exe` | Avast | Déclenche une pause de 20 secondes vérifiée par timing (voir §7.4) |
| `bdagent.exe` | Bitdefender | Déclenche une pause de 160 secondes vérifiée par timing (voir §7.4) |

Note d'honnêteté : `$YEN_SHERIFF` n'est assigné qu'à ces deux lignes (confirmé à la fois dans `script.au3` et `deobfuscated.au3`) et n'apparaît nulle part ailleurs dans le fichier. Son usage réel (probablement pour choisir entre `wscript.exe` et `cscript.exe` afin d'exécuter `InnoCoder.vbs` sans fenêtre visible) n'a pas pu être confirmé statiquement. Ça reste une hypothèse raisonnable, pas une conclusion vérifiée, contrairement au reste de cette partie.

À part cet inventaire, deux vérifications supplémentaires, non liées à un AV précis, ont aussi été localisées :

- **Kill switch anti-VM/sandbox immédiat** : `If ProcessExists("vmtoolsd.exe") Or ProcessExists("VboxTray.exe") Or ProcessExists("SandboxieRpcSs.exe") Then Exit`. Détection explicite de VMware Tools, VirtualBox Guest Additions et Sandboxie, avec sortie immédiate du script si l'un des trois est présent. (La chaîne exacte présente dans l'échantillon est `VboxTray.exe` — `ProcessExists` étant insensible à la casse, cela cible bien le vrai process `VBoxTray.exe` de VirtualBox.)
- **Préparation d'un spoofing de PPID ciblant `explorer.exe`** : un handle est ouvert sur le process `explorer.exe` via `OpenProcess`, cohérent avec l'utilisation observée en §6.1 de `InitializeProcThreadAttributeList`/`UpdateProcThreadAttribute` pour faire apparaître le process injecté comme un enfant d'`explorer.exe` plutôt que du loader réel. Ce qui n'était qu'une hypothèse en §6.1 ("cohérent avec du spoofing de PPID") est maintenant rattaché à une cible concrète.

### 7.4 Détection de sandbox par altération du Sleep

La fonction `LOPEZFUNDING($ms)`, appelée dans plusieurs des branches ci-dessus, implémente une vérification classique de détection de sandbox :

1. Mesure le temps réel via `QueryPerformanceCounter`/`QueryPerformanceFrequency` avant l'appel.
2. Appelle `Sleep($ms)`.
3. Mesure à nouveau le temps réel après l'appel.
4. Si le temps réellement écoulé ne correspond pas (à une tolérance de -1 à +500 ms près) à la durée demandée, le script s'arrête (`Exit`).

C'est la technique standard pour détecter un `Sleep` intercepté ou accéléré par un environnement d'analyse automatisé, qui patche souvent cette fonction pour raccourcir artificiellement les délais. Les durées utilisées ici : **20 secondes** si Avast est détecté, **160 secondes** si Bitdefender est détecté.

Note technique sur le calcul de ces durées. Les arguments passés à `LOPEZFUNDING` sont eux aussi obfusqués avec la même astuce de grandes constantes. Pour la durée Bitdefender, l'argument est `794769 + 4294332527`. La règle de réinterprétation appliquée par `deobfuscate.py`/`validate_crossref.py` re-signe **chaque littéral individuellement** s'il tombe dans `[2^31, 2^32[` (ou `[2^63, 2^64[`) : `4294332527` est lui-même dans cette plage → `4294332527 - 2^32 = -634769`, d'où `794769 - 634769 = 160000` ms, soit 160 s. Le même résultat s'obtient en sommant d'abord puis en re-signant modulo 2^32 (`(794769 + 4294332527) mod 2^32 = 160000`) — c'est d'ailleurs la forme utilisée dans le snippet du runbook. **Piège à éviter** : appliquer le test de plage à la *somme* brute (`4295127296`) échouerait, car elle dépasse `2^32` et sort de l'intervalle ; il faut re-signer soit chaque littéral avant l'addition, soit la somme via un modulo 2^32. La première évaluation, faite en appliquant naïvement le test de plage à la somme, avait produit un résultat faux ; corrigé.

### 7.5 Gestion explicite des deux architectures (CONTEXT x86/x64)

En relisant le contexte de l'un des blocs `Switch` initialement classés "non résolus" par l'outil de validation (autour de la ligne 3595 de `script.au3`), il s'agit en fait d'un choix de structure `CONTEXT` Windows selon l'architecture cible :

```
Switch $RESPECTIVE_OPERATED_TRICK_CLIMB
Case 1
    $STRINGSFICTIONEVANSCLASSROOM = 65543      ' 0x10007 : CONTEXT_FULL (x86)
Case ( 82 + 4294967216 )                        ' réinterprété : 2
    $STRINGSFICTIONEVANSCLASSROOM = 1048583    ' 0x100007 : CONTEXT_FULL (x64)
EndSwitch
```

`0x10007` et `0x100007` sont les valeurs `CONTEXT_FULL` respectivement pour la structure `CONTEXT` x86 et x64 de Windows. Juste avant ce `Switch`, un `If`/`Else` construit la structure `$FORMULATEMPLELIVE` (utilisée ensuite dans `GetThreadContext`/`NtSetContextThread`, voir §6.1) à partir de trois chaînes déchiffrées dans la branche 64-bit, et de deux seulement dans la branche 32-bit. Le loader gère donc explicitement les deux architectures pour l'étape de détournement du contexte de thread, plutôt que de supposer une seule architecture cible.

(Sur le point d'outillage : ces 3 blocs étaient un artefact de la fenêtre de recherche du script de validation, trop courte de quelques lignes — voir §10, pas une vraie ambiguïté du malware.)

---

## 8. Confirmation externe et infrastructure de campagne

À ce stade, deux trous subsistent : le vrai payload StealC jamais observé, et le stage GCleaner en amont jamais examiné. Cette partie les ferme **sans exécuter le binaire nous-mêmes**, en exploitant des champs de l'API MalwareBazaar non lus jusqu'ici (`comment`, `file_information`, `vendor_intel`), puis en pivotant sur les indicateurs réseau via ThreatFox et des vérifications passives.

Précision de méthode : à partir d'ici, la confirmation du payload final et de sa config C2 repose sur l'exécution qu'un tiers (le sandbox **Triage**) a faite de cet échantillon, pas sur une exécution ou une émulation faite dans le cadre de cette analyse. Tout ce qui précède (§1 à §7) reste, lui, strictement statique.

### 8.1 Ce que l'API MalwareBazaar contenait déjà

Une simple requête `get_info` sur le hash, lue en entier cette fois (les analyses précédentes n'avaient extrait que quelques champs), contient :

- `"comment": "url: http://158.94.209.95/service"` : une URL de livraison notée par le reporter.
- `"file_information": [{"context": "dropped_by_malware", "value": "Gcleaner"}, ...]` : confirmation structurée du parent GCleaner, au-delà du simple tag communautaire déjà connu.
- `"vendor_intel"` → **Triage** a exécuté cet échantillon exact en sandbox et en a extrait une configuration StealC complète :

```
family: stealc
botnet: euromix
c2: http://160.20.109.75/d19ca32cb5a444ac8b87.php
lien du rapport : https://tria.ge/reports/260713-hewm3sey3t/
```

Signatures comportementales observées par Triage : `Deletes itself`, `Drops startup file`, `Executes dropped EXE`, `Suspicious use of SetThreadContext`. Elles recoupent précisément les mécanismes déjà tracés statiquement en §6 et §7 (`NtSetContextThread`, dépôt de persistance, relance via VBS), avec en plus l'auto-suppression du loader après dépôt de ses copies, un détail que l'analyse statique n'avait pas isolé explicitement.

Un rapport **CAPE Sandbox** existe également pour ce même hash (lien dans `file_information`), non consulté en détail ici, redondant avec Triage sur l'essentiel.

### 8.2 Vérification indépendante du C2 (ThreatFox)

Le C2 extrait par Triage a été recherché sur [ThreatFox](https://threatfox.abuse.ch/) (plateforme sœur de MalwareBazaar, dédiée aux indicateurs réseau), indépendamment de la sandbox qui l'a produit :

| Champ | Valeur |
|---|---|
| IOC | `http://160.20.109.75/d19ca32cb5a444ac8b87.php` |
| Famille | `win.stealc` |
| Confiance | 75% |
| Sightings | 431 |
| Première observation | 2026-07-07 23:55 UTC |
| Dernière observation | 2026-07-13 11:28 UTC |

431 observations et une dernière vue à quelques heures de cette analyse : ce n'est pas une infrastructure isolée ou éphémère, c'est un C2 actif et suivi depuis au moins une semaine.

### 8.3 Un deuxième échantillon de la même campagne

ThreatFox référence un autre hash MalwareBazaar associé au même C2 : `8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52`, vu le 07/07/2026 (6 jours avant notre échantillon). Comparaison :

| Champ | Notre échantillon | Second échantillon |
|---|---|---|
| SHA256 | `afbeeeaa...` | `8b7537c6...` |
| Architecture | I386 | AMD64 |
| Imphash | `646167cce332...` (Asgard Protector) | `e387f9bdbdc8...` (différent) |
| Commentaire de livraison | `http://158.94.209.95/service` | `http://158.94.209.95/service` (identique) |
| Tag parent | `dropped-by-GCleaner` | `dropped-by-GCleaner` |
| C2 (extrait par Triage) | `160.20.109.75/d19ca32cb5a444ac8b87.php` | `160.20.109.75/d19ca32cb5a444ac8b87.php` (identique) |
| Botnet ID | `euromix` | `eu1` |

Même URL de livraison, même parent GCleaner, même C2, deux builds différents (imphash et architecture distincts) à une semaine d'écart, avec des identifiants de botnet différents. Ça correspond à une même infrastructure de campagne opérant plusieurs builds ou sous-campagnes en parallèle, plutôt qu'à un incident isolé.

### 8.4 Le C2 est-il toujours actif ?

Vérifié sans se connecter au serveur (l'IP appartient à un opérateur malveillant ; s'y connecter directement exposerait l'adresse IP de la machine qui fait la requête, sans bénéfice réel). Deux vérifications passives à la place :

- **ThreatFox** : dernière observation à 11:28 UTC le jour même de cette analyse.
- **Shodan InternetDB** (scan passif déjà réalisé par Shodan, aucune requête de notre part vers le C2) : ports 22 (SSH, OpenSSH 9.6p1) et 80 (HTTP, nginx 1.24.0) ouverts sur cet IP, hébergé sur Ubuntu Linux, tag `eol-product`.

Le port 80 ouvert est cohérent avec un panel C2 HTTP actif. Ce n'est pas une confirmation à 100% que le endpoint précis (`/d19ca32cb5a444ac8b87.php`) répond encore, seulement que le serveur est en ligne et sert du HTTP, mais recoupé avec la dernière observation ThreatFox du jour même, c'est une bonne indication que l'infrastructure tourne toujours.

---

## 9. Conclusion générale

```
GCleaner (delivery: http://158.94.209.95/service)
  → Stub IExpress protégé par Asgard Protector (§4, §6.4)
    → AutoIt3.exe (interpréteur légitime) + Quotes.a3x (script compilé)
      → décompilé (autoit-ripper) → déobfusqué (script maison, §5)
        → anti-VM/sandbox immédiat (vmtoolsd.exe / VboxTray.exe / SandboxieRpcSs.exe)
        → détection Sleep patché (Avast 20 s, Bitdefender 160 s)
        → adaptation du comportement selon l'AV détecté (Kaspersky, Avast, AVG, Bitdefender, Sophos)
        → dépôt persistant dans %LocalAppData%\CodeInnovate Technologies Co\ + relance VBS/Startup
          → process hollowing (section mappée localement puis copiée, NtSetContextThread), gestion x86/x64
            → StealC réel, botnet "euromix"/"eu1"
              → C2 : 160.20.109.75/d19ca32cb5a444ac8b87.php (actif, 431 sightings)
```

Les deux trous identifiés à la fin de la §7 sont refermés : le payload final est identifié (StealC, config C2 extraite dynamiquement par un tiers), et le stage amont est confirmé (GCleaner, même URL de livraison retrouvée sur un second échantillon). Rien de tout ça n'a nécessité d'exécuter le binaire nous-mêmes : uniquement une lecture plus complète de champs d'API déjà accessibles, puis un pivot passif sur les indicateurs réseau qui en sont sortis.

Ce n'est pas seulement un loader qui injecte un payload : c'est un loader qui adapte activement son comportement (noms de fichiers, flags de création, délais d'exécution) à l'antivirus spécifique détecté sur la machine, avant même de tenter l'injection.

## 10. Limites et honnêteté méthodologique

- **Validation croisée des `Switch`.** Sur 354 blocs, 351 sont résolus indépendamment par les deux méthodes croisées (arithmétique vs présence d'`ExitLoop`/`Return`) avec un accord de 100%. Les 3 blocs restants n'ont qu'un seul des deux signaux disponibles (petites tables de correspondance sans `ExitLoop`, un cas de figure attendu, pas une anomalie), et ont été relus et confirmés à la main un par un ; l'un d'eux est détaillé en §7.5. `deobfuscate.py` résout finalement les 354 blocs sans laisser aucune branche ambiguë dans `deobfuscated.au3`. Une version antérieure indiquait par erreur 2 blocs non résolus : c'était une limite de la fenêtre de recherche du script de validation (5 lignes en arrière, alors que l'assignation réelle se trouvait parfois ~6 lignes plus haut, à cheval sur un `If`/`Else`) ; fenêtre élargie à 60 lignes dans `deobfuscate.py` et `validate_crossref.py`, corrigé.
- **Payload final non observé.** L'analyse reste 100% statique jusqu'à la §8 : le payload réellement injecté (post-hollowing) n'est jamais présent en clair dans ce binaire (cohérent avec le design du loader). Le déroulement de la création de process, la structure `PROCESS_INFORMATION` et la chaîne `NtOpenSection`/`NtMapViewOfSection`/`NtWriteVirtualMemory` sont en revanche tracés statiquement de bout en bout (§6.1), pas juste déduits de l'ordre d'apparition des appels.
- **Attribution du crypter.** L'identification comme **Asgard Protector** repose sur une correspondance technique solide avec une source publique indépendante (§6.4), pas sur une comparaison bit à bit avec un échantillon de référence identique. La détection anti-sandbox par ping DNS décrite par cette source n'a pas été retrouvée dans notre échantillon.
- **Confirmation finale via un tiers.** Le payload et sa config C2 sont confirmés par l'exécution qu'un tiers (Triage) a faite du sample, recoupée par ThreatFox et un scan passif Shodan — jamais par une exécution ou une connexion réalisée par l'auteur.

## 11. IOCs consolidés

| Type | Valeur |
|---|---|
| SHA256 (stub SFX) | `afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da` |
| MD5 (stub SFX) | `dc8db3908bec45fc19bfb4d2c4514474` |
| Imphash (crypter Asgard Protector) | `646167cce332c1c252cdcb1839e0cf48` |
| SHA256 (AutoIt3.exe légitime abusé) | `92c6531a09180fae8b2aae7384b4cea9986762f0c271b35da09b4d0e733f9f45` |
| SHA256 (Quotes.a3x, script malveillant) | `49ded704632abe3642b76c32c60d46ab99402495624921787e0c57a85f83327d` |
| Second échantillon lié (AMD64) | `8b7537c6624998423c0dc5e63d133a4380df59ff64a623f35f2f669e63061c52` |
| URL de livraison (GCleaner) | `http://158.94.209.95/service` |
| C2 StealC | `http://160.20.109.75/d19ca32cb5a444ac8b87.php` |
| Botnet ID | `euromix`, `eu1` |
| Clé de registre persistance | `Software\Microsoft\Windows\CurrentVersion\RunOnce` |
| Dossier de dépôt | `%LocalAppData%\CodeInnovate Technologies Co\` |
| Artefacts déposés | `InnoCoder.exe` / `AutoIt3.exe`, `q` / `q.a3x`, `InnoCoder.vbs`, `InnoCoder.lnk` |
| Chaînes anti-VM | `XeN:`, `XeNa`, `xeNe` (détection Xen) |
| Process kill-switch VM/sandbox | `vmtoolsd.exe`, `VboxTray.exe`, `SandboxieRpcSs.exe` |
| Timestamp PE falsifié | `2040-03-15` (réel probable : proche du 12-13/07/2026) |

## 12. Reproduire l'analyse

Le log détaillé (commande / pourquoi / sortie brute / ce qu'on en retient) de chacune des quatre parties est dans [`runbook.md`](runbook.md), qui couvre :

- [Partie 1 — extraction du stub IExpress et du loader AutoIt](runbook.md#partie-1--extraction-du-stub-iexpress-et-du-loader-autoit) (§1–4 ci-dessus)
- [Partie 2 — déobfuscation](runbook.md#partie-2--déobfuscation-du-loader-autoit-quotesa3x) (§5–6), dont la [validation croisée des `Switch`](runbook.md#validation-croisée-de-la-résolution-des-switch) et l'[identification du crypter par imphash](runbook.md#identification-du-crypter-par-recherche-dimphash)
- [Partie 3 — persistance et évasion anti-AV](runbook.md#partie-3--persistance-et-évasion-anti-av-du-loader-autoit) (§7)
- [Partie 4 — confirmation externe](runbook.md#partie-4--confirmation-externe-et-infrastructure-de-campagne) (§8)

Prérequis et séquence complète pour rejouer de zéro : voir [reproductibilité de bout en bout](runbook.md#reproductibilité-de-bout-en-bout).
