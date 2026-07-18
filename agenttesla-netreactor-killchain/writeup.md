# Analyse AgentTesla : d'un leurre naval à un exfil FTP, à travers un control-flow flattening réel de 1 891 cases

**Analyste :** Gordon PEIRS
**Date d'analyse :** 15-16/07/2026
**Type :** Analyse statique jusqu'en §10 (aucune exécution du binaire par l'auteur) — voir la note de méthode en §10 pour la seule étape reposant sur l'exécution d'un tiers.
**Famille :** AgentTesla (infostealer/keylogger, MaaS)

> Ce document regroupe l'intégralité du récit analytique (constats, hypothèses, conclusions) des quatre volets de l'enquête. La **preuve de travail reproductible** (commande / pourquoi / sortie brute) vit séparément dans [`runbook.md`](runbook.md), organisé selon les mêmes quatre parties. Les outils autonomes sont dans [`tools/`](tools/).

---

## 1. Contexte et choix de l'échantillon

Suite directe de l'enquête StealC (voir [`../stealc-autoit-killchain/`](../stealc-autoit-killchain/)) : après une première famille en AutoIt/natif, palier suivant volontairement choisi sur un vecteur différent — un loader **.NET** — pour élargir la boîte à outils (décompilation .NET, protecteurs commerciaux .NET) plutôt que refaire un cas similaire.

Échantillon récupéré via [MalwareBazaar](https://bazaar.abuse.ch/), recherche ciblée sur des samples `.NET`/CIL récents taggés `AgentTesla`, filtré sur les fichiers `.exe` réellement compilés en CIL (par opposition aux scripts `.js`/`.vbs` de première étape qui dominent le flux du jour). Une première piste — chercher directement le tag `ConfuserEX` — a été abandonnée (seulement 3 résultats au total sur MalwareBazaar pour ce tag, le plus récent datant de 2025-07-29, pas assez représentatif) au profit d'une recherche plus large par signature `AgentTesla` puis filtrage côté client sur les vrais binaires `.NET/MSIL/CIL`.

## 2. Identité de l'échantillon (stage 1)

| Champ | Valeur |
|---|---|
| SHA256 | `bc6d86cef1b7404823c1d830387b2c9b1289c453620482fc1749dd5d2ade3897` |
| Nom de fichier | `CTM.exe` |
| Taille | 1 320 960 octets |
| Type | PE32, .NET/CIL (Mono/.NET), 3 sections |
| Première observation (MalwareBazaar) | 2026-07-14 08:53:50 |
| Tag communautaire | `AgentTesla` |
| Reporter | `threatcat_ch` |

Tag communautaire pris comme point de départ uniquement, pas comme confirmation — même réserve méthodologique que pour StealC. Levée en §10.

## 3. Outillage

- `pefile`, pour le parsing PE et l'extraction de ressources natives
- [`capa`](https://github.com/mandiant/capa) 9.4.0 + règles officielles, pour la détection de capacités
- [`ilspycmd`](https://github.com/icsharpcode/ILSpy) 10.1.1 (`dotnet tool install -g ilspycmd`), décompilateur .NET en ligne de commande, cross-platform
- `.NET SDK` 10.0 (`pacman -S dotnet-sdk`), nécessaire pour `ilspycmd` et les outils construits ensuite
- `pycryptodome`, pour le déchiffrement AES scripté

Tout le travail a été réalisé en local, sans exécution du binaire. Contrairement à StealC (Windows natif, inexécutable sur Linux sans Wine), un binaire .NET pourrait théoriquement tourner via `dotnet`/Wine — discipline maintenue : jamais d'exécution, `chmod -x` systématique dès téléchargement.

---

## 4. Stage 1 — analyse statique du leurre et chaîne de chargement AES

### 4.1 Capa

12 capacités matchées, les plus significatives :

- `compiled to the .NET platform`
- `access .NET resource`
- `decrypt data using AES via .NET`
- `invoke .NET assembly method`
- `reference anti-VM strings targeting Xen`
- `reference analysis tools strings`

**Hypothèse initiale posée avant lecture du code** : loader .NET qui déchiffre une ressource embarquée en AES puis charge un second assembly par réflexion. Confirmée dans la suite de cette section.

### 4.2 Décompilation (ilspycmd)

```
ilspycmd -o decompiled/ <sha256>.exe
```

→ 16 811 lignes de C# décompilé, 64 classes. Noms d'identifiants aléatoires (`0fdPNa5xi7Z`, `2Cnrxq`, `aKg4d0BnFz3`...) : obfuscation d'identifiants systématique.

**Prudence méthodologique** : ce style (chaînes alphanumériques courtes et aléatoires) est superficiellement cohérent avec ConfuserEx, et d'autres échantillons AgentTesla sur MalwareBazaar portent effectivement le tag communautaire `ConfuserEX`. Mais ce rapprochement n'a **jamais été vérifié directement sur ce sample précis** — il reste une hypothèse par analogie, pas une preuve. Le vrai protecteur du stage 2 sera identifié avec certitude en §5, et ce sera un tout autre produit (Eziriz .NET Reactor). Le protecteur du stage 1 lui-même n'a en réalité jamais été confirmé formellement — voir §12.

### 4.3 Point d'entrée

```csharp
[STAThread]
public static void 4Rzepd2M9()
{
    DateTime dateTime = DateAndTime.DateSerial(25, 6, 2026);
    ...
    if (!Xf8i0tdBN4k())
```

Le point d'entrée réel n'a pas de nom significatif (renommé comme le reste) — repéré via l'attribut `[STAThread]`, seul indice fiable indépendant du renommage.

**Vérifié** : `Xf8i0tdBN4k()` → `return true;` inconditionnellement. Porte factice ou vestige d'un check retiré par le protecteur, pas un vrai kill switch. La variable `dateTime` (25/06/2026, cohérente avec une semaine avant le `first_seen` MalwareBazaar) est construite mais son usage ultérieur n'a pas été tracé plus loin — laissé en l'état plutôt que sur-interprété.

### 4.4 Le leurre visible : une fausse application métier complète

En cherchant le contexte du point d'entrée, l'application affiche (via des handlers d'événements `MessageBox`) :

- *"Stiffener optimization algorithm executed. Profiles selected to minimize weight while satisfying CSR rules."*
- *"Profile filter dialog would open here to filter by type, weight, or dimensions."*
- *"Custom profile import wizard would open here to read from CSV or XML."*
- *"Plate report exported to CSV."* / *"Stiffener report exported to CSV."*

Et dessine dynamiquement sur un `Bitmap` des labels techniques : **"STRENGTH DECK"**, **"INNER BOTTOM"**, **"HOPPER TANK"**, **"BOTTOM PLATE"** — vocabulaire de structure navale. `CSR` (Common Structural Rules) est un référentiel réel de classification maritime, pas un terme inventé.

**Conclusion** : `CTM.exe` n'est pas un leurre minimal — c'est une fausse application complète et cohérente de dimensionnement de structures de navire (calcul de raidisseurs, filtrage de profils, export de rapports), avec une interface fonctionnelle en apparence. Cohérent avec un ciblage sectoriel maritime/shipping, probablement livré par phishing ciblé (le vecteur de livraison lui-même n'a pas été confirmé indépendamment — voir §12).

### 4.5 Chaîne de chargement vers le stage 2

Traçage de la logique de chargement en mémoire :

1. Une ressource manifest .NET, `Genitalk.klaoxao.tiff` (459 024 octets), est extraite via `Assembly.GetExecutingAssembly().GetManifestResourceStream(...)`.
2. Les octets sont **inversés** (`Array.Reverse`) — évasion simple de scanners de signature statique.
3. Déchiffrement **AES-128-CBC**, avec une clé codée en dur **réutilisée comme IV** (`e4a931cb6e204322da0d1a30d946633b`) — faille d'implémentation du malware, pas de notre méthode.
4. Chargement du résultat par réflexion : `Assembly.Load(byte[])` n'est jamais appelé littéralement — le code recherche par réflexion une `MethodInfo` ayant la forme de cet appel puis l'invoque (`methodInfo.Invoke(null, new object[] { bytes })`), pour éviter la présence littérale de la chaîne `"Assembly.Load"` dans le binaire.
5. Une fois l'assembly chargé en mémoire, un helper générique (`types[25]` de l'assembly, indexation numérique plutôt que par nom) cherche une méthode statique sans paramètre et l'invoque — c'est le point d'entrée du stage 2.

**Résultat vérifié** (script [`tools/decrypt_stage2_resource.py`](tools/decrypt_stage2_resource.py)) : le déchiffrement produit un **PE32 .NET DLL valide** (magic `MZ` confirmé), 459 024 octets — même taille que la ressource source, cohérent avec un AES sans padding supplémentaire visible.

```
SHA256 (stage 2) : 39fdba7a439cb09842f26d34f84606e3cc7f685b407deceb49ee7cb71271ebcd
```

**Vérification MalwareBazaar** : `get_info` sur ce hash → `hash_not_found`. Ce stage 2 n'était pas indexé publiquement au moment de l'analyse — aucun rapport tiers à croiser dessus à ce stade (contrairement à StealC où la confirmation externe existait dès le départ). L'enquête continue seule sur ce terrain jusqu'à la confirmation externe (§10).

---

## 5. Stage 2 — identification du protecteur (Eziriz .NET Reactor)

Le stage 2 (DLL .NET extrait et déchiffré en §4.5) est un binaire d'environ 459 Ko, décompilé en 18 571 lignes de C# via `ilspycmd`. `capa` y détecte 14 capacités, notamment `check for debugger via API`, `manipulate unmanaged memory in .NET`, `unmanaged call` — signaux d'une couche d'évasion et de manipulation mémoire native plus poussée que le stage 1.

### 5.1 Correction d'hypothèse : ce n'est pas ConfuserEx

Le stage 1 (§4.2) laissait planer une hypothèse non vérifiée de type ConfuserEx, par analogie avec d'autres échantillons AgentTesla tagués ainsi sur MalwareBazaar. Le stage 2 tranche cette question, mais dans une direction différente : une chaîne trouvée en clair dans le code décompilé identifie le protecteur avec certitude, sans ambiguïté possible :

```
"This assembly is protected by an unregistered version of Eziriz's ".NET Reactor"! This assembly won't further work."
```

C'est le message de licence trial d'**Eziriz .NET Reactor**, un protecteur commercial .NET différent de ConfuserEx. Cette chaîne apparaît dans un `case` du dispatcher principal (voir §6), déclenché quand l'assembly détecte tourner sans licence valide.

**Point méthodologique** : le style d'obfuscation observé au stage 1 (identifiants aléatoires courts) et celui du stage 2 (identifiants en mots-anglais plausibles — `AdjustableSchema`, `SchemaDecryptor`, `LocatorDecryptor`...) sont visuellement différents. Il n'a pas été établi si le stage 1 utilise le même protecteur avec une configuration de renommage différente, ou un protecteur distinct — question laissée ouverte, non nécessaire pour la suite.

Cette identification sera confirmée de façon totalement indépendante en §10 (tag `netreactor` d'ANY.RUN, obtenu par classification automatique tierce, sans lien avec cette lecture de code).

---

## 6. Control-flow flattening réel — ampleur et outils construits

### 6.1 Un vrai flattening, pas un motif « 1 branche réelle + leurres »

Contrairement au script AutoIt de StealC (`Switch` où une seule branche est réellement exécutée par bloc, le reste étant du code mort), le stage 2 utilise un **control-flow flattening classique et complet** : chaque `case` d'un dispatcher `switch(état)` est du code réel, chaîné au suivant via des réaffectations de la variable d'état — y compris de vrais branchements conditionnels (un `if`/`else` dans un `case` peut envoyer vers deux états suivants différents).

Échelle mesurée :

| | AsgardProtector (StealC, AutoIt) | .NET Reactor (AgentTesla, stage 2) |
|---|---|---|
| Blocs `Switch`/dispatcher | 354 | **79** (dont 24 avec ≥5 cases, les vrais dispatchers) |
| Cases au total | ~354 (1 par bloc) | **1 891** |
| Plus gros bloc | — | **747 cases, 4 621 lignes** — à lui seul plus gros que la totalité des 354 blocs AsgardProtector cumulés |

### 6.2 Outils construits

Le problème n'est plus "quelle est la seule branche réelle" (résolu par arithmétique chez StealC) mais "comment reconstruire un vrai graphe de flot de contrôle avec branchements". Deux scripts, dans cet ordre :

- [`deflatten_cs.py`](tools/deflatten_cs.py) — parse chaque `switch(var) { case N: ... }`, extrait pour chaque `case` son (ou ses) état(s) suivant(s) (`default_edge` inconditionnel, `branch_edges` conditionnels), et le classe : linéaire (1 seul successeur), branchant (plusieurs), terminal (sort du dispatcher), ou donnée-dépendant (le prochain état dépend d'une lecture runtime, non résolvable statiquement).
- [`linearize_cs.py`](tools/linearize_cs.py) — parcourt le graphe extrait depuis un point d'entrée détecté (recherche arrière du littéral qui initialise la variable d'état), et émet les blocs en ordre de visite (DFS itératif, pas récursif — certaines chaînes dépassent la limite de récursion Python), avec les arêtes explicitées en commentaire plutôt que noyées dans un `switch` unique.

Les deux scripts sont volontairement génériques (n'importe quel `switch(var)` du fichier, pas seulement le plus gros) — mêmes outils réutilisés en §8 pour explorer plusieurs points d'entrée.

### 6.3 Deux bugs trouvés par vérification manuelle, corrigés (même discipline que StealC)

**Bug 1 — `goto case`/`goto label` non détectés.** La première version de `deflatten_cs.py` ne cherchait que les réaffectations littérales `var = N;`. En vérifiant à la main le plus petit bloc du fichier (6 cases, celui qui contient justement le message ".NET Reactor" cité en §5.1), plusieurs `goto case 0;` et `goto end_IL_0014;` sont visibles dans le code source mais totalement absents de l'analyse — des branches réelles classées à tort comme "terminales". Corrigé en ajoutant la détection de `goto case N` (traité comme une arête `CASE`) et `goto Label` (traité comme une arête de sortie `EXIT`).

Vérification après correction sur ce même bloc de 6 cases — comparaison ligne à ligne avec la source :
```
case [None] (default): default=('EXIT','return') branch=[('EXIT','goto end_IL_0014'), ('CASE', 0)]
case [3]: default=('CASE', 10) branch=[('CASE', 1)]
case [0]: default=('EXIT','throw') branch=[] TERMINAL
```
Correspond exactement au code source relu à la main.

**Bug 2 — chaîne de copie interrompue par un préfixe de type.** Le détecteur de point d'entrée (`find_entry_value`) suit une chaîne de copies en arrière (`num3 = num2; num2 = num;`) jusqu'à trouver le littéral initial. Une **déclaration** (`int num2 = num;`) a un préfixe de type que la regex de la première version ne gérait pas — seule une réaffectation nue (`num2 = num;`) était reconnue. Sur le plus gros dispatcher, le vrai littéral (`int num = 299;`) se trouve à **114 lignes** du `switch`, très au-delà de la fenêtre de recherche initiale (60 lignes, reprise par réflexe de l'expérience StealC — insuffisante ici). Résultat avant correction : couverture proche de 0 sur la quasi-totalité des 24 dispatchers.

Corrigé en bornant la recherche non plus par un nombre de lignes fixe mais par la **signature de la méthode englobante** (recherche arrière jusqu'à la ligne de déclaration de méthode la plus proche), et en acceptant le préfixe de type dans la regex de copie.

### 6.4 Résultat après correction

Couverture (`linearize_cs.py`) sur les 3 plus gros dispatchers, seule entrée `299` (point d'entrée "évident", trouvé en premier) :

| Switch (ligne source) | Cases | États atteints depuis l'entrée 299 |
|---|---|---|
| 6660 | 377 | 301/379 (79%) |
| **8965** (suspecté : logique d'injection) | 649 | **415/673 (62%)** |
| 15073 | 388 | 302/397 (76%) |

> **Note de cohérence relevée à la fusion de ce document** : le décompte brut de l'exécution de `deflatten_cs.py` (voir [`runbook.md`](runbook.md#partie-2--identification-du-protecteur-et-control-flow-flattening)) attribue **747 cases** au bloc de la ligne 8965 (« le plus gros bloc (ligne 8965) fait 747 cases sur 4 621 lignes »), alors que le tableau ci-dessus et toute l'analyse qui suit (§7, §8 — coverage 415/673 puis 653/673, séquence d'injection décrite comme « le dispatcher à 649 cases ») utilisent de façon cohérente **649 cases** pour ce même bloc. Le nombre d'états atteignables (673) est également plus proche de 649 que de 747. Faute d'accès au décompilé source pour trancher, ce document retient 649 (valeur utilisée par toute l'analyse en aval) ; il est possible que 747/4621-lignes corresponde en réalité à un bloc distinct, non exploré en détail, plutôt qu'à celui de la ligne 8965. Incohérence à vérifier si l'échantillon est ré-analysé.

Les dispatchers plus petits (5-45 cases, méthodes utilitaires) ont une bien moins bonne couverture — probablement parce que leur variable d'état est initialisée depuis un **paramètre de méthode**, pas un littéral local suivable par cette heuristique. Limite connue, non résolue avant §8.

---

## 7. Séquence d'injection tracée, et une fausse piste corrigée

### 7.1 La séquence, avec arguments réels

En remontant les trampolines qui appellent les wrappers d'API Windows résolues dynamiquement (`LoadLibrary`+`GetProcAddress` avec noms d'API découpés en morceaux — ex. `"Write ".Trim() + "Process ".Trim() + "Memory"` — pour éviter leur présence littérale), la séquence apparaît avec ses arguments réels dans le flux reconstruit du dispatcher à 649 cases :

| Étape | Appel réel retrouvé | Signification |
|---|---|---|
| Recherche ressource | `ExecuteSharer(..., "__", 10u)` | `FindResourceA(module, "__", RT_RCDATA)` |
| Ouverture process | `DestroyDetailedRole(56u, 1, pid)` | `OpenProcess(0x38, TRUE, pid)` — `0x38` = `PROCESS_VM_OPERATION\|PROCESS_VM_WRITE\|PROCESS_VM_READ`, droits minimaux d'injection |
| Allocation | `InstantiateSegmentedStrategy(IntPtr.Zero, taille, 4096u, 64u)` | `VirtualAlloc(NULL, taille, MEM_COMMIT, PAGE_EXECUTE_READWRITE)` — allocation **locale** |
| Écriture | `StructAdvancedQueue(intPtr7, intPtr6, buffer, 4u, out param)` | `WriteProcessMemory(hProcess, addr, buffer, 4, ...)` |
| Protection | `ValidateDetachedFunction(...)` (~8 occurrences, flags alternés) | `VirtualProtect` — cycle RW/RX cohérent avec un patch mémoire |
| Nettoyage | `InstantiateTransformableFinalizer(intPtr7)` | `CloseHandle(intPtr7)` |

**Réserve explicite** : cet ordre reflète l'ordre de *visite* du graphe par le parcours DFS, pas nécessairement l'ordre d'*exécution* réel sur un run donné (le graphe a de vrais branchements). Voir aussi §12 sur ce point.

### 7.2 Une fausse piste trouvée — et corrigée avant d'être présentée comme un résultat

La source du `pid` a été tracée jusqu'au bout :

```csharp
internal static object StoreConfiguration() { return Process.GetCurrentProcess(); }
internal static object ManageConsumer(object P_0) { return ((Process)P_0).MainModule; }
internal static IntPtr DestroyConcreteObserver(object P_0) { return ((ProcessModule)P_0).BaseAddress; }
```

Le `pid` passé à `OpenProcess` est celui du **process courant lui-même**, et la ressource `"__"` est cherchée dans le module de base du process courant — ce qui, dans un premier temps, a été lu comme de l'**auto-injection** (le stage 2 s'injecte dans son propre process).

**Correction, avant publication** : la fonction qui consomme le résultat de `FindResourceA` (`DestroySegmentedProxy(P_0, P_1)`) n'est qu'un test d'inégalité `P_0 != P_1`. Le code réel est :

```csharp
if (FindResourceA(moduleBase, "__", RT_RCDATA) == IntPtr.Zero)  // ressource absente
{
    num = 28;  // nouvel etat de la boucle EXTERNE
    break;
}
// sinon seulement : suite de la sequence d'auto-injection ci-dessus
```

Vérifié avec `pefile` sur les deux binaires (stage 1, qui est le vrai `MainModule` du process puisque le stage 2 est chargé en mémoire sans fichier propre sur disque ; et stage 2 lui-même) : **aucune ressource native `RT_RCDATA` nommée `"__"` n'existe dans l'un ou l'autre**. Seules des ressources `RT_ICON`/`RT_GROUP_ICON`/`RT_VERSION` standard sont présentes.

**Conclusion** : la séquence d'auto-injection ci-dessus est du code réel du template du crypter (probablement activée sur d'autres builds/configurations), mais **elle n'est jamais empruntée sur cet échantillon précis**. Le vrai chemin d'exécution part vers l'état **28** de la boucle externe — poursuivi en §8.

---

## 8. Le vrai chemin d'exécution et couverture quasi-complète (97%)

### 8.1 L'état 28 mène à une ressource qui existe réellement

`num = 28; break;` (le repli quand `FindResourceA("__")` échoue) réinjecte `num3 = 28` au tour suivant de la boucle externe — **c'est le même dispatcher qu'en §6-7**, pas une machine à états séparée : réentrer dans la triple boucle `while(true){ int num2 = num; while(true){ int num3 = num2; while(true){ switch(num3)...` réamorce simplement `num3` avec la nouvelle valeur de `num`.

Un parcours depuis l'entrée 28 (plutôt que 299) couvre **417/673 états**, davantage que la fausse piste précédente. Point clé, à l'état 30 :

```csharp
schemaMember = new SchemaMember((Stream)CompareAdvancedWatcher(schemaEncryptor, "ObjectRequester.ScopeObject"));
```

`"ObjectRequester.ScopeObject"` est l'une des 4 vraies ressources .NET managées du stage 2 (confirmées présentes via `ilspycmd --list-resources` : `ObjectRequester.ScopeObject`, `ScheduledObject.ObjectParser`, `DecryptorCompressor.ControllableObject`, `AuditorMap.LocalObject`) — contrairement à la ressource native `"__"` du §7, absente des deux binaires. C'est le vrai point d'accès au payload.

Tracé également :
- `schemaEncryptor` = `Type.GetTypeFromHandle(...).Assembly` — l'assembly courant (stage 2 lui-même), obtenu par un détour pour éviter l'appel littéral `Assembly.GetExecutingAssembly()`.
- La classe `SchemaMember` n'est qu'un `BinaryReader` (`ReadBytes`/`Read`/`ReadInt32`/`Close`) — aucun déchiffrement dedans, juste la lecture séquentielle brute du flux.
- Les 4 ressources extraites (92 Ko, 132 Ko, 4 Ko, 256 octets) sont toutes à haute entropie, sans en-tête reconnaissable — chiffrées.

### 8.2 Couverture quasi-complète par cascade de points d'entrée

Constat : chaque `case` marqué "terminal" qui réaffecte la variable **externe** `num` (et non `num3`) correspond en réalité à un nouveau point d'entrée dans ce même dispatcher — pas une machine à états séparée à modéliser.

Script de point fixe : explore depuis `{299, 28}`, collecte chaque nouvelle valeur de `num` trouvée dans un nœud terminal, l'ajoute comme point d'entrée à explorer, répète jusqu'à stabilisation.

**Résultat : 653/673 états couverts (97%)**, contre 415/673 avec la seule entrée 299 (§6.4). 79 points d'entrée distincts découverts au total en cascade. 20 états seulement restent inatteignables depuis un point d'entrée connu.

Cette technique n'a pas nécessité de nouvel outil — c'est un usage différent de `linearize_cs.py`/`deflatten_cs.py` déjà construits, appliqué en boucle plutôt qu'une seule fois.

### 8.3 Ce qui bloque le déchiffrement final : un format dispersé, pas une boucle isolable

Les points de lecture de `schemaMember` (via `InstantiatePassiveDecider(schemaMember)` = `BinaryReader.ReadInt32()`) sont dispersés sur **18-20 états** du graphe, certains lisant et **jetant le résultat sans l'assigner** — cohérent avec un format d'enregistrement custom où certains champs sont simplement sautés (skip de position dans le flux), pas une boucle de déchiffrement simple à isoler et rejouer.

---

## 9. Deux tentatives d'automatisation du déchiffrement final

### 9.1 Vérification publique avant d'investir davantage d'heures à la main

Avant de continuer à la main, vérification publique (`WebSearch`) du fonctionnement interne de .NET Reactor : confirmé, **.NET Reactor stocke son bytecode de VM et ses métadonnées de protection directement dans des ressources d'assembly** ([source](https://deepwiki.com/void-stack/VMAttack/5.1-eziriz-.net-reactor-analysis)). Le pattern `SchemaMember`/`BinaryReader`/ressources nommées tracé plus haut est donc très probablement le **mécanisme générique de .NET Reactor lui-même**, pas un mécanisme de livraison de payload spécifique à ce malware — continuer à la main aurait revalidé le fonctionnement d'un produit commercial déjà documenté publiquement, sans avancer sur le malware en tant que tel.

### 9.2 Première tentative : NETReactorSlayer (binaire officiel)

Un outil dédié à ce protecteur existe : [**NETReactorSlayer**](https://github.com/SychicBoy/NETReactorSlayer) (GPLv3, supporte .NET Reactor 6.0-6.9), avec un build natif Linux x64 — pas besoin de Wine. Utilisé en lecture/transformation statique uniquement, jamais d'exécution du binaire cible.

**Résultat, `NETReactorSlayer.CLI stage2.dll`** :
```
751 Methods decrypted.
999 Equations resolved.
Anti tamper removed.
Anti debugger removed.
[ERROR] An unexpected error occurred during decrypting resources. Object reference not set to an instance of an object.
185 Calls to obfuscator types removed.
567 Methods inlined.
```

Progrès réel et global (méthodes déchiffrées, anti-tamper/anti-debug retirés, nettoyage), **mais** :
- Le déchiffrement des ressources échoue (exception dans l'outil) — `ObjectRequester.ScopeObject` reste chiffrée.
- La méthode d'injection elle-même reste flattened après nettoyage : toujours 26 `while(true)` et plusieurs `switch` imbriqués dans son décompilé. Le fichier nettoyé est même **plus long** que l'original (25 353 lignes contre 18 571) — l'inlining de 567 méthodes a dilué le compte de lignes plutôt que de le réduire.

### 9.3 Deuxième tentative : compilation depuis la source, avec un correctif jamais publié

Recherche du bug précis (`WebSearch`) dans l'historique Git du dépôt officiel : un commit **"Improve resource decrypter. Resolve #54"**, daté du **15/12/2022** — soit **3 jours après** la publication de la release v6.4.0.0 utilisée à l'étape précédente. Ce correctif n'a jamais été inclus dans un binaire publié (aucune release depuis).

Compilé depuis la source (`git clone` + `dotnet build -f net6.0`, exécuté avec `DOTNET_ROLL_FORWARD=LatestMajor` pour tourner sur le runtime .NET 10 installé, faute de runtime 6.0 disponible). **Même erreur exacte malgré le correctif.**

**Diagnostic par lecture directe du code source** (`NETReactorSlayer.Core/Stages/ResourceResolver.cs`) : ce stage cible spécifiquement le pattern ".NET Reactor assembly-en-ressource chargé via un handler `AppDomain.AssemblyResolve`" — il recherche une méthode de signature `(object, ResolveEventArgs)` ou `(object, object)`. Le mécanisme de ce sample (`SchemaMember` lisant directement `GetManifestResourceStream` depuis le code flattened, sans jamais passer par `AssemblyResolve`) est un **mécanisme différent** de .NET Reactor. Le `Find()` de l'outil matche partiellement (assez pour se déclencher) puis échoue — pas un bug ponctuel à corriger, un outil qui cible une fonctionnalité différente de celle réellement utilisée ici.

### 9.4 Bilan des deux tentatives

**Acquis, vérifiés** :
- Vrai chemin d'exécution identifié (entrée 28, pas 299), menant à une ressource .NET réellement présente
- 97% du graphe de la fonction d'injection couvert et vérifié (653/673 états)
- Deux tentatives d'automatisation du déchiffrement final documentées, avec diagnostic précis de leurs limites respectives — l'une par excès de dispersion du format (outil maison), l'autre par mécanisme ciblé différent du bon (outil spécialisé)

**Ouvert à ce stade** : le contenu déchiffré de `ObjectRequester.ScopeObject` (92 Ko), probable payload final. Fermé autrement en §10.

---

## 10. Confirmation externe et infrastructure de campagne

La question ouverte à ce stade : le contenu réel du payload final (`ObjectRequester.ScopeObject`, 92 Ko chiffrés), après deux tentatives d'automatisation infructueuses sur le déchiffrement complet (§9). Plutôt que de s'acharner davantage sur une voie technique bloquée, cette section ferme la question par recoupement OSINT — même logique méthodologique que StealC Partie 4 : privilégier la preuve la plus fiable disponible.

**Précision de méthode**, comme pour StealC : à partir d'ici, la confirmation s'appuie sur l'exécution qu'un tiers (les sandboxes ANY.RUN, Triage, VMRay) a faite de cet échantillon exact, pas sur une exécution réalisée dans le cadre de cette analyse. Les sections précédentes (§1 à §9) restent strictement statiques.

### 10.1 Ce que l'API MalwareBazaar contenait déjà

Une lecture complète de `get_info` (champ `vendor_intel`, pas seulement hash/tags comme aux étapes précédentes) sur le hash exact de notre stage 1 révèle une couverture sandbox tierce jamais consultée jusqu'ici : ANY.RUN, Triage, VMRay, CAPE, UnpacMe, Intezer, Kaspersky, ReversingLabs, entre autres.

**Confirmation indépendante de la famille** : ANY.RUN, Triage et VMRay classifient tous les trois `agenttesla`, indépendamment du simple tag communautaire MalwareBazaar — jamais vérifié par nous jusqu'à ce point (même réserve posée en §2, levée ici).

**Tags ANY.RUN** : `netreactor, stealer, ip-check, evasion, agenttesla, ftp, exfiltration`. Le tag `netreactor` confirme, de façon totalement indépendante, l'identification du protecteur faite en §5.1 via une chaîne trouvée en clair dans le code — deux méthodes complètement différentes (lecture de code vs classification automatique tierce) aboutissent à la même conclusion.

### 10.2 Configuration extraite dynamiquement par Triage

Rapport complet : [tria.ge/reports/260714-kt4y4scs2z](https://tria.ge/reports/260714-kt4y4scs2z/)

```
Exfiltration : FTP
Hôte         : ftp.piovau.com:21
Identifiants : présents en clair dans le rapport de sandbox
```

Comportements confirmés par l'exécution dynamique :
- Accès aux profils Microsoft Outlook — confirme un vol de données réel, pas seulement une capacité théorique déduite du code statique
- Consultation d'adresse IP externe via un service web — cohérent avec le tag `ip-check` d'ANY.RUN
- **Usage de `SetThreadContext`**, signalé explicitement par le sandbox

### 10.3 Un recoupement qui referme une question laissée ouverte en §7-8

`SetThreadContext` n'apparaît **nulle part** dans notre traçage statique du stage 2 (§6 à §8) : la séquence tracée par nous s'arrête à `OpenProcess`/`VirtualAlloc`/`WriteProcessMemory`/`VirtualProtect`, jamais `SetThreadContext`/`ResumeThread`. Ce n'est pas une contradiction — ça complète la chaîne :

```
Stage 2 (tracé statiquement, §6-8)
  → prépare/charge une image en mémoire locale RWX, écrit dans un process distant
    → payload final (jamais extrait manuellement, dans la ressource chiffrée)
      → exécute le hollowing classique par détournement de contexte de thread (SetThreadContext, vu par le sandbox)
```

Exactement le pattern StealC (process hollowing par section mappée), mais un cran plus loin dans la chaîne pour AgentTesla — le hollowing "classique" n'est pas dans le stage qu'on a pu lire, il est dans celui qu'on n'a pas pu déchiffrer, et seule l'exécution réelle (par un tiers) le révèle.

### 10.4 UnpacMe : probable confirmation directe du contenu déchiffré

`UnpacMe` référence 5 hashs liés au même run d'unpacking automatique sur notre échantillon, dont un avec des détections antivirus directes :

```
SHA256 : 352ce702aafbbb7253872bfb6c55ab6d7bba6a4cc83cce427fb4c863331ef566
Détections : win_agent_tesla_g2, triage_agenttesla_infostealer
```

C'est vraisemblablement — non confirmé formellement, la page UnpacMe étant rendue en JavaScript et non consultable via récupération simple de page — le contenu déchiffré de la ressource qu'on cherchait à extraire à la main en §8-9. Piste ouverte pour une session future si une confirmation plus directe est nécessaire (téléchargement du hash lui-même via MalwareBazaar ou l'API UnpacMe si disponible publiquement).

---

## 11. Conclusion générale

```
CTM.exe (leurre : outil de dimensionnement de structure navale, MalwareBazaar 2026-07-14)
  → ressource .NET chiffrée (inversion + AES-128, clé=IV en dur)
    → stage 2 : protégé Eziriz .NET Reactor (confirmé en clair, puis indépendamment par ANY.RUN)
      → control-flow flattening réel (1 891 cases), outils dédiés construits et validés à la main
        → fausse piste d'auto-injection identifiée et corrigée avant publication
          → vrai chemin tracé à 97% : OpenProcess/VirtualAlloc/WriteProcessMemory/VirtualProtect
            → payload final chiffré (non extrait manuellement)
              → AgentTesla confirmé (3 sandboxes indépendantes), hollowing classique (SetThreadContext, vu dynamiquement)
                → exfiltration FTP vers ftp.piovau.com, vol de données Outlook
```

La question "que contient le payload final" est fermée par recoupement OSINT, pas par déchiffrement manuel complet — cohérent avec la méthode déjà validée sur StealC : deux tentatives sérieuses et documentées (outil maison, outil spécialisé) plutôt qu'un acharnement sans fin sur une voie technique bloquée, puis une confirmation externe indépendante quand elle existe.

## 12. Limites et honnêteté méthodologique

- Le contenu exact de `ObjectRequester.ScopeObject` n'a jamais été déchiffré directement par nous — seulement recoupé via des sandboxes tierces (§10.4).
- La séquence d'injection (§7.1) reflète un ordre de *visite* de graphe, pas un ordre d'*exécution* chronologiquement confirmé sur un run réel.
- Le protecteur du stage 1 (§4.2) n'a jamais été confirmé formellement — seul celui du stage 2 l'a été, par une preuve directe (§5.1) puis une confirmation tierce indépendante (§10.1).
- Aucune vérification passive indépendante (type ThreatFox) n'a été faite sur l'infrastructure FTP (`ftp.piovau.com`) — piste ouverte si une confirmation supplémentaire de son activité était nécessaire.
- 20 états du dispatcher principal (§8.2) restent inatteignables par tout point d'entrée connu — probable code mort, jamais confirmé comme tel.
- **Incohérence relevée à la fusion de ce document, non résolue** : le nombre de cases attribué au dispatcher de la ligne 8965 diverge entre le journal brut de `deflatten_cs.py` (747, voir runbook) et l'analyse qui suit (649, utilisé de façon cohérente en §6.4, §7.1, §8) — voir la note en §6.4.

## 13. IOCs consolidés

| Type | Valeur |
|---|---|
| SHA256 (stage 1, `CTM.exe`) | `bc6d86cef1b7404823c1d830387b2c9b1289c453620482fc1749dd5d2ade3897` |
| SHA256 (stage 2, DLL déchiffrée) | `39fdba7a439cb09842f26d34f84606e3cc7f685b407deceb49ee7cb71271ebcd` (non indexé sur MalwareBazaar) |
| SHA256 (probable payload final déchiffré, via UnpacMe) | `352ce702aafbbb7253872bfb6c55ab6d7bba6a4cc83cce427fb4c863331ef566` |
| Ressource stage1→stage2 | `Genitalk.klaoxao.tiff` (459 024 octets) |
| Clé/IV AES-128 (stage1→stage2) | `e4a931cb6e204322da0d1a30d946633b` |
| Ressource stage2→payload | `ObjectRequester.ScopeObject` (92 Ko, chiffrée, jamais déchiffrée manuellement) |
| Autres ressources stage 2 | `ScheduledObject.ObjectParser` (132 Ko), `DecryptorCompressor.ControllableObject` (4 Ko), `AuditorMap.LocalObject` (256 o) |
| Protecteur (stage 2) | Eziriz .NET Reactor (chaîne de licence trial en clair + confirmation ANY.RUN) |
| C2 exfiltration | FTP `ftp.piovau.com:21` |
| Famille | AgentTesla (confirmée ANY.RUN + Triage + VMRay) |
| Rapport Triage | [tria.ge/reports/260714-kt4y4scs2z](https://tria.ge/reports/260714-kt4y4scs2z/) |

## 14. Reproduire l'analyse

Le log détaillé (commande / pourquoi / sortie brute / ce qu'on en retient) de chacune des quatre parties est dans [`runbook.md`](runbook.md), qui couvre :

- [Partie 1 — loader stage 1](runbook.md#partie-1--loader-stage-1) (§4 ci-dessus)
- [Partie 2 — identification du protecteur et control-flow flattening](runbook.md#partie-2--identification-du-protecteur-et-control-flow-flattening) (§5–7)
- [Partie 3 — vrai chemin et tentatives d'outillage](runbook.md#partie-3--vrai-chemin-et-tentatives-doutillage) (§8–9)
- [Partie 4 — confirmation externe](runbook.md#partie-4--confirmation-externe) (§10)

Prérequis : `pefile`, `capa`+règles, `ilspycmd`, `.NET SDK` 10.0, `pycryptodome`, une clé API MalwareBazaar (voir [`../stealc-autoit-killchain/runbook.md`](../stealc-autoit-killchain/runbook.md) pour l'installation de la base commune).
