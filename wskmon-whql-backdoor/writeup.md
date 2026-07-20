# Writeup : wskmon.sys : backdoor kernel-mode signé WHQL, abus du Windows Filtering Platform (et deux outils liés par le même certificat)

**Date d'analyse :** 18/07/2026
**Analyste :** Gordon PEIRS
**Type :** Analyse statique uniquement (aucune exécution des samples, aucun chargement des drivers)
**Famille :** Non nommée officiellement, identifiée ici par son nom de fichier et ses chaînes internes (`WskMon`)

> Ce document regroupe l'analyse technique complète de `wskmon.sys` et des deux autres outils retrouvés signés avec le même certificat (`devhost.sys`, `844ljfpvz.sys`). Le [signalement MSRC](02-wskmon-msrc-report.md) (lettre de divulgation destinée à Microsoft) et le [PoC de déclenchement](poc_trigger.py) restent des documents séparés, ce ne sont pas de la prose d'analyse mais des livrables distincts.

## 1. Contexte

Échantillon repéré sur MalwareBazaar (tag `rootkit`), signalé le 27/06/2026, compilé le 04/04/2026. Contrairement aux droppers habituels de ce dossier, ce n'est pas un malware user-mode : c'est un **driver kernel Windows x64 signé WHQL** (Windows Hardware Compatibility Publisher), abusant du **Windows Filtering Platform (WFP)** pour implanter un backdoor réseau furtif, invisible pour la quasi-totalité des antivirus au moment de l'analyse.

Un writeup public existe déjà sur ce sample : [Nextron Systems, "Anatomy of a WHQL-signed Windows Filtering Platform (WFP) kernel-resident network backdoor"](https://www.nextron-systems.com/2026/06/26/anatomy-of-a-whql-signed-windows-filtering-platform-wfp-kernel-resident-network-backdoor) (26/06/2026), accompagné d'un [PoC client Python](https://gist.github.com/pierrehpezier/fe1977d390a45e64d522e657fb8d3640). Cette analyse a été menée **indépendamment**, sans se fier aux affirmations de cet article avant de les avoir vérifiées soi-même dans le désassemblage, une seule d'entre elles (le nom de la fonction `RtlCreateUserThread`) s'est révélée incomplète : elle omet le mécanisme de repli réel (§8). Le reste des sections ci-dessous va sensiblement plus loin que ce qui est documenté publiquement (récapitulatif en §18).

## 2. Identité de l'échantillon

| Champ | Valeur |
|---|---|
| SHA256 | `495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979` |
| Nom de fichier | `wskmon.sys` |
| Taille | 32 344 octets |
| Type | PE32+ driver kernel (x86-64) |
| Imphash | `5c6478fa51bfe6402aa0892dc333f989` |
| Compilation | 2026-04-04 13:05:19 UTC |
| Première observation MalwareBazaar | 2026-06-27 |
| Détection antivirus au moment de l'analyse | Quasi nulle, Kaspersky "Clean", YOROI "Legit File", FileScan-IO "NO_THREAT", ReversingLabs 1/23 scanners |
| Échantillons apparentés | **Aucun par imphash** (recherche infructueuse, normal, ce sont des builds différents), **mais deux par certificat**, voir §4 |

## 3. La signature : le vrai problème

Le fichier de signature Authenticode (répertoire Security du PE, extrait directement du binaire et vérifié par deux bibliothèques indépendantes, `openssl` et `cryptography`) ne contient que **deux certificats X.509**, tous les deux appartenant à Microsoft :

| Champ | Valeur |
|---|---|
| Sujet (certificat de signature) | Microsoft Windows Hardware Compatibility Publisher |
| Émetteur | Microsoft Windows Third Party Component CA 2012 |
| Validité | 2025-11-13 → 2026-11-10 (**valide au moment de la rédaction, vérifié en direct contre la CRL Microsoft, aucune révocation, dernière mise à jour de la liste le 2026-05-07**) |
| Numéro de série | `330000013c4a61fb3578d2b6dd00000000013c` |
| Empreinte SHA256 | `2e8072ded075c6b6c0df8c364e9d12319577114991f2455ebc4b364b367f7dba` |

**Précision importante, corrigée après une seconde vérification :** le nom « 深圳市奥联信息安全技术有限公司 » (Shenzhen Aolian Information Security Technology Co., Ltd), rapporté par Nextron comme « Subject » du certificat, n'est **pas** le champ Subject d'un certificat X.509, aucun des deux certificats embarqués ne porte ce nom. La chaîne est retrouvée en clair (UTF-16BE, offset `0x6543` du fichier), à l'intérieur du répertoire de sécurité, à l'emplacement exact où Authenticode stocke l'attribut signé **SpcSpOpusInfo** (le champ « nom de programme » que le soumetteur renseigne lui-même et qui apparaît dans la boîte de dialogue Windows « Détails de la signature numérique »). C'est une donnée réelle, signée, et directement liée à la soumission, mais techniquement distincte du certificat lui-même, ce qui change la formulation à employer dans un signalement : Aolian a *fourni* cette information au moment de la soumission, ce n'est pas forcément le titulaire du certificat de signature final (qui reste Microsoft, par construction du programme d'attestation).

Aolian est une entreprise de cryptographie chinoise réelle et établie (fondée en 2009, unité désignée par l'Administration d'État de la Cryptographie chinoise, algorithme SM9 adopté comme standard ISO/IEEE/3GPP/IETF). **Le scénario le plus probable n'est pas qu'Aolian ait construit ce driver**, mais que son compte Microsoft Partner Center (Hardware Dev Center) ou l'accès utilisé pour soumettre cette signature aient été compromis ou détournés, un schéma documenté précédemment par Mandiant et SentinelOne fin 2022 (campagne POORTRY/STONESTOP, groupe UNC3944), où plusieurs comptes vendeurs légitimes ont servi, volontairement ou non, à faire signer des drivers malveillants via le canal d'**attestation signing**, la voie de signature allégée du programme WHCP, ne nécessitant qu'un certificat EV et une soumission, sans test matériel complet (HLK).

Point notable : ce sample est compilé en **avril 2026**, après l'annonce par Microsoft (avril 2026) de la suppression de la confiance pour les drivers cross-signés historiques et du renforcement du programme WHCP. Ce driver a donc obtenu une signature légitime **après** ce durcissement, la nouvelle politique n'a pas empêché cet abus précis.

## 4. Le même certificat, réutilisé sur trois fichiers : ce n'est pas un abus isolé

Une recherche MalwareBazaar par **numéro de série du certificat** (`330000013c4a61fb3578d2b6dd00000000013c`), plutôt que par imphash, remonte deux autres fichiers signés avec exactement le même certificat, jamais mentionnés par le writeup public :

| Fichier | SHA256 | Imphash | Compilation | Première observation | Rapporteur |
|---|---|---|---|---|---|
| `devhost.sys` | `ee8844ffd3879190fb389b0f613cb2dcdcd83375cf0a6994170a648c5ca8c479` | `fb7c5ff17455f725aa59f998a0f324ca` | 2026-01-17 | 2026-04-22 | smica83 |
| `844ljfpvz.sys` | `1d9224a72e64bb2aad289edc81ea0720c764511c3e2b5beb5d0d5ce82a719abd` | `7282cc9e51cb73de8f89c7740b0e69fb` | 2026-04-15 | 2026-06-19 | smica83 |
| `wskmon.sys` (cet échantillon) | `495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979` | `5c6478fa51bfe6402aa0892dc333f989` | 2026-04-04 | 2026-06-27 | GDHJDSYDH1 |

Trois imphashes différents = trois builds distincts, pas la même charge utile recompilée.

**Deux fenêtres temporelles distinctes, à ne pas confondre** :
- **Par date de compilation** (janvier → avril 2026) : `devhost.sys` (17/01) est le plus ancien, `wskmon.sys` (04/04) au milieu, `844ljfpvz.sys` (15/04) le plus récent, un peu moins de **trois mois** d'écart entre le premier et le dernier build (17/01 → 15/04).
- **Par date de première observation publique** (avril → juin 2026) : `devhost.sys` (22/04) en premier, `844ljfpvz.sys` (19/06) ensuite, `wskmon.sys` (27/06) en dernier, soit **devhost.sys → 844ljfpvz.sys → wskmon.sys** dans cet ordre-là, différent de l'ordre de compilation. Un peu plus de deux mois d'écart (22/04 → 27/06).

Le certificat a donc été réutilisé activement sur une fenêtre de compilation d'environ trois mois, et observé publiquement sur une fenêtre d'environ deux mois, repéré par deux rapporteurs indépendants sans lien apparent. Les noms de fichiers (`devhost.sys` imitant la convention `*host.sys` légitime de Windows, `844ljfpvz.sys` au nom généré, `wskmon.sys` au nom plausible) suggèrent des tentatives de déguisement variées d'un build à l'autre, cohérent avec un accès de signature détenu et réutilisé dans la durée plutôt qu'un usage ponctuel. Analyse détaillée des deux autres échantillons en §12-13.

## 5. Enregistrement WFP : DriverEntry

`DriverEntry` (`entry0`, `0x140001030`) :

1. `ExInitializeRundownProtection` sur une structure globale (`0x1400060a0`), synchronisation pour un arrêt propre.
2. `IoCreateDevice` crée un objet device **nommé** : `\Device\WskMon` (type `FILE_DEVICE_UNKNOWN`). Le pointeur est conservé dans une globale (`0x140006080`), réutilisée plus tard comme device propriétaire des work items différés.
3. Remplissage de la table de dispatch du `DRIVER_OBJECT` : `DriverUnload` reçoit une routine de fermeture propre (§10) ; les **28 entrées `MajorFunction[]`** (CREATE, CLOSE, READ, WRITE, DEVICE_CONTROL, etc.) pointent **toutes vers le même stub générique** (`0x140001000`) qui ne fait qu'appeler `IofCompleteRequest` avec succès, sans rien traiter. **Aucune IOCTL locale n'est implémentée**, le device object n'est qu'un ancrage technique, pas un canal de contrôle.
4. Résolution différée des primitives de création de thread (§8).
5. Enregistrement WFP complet, en transaction : `FwpmEngineOpen0` → `FwpmTransactionBegin0` → `FwpmSubLayerAdd0` ("WskMon Sub") → `FwpsCalloutRegister1` + `FwpmCalloutAdd0` ("WskMon Callout") → `FwpmFilterAdd0` ("WskMon Filter") → `FwpmTransactionCommit0`. Sur échec à n'importe quelle étape : `FwpmTransactionAbort0` et nettoyage en cascade.

**Couche réseau ciblée :** le GUID chargé pour le callout (`0x140005420`) correspond **exactement, octet pour octet**, au GUID Microsoft documenté `FWPM_LAYER_STREAM_V4`, `DEFINE_GUID(FWPM_LAYER_STREAM_V4, 0x3b89653c, 0xc170, 0x49e4, 0xb1, 0xcd, 0xe0, 0xee, 0xee, 0xe1, 0x9a, 0x3e)`, vérifié contre le header source `fwpmu.h`, et non pas une simple ressemblance de préfixe. Confirmé indépendamment par l'usage de `FwpsCopyStreamDataToBuffer0`, une API qui n'existe que sur les couches "stream" (flux TCP déjà réassemblé, pas de l'inspection paquet par paquet). Le driver s'accroche donc au flux TCP IPv4 applicatif.

## 6. La fonction de classification : double déclencheur réseau

La fonction de classification (`0x1400013a0`), retrouvée en remontant les cross-références depuis `FwpsCalloutRegister1` (un seul appelant dans tout le binaire) jusqu'à la structure `FWPS_CALLOUT1`, inspecte chaque flux TCP passant par la couche Stream V4 :

```
cmp al, 0x7f      ; test direct en tête de flux
cmp byte, 0x4e    ; 'N'
cmp byte, 0x54    ; 'T'
cmp byte, 0x46    ; 'F'
```

→ octets magiques `7F 4E 54 46` en tête de flux (mode brut).

Si le flux commence par `"POST"` (`50 4F 53 54`), le driver copie les 1024 premiers octets du corps (`FwpsCopyStreamDataToBuffer0`, `r8d = 0x400`) et scanne cette zone à la recherche du même motif magique, masquant les commandes dans du trafic HTTP légitime pour contourner l'inspection réseau classique.

Une fois le motif trouvé, structure de commande lue directement depuis le flux :

| Offset | Champ | Détail |
|---|---|---|
| +4 | Type de commande | 1 octet, valeurs valides 1–3 (vérifié : `lea eax,[rdx-1]; cmp al,2; ja fail`) |
| +0x25 | Longueur du payload | 4 octets **big-endian**, construits par trois `shl 8` / `or` successifs |
| +0x29 | Payload chiffré | XOR rotatif |

## 7. Authentification et chiffrement

**HMAC-SHA256**, confirmé par la séquence d'appels CNG exacte : `BCryptCreateHash → BCryptHashData ×2 → BCryptFinishHash → BCryptDestroyHash` (fonction `0x140001bf0`, aussi invoquée une fois au chargement du driver). Retour `false` → le paquet est rejeté silencieusement, aucune trace, aucune réponse.

**Clé XOR extraite en clair**, table de 32 octets à `0x140005470` (indexée via `and eax, 0x1f`) :

```
d2 47 8a 1e f3 6b c0 95 54 29 e7 3d 81 af 66 0c
b8 72 1f e4 43 9d 5e 28 a6 0d 73 c9 3b 84 f1 52
```

## 8. Résolution dynamique des primitives de thread : le double repli

Aucune fonction de création de thread n'apparaît dans la table d'imports statique. `entry0` appelle `fcn.140001d50` au chargement, qui procède en deux temps :

1. **Voie normale :** `MmGetSystemRoutineAddress` résout `RtlCreateUserThread` par son nom (chaîne UTF-16LE `"RtlCreateUserThread"` en `.rdata`), résultat mis en cache dans une globale (`0x1400060c8`). Si trouvé → terminé.
2. **Voie de repli, si la résolution normale échoue :** lecture du **MSR `IA32_LSTAR`** (`rdmsr`, `ecx = 0xc0000082`), le registre modèle-spécifique contenant l'adresse du point d'entrée des syscalls (`KiSystemCall64`). Scan des 1024 premiers octets à partir de cette adresse à la recherche du motif d'opcode `4C 8D 15` (`lea r10, [rip+...]`), calcul manuel de la cible RIP-relative pour obtenir la **base de la SSDT** (System Service Descriptor Table), mise en cache dans `0x1400060b8`.

Une seconde fonction (`0x140002770`), appelée juste avant chaque tentative d'injection, transforme cette base SSDT en pointeur exploitable :

1. Parcourt la table d'export de `ntdll.dll` pour localiser le stub utilisateur `ZwCreateThreadEx`.
2. Vérifie que ce stub commence par le prologue syscall x64 standard (`4C 8B D1 B8` = `mov r10,rcx; mov eax,imm32`).
3. Extrait le **numéro de syscall** codé en dur dans ce stub.
4. Indexe la SSDT avec ce numéro : `entry = table[num]`, `sar entry, 4` (les 4 bits de poids faible codent le nombre d'arguments), `+ table_base` → adresse noyau réelle de l'implémentation de `ZwCreateThreadEx`. Mis en cache dans `0x1400060c0`.

C'est une reconstruction manuelle et correcte de la table de service Windows, sans aucune API documentée, reposant uniquement sur un registre modèle-spécifique Intel et la structure binaire connue des stubs syscall, une technique historiquement associée à des rootkits et outils de contournement d'EDR, pas à du code amateur.

La fonction partagée `0x1400025f0` (appelée par les commandes 1 et 3) ouvre le process cible (`ZwOpenProcess`, `PROCESS_ALL_ACCESS`), puis appelle en priorité le pointeur `RtlCreateUserThread` résolu, ou à défaut le pointeur `ZwCreateThreadEx` dérivé de la SSDT.

## 9. Les trois commandes

**Cible commune (commandes 1 et 3) :** énumération de tous les process via `ZwQuerySystemInformation`, comparaison nom par nom avec la chaîne `"svchost.exe"`, puis vérification précise du compte propriétaire via `PsReferencePrimaryToken` + `SeQueryInformationToken(TokenUser)` (classe `1`, confirmée dans le désassemblage). La comparaison porte sur la sous-autorité du SID retourné : `0x12` = 18 décimal, exactement la sous-autorité du SID bien connu `S-1-5-18` (**NT AUTHORITY\SYSTEM**). Le driver ne se contente pas de la première instance de `svchost.exe` trouvée, il vérifie spécifiquement qu'elle tourne sous le compte SYSTEM avant de la cibler.

| Cmd | Fonction | Mécanisme |
|---|---|---|
| `0x01` | `0x140001e10` | Parcourt le PEB du process cible pour localiser `kernel32.dll`, résout `WinExec` dans sa table d'export, déclenche l'exécution via le mécanisme de la §8 |
| `0x02` | `0x1400027f0` | Convertit le chemin UTF8→Unicode (`RtlUTF8ToUnicodeN`), préfixe `\??\` construit octet par octet, `ZwCreateFile` avec `DesiredAccess=GENERIC_WRITE\|SYNCHRONIZE`, `ShareAccess=0` (exclusif), **`CreateDisposition=5` (`FILE_OVERWRITE_IF`)**, `CreateOptions=FILE_SYNCHRONOUS_IO_NONALERT`, handle ouvert avec `OBJ_KERNEL_HANDLE` (invisible en énumération user-mode) |
| `0x03` | `0x140002040` | `ZwAllocateVirtualMemory` dans le process cible, copie du shellcode reçu, déclenche l'exécution via le même mécanisme que la commande 1 |

## 10. Arrêt propre : DriverUnload

`0x1400011c0` : positionne un flag global (`0x1400060a8`, le même que la fonction de classification consulte pour savoir si elle doit ignorer les paquets), attend la fin de tout traitement en cours (`ExWaitForRundownProtectionRelease`), désenregistre proprement le callout et la sous-couche WFP, supprime le device object. Synchronisation kernel correcte, pas de code bâclé.

## 11. Ce qui n'existe pas dans ce binaire

- **Aucune infrastructure C2 sortante.** Toutes les URL présentes sont les métadonnées légitimes de la chaîne de certificats Microsoft (CRL, OCSP). Le backdoor est **purement passif** : il n'appelle jamais personne, il attend qu'on lui envoie le bon paquet sur une connexion existante.
- **Aucune persistance.** Pas un seul import registre (`ZwCreateKey`, `ZwSetValueKey`, etc.). Le chargement initial du driver dépend entièrement d'un composant externe, absent de ce fichier (le candidat le plus probable, `devhost.sys`, est analysé en §12).
- **Aucun chemin PDB.** Entrée `IMAGE_DEBUG_TYPE_POGO` présente, mais pas de `CodeView`, pas de fuite de type `campus.py` (comparer à l'enquête Efimer).

---

## 12. devhost.sys : primitive de lecture/écriture mémoire physique arbitraire

Trouvé en §4 par recherche du certificat partagé.

| Champ | Valeur |
|---|---|
| SHA256 | `ee8844ffd3879190fb389b0f613cb2dcdcd83375cf0a6994170a648c5ca8c479` |
| Taille | 22 104 octets |
| Compilation | 2026-01-17 (le plus ancien des trois, antérieur à `wskmon.sys` de plus de deux mois) |
| Première observation MalwareBazaar | 2026-04-22 |

**Imports :** `KeRevertToUserAffinityThread`, `KeSetSystemAffinityThread`, `KeQueryActiveProcessors`, `MmProbeAndLockPages`, `MmUnlockPages`, `IoAllocateMdl`, `IoFreeMdl`, plus deux **symboles de données kernel** importés directement : `MmSystemRangeStart` et `MmUserProbeAddress` (les bornes de séparation espace utilisateur/kernel), et `NtBuildNumber`.

Contrairement à `wskmon.sys`, ce driver crée à la fois un objet device (`\Device\devhost`) **et son lien symbolique DOS** (`\??\devhost`), accessible depuis le mode utilisateur via `\\.\devhost`, avec un IOCTL réel (contrairement au device de `wskmon.sys` qui ne faisait que renvoyer succès sans rien traiter).

**Ce que fait réellement le driver :**

1. À la fin de `DriverEntry`, lecture directe des registres de contrôle CPU :
   ```asm
   mov rax, cr3   ; base de la table de pages (PML4) du process courant
   mov qword [rcx + 0x10], rax
   mov rax, cr4   ; bits PAE/SMEP/SMAP...
   ```
   Ces valeurs sont stockées dans une structure de contexte, exploitable par l'appelant via l'IOCTL.

2. Le handler d'E/S (`fcn.140001640`, enregistré comme callback sur le device) vérifie l'IRQL courant via `mov rax, cr8` avant de traiter la requête, cohérent avec un vrai pilote respectueux des contraintes kernel, pas du code jeté à la va-vite.

3. Le cœur du moteur (`fcn.1400012a0`) est un **copieur mémoire générique par blocs de 4 Ko (0x1000)** : pour chaque page, `IoAllocateMdl` → `MmProbeAndLockPages` → obtention d'une adresse virtuelle système (via le champ MDL `MappedSystemVa` ou, à défaut, un pointeur résolu dynamiquement à `0x140004128`) → copie effective (`fcn.1400011e0`) → `MmUnlockPages` → `IoFreeMdl`. C'est la technique MDL classique pour mapper temporairement n'importe quelle page physique en espace kernel, lire/écrire, puis démapper.

**Interprétation :** combiné, CR3 exposé + primitive de lecture/écriture physique arbitraire + interface accessible en mode utilisateur = tout ce qu'il faut pour **mapper manuellement un autre driver en mémoire kernel sans passer par le chargeur normal de Windows**, contournant la vérification de signature standard (technique dite de "manual mapping", proche de ce que font des outils publics comme kdmapper). C'est un candidat sérieux pour le mécanisme de chargement externe qui restait introuvable dans l'analyse de `wskmon.sys` seul (§11), sans preuve directe d'un lien entre les deux au-delà du certificat partagé.

**Détail d'implémentation, vérifié après coup :** ce driver est construit sur le **Windows Driver Framework (KMDF)**, pas en WDM brut comme `wskmon.sys`, confirmé par des appels indirects via des pointeurs de fonction résolus dynamiquement (`0x140004080`, `0x140004088`, `0x140004090`, jamais dans la table d'imports statique), cohérent avec le mécanisme de liaison `WdfVersionBind` et les API `WdfRequestRetrieve*Buffer`. Ça explique la fonction d'initialisation de 1177 octets en tête de `DriverEntry`, qui n'est que du boilerplate de configuration de structures WDF répété, pas de la logique métier. **Recherche exhaustive du code IOCTL, résultat négatif confirmé.** Un scan complet de toutes les sections du fichier à la recherche de constantes DWORD dans la plage `0x220000`–`0x22FFFF` (cohérente avec `DeviceType = 0x22` / `FILE_DEVICE_UNKNOWN`, vérifié comme le type réellement utilisé dans l'appel `IoCreateDevice`) ne retourne **aucun résultat**. Combiné à l'absence de toute comparaison littérale sur un tel code dans les deux fonctions qui traitent la requête (`fcn.140001640`, `fcn.1400014a0`, qui ne branchent que sur des tailles de buffer et la validité d'adresses via `MmUserProbeAddress`), la conclusion la plus probable n'est plus "je n'ai pas trouvé" mais **"il n'y a probablement pas de discrimination par code IOCTL", n'importe quel appel `DeviceIoControl` vers `\\.\devhost` déclenche la même primitive de copie**, du moment que les tailles de buffer passent la validation. C'est une conception encore plus permissive que "plusieurs IOCTL, chacun avec sa fonction" : ici, un seul comportement, sans porte de sélection.

## 13. 844ljfpvz.sys : outil minimal, fonction non déterminée

| Champ | Valeur |
|---|---|
| SHA256 | `1d9224a72e64bb2aad289edc81ea0720c764511c3e2b5beb5d0d5ce82a719abd` |
| Taille | 14 936 octets |
| Compilation | 2026-04-15 (le plus récent des trois par date de compilation, voir §4) |
| Première observation MalwareBazaar | 2026-06-19 |

Driver extrêmement réduit, quatre fonctions, aucun device créé, aucun lien symbolique. Deux imports seulement : `MmUserProbeAddress` et **`ZwSetSystemInformation`**, une API privilégiée capable de modifier des paramètres système globaux.

L'unique action réelle du driver, dans `DriverEntry` :
```
ZwSetSystemInformation(75, &struct{0x53425342 /* "BSBS" */, ...}, 24)
```

Classe d'information système `75` (0x4B), avec un magic `"BSBS"` codé en dur dans la structure passée. **Cette classe n'est pas documentée publiquement de façon fiable**, je ne fournis pas d'interprétation de sa fonction exacte faute de source solide pour la confirmer ; toute affirmation sur "ce que fait ce driver" au-delà de "il appelle `ZwSetSystemInformation` avec ces paramètres précis" serait une supposition non vérifiée, exactement le genre de raccourci qu'on essaie d'éviter dans cette série.

**Fuite PDB, celle-ci, contrairement à `wskmon.sys`, existe vraiment.** Le répertoire debug contient une entrée CodeView (type 2), absente des deux autres fichiers :

```
F:\0316 桌面\QDDDD\驱动最新加绘制-改PTE方案\x64\Release\NewDriverMMM.pdb
```

Traduction approximative : `驱动` (driver) `最新` (dernier/nouveau) `加绘制` (+ rendu/dessin) `-改PTE方案` (scheme PTE modifié). `绘制` (rendu à l'écran) et la mention explicite de manipulation de PTE (Page Table Entry) sont un vocabulaire très caractéristique du milieu des **cheats de jeux vidéo en Chine** (overlay ESP, contournement d'anti-cheat par manipulation de table de pages), pas du tout le registre habituel d'un outillage d'espionnage ou de cybercriminalité financière classique. Projet nommé `NewDriverMMM`, dossier de travail `QDDDD`.

## 14. Empreintes de compilation : un ou plusieurs auteurs ?

Comparaison des Rich headers (fingerprint de toolchain MSVC) des trois fichiers :

| Fichier | Build compilateur (primaire) | Build linker (secondaire) | PDB |
|---|---|---|---|
| `wskmon.sys` | 33145 | 35725 | Absent |
| `devhost.sys` | 33145 | 35214 | Absent |
| `844ljfpvz.sys` | 27412 | 30159 | **Présent, chinois, thème cheat-gaming** |

`wskmon.sys` et `devhost.sys` partagent le **même build de compilateur principal**, avec seulement le composant linker qui diverge légèrement, cohérent avec la même machine/le même développeur sur les ~2,5 mois séparant leurs dates de compilation (une mise à jour Visual Studio entre les deux builds expliquerait l'écart). Discipline OPSEC identique sur les deux (aucune fuite de chemin).

`844ljfpvz.sys` utilise un toolchain de compilation **entièrement différent**, sans aucun recouvrement avec les deux autres, et laisse fuiter un chemin de développement complet, une rupture nette de discipline OPSEC par rapport aux deux premiers.

**Interprétation :** le certificat partagé ne prouve pas un acteur unique. C'est exactement le schéma documenté par Mandiant en 2022 (POORTRY/STONESTOP) : un accès de signature compromis, réutilisé par plusieurs parties indépendantes sans lien entre elles. Les indices ici pointent vers **deux origines distinctes** : `wskmon.sys` + `devhost.sys` forment vraisemblablement un même kit développé par un seul auteur ou une seule équipe (même toolchain, même rigueur OPSEC) ; `844ljfpvz.sys` semble provenir d'un développeur différent, probablement issu du milieu du cheat-gaming chinois, qui a eu accès au même pipeline de signature compromis pour un projet distinct et sans rapport apparent avec les deux premiers.

## 15. Conclusion : un kit d'outils, pas un backdoor isolé

Le certificat n'a pas signé un seul backdoor isolé, il a signé **trois outils de nature différente** sur une fenêtre d'environ trois mois de compilation (janvier à avril 2026, §4) et deux mois d'observation publique (avril à juin) :

| Rôle probable | Fichier | Compilation |
|---|---|---|
| Primitive R/W mémoire physique (chargeur possible) | `devhost.sys` | 2026-01-17 |
| Backdoor réseau WFP (documenté en détail, §5-11) | `wskmon.sys` | 2026-04-04 |
| Fonction non déterminée (`ZwSetSystemInformation`) | `844ljfpvz.sys` | 2026-04-15 |

Ce n'est plus la signature d'un seul fichier malveillant isolé, c'est cohérent avec un **kit d'outils complet** (chargeur + backdoor + composant additionnel) développé et signé sous le même accès pendant plusieurs mois, très probablement par au moins deux développeurs distincts (§14).

Chaîne reconstituée :

```
Certificat WHQL valide (Aolian, probablement compromis)
  → devhost.sys (candidat chargeur) : CR3 exposé + R/W mémoire physique via MDL,
    accessible en mode utilisateur (\\.\devhost), compilé 3 mois avant wskmon.sys
      → wskmon.sys chargé en kernel (lien direct non prouvé, mais capacité compatible)
        → \Device\WskMon créé (aucune IOCTL réelle, simple ancrage technique)
          → Callout WFP enregistré sur FWPM_LAYER_STREAM_V4
            → Écoute passive : octets magiques 7F 4E 54 46 (TCP brut ou corps POST HTTP)
              → HMAC-SHA256 vérifié → XOR déchiffré (clé 32 octets)
                → Cmd 1/3 : svchost.exe SYSTEM ciblé (SID S-1-5-18 vérifié)
                  → RtlCreateUserThread (résolution dynamique)
                    → repli : lecture MSR IA32_LSTAR → scan syscall → SSDT manuelle
                → Cmd 2 : écriture fichier arbitraire (handle kernel invisible)
  → 844ljfpvz.sys : composant tiers, fonction non déterminée (ZwSetSystemInformation)
```

## 16. IOCs consolidés

| Type | Valeur |
|---|---|
| SHA256 (`wskmon.sys`) | `495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979` |
| Imphash (`wskmon.sys`) | `5c6478fa51bfe6402aa0892dc333f989` |
| SHA256 (`devhost.sys`) | `ee8844ffd3879190fb389b0f613cb2dcdcd83375cf0a6994170a648c5ca8c479` |
| SHA256 (`844ljfpvz.sys`) | `1d9224a72e64bb2aad289edc81ea0720c764511c3e2b5beb5d0d5ce82a719abd` |
| Nom de device | `\Device\WskMon`, `\Device\devhost` |
| Octets magiques réseau | `7F 4E 54 46` |
| Clé XOR (32 octets) | `d2478a1ef36bc0955429e73d81af660cb8721fe4439d5e28a60d73c93b84f152`[^xorkey] |
| Cible d'injection | `svchost.exe` (instance privilégiée uniquement) |
| Certificat (thumbprint) | `2e8072ded075c6b6c0df8c364e9d12319577114991f2455ebc4b364b367f7dba` |
| Certificat (numéro de série) | `330000013c4a61fb3578d2b6dd00000000013c` |
| PDB (`844ljfpvz.sys` uniquement) | `F:\0316 桌面\QDDDD\驱动最新加绘制-改PTE方案\x64\Release\NewDriverMMM.pdb` |

[^xorkey]: Regroupée en deux lignes de 16 octets en §7 pour la lecture ; la coupure de la version précédente de ce document tombait au milieu d'un octet (après le 9ᵉ octet plutôt qu'au milieu à 16), corrigé ici en une seule chaîne continue de 32 octets sans espace, pour un copier-coller IOC sans ambiguïté.

## 17. Détection

- Présence du device `\Device\WskMon` (et, si `devhost.sys` est aussi présent, `\Device\devhost`) sur une machine (visible via WinObj ou énumération `\Device\`).
- Trafic réseau contenant la séquence `7F 4E 54 46`, en tête de flux TCP ou dans les 1024 premiers octets d'un corps `POST`.
- Le certificat lui-même (empreinte ci-dessus) tant qu'il n'est pas révoqué.

## 18. Ce que cette analyse ajoute au writeup public existant

| Élément | Nextron (public) | Cette analyse |
|---|---|---|
| Octets magiques, HMAC, XOR | Oui | Confirmé indépendamment, clé XOR extraite en clair |
| Mécanisme d'exécution (cmd 1/3) | "RtlCreateUserThread dans svchost.exe" | Confirmé + double repli SSDT/MSR entièrement documenté, jamais mentionné |
| Persistance | Non documentée | Confirmée absente de ce binaire (aucun import registre) |
| Objet device `\Device\WskMon` | Non mentionné | Identifié, IOC exploitable |
| Couche réseau WFP exacte | Non précisée | Stream V4, confirmée par GUID + API |
| `CreateDisposition` exact | Non précisé | `FILE_OVERWRITE_IF` (5), confirmé |
| Contexte de signature | Non creusé | Lien avec le précédent POORTRY/STONESTOP (2022), hypothèse de compte compromis plutôt que complice |
| `devhost.sys` / `844ljfpvz.sys` | Non mentionnés | Trouvés par recherche du certificat partagé, analysés en détail (§12-14), candidat chargeur identifié |

## 19. Documents associés et divulgation

- [`02-wskmon-msrc-report.md`](02-wskmon-msrc-report.md), signalement destiné au Microsoft Security Response Center : révocation du certificat, enquête sur le compte de soumission, preuve de réutilisation sur les trois fichiers.
- [`poc_trigger.py`](poc_trigger.py), générateur de paquet de déclenchement (magic bytes + HMAC-SHA256 + XOR), reconstruit entièrement depuis le désassemblage, preuve d'exploitabilité pour le rapport MSRC. N'envoie rien par défaut ; nécessite une cible explicite + confirmation manuelle.

**Note sur la divulgation.** Le certificat documenté ici est **actif** au moment de cette analyse. Par cohérence avec les pratiques de divulgation coordonnée (signaler au vendeur avant publication large), ce dossier reste privé jusqu'à confirmation de la révocation par Microsoft ou un délai raisonnable sans réponse. La société dont le nom apparaît dans le certificat (Aolian) est très vraisemblablement une victime dans cette histoire (§3) et n'a pas vocation à être présentée publiquement comme responsable sans confirmation.
