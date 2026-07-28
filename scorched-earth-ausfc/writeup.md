# Analyse Prinz Eugen (module encrypter) : mot de passe codé en dur derrière un chiffrement Argon2id + ChaCha20-Poly1305 par ailleurs sain

**Analyste :** Gordon PEIRS
**Date d'analyse :** 27/07/2026
**Type :** Analyse statique uniquement (le binaire n'a jamais été exécuté). Ghidra headless via PyGhidra, décompilation par nom de symbole Go. Déchiffrement réel d'un fichier victime confirmé par ré-implémentation Python de la chaîne cryptographique complète.
**Famille :** Ransomware **Prinz Eugen** (nom de projet interne "scorched-earth-ausfc", retrouvé dans les chemins de compilation embarqués et cité comme IOC par ThreatDown). RaaS documenté publiquement (voir §10) : usurpation de marque (Standard Bank), leak-site Tor, accès initial par identifiants RDP compromis. Ce binaire précis (`fc.exe`, hash différent de l'échantillon ThreatDown) a été fourni directement pour analyse, hors de toute plateforme d'échantillons publique, avec un fichier réellement chiffré à récupérer.

---

## 1. Contexte et échantillon

Binaire `fc.exe` fourni pour analyse avec un objectif concret : un fichier a été chiffré par cet outil et doit être récupéré, sans mot de passe ni fichier-clé connus au départ.

| Champ | Valeur |
|---|---|
| SHA256 | `88e63d1f5f5478bb98269bb48c7508c6fc90f1f203f37aa7b30b801080b55fbd` |
| Type | PE32+, x86-64, 16 sections, console |
| Taille | 3 673 600 octets |
| Runtime | Go 1.26.2 |
| Chemin de compilation embarqué | `C:/Users/User/source/scorched-earth-ausfc/cmd/encrypter/main.go` |
| Module Go | `scorched-earth-ausfc` (devel), dépendances `golang.org/x/crypto v0.50.0`, `golang.org/x/sys v0.43.0` |

Le binaire n'est **pas strippé** : la table de symboles COFF conserve l'intégralité des noms de packages et de fonctions Go (`internal/crypto`, `internal/chv1`, `internal/fswalk`, `cmd/encrypter`), ce qui permet de naviguer directement par nom de symbole plutôt que de reconstruire la structure du programme à partir de zéro.

Le chemin `cmd/encrypter/main.go` indique un dépôt Go à plusieurs binaires : celui-ci est le **module de chiffrement seul**. L'échantillon distinct analysé par ThreatDown (`servertool.exe`, voir §10) provient vraisemblablement d'un autre `cmd/` du même dépôt, orienté orchestration/C2, ce qui explique l'absence totale de capacité réseau ou de persistance dans ce binaire précis (confirmé §3).

Un fichier réellement chiffré par cet outil a été fourni en complément : `HelloWorld.txt.prinzeugen` (86 octets), qui sert de base de vérification tout au long de cette analyse.

## 2. Outillage

- `pefile`, `objdump`, `strings` pour le triage initial et l'extraction de la table de symboles COFF.
- Ghidra headless via PyGhidra pour la décompilation, avec un outil dédié écrit pour cette analyse (`decompile_by_name.py`, dans `tools/`) qui résout une fonction par son nom de symbole Go complet plutôt que par une adresse calculée à la main.
- Python (`argon2-cffi`, `cryptography`) pour ré-implémenter la chaîne de dérivation de clé et valider le déchiffrement.

## 3. Triage : un binaire Go non strippé, sans capacité réseau

Le PE lui-même n'importe que `kernel32.dll` en direct, ce qui est trompeur : les binaires Go font la plupart de leurs appels système sans passer par la table d'imports classique. La table de symboles révèle la véritable nature du binaire : sections aux noms longs (`/4`, `/19`, `/32`...) typiques du format COFF avec table de chaînes, section `.symtab` complète, et des chaînes de caractères qui confirment sans ambiguïté un binaire Go (`go1.26.2`, `golang.org/x/crypto/argon2`, `golang.org/x/crypto/chacha20poly1305`, `golang.org/x/crypto/hkdf`).

Point notable pour la suite : **aucune capacité réseau réelle** n'est présente dans la table de symboles. Ni `net.Dial`, ni `net/http`, ni `crypto/tls` (les seules occurrences de "tls" dans le binaire sont le thread-local-storage interne du runtime Go, sans rapport). L'unique appelant de `os.Getenv` provient du runtime Go lui-même (résolution de `PATH` pour `os/exec`, options `GODEBUG`), jamais du code de l'outil. Ce chiffreur n'exfiltre donc rien vers un serveur de commande et contrôle : toute la logique de clé est locale au processus.

Comportement notable également : la fonction `main.selfDelete` relance le processus lui-même via `os/exec.Command` pour se supprimer une fois le travail terminé, un comportement typique d'un outil de type ransomware plutôt que d'un utilitaire de sauvegarde ordinaire.

## 4. Architecture du programme

La table de symboles COFF liste directement les packages internes :

- `internal/crypto` : `DeriveKeyArgon2id`, `deriveFinalKey`, `DeriveKeyMaterial`, `EncryptFileTo`, `DecryptTo`, `VerifyEncryptedMatchesFile`.
- `internal/chv1` : `EncodeHeaderV1`, `DecodeHeaderV1`, `ReadHeaderV1`, `WriteHeaderV1` (format de fichier maison).
- `internal/fswalk` : `IterFiles`, `isEncrypted`, `isTmp`, `shouldExclude` (parcours récursif de répertoire).
- `cmd/encrypter` : `main.main`, `main.encryptOne`, `main.selfDelete`.

`main.main` accepte un flag `-delete` (supprimer les originaux après chiffrement + vérification) et une liste de chemins en argument. Pour chaque fichier trouvé par `fswalk.IterFiles`, un pool de goroutines (une par cœur CPU disponible) appelle `main.encryptOne`, qui ouvre le fichier, appelle `crypto.EncryptFileTo`, synchronise et renomme le résultat, puis optionnellement vérifie l'intégrité via `crypto.VerifyEncryptedMatchesFile` avant de supprimer l'original.

## 5. Le format de fichier `chv1`, décodé et vérifié champ par champ

`chv1.ReadHeaderV1` lit un header de taille fixe : exactement `0x35` = 53 octets, avant tout contenu chiffré. `chv1.DecodeHeaderV1` valide successivement le magic, la version, l'identifiant de KDF, la longueur du sel, l'identifiant de chiffrement et la longueur du nonce de base, avec un message d'erreur explicite pour chaque champ invalide (`"unsupported kdf"`, `"unsupported base nonce length"`, etc., retrouvés en clair dans le binaire).

Décodage complet, vérifié en confrontant chaque champ au fichier réel `HelloWorld.txt.prinzeugen` :

```
offset  taille  champ
0       4       magic "CHV1"
4       1       version (=1)
5       1       identifiant KDF (=1, Argon2id)
6       4       coût mémoire Argon2 en KiB (u32 little-endian)
10      4       coût temps Argon2 / itérations (u32 little-endian)
14      4       parallélisme Argon2 (u32 little-endian)
18      1       longueur du sel (=16, fixe)
19      16      sel (aléatoire, crypto/rand.Read, frais par fichier)
35      1       identifiant de chiffrement (=2, ChaCha20-Poly1305)
36      1       longueur du nonce de base (=4, fixe)
37      4       nonce de base (aléatoire, crypto/rand.Read, frais par fichier)
41      4       taille de chunk (u32 little-endian)
45      8       taille du fichier original (u64 little-endian)

puis, répété par chunk :
        4       longueur du chunk chiffré (u32 little-endian)
        N       texte chiffré + tag d'authentification Poly1305 (16 octets)
```

Sur `HelloWorld.txt.prinzeugen` : Argon2id avec un coût mémoire de 262144 KiB (256 Mo), 3 itérations, parallélisme 2, un unique chunk de taille 1048576 (1 Mo, ici largement suffisant pour les 13 octets du fichier original). Chaque octet des 86 octets du fichier est expliqué par ce décodage, sans reste.

Le nonce par chunk se construit en concaténant les 4 octets aléatoires du header avec un compteur de chunk sur 8 octets, ce qui garantit son unicité à l'intérieur d'un même fichier. Le sel étant lui aussi régénéré aléatoirement à chaque fichier, la clé dérivée diffère d'un fichier à l'autre : pas de réutilisation nonce/clé entre fichiers malgré les 32 bits seulement de nonce aléatoire par fichier.

## 6. Chaîne de dérivation de clé

Reconstituée par décompilation de `crypto.deriveFinalKey`, `crypto.DeriveKeyArgon2id` et `crypto.DeriveKeyMaterial` :

1. Argon2id(mot de passe, sel, temps=3, mémoire=262144 KiB, parallélisme=2) produit 32 octets.
2. SHA-256 de ce résultat (et, si un fichier-clé est fourni, SHA-256 de son contenu concaténé au précédent).
3. HKDF-SHA256 de ce condensé, avec le même sel de 16 octets et une chaîne d'info fixe : `scorched-earth key v1` (21 octets), produit la clé finale de 32 octets utilisée directement comme clé ChaCha20-Poly1305.

Les paramètres Argon2id (256 Mo, 3 itérations, parallélisme 2) sont des constantes codées en dur dans `main.main`, pas des valeurs configurables par ligne de commande : elles sont sérieuses (un coût mémoire de 256 Mo par tentative rend le brute-force GPU/ASIC très coûteux), ce qui, combiné au sel et au nonce authentiquement aléatoires, donnerait un schéma de chiffrement solide **si le mot de passe qui alimente cette chaîne était lui-même secret et fort**.

## 7. Le mot de passe est codé en dur dans le binaire

Aucun flag `-password` n'est enregistré (seul `-delete` l'est), aucune lecture interactive masquée (`golang.org/x/term.ReadPassword` absent de la table de symboles), aucune variable d'environnement propre au programme. Le seul candidat restant, visible dans `main.main`, est un buffer de 32 octets construit une seule fois avant la boucle sur les fichiers et réutilisé pour chaque appel à `encryptOne`.

Le nommage automatique de Ghidra pour cette zone de données est trompeur (il attribue à ce buffer le nom d'une chaîne d'erreur voisine dans `.rdata`). En lisant directement les octets à l'adresse virtuelle réellement référencée par le décompilateur (via `pefile.get_data()`), le contenu apparaît en clair :

```
SUPERCLEDEMORTQUITUE (valeur réelle remplacée pour cette publication)
```

32 caractères alphanumériques imprimables dans le binaire réel : un mot de passe manifestement généré aléatoirement à la compilation, puis embarqué en dur. Il est identique pour tous les fichiers chiffrés par cet exécutable précis, puisqu'il n'est lu qu'une seule fois avant la boucle de traitement. La valeur exacte n'est pas publiée ici (elle a été communiquée séparément à la personne concernée) ; le mécanisme d'extraction et sa validation par déchiffrement réel (§8) restent, eux, entièrement documentés.

## 8. Déchiffrement réel confirmé

Ré-implémentation en Python de la chaîne complète (Argon2id via `argon2-cffi`, HKDF-SHA256 et ChaCha20-Poly1305 via `cryptography`), appliquée au sel et au nonce extraits du fichier réel `HelloWorld.txt.prinzeugen` avec le mot de passe retrouvé ci-dessus :

```python
argon2_out = hash_secret_raw(password, salt, time_cost=3, memory_cost=262144,
                              parallelism=2, hash_len=32, type=Type.ID)
material = hashlib.sha256(argon2_out).digest()
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
           info=b"scorched-earth key v1").derive(material)
nonce = base_nonce + struct.pack("<Q", 0)
ChaCha20Poly1305(key).decrypt(nonce, ciphertext_avec_tag, None)
```

Le tag Poly1305 est validé et le texte clair obtenu correspond exactement à la taille originale annoncée dans le header (13 octets) : `Hello World !`. Le fichier est donc authentifié et déchiffré avec succès, confirmant que le mot de passe retrouvé est le bon.

Un outil autonome, `tools/decrypt_chv1.py`, généralise cette chaîne à n'importe quel fichier produit par ce même binaire, y compris les fichiers occupant plusieurs chunks.

## 9. Confirmation externe : ransomware Prinz Eugen (ThreatDown)

Le nom de projet Go "scorched-earth-ausfc" (§1) est cité littéralement comme IOC dans une analyse publique de ThreatDown (Malwarebytes) publiée sous le nom **"Prinz Eugen ransomware"**, portant sur un échantillon distinct (`servertool.exe`, SHA256 `686213cc11d36af764de824801bced9366dfca3823fe0d51b752f74149bcf1f4`) : correspondance de nom de projet suffisamment spécifique pour ne pas être une coïncidence, cette famille recoupe donc directement l'échantillon de cette analyse.

**Ce que documente ThreatDown, non observé directement ici** (recoupement externe, pas vérifié sur ce binaire) :

| Type | Valeur |
|---|---|
| Infrastructure C2 | `212.80.7.74` (AS215439, Play2go International, Francfort), HTTPS/443 |
| Domaines de phishing | `stndrdbnk.cc` (usurpation Standard Bank), `g-captchafestung.sbs` (faux CAPTCHA), `festung-e.duckdns.org` |
| Leak-site Tor | `prinzfkbjiazbrur4mjje6mntjc4vydx3iatkkzycufoylqcoo4y7pqd.onion` (actif), `6cudc5cqa2bjpwdhcwm2lj6dbqejjjqzeo6ipwvmbazr6cgu7vfk3dad.onion` (inactif) |
| Persistance observée | `net user admin germania /add` |
| Handles d'acteur | ROOTBOY, avtokz, GERMANIA |
| Contacts | `prinzeugen@mail2tor.co`, `standardbankcc@cock.li`, TOX `496187425B2944D73FBB17CAF3F9FD569B9ED3A08A497A8314CB4F27A51E65081ACEE1E22F21` |
| Bitcoin | `bc1q2ztpcvqdaptej6uu2ywt9mrlatx6envu34rf0v` |
| Vecteur d'accès initial | Identifiants RDP compromis, abus de l'outil RMM RemotePC (IDrive) |

**Ce que confirme la présente analyse, chiffrement au niveau code plutôt qu'au niveau comportemental** : ThreatDown décrit le même schéma cryptographique (Argon2id → SHA-256 → HKDF-SHA256, ChaCha20-Poly1305, magic `CHV1`, chiffrement par chunk), confirmant indépendamment le format `chv1` décodé en §5 et la chaîne de clé de §6.

**Divergence notable sur la clé** : ThreatDown affirme, sur leur échantillon, l'absence de mot de passe codé en dur ("clé maître zéroïsée avant sortie"). Sur l'échantillon `fc.exe` de cette analyse, un mot de passe codé en dur **a été extrait et son fonctionnement confirmé par déchiffrement réel** (§7-8). Deux lectures possibles, non tranchées ici faute d'accès à l'échantillon ThreatDown : un défaut de build spécifique à cet exemplaire (cohérent avec §10, mot de passe régénéré par compilation), ou une clé présente mais non localisée dans leur analyse. Dans les deux cas, la voie de récupération décrite dans `remediation.md` n'est démontrée que pour un binaire présentant ce défaut, pas pour l'ensemble de la famille.

**Étendue non couverte par cette analyse** : `fc.exe` correspond au chemin `cmd/encrypter/main.go` (§1), soit uniquement le module de chiffrement de fichiers. Toute l'infrastructure listée ci-dessus (C2, persistance, phishing, RMM) provient d'un binaire distinct (`servertool.exe`) non examiné ici.

## 10. Conclusion

Le schéma cryptographique lui-même (Argon2id, HKDF-SHA256, ChaCha20-Poly1305, sel et nonce tirés d'un vrai générateur aléatoire système) est correctement construit et ne présente aucune faiblesse structurelle. La faille se situe entièrement dans la gestion de la clé : un mot de passe généré une fois à la compilation puis figé en dur dans l'exécutable, identique pour toutes les exécutions de ce binaire précis. Quiconque récupère ce fichier `fc.exe` peut en extraire le mot de passe et déchiffrer l'intégralité des fichiers qu'il a produits, sans avoir besoin de casser la moindre primitive cryptographique.

Cette faiblesse est spécifique au binaire embarquant ce mot de passe précis : si le même outil est recompilé (mot de passe régénéré à chaque compilation, à en juger par son caractère manifestement aléatoire), un autre exemplaire du binaire embarquerait un mot de passe différent, qu'il faudrait retrouver indépendamment par la même méthode.

Le rattachement à la famille Prinz Eugen (§9) élargit la portée pratique de cette faille : les organisations victimes de cette famille, si elles peuvent mettre la main sur le binaire de chiffrement (`fc.exe` ou équivalent) plutôt que sur le seul C2, ont une chance concrète d'y trouver le même défaut plutôt que de devoir payer une rançon ou perdre leurs données.
