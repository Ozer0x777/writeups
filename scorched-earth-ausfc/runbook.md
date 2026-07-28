# Runbook : reproduction pas à pas (scorched-earth-ausfc)

## A. Acquisition et triage initial

```bash
unzip -l Archive.zip
# -> un seul fichier : fc.exe (pas de mot de passe sur l'archive)
unzip -o Archive.zip -d /tmp/inspect
sha256sum fc.exe
file fc.exe   # PE32+ executable for MS Windows 6.01 (console), x86-64, 16 sections
```

```python
import pefile
pe = pefile.PE("fc.exe", fast_load=True)
pe.parse_data_directories()
for s in pe.sections:
    print(s.Name.decode(errors="ignore").strip("\x00"), round(s.get_entropy(), 2))
for e in pe.DIRECTORY_ENTRY_IMPORT:
    print(e.dll.decode())
```
Retour : sections nommées `/4`, `/19`, `/32`... (noms longs COFF via table de chaînes, typique MinGW/Go), section `.symtab` présente, seul `kernel32.dll` importé directement. Ces indices pointent vers un binaire Go (confirmé ensuite).

```bash
strings -n 8 fc.exe | grep -iE "go1\.|golang|Go build ID"
```
Retour : `go1.26.2`, `golang.org/x/crypto/argon2`, `golang.org/x/crypto/chacha20poly1305`, `golang.org/x/crypto/hkdf`, `golang.org/x/crypto/blake2b`.

```bash
strings -n 6 fc.exe | grep -iE "C:/Users|scorched|main\.go"
```
Retour : `C:/Users/User/source/scorched-earth-ausfc/cmd/encrypter/main.go`, `mod scorched-earth-ausfc (devel)`. Recherche web du nom de projet : infructueuse, pas de dépôt public trouvé.

## B. Extraction des symboles Go (binaire non strippé)

```bash
objdump -t fc.exe | grep -i "crypto\.\|chv1\.\|fswalk\."
```
Retour : table de symboles COFF complète avec noms de packages/fonctions Go en clair (`scorched-earth-ausfc/internal/crypto.DeriveKeyArgon2id`, `.deriveFinalKey`, `.EncryptFileTo`, `.DecryptTo`, `.VerifyEncryptedMatchesFile`, `internal/chv1.EncodeHeaderV1`/`DecodeHeaderV1`/`ReadHeaderV1`/`WriteHeaderV1`, `internal/fswalk.IterFiles`/`isEncrypted`/`isTmp`/`shouldExclude`).

## C. Décompilation par nom de symbole (Ghidra headless, PyGhidra)

Outil créé pour cette investigation, généralise `decompile_addr.py` d'incransom/pay2key en résolvant l'adresse par nom de symbole Ghidra plutôt que par adresse fournie à la main (le binaire Go non strippé rend ça possible et bien plus rapide) :

```bash
python3 tools/decompile_by_name.py fc.exe keycore.txt \
  "scorched-earth-ausfc/internal/crypto.DeriveKeyArgon2id" \
  "scorched-earth-ausfc/internal/crypto.deriveFinalKey" \
  "scorched-earth-ausfc/internal/crypto.DeriveKeyMaterial"
```
Retour : chaîne de dérivation de clé complète : Argon2id -> SHA-256 -> HKDF-SHA256, sel de 16 octets. Détail dans writeup.md §6.

```bash
python3 tools/decompile_by_name.py fc.exe encrypt_main.txt \
  "scorched-earth-ausfc/internal/crypto.EncryptFileTo"
```
Retour : confirme `crypto/rand.Read` pour le sel (16 octets) et le préfixe de nonce (4 octets), `chacha20poly1305.New`, boucle de chiffrement par chunks avec nonce = préfixe aléatoire || compteur de chunk (12 octets), hash SHA-256 du texte clair en parallèle (probablement pour `VerifyEncryptedMatchesFile`).

```bash
python3 tools/decompile_by_name.py fc.exe nonce_header.txt \
  "scorched-earth-ausfc/internal/crypto.nonceForChunk" \
  "scorched-earth-ausfc/internal/chv1.EncodeHeaderV1"
```
Retour : `nonceForChunk` introuvable comme symbole distinct (confirmé par `objdump -t | grep -i nonce` : aucun résultat), probablement inlinée par le compilateur Go dans `EncryptFileTo` (cohérent avec ce qui a été vu directement dans cette dernière). `EncodeHeaderV1` : `DECOMPILE FAILED` sur la première tentative, retentée avec succès ensuite.

## D. Décodage du format `chv1` sur un fichier chiffré réel

Contexte : un fichier réellement chiffré a été fourni en complément du binaire, `HelloWorld.txt.prinzeugen` (86 octets).

```bash
python3 tools/decompile_by_name.py fc.exe header_v1.txt \
  "scorched-earth-ausfc/internal/chv1.WriteHeaderV1" \
  "scorched-earth-ausfc/internal/chv1.DecodeHeaderV1" \
  "scorched-earth-ausfc/internal/chv1.ReadHeaderV1"
```
Retour clé : `ReadHeaderV1` lit exactement `0x35` = 53 octets fixes (taille du header). `DecodeHeaderV1` valide successivement : magic `0x31564843`="CHV1" (LE), byte[4]==1 (version), byte[5]==1 (kdf, sinon erreur "unsupported kdf"), byte[0x12]=byte[18]==0x10=16 (longueur du sel, copie depuis l'offset 0x13=19, soit exactement le sel), byte[0x23]=byte[35]==2 (cipher id, sinon erreur de 22 caractères), byte[9*4]=byte[36]==4 (longueur du nonce de base, sinon erreur "unsupported base nonce length").

Décodage complet et vérification arithmétique sur le fichier réel :
```python
import struct
data = open("HelloWorld.txt.prinzeugen","rb").read()
print("magic:", data[0:4], "version:", data[4], "kdf_id:", data[5])
print("argon2 memory KiB:", struct.unpack("<I", data[6:10])[0])
print("argon2 time:", struct.unpack("<I", data[10:14])[0])
print("argon2 parallelism:", struct.unpack("<I", data[14:18])[0])
print("salt:", data[19:35].hex())
print("cipher_id:", data[35], "base_nonce_len:", data[36])
print("base_nonce:", data[37:41].hex())
print("chunk_size:", struct.unpack("<I", data[41:45])[0])
print("orig_size:", struct.unpack("<Q", data[45:53])[0])
chunk_len = struct.unpack("<I", data[53:57])[0]
print("chunk_ct_len:", chunk_len)
print("total accounted:", 57+chunk_len, "== filelen", len(data))
```
Retour : chaque champ vérifié, 86/86 octets du fichier expliqués sans reste. Argon2id memory=262144 KiB (256 Mo), time=3, parallelism=2, chunk_size=1048576 (1 Mo), taille originale=13 octets, un seul chunk (13+16 tag=29 octets). Détail dans writeup.md §5.

## E. Recherche du mot de passe : capacités réseau, env, CLI, puis constante codée en dur

```bash
grep -iE "net/http|net\.Dial|crypto/tls|smtp|webhook" /tmp/all_syms.txt   # vide : pas de capacite reseau
grep -iE "flag\.String|term\.ReadPassword|os\.Getenv|Password" /tmp/all_syms.txt
python3 tools/decompile_by_name.py fc.exe getenv_callers.txt "os.Getenv"
# -> tous les appelants sont des internes Go/stdlib (os/exec, golang.org/x/sys/cpu), jamais le code du binaire
```

```bash
python3 tools/decompile_by_name.py fc.exe main_flow.txt "main.main" "main.encryptOne" "main.selfDelete"
```
Retour : `main.main` construit un buffer de 32 octets une seule fois avant la boucle de fichiers (variable nommée de façon confuse par Ghidra, ex. `s_timeBegin_EndPeriod_not_foundtri_14014b199._3387_8_`), réutilisé pour chaque appel à `encryptOne`. `main.selfDelete` confirme l'auto-suppression après usage (`os.Executable()` + `os/exec.Command`).

Localisation des octets bruts réels (contourner le nommage confus de Ghidra, lire directement l'adresse virtuelle référencée via `pefile`) :
```python
import pefile
pe = pefile.PE("fc.exe", fast_load=True)
imagebase = pe.OPTIONAL_HEADER.ImageBase
addr = 0x14014b199 + 3387   # adresse de base du symbole + offset relatif lu dans le decompile
rva = addr - imagebase
print(pe.get_data(rva, 32))
```
Retour : `b'SUPERCLEDEMORTQUITUE'` (valeur réelle remplacée pour cette publication), 32 caractères ASCII dans le binaire réel, mot de passe codé en dur.

Même technique pour retrouver la chaîne d'info HKDF (`DAT_140148620`-ish dans `DeriveKeyMaterial`, ajustée de quelques octets pour tomber sur le bon début de chaîne) : `b'scorched-earth key v1'` (21 octets).

## F. Déchiffrement réel confirmé

```python
import hashlib, struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

data = open("HelloWorld.txt.prinzeugen","rb").read()
salt, base_nonce, ct = data[19:35], data[37:41], data[57:57+29]
password = b"SUPERCLEDEMORTQUITUE"  # valeur reelle remplacee pour cette publication

argon2_out = hash_secret_raw(password, salt, time_cost=3, memory_cost=262144, parallelism=2, hash_len=32, type=Type.ID)
material = hashlib.sha256(argon2_out).digest()
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"scorched-earth key v1").derive(material)
nonce = base_nonce + struct.pack("<Q", 0)
print(ChaCha20Poly1305(key).decrypt(nonce, ct, None))
# -> b'Hello World !'
```
**Déchiffrement réussi, tag Poly1305 validé.** Outil générique créé : `tools/decrypt_chv1.py FICHIER.prinzeugen [SORTIE]`, gère les fichiers multi-chunks. Détail dans writeup.md §8.

## Conclusion (premier passage)

Aucune faille évidente trouvée sur le sel et le nonce, qui viennent de `crypto/rand` (CSPRNG réel), pas de seed temporelle ni de PRNG faible : la faille identifiée par la suite se situe dans le mot de passe codé en dur (writeup.md §7), pas dans cette partie du schéma.
