# Analyse Prinz Eugen (module encrypter) : mot de passe codé en dur derrière un chiffrement par ailleurs sain

Reverse engineering statique du module de chiffrement (`fc.exe`, Go, non strippé) du ransomware **Prinz Eugen**, identifié par recoupement du nom de projet Go embarqué ("scorched-earth-ausfc") avec une analyse publique de ThreatDown (Malwarebytes). Fourni directement pour analyse avec un fichier réellement chiffré à récupérer, sans mot de passe connu au départ. Le schéma cryptographique (Argon2id, HKDF-SHA256, ChaCha20-Poly1305, sel et nonce tirés d'un vrai CSPRNG) est correctement construit, mais le mot de passe qui l'alimente est généré une fois à la compilation puis codé en dur dans le binaire, identique pour tous les fichiers chiffrés par cet exemplaire précis. Déchiffrement réel confirmé (tag Poly1305 validé) sur le fichier fourni. ThreatDown ne rapporte pas ce défaut sur leur propre échantillon (`servertool.exe`, un binaire distinct du même dépôt) : voir `writeup.md` §9 pour la divergence.

**Analyste :** Gordon PEIRS ([@ozer0x777](https://github.com/Ozer0x777)) · **Méthode :** statique (Ghidra headless via PyGhidra, décompilation par nom de symbole Go), aucune exécution du binaire. Déchiffrement validé par ré-implémentation Python indépendante de la chaîne cryptographique complète.

## Documents

| Document | Contenu |
|---|---|
| [writeup.md](writeup.md) | Analyse complète : triage, architecture du programme, format de fichier `chv1` décodé champ par champ, chaîne de dérivation de clé, localisation du mot de passe codé en dur, déchiffrement réel confirmé, confirmation externe et attribution à la famille Prinz Eugen (ThreatDown) |
| [runbook.md](runbook.md) | Log de reproduction pas à pas |
| [remediation.md](remediation.md) | Détection, récupération de fichiers chiffrés par cet outil et recommandations |
| [scorched_earth_ausfc.yar](scorched_earth_ausfc.yar) | Règles YARA (chemin de build interne + packages Go caractéristiques) |
| [tools/decrypt_chv1.py](tools/decrypt_chv1.py) | Déchiffreur générique pour tout fichier `.prinzeugen` produit par ce binaire (format `chv1`, gère les fichiers multi-chunks) |
| [tools/restore_all.py](tools/restore_all.py) | Restauration complète d'un dossier : sauvegarde systématique des fichiers chiffrés, déchiffrement avec vérification d'intégrité, nettoyage optionnel des originaux uniquement après succès vérifié |
| [tools/decompile_by_name.py](tools/decompile_by_name.py) | Décompile une fonction Ghidra par son nom de symbole Go complet |

## Ce que ce dossier ne contient pas (volontairement)

Le binaire n'est pas versionné. Cette analyse porte uniquement sur le module de chiffrement (`fc.exe`) : l'infrastructure C2, la persistance et le vecteur d'accès initial documentés par ThreatDown pour cette famille proviennent d'un binaire distinct non examiné ici (voir `writeup.md` §9).
