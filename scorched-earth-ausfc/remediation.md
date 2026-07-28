# Guide de détection et remédiation : ransomware Prinz Eugen (module de chiffrement, mot de passe codé en dur)

Destiné à quelqu'un qui doit vérifier ou récupérer des fichiers chiffrés par cet outil, pas à un public d'analystes. Basé sur les constats de [`writeup.md`](writeup.md). Le contexte de campagne (§6) provient d'une analyse externe (ThreatDown) portant sur un binaire distinct de la même famille, pas observé directement dans cette analyse : à traiter comme un recoupement, pas une confirmation locale.

## 1. Suis-je concerné ?

Fichiers renommés avec l'extension `.prinzeugen`. Le binaire responsable (`fc.exe`) se relance lui-même pour se supprimer une fois le travail terminé (`main.selfDelete`), il peut donc ne plus être présent sur le disque après coup.

## 2. Récupération : le mot de passe est dans le binaire, pas dans votre tête

**Contrairement à un ransomware classique, aucune clé secrète détenue par un tiers n'est nécessaire ici.** Le mot de passe qui protège tous les fichiers chiffrés par un exemplaire donné de cet outil est généré une seule fois à la compilation, puis codé en dur dans le binaire. Si vous disposez du binaire responsable (`fc.exe` ou équivalent) :

1. Utiliser [`tools/decrypt_chv1.py`](tools/decrypt_chv1.py) FICHIER.prinzeugen pour déchiffrer un fichier individuel (gère les fichiers multi-chunks).
2. Pour un dossier entier, utiliser [`tools/restore_all.py`](tools/restore_all.py) DOSSIER, qui sauvegarde systématiquement les fichiers `.prinzeugen` avant toute action, restaure chaque fichier avec vérification du tag Poly1305 (les échecs de déchiffrement ne touchent jamais à l'original), et ne supprime les originaux qu'en option explicite (`--clean`), jamais par défaut.

**Si le binaire responsable n'est pas disponible**, le mot de passe codé en dur (`writeup.md` §7) est spécifique à cet exemplaire précis du binaire (généré à la compilation) : il ne fonctionnera pas nécessairement sur des fichiers produits par un autre exemplaire recompilé de l'outil. Il faut alors reproduire la même méthode d'extraction sur le binaire concerné.

## 3. Ce que ce binaire précis n'est pas

Le module de chiffrement (`fc.exe`) n'a aucune capacité réseau (table d'imports PE réelle vérifiée : uniquement `kernel32.dll`, fonctions process/mémoire) : ce n'est pas lui qui exfiltre ou communique avec un C2. Le comportement d'auto-suppression après exécution (`main.selfDelete`) est en revanche typique d'un usage malveillant plutôt que d'un outil de sauvegarde légitime laissé volontairement en place. La famille dans son ensemble (§6) a bien une infrastructure C2 et de persistance, mais portée par un binaire distinct (`servertool.exe` selon ThreatDown), pas par ce module de chiffrement.

## 4. Nettoyage

1. Conserver une copie des fichiers `.prinzeugen` avant toute tentative de récupération (l'outil `restore_all.py` le fait automatiquement).
2. Une fois la récupération vérifiée (tag Poly1305 validé, contenu cohérent), les fichiers chiffrés d'origine peuvent être supprimés en toute sécurité.
3. Si le binaire responsable est retrouvé sur une machine, le conserver comme preuve avant suppression : c'est la seule source du mot de passe pour cet exemplaire.

## 5. Réduction de surface d'attaque

- Si l'origine de ce binaire sur votre machine n'est pas identifiée (pas un outil que vous avez vous-même déployé), traiter l'incident comme une compromission plus large : la présence de cet outil suppose un accès préalable à la machine.
- Aucune capacité de propagation ou de persistance n'a été identifiée dans ce binaire précis (statique uniquement). Selon ThreatDown (§6), l'accès initial de cette famille passe typiquement par des identifiants RDP compromis et l'abus de l'outil RMM légitime RemotePC (IDrive) : vérifier les connexions RDP et RemotePC non autorisées, pas seulement la présence du binaire de chiffrement.

## 6. Contexte de campagne (source externe, non vérifié localement)

D'après l'analyse ThreatDown de la famille Prinz Eugen (portant sur un échantillon distinct, `servertool.exe`) :

| Type | Valeur |
|---|---|
| Infrastructure C2 | `212.80.7.74` (HTTPS/443) |
| Domaines de phishing | `stndrdbnk.cc` (usurpation Standard Bank), `g-captchafestung.sbs`, `festung-e.duckdns.org` |
| Leak-site Tor | `prinzfkbjiazbrur4mjje6mntjc4vydx3iatkkzycufoylqcoo4y7pqd.onion` |
| Persistance observée | création d'un compte local `germania` (`net user admin germania /add`) |
| Vecteur d'accès initial | identifiants RDP compromis, abus de RemotePC (IDrive) |

Vérifier en priorité la présence d'un compte local `germania` non reconnu et les connexions RDP/RemotePC suspectes. Signaler hash et IOCs à un CERT national ou à abuse.ch ; cette famille cible des organisations avec usurpation de marque (Standard Bank) à des fins de phishing, pas uniquement du chiffrement opportuniste.
