# Signalement OCLCTIC : Campagne Efimer/ClickFix

**Destinataire :** OCLCTIC-DST via PHAROS  
**Plateforme :** https://www.internet-signalement.fr  
**Ou email direct :** oclctic@interieur.gouv.fr  
**Objet :** Signalement campagne malware active, Clipper crypto + botnet WordPress (famille Efimer/ClickFix), SHA256 inclus  
**Date :** 2026-07-17  
**Analyste :** Gordon PEIRS

---

À l'attention de l'OCLCTIC-DST,

Je suis analyste en malware et vous contacte suite à la découverte et l'analyse complète d'une campagne criminelle active ciblant des utilisateurs de cryptomonnaies via une technique dite "ClickFix".

## Résumé de la menace

| Champ | Valeur |
|-------|--------|
| Famille | Efimer (dropper PyInstaller + PyArmor) |
| Vecteur | ClickFix (page web malveillante forçant exécution manuelle) |
| Actif depuis | 2026-07-12 (≥ 100 samples sur MalwareBazaar en 5 jours) |
| Double mission | Vol de cryptomonnaies (clipboard hijacking) + botnet de bruteforce WordPress |
| Infrastructure | C2 full-Tor v3 (3 hidden services indépendants) |
| SHA-256 sample | `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4` |

## Élément prioritaire : Piste KYC (actionnable)

L'analyse blockchain des fonds entrants sur le wallet de l'attaquant révèle deux dépôts provenant d'exchanges soumis aux obligations KYC :

**Dépôt 1, 2025-03-26 :**
- Source : `bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h`
- Volume total : 59 571 438 BTC reçus (cumul historique de flux, pas un solde, voir note*) / 2 274 664 TX → Exchange de niveau supérieur (Binance/Coinbase tier)
- Montant : 0.00096260 BTC → `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0`

**Dépôt 2, 2026-05-30 (jour du build du malware) :**
- Chemin : `bc1qx9n80t5q7tfmutzaj0ramzzzsvtveara68zntc` → `bc1qgrnp6pv7gkjcway23yj9wd83emnpcht43ta0rm` (relais) → `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` (attaquant)
- Cluster bc1qx9n80 : 628 396 BTC reçus (cumul historique*), 1 448 adresses associées → Exchange majeur avec KYC obligatoire
- Montant : 0.00444391 BTC

*Note : ces volumes sont le cumul de tout ce qu'une adresse hub d'exchange a jamais reçu (des millions de transactions font repasser les mêmes BTC des milliers de fois par la même adresse au fil des années), pas un solde ni une preuve de détention. Vérifié en direct sur mempool.space, cohérent avec les chiffres ci-dessus.

**Implication :** l'auteur possède des comptes enregistrés sur au minimum deux plateformes d'exchange soumises à KYC. Une demande d'entraide judiciaire (MLAT/ENTR) ou une réquisition directe à ces plateformes permettrait d'identifier l'auteur (documents d'identité, adresse IP de connexion, compte bancaire de sortie).

**Chaîne de retrait BTC documentée :**
```
bc1qz33n9... → bc1q5acrlm0j5ljh2t4fpmxasaeaqkc5j32z5h634y (intermédiaire, vidé en 1h30)
             → bc1qns9f7yfx3ry9lj6yz7c9er0vwa0ye2eklpzqfw
               (15 228 010 BTC cumulés, pool Binance probable)
```

## Adresses crypto de l'auteur (hardcodées dans le binaire)

| Format | Adresse |
|--------|---------|
| BTC P2PKH | `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4` |
| BTC P2SH | `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW` |
| BTC Bech32 | `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` |
| TRX (TRON) | `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` |
| XMR | `87Y35DbRFf2G2PyghoVAox4tsxfxqwjZh3AMaxrkjasBNW4rmQWs9hfanP5haACxfnXrKPZoesSP18XciY8xVaoY5MLitaW` |

## Identité de la machine de build (fuite OPSEC)

Le malware contient accidentellement les artefacts de compilation de l'attaquant (module `campus.py`, archive RAR interne) :

| Information | Valeur |
|-------------|--------|
| Hostname | `DESKTOP-UOB4Aig` |
| OS | Windows 10/11 |
| Utilisateur local | `User` (nom générique, probable pseudonyme) |
| CPU | Intel Arrow Lake, Family 6 Model 198 Stepping 2 (Core Ultra 200 series, sortie oct. 2024) |
| Processeurs | 8 (machine physique personnelle, pas une VM) |
| Stack de développement | Python 3.13, LLVM/Clang, VS Code, Node.js, Go, WireGuard VPN |
| Date de build | 2026-05-30 04:49:41 UTC |
| Chemin de build | `C:\Users\User\Desktop\pyinstaller-6.20.0\` |

## Flux financier TRX : exchange no-KYC (FixedFloat)

| Champ | Valeur |
|-------|--------|
| Wallet attaquant | `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` |
| Total reçu | ~375 USDT-TRC20 |
| Virement sortant | 2026-05-13 → `TY9wnbgAynRMse2UHC3boo28UFQNnJLiTu` |
| Destination finale | `TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf` (FixedFloat Exchange Hot Wallet, no-KYC) |

Paiement entrant notable : 2026-05-04, 330 USDT reçus de `TTgSknazmXS4Pgvdfa8kmFaBiXumLcatLq` (wallet créé le 2026-04-20, 68 TX de volume, probable acheteur d'accès au malware, modèle MaaS).

## Infrastructure C2

| Rôle | Adresse Tor v3 |
|------|---------------|
| Clipper (exfiltration) | `hek5ensy7wqqls2cafflihs7sdqr4dwxux47vp3k7pgffeasxsfeeyid.onion/route.php` |
| Clipper (mises à jour) | `swjxev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qbkbakh6wnyead.onion/core/repla.php` |
| Botnet WordPress | `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion/route.php` |

## Pièces jointes disponibles

- Writeup technique complet (18 sections, 1 500+ lignes)
- Règle YARA (détecte 100+ samples, fichier `efimer_dropper.yar` joint)
- Table IoCs journaliers 2026-07-12 → 2026-07-31
- Graphe de flux blockchain
- Sample disponible sur MalwareBazaar, tag : `efimer`, SHA-256 : `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4`

Je reste disponible pour fournir toute précision technique ou pièce complémentaire utile à une enquête.

Cordialement,  
Gordon PEIRS  
Analyste malware indépendant
