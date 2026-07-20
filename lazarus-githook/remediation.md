# Remediation — Lazarus githook (DEV#POPPER)

## Indicateurs de compromission (IoCs)

### Réseau

| Indicateur | Rôle |
|---|---|
| `144.172.103.226` | Serveur de staging (stage 0 → 1), HTTP |
| `95.217.102.138:1144` | C2 stage 2, chemin `/s/30620700`, HTTP |
| `95.216.64.240:1224` | C2 Python HTTP — beacon `/keys`, uploads, commandes `/brow/*` |
| `69.197.164.135:2245` | C2 RAT TCP brute — canal de contrôle interactif persistant |
| `pub-acf013a9b65140b7b58cc3c104ee7105.r2.dev` | CDN Cloudflare R2 (payload Windows `p.zip`) |
| `pub-06714264305c44ea94491c0c8d961a87.r2.dev` | CDN Cloudflare R2 (payload Linux `plinux.tar.xz`, macOS `pmac.tar.gz`) |
| `ip-api.com` | Géolocalisation passive (appelé par le backdoor comms) |

### Système de fichiers

| Plateforme | Chemin | Description |
|---|---|---|
| Linux | `~/.viminf` | Script Node.js (stage 3 persisté sur disque) |
| Linux | `~/.config/autostart/PyToolUpdater.desktop` | Mécanisme de persistance XDG autostart |
| macOS | `~/.viminf` | Script Node.js (stage 3 persisté sur disque) |
| macOS | `~/.zprofile` | Bloc bootstrap injecté entre marqueurs `# >>> PyToolUpdater bootstrap >>` |
| macOS | `/tmp/PyToolUpdater.pid` | PID file anti-doublon du bootstrap |
| macOS | `/tmp/PyToolUpdater.log` | Log stderr du processus persisté |
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PyToolUpdater` | Clé registre de persistance |
| Linux/macOS | `~/.n2/` | Répertoire de travail RAT (flist = journal uploads, bow = browser stealer) |
| Linux/macOS | `~/.n3/` | Répertoire de staging stage 1 JS stealer (crypto wallets, données navigateur) |
| Tous | `.poc2` (répertoire courant) | Lock file du module comms Python |
| Tous | `p.zip` / `plinux.tar.xz` / `pmac.tar.gz` | Archives temporaires dans `tmpdir()` |

---

## Détection

### Réseau (pare-feu / proxy / EDR)

```
# Bloquer les IPs C2 (toutes directions)
144.172.103.226
95.217.102.138
95.216.64.240
69.197.164.135    # RAT TCP - à bloquer en priorité (canal de contrôle interactif)

# Port TCP non-standard à surveiller
:2245             # connexion TCP sortante persistante vers 69.197.164.135

# Bloquer les domaines R2 (exfiltration payload)
pub-acf013a9b65140b7b58cc3c104ee7105.r2.dev
pub-06714264305c44ea94491c0c8d961a87.r2.dev

# Détecter la balise C2 stage 2 (pattern URL)
http://*/s/30620700
```

### Processus / comportemental

- Processus `node` lancé depuis un hook git (`post-checkout`, `pre-commit`) avec argument `-e <code>`
- Enfant `node` avec `detached: true` et `stdio: 'ignore'`
- Accès réseau de `node` vers `95.217.102.138:1144` depuis le répertoire d'un projet git
- Processus Python établissant une connexion TCP persistante vers `69.197.164.135:2245`
- Écriture dans `HKCU\...\CurrentVersion\Run\PyToolUpdater`
- Création de `~/.config/autostart/PyToolUpdater.desktop` (Linux)
- Modification de `~/.zprofile` avec ajout de bloc entre marqueurs `PyToolUpdater bootstrap` (macOS)
- Création de `~/.n2/` et accès récurrent à `~/.n2/flist`
- Création de `~/.n3/` et accès aux répertoires `Local Extension Settings` des navigateurs (stage 1 JS stealer)

### YARA

Les règles `lazarus_githook.yar` couvrent les 6 fichiers de la chaîne. Lancer sur :
- Tous les hooks git dans `~/.git/hooks/` ou `.git/hooks/` des projets
- Répertoires temporaires (`/tmp`, `%TEMP%`)
- Répertoire de l'utilisateur (recherche récursive)

```bash
yara -r lazarus_githook.yar ~/.git/hooks/ /tmp/ ~/ 2>/dev/null
```

### Audit git hooks

```bash
# Trouver tous les hooks exécutables dans les projets git accessibles
find ~ -path '*/.git/hooks/*' -type f -executable 2>/dev/null

# Vérifier chaque hook pour les patterns suspects
grep -rl '144\.172\.103\.\|95\.21[67]\.\|/301/' ~/.git/hooks/ $(find ~ -path '*/.git/hooks' -type d 2>/dev/null) 2>/dev/null
```

---

## Nettoyage

### Linux

```bash
# 1. Supprimer le mécanisme de persistance XDG autostart
rm -f ~/.config/autostart/PyToolUpdater.desktop

# 2. Supprimer le payload Node.js
rm -f ~/.viminf

# 3. Supprimer les répertoires de travail du malware
rm -rf ~/.n2/   # RAT Python
rm -rf ~/.n3/   # Stage 1 JS stealer (staging wallets crypto)

# 4. Supprimer le lock file backdoor
rm -f .poc2           # dans chaque répertoire de projet compromis

# 5. Tuer les processus backdoor en cours
pkill -f "viminf"
pkill -f "95.216.64.240"
pkill -f "69.197.164.135"

# 6. Supprimer le git hook compromis
rm -f /chemin/du/projet/.git/hooks/post-checkout
rm -f /chemin/du/projet/.git/hooks/pre-commit
```

### macOS

```bash
# 1. Nettoyer le bloc bootstrap dans ~/.zprofile
# Repérer les marqueurs et supprimer le bloc entre eux
sed -i '' '/# >>> PyToolUpdater bootstrap >>/,/# <<< PyToolUpdater bootstrap <</{d;}' ~/.zprofile

# 2. Supprimer les fichiers temporaires du bootstrap
rm -f /tmp/PyToolUpdater.pid
rm -f /tmp/PyToolUpdater.log

# 3. Supprimer le payload Node.js
rm -f ~/.viminf

# 4. Supprimer les répertoires de travail du malware
rm -rf ~/.n2/   # RAT Python
rm -rf ~/.n3/   # Stage 1 JS stealer

# 5. Supprimer lock file et hooks
rm -f .poc2
rm -f /chemin/du/projet/.git/hooks/post-checkout
```

### Windows

```powershell
# 1. Supprimer la clé de registre de persistance
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                    -Name "PyToolUpdater" -ErrorAction SilentlyContinue

# 2. Identifier et supprimer le binaire PyToolUpdater
# Lire la valeur pour trouver le chemin exact
(Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run").PyToolUpdater

# Tuer le processus puis supprimer
Stop-Process -Name "PyToolUpdater" -Force -ErrorAction SilentlyContinue
# Supprimer le fichier (chemin lu à l'étape précédente)

# 3. Supprimer le git hook compromis
Remove-Item "C:\chemin\projet\.git\hooks\pre-commit" -ErrorAction SilentlyContinue
```

---

## Actions post-incident

1. **Rotation des identifiants navigateur** : si le module comms ou le stealer a tourné, tous les navigateurs ciblés sont compromis (Chrome, Brave, Opera, Edge, Yandex). Mots de passe et **numéros de carte bancaire** exfiltrés via `credit_cards` SQLite.

1b. **Rotation des wallets crypto** : stage 1 JS cible 22 extensions Chrome dont MetaMask, Phantom (Solana) et Binance Chain Wallet — toutes les données `Local Extension Settings` sont exfiltrées vers `95.216.64.240:1224/uploads`. Le keypair Solana CLI (`~/.config/solana/id.json`) et le wallet Exodus sont également ciblés. Si ces wallets étaient présents sur le système compromis, considérer les clés privées comme exposées et transférer les fonds sur de nouvelles adresses générées sur un système propre. Supprimer `~/.n3/` si présent.

2. **Rotation des tokens d'API** : tous les fichiers `.env` du système ont pu être uploadés (`ssh_env`, code 8). GitHub, npm, AWS, GCP, tout token en clair dans un `.env` est à invalider.

3. **Révision de la clipboard** : le keylogger Windows capture également le presse-papier. Tout secret copié-collé pendant la période de compromission est exposé.

4. **Vérification des connexions TCP sortantes** : chercher dans les logs réseau des connexions persistantes vers `69.197.164.135:2245` (reconnexion avec backoff exponentiel, difficile à détecter sans inspection des ports).

5. **Audit `~/.n2/flist`** : si le fichier existe, il liste chaque fichier uploadé au C2 (timestamp + chemin local complet).

6. **Audit des commits récents** : vérifier qu'aucun code malveillant n'a été intégré depuis le système compromis.

7. **Réinstallation propre des hooks git** : après nettoyage, auditer tous les projets git locaux pour des hooks non vérifiés.
