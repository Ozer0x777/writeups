# Guide de détection et remédiation : InfernoGrabber (leurre AI DeepSeek, File System Access API + stealer Python)

Destiné à quelqu'un qui doit vérifier ou nettoyer un système, pas à un public d'analystes. Basé sur les constats de [`writeup.md`](writeup.md).

Deux vecteurs distincts : (1) la page web abusant la File System Access API, (2) l'exécution directe du script Python.

## 1. Suis-je concerné ?

### Vecteur 1 : page web malveillante (File System Access API)

Vous avez visité une page présentée comme un outil d'amélioration d'avatars Discord ("AI Discord Avatar Upscaler") et autorisé l'accès à un dossier local via la boîte de dialogue du navigateur.

**Indicateur :** un onglet Chromium, Chrome ou Edge a affiché une boîte de dialogue "Choisir un dossier" ou "Autoriser l'accès à [nom du dossier]", et vous avez cliqué "Autoriser".

**Périmètre réel :** une seule autorisation donne un accès récursif en lecture à l'intégralité du dossier choisi et de tous ses sous-dossiers. Si vous avez pointé vers Documents, Bureau, ou un dossier parent, la totalité de l'arborescence est accessible côté page.

### Vecteur 2 : exécution du script Python

Le fichier `deepseek_python_20260125_da0631.py` (SHA256 `07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5`) a été exécuté localement, avec ses dépendances (`selenium`, `pyautogui`, `GPUtil`).

**Note :** au moment de l'analyse, le webhook Discord d'exfiltration est confirmé mort. Dans les deux sandboxes testées, aucune exfiltration réseau n'a abouti faute de dépendances. L'impact concret dépend de l'environnement d'exécution.

## 2. Ce qui peut avoir été exfiltré

**Via la page web (Vecteur 1) :**

- Tout fichier du dossier autorisé et de ses sous-dossiers, en lecture récursive complète
- L'accès est donné pour la durée de la session navigateur (révocable, voir §3)

**Via le script Python (Vecteur 2, si les dépendances étaient présentes) :**

- Cookies, tokens de session, identifiants de navigateurs Chromium (`User Data/Default/Cookies`, `Login Data`)
- Tokens Discord
- Numéros de cartes bancaires
- Adresses de portefeuilles crypto
- Frappes clavier (si `pyautogui` disponible)
- Captures d'écran, flux webcam, enregistrements microphone
- Données collectées localement dans `inferno.db` (SQLite)

## 3. Nettoyage

**Vecteur 1 (page web) :**

1. Révoquer l'autorisation accordée dans le navigateur :
   - Chrome/Edge : `chrome://settings/content/filesystem` ou icône de cadenas dans la barre d'adresse > Autorisations de site > Fichiers
   - L'accès est résilié immédiatement, aucun fichier local n'est modifié par l'accès seul en lecture
2. Aucune persistance locale ne résulte de la page web seule.

**Vecteur 2 (script Python) :**

1. Supprimer le script Python et ses dépendances installées.
2. Chercher et supprimer `inferno.db` (base de collecte locale) :
   ```bash
   find ~ -name "inferno.db" 2>/dev/null
   ```
3. Vérifier l'absence de tâche planifiée ou cron créés par le script (la capacité de persistance n'a pas abouti dans les tests, mais vérifier quand même).

## 4. Évaluation et actions prioritaires

- Changer les mots de passe de tous les comptes accessibles via les navigateurs de la machine
- Révoquer les tokens Discord : Paramètres Discord > Confidentialité et sécurité > Déconnecter de toutes les sessions
- Si des numéros de carte de paiement ont pu être capturés : contacter la banque pour opposition et renouvellement de carte
- Signaler la page web à Google Safe Browsing (via le bouton "Signaler" dans Chrome) et à l'hébergeur du site leurre

## 5. Réduction de surface d'attaque

- Ne jamais autoriser l'accès à un dossier sensible via la boîte de dialogue File System Access API sur une page dont l'origine n'est pas connue et vérifiée
- Utiliser des profils navigateur séparés : un profil dédié aux services sensibles (banque, crypto), un profil pour la navigation générale
- La règle YARA [`infernograbber.yar`](infernograbber.yar) permet de détecter le script Python sur disque ou dans des archives reçues
- Soumettre le hash `07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5` à ThreatFox / MalwareBazaar si non encore présent
