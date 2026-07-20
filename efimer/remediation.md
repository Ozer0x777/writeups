# Guide de détection et remédiation : Efimer (ClickFix, clipper BTC/TRX/XMR, botnet WordPress)

Destiné à quelqu'un qui doit vérifier ou nettoyer une machine ou un site, pas à un public d'analystes. Basé sur les constats de [`writeup.md`](writeup.md) ; les points non confirmés directement sont marqués comme tels.

Deux rôles distincts : victime Windows du clipper, et propriétaire d'un site WordPress utilisé pour le bruteforcing.

## 1. Suis-je concerné ?

### Victime Windows (clipper)

Le vecteur est une fausse page CAPTCHA qui pousse à coller une commande PowerShell. L'infection ne se produit **que si la commande a été exécutée manuellement**.

```powershell
# Vérifier les tâches planifiées avec un nom en CVCVCVCV (8 caractères consonne-voyelle alternés)
Get-ScheduledTask | Where-Object { $_.TaskName -match "^[bcdfghjklmnpqrstvwxyz][aeiou][bcdfghjklmnpqrstvwxyz][aeiou][bcdfghjklmnpqrstvwxyz][aeiou][bcdfghjklmnpqrstvwxyz][aeiou]$" }

# Ou calculer le slug du jour exact avec l'outil fourni, puis chercher la tâche par nom
# python3 tools/daily_slug.py 2026-07-20

# Vérifier la clé Run du registre
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
```

### Propriétaire de site WordPress

Indicateur : pic de requêtes `POST /xmlrpc.php` dans les logs Apache/Nginx venant de nombreuses IP distinctes (le bruteforcer est déployé sur des machines infectées, pas depuis un seul serveur).

## 2. Signes d'infection active (Windows)

- **Tâche planifiée** dont le nom suit le pattern CVCVCVCV (8 caractères), dans le namespace `\`, avec déclencheur toutes les 60 secondes. Le nom exact du jour est calculable avec [`tools/daily_slug.py`](tools/daily_slug.py).
- **Processus Tor** (`uusd.exe`) dans un sous-dossier de `%APPDATA%` nommé par le slug journalier
- **Script JS** (`002_n.js`, clipper) dans le même dossier, exécuté par Node.js ou un interpréteur embarqué
- **Modification du presse-papier** : toute adresse Bitcoin (variantes incluses : bc1, 1, 3), TRON ou Monero copiée est remplacée silencieusement par une adresse de l'attaquant

## 3. Nettoyage (Windows)

1. Couper le réseau immédiatement : les C2 sont des hidden services Tor, la communication est active tant que le clipper tourne.
2. Calculer le nom du dossier du jour : `python3 tools/daily_slug.py` (N=0) donne le nom du dossier dans `%APPDATA%`.
3. Supprimer la tâche planifiée correspondante : `Unregister-ScheduledTask -TaskName "<slug>" -Confirm:$false`
4. Tuer `uusd.exe` et tout processus Node.js ou interpréteur JS associé.
5. Supprimer le dossier d'installation `%APPDATA%\<slug>\`.
6. Supprimer l'entrée Run du registre si présente.

## 4. Évaluation de la compromission

Le clipper détourne les adresses crypto silencieusement, sans aucun message visible. Toute transaction effectuée pendant la période d'infection est à vérifier.

**Vérifier impérativement :**

- Les transactions sortantes de vos wallets BTC, TRX, XMR depuis la date estimée d'infection
- Les adresses effectivement reçues par le destinataire (comparer avec ce que vous aviez collé)
- Les mots de passe de sites WordPress si la machine administre ou héberge un site WordPress

**Spécificité BIP39 :** le clipper accumule les mots de phrase mnémonique copiés mot par mot sur des événements de copie successifs (mécanisme `MakeREPL` décrit dans [`writeup.md`](writeup.md) §4). Si vous avez copié des mots d'une seed phrase, même un par un, considérez-la compromise même sans avoir copié toute la phrase d'un seul bloc.

## 5. Signalement

Les wallets hardcodés ont été tracés jusqu'à des exchanges soumis au KYC et à FixedFloat. Les signalements préparés sont documentés dans [`writeup.md`](writeup.md) §15 (IOCs consolidés et procédures).

- **FixedFloat** : `support@fixedfloat.com`
- **Exchanges KYC identifiés** : formulaires de signalement réglementaires propres à chaque exchange
- **C2 Tor** : soumission à abuse.ch (tag `clipper`) via le portail web

## 6. Réduction de surface d'attaque

- Pour WordPress : désactiver XMLRPC si non utilisé (ajouter dans `.htaccess` : `<Files xmlrpc.php>` / `Require all denied` / `</Files>`), ou activer fail2ban sur les requêtes XMLRPC répétées
- Ajouter [`efimer_dropper.yar`](efimer_dropper.yar) aux points d'entrée réseau et email
- Bloquer les connexions sortantes vers le réseau Tor (ports 9001, 9030, 9050, 9051, 9150) si le contexte le permet
