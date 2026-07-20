# Lazarus githook — DEV#POPPER / Contagious Interview

Analyse statique complète d'une chaîne d'infection git hook attribuée au groupe Lazarus (DEV#POPPER, Contagious Interview). Vecteur : dépôt git piégé, hook `post-checkout` ou `pre-commit` qui télécharge et exécute une chaîne JS multi-stages.

## Fichiers

| Fichier | Rôle |
|---|---|
| [`writeup.md`](writeup.md) | Récit analytique complet (5 stages + attribution) |
| [`runbook.md`](runbook.md) | Étapes reproductibles (déobfuscation JS, extraction IoCs) |
| [`lazarus_githook.yar`](lazarus_githook.yar) | Règles YARA (4 règles : hook, JS stages, Python) |
| [`remediation.md`](remediation.md) | Guide de détection et nettoyage |
| [`tools/js_deobf.py`](tools/js_deobf.py) | Désobfuscateur obfuscator.io pour les 3 stages JS |
| [`tools/a3f41333_resolved.js`](tools/a3f41333_resolved.js) | Stage 2 désobfusqué |
| [`tools/683a1607_resolved.js`](tools/683a1607_resolved.js) | Stage 3 désobfusqué |
| [`tools/02e6fbf7_resolved.js`](tools/02e6fbf7_resolved.js) | Stage 1 désobfusqué |

## Chaîne résumée

```
git hook (.sh)
  → wget/curl 144.172.103.226/301/301{m,l,w}
    → stage1 JS (.unknown, 20 KB, obfuscator.io rot=112)
        [stealer]: 22 extensions Chrome (MetaMask, Phantom, BNB Wallet) + Solana CLI + Exodus
        [stealer]: → 95.216.64.240:1224/uploads (via ~/.n3/)
      → stage2 JS (3.5 KB, obfuscator.io rot=46)
        → C2 95.217.102.138:1144/s/30620700
          → stage3 JS (9.8 KB, obfuscator.io rot=70)
            → Cloudflare R2 CDN → p.zip / plinux.tar.xz / pmac.tar.gz
              → PyToolUpdater (persistance XDG/.zprofile/registre)
              → b34aa84.py (browser stealer → 95.216.64.240:1224)
              → cd3b606.py (RAT TCP → 69.197.164.135:2245 + HTTP → 95.216.64.240:1224)
```

## IoCs clés

| Type | Valeur |
|---|---|
| IP C2 (stage0-1) | `144.172.103.226` |
| IP C2 (stage2) | `95.217.102.138:1144` |
| IP C2 Python HTTP | `95.216.64.240:1224` |
| IP C2 RAT TCP | `69.197.164.135:2245` |
| CDN Windows | `pub-acf013a9b65140b7b58cc3c104ee7105.r2.dev` |
| CDN Linux/macOS | `pub-06714264305c44ea94491c0c8d961a87.r2.dev` |
| Payload (script) | `~/.viminf` (Node.js — exécuté par le mécanisme de persistance) |
| Persistance Linux | `~/.config/autostart/PyToolUpdater.desktop` |
| Persistance macOS | `~/.zprofile` (bloc bootstrap marqué `# >>> PyToolUpdater bootstrap >>`) |
| Persistance Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PyToolUpdater` |
| Répertoire RAT | `~/.n2/` |
| Répertoire stealer JS | `~/.n3/` (stage 1 — staging wallets crypto) |
