# wskmon.sys : un backdoor kernel signé WHQL, caché dans le Windows Filtering Platform

Reverse engineering statique complet d'un driver Windows x64 (`wskmon.sys`) signé par une chaîne de certification Microsoft valide, qui implante un backdoor réseau furtif en abusant du Windows Filtering Platform. Analyse menée indépendamment d'un writeup public existant (Nextron Systems), en vérifiant chaque affirmation dans le désassemblage plutôt qu'en la recopiant, ce qui a permis de documenter un mécanisme de repli entier (reconstruction manuelle de la SSDT via lecture de MSR) absent de toute source publique.

**Analyste :** Gordon PEIRS · **Période :** juillet 2026 · **Méthode :** analyse statique uniquement (aucune exécution, aucun chargement du driver) + vérification croisée systématique contre le désassemblage réel, jamais contre la seule prose d'un article tiers.

## Résumé exécutif

`wskmon.sys` porte une signature WHQL Microsoft valide (Windows Hardware Compatibility Publisher) tout en fonctionnant comme un backdoor kernel-mode purement passif : il n'appelle jamais de C2, il attend qu'on lui envoie un paquet contenant une séquence d'octets magiques (`7F 4E 54 46`) sur n'importe quel flux TCP passant par la machine, en clair ou caché dans le corps d'une requête HTTP POST. Une fois authentifié par HMAC-SHA256 et déchiffré par XOR, il exécute trois types de commandes : exécution de commande via injection dans un `svchost.exe` privilégié, écriture de fichier arbitraire avec un handle invisible en mode utilisateur, ou exécution de shellcode brut.

Le point le plus notable : quand la résolution documentée des fonctions de création de thread échoue, le driver reconstruit **à la main** la table de service Windows (SSDT) en lisant un registre modèle-spécifique Intel (`IA32_LSTAR`) et en repérant le prologue binaire des stubs syscall, une technique de contournement d'API documentée nulle part dans les sources publiques sur cet échantillon. Le certificat de signature appartient à une entreprise chinoise de cryptographie réelle et reconnue internationalement ; le scénario le plus probable, cohérent avec un précédent documenté par Mandiant en 2022 (POORTRY/STONESTOP), est un compte de signature compromis plutôt qu'un vendeur complice.

**Chiffres clés :** 3 commandes disséquées avec leur mécanisme d'exécution réel · clé XOR de 32 octets extraite en clair · double mécanisme de résolution de thread (API documentée + reconstruction manuelle de SSDT) · aucune infrastructure C2 ni persistance présente dans le fichier · certificat toujours valide au moment du signalement · **deux autres outils retrouvés signés avec le même certificat**, dont une primitive de lecture/écriture mémoire physique arbitraire candidate au rôle de chargeur.

## Chaîne reconstituée

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

## Writeups

| Document | Contenu |
|---|---|
| [writeup.md](writeup.md) | Analyse technique complète en un seul document (19 sections) : `wskmon.sys` (enregistrement WFP, déclencheur réseau, HMAC/XOR, les trois commandes, le double mécanisme de résolution de thread, DriverUnload, contexte du certificat) puis `devhost.sys` (primitive R/W mémoire physique, candidat chargeur) et `844ljfpvz.sys` (composant minimal non déterminé), trouvés via le certificat partagé |
| [02, Signalement MSRC](02-wskmon-msrc-report.md) | Rapport destiné au Microsoft Security Response Center : révocation du certificat, enquête sur le compte de soumission, preuve de réutilisation sur trois fichiers. Document séparé du writeup, c'est un livrable externe (lettre de divulgation), pas de la prose d'analyse |
| [`poc_trigger.py`](poc_trigger.py) | Générateur de paquet de déclenchement (magic bytes + HMAC-SHA256 + XOR), reconstruit entièrement depuis le désassemblage, preuve d'exploitabilité pour le rapport MSRC. N'envoie rien par défaut ; nécessite une cible explicite + confirmation manuelle |

## Ce que ce dossier ne contient pas (volontairement)

Aucun binaire n'est versionné ici. L'échantillon est identifié par son hash SHA256 et récupérable sur [MalwareBazaar](https://bazaar.abuse.ch/) (tag `rootkit`). Le certificat étant encore valide au moment de la rédaction, aucune divulgation publique large (blog, réseaux sociaux) n'a été faite avant le signalement à Microsoft, voir la note de divulgation coordonnée ci-dessous.

## Note sur la divulgation

Le certificat documenté ici est **actif** au moment de cette analyse. Par cohérence avec les pratiques de divulgation coordonnée (signaler au vendeur avant publication large), ce dossier reste privé jusqu'à confirmation de la révocation par Microsoft ou un délai raisonnable sans réponse. La société dont le nom apparaît dans le certificat (Aolian) est très vraisemblablement une victime dans cette histoire, voir la section dédiée du writeup 01, et n'a pas vocation à être présentée publiquement comme responsable sans confirmation.
