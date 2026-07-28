#!/usr/bin/env python3
"""
restore_all.py : restauration complete d'un dossier contenant des fichiers
chiffres par scorched-earth-ausfc (extension .prinzeugen, format chv1).

Workflow, dans l'ordre, jamais modifiable :
  1. Sauvegarde de TOUS les .prinzeugen trouves dans un sous-dossier dedie,
     avant toute autre action (systematique, non desactivable).
  2. Restauration (dechiffrement) de chaque fichier a partir de la copie de
     sauvegarde, avec verification du tag Poly1305 (integree au dechiffrement
     AEAD : un mauvais mot de passe ou un fichier corrompu leve une exception,
     rien n'est ecrit dans ce cas).
  3. Nettoyage optionnel : uniquement si --clean est passe, suppression du
     .prinzeugen original UNIQUEMENT pour les fichiers dont la restauration a
     reussi. Les echecs ne sont jamais touches. La sauvegarde de l'etape 1
     n'est jamais supprimee par cet outil, quel que soit --clean.

Usage :
    restore_all.py DOSSIER [--clean] [--password MOT_DE_PASSE]

Sans --clean : sauvegarde + restauration seulement, les .prinzeugen d'origine
restent en place (mode surete par defaut).
"""
import sys
import shutil
import argparse
from pathlib import Path
from datetime import datetime

from decrypt_chv1 import decrypt_file, HARDCODED_PASSWORD

EXT = ".prinzeugen"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="dossier a traiter (parcouru recursivement)")
    ap.add_argument("--clean", action="store_true",
                     help="supprime les .prinzeugen d'origine apres restauration reussie (jamais par defaut)")
    ap.add_argument("--password", default=None,
                     help="mot de passe a utiliser (par defaut : celui retrouve pour fc.exe / hash 88e63d1f...)")
    args = ap.parse_args()

    folder = Path(args.folder)
    if not folder.is_dir():
        sys.exit(f"pas un dossier : {folder}")

    password = args.password.encode() if args.password else HARDCODED_PASSWORD

    targets = sorted(folder.rglob(f"*{EXT}"))
    if not targets:
        print(f"aucun fichier {EXT} trouve dans {folder}")
        return

    backup_dir = folder / f"_backup_chiffre_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_dir.mkdir(exist_ok=False)
    print(f"[1/3] sauvegarde de {len(targets)} fichier(s) chiffre(s) vers {backup_dir}")

    backups = {}
    for src in targets:
        rel = src.relative_to(folder)
        dst = backup_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        backups[src] = dst
    print(f"      sauvegarde terminee ({len(backups)} fichier(s))")

    print("[2/3] restauration (dechiffrement + verification du tag Poly1305)")
    succeeded, failed = [], []
    for src, backup in backups.items():
        out_name = src.name[: -len(EXT)]
        out_path = src.with_name(out_name)
        try:
            decrypt_file(str(backup), str(out_path), password=password)
            succeeded.append(src)
            print(f"      OK   {src.name} -> {out_path.name}")
        except Exception as e:
            failed.append((src, e))
            print(f"      ECHEC {src.name} : {e}")

    print(f"      {len(succeeded)} reussi(s), {len(failed)} echec(s)")
    if failed:
        print("      fichiers en echec (jamais touches, ni supprimes) :")
        for src, e in failed:
            print(f"        - {src} : {e}")

    if args.clean:
        print("[3/3] nettoyage : suppression des .prinzeugen d'origine restaures avec succes")
        for src in succeeded:
            src.unlink()
            print(f"      supprime : {src}")
        print(f"      la sauvegarde reste disponible dans {backup_dir}")
    else:
        print("[3/3] nettoyage non demande (--clean absent) : les .prinzeugen d'origine sont conserves")

    print(f"\nTermine. Sauvegarde : {backup_dir}")


if __name__ == "__main__":
    main()
