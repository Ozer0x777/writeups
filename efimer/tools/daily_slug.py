#!/usr/bin/env python3
"""
Calcul des slugs journaliers Efimer (daily_random_slug).

Reconstitution de l'algorithme depuis le bytecode de installer.pyc.
La graine est SHA256(f"{jour_UTC}-{N}") % 2^32, injectée dans random.Random.
N=0 : dossier C:\\Users\\Public\\Videos\\[slug]\\
N=1 : nom de la tâche planifiée
N=2 : nom du fichier JS clipper

Usage:
  python3 daily_slug.py                          # slugs pour aujourd'hui (UTC)
  python3 daily_slug.py 2026-07-15               # slugs pour une date précise
  python3 daily_slug.py 2026-07-15 2026-07-31    # table sur une plage de dates
"""
import sys
import hashlib
import random
import datetime

VOWELS     = 'aeiou'
CONSONANTS = 'bcdfghjklmnpqrstvwxyz'


def daily_random_slug(day_number, N):
    seed_int = int(hashlib.sha256(f"{day_number}-{N}".encode()).hexdigest(), 16) % 0x100000000
    rng = random.Random(seed_int)
    return ''.join(rng.choice(CONSONANTS) + rng.choice(VOWELS) for _ in range(4))


def day_number(date):
    epoch = datetime.datetime(1970, 1, 1)
    return (date - epoch).days


def slugs_for_date(date):
    d = day_number(date)
    return daily_random_slug(d, 0), daily_random_slug(d, 1), daily_random_slug(d, 2)


def main():
    args = sys.argv[1:]

    if len(args) == 0:
        now = datetime.datetime.utcnow()
        dates = [datetime.datetime(now.year, now.month, now.day)]
    elif len(args) == 1:
        dates = [datetime.datetime.strptime(args[0], '%Y-%m-%d')]
    else:
        start = datetime.datetime.strptime(args[0], '%Y-%m-%d')
        end   = datetime.datetime.strptime(args[1], '%Y-%m-%d')
        dates = []
        cur = start
        while cur <= end:
            dates.append(cur)
            cur += datetime.timedelta(days=1)

    header = f"{'Date':<12}  {'Dossier (N=0)':<14}  {'Tache (N=1)':<14}  {'Clipper (N=2)':<14}  Chemin JS complet"
    print(header)
    print('-' * len(header))

    for date in dates:
        folder, task, js = slugs_for_date(date)
        path = f"C:\\Users\\Public\\Videos\\{folder}\\{js}.js"
        print(f"{date.strftime('%Y-%m-%d'):<12}  {folder:<14}  {task:<14}  {js:<14}  {path}")


if __name__ == '__main__':
    main()
