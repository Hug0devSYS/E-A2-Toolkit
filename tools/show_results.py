"""Affiche les résultats des tests complets (fichiers *.jsonl produits par --fulltest).
Usage : python tools/show_results.py DOSSIER_RESULTATS [FAIL,WARN]"""
import glob
import json
import os
import sys

d = sys.argv[1]
only = sys.argv[2].split(",") if len(sys.argv) > 2 else None
tot = {}
for f in sorted(glob.glob(os.path.join(d, "*.jsonl"))):
    for line in open(f, encoding="utf-8"):
        r = json.loads(line)
        tot.setdefault(r["app"], {}).setdefault(r["status"], 0)
        tot[r["app"]][r["status"]] += 1
        if only and r["status"] not in only:
            continue
        print("%-4s | %-9s | %-15s | %-55s | %s" % (r["status"], r["app"], r["area"][:15], r["test"][:55], r["detail"][:200].replace("\n", " ")))
print("\nBilan :", json.dumps(tot, ensure_ascii=False))
