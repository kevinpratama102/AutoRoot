#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build-scanner — regen dist/lpescan.py + dist/lpe-data.json.gz dari dataset terkini.
Idempoten; jalankan ulang kapan saja (mis. setelah dataset di-refresh pipeline followup)."""
import csv
import gzip
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = "/home/davinz/AutoRoot/cve-lpe"
FULL_JSON = f"{ROOT}/cve-lpe-full.json"
POC_INDEX = f"{ROOT}/pocs/poc-index.csv"
DIST = os.path.join(HERE, "dist")
TABLES = os.path.join(HERE, "tables.py")
SCANNER_SRC = os.path.join(HERE, "lpescan.py")
MARKER = "# %%TABLES%%"


def main():
    os.makedirs(DIST, exist_ok=True)

    # ---- 1) dataset CVE ----
    rows = json.load(open(FULL_JSON))
    cves = []
    for r in rows:
        cves.append({
            "id": r["id"], "published": r["published"], "score": r.get("score"),
            "severity": r.get("severity"), "description": r.get("description", ""),
            "affected": r.get("affected") or [], "os": r["os"], "kev": bool(r.get("kev")),
        })

    # ---- 2) slim poc map ----
    pocs = {}
    try:
        with open(POC_INDEX) as f:
            for row in csv.DictReader(f):
                cid = row["id"]
                pocs.setdefault(cid, [])
                url = row["url"]
                if not any(p["url"] == url for p in pocs[cid]):
                    pocs[cid].append({"repo": row["repo"], "url": url})
    except FileNotFoundError:
        print("[!] poc-index.csv tidak ditemukan — lanjut tanpa peta PoC")

    # ---- 3) tulis lpe-data.json.gz ----
    data = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": len(cves), "cves": cves, "pocs": pocs}
    data_path = os.path.join(DIST, "lpe-data.json.gz")
    with gzip.open(data_path, "wt", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    print(f"[+] lpe-data.json.gz : {len(cves)} CVE, {len(pocs)} CVE dengan PoC, "
          f"{os.path.getsize(data_path) / 1e6:.1f} MB")

    # ---- 4) splice tables.py ke lpescan.py ----
    tables_body = open(TABLES).read()
    tables_body = re.sub(r'^# -\*- coding:.*$', "", tables_body, flags=re.M)
    tables_body = re.sub(r'^""".*?"""', "", tables_body, flags=re.S)
    tables_body = re.sub(r'^#.*$', "", tables_body, flags=re.M)
    tables_body = tables_body.strip()
    src = open(SCANNER_SRC).read()
    if MARKER not in src:
        raise SystemExit(f"[!] marker {MARKER} tidak ada di {SCANNER_SRC}")
    out_src = src.replace(MARKER, tables_body)
    out_path = os.path.join(DIST, "lpescan.py")
    with open(out_path, "w") as f:
        f.write(out_src)
    print(f"[+] dist/lpescan.py  : tables di-splice ({os.path.getsize(out_path) / 1e3:.0f} KB)")

    # ---- 5) laporan coverage PKG_TO_CPE (alat tuning) ----
    exec(compile(tables_body, "tables.py", "exec"), globals())
    cpe_counts = Counter()
    for r in cves:
        if r["os"] != "linux":
            continue
        for a in r["affected"]:
            cpe = a.split(" [")[0]
            cpe_counts[cpe] += 1
    mapped_cpes = set()
    for aliases in PKG_TO_CPE.values():
        for vend, prod in aliases:
            mapped_cpes.add(f"{vend}:{prod}")
    for aliases in DISTRO_TO_CPE.values():  # ditangani tier distro pin
        for vend, prod in aliases:
            mapped_cpes.add(f"{vend}:{prod}")
    print("\n[*] coverage PKG_TO_CPE (entry dataset -> count):")
    covered = 0
    for cpe, n in cpe_counts.most_common():
        if cpe in mapped_cpes:
            covered += n
    for pat, aliases in sorted(PKG_TO_CPE.items()):
        hits = sum(cpe_counts.get(f"{v}:{p}", 0) for v, p in aliases)
        flag = "" if hits else "  <-- tanpa entry di dataset"
        print(f"    {pat:<20} {hits:5d}{flag}")
    total_linux = sum(n for cpe, n in cpe_counts.items())
    print(f"\n[*] total entry affected linux: {total_linux}, "
          f"termapping: {covered} ({100 * covered / max(total_linux, 1):.1f}%)")
    print("[*] top-30 CPE linux yang belum termapping:")
    shown = 0
    for cpe, n in cpe_counts.most_common(120):
        if cpe in mapped_cpes or cpe == "linux:linux_kernel":
            continue
        if "firmware" in cpe or cpe.startswith("google:android"):
            continue
        print(f"    {n:5d}  {cpe}")
        shown += 1
        if shown >= 30:
            break
    print("\nBUILD-SCANNER DONE")


if __name__ == "__main__":
    main()
