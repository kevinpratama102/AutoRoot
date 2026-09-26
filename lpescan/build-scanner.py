#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build-scanner — regen dist/lpescan.py + dist/lpe-data.json.gz dari dataset terkini.
Idempoten; jalankan ulang kapan saja (mis. setelah dataset di-refresh pipeline followup)."""
import csv
import gzip
import json
import os
import re
import sys
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

# ---- klasifikasi kelas container-escape (runc/containerd/buildkit/docker/kernel) ----
ESCAPE_PRODUCTS = {
    "docker:docker", "linuxfoundation:runc", "linuxfoundation:containerd",
    "mobyproject:buildkit", "podman_project:podman", "linuxcontainers:lxc",
}
ESCAPE_DESC_KW = ("container escape", "escape the container", "container breakout",
                  "container filesystem breakout", "docker escape", "host root access")


def is_escape_class(r):
    """True bila CVE berpotensi escape container ke host (runc/containerd/kernel)."""
    d = (r.get("description") or "").lower()
    if any(k in d for k in ESCAPE_DESC_KW):
        return True
    return any(a.split(" [")[0] in ESCAPE_PRODUCTS for a in (r.get("affected") or []))


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
            "escape": is_escape_class(r),
        })
    n_esc = sum(1 for c in cves if c["escape"])
    print(f"[*] dataset: {len(cves)} CVE, {n_esc} kelas container-escape")

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

    # ---- 5b) emit TSV untuk port bash (lpescan.sh) & PowerShell (lpescan.ps1) ----
    sys.path.insert(0, HERE)
    from lpescan import parse_affected, normalize_num  # reuse engine, tanpa duplikasi

    lin_cpes = {"linux:linux_kernel"}
    for aliases in PKG_TO_CPE.values():
        for v, p in aliases:
            lin_cpes.add(f"{v}:{p}")
    for aliases in DISTRO_TO_CPE.values():
        for v, p in aliases:
            lin_cpes.add(f"{v}:{p}")

    def _norm(v):
        # strip sufiks arsip lalu normalize_num — parity eval_constraint(installed_toks=...)
        toks = normalize_num(re.sub(r"_[A-Za-z0-9]+$", "", v))
        return " ".join(str(t) for t in toks)  # "" = valid list kosong ; "-" = kolom absen

    def _s(x):
        return "-" if x is None or x == "" else str(x)

    lin_rows, win_rows, skipped, wide = [], [], 0, 0
    for r in rows:
        rid, pub = r["id"], r.get("published")
        kev = "1" if r.get("kev") else "0"
        esc = "1" if is_escape_class(r) else "0"
        for a in (r.get("affected") or []):
            cpe, cons = parse_affected(a)
            if cpe is None or not cons:
                skipped += 1
                continue
            if len(cons) > 3:
                wide += 1
                skipped += 1
                continue
            if any((not op) and v for op, v in cons):
                skipped += 1  # pair op kosong -> eval_constraint selalu False
                continue
            triples = [("-", "-", "-"), ("-", "-", "-"), ("-", "-", "-")]
            for i, (op, v) in enumerate(cons):
                triples[i] = ("ALL", "-", "-") if op == "ALL" else (op, v, _norm(v))
            cols = [rid, _s(pub), _s(r.get("score")), _s(r.get("severity")), kev, esc,
                    r["os"], cpe, a.replace("\t", " ")]
            for t in triples:
                cols += [t[0], t[1], t[2]]
            line = "\t".join(cols)
            if cpe in lin_cpes:
                lin_rows.append(line)
            elif cpe.startswith("microsoft:windows_"):
                win_rows.append(line)

    for name, content in (("lpe-cves-linux.tsv", lin_rows), ("lpe-cves-win.tsv", win_rows)):
        p = os.path.join(DIST, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(content) + ("\n" if content else ""))
        print(f"[+] dist/{name:24s}: {len(content)} baris "
              f"({os.path.getsize(p) / 1e6:.1f} MB)")

    with open(os.path.join(DIST, "lpe-cve-meta.tsv"), "w", encoding="utf-8") as f:
        for r in rows:
            d = (r.get("description") or "").replace("\t", " ") \
                 .replace("\n", " ").replace("\r", " ")
            f.write(f"{r['id']}\t{d[:600]}\n")
    print(f"[+] dist/lpe-cve-meta.tsv     : {len(rows)} baris (desc flatten <=600)")

    with open(os.path.join(DIST, "lpe-pkgmap.tsv"), "w", encoding="utf-8") as f:
        for pat, aliases in PKG_TO_CPE.items():
            for v, p in aliases:
                f.write(f"{pat}\t{v}\t{p}\n")
    with open(os.path.join(DIST, "lpe-distromap.tsv"), "w", encoding="utf-8") as f:
        for osid, aliases in DISTRO_TO_CPE.items():
            for v, p in aliases:
                f.write(f"{osid}\t{v}:{p}\n")
    with open(os.path.join(DIST, "lpe-gtfo.tsv"), "w", encoding="utf-8") as f:
        for g in GTFO_SUIDS:
            f.write(f"{g}\n")
    with open(os.path.join(DIST, "lpe-winrelease.tsv"), "w", encoding="utf-8") as f:
        for prod, relmap in WIN_RELEASE_TO_BUILD.items():
            for tok, b in relmap.items():
                f.write(f"{prod}\t{tok}\t{b}\n")  # urutan baris = ladder, last-match-wins
    with open(os.path.join(DIST, "lpe-winprivs.tsv"), "w", encoding="utf-8") as f:
        for priv, saran in WIN_INTERESTING_PRIVS.items():
            f.write(f"{priv}\t{saran}\n")
    with open(os.path.join(DIST, "lpe-pocs.tsv"), "w", encoding="utf-8") as f:
        for cid, plist in pocs.items():
            for p in plist:
                f.write(f"{cid}\t{p['repo']}\t{p['url']}\n")
    with open(os.path.join(DIST, "lpe-info.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(["generated", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "count", str(len(cves)), "linux_rows", str(len(lin_rows)),
                           "win_rows", str(len(win_rows)), "skipped", str(skipped)]) + "\n")
    print(f"[+] dist/lpe-info.tsv        : generated={data['generated']} "
          f"count={len(cves)} lin={len(lin_rows)} win={len(win_rows)} skipped={skipped}")
    if wide:
        print(f"[!] {wide} baris >3 op dibuang (belum ada di dataset lin/win — cek bila refresh)")

    for s in ("lpescan.sh", "lpescan.ps1"):
        src = os.path.join(HERE, s)
        if os.path.exists(src):
            with open(src, "rb") as f_in, open(os.path.join(DIST, s), "wb") as f_out:
                f_out.write(f_in.read())
            print(f"[+] dist/{s:24s}: disalin ({os.path.getsize(src) / 1e3:.0f} KB)")
        else:
            print(f"[!] {s} belum ada — dist/{s} tidak dibuat")
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
