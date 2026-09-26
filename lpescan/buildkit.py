#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""buildkit — bundel biner PoC yang cocok dengan hasil scan lpescan jadi kit zip.
Jalan di MESIN ARSIP saja. TIDAK PERNAH mengeksekusi PoC — murni copy/zip/markdown.

Usage: python3 buildkit.py --report scan-report-*.json [--out kits] [--include-possible]
"""
import argparse
import glob
import json
import os
import shutil
import sys
import zipfile
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
POCS = "/home/davinz/AutoRoot/cve-lpe/pocs"
BIN = f"{POCS}/bin"
SRC_LINUX = f"{POCS}/src"
SRC_WIN = f"{POCS}/src-windows"
KITS = os.path.join(HERE, "kits")


def find_linux_dir(cve_id, poc_rows):
    """Cari dir sumber linux: nama mengandung cve-{id} ATAU cocok {owner}__{repo}."""
    cid_l = cve_id.lower()
    for d in os.listdir(SRC_LINUX):
        if cid_l in d.lower():
            return os.path.join(SRC_LINUX, d)
    for p in poc_rows:
        repo = p["repo"]
        if "/" in repo:
            cand = os.path.join(SRC_LINUX, f"{repo.split('/')[0]}__{repo.split('/')[1]}")
            if os.path.isdir(cand):
                return cand
    return None


def zip_dir(srcdir, dest_zip, arc_prefix):
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(srcdir):
            dirs[:] = [x for x in dirs if x != ".git"]
            for fn in files:
                full = os.path.join(root, fn)
                zf.write(full, os.path.join(arc_prefix, os.path.relpath(full, srcdir)))


def find_windows_dir(cve_id, poc_rows):
    """Cari dir sumber windows: nama mengandung cve-{id} ATAU cocok {owner}__{repo}."""
    cid_l = cve_id.lower()
    for d in os.listdir(SRC_WIN):
        dl = d.lower()
        if cid_l in dl:
            return os.path.join(SRC_WIN, d)
    for p in poc_rows:
        repo = p["repo"]
        if "/" in repo:
            key = f"{repo.split('/')[0]}__{repo.split('/')[1]}"
            cand = os.path.join(SRC_WIN, key)
            if os.path.isdir(cand):
                return cand
    return None


def compile_recipe(srcdir):
    """Deteksi project file -> resep kompilasi untuk FLARE VM."""
    projs = {"sln": [], "vcxproj": [], "csproj": []}
    for root, dirs, files in os.walk(srcdir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            ext = fn.split(".")[-1].lower()
            if ext in projs:
                projs[ext].append(os.path.join(root, fn))
    for ext in ("sln", "vcxproj"):
        if projs[ext]:
            p = projs[ext][0]
            return f'msbuild "{p}" /p:Configuration=Release /p:Platform=x64'
    if projs["csproj"]:
        p = projs["csproj"][0]
        return f'msbuild "{p}" -p:Configuration=Release'
    return "tidak ada .sln/.vcxproj/.csproj — baca README di sumber"


def main():
    ap = argparse.ArgumentParser(description="buildkit — bundel kit PoC dari hasil scan")
    ap.add_argument("--report", required=True, help="path scan-report-*.json dari lpescan")
    ap.add_argument("--out", default=KITS, help="direktori output kit (default: kits/)")
    ap.add_argument("--include-possible", action="store_true",
                    help="sertakan juga match confidence 'possible' (distro-pin/[all])")
    args = ap.parse_args()

    report = json.load(open(args.report))
    target = report.get("target", {})
    tos = target.get("os", "")
    host = target.get("hostname", "unknown")
    if tos not in ("linux", "windows"):
        sys.exit(f"[!] os target '{tos}' tidak dikenal — cek isi report")
    os.makedirs(args.out, exist_ok=True)

    # ---- seleksi CVE ----
    selected = []
    for f in report.get("findings", {}).get("cve", []):
        if not f.get("has_poc"):
            continue
        if f.get("confidence") == "possible" and not args.include_possible:
            continue
        selected.append(f)
    selected.sort(key=lambda f: (not f["kev"], -(f.get("score") or 0), f["id"]))
    if not selected:
        sys.exit("[!] tidak ada CVE dengan PoC pada report ini (atau semua 'possible').")

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    kit_dir = os.path.join(args.out, f"lpe-kit-{host}-{ts}")
    os.makedirs(kit_dir, exist_ok=True)
    binaries_dir = os.path.join(kit_dir, "binaries")
    lsrc_dir = os.path.join(kit_dir, "linux-src")
    wsrc_dir = os.path.join(kit_dir, "windows-src")
    os.makedirs(binaries_dir, exist_ok=True)
    os.makedirs(lsrc_dir, exist_ok=True)
    os.makedirs(wsrc_dir, exist_ok=True)

    manifest = []
    readme_parts = [
        f"# LPE Kit — {host} ({tos})",
        "",
        f"- Dibuat: {ts}",
        f"- Dataset: {report.get('scanner', {}).get('dataset_generated', '?')} "
        f"({report.get('scanner', {}).get('cve_count', '?')} CVE)",
        f"- CVE terseleksi: {len(selected)}",
        "",
        "> **PERINGATAN:** review setiap sumber PoC sebelum dijalankan. Verifikasi offset,",
        "> arsitektur target, dan constraint versi. Jangan eksekusi membabi buta.",
        "",
    ]

    n_bin = n_src = n_none = 0
    for f in selected:
        cid = f["id"]
        matches = f.get("matches", [])[0] if f.get("matches") else {}
        constraint = matches.get("constraint", "?")
        installed = matches.get("installed", "?")
        repos = ", ".join(p["url"] for p in f.get("pocs", []))
        sev = f.get("severity") or "?"
        score = f.get("score")
        kev = " **[KEV]**" if f.get("kev") else ""
        head = f"## {cid} — {sev} {score}{kev}"
        desc = (f.get("description") or "")[:300]
        kit_paths = []

        if tos == "linux":
            bins = sorted(glob.glob(os.path.join(BIN, f"{cid}-*")))
            for b in bins:
                dst = os.path.join(binaries_dir, os.path.basename(b))
                if not os.path.exists(dst):
                    shutil.copy2(b, dst)
                kit_paths.append(f"binaries/{os.path.basename(b)}")
                n_bin += 1
            if not bins:
                d = find_linux_dir(cid, f.get("pocs", []))
                if d:
                    zname = f"{cid}-{os.path.basename(d)}.zip"
                    zp = os.path.join(lsrc_dir, zname)
                    zip_dir(d, zp, os.path.basename(d))
                    has_make = any(fn.lower() == "makefile" or fn.lower().endswith(".c")
                                   for _, _, fs in os.walk(d) for fn in fs)
                    recipe = ("cd ke direktori hasil unzip lalu make/gcc (ada source C/Makefile)"
                              if has_make else "tidak ada source C/Makefile — baca README")
                    kit_paths += [f"linux-src/{zname}", f"build: {recipe}"]
                else:
                    kit_paths.append(f"(clone: {repos})")
                n_src += 1
                readme_parts += [head, f"- constraint: `{constraint}` vs terpasang `{installed}`",
                                 f"- {desc}", f"- **source-only**: {repos}",
                                 f"- kit: " + " ; ".join(kit_paths), ""]
                continue
        else:
            d = find_windows_dir(cid, f.get("pocs", []))
            if d:
                zname = f"{cid}-{os.path.basename(d)}.zip"
                zp = os.path.join(wsrc_dir, zname)
                zip_dir(d, zp, os.path.basename(d))
                recipe = compile_recipe(d)
                kit_paths.append(f"windows-src/{zname}")
                kit_paths.append(f"compile: {recipe}")
                n_src += 1
            else:
                kit_paths.append(f"(clone di FLARE VM: {repos})")
                n_none += 1

        readme_parts += [head,
                         f"- matched_by: {f.get('matched_by')} ({f.get('confidence')})",
                         f"- constraint: `{constraint}` vs terpasang `{installed}`",
                         f"- {desc}",
                         f"- repo: {repos}",
                         f"- kit: " + " ; ".join(kit_paths),
                         ""]
        manifest.append({"cve": cid, "os": tos, "severity": sev, "score": score,
                         "kev": "YES" if f.get("kev") else "",
                         "matched_by": f.get("matched_by"), "installed_version": installed,
                         "constraint": constraint, "kit_path": " | ".join(kit_paths),
                         "repo": repos})

    with open(os.path.join(kit_dir, "KIT-README.md"), "w") as f:
        f.write("\n".join(readme_parts))
    with open(os.path.join(kit_dir, "manifest.csv"), "w") as f:
        f.write("cve,os,severity,score,kev,matched_by,installed_version,constraint,kit_path,repo\n")
        for m in manifest:
            def q(s):
                s = str(s).replace('"', '""')
                return f'"{s}"' if any(c in s for c in ',"\n') else s
            f.write(",".join(q(m[k]) for k in ("cve", "os", "severity", "score", "kev",
                                               "matched_by", "installed_version",
                                               "constraint", "kit_path", "repo")) + "\n")

    zip_path = kit_dir + ".zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(kit_dir):
            for fn in files:
                full = os.path.join(root, fn)
                zf.write(full, os.path.relpath(full, kit_dir))
    shutil.rmtree(kit_dir)

    print(f"[+] kit: {zip_path}")
    print(f"[+] {len(selected)} CVE — biner: {n_bin}, source/compile: {n_src}, "
          f"belum ada: {n_none}")
    if tos == "windows":
        print("\n=== KOMPILASI DI FLARE VM (contoh) ===")
        for f in selected:
            d = find_windows_dir(f["id"], f.get("pocs", []))
            if d:
                print(f"# {f['id']}: {compile_recipe(d)}")
    print("\nBUILDKIT DONE")


if __name__ == "__main__":
    main()
