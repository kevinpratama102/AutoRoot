# lpescan — Scanner LPE ala PEAS + Kit Bundler PoC

Scanner LPE ala LinPEAS/WinPEAS yang terhubung ke arsip CVE lokal
(`../cve-lpe/`, 23.834 CVE). Alur kerja end-to-end:

```
[MESIN ARSIP]                            [SERVER TARGET]
python3 build-scanner.py                 copy dist/lpescan.py + dist/lpe-data.json.gz
   -> dist/                              python3 lpescan.py
   -> dist/lpe-data.json.gz                 -> scan-report-{host}-{ts}.json
                                          bawa pulang report itu
[MESIN ARSIP]
python3 buildkit.py --report scan-report-*.json
   -> kits/lpe-kit-{host}-{ts}.zip       -> copy kit ke target, review, jalankan
```

## Komponen

| File | Fungsi |
|---|---|
| `lpescan.py` | Scanner (source, hand-maintained). Marker `# %%TABLES%%` diisi otomatis. |
| `tables.py` | Tabel data: `PKG_TO_CPE` (nama paket -> CPE), `DISTRO_TO_CPE`, `WIN_RELEASE_TO_BUILD`, `GTFO_SUIDS` |
| `build-scanner.py` | Regen `dist/` dari dataset terkini (jalankan ulang SETELAH dataset di-refresh) |
| `buildkit.py` | Bundel biner PoC yang cocok jadi kit zip (mesin arsip saja) |
| `dist/` | Unit deploy: `lpescan.py` + `lpe-data.json.gz` (2 file, stdlib-only, tanpa jaringan) |
| `kits/` | Output kit zip |

## Cara pakai

### 1. Build scanner (setelah dataset di-update)

```bash
python3 build-scanner.py
# -> dist/lpescan.py + dist/lpe-data.json.gz ; laporan coverage PKG_TO_CPE
python3 dist/lpescan.py --selftest   # 23 asersi version engine
```

### 2. Scan target

```bash
# copy dist/lpescan.py + dist/lpe-data.json.gz ke target (scp/flashdisk)
python3 lpescan.py                    # output console berwarna + report JSON
python3 lpescan.py --json-only        # hanya tulis report
```

Apa yang di-scan:
- **CVE matching** (4 tier, prioritas: kernel > package > os-build > distro-pin):
  kernel vs `uname -r`, paket terpasang (dpkg/rpm) vs tabel CPE, distro pin
  vs `/etc/os-release`, Windows build vs bound NVD (`<10.0.22631.4751`),
  plus flag KEV (CISA known-exploited) dan peta repo PoC publik.
- **Deteksi backport distro** (`[BP]`): kernel distro (Ubuntu/Debian/Kali/…,
  suffix `-generic`/`-amd64`/`+kali` dll) memakai nomor ABI sendiri
  (`5.15.0-191` ≠ patch level upstream `5.15.191`) sehingga match rentang
  NVD rawan false positive. Scanner membaca build date dari `/proc/version`
  dan menandai match yang CVE-nya dipublikasikan >60 hari sebelum build —
  hampir pasti sudah di-backport → confidence turun ke `possible` + flag
  `likely_backported` di report. CVE yang dipublikasikan dekat/setelah
  build date TIDAK di-flag (perlu verifikasi manual).
- **PEAS checks**: ±42 cek Linux (SUID, sudo, capabilities, cron, kredensial,
  docker, NFS, systemd, dll) / ±27 cek Windows (token privilege, unquoted
  service path, AlwaysInstallElevated, stored creds, UAC, autoruns, dll).

Scanner **tidak pernah mengeksekusi PoC** — deteksi saja.

### 3. Bundel kit

```bash
python3 buildkit.py --report scan-report-{host}-{ts}.json
# -> kits/lpe-kit-{host}-{ts}.zip
#    binaries/        ELF PoC terkompilasi (Linux)
#    windows-src/     zip sumber per CVE + resep kompilasi (Windows/FLARE VM)
#    KIT-README.md    per-CVE: constraint vs versi terdeteksi, repo, path kit
#    manifest.csv
```

Linux: biner diambil dari `../cve-lpe/pocs/bin/` (508 ELF). CVE yang punya repo
tapi belum ada binernya ditandai *source-only*. Windows: sumber di-zip dari
`../cve-lpe/pocs/src-windows/`, kompilasi di FLARE VM (`msbuild ...`).

## Catatan

- Dataset = snapshot NVD + CISA KEV yang di-generate per `2026-09-26`.
- `--selftest` memvalidasi version engine terhadap bentuk string dataset nyata.
- Jalankan ulang `build-scanner.py` + re-copy `dist/` setiap kali dataset
  berubah (mis. setelah pipeline followup selesai).
