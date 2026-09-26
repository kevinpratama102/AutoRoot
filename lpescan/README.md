# lpescan — Scanner LPE ala PEAS + Kit Bundler PoC

Scanner LPE ala LinPEAS/WinPEAS yang terhubung ke arsip CVE lokal
(`../cve-lpe/`, 23.847 CVE). Alur kerja end-to-end:

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
| `lpescan.py` | Scanner (source, hand-maintained). Marker `# %%TABLES%%` diisi otomatis. **Referensi** — behaviour port bash/PS mengejarnya. |
| `lpescan.sh` | Port **bash** untuk Linux tanpa python (bash 4+, awk POSIX) — full parity |
| `lpescan.ps1` | Port **PowerShell 5.1** untuk Windows tanpa python — full parity |
| `tables.py` | Tabel data: `PKG_TO_CPE` (nama paket -> CPE), `DISTRO_TO_CPE`, `WIN_RELEASE_TO_BUILD`, `GTFO_SUIDS` |
| `build-scanner.py` | Regen `dist/` dari dataset terkini (jalankan ulang SETELAH dataset di-refresh); emit 10 TSV untuk port bash/PS + copy `lpescan.sh`/`lpescan.ps1` |
| `buildkit.py` | Bundel biner PoC yang cocok jadi kit zip (mesin arsip saja) |
| `dist/` | Unit deploy: per implementasi — python = `lpescan.py` + `lpe-data.json.gz`; bash/PS = scanner + TSV (lihat matriks di bawah) |
| `kits/` | Output kit zip |

## Cara pakai

### 1. Build scanner (setelah dataset di-update)

```bash
python3 build-scanner.py
# -> dist/lpescan.py + dist/lpe-data.json.gz ; laporan coverage PKG_TO_CPE
python3 dist/lpescan.py --selftest   # 35 asersi (version engine + backport + container-escape)
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
- **Deteksi container escape** (`[ESC]`): dataset menandai kelas CVE
  container-escape (runc/containerd/buildkit/docker/kernel — deskripsi
  "container escape" atau product yang relevan). Match yang masuk kelas ini
  di-flag `escape_class` di report + `[ESC]` di konsol. Bila scanner berjalan
  **di dalam container** (terdeteksi lewat `/.dockerenv`/cgroup), blok TARGET
  memberi catatan bahwa match `[ESC]` bisa menyentuh host — verifikasi versi
  runtime host dari sisi host.
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

## Port tanpa python — lpescan.sh (bash) & lpescan.ps1 (PowerShell 5.1)

Banyak target tidak punya python3 (server minimal, Windows tanpa python). Dua port
full-parity 1:1: matching 4-tier + flag KEV/`[BP]`/`[ESC]` + semua PEAS checks
(16 Linux / 10 Windows) + report JSON schema identik, sehingga `buildkit.py`
tetap jalan tanpa perubahan. `lpescan.py` adalah referensi (semua gate parity
diuji terhadapnya).

| Implementasi | Target | Runtime | Unit deploy (copy ke target) |
|---|---|---|---|
| `lpescan.py` | Linux/Windows dgn python3 | python 3.8+ stdlib-only | `lpescan.py` + `lpe-data.json.gz` (2 file) |
| `lpescan.sh` | Linux tanpa python | bash 4+ + awk POSIX (mawk/busybox ok), tanpa jq | `lpescan.sh` + `lpe-cves-linux.tsv` + `lpe-cve-meta.tsv` + `lpe-pkgmap.tsv` + `lpe-distromap.tsv` + `lpe-gtfo.tsv` + `lpe-pocs.tsv` + `lpe-info.tsv` (8 file, ±2 MB) |
| `lpescan.ps1` | Windows tanpa python | Windows PowerShell 5.1+ | `lpescan.ps1` + `lpe-cves-win.tsv` + `lpe-cve-meta.tsv` + `lpe-pocs.tsv` + `lpe-winrelease.tsv` + `lpe-winprivs.tsv` + `lpe-info.tsv` (7 file, ±4,5 MB) |

Flag identik: `--report PATH`, `--json-only`, `--no-color`, `--selftest`
(PS: `-Report PATH -JsonOnly -NoColor -Selftest`; `--selftest` bisa dijalankan
cross-platform — pwsh lokal di mesin arsip).

```bash
# selftest per impl (mesin arsip)
python3 dist/lpescan.py --selftest                       # 35 asersi (referensi)
bash dist/lpescan.sh --selftest                          # 30 asersi
pwsh -NoProfile -File dist/lpescan.ps1 -Selftest         # 37 asersi

# target Windows tanpa python — dari cmd/PS:
powershell -ExecutionPolicy Bypass -File lpescan.ps1 -Report scan-win.json
```

PEAS checks sama 1:1: 16 cek Linux (`chk_linux_*`) dan 10 cek Windows
(`chk_win_*` — os/hotfixes/services/alwaysinstalled/privs/creds/uac/autoruns/
dll/defense); kategori, severity, judul, dan field `check` (= nama fungsi)
identik dengan python.

### Divergence terdokumentasi (kosmetik — tidak mengubah hasil buildkit)

- `description` di report bash/PS = **600 char pertama** (`lpe-cve-meta.tsv`,
  di-flatten saat build); python memakai deskripsi utuh dari `lpe-data.json.gz`.
- Urutan listing SUID/glob bisa beda (find = urutan readdir vs `os.walk` python)
  — himpunan temuan sama, urutan baris saja.
- Pesan teks `check ... gagal` memakai exception lokal (platform bisa beda kalimat;
  python memakai `str(e)`).
- PS: cek "writable" pakai atribut `ReadOnly` (`[System.IO.File]::GetAttributes`)
  — ini persis semantik `os.access` CPython di Windows (`win32_access`), bukan
  probe tulis, jadi scanner tetap 100% read-only.

## Catatan

- Dataset = snapshot NVD + CISA KEV yang di-generate per `2026-09-26`,
  ditambah 13 CVE runc/containerd/buildkit/docker kurasi manual
  (CVE-2019-5736, CVE-2024-21626, dll.) yang terlewat keyword pipeline NVD.
- `--selftest` memvalidasi version engine terhadap bentuk string dataset nyata.
- Jalankan ulang `build-scanner.py` + re-copy `dist/` setiap kali dataset
  berubah (mis. setelah pipeline followup selesai).
