# AutoRoot — Toolkit Riset LPE: CVE → Scan → Kit PoC

AutoRoot adalah toolkit riset **local privilege escalation (LPE)** yang merangkai tiga komponen
dalam satu alur kerja: arsip CVE lokal, scanner ala LinPEAS/WinPEAS, dan bundler kit PoC.

| Komponen | Isi |
|---|---|
| **cve-lpe** | Arsip **23.834 CVE** LPE (NVD API 2.0 + CISA KEV) + indeks **1.298 repo PoC publik**: 508 biner ELF terkompilasi, 1.594 sumber Linux, 623 sumber Windows |
| **lpescan** | Scanner full enumerasi (versi + misconfig, ±42 cek Linux / ±27 cek Windows) yang mencocokkan hasilnya ke dataset CVE. Python stdlib-only, **read-only**, tanpa jaringan |
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
│   ├── cve-lpe-full.json      # 23.834 record (format ringkas 9 key)
│   ├── cve-lpe-full.csv
│   ├── linux/ windows/ other/ # split per OS per tahun
│   ├── pocs/                  # PoC publik: bin/ src/ src-windows/ poc-index.csv
│   └── README.md              # statistik dataset per OS/tahun
└── lpescan/                   # scanner + bundler
    ├── lpescan.py             # scanner (source, hand-maintained)
    ├── tables.py              # tabel mapping: pkg→CPE, distro→CPE, release→build, GTFO-SUID
    ├── build-scanner.py       # regen dist/ dari dataset terkini (idempoten)
    ├── buildkit.py            # bundler kit PoC (mesin arsip saja)
    ├── dist/                  # UNIT DEPLOY: lpescan.py + lpe-data.json.gz (2.5 MB)
    ├── kits/                  # output kit zip (generated)
    └── README.md              # workflow detail per langkah
```

## Dataset — cve-lpe

- **Sumber**: NVD API 2.0 (query keyword variants + daftar cveId kurasi) + CISA KEV
- **23.834 CVE** (1989–2026): linux 3.958 / windows 6.114 / other 13.762
- Severity: CRITICAL 1.940 · HIGH 16.277 · MEDIUM 5.375 · LOW 239
- **KEV** (CISA Known Exploited Vulnerabilities): **299** record — diprioritaskan di report
- Record tanpa `affected[]`: 2.843 (di-skip saat matching)
- Format record: `id, published, score, severity, description, affected[], os, kev`
- `affected[]` = CPE 2.3 `vendor:product [range]` — range bisa `[all]`, exact `[6.8]` / `[7.0_s390x]`,
  atau bound `[<10.0.22631.4751]`
- PoC: `pocs/poc-index.csv` (3.734 baris → 1.298 CVE) dipetakan ke `pocs/bin/` (ELF),
  `pocs/src/` (repo Linux), `pocs/src-windows/` (repo Windows)

## lpescan — scanner

Matching CVE 4 tier, prioritas **kernel > package > os-build > distro-pin**:

| Tier | Cara kerja | Confidence |
|---|---|---|
| kernel | `uname -r` vs range/pin `linux:linux_kernel` (8.000+ entry, `[all]` di-skip kecuali KEV) | high |
| package | dpkg/rpm vs tabel `PKG_TO_CPE` (sudo, glibc, polkit, openssl, systemd, firefox, dll.) | high |
| os-build | build Windows (`10.0.22631.4751`) vs bound NVD + tabel release→build | high |
| distro-pin | os-release vs `debian:debian_linux` / `canonical:ubuntu_linux` dll. | possible |

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
python3 dist/lpescan.py --selftest          # 23 asersi version engine

# target Linux
python3 lpescan.py                          # output konsol berwarna + scan-report-*.json
python3 lpescan.py --json-only              # hanya tulis report
python3 lpescan.py --report /tmp/r.json --no-color

# target Windows (mis. FLARE VM — butuh python3 di target)
python3 lpescan.py --report scan-win.json
```

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
- Kompilasi PoC Windows: FLARE VM dengan msbuild (resep dicetak otomatis oleh buildkit)

## Catatan pengembangan

- Dataset di-refresh lewat pipeline NVD (keyword + cveId kurasi — keyword murni melesetkan
  CVE kernel 2026 dengan pola deskripsi "In the Linux kernel..." seperti DirtyFrag/CopyFail);
  setelah refresh tinggal jalankan ulang `build-scanner.py`
- `--selftest` memvalidasi version engine terhadap bentuk string dataset nyata
  (arch suffix `7.0_s390x`, patch-level `1.9.5p2`, build Windows, pin exact `[6.8]`, dll.)

## Disclaimer

Tool ini dibuat untuk **pendidikan dan riset keamanan terautorisasi** (lab pribadi, CTF,
pentest dengan izin). Penulis tidak bertanggung jawab atas penggunaan yang melanggar hukum.
Review setiap PoC sebelum dijalankan — verifikasi offset, arsitektur, dan constraint versi.

## Lisensi

TBD — tentukan sebelum publikasi (dataset berasal dari NVD/CISA, domain publik;
kode tool bisa MIT).
