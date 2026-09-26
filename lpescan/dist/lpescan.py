#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lpescan — scanner LPE ala LinPEAS/WinPEAS + matcher CVE dari arsip lokal.

Alur kerja:
  1) (mesin arsip)  python3 build-scanner.py          -> dist/lpescan.py + dist/lpe-data.json.gz
  2) (target)       copy dist/lpescan.py + dist/lpe-data.json.gz, lalu:  python3 lpescan.py
  3) bawa pulang scan-report-*.json
  4) (mesin arsip)  python3 buildkit.py --report scan-report-*.json  -> kits/*.zip

Scanner ini HANYA mendeteksi — tidak pernah mengeksekusi PoC apa pun.
Usage: python3 lpescan.py [--report PATH] [--no-color] [--json-only] [--selftest]
"""
import argparse
import fnmatch
import glob
import gzip
import html
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

SCANNER_VERSION = "1.2.0"
DATA_FILENAME = "lpe-data.json.gz"

try:  # mode source: tables.py ada di sebelah lpescan.py
    from tables import PKG_TO_CPE, DISTRO_TO_CPE, WIN_RELEASE_TO_BUILD, GTFO_SUIDS
except ImportError:
    pass  # mode dist: tables di-splice oleh build-scanner di bawah

"""Tabel data lpescan — displice ke dist/lpescan.py oleh build-scanner.py.
HANYA berisi literal data, tanpa import/dokumen panjang."""


PKG_TO_CPE = {
    "sudo":            [("todd_miller", "sudo"), ("sudo_project", "sudo")],
    "libc6":           [("gnu", "glibc")],
    "glibc":           [("gnu", "glibc")],
    "libc6-*":         [("gnu", "glibc")],
    "bash":            [("gnu", "bash")],
    "coreutils":       [("gnu", "coreutils")],
    "util-linux":      [("andries_brouwer", "util-linux"), ("kernel", "util-linux")],
    "policykit-1":     [("polkit_project", "polkit")],
    "polkitd":         [("polkit_project", "polkit")],
    "polkit":          [("polkit_project", "polkit")],
    "snapd":           [("canonical", "snapd")],
    "apport":          [("canonical", "apport")],
    "python-apport":   [("canonical", "apport")],
    "dbus":            [("freedesktop", "libdbus")],
    "dbus-daemon":     [("freedesktop", "libdbus")],
    "libdbus-1-*":     [("freedesktop", "libdbus")],
    "openssl":         [("openssl", "openssl")],
    "libssl*":         [("openssl", "openssl")],
    "libcrypto*":      [("openssl", "openssl")],
    "perl":            [("perl", "perl")],
    "perl-base":       [("perl", "perl")],
    "perl-*":          [("perl", "perl")],
    "python3*":        [("python", "python")],
    "python2*":        [("python", "python")],
    "python-*":        [("python", "python")],
    "rpm":             [("rpm", "rpm")],
    "rpm-libs":        [("rpm", "rpm")],
    "xen*":            [("xen", "xen")],
    "qemu*":           [("qemu", "qemu")],
    "openldap":        [("openldap", "openldap")],
    "slapd":           [("openldap", "openldap")],
    "libldap*":        [("openldap", "openldap")],
    "postgresql":      [("postgresql", "postgresql")],
    "postgresql-*":    [("postgresql", "postgresql"), ("debian", "postgresql-common")],
    "samba":           [("samba", "samba")],
    "smbd":            [("samba", "samba")],
    "samba-common":    [("samba", "samba")],
    "rsync":           [("samba", "rsync")],
    "cifs-utils":      [("samba", "cifs-utils")],
    "zlib1g":          [("zlib", "zlib")],
    "zlib":            [("zlib", "zlib")],
    "libexpat1":       [("libexpat_project", "libexpat")],
    "expat":           [("libexpat_project", "libexpat")],
    "libxml2":         [("xmlsoft", "libxml2")],
    "libxml2-*":       [("xmlsoft", "libxml2")],
    "libssh*":         [("libssh", "libssh")],
    "sqlite3":         [("sqlite", "sqlite")],
    "libsqlite3*":     [("sqlite", "sqlite")],
    "systemd":         [("systemd_project", "systemd")],
    "systemd-*":       [("systemd_project", "systemd")],
    "cups*":           [("apple", "cups"), ("linuxfoundation", "cups-filters")],
    "apache2":         [("apache", "http_server")],
    "httpd":           [("apache", "http_server")],
    "tomcat*":         [("apache", "tomcat")],
    "nginx*":          [("nginx", "nginx"), ("f5", "nginx")],
    "firefox":         [("mozilla", "firefox")],
    "firefox-*":       [("mozilla", "firefox")],
    "thunderbird":     [("mozilla", "thunderbird")],
    "curl":            [("haxx", "curl")],
    "libcurl*":        [("haxx", "libcurl"), ("haxx", "curl")],
    "wget":            [("gnu", "wget")],
    "tar":             [("gnu", "tar")],
    "gawk":            [("gnu", "gawk")],
    "findutils":       [("gnu", "findutils")],
    "screen":          [("gnu", "screen"), ("juergen", "weigert_screen")],
    "tmux":            [("nicholas_marriott", "tmux")],
    "procps":          [("procps-ng_project", "procps-ng")],
    "procps-ng":       [("procps-ng_project", "procps-ng")],
    "openssh*":        [("openbsd", "openssh")],
    "openssh-server":  [("openbsd", "openssh")],
    "openssh-client":  [("openbsd", "openssh")],
    "bind9*":          [("isc", "bind")],
    "bind":            [("isc", "bind")],
    "krb5-*":          [("eyrie", "pam-krb5")],
    "libpam-krb5":     [("eyrie", "pam-krb5")],
    "shadow":          [("shadow_project", "shadow"), ("suse", "shadow")],
    "login":           [("shadow_project", "shadow")],
    "passwd":          [("shadow_project", "shadow")],
    "exim4*":          [("exim", "exim"), ("university_of_cambridge", "exim")],
    "postfix":         [("postfix", "postfix")],
    "sendmail*":       [("sendmail", "sendmail"), ("eric_allman", "sendmail")],
    "dovecot*":        [("dovecot", "dovecot")],
    "proftpd*":        [("proftpd", "proftpd"), ("proftpd_project", "proftpd")],
    "pure-ftpd*":      [("pureftpd", "pure-ftpd")],
    "lighttpd":        [("lighttpd", "lighttpd")],
    "php*":            [("php", "php")],
    "expect":          [("don_libes", "expect")],
    "policycoreutils": [("redhat", "policycoreutils")],
    "language-selector*": [("ubuntu", "language-selector")],
}


DISTRO_TO_CPE = {
    "debian":        [("debian", "debian_linux")],
    "ubuntu":        [("canonical", "ubuntu_linux")],
    "fedora":        [("fedoraproject", "fedora")],
    "rhel":          [("redhat", "enterprise_linux_server"),
                      ("redhat", "enterprise_linux_desktop"),
                      ("redhat", "enterprise_linux_workstation")],
    "redhat":        [("redhat", "enterprise_linux_server")],
    "centos":        [("redhat", "enterprise_linux_server")],
    "opensuse-leap": [("opensuse", "leap")],
    "opensuse":      [("opensuse", "opensuse")],
    "sles":          [("suse", "suse_linux")],
    "kali":          [("debian", "debian_linux")],
}


WIN_RELEASE_TO_BUILD = {
    "windows_10": {
        "1507": 10240, "1511": 10586, "1607": 14393, "1703": 15063,
        "1709": 16299, "1803": 17134, "1809": 17763, "1903": 18362,
        "1909": 18363, "2004": 19041, "20h2": 19042, "21h1": 19043,
        "21h2": 19044, "22h2": 19045,
    },
    "windows_11": {
        "21h2": 22000, "22h2": 22621, "23h2": 22631,
        "24h2": 26100, "25h2": 26100, "26h1": 26100,
    },
    "windows_server_2008": {"sp2": 6002},
    "windows_server_2008_r2": {"sp1": 7601},
    "windows_server_2012": {"": 9200},
    "windows_server_2012_r2": {"": 9600},
    "windows_server_2016": {"1607": 14393, "1809": 17763, "1903": 18362, "1909": 18363},
    "windows_server_2019": {"1809": 17763, "1903": 18362, "1909": 18363},
    "windows_server_2022": {"21h2": 20348},
    "windows_server_2022_23h2": {"23h2": 25398},
    "windows_server_2025": {"24h2": 26100},
    "windows_7": {"sp1": 7601},
    "windows_8.1": {"": 9600},
    "windows_rt_8.1": {"": 9600},
}


GTFO_SUIDS = [
    "find", "vim*", "nano", "less", "more", "awk", "gawk", "python*", "perl",
    "ruby*", "php*", "bash", "dash", "sh", "zsh", "env", "cp", "mv", "tar",
    "unzip", "zip", "ssh", "scp", "sftp", "curl", "wget", "socat", "nc",
    "ncat", "pkexec", "mount", "umount", "fusermount*", "su", "ping", "ping6",
    "passwd", "chsh", "chfn", "newgrp", "gpasswd", "sudoedit", "tcpdump",
    "capsh", "setcap", "getcap", "systemctl", "journalctl", "busctl", "crontab",
    "at", "flock", "comm", "csplit", "cut", "diff", "expand", "fmt", "fold",
    "head", "join", "nl", "od", "paste", "pr", "sed", "sort", "split", "tail",
    "tee", "tr", "uniq", "xxd", "base64", "openssl", "date", "timeout", "watch",
    "node*", "lua*", "ruby*", "cpan", "gdb", "strace", "taskset", "chroot",
    "nsenter", "unshare", "bwrap", "rpm", "dpkg", "apt*", "dockerd", "docker",
    "runuser", "pkill", "pgrep", "ps", "top", "htop", "ionice", "nice", "nohup",
    "printf", "echo", "sleep", "uptime", "w", "who", "id", "groups", "csh",
    "ksh", "expect", "screen", "tmux", "script", "mail", "mutt", "git", "hg",
    "svn", "rsh", "rlogin", "tclsh*", "wish*", "dbus*", "gcore", "javac", "java",
]


WIN_INTERESTING_PRIVS = {
    "SeImpersonatePrivilege": "Potato family (JuicyPotato/PrintSpoofer/GodPotato)",
    "SeAssignPrimaryTokenPrivilege": "Potato family (JuicyPotato/PrintSpoofer)",
    "SeBackupPrivilege": "robocopy /b atau reg save SAM/SYSTEM + secretsdump",
    "SeRestorePrivilege": "tulis file sistem (ganti driver/service binary)",
    "SeDebugPrivilege": "injeksi ke proses SYSTEM (mimikatz / token steal)",
    "SeTakeOwnershipPrivilege": "ambil kepemilikan file sistem lalu modifikasi",
    "SeLoadDriverPrivilege": "load driver rentan (Capcom / BYOVD)",
    "SeCreateTokenPrivilege": "buat token sendiri (potensi SYSTEM)",
    "SeTcbPrivilege": "bertindak sebagai bagian OS (setara SYSTEM)",
    "SeEnableDelegationPrivilege": "delegasi token (relay/kerberoast vector)",
}


# ======================================================================
# Version engine
# ======================================================================

def _parts(v):
    """Pecah versi jadi token: digit -> int, huruf -> str lowercase.
    '5.15.0-72-generic' -> [5,15,0,72,'generic'] ; '1.9.5p2' -> [1,9,5,'p',2]"""
    return [int(x) if x.isdigit() else x.lower()
            for x in re.findall(r"\d+|[A-Za-z]+", str(v))]


def cmp_version(a, b):
    """Bandingkan dua versi: -1/0/1. numeric > alpha; prefix sama -> lebih
    pendek = lebih kecil ('1.6.3' < '1.6.3_p7', '1.9.5' < '1.9.5p2')."""
    pa, pb = _parts(a), _parts(b)
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int) != isinstance(y, int):
            return 1 if isinstance(x, int) else -1   # numeric > alpha
        return -1 if x < y else 1
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


def normalize_num(v):
    """Hanya digit + buang trailing zero. Untuk kernel/build/distro token:
    '6.8.0-generic' -> [6,8] ; '5.15.0-72' -> [5,15,0,72] ; '20.04' -> [20,4]"""
    toks = [int(x) for x in re.findall(r"\d+", str(v))]
    while toks and toks[-1] == 0:
        toks.pop()
    return toks


def _cmp_list(pa, pb):
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int) != isinstance(y, int):
            return 1 if isinstance(x, int) else -1   # numeric > alpha
        return -1 if x < y else 1
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


def parse_affected(s):
    """'vendor:product [range]' -> (cpe, constraint)
    constraint = [('ALL',None)] | [('EXACT','v')] | [('<','a'),('>=','b'),...]"""
    s = html.unescape(s)
    s = s.replace("\\+", "+").replace("\\_", "_").replace("\\/", "/") \
         .replace("\\(", "(").replace("\\)", ")")
    m = re.match(r"^([^\s]+)\s+\[([^\]]*)\]$", s.strip())
    if not m:
        return None, None
    cpe, body = m.group(1), m.group(2).strip()
    if body.lower() == "all":
        return cpe, [("ALL", None)]
    toks = re.findall(r"(<=|>=|<|>)?\s*([A-Za-z0-9][A-Za-z0-9._~+()]*)", body)
    if not toks:
        return None, None
    if len(toks) == 1 and not toks[0][0]:
        return cpe, [("EXACT", toks[0][1])]
    return cpe, [(op, v) for op, v in toks]


def eval_constraint(installed, constraint, installed_toks=None):
    """Evaluasi constraint terhadap versi terpasang. installed_toks: list int
    ter-normalisasi opsional (untuk kernel/build/distro tier)."""
    if installed_toks is not None:
        pv = installed_toks
    else:
        pv = _parts(installed)
    for op, v in constraint:
        if installed_toks is not None:
            v = re.sub(r"_[A-Za-z0-9]+$", "", v)  # strip arch suffix 7.0_s390x -> 7.0
            qv = normalize_num(v)
        else:
            qv = _parts(v)
        c = _cmp_list(pv, qv)
        if op == "ALL":
            return True
        if op == "EXACT":
            if c != 0:
                return False
        elif op == "<":
            if c >= 0:
                return False
        elif op == "<=":
            if c > 0:
                return False
        elif op == ">":
            if c <= 0:
                return False
        elif op == ">=":
            if c < 0:
                return False
        else:
            return False
    return True


def candidate_versions(pkgver):
    """Varian versi paket yang dicoba: strip epoch '1:', strip debian rev
    '2.0-1ubuntu2' -> '2.0', strip trailing '.0'."""
    v = re.sub(r"^\d+:", "", pkgver)
    out = [v]
    m = re.match(r"^(.+?)-\d[^-]*$", v)
    if m and "-" not in m.group(1):
        out.append(m.group(1))
    for base in list(out):
        b = base
        while True:
            m = re.match(r"^(.*)\.0$", b)
            if not m:
                break
            b = m.group(1)
            out.append(b)
    return out


# ======================================================================
# Distro-kernel / backport detection
# ======================================================================

BACKPORT_GRACE_DAYS = 60
_KERNEL_DISTRO_SUFFIXES = (
    "-generic", "-amd64", "-cloud", "-azure", "-aws", "-gke", "-gcp",
    "-oracle", "-lowlatency", "-realtime", "-rt", "-raspi", "-server",
    "-desktop", "-oem", "+kali", "-kali", "-xanmod", "-liquorix",
)
_DISTRO_KEYWORDS = ("ubuntu", "debian", "kali", "fedora", "redhat", "suse",
                    "arch", "manjaro", "centos", "rocky", "almalinux", "alma",
                    "oracle", "mint", "raspbian")
_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
           "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}


def _parse_proc_version_date(text):
    """Ambil build date dari /proc/version. Dua format:
    - Ubuntu: '... #201-Ubuntu SMP Fri Aug 7 18:39:04 UTC 2026'
    - Debian/Kali: '... Kali 7.1.5-1kali1 (2026-07-29)'
    -> datetime. None jika gagal. Parsing manual (bukan strptime) supaya
    kebal locale bulan non-Inggris."""
    m = re.search(r"\b\w{3} (\w{3})\s+(\d{1,2}) (\d{1,2}):(\d{2}):(\d{2}) \w{3,5} (\d{4})\b",
                  text or "")
    if m:
        mon = _MONTHS.get(m.group(1).lower())
        if mon is not None:
            try:
                return datetime(int(m.group(6)), mon, int(m.group(2)),
                                int(m.group(3)), int(m.group(4)), int(m.group(5)))
            except ValueError:
                pass
    m = re.search(r"\((\d{4})-(\d{2})-(\d{2})\)", text or "")
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    return None


def _kernel_build_info(kernel, proc_version):
    """Deteksi kernel distro (bukan vanilla upstream) + build date-nya.
    Nomor versi kernel distro ('5.15.0-191') memakai skema ABI sendiri
    sehingga TIDAK bisa dibandingkan langsung dengan patch level upstream
    ('5.15.204') — match terhadap rentang NVD jadi rawan false positive."""
    kl = kernel.lower()
    pv = (proc_version or "").lower()
    suffix_hit = any(kl.endswith(s) for s in _KERNEL_DISTRO_SUFFIXES) or \
        "-ubuntu" in kl or "-debian" in kl
    # prioritas: keyword di NAMA KERNEL dulu ('+kali', '-xanmod', ...), baru
    # di /proc/version (hindari false-hit seperti gcc '(Debian 14.2.0-19)')
    name = None
    for d in _DISTRO_KEYWORDS:
        if d in kl:
            name = d
            break
    if name is None:
        for d in _DISTRO_KEYWORDS:
            if d in pv:
                name = d
                break
    if suffix_hit and name is None:
        name = "ubuntu" if ("-generic" in kl or "-ubuntu" in kl) else "debian"
    if not suffix_hit and name is None:
        return {"distro_kernel": False, "distro_name": None,
                "build_date": None, "source": None}
    return {"distro_kernel": True, "distro_name": name,
            "build_date": _parse_proc_version_date(pv) if pv else None,
            "source": "/proc/version" if pv else None}


def _likely_backported(published, build_date, grace_days=BACKPORT_GRACE_DAYS):
    """CVE yang dipublikasikan >grace_days SEBELUM kernel distro di-build
    hampir pasti sudah masuk backport distro. Return bool (False juga jika
    tanggal tidak bisa diparse)."""
    if not published or not build_date:
        return False
    try:
        pub = datetime.strptime(str(published)[:10], "%Y-%m-%d").date()
    except ValueError:
        return False
    bd = build_date.date() if isinstance(build_date, datetime) else build_date
    if not isinstance(bd, type(pub)):
        return False
    return (bd - pub).days > grace_days


# ======================================================================
# Data loading
# ======================================================================

def data_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), DATA_FILENAME)


def load_data():
    p = data_path()
    if not os.path.exists(p):
        sys.exit(f"[!] {DATA_FILENAME} tidak ditemukan di samping lpescan.py — "
                 f"jalankan build-scanner.py di mesin arsip, lalu copy ulang dist/.")
    try:
        with gzip.open(p, "rt", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        sys.exit(f"[!] {DATA_FILENAME} korup/gagal dibaca: {e}")


def build_index(cves):
    """index['vendor:product'] -> [(ci, pi, constraint, raw_string)]"""
    idx = {}
    for ci, r in enumerate(cves):
        aff = r.get("affected") or []
        for pi, a in enumerate(aff):
            cpe, cons = parse_affected(a)
            if cpe is None or cons is None:
                continue
            idx.setdefault(cpe, []).append((ci, pi, cons, a))
    return idx


# ======================================================================
# Command helpers (semua hardcoded, tidak pernah input user)
# ======================================================================

def run_cmd(cmd, timeout=15):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout)
    except Exception:
        return None


def sh_out(cmd, timeout=15):
    r = run_cmd(cmd, timeout)
    if r is None or r.returncode != 0:
        return ""
    return (r.stdout or "") + (r.stderr or "")


# ======================================================================
# Facts collection
# ======================================================================

def _in_container():
    """Deteksi apakah scanner berjalan di dalam container (/.dockerenv atau cgroup)."""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup") as f:
            cg = f.read()
        if any(k in cg for k in ("docker", "kubepods", "lxc", "libpod")):
            return True
    except OSError:
        pass
    return False


def collect_facts_linux():
    distro = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    distro[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    if not distro:
        r = run_cmd("lsb_release -a 2>/dev/null")
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                m = re.match(r"(Distributor ID|Release|Codename):\s*(.+)", line)
                if m:
                    key = {"Distributor ID": "ID", "Release": "VERSION_ID",
                           "Codename": "VERSION_CODENAME"}[m.group(1)]
                    distro[key] = m.group(2).strip().lower()
    packages = {}
    r = run_cmd("dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null", 30)
    if r and r.returncode == 0 and r.stdout.strip():
        for line in r.stdout.splitlines():
            if "\t" in line:
                name, ver = line.split("\t", 1)
                packages[name] = ver
    if not packages:
        r = run_cmd("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null", 30)
        if r and r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.splitlines():
                if "\t" in line:
                    name, ver = line.split("\t", 1)
                    packages[name] = ver
    debian_version = ""
    try:
        with open("/etc/debian_version") as f:
            debian_version = f.read().strip()
    except OSError:
        pass
    kernel_str = platform.release()
    proc_version = ""
    try:
        with open("/proc/version") as f:
            proc_version = f.read().strip()
    except OSError:
        pass
    if not proc_version:
        r = run_cmd("uname -v")
        if r and r.returncode == 0:
            proc_version = r.stdout.strip()
    return {
        "hostname": socket.gethostname(),
        "os": "linux",
        "arch": platform.machine(),
        "kernel": kernel_str,
        "kernel_build": _kernel_build_info(kernel_str, proc_version),
        "distro": {"id": distro.get("ID", "").lower(),
                   "version_id": distro.get("VERSION_ID", ""),
                   "codename": distro.get("VERSION_CODENAME", ""),
                   "pretty": distro.get("PRETTY_NAME", "")},
        "debian_version": debian_version,
        "packages": packages,
        "in_container": _in_container(),
    }


def collect_facts_windows():
    import winreg  # guarded: hanya diimpor di Windows
    build, ubr, dver, product, edition = 0, 0, "", "", ""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            def rv(name):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return ""
            build = int(rv("CurrentBuildNumber") or 0)
            ubr = int(rv("UBR") or 0)
            dver = str(rv("DisplayVersion") or "")
            product = str(rv("ProductName") or "")
            edition = str(rv("EditionID") or "")
    except Exception:
        pass
    if not build:
        txt = sh_out("powershell -NoProfile -NonInteractive -Command \""
                     "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion') | "
                     "Select-Object CurrentBuildNumber,UBR,DisplayVersion,ProductName,EditionID | Format-List\"", 30)
        for m in re.finditer(r"(\w+)\s*:\s*(.+)", txt):
            k_, v_ = m.group(1), m.group(2).strip()
            if k_ == "CurrentBuildNumber":
                try:
                    build = int(v_ or 0)
                except ValueError:
                    build = 0
            elif k_ == "UBR":
                try:
                    ubr = int(v_ or 0)
                except ValueError:
                    ubr = 0
            elif k_ == "DisplayVersion":
                dver = v_
            elif k_ == "ProductName":
                product = v_
            elif k_ == "EditionID":
                edition = v_

    full_build = f"10.0.{build}.{ubr}" if build else ""
    prod_l = product.lower()
    is_server = "server" in prod_l

    # derive family + release tokens
    tokens = []
    fam = None
    if build:
        if is_server:
            fam = "windows_server"
            if build >= 26100:
                tokens.append("windows_server_2025")
            elif build >= 25398:
                tokens.append("windows_server_2022_23h2")
            elif build >= 20348:
                tokens.append("windows_server_2022")
            elif build >= 17763:
                tokens.append("windows_server_2019")
            elif build >= 14393:
                tokens.append("windows_server_2016")
            elif build >= 9600:
                tokens.append("windows_server_2012_r2")
            elif build >= 9200:
                tokens.append("windows_server_2012")
            elif build >= 7601:
                tokens.append("windows_server_2008_r2")
            else:
                tokens.append("windows_server_2008")
        elif build >= 26100:
            fam = "windows_11"
            tokens += ["windows_11_24h2", "windows_11_25h2", "windows_11_26h1"]
        elif build >= 22000:
            fam = "windows_11"
            rel = dver.lower() or ""
            for r_, b_ in WIN_RELEASE_TO_BUILD.get("windows_11", {}).items():
                if b_ == build:
                    rel = r_
            tokens.append(f"windows_11_{rel}" if rel else "windows_11")
        elif build >= 10240:
            fam = "windows_10"
            rel = dver.lower() or ""
            for r_, b_ in WIN_RELEASE_TO_BUILD.get("windows_10", {}).items():
                if b_ == build:
                    rel = r_
            tokens.append(f"windows_10_{rel}" if rel else "windows_10")
        elif build >= 9600:
            fam = "windows_8.1"
            tokens.append("windows_8.1")
        elif build >= 7601:
            fam = "windows_7"
            tokens.append("windows_7")
    if fam:
        tokens.append(fam)
    tokens = sorted(set(tokens))

    hotfixes = []
    out = sh_out("powershell -NoProfile -NonInteractive -Command "
                 "\"Get-CimInstance Win32_QuickFixEngineering | Select-Object -ExpandProperty HotFixID\"", 40)
    if out.strip():
        hotfixes = [l.strip() for l in out.splitlines() if l.strip() and re.match(r"^KB\d+", l.strip(), re.I)]
    if not hotfixes:
        out = sh_out("wmic qfe get HotFixID 2>nul", 40)
        hotfixes = [l.strip() for l in out.splitlines()
                    if re.match(r"^KB\d+", l.strip(), re.I)]

    privileges = []
    out = sh_out("whoami /priv", 20)
    privileges = re.findall(r"(Se\w+Privilege)", out)

    return {
        "hostname": socket.gethostname(),
        "os": "windows",
        "arch": platform.machine(),
        "windows": {
            "product_name": product,
            "edition": edition,
            "display_version": dver,
            "build": build,
            "ubr": ubr,
            "full_build": full_build,
            "release_tokens": tokens,
            "hotfixes": hotfixes,
            "privileges": sorted(set(privileges)),
        },
        "packages": {},
        "distro": {},
    }


def collect_facts():
    return collect_facts_windows() if platform.system() == "Windows" else collect_facts_linux()


# ======================================================================
# CVE matcher
# ======================================================================

TIER = {"kernel": 0, "package": 1, "os_build": 2, "distro_pin": 3}

def _add_match(res, ci, cve, tier, conf, cpe, raw, installed, backported=False):
    if backported and conf == "high":
        conf = "possible"
    cur = res.get(ci)
    if cur is None or TIER[tier] < TIER[cur["tier"]]:
        res[ci] = {"tier": tier, "confidence": conf, "matches": []}
    elif TIER[tier] > TIER[cur["tier"]]:
        return
    else:
        if conf == "high":
            res[ci]["confidence"] = "high"
    if backported:
        res[ci]["likely_backported"] = True
    if cve.get("escape"):
        res[ci]["escape_class"] = True
    res[ci]["matches"].append({"cpe": cpe, "constraint": raw, "installed": installed})


def match_cves(facts, data):
    cves = data["cves"]
    idx = build_index(cves)
    res = {}

    def is_all(cons):
        return len(cons) == 1 and cons[0][0] == "ALL"

    # ---- tier kernel ----
    # facts windows tidak punya key "kernel" -> guard wajib (sebelumnya KeyError);
    # knorm kosong juga berbahaya: eval_constraint tanpa pv-guard akan match [>=x]
    # terhadap [] dan menghasilkan kernel match palsu di host windows
    if facts.get("kernel"):
        knorm = normalize_num(facts["kernel"])
        kb = facts.get("kernel_build") or {}
        kb_flag = bool(kb.get("distro_kernel"))
        kb_date = kb.get("build_date")
        for ci, pi, cons, raw in idx.get("linux:linux_kernel", []):
            if is_all(cons):
                if cves[ci].get("kev"):
                    _add_match(res, ci, cves[ci], "kernel", "possible",
                               "linux:linux_kernel", raw, facts["kernel"],
                               backported=kb_flag and _likely_backported(
                                   cves[ci].get("published"), kb_date))
                continue
            if eval_constraint(None, cons, installed_toks=knorm):
                _add_match(res, ci, cves[ci], "kernel", "high",
                           "linux:linux_kernel", raw, facts["kernel"],
                           backported=kb_flag and _likely_backported(
                               cves[ci].get("published"), kb_date))

    # ---- tier package ----
    for name, ver in facts["packages"].items():
        nl = name.lower()
        for pat, aliases in PKG_TO_CPE.items():
            if not fnmatch.fnmatch(nl, pat):
                continue
            for vend, prod in aliases:
                for ci, pi, cons, raw in idx.get(f"{vend}:{prod}", []):
                    if is_all(cons):
                        if cves[ci].get("kev"):
                            _add_match(res, ci, cves[ci], "package", "possible",
                                       f"{vend}:{prod}", raw, f"{name} {ver}")
                        continue
                    for cand in candidate_versions(ver):
                        if eval_constraint(cand, cons):
                            _add_match(res, ci, cves[ci], "package", "high",
                                       f"{vend}:{prod}", raw, f"{name} {ver}")
                            break

    # ---- tier distro pin ----
    if facts["distro"]:
        did = facts["distro"].get("id", "")
        vids = [facts["distro"].get("version_id", "")]
        if facts.get("debian_version"):
            vids.append(facts["debian_version"])
        for distro_id, aliases in DISTRO_TO_CPE.items():
            if did != distro_id:
                continue
            for vend, prod in aliases:
                for ci, pi, cons, raw in idx.get(f"{vend}:{prod}", []):
                    if is_all(cons):
                        continue
                    for vid in vids:
                        if not vid:
                            continue
                        dnorm = normalize_num(vid)
                        if not dnorm:
                            continue
                        if eval_constraint(None, cons, installed_toks=dnorm):
                            _add_match(res, ci, cves[ci], "distro_pin", "possible",
                                       f"{vend}:{prod}", raw, f"{did} {vid}")
                            break

    # ---- tier windows ----
    if facts["os"] == "windows":
        w = facts["windows"]
        tokens = set(w["release_tokens"])
        build_norm = normalize_num(w["full_build"])
        token_fams = set()
        for t in tokens:
            if t.startswith("windows_server"):
                token_fams.add("windows_server")
            elif t.startswith("windows_11"):
                token_fams.add("windows_11")
            elif t.startswith("windows_10"):
                token_fams.add("windows_10")
            elif t.startswith("windows_8"):
                token_fams.add("windows_8")
            elif t.startswith("windows_7"):
                token_fams.add("windows_7")

        def entry_fam(prod):
            if prod.startswith("windows_server"):
                return "windows_server"
            for f in ("windows_11", "windows_10", "windows_8", "windows_7"):
                if prod.startswith(f):
                    return f
            return prod

        for cpe_key, entries in idx.items():
            vend, prod = cpe_key.split(":", 1)
            if vend != "microsoft" or not prod.startswith("windows_"):
                continue
            efam = entry_fam(prod)
            if efam not in token_fams and efam not in ("windows_10", "windows_11", "windows_server"):
                continue
            fam_ok = efam in token_fams
            for ci, pi, cons, raw in entries:
                if is_all(cons):
                    if fam_ok and (cves[ci].get("kev") or prod in tokens):
                        _add_match(res, ci, cves[ci], "os_build", "possible",
                                   cpe_key, raw, w["full_build"])
                    continue
                if cons[0][0] == "EXACT":
                    # release token [1607] / [20h2] / [sp1]
                    rel = cons[0][1].lower()
                    relmap = WIN_RELEASE_TO_BUILD.get(prod)
                    if not relmap and fam_ok:
                        # product token generik (windows_10) -> cari di family map
                        base = prod
                        if base in WIN_RELEASE_TO_BUILD:
                            relmap = WIN_RELEASE_TO_BUILD[base]
                    if relmap:
                        b = relmap.get(rel, relmap.get(rel.lstrip("0")))
                        if b is not None and b == w["build"]:
                            _add_match(res, ci, cves[ci], "os_build", "high",
                                       cpe_key, raw, w["full_build"])
                    continue
                # bound build: product token harus tepat di tokens terdeteksi
                if prod not in tokens:
                    continue
                if eval_constraint(None, cons, installed_toks=build_norm):
                    _add_match(res, ci, cves[ci], "os_build", "high",
                               cpe_key, raw, w["full_build"])
    return res


# ======================================================================
# PEAS checks
# ======================================================================

PEAS_CHECKS = []  # [(category, name, scope, func)]

def peas_check(cat, scope):
    def deco(fn):
        PEAS_CHECKS.append((cat, fn.__name__, scope, fn))
        return fn
    return deco


def F(cat, sev, title, detail=""):
    return {"category": cat, "severity": sev, "title": title, "detail": detail}


# ---------------- LINUX ----------------

@peas_check("system", "linux")
def chk_linux_sysinfo(ctx):
    out = []
    un = sh_out("uname -a")
    if un.strip():
        out.append(F("system", "INFO", "uname", un.strip()))
    if ctx["facts"]["distro"].get("pretty"):
        out.append(F("system", "INFO", "distro", ctx["facts"]["distro"]["pretty"]))
    for p in ("/proc/sys/kernel/randomize_va_space", "/proc/sys/kernel/kptr_restrict",
              "/proc/sys/kernel/dmesg_restrict", "/proc/sys/kernel/unprivileged_userns_clone",
              "/proc/sys/kernel/yama/ptrace_scope"):
        try:
            v = open(p).read().strip()
        except OSError:
            continue
        name = os.path.basename(p)
        if name == "randomize_va_space" and v == "0":
            out.append(F("system", "MEDIUM", "ASLR mati", f"{p} = 0 (eksploitasi lebih mudah)"))
        elif name == "kptr_restrict" and v == "0":
            out.append(F("system", "LOW", "kptr_restrict=0", "alamat kernel terlihat dari usermode"))
        elif name == "dmesg_restrict" and v == "0":
            out.append(F("system", "LOW", "dmesg bisa dibaca user", "dmesg_restrict=0"))
        elif name == "unprivileged_userns_clone" and v == "1":
            out.append(F("system", "LOW", "user namespaces aktif", "unprivileged_userns_clone=1"))
    if os.access("/dev/kmsg", os.R_OK):
        out.append(F("system", "LOW", "/dev/kmsg bisa dibaca", "leak alamat kernel"))
    for f in ("/etc/ld.so.preload",):
        if os.access(f, os.W_OK):
            out.append(F("system", "HIGH", f"{f} writable!", "injeksi library via preload"))
    if os.environ.get("LD_LIBRARY_PATH"):
        out.append(F("system", "LOW", "LD_LIBRARY_PATH di environment",
                     os.environ["LD_LIBRARY_PATH"]))
    try:
        symlink = open("/proc/sys/fs/protected_symlinks").read().strip()
        hardlink = open("/proc/sys/fs/protected_hardlinks").read().strip()
        if symlink == "0":
            out.append(F("system", "MEDIUM", "protected_symlinks=0", "symlink attack dimungkinkan"))
        if hardlink == "0":
            out.append(F("system", "MEDIUM", "protected_hardlinks=0", "hardlink attack dimungkinkan"))
    except OSError:
        pass
    for f in ("/etc/hosts.equiv",):
        if os.path.exists(f):
            out.append(F("system", "HIGH", f"{f} ada!", "trust equivalence"))
    for f in ("/etc/selinux/config",):
        if os.path.exists(f):
            v = sh_out("getenforce 2>/dev/null").strip()
            out.append(F("system", "INFO", f"SELinux: {v or 'konfigurasi ada'}", f))
    if os.path.isdir("/sys/kernel/security/apparmor"):
        out.append(F("system", "INFO", "AppArmor aktif", "/sys/kernel/security/apparmor"))
    return out


@peas_check("users", "linux")
def chk_linux_users(ctx):
    out = []
    try:
        for line in open("/etc/passwd"):
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(":")
            if len(parts) > 6 and (parts[2] == "0" or parts[3] == "0") and parts[0] != "root":
                out.append(F("users", "HIGH", f"akun UID/GID 0 selain root: {parts[0]}", line.strip()))
    except OSError:
        pass
    try:
        groups = open("/etc/group").read()
        for g in ("sudo", "wheel", "docker", "lxd", "lxc", "adm", "shadow", "disk", "video"):
            for line in groups.splitlines():
                if line.startswith(g + ":"):
                    members = line.split(":")[3].strip()
                    if members:
                        out.append(F("users", "HIGH" if g in ("sudo", "wheel", "docker", "lxd", "lxc") else "MEDIUM",
                                     f"anggota grup {g}: {members}", line.strip()))
    except OSError:
        pass
    try:
        st = os.stat("/etc/sudoers")
        if st.st_mode & 0o002:
            out.append(F("users", "HIGH", "/etc/sudoers world-writable!"))
    except OSError:
        pass
    if os.path.isdir("/etc/sudoers.d"):
        for f in os.listdir("/etc/sudoers.d"):
            p = os.path.join("/etc/sudoers.d", f)
            try:
                if os.stat(p).st_mode & 0o002:
                    out.append(F("users", "HIGH", f"{p} world-writable!"))
            except OSError:
                pass
    return out


@peas_check("sudo", "linux")
def chk_linux_sudo(ctx):
    out = []
    v = sh_out("sudo -V 2>/dev/null | head -1").strip()
    if v:
        out.append(F("sudo", "INFO", "sudo version", v))
    l = sh_out("sudo -n -l 2>&1").strip()
    if l and "not allowed" not in l.lower() and "a password is required" not in l.lower() and "command not found" not in l.lower():
        if re.search(r"\(ALL\s*(:\s*ALL)?\)\s*(ALL|NOPASSWD:\s*ALL)", l) or "NOPASSWD" in l:
            out.append(F("sudo", "HIGH", "sudo NOPASSWD untuk user ini", l[:400]))
        else:
            out.append(F("sudo", "MEDIUM", "sudo -l tersedia (non-interaktif)", l[:400]))
        if re.search(r"env_keep\+=?(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB)", l):
            out.append(F("sudo", "HIGH", "sudo env_keep LD_* terkonfigurasi", "potensi injeksi library"))
    try:
        sr = ""
        for f in ("/etc/sudoers",) + tuple(glob.glob("/etc/sudoers.d/*")):
            try:
                sr += open(f).read() + "\n"
            except OSError:
                pass
        for m in re.finditer(r"^[^#\n]*NOPASSWD.*$", sr, re.M):
            out.append(F("sudo", "HIGH", "baris NOPASSWD di sudoers", m.group(0).strip()))
    except OSError:
        pass
    return out


@peas_check("suid", "linux")
def chk_linux_suid(ctx):
    out = []
    found = []
    skip = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker",
            "/var/lib/lxc", "/var/cache", "/var/tmp", "/tmp")
    try:
        for root, dirs, files in os.walk("/", followlinks=False):
            dirs[:] = [d for d in dirs if not any(os.path.join(root, d).startswith(s) for s in skip)]
            if len(found) > 400:
                break
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    mode = os.lstat(p).st_mode
                except OSError:
                    continue
                if mode & 0o4000 or mode & 0o2000:
                    found.append((p, mode))
    except Exception:
        pass
    for p, mode in found:
        base = os.path.basename(p).lower()
        suid = bool(mode & 0o4000)
        tag = "SUID" if suid else "SGID"
        if any(fnmatch.fnmatch(base, g) for g in GTFO_SUIDS):
            out.append(F("suid", "HIGH" if suid else "MEDIUM",
                         f"{tag} GTFO-bins: {p}", oct(mode)[-4:]))
        elif suid:
            out.append(F("suid", "MEDIUM", f"SUID custom: {p}", oct(mode)[-4:]))
    return out


@peas_check("capabilities", "linux")
def chk_linux_caps(ctx):
    out = []
    txt = sh_out("getcap -r / 2>/dev/null", 45)
    if not txt.strip():
        txt = sh_out("/usr/sbin/getcap -r / 2>/dev/null", 45)
    dangerous = ("cap_setuid", "cap_dac_override", "cap_dac_read_search", "cap_chown",
                 "cap_sys_admin", "cap_sys_module", "cap_net_admin", "cap_sys_ptrace",
                 "cap_net_raw", "cap_setgid", "cap_linux_immutable", "cap_fowner")
    for line in txt.splitlines():
        if any(d in line.lower() for d in dangerous):
            out.append(F("capabilities", "HIGH", "file capability berbahaya", line.strip()))
        elif "=" in line:
            out.append(F("capabilities", "MEDIUM", "file capability", line.strip()))
    return out


@peas_check("path", "linux")
def chk_linux_path(ctx):
    out = []
    for ent in os.environ.get("PATH", "").split(":"):
        if ent in ("", "."):
            out.append(F("path", "HIGH", "PATH berisi '.' atau entri kosong", f"PATH={os.environ.get('PATH','')}"))
            continue
        if not ent:
            continue
        try:
            st = os.stat(ent)
            if st.st_mode & 0o002:
                out.append(F("path", "HIGH", f"entri PATH world-writable: {ent}"))
            elif st.st_uid != 0 and os.geteuid() != st.st_uid:
                out.append(F("path", "MEDIUM", f"entri PATH milik user lain: {ent}"))
        except OSError:
            pass
    return out


@peas_check("cron", "linux")
def chk_linux_cron(ctx):
    out = []
    cron_files = ["/etc/crontab"] + glob.glob("/etc/cron.d/*") + \
                 glob.glob("/etc/cron.hourly/*") + glob.glob("/etc/cron.daily/*") + \
                 glob.glob("/etc/cron.weekly/*") + glob.glob("/etc/cron.monthly/*") + \
                 glob.glob("/var/spool/cron/crontabs/*") + glob.glob("/var/spool/cron/*")
    for p in cron_files:
        if not os.path.exists(p):
            continue
        try:
            st = os.stat(p)
            if st.st_mode & 0o002:
                out.append(F("cron", "HIGH", f"file cron world-writable: {p}"))
            if st.st_uid != 0:
                out.append(F("cron", "MEDIUM", f"file cron milik non-root: {p}"))
        except OSError:
            continue
        try:
            body = open(p).read()
            if re.search(r"\b(tar|chown|chmod|rsync|zip|find)\b[^\n]*\*", body):
                out.append(F("cron", "HIGH", f"kemungkinan wildcard injection di {p}",
                             [l.strip() for l in body.splitlines()
                              if re.search(r"\b(tar|chown|chmod|rsync|zip|find)\b[^\n]*\*", l)][:3]))
        except OSError:
            pass
    for d in ("/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"):
        try:
            if os.path.isdir(d) and os.stat(d).st_mode & 0o002:
                out.append(F("cron", "HIGH", f"direktori cron world-writable: {d}"))
        except OSError:
            pass
    return out


@peas_check("passwd", "linux")
def chk_linux_passwd(ctx):
    out = []
    for f in ("/etc/passwd", "/etc/shadow", "/etc/gshadow"):
        try:
            st = os.stat(f)
            if st.st_mode & 0o002:
                out.append(F("passwd", "HIGH", f"{f} world-writable!"))
            if f == "/etc/shadow" and os.access(f, os.R_OK) and st.st_uid != os.geteuid():
                out.append(F("passwd", "HIGH", "/etc/shadow bisa dibaca (hash crack)"))
        except OSError:
            pass
    return out


@peas_check("containers", "linux")
def chk_linux_containers(ctx):
    out = []
    if os.path.exists("/.dockerenv"):
        out.append(F("containers", "INFO", "berjalan di dalam container docker"))
    try:
        with open("/proc/1/cgroup") as f:
            if "docker" in f.read() or "kubepod" in f.read():
                out.append(F("containers", "INFO", "cgroup menunjukkan container"))
    except OSError:
        pass
    if os.path.exists("/var/run/docker.sock"):
        try:
            if os.stat("/var/run/docker.sock").st_mode & 0o002 or os.access("/var/run/docker.sock", os.W_OK):
                out.append(F("containers", "HIGH", "docker.sock writable!", "docker run -v /:/host → escape"))
            else:
                out.append(F("containers", "MEDIUM", "docker.sock ada (perlu grup docker)"))
        except OSError:
            out.append(F("containers", "MEDIUM", "docker.sock ada"))
    for p in ("/run/podman/podman.sock", "/run/containerd/containerd.sock"):
        if os.path.exists(p):
            out.append(F("containers", "MEDIUM", f"{p} ada"))
    for p in ("/root/.kube/config", os.path.expanduser("~/.kube/config")):
        if os.path.exists(p):
            out.append(F("containers", "HIGH", f"kubeconfig: {p}"))
    return out


@peas_check("network", "linux")
def chk_linux_net(ctx):
    out = []
    txt = sh_out("ss -tlnp 2>/dev/null", 15)
    if not txt.strip():
        txt = sh_out("netstat -tlnp 2>/dev/null", 15)
    for line in txt.splitlines():
        m = re.search(r"pid=(\d+)", line)
        if not m:
            continue
        pid = m.group(1)
        try:
            status = open(f"/proc/{pid}/status").read()
            if "Uid:\t0\t" in status:
                out.append(F("network", "MEDIUM", f"service sebagai root: {line.strip()[:120]}"))
        except OSError:
            pass
    interesting = {"127.0.0.1:6379": "redis", "127.0.0.1:3306": "mysql",
                   "127.0.0.1:5432": "postgres", "127.0.0.1:2375": "docker-api",
                   "127.0.0.1:27017": "mongodb", "127.0.0.1:11211": "memcached",
                   "127.0.0.1:9200": "elasticsearch", ":22": "ssh"}
    for line in txt.splitlines():
        for port, svc in interesting.items():
            if port in line:
                out.append(F("network", "INFO", f"listener {svc} terdeteksi", line.strip()[:120]))
    r = run_cmd("redis-cli -h 127.0.0.1 ping 2>/dev/null", 3)
    if r and r.stdout and "PONG" in r.stdout:
        out.append(F("network", "HIGH", "redis tanpa auth!", "redis-cli ping → PONG"))
    return out


@peas_check("systemd", "linux")
def chk_linux_systemd(ctx):
    out = []
    for d in ("/etc/systemd/system", "/usr/lib/systemd/system"):
        for f in glob.glob(d + "/*.service") + glob.glob(d + "/*.timer"):
            try:
                st = os.stat(f)
                if st.st_mode & 0o002:
                    out.append(F("systemd", "HIGH", f"unit systemd world-writable: {f}"))
            except OSError:
                continue
            try:
                body = open(f).read()
                for m in re.finditer(r"Exec\w*=(/[\w./-]+)", body):
                    exe = m.group(1)
                    if os.path.exists(exe):
                        try:
                            if os.stat(exe).st_mode & 0o002:
                                out.append(F("systemd", "HIGH",
                                             f"binary ExecStart writable: {exe} (unit {f})"))
                        except OSError:
                            pass
            except OSError:
                pass
    return out


@peas_check("nfs", "linux")
def chk_linux_nfs(ctx):
    out = []
    try:
        for line in open("/etc/exports"):
            line = line.strip()
            if line and not line.startswith("#"):
                if "no_root_squash" in line or re.search(r"\brw\b", line):
                    out.append(F("nfs", "HIGH" if "no_root_squash" in line else "MEDIUM",
                                 "export NFS berisiko", line))
    except OSError:
        pass
    txt = sh_out("mount -t nfs,nfs4 2>/dev/null")
    if txt.strip():
        out.append(F("nfs", "INFO", "mount NFS", txt.strip().splitlines()[:5]))
    return out


@peas_check("credentials", "linux")
def chk_linux_creds(ctx):
    out = []
    pat = re.compile(r"(password|passwd|token|secret|api[_-]?key|access[_-]?key|mysql|psql|bearer)", re.I)
    homes = [os.path.expanduser("~"), "/root"] + [d for d in glob.glob("/home/*") if os.path.isdir(d)]
    for h in set(homes):
        for hf in (".bash_history", ".zsh_history", ".mysql_history", ".psql_history"):
            p = os.path.join(h, hf)
            try:
                if os.path.exists(p) and os.access(p, os.R_OK):
                    hits = [l.strip() for l in open(p, errors="ignore") if pat.search(l)][:3]
                    if hits:
                        out.append(F("credentials", "MEDIUM", f"{p}: kredensial mencurigakan", hits))
            except OSError:
                pass
        for kf in ("id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"):
            p = os.path.join(h, ".ssh", kf)
            if os.path.exists(p) and os.access(p, os.R_OK):
                out.append(F("credentials", "HIGH", f"kunci SSH terbaca: {p}"))
        for cf in (".aws/credentials", ".git-credentials", ".netrc", ".config/gcloud/credentials.db"):
            p = os.path.join(h, cf)
            if os.path.exists(p) and os.access(p, os.R_OK):
                out.append(F("credentials", "HIGH", f"file kredensial: {p}"))
    for p in glob.glob("/var/www/*/wp-config.php") + glob.glob("/var/www/*/*/wp-config.php"):
        if os.path.exists(p) and os.access(p, os.R_OK):
            out.append(F("credentials", "HIGH", f"wp-config.php terbaca: {p}"))
    for p in glob.glob("/var/www/*/.env") + glob.glob("/var/www/*/*/.env"):
        if os.path.exists(p) and os.access(p, os.R_OK):
            out.append(F("credentials", "HIGH", f".env terbaca: {p}"))
    return out


@peas_check("sessions", "linux")
def chk_linux_sessions(ctx):
    out = []
    for p in glob.glob("/tmp/tmux-*") + glob.glob("/tmp/.tmux*") + \
             glob.glob("/run/screen/S-*") + glob.glob("/var/run/screen/S-*") + \
             glob.glob("/dev/shm/screen/S-*"):
        out.append(F("sessions", "MEDIUM", f"socket sesi aktif: {p}",
                     f"attach: tmux -S {p}" if "tmux" in p else f"attach: screen -x {p}"))
    return out


@peas_check("git", "linux")
def chk_linux_git(ctx):
    out = []
    p = os.path.expanduser("~/.gitconfig")
    if os.path.exists(p) and os.access(p, os.R_OK):
        out.append(F("git", "INFO", "gitconfig user", p))
    r = run_cmd("find /home /root /var/www /opt /srv -maxdepth 5 \\( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name '*.ovpn' -o -name '*.kdbx' \\) -type f 2>/dev/null", 20)
    if r and r.stdout.strip():
        for line in r.stdout.splitlines()[:15]:
            out.append(F("git", "MEDIUM", f"file sensitif ditemukan: {line.strip()}"))
    return out


@peas_check("misc", "linux")
def chk_linux_misc(ctx):
    out = []
    for d in ("/etc/update-motd.d",):
        try:
            if os.path.isdir(d) and os.stat(d).st_mode & 0o002:
                out.append(F("misc", "MEDIUM", f"{d} world-writable (motd exec saat login)"))
        except OSError:
            pass
    for h in ("/root", os.path.expanduser("~")):
        for f in (".rhosts", ".forward"):
            p = os.path.join(h, f)
            if os.path.exists(p):
                out.append(F("misc", "MEDIUM", f"{p} ada"))
    txt = sh_out("ps aux 2>/dev/null")
    for proc in ("mysqld", "mariadbd"):
        if re.search(rf"^(\S+)\s+\d+.*{proc}.*--skip-grant-tables", txt, re.M):
            out.append(F("misc", "HIGH", "mysqld jalan dengan --skip-grant-tables!"))
    return out


# ---------------- WINDOWS ----------------

@peas_check("os", "windows")
def chk_win_os(ctx):
    out = []
    w = ctx["facts"]["windows"]
    out.append(F("os", "INFO", "OS", f"{w['product_name']} {w['edition']} build {w['full_build']} ({w['display_version']})"))
    r = run_cmd("powershell -NoProfile -NonInteractive -Command "
                "\"(Get-CimInstance Win32_ComputerSystem) | Select-Object -ExpandProperty PartOfDomain\"", 20)
    if r and r.stdout.strip().lower() == "false":
        out.append(F("os", "INFO", "workgroup (bukan domain)"))
    for k, v in os.environ.items():
        if k.lower() in ("computername", "username"):
            out.append(F("os", "INFO", k, v))
    return out


@peas_check("hotfixes", "windows")
def chk_win_hotfixes(ctx):
    out = []
    w = ctx["facts"]["windows"]
    if w["hotfixes"]:
        out.append(F("hotfixes", "INFO", f"{len(w['hotfixes'])} hotfix terpasang",
                     ", ".join(w["hotfixes"][:20]) + ("..." if len(w["hotfixes"]) > 20 else "")))
    else:
        out.append(F("hotfixes", "LOW", "daftar hotfix tidak terbaca (query gagal)"))
    return out


@peas_check("services", "windows")
def chk_win_services(ctx):
    out = []
    txt = sh_out("powershell -NoProfile -NonInteractive -Command "
                 "\"Get-CimInstance Win32_Service | Select-Object Name,State,StartName,PathName | Format-List\"", 45)
    blocks = re.split(r"\n\s*\n", txt)
    for b in blocks:
        name = re.search(r"^Name\s*:\s*(.+)$", b, re.M)
        path = re.search(r"^PathName\s*:\s*(.+)$", b, re.M)
        start = re.search(r"^StartName\s*:\s*(.+)$", b, re.M)
        if not path:
            continue
        p = path.group(1).strip().strip('"')
        nm = (name.group(1).strip() if name else "?")
        sm = (start.group(1).strip() if start else "?")
        if re.match(r"^[A-Za-z]:\\[^\"']* [^\"']*$", path.group(1).strip()):
            out.append(F("services", "HIGH", f"unquoted service path: {nm}", p))
        d = os.path.dirname(p)
        if d and os.path.isdir(d):
            try:
                if os.access(d, os.W_OK):
                    out.append(F("services", "HIGH", f"dir binary service writable: {d} ({nm}, StartName={sm})"))
            except OSError:
                pass
    return out


@peas_check("registry", "windows")
def chk_win_alwaysinstalled(ctx):
    out = []
    for h in ("HKLM", "HKCU"):
        for p in (f"{h}\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                  f"{h}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Installer"):
            r = run_cmd(f'reg query "{p}" /v AlwaysInstallElevated 2>nul', 10)
            if r and r.stdout and re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1", r.stdout):
                out.append(F("registry", "HIGH", f"AlwaysInstallElevated aktif di {h}", "msi dengan payload → SYSTEM"))
    return out


@peas_check("privileges", "windows")
def chk_win_privs(ctx):
    out = []
    privs = ctx["facts"]["windows"]["privileges"]
    for p in privs:
        if p in WIN_INTERESTING_PRIVS:
            out.append(F("privileges", "HIGH", f"token privilege: {p}",
                         f"saran: {WIN_INTERESTING_PRIVS[p]}"))
        else:
            out.append(F("privileges", "INFO", f"token privilege: {p}"))
    return out


@peas_check("credentials", "windows")
def chk_win_creds(ctx):
    out = []
    r = run_cmd("cmdkey /list", 10)
    if r and r.stdout:
        tg = re.findall(r"Target:\s*(\S+)", r.stdout)
        if tg:
            out.append(F("credentials", "MEDIUM", f"stored credentials: {len(tg)} target", ", ".join(tg[:10])))
    r = run_cmd("vaultcmd /list", 10)
    if r and "Error" not in r.stdout and r.stdout.strip():
        out.append(F("credentials", "INFO", "credential vault ada", r.stdout.strip().splitlines()[:5]))
    for f in (r"C:\Windows\System32\config\SAM", r"C:\Windows\System32\config\SYSTEM"):
        if os.path.exists(f):
            try:
                if os.access(f, os.R_OK):
                    out.append(F("credentials", "HIGH", f"{os.path.basename(f)} terbaca (secretsdump!)"))
            except OSError:
                pass
    for p in (r"C:\Users", r"C:\ProgramData"):
        if os.path.isdir(p):
            for fn in ("unattend.xml", "sysprep.xml", "sysprep.inf"):
                for m in glob.glob(os.path.join(p, "**", fn), recursive=True)[:5]:
                    if os.path.exists(m):
                        try:
                            body = open(m, errors="ignore").read()
                            if "<PlainText>true</PlainText>" in body or "Password" in body:
                                out.append(F("credentials", "HIGH", f"unattend berisi password: {m}"))
                            else:
                                out.append(F("credentials", "MEDIUM", f"file unattend: {m}"))
                        except OSError:
                            out.append(F("credentials", "MEDIUM", f"file unattend: {m}"))
    for d in (r"C:\Windows\Panther",):
        for m in glob.glob(os.path.join(d, "unattend*.xml")):
            out.append(F("credentials", "MEDIUM", f"file unattend: {m}"))
    for g in glob.glob(r"C:\Windows\System32\GroupPolicy\**\Groups.xml", recursive=True):
        try:
            body = open(g, errors="ignore").read()
            if "cpassword" in body:
                out.append(F("credentials", "HIGH", f"GPP cpassword di {g}", "dekripsi dengan gpp-decrypt"))
        except OSError:
            pass
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            for name in ("DefaultUserName", "DefaultPassword", "DefaultDomainName"):
                try:
                    v = winreg.QueryValueEx(k, name)[0]
                    if v:
                        out.append(F("credentials", "HIGH" if name == "DefaultPassword" else "MEDIUM",
                                     f"Winlogon {name} terisi", str(v)))
                except OSError:
                    pass
    except Exception:
        pass
    return out


@peas_check("uac", "windows")
def chk_win_uac(ctx):
    out = []
    r = run_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA 2>nul', 10)
    if r and r.stdout:
        if re.search(r"EnableLUA\s+REG_DWORD\s+0x0", r.stdout):
            out.append(F("uac", "HIGH", "UAC dinonaktifkan (EnableLUA=0)"))
        else:
            out.append(F("uac", "INFO", "UAC aktif"))
    r = run_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin 2>nul', 10)
    if r and r.stdout and re.search(r"ConsentPromptBehaviorAdmin\s+REG_DWORD\s+0x0", r.stdout):
        out.append(F("uac", "HIGH", "UAC auto-elevate admin (ConsentPromptBehaviorAdmin=0)"))
    return out


@peas_check("autoruns", "windows")
def chk_win_autoruns(ctx):
    out = []
    for h in ("HKLM", "HKCU"):
        for key in ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"):
            r = run_cmd(f'reg query "{h}\\{key}" 2>nul', 10)
            if r and r.stdout:
                for line in r.stdout.splitlines():
                    m = re.search(r"^\s+(\S+)\s+REG_\S+\s+(.+)$", line)
                    if m:
                        out.append(F("autoruns", "MEDIUM", f"autorun {h}\\{key}: {m.group(1)}",
                                     m.group(2).strip()))
    startup = os.path.join(os.environ.get("APPDATA", ""),
                           r"Microsoft\Windows\Start Menu\Programs\Startup")
    if startup and os.path.isdir(startup):
        for f in os.listdir(startup):
            out.append(F("autoruns", "MEDIUM", f"startup folder user: {f}"))
    return out


@peas_check("dll", "windows")
def chk_win_dll(ctx):
    out = []
    for ent in os.environ.get("PATH", "").split(";"):
        if ent in ("", "."):
            out.append(F("dll", "HIGH", "PATH berisi '.' atau kosong"))
            continue
        try:
            if os.path.isdir(ent) and os.access(ent, os.W_OK):
                out.append(F("dll", "MEDIUM", f"entri PATH writable: {ent}"))
        except OSError:
            pass
    for base in (r"C:\Program Files", r"C:\Program Files (x86)"):
        if os.path.isdir(base):
            try:
                for d in os.listdir(base):
                    p = os.path.join(base, d)
                    if os.path.isdir(p) and os.access(p, os.W_OK):
                        out.append(F("dll", "MEDIUM", f"dir di Program Files writable (DLL sideload): {p}"))
            except OSError:
                pass
    return out


@peas_check("defense", "windows")
def chk_win_defense(ctx):
    out = []
    txt = sh_out("powershell -NoProfile -NonInteractive -Command "
                 "\"Get-CimInstance -Namespace root\\SecurityCenter2 AntiVirusProduct | "
                 "Select-Object -ExpandProperty displayName\"", 30)
    if txt.strip():
        out.append(F("defense", "INFO", "AV terdeteksi", ", ".join(t.strip() for t in txt.splitlines() if t.strip())))
    else:
        out.append(F("defense", "LOW", "tidak ada AV terdeteksi (SecurityCenter2 kosong)"))
    r = run_cmd("sc query windefend", 10)
    if r and r.returncode == 0 and "RUNNING" in r.stdout:
        out.append(F("defense", "INFO", "Windows Defender berjalan"))
    r = run_cmd("manage-bde -status 2>nul", 15)
    if r and r.stdout:
        m = re.search(r"Conversion Status:\s*(\S+)", r.stdout)
        if m:
            out.append(F("defense", "INFO", f"BitLocker: {m.group(1)}"))
    return out


# ======================================================================
# PEAS runner
# ======================================================================

def run_peas(facts):
    scope = facts["os"]
    ctx = {"facts": facts, "sh": sh_out}
    findings = []
    for cat, name, s, fn in PEAS_CHECKS:
        if s not in (scope, "any"):
            continue
        try:
            res = fn(ctx) or []
        except Exception as e:
            res = [F(cat, "INFO", f"check {name} gagal: {e}")]
        for f in res:
            f["check"] = name
            findings.append(f)
    return findings


# ======================================================================
# Report
# ======================================================================

def build_report(facts, data, cve_res, peas_findings):
    cves = data["cves"]
    pocs = data.get("pocs", {})
    cve_findings = []
    for ci, m in cve_res.items():
        r = cves[ci]
        cve_findings.append({
            "id": r["id"], "score": r.get("score"), "severity": r.get("severity"),
            "published": r.get("published"), "kev": bool(r.get("kev")),
            "matched_by": m["tier"], "confidence": m["confidence"],
            "likely_backported": bool(m.get("likely_backported")),
            "escape_class": bool(m.get("escape_class")),
            "matches": m["matches"],
            "description": (r.get("description") or "")[:600],
            "has_poc": r["id"] in pocs,
            "pocs": pocs.get(r["id"], []),
        })
    order = {"kernel": 0, "package": 1, "os_build": 2, "distro_pin": 3}
    cve_findings.sort(key=lambda f: (not f["kev"], order.get(f["matched_by"], 4),
                                     -(f["score"] or 0), f["id"]))
    report = {
        "scanner": {"version": SCANNER_VERSION,
                    "dataset_generated": data.get("generated", ""),
                    "cve_count": data.get("count", len(cves))},
        "target": facts,
        "findings": {"peas": peas_findings, "cve": cve_findings},
        "stats": {
            "peas_total": len(peas_findings),
            "cve_total": len(cve_findings),
            "kev": sum(1 for f in cve_findings if f["kev"]),
            "backport_flagged": sum(1 for f in cve_findings if f["likely_backported"]),
            "escape_flagged": sum(1 for f in cve_findings if f["escape_class"]),
            "by_tier": {t: sum(1 for f in cve_findings if f["matched_by"] == t) for t in order},
            "by_severity": {},
        },
    }
    for f in cve_findings:
        sv = f["severity"] or "N/A"
        report["stats"]["by_severity"][sv] = report["stats"]["by_severity"].get(sv, 0) + 1
    return report


SEV_COLORS = {"CRITICAL": "\033[1;31m", "HIGH": "\033[1;33m", "MEDIUM": "\033[33m",
              "LOW": "\033[36m", "INFO": "\033[37m"}
C = {"r": "\033[0m", "b": "\033[1m", "g": "\033[32m", "dim": "\033[2m"}


def print_report(report, color=True):
    def paint(s, col):
        return (col + s + C["r"]) if color else s

    sc = report["scanner"]
    tg = report["target"]
    print(paint("=" * 72, C["b"]))
    print(paint(" LPESCAN v" + sc["version"] + "  —  LPE scanner + CVE matcher", C["b"]))
    print(paint(f" dataset: {sc['cve_count']} CVE ({sc['dataset_generated']})", C["dim"]))
    print(paint("=" * 72, C["b"]))
    print(paint("[ TARGET ]", C["b"]))
    print(f"  hostname : {tg['hostname']}   os: {tg['os']}   arch: {tg['arch']}")
    if tg["os"] == "linux":
        kb = tg.get("kernel_build") or {}
        kline = f"  kernel   : {tg['kernel']}"
        if kb.get("distro_kernel"):
            bd = kb.get("build_date")
            kline += paint(f"  [distro-kernel: {kb.get('distro_name') or '?'}"
                           + (f" build {bd.strftime('%Y-%m-%d')}" if bd else "")
                           + "]", C["dim"])
        print(kline)
        if tg["distro"].get("pretty"):
            print(f"  distro   : {tg['distro']['pretty']}")
        print(f"  packages : {len(tg['packages'])} terpasang")
        if tg.get("in_container"):
            print(paint("  container: YA (/.dockerenv/cgroup) — match [ESC] bisa menyentuh host",
                        "\033[1;35m"))
    else:
        w = tg["windows"]
        print(f"  windows  : {w['product_name']} build {w['full_build']} ({w['display_version']})")
        print(f"  hotfixes : {len(w['hotfixes'])}")

    st = report["stats"]
    kev_cves = [f for f in report["findings"]["cve"] if f["kev"]]
    if kev_cves:
        print(paint(f"\n[ !!! ] {len(kev_cves)} CVE KEV (known exploited) TERDETEKSI !!!", "\033[1;31m"))
        for f in kev_cves[:10]:
            bp = " [BP]" if f.get("likely_backported") else ""
            print(paint(f"  {f['id']} ({f['severity']} {f['score']}) — {f['matched_by']}{bp}", C["r"]))

    print(paint(f"\n[ CVE MATCH ] {st['cve_total']} CVE (by tier: "
                f"{', '.join(f'{k}={v}' for k, v in st['by_tier'].items() if v)})", C["b"]))
    hdr = f"  {'ID':<18} {'SEV':<9} {'KEV':<4} {'TIER':<10} {'KONSTRUKSI':<28} TERPASANG"
    print(paint(hdr, C["dim"]))
    for f in report["findings"]["cve"][:40]:
        sev = f["severity"] or "?"
        col = SEV_COLORS.get(sev, C["r"])
        kev = "YES" if f["kev"] else ""
        first = f["matches"][0] if f["matches"] else {}
        cons = first.get("constraint", "")[:26]
        inst = first.get("installed", "")[:26]
        line = (f"  {f['id']:<18} " + paint(f"{sev:<9}", col) + f" {kev:<4} "
                f"{f['matched_by']:<10} {cons:<28} {inst}")
        if f["has_poc"]:
            line += paint("  [PoC]", C["g"])
        if f.get("likely_backported"):
            line += paint("  [BP]", "\033[33m")
        if f.get("escape_class"):
            line += paint("  [ESC]", "\033[35m")
        print(line)
    if st["cve_total"] > 40:
        print(paint(f"  ... {st['cve_total'] - 40} CVE lagi (lihat file report)", C["dim"]))
    if st.get("backport_flagged"):
        print(paint(f"\n[ i ] {st['backport_flagged']} match di-flag [BP] = kemungkinan ter-backport:"
                    f" kernel distro di-build >{BACKPORT_GRACE_DAYS} hari setelah CVE"
                    f" dipublikasikan. Nomor versi kernel distro (ABI) tidak setara patch"
                    f" level upstream — verifikasi patch status distro (USN/dsa) sebelum"
                    f" menyimpulkan vulnerable.", C["dim"]))

    esc = [f for f in report["findings"]["cve"] if f.get("escape_class")]
    if esc:
        ids = ", ".join(f["id"] for f in esc[:8])
        print(paint(f"\n[ ! ] {len(esc)} match kelas container-escape (runc/containerd/kernel): {ids}"
                    + (" ..." if len(esc) > 8 else ""), "\033[1;35m"))
        if tg.get("in_container"):
            print(paint("      target DI DALAM container — bila terverifikasi vulnerable, eksploitasi"
                        " bisa menyentuh HOST (runtime runc/containerd atau kernel host)."
                        " Verifikasi versi runtime host dari sisi host.", C["dim"]))
        else:
            print(paint("      target bukan container — relevan bila host ini menjalankan container"
                        " (runc/containerd/buildkit); di luar itu perlakukan sebagai LPE/DoS biasa.", C["dim"]))

    print(paint(f"\n[ PEAS CHECKS ] {st['peas_total']} temuan", C["b"]))
    by_cat = {}
    for f in report["findings"]["peas"]:
        by_cat.setdefault(f["category"], []).append(f)
    for cat, fs in by_cat.items():
        print(paint(f"  --- {cat} ({len(fs)}) ---", C["b"]))
        for f in fs[:15]:
            col = SEV_COLORS.get(f["severity"], C["r"])
            print(paint(f"    [{f['severity']:<7}]", col) + f" {f['title']}")
            if f.get("detail"):
                d = str(f["detail"])
                if isinstance(f["detail"], list):
                    d = " ; ".join(str(x) for x in f["detail"])
                print(paint(f"      {d[:200]}", C["dim"]))
        if len(fs) > 15:
            print(paint(f"      ... {len(fs) - 15} lagi (lihat file report)", C["dim"]))

    print(paint("\n[ ! ] Scanner hanya mendeteksi — TIDAK mengeksekusi PoC apa pun.", C["dim"]))
    print(paint("    Jalankan buildkit.py di mesin arsip untuk membundel biner yang cocok.", C["dim"]))


# ======================================================================
# Selftest
# ======================================================================

def selftest():
    ok = fail = 0
    def chk(name, cond, note=""):
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK]   {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name}  {note}")

    print("[*] selftest version engine...")
    cpe, cons = parse_affected("linux:linux_kernel [>=3.15 <5.15.149]")
    chk("parse range 2-op", cons == [(">=", "3.15"), ("<", "5.15.149")], str(cons))
    chk("kernel 5.15.0-72 match", eval_constraint(None, cons, normalize_num("5.15.0-72-generic")))
    chk("kernel 5.15.149 tidak match", not eval_constraint(None, cons, normalize_num("5.15.149")))
    cpe, cons = parse_affected("linux:linux_kernel [6.8]")
    chk("pin exact [6.8] parse", cons == [("EXACT", "6.8")], str(cons))
    chk("kernel 6.8.0 match pin", eval_constraint(None, cons, normalize_num("6.8.0-generic")))
    chk("kernel 6.9 tidak match pin", not eval_constraint(None, cons, normalize_num("6.9")))
    cpe, cons = parse_affected("todd_miller:sudo [<1.9.5p2]")
    chk("sudo 1.9.5p1 match", eval_constraint("1.9.5p1", cons))
    chk("sudo 1.9.5p2 tidak match", not eval_constraint("1.9.5p2", cons))
    cpe, cons = parse_affected("todd_miller:sudo [1.6.3_p7]")
    chk("sudo 1.6.3_p7 exact match", eval_constraint("1.6.3_p7", cons))
    chk("sudo 1.6.3 exact TIDAK match", not eval_constraint("1.6.3", cons))
    cpe, cons = parse_affected("litespeedtech:litespeed_cpanel_plugin [<5.3.1.0]")
    chk("5.3.1 match <5.3.1.0", eval_constraint("5.3.1", cons))
    cpe, cons = parse_affected("microsoft:windows_11_23h2 [<10.0.22631.4751]")
    chk("build 22631.3447 match", eval_constraint(None, cons, normalize_num("10.0.22631.3447")))
    chk("build 22631.4751 tidak match", not eval_constraint(None, cons, normalize_num("10.0.22631.4751")))
    cpe, cons = parse_affected("microsoft:windows_10 [1607]")
    chk("release [1607] exact parse", cons == [("EXACT", "1607")], str(cons))
    cpe, cons = parse_affected("notepad-plus-plus:notepad\\+\\+ [>=8.9.4 <8.9.6]")
    chk("CPE escaped parse", cpe == "notepad-plus-plus:notepad++", str(cpe))
    chk("8.9.5 match escaped range", eval_constraint("8.9.5", cons))
    cpe, cons = parse_affected("canonical:ubuntu_linux [20.04]")
    chk("distro pin ubuntu 20.04 match", eval_constraint(None, cons, normalize_num("20.04")))
    cpe, cons = parse_affected("debian:debian_linux [10.0]")
    chk("debian 10 == 10.0", eval_constraint(None, cons, normalize_num("10")))
    cpe, cons = parse_affected("redhat:enterprise_linux_server [7.0_s390x]")
    chk("rhel pin arch suffix match", eval_constraint(None, cons, normalize_num("7.0")))
    chk("cmp 1.6.3 < 1.6.3_p7", cmp_version("1.6.3", "1.6.3_p7") < 0)
    chk("cmp 1.9.5 < 1.9.5p2", cmp_version("1.9.5", "1.9.5p2") < 0)
    chk("candidate rev strip", "2.0" in candidate_versions("2.0-1ubuntu2"),
        str(candidate_versions("2.0-1ubuntu2")))
    chk("candidate epoch strip", "1.9.5" in candidate_versions("1:1.9.5-2"),
        str(candidate_versions("1:1.9.5-2")))

    print("[*] selftest distro-kernel / backport...")
    kb = _kernel_build_info("5.15.0-191-generic",
                            "Linux version 5.15.0-191-generic (buildd@lcy02-amd64-091) "
                            "(gcc (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0) #201-Ubuntu "
                            "SMP Fri Aug 7 18:39:04 UTC 2026")
    chk("distro kernel ubuntu terdeteksi",
        kb["distro_kernel"] and kb["distro_name"] == "ubuntu", str(kb))
    chk("build date terparse",
        kb["build_date"] == datetime(2026, 8, 7, 18, 39, 4), str(kb["build_date"]))
    chk("kernel vanilla bukan distro",
        not _kernel_build_info("5.15.191", "")["distro_kernel"],
        str(_kernel_build_info("5.15.191", "")))
    kb3 = _kernel_build_info("7.1.5+kali-amd64",
                             "Linux version 7.1.5+kali-amd64 (root@kali) "
                             "(gcc-14 (Debian 14.2.0-19) 14.2.0) #1 SMP PREEMPT_DYNAMIC "
                             "Tue Sep 22 12:00:00 UTC 2026")
    chk("suffix +kali terdeteksi",
        kb3["distro_kernel"] and kb3["distro_name"] == "kali", str(kb3))
    chk("backport: lama -> True",
        _likely_backported("2022-03-07", datetime(2026, 8, 7)))
    chk("format tanggal debian/kali terparse",
        _parse_proc_version_date("Linux version 7.1.5+kali-amd64 (devel@kali.org) "
                                 "#1 SMP PREEMPT_DYNAMIC Kali 7.1.5-1kali1 (2026-07-29)")
        == datetime(2026, 7, 29))
    chk("backport: dekat build -> False",
        not _likely_backported("2026-08-01", datetime(2026, 8, 7)))
    chk("backport: tanggal hilang -> False",
        not _likely_backported("", None) and not _likely_backported("2022-01-01", None))

    print("[*] selftest container-escape...")
    chk("_in_container deterministik (host dev = False)", _in_container() is False)
    res = {}
    _add_match(res, 0, {"id": "CVE-TEST-ESC", "escape": True, "kev": False},
               "kernel", "high", "x:y", "[all]", "1.0")
    _add_match(res, 1, {"id": "CVE-TEST-NO", "escape": False, "kev": False},
               "kernel", "high", "x:y", "[all]", "1.0")
    chk("flag escape_class terpropagasi di match",
        res[0].get("escape_class") is True, str(res[0]))
    chk("cve non-escape tanpa flag escape_class",
        not res[1].get("escape_class"), str(res[1]))
    # simulasi alur penuh: record escape + facts container
    fake_data = {"cves": [{"id": "CVE-TEST-ESC", "escape": True, "kev": False,
                           "affected": ["linux:linux_kernel [>=3.0 <9.0]"],
                           "published": "2022-01-01", "score": 7.0, "severity": "HIGH",
                           "description": "container escape"}],
                 "pocs": {}, "generated": "", "count": 1}
    fake_facts = {"kernel": "5.15.0", "kernel_build": {}, "distro": {"id": "", "version_id": ""},
                  "packages": {}, "debian_version": "", "os": "linux", "in_container": True}
    m = match_cves(fake_facts, fake_data)
    chk("match di dalam container membawa escape_class",
        m.get(0, {}).get("escape_class") is True, str(m))

    print(f"\n[*] selftest selesai: {ok} OK, {fail} FAIL")
    return fail == 0


# ======================================================================
# Main
# ======================================================================

def main():
    ap = argparse.ArgumentParser(description="lpescan — LPE scanner ala PEAS + matcher CVE")
    ap.add_argument("--report", help="path file report JSON (default: ./scan-report-{host}-{ts}.json)")
    ap.add_argument("--no-color", action="store_true", help="tanpa warna ANSI")
    ap.add_argument("--json-only", action="store_true", help="hanya tulis report JSON, tanpa output console")
    ap.add_argument("--selftest", action="store_true", help="jalankan selftest version engine lalu keluar")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    t0 = time.time()
    data = load_data()
    print(f"[*] dataset: {data.get('count', len(data['cves']))} CVE, "
          f"{len(data.get('pocs', {}))} CVE dengan PoC publik", flush=True)
    facts = collect_facts()
    print(f"[*] fakta target terkumpul (os={facts['os']}, kernel/build ok)", flush=True)
    cve_res = match_cves(facts, data)
    print(f"[*] CVE match: {len(cve_res)}", flush=True)
    peas_findings = run_peas(facts)
    print(f"[*] PEAS checks: {len(peas_findings)} temuan "
          f"({time.time() - t0:.1f}s)", flush=True)
    report = build_report(facts, data, cve_res, peas_findings)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.report or f"scan-report-{facts['hostname']}-{ts}.json"
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if not os.path.isdir(out_dir):
        raise SystemExit(f"[!] direktori report tidak ada: {out_dir}")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=1, default=str)
    if not args.json_only:
        print_report(report, color=not args.no_color)
    print(f"\n[+] report tersimpan: {out_path}")


if __name__ == "__main__":
    main()
