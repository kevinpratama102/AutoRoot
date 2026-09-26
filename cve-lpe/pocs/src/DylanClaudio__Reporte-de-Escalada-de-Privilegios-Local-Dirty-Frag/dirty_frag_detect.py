#!/usr/bin/env python3
"""
Dirty Frag — CVE-2026-43284 / CVE-2026-43500
Local Privilege Escalation Detection Script

CVE-2026-43284  IPsec ESP in-place decryption page-cache write (esp4 / esp6)
CVE-2026-43500  RxRPC in-place decryption page-cache write (rxrpc)

The kernel's in-place decryption fast paths allow paged fragments backed by
unprivileged pipe/splice buffers to be decrypted in place, letting a local
user corrupt arbitrary page-cache entries and obtain root. The two sub-bugs
are chained: neither alone gives a sufficiently reliable primitive, but
together they cover each other's blind spots.

Checks performed:
  1.  Kernel version — affected range
  2.  Patch status  — CVE-2026-43284 (esp4/esp6 fix, upstream commit f4c50a4034e6)
  3.  Patch status  — CVE-2026-43500 (rxrpc fix, upstream commit aa54b1d27fe0)
  4.  esp4 module   — loaded / loadable / blacklisted?
  5.  esp6 module   — loaded / loadable / blacklisted?
  6.  rxrpc module  — loaded / loadable / blacklisted?
  7.  XFRM netlink socket access (CVE-2026-43284 ESP path primitive)
  8.  AF_RXRPC socket access (CVE-2026-43500 RxRPC path primitive)
  9.  Active mitigations (AppArmor, SELinux, user-ns restrictions)

No root required — everything checked here is visible to unprivileged users,
which is the same vantage point a real attacker would have.
"""

import os
import re
import sys
import socket
import subprocess
import platform

# ── Terminal colours ──────────────────────────────────────────────────────────

def _tty():
    return sys.stdout.isatty()

BOLD   = "\033[1m"    if _tty() else ""
RED    = "\033[91m"   if _tty() else ""
GREEN  = "\033[92m"   if _tty() else ""
YELLOW = "\033[93m"   if _tty() else ""
CYAN   = "\033[96m"   if _tty() else ""
DIM    = "\033[2m"    if _tty() else ""
RESET  = "\033[0m"    if _tty() else ""

# ── Result accumulator ────────────────────────────────────────────────────────

# Each entry: (display_name, cve_tag, is_vulnerable: bool, reason: str)
results = []

def record(name, cve_tag, vulnerable, reason, detail=""):
    results.append((name, cve_tag, vulnerable, reason, detail))
    tag   = f"{RED}[VULNERABLE]{RESET}" if vulnerable else f"{GREEN}[OK]{RESET}"
    label = f"{BOLD}{name}{RESET}"
    print(f"  {tag} {label}")
    if cve_tag:
        print(f"  {DIM}        CVE : {cve_tag}{RESET}")
    print(f"  {DIM}     Reason : {reason}{RESET}")
    if detail:
        print(f"  {DIM}     Detail : {detail}{RESET}")
    print()

def header(title):
    bar = "─" * 60
    print(f"\n{BOLD}{CYAN}=== {title} ==={RESET}")
    print(f"{DIM}{bar}{RESET}")

# ── Helper: run a command, return stdout (or "" on error) ─────────────────────

def _run(*args, **kwargs):
    try:
        r = subprocess.run(list(args), capture_output=True, text=True, timeout=5, **kwargs)
        return r.stdout.strip()
    except Exception:
        return ""

# ── Helper: check if a modprobe blacklist entry exists ───────────────────────

def _is_blacklisted(module):
    """Return True if module is blacklisted in any modprobe config."""
    conf_dirs = [
        "/etc/modprobe.d",
        "/usr/lib/modprobe.d",
        "/run/modprobe.d",
    ]
    pattern = re.compile(r"^\s*install\s+" + re.escape(module) + r"\s+/bin/false", re.M)
    for d in conf_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fn in os.listdir(d):
                if not fn.endswith(".conf"):
                    continue
                try:
                    txt = open(os.path.join(d, fn)).read()
                    if pattern.search(txt):
                        return True, os.path.join(d, fn)
                except OSError:
                    pass
        except PermissionError:
            pass
    return False, None

# ── Helper: check if module is currently loaded ───────────────────────────────

def _module_loaded(module):
    # Primary: /proc/modules (may be absent in some containers)
    try:
        with open("/proc/modules") as f:
            for line in f:
                if line.split()[0] == module:
                    return True
    except OSError:
        pass
    # Secondary: /sys/module/<name> directory (present even when /proc/modules is not)
    if os.path.isdir(f"/sys/module/{module}"):
        return True
    # Tertiary: lsmod if available
    out = _run("lsmod")
    if out:
        return bool(re.search(r"^" + re.escape(module) + r"\b", out, re.M))
    return False

# ── 1. Kernel version ─────────────────────────────────────────────────────────

def check_kernel_version():
    header("Kernel Version")
    release = platform.release()

    # Parse X.Y.Z
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", release)
    if not m:
        record("Kernel version", None, False,
               "Could not parse kernel version — check manually",
               f"uname -r: {release}")
        return

    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    ver = (major, minor, patch)

    # CVE-2026-43284 introduced by commit cac2661c53f3 (Jan 2017, kernel ~4.10)
    # CVE-2026-43500 introduced by commit 2dc334f1a63a (Jun 2023, kernel ~6.4)
    # CVE-2026-43284 upstream fix: f4c50a4034e6 (merged 2026-05-07)
    # CVE-2026-43500 upstream fix: aa54b1d27fe0 (merged 2026-05-10); distro backports in progress

    if ver < (4, 10, 0):
        record("Kernel version", "CVE-2026-43284 / CVE-2026-43500",
               False,
               f"Kernel {release} predates the vulnerable in-place ESP fast path (introduced ~4.10)")
        return

    # CVE-2026-43284 is patched at kernel commit level; distros shipping patched
    # kernels should have a version suffix bump.  We flag any kernel >= 4.10 as
    # potentially vulnerable and refine in the patch-presence check below.
    msg43284 = f"Kernel {release} is in the affected range for CVE-2026-43284 (esp4/esp6, introduced ~4.10)"
    if ver >= (6, 4, 0):
        detail = f"{release} — also in range for CVE-2026-43500 (rxrpc, introduced ~6.4)"
        record("Kernel version", "CVE-2026-43284 + CVE-2026-43500",
               True, msg43284, detail)
    else:
        record("Kernel version", "CVE-2026-43284",
               True, msg43284,
               f"{release} — predates CVE-2026-43500 rxrpc variant (introduced ~6.4)")

# ── 2 & 3. Patch presence ─────────────────────────────────────────────────────

def _get_pkg_kernel_version():
    """Try to read the installed kernel package version from dpkg/rpm."""
    out = _run("dpkg", "-l", "linux-image-*")
    if out:
        # look for a line with 'ii' and a version that looks like a kernel
        for line in out.splitlines():
            if line.startswith("ii") and "linux-image" in line:
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]  # package version field

    release = platform.release()
    out = _run("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n",
               f"kernel-{release}")
    if out and "not installed" not in out:
        return out.strip()

    return None

def check_patch_43284():
    """CVE-2026-43284: esp4/esp6 fix — upstream commit f4c50a4034e6, merged 2026-05-07.

    IMPORTANT: The fix is a pure runtime code change (adds skb_has_shared_frag()
    guard in esp_input()).  It introduces NO new kernel config option — there is no
    CONFIG_XFRM_ESP_NO_INPLACE or any equivalent flag to look for in /boot/config.
    Patch detection must rely on package version metadata.

    We also check CONFIG_INET_ESP / CONFIG_INET6_ESP to flag whether the vulnerable
    ESP path is compiled built-in (=y) rather than a module (=m).  Built-in means
    the modprobe blacklist mitigation does NOT work for this path.
    """
    header("Patch Status — CVE-2026-43284 (ESP / esp4 / esp6)")

    release = platform.release()

    # ── Read kernel config to check ESP build mode (exposure, not patch) ──────
    config_paths = [
        f"/boot/config-{release}",
        "/boot/config",
        "/proc/config.gz",
    ]
    inet_esp_val  = None
    inet6_esp_val = None
    for cp in config_paths:
        if os.path.exists(cp):
            try:
                if cp.endswith(".gz"):
                    import gzip
                    txt = gzip.open(cp, "rt", errors="replace").read()
                else:
                    txt = open(cp).read()
                m4 = re.search(r"^CONFIG_INET_ESP=([ym])", txt, re.M)
                m6 = re.search(r"^CONFIG_INET6_ESP=([ym])", txt, re.M)
                if m4:
                    inet_esp_val = m4.group(1)
                if m6:
                    inet6_esp_val = m6.group(1)
                break
            except Exception:
                pass

    # Build a config note for the detail field
    config_note = ""
    if inet_esp_val:
        config_note += f"CONFIG_INET_ESP={inet_esp_val}"
        if inet_esp_val == "y":
            config_note += " (built-in — modprobe blacklist WILL NOT block esp4)"
    if inet6_esp_val:
        config_note += f"  CONFIG_INET6_ESP={inet6_esp_val}"
        if inet6_esp_val == "y":
            config_note += " (built-in — modprobe blacklist WILL NOT block esp6)"

    # ── Package version check ─────────────────────────────────────────────────
    pkg_ver = _get_pkg_kernel_version()
    upstream_note = "Upstream fix: commit f4c50a4034e6 (netdev/net.git, merged 2026-05-07)"

    if pkg_ver:
        record("Patch — CVE-2026-43284", "CVE-2026-43284",
               True,
               "Patch status cannot be confirmed automatically — verify package version against your distro advisory",
               f"Running kernel: {release}  |  Package: {pkg_ver}"
               + (f"  |  {config_note}" if config_note else "")
               + f"  |  {upstream_note}")
    else:
        record("Patch — CVE-2026-43284", "CVE-2026-43284",
               True,
               "Could not determine installed package version — assume unpatched",
               f"Running kernel: {release}"
               + (f"  |  {config_note}" if config_note else "")
               + f"  |  {upstream_note}")

def check_patch_43500():
    """CVE-2026-43500: rxrpc fix — upstream patch merged 2026-05-10 at aa54b1d27fe0.

    The fix was confirmed present in the researcher's own disclosure (V4bel/dirtyfrag)
    and reported by The Hacker News on 2026-05-11.  Distro backports are in progress
    but not yet widely shipped as of 2026-05-11 — check your vendor advisory.
    """
    header("Patch Status — CVE-2026-43500 (RxRPC)")

    release = platform.release()
    ver_m = re.match(r"(\d+)\.(\d+)\.(\d+)", release)
    if not ver_m:
        record("Patch — CVE-2026-43500", "CVE-2026-43500",
               True,
               "Could not parse kernel version; assume unpatched",
               "Upstream fix: commit aa54b1d27fe0 (mainline, merged 2026-05-10) — check distro advisory for backport status")
        return

    major, minor = int(ver_m.group(1)), int(ver_m.group(2))
    if (major, minor) < (6, 4):
        record("Patch — CVE-2026-43500", "CVE-2026-43500",
               False,
               f"Kernel {release} predates the rxrpc in-place fast path (introduced ~6.4) — not affected by this sub-CVE")
        return

    # Upstream patch exists but distro backports are still in progress as of 2026-05-11.
    pkg_ver = _get_pkg_kernel_version()
    upstream_note = "Upstream fix: commit aa54b1d27fe0 (mainline, merged 2026-05-10)"
    record("Patch — CVE-2026-43500", "CVE-2026-43500",
           True,
           "Upstream patch merged 2026-05-10 but distro backports not yet widely available — assume unpatched",
           f"Running kernel: {release}"
           + (f"  |  Package: {pkg_ver}" if pkg_ver else "")
           + f"  |  {upstream_note}"
           + "  |  Module blacklisting (rxrpc) remains the practical mitigation until distro ships backport")

# ── 4-6. Module checks ────────────────────────────────────────────────────────

def _check_module(modname, cve_tag, description):
    header(f"Module — {modname}  ({description})")
    loaded = _module_loaded(modname)
    blacklisted, bl_path = _is_blacklisted(modname)

    if blacklisted:
        record(f"{modname} module", cve_tag,
               False,
               f"Blacklisted in {bl_path} — module will not auto-load",
               "Loaded right now: " + ("yes (consider rmmod)" if loaded else "no"))
        return

    if loaded:
        record(f"{modname} module", cve_tag,
               True,
               f"Module is currently LOADED — exploit primitive is live",
               "No blacklist entry found; module will reload after reboot unless blacklisted")
    else:
        # Module not loaded, no blacklist — check availability without relying on
        # modinfo (often absent on minimal/container systems).
        mod_found = False
        # 1. modinfo if present
        if _run("modinfo", modname):
            mod_found = True
        # 2. /lib/modules/<kver> filesystem search
        if not mod_found:
            kver = platform.release()
            mod_dir = f"/lib/modules/{kver}"
            if os.path.isdir(mod_dir):
                try:
                    r = subprocess.run(
                        ["find", mod_dir, "-name", f"{modname}.ko*", "-type", "f"],
                        capture_output=True, text=True, timeout=5
                    )
                    if r.stdout.strip():
                        mod_found = True
                except Exception:
                    pass
        # 3. Conservative fallback: if we can't confirm absence, assume loadable.
        #    Better a false-positive (flag it) than a false-safe (miss it).
        if not mod_found:
            mod_found = True

        if mod_found:
            record(f"{modname} module", cve_tag,
                   True,
                   "Module is not loaded but is available and will auto-load on first use",
                   "No blacklist found in /etc/modprobe.d or /usr/lib/modprobe.d")
        else:
            record(f"{modname} module", cve_tag,
                   False,
                   "Module not loaded and could not be confirmed present — unlikely exploitable via this path")

def check_modules():
    _check_module("esp4",  "CVE-2026-43284", "IPsec ESP over IPv4")
    _check_module("esp6",  "CVE-2026-43284", "IPsec ESP over IPv6")
    _check_module("rxrpc", "CVE-2026-43500", "RxRPC / AFS distributed filesystem protocol")

# ── 7. Socket access checks ───────────────────────────────────────────────────

def check_afalg_socket():
    """Check the socket primitives used by Dirty Frag.

    Dirty Frag uses:
      - XFRM netlink (AF_NETLINK / NETLINK_XFRM) for the ESP path (CVE-2026-43284)
      - AF_RXRPC (socket family 33) for the RxRPC path (CVE-2026-43500)
    """
    header("Socket Access — XFRM Netlink (CVE-2026-43284) and AF_RXRPC (CVE-2026-43500)")

    # ── XFRM netlink socket (ESP path) ───────────────────────────────────────
    AF_NETLINK    = 16
    NETLINK_XFRM  = 6
    try:
        s = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
        s.close()
        record("XFRM netlink socket (AF_NETLINK/NETLINK_XFRM)", "CVE-2026-43284",
               True,
               "XFRM netlink socket opened successfully — ESP path exploit primitive is accessible",
               f"uid={os.getuid()}  euid={os.geteuid()}")
    except PermissionError:
        record("XFRM netlink socket (AF_NETLINK/NETLINK_XFRM)", "CVE-2026-43284",
               False,
               "XFRM netlink socket creation denied — ESP path is restricted on this system")
    except OSError as e:
        record("XFRM netlink socket (AF_NETLINK/NETLINK_XFRM)", "CVE-2026-43284",
               False,
               f"XFRM netlink socket error: {e} — ESP path likely not accessible")

    # ── AF_RXRPC socket (RxRPC path) ─────────────────────────────────────────
    AF_RXRPC = 33
    try:
        s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, 0)
        s.close()
        record("AF_RXRPC socket", "CVE-2026-43500",
               True,
               "AF_RXRPC socket opened successfully — RxRPC path exploit primitive is accessible",
               f"uid={os.getuid()}  euid={os.geteuid()}")
    except PermissionError:
        record("AF_RXRPC socket", "CVE-2026-43500",
               False,
               "AF_RXRPC socket creation denied — RxRPC path is restricted on this system")
    except OSError as e:
        record("AF_RXRPC socket", "CVE-2026-43500",
               False,
               f"AF_RXRPC socket error: {e} — rxrpc module likely not loaded or not compiled in")

# ── 10. Active mitigations ────────────────────────────────────────────────────

def check_mitigations():
    header("Active Mitigations")

    # AppArmor — check filesystem first (no binary dependency), then aa-status
    aa_active = (
        os.path.exists("/sys/kernel/security/apparmor/profiles") or
        os.path.exists("/sys/kernel/security/apparmor") and
        os.path.isfile("/sys/kernel/security/apparmor/.access")
    )
    if not aa_active:
        # aa-status may be at different paths
        for aa_bin in ["/usr/sbin/aa-status", "/sbin/aa-status", "aa-status"]:
            out = _run(aa_bin)
            if out:
                aa_active = True
                break
    if aa_active:
        record("AppArmor", None, False,
               "AppArmor is active — may restrict module loading depending on policy",
               "Not a complete block; verify your esp/rxrpc policies")
    else:
        record("AppArmor", None, True,
               "AppArmor not detected or not active")

    # SELinux — check /sys/fs/selinux/enforce (most reliable, no binary needed)
    se_enforce = "/sys/fs/selinux/enforce"
    se_status = None
    if os.path.exists(se_enforce):
        try:
            se_status = open(se_enforce).read().strip()
        except OSError:
            pass
    if se_status is None:
        # Fallback: getenforce binary (may be in /usr/sbin or /sbin)
        for ge_bin in ["/usr/sbin/getenforce", "/sbin/getenforce", "getenforce"]:
            out = _run(ge_bin)
            if out:
                se_status = out.lower()
                break
    if se_status in ("1", "enforcing"):
        record("SELinux", None, False,
               "SELinux is Enforcing — module loading may be restricted",
               "Verify your esp4/esp6/rxrpc SELinux module policies")
    elif se_status in ("0", "permissive"):
        record("SELinux", None, True,
               "SELinux is Permissive — logs violations but does not block exploitation")
    else:
        record("SELinux", None, True, "SELinux not active or not enforcing")

    # User namespace restriction (limits namespace-based privilege escalation mitigations)
    ns_val = ""
    try:
        ns_val = open("/proc/sys/kernel/unprivileged_userns_clone").read().strip()
    except OSError:
        pass
    if not ns_val:
        try:
            ns_val = open("/proc/sys/user/max_user_namespaces").read().strip()
        except OSError:
            pass

    if ns_val == "0":
        record("Unprivileged user namespaces", None, False,
               "Unprivileged user namespaces are disabled — reduces attack surface for some exploitation paths")
    else:
        record("Unprivileged user namespaces", None, True,
               f"Unprivileged user namespaces are enabled (value: {ns_val or 'default'}) — no restriction in place",
               "Not directly exploited by Dirty Frag but widens the attack surface for chained exploits")

    # Dirtyfrag-specific blacklist check (combined)
    bl_file = "/etc/modprobe.d/dirtyfrag.conf"
    if os.path.exists(bl_file):
        record("Dirty Frag modprobe blacklist file", None, False,
               f"Found {bl_file} — the recommended Dirty Frag mitigation file is present",
               "Individual module checks above confirm whether entries are effective")
    else:
        record("Dirty Frag modprobe blacklist file", None, True,
               f"{bl_file} not found — recommended mitigation file not deployed",
               "See remediation section below for the one-liner to create it")

# ── Summary ───────────────────────────────────────────────────────────────────

def summary():
    header("Summary")

    vulnerable = [(n, cve, r) for n, cve, v, r, *_ in results if v]
    safe       = [(n, cve, r) for n, cve, v, r, *_ in results if not v]

    if vulnerable:
        print(f"\n  {BOLD}{RED}SYSTEM IS LIKELY VULNERABLE TO DIRTY FRAG{RESET}")
        print(f"  {DIM}CVE-2026-43284 (esp4/esp6) and/or CVE-2026-43500 (rxrpc){RESET}\n")
        print(f"  {len(vulnerable)} vulnerable condition(s):\n")
        for name, cve, reason in vulnerable:
            cve_str = f"  {DIM}[{cve}]{RESET}" if cve else ""
            print(f"    {RED}✗{RESET} {BOLD}{name}{RESET}{cve_str}")
            print(f"       {DIM}{reason}{RESET}\n")
    else:
        print(f"\n  {BOLD}{GREEN}No vulnerable conditions detected{RESET}\n")

    if safe:
        print(f"  {len(safe)} mitigated/safe condition(s):\n")
        for name, cve, reason in safe:
            print(f"    {GREEN}✓{RESET} {name}")

    print(f"""
  {BOLD}Recommended immediate actions:{RESET}

  1. Blacklist all three vulnerable modules (stops both CVEs):

       {CYAN}sudo sh -c "printf 'install esp4 /bin/false\\ninstall esp6 /bin/false\\ninstall rxrpc /bin/false\\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches"{RESET}

     {YELLOW}Note:{RESET} disabling esp4/esp6 will break IPsec/VPN tunnels.
           disabling rxrpc will break AFS-based filesystems.
           Check before deploying fleet-wide.

  2. Apply your distribution's kernel update for CVE-2026-43284:
       {CYAN}Ubuntu/Debian  : sudo apt-get update && sudo apt-get dist-upgrade{RESET}
       {CYAN}RHEL/CentOS    : sudo dnf update kernel{RESET}
       {CYAN}Arch           : sudo pacman -Syu linux{RESET}

  3. {BOLD}CVE-2026-43500 upstream patch merged 2026-05-10 (commit aa54b1d27fe0) but distro backports are still in progress.{RESET}
     Module blacklisting (rxrpc) is the practical mitigation until your distro ships a patched kernel.

  4. After patching, verify with:
       {CYAN}lsmod | grep -E '^(esp4|esp6|rxrpc)'  # should return nothing{RESET}
       {CYAN}grep dirtyfrag /etc/modprobe.d/*.conf  # should show /bin/false entries{RESET}

  {DIM}Disclosure: 2026-05-08 by Hyunwoo Kim (@v4bel).{RESET}
  {DIM}Write-up  : https://github.com/V4bel/dirtyfrag{RESET}
""")

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"{BOLD}Dirty Frag — CVE-2026-43284 / CVE-2026-43500{RESET}")
    print(f"Linux Kernel Local Privilege Escalation Detection Script")
    print(f"IPsec ESP (esp4/esp6) + RxRPC in-place decryption page-cache write")
    print(f"Running as uid={os.getuid()}, euid={os.geteuid()}\n")

    check_kernel_version()
    check_patch_43284()
    check_patch_43500()
    check_modules()
    check_afalg_socket()
    check_mitigations()
    summary()
