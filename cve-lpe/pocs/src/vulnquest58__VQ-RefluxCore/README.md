# VQ-RefluxCore: Kernel Vulnerability Assessment & Research Framework

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Target](https://img.shields.io/badge/CVE-2026--64600-red.svg)
![License](https://img.shields.io/badge/license-Educational--Only-orange.svg)

**VQ-RefluxCore** is an advanced security research framework designed to model, analyze, and demonstrate Local Privilege Escalation (LPE) mechanics associated with kernel-level race conditions and filesystem structure vulnerabilities (**CVE-2026-64600** / RefluXFS).

---

## 👤 Developer & Metadata

| Attribute | Details |
| :--- | :--- |
| **Developer** | VulnQuest |
| **GitHub Handle** | [@vulnquest58](https://github.com/vulnquest58) |
| **Framework Version** | `2.0.0` (RefluxCore) |
| **Release Date** | July 24, 2026 |
| **Classification** | LPE Research & Security Audit Framework |

---

## 🎯 Target Vulnerability: CVE-2026-64600 (RefluXFS)

**CVE-2026-64600** represents a Time-of-Check to Time-of-Use (TOCTOU) race condition flaw identified in the RefluXFS kernel module implementation (Linux Kernel versions `>= 4.11`).

### Vulnerability Mechanism:
1. **Ineffective Locking:** Inadequate lock synchronization during inode attribute updates across parallel file operations.
2. **Privilege Boundary Crossing:** Privilege checks performed during initial file access validation can be desynchronized during write operations via high-frequency concurrent threads.
3. **Execution Escalation:** Allows an unprivileged user process to elevate execution context through system binary interaction and filesystem state manipulation.

---

## 🔬 Core Technical Features & Modules

VQ-RefluxCore incorporates multiple modular components for auditing system resilience against kernel race conditions:

* **Multithreaded Race Condition Engine:** Deploys synchronized thread workers (`VQ_RACE_THREADS`) operating over configurable iterations (`VQ_RACE_ITERATIONS`) to stress-test filesystem locking consistency.
* **SUID Binary Audit & Escalation Vector Scan:** Automated discovery and inspection of local executables configured with the `SUID` (Set User ID) permission bit.
* **In-Memory Operations:** Operates out of volatile shared memory structures (`/dev/shm`) to minimize disk footprint and evaluate volatile memory security policies.
* **Environment & Kernel Profiling:** Automated kernel version checking (`uname -r`), architecture validation, and filesystem capability checks (`xfs_info`).
* **Automated Cleanup & Signal Trap:** Built-in trap handling (`SIGINT`, `SIGTERM`, `EXIT`) to guarantee proper removal of volatile artifacts upon execution termination.

---

## 💻 Usage & CLI Reference

### Basic Syntax
```bash
chmod +x vq-refluxcore.sh
./vq-refluxcore.sh [OPTIONS]
```

### Supported Command-Line Flags

| Flag | Description |
| :--- | :--- |
| `--aggressive` | Enables high-throughput multithreaded race stress testing. |
| `--debug` | Enables verbose debug logging output (`VQ_DEBUG=1`). |
| `--no-cleanup` | Disables automated temporary artifact removal for manual forensic analysis. |
| `--help` | Displays usage summary and options menu. |

---

## 🛡️ Defensive Mitigation & Hardening

To safeguard Linux systems against kernel-level LPE vulnerabilities and race condition exploits:

1. **Kernel Patching:** Upgrade kernel image to the latest LTS version featuring patched RefluXFS synchronization handlers.
2. **Mount Option Security:** Configure volatile memory mounts (`/dev/shm`, `/tmp`) with strict security flags in `/etc/fstab`:
   ```text
   tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
   ```
3. **Hardened Symlink Protections:** Ensure kernel symlink and hardlink protections are enforced:
   ```bash
   sysctl -w fs.protected_symlinks=1
   sysctl -w fs.protected_hardlinks=1
   ```
4. **SUID Binary Auditing:** Periodically audit non-standard SUID binaries using security monitoring tools or manual inspection:
   ```bash
   find / -perm -4000 -type f 2>/dev/null
   ```

---

## ⚖️ Legal & Ethical Disclaimer

> **IMPORTANT:** This framework is designed exclusively for authorized penetration testing, security research, CTF challenges, and educational auditing in isolated laboratory environments. Unauthorized execution of security research tools on systems without prior written consent is illegal and strictly prohibited. The developer (VulnQuest) assumes no liability for misuse or damage caused by this software.
