# CVE-2021-3493 Comprehensive Exploit Framework ${\color{#FF4D2E} \textbf{\textsf{[DeepRoot]}}}$

**OverlayFS Capability Privilege Escalation Framework - Red Team Professional Edition**

## Overview

DeepRoot framework is a comprehensive privilege escalation exploit for **CVE-2021-3493** (OverlayFS Privilege Escalation) with advanced red team features including persistence mechanisms, stealth capabilities, and post-exploitation modules.

**Created by:** George S. Yanni  
**Original Advisory:** https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/

---

## ⚠️ WARNING

**FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

DeepRoot framework is designed for:
- Security research and education
- Authorized penetration testing
- Red team exercises with explicit permission
- Vulnerability assessment in controlled environments

**DO NOT use against production systems without explicit authorization. Unauthorized access to computer systems is illegal.**

---

## Vulnerability Details

**CVE-2021-3493** is a privilege escalation vulnerability in the Linux OverlayFS filesystem that allows an unprivileged user to gain root privileges by exploiting improper capability handling in user namespaces.

**Key Characteristics:**
- Exploits OverlayFS capability handling bug
- Uses user namespaces (`CLONE_NEWUSER`) to map UID 0
- Uses mount namespaces (`CLONE_NEWNS`) for isolated mounts
- Sets file capabilities on binaries via `setxattr()`
- Works on systems with user namespaces enabled

---

## Features

### Core Exploit
- **Privilege Escalation:** Reliable root access via OverlayFS vulnerability
- **Namespace Isolation:** Uses user and mount namespaces for safe exploitation
- **Capability Injection:** Sets `CAP_ALL_EP` (all capabilities) on target binary
- **Stealth Mode:** Optional stealth features to reduce detection

### Persistence Mechanisms
1. **SSH Backdoor** - Inject SSH public key for root access
2. **Sudo Backdoor** - Modify sudoers to allow passwordless root access
3. **Cron Persistence** - Install cron jobs for recurring execution
4. **Systemd Service** - Create systemd service for boot persistence
5. **LD_PRELOAD Backdoor** - Hook library functions for code injection

### Post-Exploitation
6. **System Information Collection** - Gather system reconnaissance data
7. **Credential Search** - Find passwords, keys, and sensitive files
8. **Lateral Movement** - Identify SSH keys and network opportunities
9. **C2 Connection Testing** - Verify network connectivity for C2 setup

### Utilities
- **Shell Access** - Direct root shell spawn
- **Cleanup** - Remove exploit artifacts

---

## File Structure

```
CVE-2021-3493/
├── comprehensive.c          # Main exploit source code
├── README.md                # This file
│
├── Option_1_Inject_SSH_backdoor_key/
│   └── README.md            # SSH backdoor guide
│
├── Option_2_Install_sudo_backdoor/
│   └── README.md            # Sudo backdoor guide
│
├── Option_3_Install_cron_persistence/
│   └── README.md            # Cron persistence guide
│
├── Option_4_Install_systemd_service/
│   └── README.md            # Systemd service guide
│
├── Option_5_Install_LD_PRELOAD_backdoor/
│   └── README.md            # LD_PRELOAD backdoor guide
│
├── Option_6_Collect_system_information/
│   └── README.md            # System info collection guide
│
├── Option_7_Search_for_credentials/
│   └── README.md            # Credential search guide
│
├── Option_8_Check_lateral_movement/
│   └── README.md            # Lateral movement guide
│
├── Option_9_Establish_C2_connection/
│   └── README.md            # C2 connection guide
│
├── Option_Shell_and_Cleanup/
│   └── README.md            # Shell and cleanup guide
│
└── Stealth_Mode_Guide/
    └── README.md            # Stealth mode documentation
```

---

## Quick Start

### Compilation

```bash
gcc -o comprehensive comprehensive.c
```

### Basic Usage

```bash
# Run the exploit
./comprehensive

# The exploit will:
# 1. Create necessary directories (./ovlcap/)
# 2. Set up user and mount namespaces
# 3. Mount OverlayFS
# 4. Set capabilities on binary
# 5. Execute privileged binary
# 6. Present post-exploitation menu
```

### Post-Exploitation Menu

After successful privilege escalation, you'll see:

```
╔══════════════════════════════════════════════════╗
║        POST-EXPLOITATION MENU                    ║
╚══════════════════════════════════════════════════╝

Available actions:
  1. Inject SSH backdoor key
  2. Install sudo backdoor
  3. Install cron persistence
  4. Install systemd service
  5. Install LD_PRELOAD backdoor
  6. Collect system information
  7. Search for credentials
  8. Check lateral movement
  9. Establish C2 connection
  s. Spawn root shell
  0. Cleanup and exit

Select option:
```

---

## Detailed Documentation

Each option has its own documentation folder with complete guides:

### Persistence Options

- **[Option 1: SSH Backdoor](Option_1_Inject_SSH_backdoor_key/README.md)** - Inject SSH public key for persistent root access
- **[Option 2: Sudo Backdoor](Option_2_Install_sudo_backdoor/README.md)** - Modify sudoers for passwordless root access
- **[Option 3: Cron Persistence](Option_3_Install_cron_persistence/README.md)** - Install cron jobs for recurring execution
- **[Option 4: Systemd Service](Option_4_Install_systemd_service/README.md)** - Create systemd service for boot persistence
- **[Option 5: LD_PRELOAD Backdoor](Option_5_Install_LD_PRELOAD_backdoor/README.md)** - Hook library functions to inject code

### Post-Exploitation Options

- **[Option 6: System Information](Option_6_Collect_system_information/README.md)** - Collect system reconnaissance data
- **[Option 7: Credential Search](Option_7_Search_for_credentials/README.md)** - Search for passwords and sensitive files
- **[Option 8: Lateral Movement](Option_8_Check_lateral_movement/README.md)** - Find SSH keys and network opportunities
- **[Option 9: C2 Connection](Option_9_Establish_C2_connection/README.md)** - Test network connectivity for C2 setup

### Utilities

- **[Shell and Cleanup](Option_Shell_and_Cleanup/README.md)** - Spawn root shell or cleanup artifacts
- **[Stealth Mode Guide](Stealth_Mode_Guide/README.md)** - Documentation for stealth features

---

## Requirements

### System Requirements

- Linux system (kernel with OverlayFS support)
- User namespaces enabled (`kernel.unprivileged_userns_clone=1` or CAP_SYS_ADMIN)
- GCC compiler
- Root access NOT required initially (that's the point!)

### Kernel Compatibility

The exploit targets systems vulnerable to CVE-2021-3493. Check your kernel version and ensure user namespaces are available.

---

## How It Works

### Exploit Flow

1. **Namespace Creation:** Creates new user and mount namespaces using `unshare(CLONE_NEWNS | CLONE_NEWUSER)`

2. **UID/GID Mapping:** Maps current unprivileged UID to 0 (root) within the new namespace via `/proc/self/uid_map` and `/proc/self/gid_map`

3. **OverlayFS Mount:** Mounts OverlayFS with lower, upper, and work directories

4. **Binary Copy:** Copies the exploit binary to the overlay merge directory

5. **Capability Injection:** Uses `setxattr()` to set `CAP_ALL_EP` (all capabilities, effective and permitted) on the copied binary

6. **Privileged Execution:** Executes the binary from the upper directory, which has full capabilities and runs as root

### Technical Details

- **User Namespace:** Allows mapping of UIDs/GIDs within isolated namespace
- **Mount Namespace:** Creates isolated mount point for OverlayFS
- **File Capabilities:** Linux capability system allows fine-grained privileges on files
- **OverlayFS:** Merges multiple directory trees, upper directory takes precedence

---

## Stealth Features

The exploit includes optional stealth mode (`--stealth` flag) that:

- Reduces logging verbosity
- Lowers process priority (`nice(19)`)
- Prevents core dumps
- Clears environment variables
- Modifies file timestamps

See [Stealth Mode Guide](Stealth_Mode_Guide/README.md) for details.

---

## Examples

### Basic Privilege Escalation

```bash
./comprehensive
# Wait for menu, select 's' for shell
```

### Install SSH Backdoor

```bash
./comprehensive
# Select option 1
# Follow prompts to inject your SSH public key
```

### Install Cron Persistence

```bash
./comprehensive
# Select option 3
# Cron job installed, runs every 5 minutes
```

### Stealth Mode

```bash
./comprehensive --stealth
# Exploit runs with reduced logging and OPSEC features
```




## Legal and Ethical Considerations

**IMPORTANT DISCLAIMERS:**

1. **Authorization Required:** Only use DeepRoot on systems you own or have explicit written permission to test

2. **Legal Liability:** Unauthorized access to computer systems is illegal in most jurisdictions. You are solely responsible for your actions

3. **Educational Purpose:** DeepRoot is provided for educational and research purposes

4. **No Warranty:** This software is provided "as is" without warranty of any kind

5. **Ethical Use:** Use responsibly and ethically. Do not harm systems or data

---

## Credits

- **DeepRoot Development:** George S. Yanni
- **Vulnerability:** CVE-2021-3493 (OverlayFS Privilege Escalation)
- **Original Advisory:** SSD Advisory - OverlayFS PE

---

## License

DeepRoot is provided for educational purposes. Use at your own risk.

---

## Contributing

This is an educational project. Contributions, bug reports, and improvements are welcome, but please ensure all code maintains the educational and ethical standards of this project.





---

**Remember: With great power comes great responsibility. Use DeepRoot ethically and legally.**

${\color{3DA300}- \text{George S. Yanni}}$
### Feedback & Contact

For any recommendations, improvements, bug reports, or questions about DeepRoot, feel free to reach out on
[LinkedIn](https://www.linkedin.com/in/george-yanni-0x13/) .