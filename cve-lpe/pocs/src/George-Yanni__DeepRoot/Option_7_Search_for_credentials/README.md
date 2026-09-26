# Option 7: Search for Credentials

## Overview

**Purpose:** Searches common system locations for credential files and sensitive information.

**What It Does:**
- Checks for credential files in standard locations
- Searches user home directories
- Looks for SSH keys and configuration files
- Displays findings (files that exist)

---

## Usage

### Step 1: Run the Exploit and Gain Root Access

```bash
./comprehensive
# Wait for privilege escalation
```

### Step 2: Select Option 7

```
Select option: 7
```

### Step 3: Review Output

DeepRoot checks for files in these locations:

- `/etc/shadow` - Password hashes
- `/etc/passwd` - User account database
- `/root/.bash_history` - Root command history
- `/home/*/.bash_history` - User command histories
- `/root/.ssh/id_rsa` - Root SSH private key
- `/home/*/.ssh/id_rsa` - User SSH private keys
- `/var/log/auth.log` - Authentication logs
- `/var/log/secure` - Security logs
- `/etc/fstab` - File system table (may contain credentials)
- `/etc/hosts` - Hostname mappings
- `/etc/hostname` - System hostname
- `/proc/net/tcp` - TCP connections
- `/proc/net/udp` - UDP connections

**Note:** Only files that exist are reported. The framework doesn't extract or display file contents.

---

## What Gets Searched

**Credential Files:**
- Password hashes (`/etc/shadow`)
- SSH private keys
- Command histories (may contain passwords)

**System Files:**
- User databases
- Configuration files
- Network information

**Log Files:**
- Authentication logs
- Security logs

---

## Limitations

1. **No Content Extraction:** Only checks if files exist, doesn't read contents
2. **Basic Search:** Only checks predefined locations
3. **Manual Review Required:** Must manually access found files
4. **Privilege Dependent:** Some locations require root access

---

## Quick Reference

```bash
# Search for credentials
./comprehensive
# Select option: 7

# If files are found, manually access them:
cat /etc/shadow
cat /root/.bash_history
cat /root/.ssh/id_rsa
```

---

## Use Cases

- Finding password hashes for cracking
- Locating SSH keys for authentication
- Discovering command history with embedded credentials
- Identifying sensitive configuration files
