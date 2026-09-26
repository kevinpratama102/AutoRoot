# Option 8: Check Lateral Movement

## Overview

**Purpose:** Identifies opportunities for lateral movement within the network.

**What It Does:**
- Searches for SSH keys on the system
- Checks known hosts to find other machines
- Examines ARP table for network neighbors
- Looks for NFS shares for network access

---

## Usage

### Step 1: Run the Exploit and Gain Root Access

```bash
./comprehensive
# Wait for privilege escalation
```

### Step 2: Select Option 8

```
Select option: 8
```

### Step 3: Review Output

DeepRoot checks for:

- **SSH Keys:** Private keys (`id_rsa`, `id_dsa`) and `authorized_keys` files
- **Known Hosts:** Entries from SSH `known_hosts` files showing other machines
- **ARP Table:** Network neighbors visible on the local network
- **NFS Shares:** Network File System shares available for mounting

---

## What Gets Checked

**SSH Keys:**
- Searches `/home` and `/root` for:
  - `id_rsa` - RSA private keys
  - `id_dsa` - DSA private keys
  - `authorized_keys` - Public keys allowed to connect

**Known Hosts:**
- Extracts entries from SSH `known_hosts` files
- Shows hostnames/IPs of machines this system has connected to

**Network Information:**
- ARP table entries (IP to MAC mappings)
- Other hosts on the local network

**Network Shares:**
- NFS exports available for mounting

---

## Limitations

1. **Basic Checks:** Only performs simple searches
2. **No Deep Analysis:** Doesn't test key validity or connectivity
3. **Manual Verification Required:** Found keys must be tested manually
4. **Network Dependent:** ARP and NFS checks depend on network configuration

---

## Quick Reference

```bash
# Check lateral movement opportunities
./comprehensive
# Select option: 8

# If SSH keys are found, test them:
ssh -i /path/to/id_rsa user@target-host

# Review known hosts:
cat /root/.ssh/known_hosts

# Check ARP table manually:
arp -a
```

---

## Use Cases

- Finding SSH keys to access other machines
- Identifying network neighbors for further compromise
- Discovering NFS shares for data exfiltration
- Mapping network topology through known hosts
