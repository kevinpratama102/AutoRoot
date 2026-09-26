# Option 6: Collect System Information

## Overview

**Purpose:** Collects basic system reconnaissance information to understand the compromised system.

**What It Does:**
- Runs common system commands to gather information
- Displays output for manual review
- No data is saved or exfiltrated (manual collection)

---

## Usage

### Step 1: Run the Exploit and Gain Root Access

```bash
./comprehensive
# Wait for privilege escalation
```

### Step 2: Select Option 6

```
Select option: 6
```

### Step 3: Review Output

DeepRoot will execute and display output from:

- `uname -a` - System kernel information
- `id` - Current user/group IDs
- `hostname` - System hostname
- `ip addr` - Network interfaces and IP addresses
- `netstat -tulpn` - Network connections and listening ports
- `ps aux` - Running processes
- `cat /etc/passwd | tail -20` - User accounts (last 20)
- `cat /etc/shadow | head -5` - Password hashes (first 5, if readable)
- `ls -la /home/` - Home directory listings
- `df -h` - Disk usage
- `cat /proc/version` - Kernel version
- `cat /proc/cpuinfo | grep 'model name'` - CPU information
- `free -h` - Memory usage

---

## What Gets Collected

**System Information:**
- Kernel version and OS details
- Hostname and network configuration
- CPU and memory information
- Disk space usage

**User Information:**
- User accounts from `/etc/passwd`
- Password hashes from `/etc/shadow` (if accessible)
- Home directory contents

**Network Information:**
- Active network connections
- Listening ports and services
- Network interface configuration

**Process Information:**
- All running processes
- Process ownership and resource usage

---

## Limitations

1. **Manual Review Required:** Output is displayed but not saved
2. **No Exfiltration:** Information must be manually copied
3. **Basic Reconnaissance:** Only runs common commands
4. **Privilege Dependent:** Some information requires root access

---

## Quick Reference

```bash
# Run system information collection
./comprehensive
# Select option: 6

# Output will be displayed on screen
# Manually copy any useful information
```

---

## Use Cases

- Initial system reconnaissance after privilege escalation
- Understanding system configuration
- Identifying network services and ports
- Finding user accounts and potential targets
- Assessing system resources
