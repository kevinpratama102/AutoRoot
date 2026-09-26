# Options S and 0: Shell and Cleanup

## Option S: Spawn Root Shell

**Purpose:** Launches an interactive root shell session.

**What It Does:**
- Spawns `/bin/bash` with root privileges
- Falls back to `/bin/sh` if bash is unavailable
- Provides interactive root shell access

**Usage:**
```
Select option: s
```

**Note:** This gives you a root shell to execute commands directly. You'll have full root access until you exit the shell.

---

## Option 0: Cleanup and Exit

**Purpose:** Removes exploit artifacts and exits the program.

**What It Does:**
- Removes the `./ovlcap/` directory and all its contents
- Cleans up temporary exploit files
- Exits the program cleanly

**Usage:**
```
Select option: 0
```

**What Gets Cleaned:**
- `./ovlcap/` directory (work, lower, upper, merge subdirectories)
- Temporary exploit files created during privilege escalation

**Note:** This only removes local exploit artifacts. Post-exploitation modifications (SSH keys, cron jobs, systemd services, etc.) are NOT removed by this option.

---
