# Exploit for CVE-2021-4034 (Pkexec) - Local Privilege Escalation
*For educational and authorized security research purposes only.*

## Original Exploit Authors
[@arthepsy](https://github.com/arthepsy/CVE-2021-4034)

## Vulnerability Description
A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

## Usage
```bash
  gcc cve-2021-4034-poc.c -o <alias>
  ./<alias>
```

## Download Via Original Source
[Download Exploit Script for CVE-2021-3560 Here](https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c)

## Exploit Requirements
- gcc
- make

## Demo
![Screenshot 2023-07-10 151320](https://github.com/asepsaepdin/CVE-2021-4034/assets/122620685/32322e35-c926-4d07-99db-b05354521354)

## Tested On
- Ubuntu 20.04.1 LTS

## Test Environment
```bash
apt install git gcc make
```

## Warning
⚠️ Becareful when running this exploit on your system

## Credits
- https://github.com/arthepsy/CVE-2021-4034
- https://github.com/berdav/CVE-2021-4034
- https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in- polkits-pkexec-cve-2021-4034
