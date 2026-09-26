# CVE-2021-4034
This is a POC for the vulnerability found in polkit's pkexec binary which is used to run programs as another users. 
For in-depth study: https://access.redhat.com/security/vulnerabilities/RHSB-2022-001

# Run
```sh
gcc poc.c -o poc && ./poc
```
