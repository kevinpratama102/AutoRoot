# CVE-2024-1086-checker

This is a simple checker script to detect the kernel configuration which is
vulnerable to exploitation. A result of "kernel config not vulnerable" from
this script only means that the vulnerability is not exploitable with currently
known paths.

## How to Use

```shell
curl -s "https://raw.githubusercontent.com/kevcooper/CVE-2024-1086-checker/main/check_cve_2024_1086.py" | python3
```

```shell
git clone https://github.com/kevcooper/CVE-2024-1086-checker.git
cd CVE-2024-1086-checker
python3 check_cve_2024_1086.py
```