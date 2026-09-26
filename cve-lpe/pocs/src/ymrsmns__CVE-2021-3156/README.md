## CVE-2021-3156

## Ansible role patches CVE-2021-3156 for CentOS

### Intro

Sudo before 1.9.5p2 has a Heap-based Buffer Overflow, allowing privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character

[CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156)

[News (RU)](https://habr.com/ru/news/t/539526/)

### RUN
```sh
ansible-playbook update_ssh.yml --tags ssh-update
```
