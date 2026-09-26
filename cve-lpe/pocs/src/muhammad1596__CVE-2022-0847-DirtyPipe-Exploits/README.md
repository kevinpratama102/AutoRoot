![Dirty Pipe](https://miro.medium.com/v2/resize:fit:1400/1*G1ov2zxEkNKR8HFiErTS5A.png)

# CVE-2022-0847-DirtyPipe-Exploits
This repository offers a comprehensive collection of exploits and documentation specifically designed for penetration testers and red team professionals. It serves as a valuable resource for those aiming to exploit the Linux Dirty Pipe vulnerability effectively.

# About The Vulnerability
- Dirty Pipe (CVE-2022-0847) is a local privilege escalation vulnerability discovered in the Linux kernel. This security flaw allows an unprivileged user to perform several critical actions, including:
	- Modifying or overwriting arbitrary read-only files, such as /etc/passwd, which can be leveraged to manipulate user authentication mechanisms.
	- Gaining an elevated shell, thereby obtaining unauthorized administrative privileges on the affected system. 

	This vulnerability arises from improper handling of pipe buffer operations within the Linux kernel, enabling an attacker to inject malicious data into sensitive files. Consequently, it poses a significant threat to system integrity and security, necessitating immediate attention and patching.

## Affected versions
The vulnerability affects Linux kernel versions newer than 5.8. Patches have been released for the following Linux kernel versions:
- 5.16.11
- 5.15.25
- 5.10.102
  
For more detailed information about the vulnerability, [CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847).

# DirtyPipe Vulnerability Scanner
- To determine if a target system is vulnerable, you can utilize an efficient and reliable Bash script developed by @muhammad1596.
- For more information and to access the script, visit the DirtyPipe Checker repository on GitHub: [DirtyPipe Checker](https://github.com/muhammad1596/CVE-2022-0847-dirty-pipe-checker).

 
## Compiling the exploit
- An automated compiler Bash script is available to streamline the compilation process for both exploits.

- Prerequisites
Ensure you have GCC installed on your system. You can install it using the following command:

```
sudo apt-get install gcc
```

Compilation Steps
1. Make the compile.sh script executable:
```
chmod +x compile.sh
```

2. Run the compile.sh script to compile the exploits:
```
./compile.sh
```

# Exploit-1 - Modifying/overwriting read only files
- This repository contains two exploits. The first, 'exploit-1.py', enables the modification or overwriting of arbitrary read-only files. 


## Running the exploit binary
- The exploit code is designed to replace the root password with "piped" and creates a backup of the `/etc/passwd` file in `/tmp/passwd`.bak. Additionally, the exploit grants an elevated root shell and restores the original `passwd` file upon completion.

```
./exploit-1
```

# Exploit-2 - Hijacking SUID binaries
- This exploit can be used to inject and overwrite data in read-only SUID process memory that run as root.

## Finding SUID binaries
```
find / -perm -4000 2>/dev/null
```
## Running the exploit binary

```
./exploit-2 /usr/bin/sudo
```


