<h1 style="font-size:10vw" align="left">CVE-2019-13272 - Pkexec Local Privilege Escalation</h1>


<img src="https://img.shields.io/badge/CVSS:3.1%20Score%20-7.8 HIGH-red"> <img src="https://img.shields.io/badge/Vulnerability%20Types%20-Privilege%20Escalation-blue"> <img src="https://img.shields.io/badge/Tested%20On%3F-Ubuntu%2016.04.6-blued">


******
⚠️ *For educational and authorized security research purposes only*


## Original Exploit Authors
Very grateful to the original PoC author [BCOLES](https://www.exploit-db.com/?author=10078)


## Description
In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.


## Demo
![pkexec](https://github.com/asepsaepdin/CVE-2019-13272/assets/122620685/22456abf-bf7f-48da-bc03-ebd3fd90284f)


******
## Step Guides
1. Install git, then clone the script from the github repository:

    ```bash
   sudo apt install git -y
   git clone https://github.com/asepsaepdin/CVE-2019-13272.git
   ```
2. Compile the poc.c with gcc using command:

   ```bash
   cd CVE-2019-13272
   gcc -s poc.c -o become_root
   ```

4. Run the script using command:

   ```bash
   ./become_root
   ```

   
******
## Credits
- https://www.exploit-db.com/exploits/47163
- https://nvd.nist.gov/vuln/detail/cve-2019-13272
