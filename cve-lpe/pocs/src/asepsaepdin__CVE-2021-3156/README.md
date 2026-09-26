<h1 style="font-size:10vw" align="left">CVE-2021-3156 - Heap-Based Buffer Overflow in Sudo</h1>


<img src="https://img.shields.io/badge/CVSS:3.1%20Score%20-7.8 HIGH-red"> <img src="https://img.shields.io/badge/Vulnerability%20Types%20-Privilege%20Escalation-blue"> <img src="https://img.shields.io/badge/Tested%20On%3F-Ubuntu%2020.04.1-blued">


******
⚠️ *For educational and authorized security research purposes only*


## Original Exploit Authors
Very grateful to the original PoC author [Qualys Research Team](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)


## Description
Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.


## Demo
![sudo](https://github.com/asepsaepdin/CVE-2021-3156/assets/122620685/375ae511-7605-4947-8692-d83914489084)


******
## Step Guides
1. Install git, then clone the script from the github repository:

    ```bash
   sudo apt install git -y
   git clone https://github.com/asepsaepdin/CVE-2021-3156.git
   ```
2. Compile the PoC using command:

   ```bash
   make
   ```

4. Run the PoC using command:

   ```bash
   ./exploit
   ```

   
******
## Credits
- https://github.com/CptGibbon/CVE-2021-3156
- https://nvd.nist.gov/vuln/detail/CVE-2021-3156
- https://github.com/blasty/CVE-2021-3156
