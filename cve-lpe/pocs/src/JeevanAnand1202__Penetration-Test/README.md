# Penetration-Test
Full penetration test report against `IP` (Ubuntu VM).   Attack chain: directory enumeration → backup file discovery → password cracking → CMS file upload → reverse shell → kernel privilege escalation (Dirty Pipe, CVE-2022-0847).

## Repository Structure
/report` – Final penetration test report (PDF)
/exploits` – Custom payloads and exploit source code
/enumeration` – Wordlists, hashes, and enumeration outputs
/logs` – Metasploit console logs, nmap scans (if any)

## Tools Used
Nmap, Gobuster, John the Ripper, Metasploit, Searchsploit, GCC.

## Notes
This repository is **private** – shared only for project review.

**Warning:** Contains sensitive data (hashes, flags, IPs). Do not make public.
