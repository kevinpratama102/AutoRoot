# CVE-2021-31956: Windows UAC Elevation of Privilege Exploit

## Overview
**CVE-2021-31956** is a UAC (User Account Control) bypass vulnerability in Windows that allows an attacker to elevate privileges to SYSTEM without triggering a UAC prompt. This CVE exploits a flaw in the way Windows handles registry keys associated with UAC prompts.

### How It Works
The vulnerability enables an attacker to modify registry keys used by UAC to run elevated programs. The attacker can change these registry keys to point to a malicious executable, causing it to run with SYSTEM privileges without triggering the normal UAC dialog. This allows arbitrary code execution with administrative privileges, bypassing the UAC security mechanism.

## Exploit Using `FodHelper.exe`

This repository contains a C++ application that demonstrates how **CVE-2021-31956** can be exploited. The compiled executable, `FodHelper.exe`, allows you to bypass UAC by running a specified program with SYSTEM privileges.

### Usage

1. **Compile the C++ Source Code**: Compile the provided C++ source code into an executable (`Exploit.exe`).
2. **Run the Exploit**: Execute the following command to launch a program (e.g., `calc.exe`) with SYSTEM privileges:

   ```bash
   Exploit.exe 1 calc.exe

### Simple Explanation of How the CVE Works:
1. **Registry Modification: The attacker modifies specific registry keys responsible for UAC elevation.**
2. **Bypass UAC Prompt: By changing these keys to point to a malicious executable, the attacker tricks Windows into executing the program with SYSTEM privileges.**
3. **Elevated Privileges: The malicious program runs without the usual UAC prompt, and the attacker gains full control over the system.**
