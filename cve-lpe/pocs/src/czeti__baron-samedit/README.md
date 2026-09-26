# Baron Samedit PoC

## Description
This is a Proof-of-Concept (PoC) exploit for the Baron Samedit vulnerability (CVE-2021-3156) tested on Ubuntu 20.04 with sudo version 1.8.31 and glibc version 2.31. The exploit leverages a heap-based buffer overflow in sudo's handling of command-line arguments when using `sudoedit` to achieve privilege escalation.

## Exploit Components
- **`exploit.asm`**: A handcrafted assembly exploit that constructs the argument and environment buffers to trigger the vulnerability.
- **`shellcode.c`**: A minimal shared object payload that executes `/bin/sh` with elevated privileges.
- **`Makefile`**: Automates the build process for both the shellcode and exploit binary.

## Build Instructions
To compile the exploit:
```sh
make
```

## Exploit Execution
1. Run the exploit binary:
   ```sh
   ./exploit
   ```
2. If successful, this will invoke the vulnerable sudoedit with a corrupted environment, leading to privilege escalation.

## Prerequisites
- Ensure that sudo version 1.8.31 is installed and unpatched.
- Ubuntu 20.04 with glibc 2.31.
- Proper permissions to execute the exploit.

## Cleanup
To remove generated files:
```sh
make clean
```

## Disclaimer
This PoC is for educational and research purposes only. Unauthorized use on systems without explicit permission is illegal and unethical, I will not be held accountable for your actions. Thank you.

