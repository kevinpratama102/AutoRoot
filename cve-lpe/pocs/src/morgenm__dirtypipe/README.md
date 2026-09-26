> **DISCLAIMER**
>
> This code is for **educational and research purposes only.** 
>
> Do not use it on systems you do not own or have permission to test.
>
> The author is **not responsible** for any misuse, damage, or legal consequences resulting from the use of this code.

# DirtyPipe (CVE-2022-0847)
View the writeup for this exploit on my [blog](https://morgenm.github.io/blog/2025/dirtypipe/). This is an implementation of the DirtyPipe ([CVE-2022-0847](https://nvd.nist.gov/vuln/detail/cve-2022-0847)) exploit I wrote in Rust based on [Max Kellermann's writeup](https://dirtypipe.cm4all.com/).
The program allows you to overwrite specific files or to overwrite an SUID binary in order to escalate privileges.

## Features
- Check if kernel version is vulnerable
- Overwrite any file with data from specified input file
- Overwrite a SUID binary (default `passwd`) to gain root
- Backup target files to `/tmp` before exploitation

## Usage
### Overwriting a file
First create an input file. The data within this file will be used to overwrite the target. Then, simply run the following:

```bash
./dirtypipe_exploit -m overwrite -i input.txt -o target_file -b offset
```

Where offset is the offset in bytes to begin writing in the file. The offset must not be on a page boundary and writing cannot cros a page boundary, due to the nature of the vulnerability.

### SUID for Privilege Escalation
`SUID` mode will replace a specified SUID binary with a given ELF payload. The `suid` ELF is provided in the release on this repo and will be used by the exploit unless otherwise specified in the options.
Additionally, you can generate this on your own, or modify the payload using the `gen_suid.py` pwntools script and the `loader.asm` file. This option will be discussed below.
The exploit sets the target to `/usr/bin/passwd` by default.

Run the following to replace `/usr/bin/passwd` with the provided payload (spawns a shell as root):
```bash
./dirtypipe_exploit -m suid
```

Then run `/usr/bin/passwd` to get a root shell.

To generate your own payload, follow these steps:
1. Run the `gen_suid.py` script, which uses pwntools to generate a payload (`shellcode.bin`) that spawns a root shell. Modify it as you see fit.
2. Create the ELF binary payload by running `nasm -f bin -o [PAYLOAD_NAME] loader.asm`. This will turn the `shellcode.bin` file into an executable.
3. Run `./dirtypipe_exploit -m suid -i [PAYLOAD_NAME] -o [TARGET_FILE]`.
4. Execute the target to gain root.

Thank you to the author of [STALKR's BLOG](https://blog.stalkr.net/) for the 64-bit Tiny ELF header ([here](https://blog.stalkr.net/2014/10/tiny-elf-3264-with-nasm.html)).