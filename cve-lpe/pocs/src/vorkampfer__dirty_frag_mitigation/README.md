# dirty_frag_mitigation
1. A bash script for mitigating  linux dirty frag exploit CVE-2026-43500
2. Works on all Debian/Ubuntu Arch based platforms i.e. Kali, ParrotSec, BlackArch
3. Added --check to run as non-root user. Added fragnesia support as it shares the same patch surface with dirtyfrag.

## Example usage:
```
ᐅ dirty_frag_fix.sh --check
[*] Checking dirtyfrag mitigation status (non-root check mode)...
[*] Config file: /etc/modprobe.d/dirtyfrag.conf
[*] install esp4 /bin/false: yes
[*] install esp6 /bin/false: yes
[*] install rxrpc /bin/false: yes
[*] Any vulnerable modules currently loaded: no
[+] Likely mitigated against dirtyfrag based on module blocklist and load state.
[*] Note: This same module-level mitigation also reduces fragnesia exposure on the same ESP/XFRM surface.
[*] Note: Fragnesia is a separate bug with its own patch, but shares mitigation surface with dirtyfrag.
```
