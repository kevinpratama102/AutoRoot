# printDemon2system (CVE-2020-1048)
### PrintDemon privilege escalation to SYSTEM
PrintDemon was a logic vulnerability in the Windows Print Spooler service (**spoolsv.exe**).
The vulnerability was in the way the spooler handled print jobs to files, and when exploited allowed arbitrary writing to the file system as the SYSTEM user.

An example exploit of this vulnerability includes overwriting the *PrintConfig.dll* in the DriverStore directory, which is then loaded by **spoolsv.exe** that is running under the SYSTEM user context, when an XPS Print Job is started (as shown in this repository).

<div align="center">
  <div style="border: 1.5px solid #ccc; display: inline-block; padding: 4px;">
    <img src="/assets/printDemon2system.gif" alt="printDemon2system Exploit" width = 95% style="display: block; border: none;">
  </div>
  <p style="margin-top: 5px;"><em>Exploiting PrintDemon for Privilege Escalation (CVE-2020-1048). Compiled with VS2022 and tested on Windows 10 x64 version 1909 (build 18363.418)</em></p>
</div>

### References
* https://decoder.cloud/2019/11/13/from-arbitrary-file-overwrite-to-system/
