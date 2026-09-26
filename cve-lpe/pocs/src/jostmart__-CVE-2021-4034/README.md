# -CVE-2021-4034

https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
 
"
"Polkit (formerly PolicyKit) is a component for controlling system-wide
privileges in Unix-like operating systems. It provides an organized way
for non-privileged processes to communicate with privileged ones. [...]
It is also possible to use polkit to execute commands with elevated
privileges using the command pkexec followed by the command intended to
be executed (with root permission)." (Wikipedia)
 
This vulnerability is an attacker's dream come true:
 
- pkexec is installed by default on all major Linux distributions (we
  exploited Ubuntu, Debian, Fedora, CentOS, and other distributions are
  probably also exploitable);
 
- pkexec is vulnerable since its creation, in May 2009 (commit c8c3d83,
  "Add a pkexec(1) command");
 
- any unprivileged local user can exploit this vulnerability to obtain
  full root privileges;
 
- although this vulnerability is technically a memory corruption, it is
  exploitable instantly, reliably, in an architecture-independent way;
 
- and it is exploitable even if the polkit daemon itself is not running.
 
We will not publish our exploit immediately; however, please note that
this vulnerability is trivially exploitable, and other researchers might
publish their exploits shortly after the patches are available. If no
patches are available for your operating system, you can remove the
SUID-bit from pkexec as a temporary mitigation; for example:
 
# chmod 0755 /usr/bin/pkexec
 
This vulnerability is one of our most beautiful discoveries; to honor
its memory, we recommend listening to DJ Pone's "Falken's Maze" (double
pun intended) while reading this advisory. Thank you very much!
"
