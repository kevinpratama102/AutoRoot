This is a combination of the zerologon_tester.py code and the tool evil-winrm to get a shell.  I just added a "os.system" to use evil-winrm.

Requirements:
- To get the Administrator NTLM HASH I recommend you to use secretsdump (tool) from impacket
- And, of course, you need to install evil-winrm

This is just a simple code to put almost everything together.

Some references:
https://tryhackme.com/room/zer0logon
https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py
https://github.com/Sq00ky/Zero-Logon-Exploit/blob/master/zeroLogon-NullPass.py
