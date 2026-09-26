# CVE-2023-23397 Windows Update Patch
CVE-2023-23397 powershell patch script for Windows 10 and 11 

This version of the script allows you to check if your device has the most reach sent patches for the latest Microsoft exploit. 
if the security updates are not found using the Powershell Command Get-hotfix it will download the latest windows update and and silently install them without restarting. it is still recommended you restart the machines as needed.

Windows update should do the trick for most folks to fix this issue.
Device that can not reach the domain server because of VPN issues or user not connecting can benifit from this script.

God Speed.
