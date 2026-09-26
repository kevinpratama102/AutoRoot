#!/bin/bash

# Author:- Anurag Jena  
Date Created:- 30/04/2021



A shell script to check the execution of a command and execute special conditions



cmmnd_checker()
{
 CVE20213156= "pgrep -x "sudoedit -s" >/dev/null"
 if $CVE20213156= true
then
    echo "Password Required"
    echo ""
    PASS="Dev_Access_6959"
read -s -p "Password: " mypassword
echo ""
if $mypassword = $PASS
then
echo "Password accepted"
else
echo "Access denied | Incident Reported"
xdg-screensaver lock
else
 echo "None"
fi
}

while true
do
$(cmmnd_checker)
sleep
