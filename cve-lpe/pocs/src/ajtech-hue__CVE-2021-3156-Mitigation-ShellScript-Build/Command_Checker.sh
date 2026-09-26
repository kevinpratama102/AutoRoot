#!/bin/bash

# Author:- Anurag Jena  Date Created:- 30/04/2021




# Author: Vivek Gite   Date: April 10, 2008 (Source: https://bash.cyberciti.biz/misc-shell/shel-to-accept-password/)
# Script accept password using read commnad
# Not *very secure*, this script is for learning purpose only 
# -------------------------------------------------------------------------
# This script is part of nixCraft shell script collection (NSSC)
# Visit http://bash.cyberciti.biz/ for more information.
# -------------------------------------------------------------------------


req_passwd()
{
PASS="Dev_Access_6959"
read -s -p "Password: " mypassword
echo ""
[ "$mypassword" == "$PASS" ] && echo "Password accepted For " || echo "Access denied Incident Reported" || exit || xdg-screensaver lock
}

PASSVULN=$(req_passwd)


cmmnd_checker()
{
SERVICE="sudoedit"
if pgrep -x "$SERVICE" >/dev/null
then
    echo "$SERVICE Invoked, Password Required"
    $PASSVULN
    
else
    echo "$SERVICE stopped"
    # uncomment to start nginx if stopped
    # systemctl start nginx
    # mail  
fi
}


