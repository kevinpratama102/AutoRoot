#!/bin/bash

@Author Anurag Jena
Date: 29/04/2021


PASS="Dev_Access_6959"
read -s -p "Password: " mypassword
echo ""
if $mypassword == $PASS
then
echo "Password accepted"
else
echo "Access denied | Incident Reported"
xdg-screensaver lock
fi
