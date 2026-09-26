#! /bin/bash

TEST="$(grep -o '....................................$' dumps/secret.txt.ntds | tr -d ':')"
export TEST2=$TEST
echo $TEST
