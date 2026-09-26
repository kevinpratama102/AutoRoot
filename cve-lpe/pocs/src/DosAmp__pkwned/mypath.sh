#!/bin/sh
P=$(realpath pkwned.c)
PROG=${P%%.c}
echo \#define PWNIE_PATH \"$PROG\"
echo \#define PWNIE_ARG0 \"${PROG##*/}\"
