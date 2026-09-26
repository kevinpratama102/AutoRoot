#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: ./dump_text file"
    exit 0
fi
echo "arm-none-eabi-objdump -D -b binary -marm myscan.txt" 
arm-none-eabi-objdump -D -b binary -marm $1 
