#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: ./extract_text input output"
    exit 0
fi

echo "arm-none-eabi-objdump -D -b binary -marm myscan.txt"
objcopy -j .text -O binary -I elf32-little $1 $2
