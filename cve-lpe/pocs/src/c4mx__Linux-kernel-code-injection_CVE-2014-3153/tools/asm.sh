#!/bin/bash

input=$1
output=$2
rel=/tmp/$RANDOM
arm-none-eabi-as $input -o $rel 
objcopy -j .text -O binary -I elf32-little $rel $output 
echo "[*] Assemble '$input' to '$output'"
echo "---"
echo "Assembly file '$input':"
cat $input
echo "---"
echo "Hexdump file '$output':"
hexdump -C $output
rm $rel