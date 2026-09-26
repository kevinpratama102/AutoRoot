#!/usr/bin/python

__author__ = "c4mx"

import sys

def rshift(val, n):
    return val>>n if val >= 0 else (val+0x100000000)>>n

def offset(current, target):
    r = rshift((target - current - 8), 2)
    return hex(r)

if __name__ == "__main__":
    if len(sys.argv[1:]) == 2:
        cur = int(sys.argv[1], 16)
        tar = int(sys.argv[2], 16)
        print offset(cur, tar)
    else:
        print("[*] Usage: calc_offset.py current target (offset in hex)")
        sys.exit(0)
