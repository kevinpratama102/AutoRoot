#!/usr/bin/python
def rshift(val, n):
    return val>>n if val >= 0 else (val+0x100000000)>>n

def offset(current, target):
    r = rshift((target - current - 8), 2)
    print r
    return hex(r)

def hex_str(str):
    return ''.join('\\x{:02x}'.format(ord(ch)) for ch in str)

def print_hex(str):
    hs = hex_str(str)
    n = 16
    for i in range(0, len(hs), n):
        print "\"" + hs[i:i+n] + "\"";

if __name__ == "__main__":
    print offset(0xc8088848, 0xc03e4a7c)
    s = 'abcdefghijklmnopqrstuvwxyz'
    print hex_str(s)
    print_hex(s)

