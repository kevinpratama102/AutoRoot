#!/usr/bin/python

__author__ = "c4mx"

from elftools.elf.elffile import ELFFile

import sys

if len(sys.argv[1:]):
    filename = sys.argv[1]
else:
    print("[*] Usage: readelf.py file")
    exit(1)

print("[*] Processing file: %s" % filename)

f = open(filename, 'rb')
elffile = ELFFile(f)
print("[*] Number of sections: %d" % elffile.num_sections())
relsec = elffile.get_section_by_name(".rel.text")
textsec = elffile.get_section_by_name(".text")
datasec = elffile.get_section_by_name(".rodata.str1.4")
#print(datasec.data())

new_file = "code_injected"
nf = open(new_file, 'wb')
nf.write(textsec.data())
nf.write(datasec.data())
nf.close()
print("[*] Written evil code to file %s" % new_file)

print("[*] Exit")
f.close()
