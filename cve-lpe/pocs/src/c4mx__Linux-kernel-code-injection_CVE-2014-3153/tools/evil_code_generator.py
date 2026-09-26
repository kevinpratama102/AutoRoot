#!/usr/bin/python

__author__ = "c4mx"

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import sys
import uuid
from subprocess import call
from subprocess import call

R_ARM_MOVT_ABS = 44
R_ARM_CALL = 28

module_name = sys.argv[1]
target_name = sys.argv[2]

data_section_padding = 0

class ELFLogger:
    """ELF Logger"""
    def __init__(self, elf):
        self.module_name = module_name
        self.target_name = target_name

        textsec = elf.get_section_by_name(".text")
        datasec = elf.get_section_by_name(".rodata.str1.4")

        self.text_size = textsec['sh_size']

        remainder = datasec['sh_size'] % 4
        if remainder:
            self.data_section_padding = 4 - remainder
        else:
            self.data_section_padding = 0
        self.data_size = datasec['sh_size'] + self.data_section_padding

        self.resolved_function = {}

    def print_info(self):
        print("module name: %s" % self.module_name)
        print("target name: %s" % self.target_name)
        print("text section size: %d" % self.text_size)
        print("data section size: %d" % self.data_size)
        print("function resolver list:")
        for func in self.resolved_function:
            print("\t-%s: at %s" % (func, hex(self.resolved_function[func])))

def write_to_offset(filename, offset, data):
    """Write data to a file object at offset given"""
    with open(filename, 'r+b') as f:
        f.seek(offset)
        f.write(data)

def extract_text_data_to_file(elf, target_name):
    """Extract .text and .rodata.str1.4 section"""
    textsec = elf.get_section_by_name(".text")
    datasec = elf.get_section_by_name(".rodata.str1.4")
    # Write code and data section to target file
    with open(target_name, 'wb') as target:
        target.write(textsec.data())
        target.write(datasec.data())
        #print("[*] Extract .text and .rodata.str1.4 to target")

def append_padding_to_data_section(elf):
    """Append 0-padding to target file if data section is not 4-byte aligned
    """
    datasec = elf.get_section_by_name(".rodata.str1.4")
    remainder = datasec['sh_size'] % 4
    if remainder:
        data_section_padding = 4 - remainder
        with open(target_name, 'ab') as target:
            target.write('\x00'*data_section_padding)

def uuid_name():
    return '/tmp/' + str(uuid.uuid4())

def assemble(asm):
    """Assembly string -> opcode"""
    f0 = uuid_name()
    with open(f0, 'wb') as f:
        f.write(asm + '\x0a')

    f1 = uuid_name()
    call(['arm-none-eabi-as', f0, '-o', f1])

    f2 = uuid_name()
    call(['objcopy', '-j', '.text', '-O', 'binary', '-I', 'elf32-little', f1, f2])

    with open(f2, 'rb') as f:
        opcode = f.read()

    call(['rm', f0, f1, f2])

    return opcode


def append_function_call_resolver(filename, data):
    """Append function call resolver after data section"""
    with open(filename, "ab") as f:
        f.write(data)


def resolve_data_ref(elf):
    """Resolve data reference"""
    reltextsec = elf.get_section_by_name('.rel.text')
    symtabsec = elf.get_section_by_name('.symtab')
    textsec = elf.get_section_by_name(".text")

    for reloc in reltextsec.iter_relocations():
        if reloc['r_info_type'] == R_ARM_MOVT_ABS:
            text_offset = reloc['r_offset']
            sym_index = reloc['r_info_sym']
            symbol = symtabsec.get_symbol(sym_index)
            data_offset = textsec['sh_size'] + symbol['st_value']
            offset = data_offset - text_offset - 8

            asm = 'add r0, pc, #' + hex(offset)
            opcode = assemble(asm)
            write_to_offset(target_name, text_offset, opcode)

def rshift(val, n):
    return val>>n if val >= 0 else (val+0x100000000)>>n

def calc_offset(current, target):
    r = rshift((target - current - 8), 2)
    #print r
    return hex(r)

def resolve_function_call(elf, elflogger):
    """Resovle external function calls"""
    reltextsec = elf.get_section_by_name('.rel.text')
    symtabsec = elf.get_section_by_name('.symtab')
    textsec = elf.get_section_by_name(".text")

    func_g_offset = 0xcccccccc

    for reloc in reltextsec.iter_relocations():
        if reloc['r_info_type'] == R_ARM_CALL:

            sym_index = reloc['r_info_sym']
            symbol = symtabsec.get_symbol(sym_index)

            if symbol.name not in elflogger.resolved_function:
                asm = ("push {r4, lr}\n"
                       "ldr r4, =#" + hex(func_g_offset) + "\n"
                       "blx r4\n"
                       "pop {r4, pc}")
                opcode = assemble(asm)
                append_function_call_resolver(target_name, opcode)

                # TODO: update resovled function dict
                #       last end of file

                func_info = {symbol.name: }
                elflogger.resolved_function.append(func_info)

                text_offset = reloc['r_offset']
                calc_offset(,)


def main():
    with open(module_name, 'rb') as modobj:
        modelf = ELFFile(modobj)
        logger = ELFLogger(modelf)

        extract_text_data_to_file(modelf, target_name)
        append_padding_to_data_section(modelf)
        resolve_data_ref(modelf)
        resolve_function_call(modelf, logger)
        logger.print_info()

if __name__ == '__main__':
    main()


