#! /usr/bin/python3

from capstone import *
from capstone.mips import *

import argparse
import os

parser = argparse.ArgumentParser(description="Disassemble a file")
parser.add_argument("file", help="path to a file containing MIPS assembly")


def main(fname):
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    with open(fname, "rb") as f:
        fbytes = f.read()

    jr_count = 0
    insns = []
    for insn in md.disasm(fbytes, 0x100000):
        name = insn.mnemonic
        op_str = insn.op_str
        
        if name == "ext":
            name = "sq"
            array = op_str.split(", ")
            array.pop()
            array.pop()
            op_str = ", ".join(array)
    
        print("/*0x%x:*/\t%s\t%s" %(insn.address, name, op_str))
    return jr_count

num = main("/home/osboxes/Desktop/main.bin")
print("main.bin - " + str(num))

# if __name__ == "__main__":
#     args = parser.parse_args()
#     main(args.file)
