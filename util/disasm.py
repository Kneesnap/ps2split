#! /usr/bin/python3

from capstone import *
from capstone.mips import *

import argparse
import os

# Setup register lookup.
registers = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15', 'f16', 'f17', 'f18', 'f19', 'f20', 'f21', 'f22', 'f23', 'f24', 'f25', 'f26', 'f27', 'f28', 'f29', 'f30', 'f31']
register_mapping = {}
register_mapping['s8'] = 30 # Same register as 'fp'.
register_mapping['ac2'] = 2 # Same as 'v0'.
register_mapping['ac3'] = 3 # Same as 'v1'.


# Begin!
parser = argparse.ArgumentParser(description="Disassemble a file")
parser.add_argument("file", help="path to a file containing MIPS assembly")

def get_instruction_integer(insn):
    return int.from_bytes(insn.bytes, byteorder='little', signed=False)

# Byte 3 - 24, 31
# Byte 2 - 16, 23
# Byte 1 - 8, 15
# Byte 0 - 0, 7
# 0 is the right-most bit. 31 is left-most.    
def get_bits(num, pos, bitCount):
    mask = 0
    for i in range(bitCount):
        mask = (mask << 1) | 1
    
    return ((num & (mask << pos)) >> pos) & mask

def get_instruction_string(labels, insn):
    name = insn.mnemonic
    op_str = insn.op_str
    op_num = get_instruction_integer(insn)
    modified = False
    
    for i in range(32): # Replace registers. Go in opposite order so registers like '$f30' don't get turned into '$f3' + '0'.
        op_str = op_str.replace('$' + registers[i], '$' + str(i))
    for key in register_mapping.keys():
        op_str = op_str.replace("$" + key, "$" + str(register_mapping[key]))
    
    if name != "branch" and (name.startswith("b") or name.startswith("j")):
    	modified = True
    	array = op_str.split(", ")
    	for i in range(len(array)):
    	    if array[i].startswith("0x"):
    	        array[i] = labels[int(array[i], 16)]
    	
    	op_str = ", ".join(array)
        
    if get_bits(op_num, 26, 6) == 0b011111: # SQ
        name = "sq"
        base = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16)
        op_str = "$" + str(rt) + ", " + (str(offset) if offset != 0 else "") + "($" + str(base) + ")"
        modified = True
    
    if get_bits(op_num, 26, 5) == 0b011110: # LQ
        name = "lq"
        base = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16)
        op_str = "$" + str(rt) + ", " + (str(offset) if offset != 0 else "") + "($" + str(base) + ")"
        modified = True
    
    if get_bits(op_num, 26, 6) == 0b000000: # Special.
        if get_bits(op_num, 0, 6) == 0b011010: # DIV
            name = "div"
            rs = get_bits(op_num, 21, 5)
            rt = get_bits(op_num, 16, 5)
            op_str = "$" + str(rs) + ", $" + str(rt)
            modified = True
        
        if get_bits(op_num, 0, 6) == 0b001111: # SYNC - TODO - Has parameter?
            name = "sync"
            op_str = ""
            modified = True
        
        if get_bits(op_num, 0, 6) == 0b001101: # BREAK - Breakpoint???
            name = "break"
            op_str = hex(get_bits(op_num, 6, 20))
            modified = True
    
        
    if modified:
        return ("/*0x%x: %s*/\t%s\t%s\t// %s %s" %(insn.address, (' '.join(format(x, '02x') for x in insn.bytes)).upper(), name, op_str, insn.mnemonic, insn.op_str))
    else:
        return ("/*0x%x: %s*/\t%s\t%s" %(insn.address, (' '.join(format(x, '02x') for x in insn.bytes)).upper(), name, op_str))


# 21FDE0 is when code stops, and it's just data.
def main(fname):
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    with open(fname, "rb") as f:
        fbytes = f.read()

    jr_count = 0
    # insns = 
    
    labels = {}
    for insn in md.disasm(fbytes, 0x100000):
        name = insn.mnemonic
        if name != "branch" and (name.startswith("b") or name.startswith("j")):
            array = insn.op_str.split(", ")
            for i in range(len(array)):
                arg = array[i]
                if arg.startswith("0x"):
                    labels[int(arg, 16)] = "label_" + arg[2:]
    
    for insn in md.disasm(fbytes, 0x100000): # insn = [id(int), address(int), mnemonic(str),o p_str(str), size (int), bytes(byte[])]
        if insn.address in labels.keys():
            print(labels[insn.address] + ":")
            
        if insn.address >= 0x21FDE0 or (insn.address >= 0x1EDA80 and insn.address < 0x21A380): # Where code ends and data begins in Frogger TGQ. Also seems to be an area for VU code? It also just seems to have data too.
            print("\t .byte %s" %((', '.join('0x' + format(x, '02x').upper() for x in insn.bytes))))
        else:
            print(get_instruction_string(labels, insn))
    
    return jr_count

num = main("/home/osboxes/Desktop/main.bin")
print("main.bin - " + str(num))

# if __name__ == "__main__":
#     args = parser.parse_args()
#     main(args.file)
