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
def get_bits(num, pos, bitCount, signed=False):
    mask = 0
    for i in range(bitCount):
        mask = (mask << 1) | 1
    
    result = ((num & (mask << pos)) >> pos) & mask
    
    neg_mask = (1 << (bitCount - 1))
    if signed and (result & neg_mask) == neg_mask:
        result = -1 * (neg_mask - (result ^ neg_mask))
    return result

# TODO: EE Core-Specific Instruction Set.
# TODO: COP1 Instruction Set

def get_register(id):
    return "$" + str(id)

def get_instruction_string(labels, insn):
    name = insn.mnemonic
    op_str = insn.op_str
    op_num = get_instruction_integer(insn)
    modified = False
    
    for i in range(32): # Replace registers. Go in opposite order so registers like '$f30' don't get turned into '$f3' + '0'.
        op_str = op_str.replace('$' + registers[i], get_register(i))
    for key in register_mapping.keys():
        op_str = op_str.replace("$" + key, get_register(register_mapping[key]))
    
    main_opcode = get_bits(op_num, 26, 6)
    
    if name == "divu":
       args = op_str.split(", ")
       args.pop(0)
       op_str = ", ".join(args)
       modified = True
    
    if name != "branch" and (name.startswith("b") or name.startswith("j")):
    	modified = True
    	array = op_str.split(", ")
    	for i in range(len(array)):
    	    if array[i].startswith("0x"):
    	        array[i] = labels[int(array[i], 16)]
    	
    	op_str = ", ".join(array)
    
    # COP0:
    if main_opcode == 0b011111: # SQ
        name = "sq"
        base = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16, signed=True)
        op_str = get_register(rt) + ", " + (str(offset) if offset != 0 else "") + "(" + get_register(base) + ")"
        modified = True
    
    if main_opcode == 0b011110: # LQ
        name = "lq"
        base = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16, signed=True)
        op_str = get_register(rt) + ", " + (str(offset) if offset != 0 else "") + "(" + get_register(base) + ")"
        modified = True
    
    if main_opcode == 0b101111: # COP0 CACHE
        name = "cache"
        base = get_bits(op_num, 21, 5)
        op = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16, signed=True)
        op_str = hex(op) + ", " + (str(offset) if offset != 0 else "") + "(" + get_register(base) + ")\t// COP0"
        modified = True
    
    if main_opcode == 0b010000: # COP0
        modified = True
        if get_bits(op_num, 21, 5) == 0b01000 and get_bits(op_num, 16, 5) == 0b00000:
            name = "bc0f"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif get_bits(op_num, 21, 5) == 0b01000 and get_bits(op_num, 16, 5) == 0b00010:
            name = "bc0fl"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif get_bits(op_num, 21, 5) == 0b01000 and get_bits(op_num, 16, 5) == 0b00001:
            name = "bc0t"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif get_bits(op_num, 21, 5) == 0b01000 and get_bits(op_num, 16, 5) == 0b00011:
            name = "bc0tl"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif get_bits(op_num, 0, 6) == 0b111001 and get_bits(op_num, 6, 15) == 0 and get_bits(op_num, 21, 5) == 0b10000: # di
            name = "di"
            op_str = ""
        elif get_bits(op_num, 0, 6) == 0b111000 and get_bits(op_num, 6, 15) == 0 and get_bits(op_num, 21, 5) == 0b10000: # ei
            name = "ei"
            op_str = ""
        elif get_bits(op_num, 0, 6) == 0b011000 and get_bits(op_num, 6, 15) == 0 and get_bits(op_num, 21, 5) == 0b10000: # eret
            name = "eret"
            op_str = ""
        elif get_bits(op_num, 0, 11) == 0b00000000000 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfbpc"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfc0"
            op_str = get_register(get_bits(op_num, 16, 5)) + ", " + get_register(get_bits(op_num, 11, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000100 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfdab"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000101 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfdabm"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000110 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfdvb"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000111 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfdvbm"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000010 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfiab"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000011 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00000:
            name = "mfiabm"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 21, 5) == 0b00000 and get_bits(op_num, 11, 5) == 0b11001 and get_bits(op_num, 6, 5) == 0b00000 and get_bits(op_num, 0, 1) == 0b1:
            name = "mfpc"
            op_str = get_register(get_bits(op_num, 16, 5)) + ", " + get_register(get_bits(op_num, 1, 5))
        elif get_bits(op_num, 21, 5) == 0b00000 and get_bits(op_num, 11, 5) == 0b11001 and get_bits(op_num, 6, 5) == 0b00000 and get_bits(op_num, 0, 1) == 0b0:
            name = "mfps"
            op_str = get_register(get_bits(op_num, 16, 5)) + ", " + get_register(get_bits(op_num, 1, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000000 and get_bits(op_num, 11, 5) == 0b11000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtbpc"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtc0"
            op_str = get_register(get_bits(op_num, 16, 5)) + ", " + get_register(get_bits(op_num, 11, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000100 and str(get_bits(op_num, 11, 5)) == 0b11000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtdab"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000101 and str(get_bits(op_num, 11, 5)) == 0b11000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtdabm"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000110 and str(get_bits(op_num, 11, 5)) == 0b11000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtdvb"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000111 and str(get_bits(op_num, 11, 5)) == 0b11000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtdvbm"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000010 and str(get_bits(op_num, 11, 5)) == 0b11000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtiab"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 0, 11) == 0b00000000011 and str(get_bits(op_num, 11, 5)) == 0b11000 and get_bits(op_num, 21, 5) == 0b00100:
            name = "mtiabm"
            op_str = get_register(get_bits(op_num, 16, 5))
        elif get_bits(op_num, 21, 5) == 0b00100 and get_bits(op_num, 11, 5) == 0b11001 and get_bits(op_num, 6, 5) == 0b00000 and get_bits(op_num, 0, 1) == 0b1:
            name = "mtpc"
            op_str = get_register(get_bits(op_num, 16, 5)) + ", " + get_register(get_bits(op_num, 1, 5))
        elif get_bits(op_num, 21, 5) == 0b00100 and get_bits(op_num, 11, 5) == 0b11001 and get_bits(op_num, 6, 5) == 0b00000 and get_bits(op_num, 0, 1) == 0b0:
            name = "mtps"
            op_str = get_register(get_bits(op_num, 16, 5)) + ", " + get_register(get_bits(op_num, 1, 5))
        elif get_bits(op_num, 21, 5) == 0b10000 and get_bits(op_num, 16, 15) == 0b000000000000000 and get_bits(op_num, 0, 6) == 0b001000:
            name = "tlbp"
            op_str = ""
        elif get_bits(op_num, 21, 5) == 0b10000 and get_bits(op_num, 16, 15) == 0b000000000000000 and get_bits(op_num, 0, 6) == 0b000001:
            name = "tlbr"
            op_str = ""
        elif get_bits(op_num, 21, 5) == 0b10000 and get_bits(op_num, 16, 15) == 0b000000000000000 and get_bits(op_num, 0, 6) == 0b000010:
            name = "tlbwi"
            op_str = ""
        elif get_bits(op_num, 21, 5) == 0b10000 and get_bits(op_num, 16, 15) == 0b000000000000000 and get_bits(op_num, 0, 6) == 0b000110:
            name = "tlbwr"
            op_str = ""
        else:
            modified = False
        
        if modified:
            op_str += "\t// COP0"
    
    if main_opcode == 0b000000: # Special.
        if get_bits(op_num, 0, 6) == 0b100111: # NOR
            name = "nor"
            rs = get_bits(op_num, 21, 5)
            rt = get_bits(op_num, 16, 5)
            rd = get_bits(op_num, 11, 5)
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            modified = True
        if get_bits(op_num, 0, 6) == 0b011010: # DIV
            name = "div"
            rs = get_bits(op_num, 21, 5)
            rt = get_bits(op_num, 16, 5)
            op_str = get_register(rs) + ", " + get_register(rt)
            modified = True
        
        if get_bits(op_num, 0, 6) == 0b001111: # SYNC
            name = "sync"
            if get_bits(op_num, 6, 5) == 0b10000:
               name = name + ".p"
            
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

main("/home/osboxes/Desktop/main.bin")

# if __name__ == "__main__":
#     args = parser.parse_args()
#     main(args.file)
