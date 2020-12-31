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

main_opcode_offset_clones = {}
main_opcode_offset_clones[0b100000] = "lb"
main_opcode_offset_clones[0b100100] = "lbu"
main_opcode_offset_clones[0b110111] = "ld"
main_opcode_offset_clones[0b011010] = "ldl"
main_opcode_offset_clones[0b011011] = "ldr"
main_opcode_offset_clones[0b100001] = "lh"
main_opcode_offset_clones[0b100101] = "lhu"
main_opcode_offset_clones[0b100011] = "lw"
main_opcode_offset_clones[0b100010] = "lwl"
main_opcode_offset_clones[0b100110] = "lwr"
main_opcode_offset_clones[0b100111] = "lwu"
main_opcode_offset_clones[0b101000] = "sb"
main_opcode_offset_clones[0b111111] = "sd"
main_opcode_offset_clones[0b101100] = "sdl"
main_opcode_offset_clones[0b101101] = "sdr"
main_opcode_offset_clones[0b101001] = "sh"


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
    
def get_fp_register(id):
    return "$f" + str(id)
    
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
    
    # NOTE: The normal instruction set isn't explicitly parsed. Wasn't any reason to support it, since capstone already handles that decently well. It's possible I missed issues with it though.
    
    # EE Core-Specific Instruction Set
    if main_opcode == 0b011100: # MMI
        sub_code = get_bits(op_num, 0, 6)
        rs = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        rd = get_bits(op_num, 11, 5)
        modified = True
        
        if sub_code == 0b011010: # DIV1
            name = "div1"
            op_str = get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b011011: # DIVU1
            name = "divu1"
            op_str = get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b000000: # MADD
            name = "madd"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b100000: # MADD1
            name = "madd1"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b000001: # MADDU
            name = "maddu"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b100001: # MADDU1
            name = "maddu1"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b010000: #MFHI1
            name = "mfhi1"
            rd = get_bits(op_num, 11, 5)
            op_str = get_register(rd)
        elif sub_code == 0b010010: #MFLO1
            name = "mflo1"
            rd = get_bits(op_num, 11, 5)
            op_str = get_register(rd)
        elif sub_code == 0b010001: #MTHI1
            name = "mthi1"
            rs = get_bits(op_num, 21, 5)
            op_str = get_register(rs)
        elif sub_code == 0b010011: # MTLO1 - The documentation here is wrong, it lists the subcode as 010001.
            name = "mtlo1"
            rs = get_bits(op_num, 21, 5)
            op_str = get_register(rs)
        elif sub_code == 0b011000: # MULT1
            name = "mult1"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b011001: # MULT
            name = "multu1"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b000100: # PLZCW
            name = "plzcw"
            op_str = get_register(rd) + ", " + get_register(rs)
        elif sub_code == 0b110000: # PMFHL.LH
            fmt = get_bits(op_num, 6, 5)
            name = "pmfhl."
            op_str = get_register(rd)
            
            if fmt == 0b00011:
                name += "lh"
            elif fmt == 0b00000:
                name += "lw"
            elif fmt == 0b00100:
                name += "sh"
            elif fmt == 0b00010:
                name += "slw"
            elif fmt == 0b00001:
                name += "uw"
            else:
                name += "error"
                
        elif sub_code == 0b110001 and get_bits(op_num, 6, 5) == 0b00000: # PMTHL
            name = "pmthl.lw"
            op_str = get_register(rs)
        elif sub_code == 0b110100: # PSLLH
            name = "psllh"
            sa = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b111100: # PSLLW
            name = "psllw"
            sa = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b110111: # PSRAH
            name = "psrah"
            sa = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b111111: # PSRAW
            name = "psraw"
            sa = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b110110: # PSRLH
            name = "psrlh"
            sa = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b111110: # PSRLW
            name = "psrlw"
            sa = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b001000: # MMI0
            pcode = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            
            if pcode == 0b01000: # PADDB
                name = "paddb"
            elif pcode == 0b00100: # PADDH
                name = "paddh"
            elif pcode == 0b11000: # PADDSB
                name = "paddsb"
            elif pcode == 0b10100: # PADDSH
                name = "paddsh"
            elif pcode == 0b10000: # PADDSW
                name = "paddsw"
            elif pcode == 0b00000: # PADDW
                name = "paddw"
            elif pcode == 0b01010: # PCGTB
                name = "pcgtb"
            elif pcode == 0b00110: # PCGTH
                name = "pcgth"
            elif pcode == 0b00010: # PCGTW
                name = "pcgtw"
            elif pcode == 0b11110: # PEXT5
                name = "pext5"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b11010: # PEXTLB
                name = "pextlb"
            elif pcode == 0b10110: # PEXTLH
                name = "pextlh"
            elif pcode == 0b10010: # PEXTLW
                name = "pextlw"
            elif pcode == 0b00111: # PMAXH
                name = "pmaxh"
            elif pcode == 0b00011: # PMAXH
                name = "pmaxw"
            elif pcode == 0b11111: # PPAC5
                name = "ppac5"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b11011: # PPACB
                name = "ppacb"
            elif pcode == 0b10111: # PPACH
                name = "ppach"
            elif pcode == 0b10011: # PPACW
                name = "ppacw"
            elif pcode == 0b01001: # PSUBB
                name = "psubb"
            elif pcode == 0b00101: # PSUBH
                name = "psubh"
            elif pcode == 0b11001: # PSUBSB
                name = "psubsb"
            elif pcode == 0b10101: # PSUBSH
                name = "psubsh"
            elif pcode == 0b10001: # PSUBSW
                name = "psubsw"
            elif pcode == 0b00001: # PSUBW
                name = "psubw"
            else:
                name = "mmi0" # Unknown
                op_str = "error"
        elif sub_code == 0b101000: # MMI1
            pcode = get_bits(op_num, 6, 5)
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            
            if pcode == 0b00101: # PABSH
                name = "pabsh"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b00001: # PABSW
                name = "pabsw"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b11000: # PADDUB
                name = "paddub"
            elif pcode == 0b10100: # PADDUH
                name = "padduh"
            elif pcode == 0b10000: # PADDUW
                name = "padduw"
            elif pcode == 0b00100: # PADSBH
                name = "padsbh"
            elif pcode == 0b01010: # PCEQB
                name = "pceqb"
            elif pcode == 0b00110: # PCEQH
                name = "pceqh"
            elif pcode == 0b00010: # PCEQW
                name = "pceqw"
            elif pcode == 0b11010: # PEXTUB
                name = "pextub"
            elif pcode == 0b10110: # PEXTUH
                name = "pextuh"
            elif pcode == 0b10010: # PEXTUW
                name = "pextuw"
            elif pcode == 0b00111: # PMINH
                name = "pminh"
            elif pcode == 0b00011: # PMINW
                name = "pminw"
            elif pcode == 0b11001: # PSUBUB
                name = "psubub"
            elif pcode == 0b10101: # PSUBUH
                name = "psubuh"
            elif pcode == 0b10001: # PSUBUW
                name = "psubuw"
            elif pcode == 0b11011: # QFSRV
                name = "qfsrv"
            else:
                name = "mmi1" # Unknown
                op_str = "error"
        elif sub_code == 0b001001: # MMI2
            pcode = get_bits(op_num, 6, 5)
            
            if pcode == 0b10010: # PAND
                name = "pand"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b01110: # PCPYLD
                name = "pcpyld"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b11101: # PDIVBW
                name = "pdivbw"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b01101: # PDIVW
                name = "pdivw"
                op_str = get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b11010: # PEXEH
                name = "pexeh"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b11110: # PEXEW
                name = "pexew"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b10001: # PHMADH
                name = "phmadh"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b10101: # PHMSBH
                name = "phmsbh"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b01010: # PINTH
                name = "pinth"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b10000: # PMADDH
                name = "pmaddh"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b00000: # PMADDW
                name = "pmaddw"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b01000: # PMFHI
                name = "pmfhi"
                op_str = get_register(rd)
            elif pcode == 0b01001: # PMFLO
                name = "pmflo"
                op_str = get_register(rd)
            elif pcode == 0b10100: # PMSUBH
                name = "pmsubh"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b00100: # PMSUBW
                name = "pmsubw"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b11100: # PMULTH
                name = "pmulth"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b01100: # PMULTW
                name = "pmultw"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b11011: # PREVH
                name = "prevh"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b11111: # PROT3W
                name = "prot3w"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b00010: # PSLLVW
                name = "psllvw"
                op_str = get_register(rd) + ", " + get_register(rt) + ", " + get_register(rs)
            elif pcode == 0b00011: # PSRLVW
                name = "psrlvw"
                op_str = get_register(rd) + ", " + get_register(rt) + ", " + get_register(rs)
            elif pcode == 0b10011: # PXOR
                name = "pxor"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            else:
                name = "mmi2" # Unknown.
                op_str = "error"
        elif sub_code == 0b101001: # MMI3
            pcode = get_bits(op_num, 6, 5)
            
            if pcode == 0b11011: # PCPYH
                name = "pcpyh"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b01110: # PCPYUD
                name = "pcpyud"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b01101: # PDIVUW
                name = "pdivuw"
                op_str = get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b11010: # PEXCH
                name = "pexch"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b11110: # PEXCW
                name = "pexcw"
                op_str = get_register(rd) + ", " + get_register(rt)
            elif pcode == 0b01010: # PINTEH
                name = "pinteh"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b00000: # PMADDUW
                name = "pmadduw"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b01000: # PMTHI
                name = "pmthi"
                op_str = get_register(rs)
            elif pcode == 0b01001: # PMTLO
                name = "pmtlo"
                op_str = get_register(rs)
            elif pcode == 0b01100: # PMULTUW
                name = "pmultuw"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b10011: # PNOR
                name = "pnor"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b10010: # POR
                name = "por"
                op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
            elif pcode == 0b00011: # POR
                name = "psravw"
                op_str = get_register(rd) + ", " + get_register(rt) + ", " + get_register(rs)
            else:
                name = "mmi3" # Unknown
                op_str = "error"
            
        else:
            modified = False
    
    if main_opcode == 0b000001: # REGIMM
        sub_code = get_bits(op_num, 16, 5)
        modified = True
        
        if sub_code == 0b11000: # MTSAB
            name = "mtsab"
            rs = get_bits(op_num, 21, 5)
            immediate = get_bits(op_num, 0, 16)
            op_str = get_register(rs) + ", " + hex(immediate)
        elif sub_code == 0b11001: # MTSAH
            name = "mtsah"
            rs = get_bits(op_num, 21, 5)
            immediate = get_bits(op_num, 0, 16)
            op_str = get_register(rs) + ", " + hex(immediate)
        else:
            modified = False
    
    if main_opcode == 0b000000: # SPECIAL
        sub_code = get_bits(op_num, 0, 6)
        modified = True
        
        if sub_code == 0b101000: #MFSA
            name = "mfsa"
            rd = get_bits(op_num, 11, 5)
            op_str = get_register(rd)
        elif sub_code == 0b101001: # MTSA
            name = "mtsa"
            rs = get_bits(op_num, 21, 5)
            op_str = get_register(rs)
        elif sub_code == 0b011000: # MULT
            name = "mult"
            rs = get_bits(op_num, 21, 5)
            rt = get_bits(op_num, 16, 5)
            rd = get_bits(op_num, 11, 5)
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b011001: # MULTU
            name = "multu"
            rs = get_bits(op_num, 21, 5)
            rt = get_bits(op_num, 16, 5)
            rd = get_bits(op_num, 11, 5)
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        else:
            modified = False
        
    
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
    
    # COP0:
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
    
    # COP1
    if main_opcode == 0b110001: # LWC
        name = "lwc1"
        base = get_bits(op_num, 21, 5)
        ft = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16, signed=True)
        op_str = get_fp_register(ft) + ", " + (str(offset) if offset != 0 else "") + "(" + get_register(base) + ")\t// COP1"
        modified = True
    
    if main_opcode == 0b111001: # SWC1
        name = "swc1"
        base = get_bits(op_num, 21, 5)
        ft = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16, signed=True)
        op_str = get_fp_register(ft) + ", " + (str(offset) if offset != 0 else "") + "(" + get_register(base) + ")\t// COP1"
        modified = True
    
    if main_opcode == 0b010001: # COP1
        sub_code = get_bits(op_num, 0, 6)
        option = get_bits(op_num, 21, 5)
        ft = get_bits(op_num, 16, 5)
        fs = get_bits(op_num, 11, 5)
        fd = get_bits(op_num, 6, 5)
        
        modified = True
        if option == 0b01000 and get_bits(op_num, 16, 5) == 0b00000: # BC1F
            name = "bc1f"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif option == 0b01000 and get_bits(op_num, 16, 5) == 0b00010: # BC1FL
            name = "bc1fl"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif option == 0b01000 and get_bits(op_num, 16, 5) == 0b00001: # BC1T
            name = "bc1t"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif option == 0b01000 and get_bits(op_num, 16, 5) == 0b00011: # BC1TL
            name = "bc1tl"
            op_str = labels[insn.address + 4 + (get_bits(op_num, 0, 16, signed=True) << 2)]
        elif option == 0b00010 and get_bits(op_num, 0, 11) == 0b00000000000: # CFC1
            name = "cfc1"
            rt = ft
            op_str = get_register(rt) + ", " + get_fp_register(fs)
        elif option == 0b00110 and get_bits(op_num, 0, 11) == 0b00000000000: # CTC1
            name = "ctc1"
            rt = ft
            op_str = get_register(rt) + ", " + get_fp_register(fs)
        elif option == 0b00000 and get_bits(op_num, 0, 11) == 0b00000000000: # MFC1
            name = "mfc1"
            rt = ft
            op_str = get_register(rt) + ", " + get_fp_register(fs)
        elif option == 0b00100 and get_bits(op_num, 0, 11) == 0b00000000000: # MTC1
            name = "mtc1"
            rt = ft
            op_str = get_register(rt) + ", " + get_fp_register(fs)
        elif sub_code == 0b000101 and option == 0b10000: # ABS.S
            name = "abs.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs)
        elif sub_code == 0b000000 and option == 0b10000: # ADD.S
            name = "add.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b011000 and option == 0b10000: # ADDA.S
            name = "adda.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b110010 and option == 0b10000 and fd == 0b00000: # C.EQ.S
            name = "c.eq.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b110000 and option == 0b10000 and fd == 0b00000: # C.F.S
            name = "c.f.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b110110 and option == 0b10000 and fd == 0b00000: # C.LE.S
            name = "c.le.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b110100 and option == 0b10000 and fd == 0b00000: # C.LT.S
            name = "c.lt.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b100000 and option == 0b10100: # CVT.S.W
            name = "cvt.s.w"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs)
        elif sub_code == 0b100100 and option == 0b10000: # CVT.W.S
            name = "cvt.w.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs)
        elif sub_code == 0b000011 and option == 0b10000: # DIV.S
            name = "div.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b011100 and option == 0b10000: # MADD.S
            name = "madd.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b011110 and option == 0b10000: # MADDA.S
            name = "madda.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b101000 and option == 0b10000: # MAX.S
            name = "max.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b101001 and option == 0b10000: # MIN.S
            name = "min.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b000110 and option == 0b10000: # MOV.S
            name = "mov.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs)
        elif sub_code == 0b011101 and option == 0b10000: # MSUB.S
            name = "msub.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b011111 and option == 0b10000: # MSUBA.S
            name = "msuba.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b000010 and option == 0b10000: # MUL.S
            name = "mul.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b011010 and option == 0b10000: # MULA.S
            name = "mula.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b000111 and option == 0b10000: # NEG.S
            name = "neg.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs)
        elif sub_code == 0b010110 and option == 0b10000: # RSQRT.S
            name = "rsqrt.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b000100 and option == 0b10000: # SQRT.S
            name = "sqrt.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(ft)
        elif sub_code == 0b000001 and option == 0b10000: # SUB.S
            name = "sub.s"
            op_str = get_fp_register(fd) + ", " + get_fp_register(fs) + ", " + get_fp_register(ft)
        elif sub_code == 0b000001 and option == 0b10000: # SUBA.S
            name = "suba.s"
            op_str = get_fp_register(fs) + ", " + get_fp_register(ft)
        else:
            modified = False
        
        if modified:
            op_str += "\t// COP1"
    
    # CPU Instruction Set (Capstone Fixes)
    if main_opcode == 0b000000: # Special.
        sub_code = get_bits(op_num, 0, 6)
        rs = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        rd = get_bits(op_num, 11, 5)
        sa = get_bits(op_num, 6, 5)
        old_state = modified
        modified = True
        
        if sub_code == 0b001101: # BREAK - Breakpoint???
            name = "break"
            op_str = hex(get_bits(op_num, 6, 20))
        elif sub_code == 0b101100: # DADD
            name = "dadd"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b101101: # DADDU
            name = "daddu"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b011010: # DIV
            name = "div"
            op_str = get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b011011: # DIVU
            name = "divu"
            op_str = get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b111000: # DSLL
            name = "dsll"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b111100: # DSLL32
            name = "dsll32"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b010100: # DSLLV
            name = "dsllv"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + get_register(rs)
        elif sub_code == 0b111011: # DSRA
            name = "dsra"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b111111: # DSRA32
            name = "dsra32"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b010111: # DSRAV
            name = "dsrav"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + get_register(rs)
        elif sub_code == 0b111010: # DSRL
            name = "dsrl"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b111110: # DSRL32
            name = "dsrl32"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + hex(sa)
        elif sub_code == 0b010110: # DSRLV
            name = "dsrlv"
            op_str = get_register(rd) + ", " + get_register(rt) + ", " + get_register(rs)
        elif sub_code == 0b101110: # DSUB
            name = "dsub"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b101111: # DSUBU
            name = "dsubu"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b010000: # MFHI
            name = "mfhi"
            op_str = get_register(rd)
        elif sub_code == 0b010010: # MFLO
            name = "mflo"
            op_str = get_register(rd)
        elif sub_code == 0b001011: # MOVN
            name = "movn"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b001010: # MOVZ
            name = "movz"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b010001: # MTHI
            name = "mthi"
            op_str = get_register(rs)
        elif sub_code == 0b010011: # MTLO
            name = "mtlo"
            op_str = get_register(rs)
        elif sub_code == 0b011000: # MULT
            name = "mult"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b011001: # MULTU
            name = "multu"
            op_str = (get_register(rd) + ", " if rd != 0 else "") + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b100111: # NOR
            name = "nor"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b100101: # OR
            name = "or"
            op_str = get_register(rd) + ", " + get_register(rs) + ", " + get_register(rt)
        elif sub_code == 0b001111: # SYNC
            name = "sync"
            op_str = ""
            if sa == 0b10000:
               name = name + ".p"
        else:
            modified = old_state
            
    if main_opcode == 0b011000: # DADDI
        name = "daddi"
        rs = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        immediate = get_bits(op_num, 0, 16, signed=True)
        op_str = get_register(rt) + ", " + get_register(rs) + ", " + str(immediate)
        
    
    if main_opcode == 0b011001: # DADDIU
        name = "daddiu"
        rs = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        immediate = get_bits(op_num, 0, 16, signed=True)
        op_str = get_register(rt) + ", " + get_register(rs) + ", " + str(immediate)
        
    if main_opcode == 0b001101: # ORI
        name = "ori"
        rs = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        immediate = get_bits(op_num, 0, 16, signed=False)
        op_str = get_register(rt) + ", " + get_register(rs) + ", " + str(immediate)
    
    if main_opcode == 0b001111: # LUI
        name = "lui"
        rt = get_bits(op_num, 16, 5)
        immediate = get_bits(op_num, 0, 16, signed=True)
        op_str = get_register(rt) + ", " + hex(immediate)
    
    if main_opcode == 0b110011: # PREF (Not the same as what goes in main_opcode_offset_clones.)
        name = main_opcode_offset_clones[main_opcode]
        base = get_bits(op_num, 21, 5)
        hint = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16, signed=True)
        op_str = str(hint) + ", " + (str(offset) if offset != 0 else "") + "(" + get_register(base) + ")"
    
    if main_opcode in main_opcode_offset_clones: # A bunch of instructions.
        name = main_opcode_offset_clones[main_opcode]
        base = get_bits(op_num, 21, 5)
        rt = get_bits(op_num, 16, 5)
        offset = get_bits(op_num, 0, 16, signed=True)
        op_str = get_register(rt) + ", " + (str(offset) if offset != 0 else "") + "(" + get_register(base) + ")"
        
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
            
        if insn.address >= 0x21FDE0 or (insn.address >= 0x1EDA80 and insn.address < 0x21A380) or (insn.address >= 0x186EA0 and insn.address < 0x186EB8): # Where code ends and data begins in Frogger TGQ. Also seems to be an area for VU code? It also just seems to have data too.
            print("\t .byte %s" %((', '.join('0x' + format(x, '02x').upper() for x in insn.bytes))))
        else:
            print(get_instruction_string(labels, insn))

main("/home/osboxes/Desktop/main.bin")

# if __name__ == "__main__":
#     args = parser.parse_args()
#     main(args.file)
