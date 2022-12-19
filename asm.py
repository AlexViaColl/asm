#!/usr/bin/env python3

import sys

REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
REGISTERS8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']

def fail(*s):
    print(*s, file=sys.stderr)
    exit(1)

def sign_extend(value, bits, unsigned=True):
    sign_bit = 1 << (bits - 1)
    if unsigned:
        return ((value & (sign_bit - 1)) - (value & sign_bit)) & (2**32-1)
    else:
        return (value & (sign_bit - 1)) - (value & sign_bit)

def modrm(x):
    mod     = (x & 0b11000000) >> 6
    reg_op  = (x & 0b00111000) >> 3
    rm      = (x & 0b00000111) >> 0
    return (mod, reg_op, rm)

def sib(x):
    scale = (x & 0b11000000) >> 6
    index = (x & 0b00111000) >> 3
    base  = (x & 0b00000111) >> 0
    return (scale, index, base)

def sib_str(scale, index, base):
    return f'{REGISTERS[base]}+{REGISTERS[index]}*{2**scale}'

def disassemble_ex_gx(raw, op, ptr_size, reg_size):
    mod, reg_op, rm = modrm(raw[1])
    #print(f'mod={mod}, reg_op={reg_op}, rm={rm}')
    if mod == 0b00:
        if rm <= 0b011 or rm == 0b110 or rm == 0b111:
            dst = f'{ptr_size} [{REGISTERS[rm]}]'
            src = f'{reg_size[reg_op]}'
            return f'{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}]'
            src = f'{reg_size[reg_op]}'
            return f'{op} {dst}, {src}'
        elif rm == 0b101:
            disp32 = int.from_bytes(raw[2:6], 'little')
            dst = f'{ptr_size} ds:{hex(disp32)}'
            src = f'{reg_size[reg_op]}'
            return f'{op} {dst}, {src}'
    elif mod == 0b01:
        if rm <= 0b011 or rm >= 0b101:
            disp = hex(sign_extend(raw[2], 8, unsigned=False))
            if disp.startswith('0x'):
                disp = f'+{disp}'
            dst = f'{ptr_size} [{REGISTERS[rm]}{disp}]'
            src = f'{reg_size[reg_op]}'
            return f'{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            disp = hex(sign_extend(raw[3], 8, unsigned=False))
            if disp.startswith('0x'):
                disp = f'+{disp}'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp}]'
            src = f'{reg_size[reg_op]}'
            return f'{op} {dst}, {src}'
    elif mod == 0b10:
        if rm <= 0b011 or rm >= 0b101:
            disp32 = hex(sign_extend(int.from_bytes(raw[2:6], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            dst = f'{ptr_size} [{REGISTERS[rm]}{disp32}]'
            src = f'{reg_size[reg_op]}'
            return f'{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            disp32 = hex(sign_extend(int.from_bytes(raw[3:7], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp32}]'
            src = f'{reg_size[reg_op]}'
            return f'{op} {dst}, {src}'
    elif mod == 0b11:
        dst = f'{reg_size[rm]}'
        src = f'{reg_size[reg_op]}'
        return f'{op} {dst}, {src}'

def disassemble_eb_gb(raw, op):
    return disassemble_ex_gx(raw, op, 'BYTE PTR', REGISTERS8)

def disassemble_ev_gv(raw, op):
    return disassemble_ex_gx(raw, op, 'DWORD PTR', REGISTERS)

def disassemble(raw):
    if len(raw) == 0:
        fail('ERROR: input was empty')

    opcode = raw[0]
    hi = (opcode & 0xF0) >> 4
    lo = (opcode & 0x0F) >> 0

    if hi == 0:
        if lo == 0:
            return disassemble_eb_gb(raw, 'ADD')
        elif lo == 1:
            return disassemble_ev_gv(raw, 'ADD') # TODO: Test
        elif lo == 4:
            return f'ADD al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'ADD eax, {hex(iz)}'
        elif lo == 6:
            return 'PUSH es'
        elif lo == 7:
            return 'POP es'
        elif lo == 0xc:
            return f'OR al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'OR eax, {hex(iz)}'
        elif lo == 0xe:
            return 'PUSH cs'
    elif hi == 1:
        if lo == 0:
            pass
        elif lo == 4:
            return f'ADC al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'ADC eax, {hex(iz)}'
        elif lo == 6:
            return 'PUSH ss'
        elif lo == 7:
            return 'POP ss'
        elif lo == 0xc:
            return f'SBB al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'SBB eax, {hex(iz)}'
        elif lo == 0xe:
            return 'PUSH ds'
        elif lo == 0xf:
            return 'POP ds'
    elif hi == 2:
        if lo == 0:
            pass
        elif lo == 4:
            return f'AND al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'AND eax, {hex(iz)}'
        elif lo == 7:
            return 'DAA'
        elif lo == 0xc:
            return f'SUB al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'SUB eax, {hex(iz)}'
        elif lo == 0xf:
            return 'DAS'
    elif hi == 3:
        if lo == 0:
            pass
        elif lo == 4:
            return f'XOR al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'XOR eax, {hex(iz)}'
        elif lo == 7:
            return 'AAA'
        elif lo == 0xc:
            return f'CMP al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'CMP eax, {hex(iz)}'
        elif lo == 0xf:
            return 'AAS'
    elif hi == 4:
        if lo <= 7:
            return f'INC {REGISTERS[lo]}'
        elif lo <= 0xf:
            return f'DEC {REGISTERS[lo-8]}'
    elif hi == 5:
        if lo <= 7:
            return f'PUSH {REGISTERS[lo]}'
        elif lo <= 0xf:
            return f'POP {REGISTERS[lo-8]}'
    elif hi == 6:
        if lo == 0:
            return 'PUSHA'
        elif lo == 1:
            return 'POPA'
        elif lo == 8:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'PUSH {hex(iz)}'
        elif lo == 0xa:
            ib = raw[1]
            ib = sign_extend(ib, 8)
            return f'PUSH {hex(ib)}'
    elif hi == 9:
        if lo == 0:
            return 'NOP'
        elif lo <= 7:
            return f'XCHG {REGISTERS[lo]}, eax'
        elif lo == 8:
            return 'CWDE'
        elif lo == 9:
            return 'CDQ'
        elif lo == 0xb:
            return 'FWAIT'
        elif lo == 0xc:
            return 'PUSHF'
        elif lo == 0xd:
            return 'POPF'
        elif lo == 0xe:
            return 'SAHF'
        elif lo == 0xf:
            return 'LAHF'
    elif hi == 0xa:
        if lo == 0:
            pass
        elif lo == 8:
            ib = raw[1]
            return f'TEST al, {hex(ib)}'
        elif lo == 9:
            iz = int.from_bytes(raw[1:5], 'little')
            return f'TEST eax, {hex(iz)}'
    elif hi == 0xb:
        if lo <= 7:
            return f'MOV {REGISTERS8[lo]}, {hex(raw[1])}'
        elif lo <= 0xf:
            iv = int.from_bytes(raw[1:5], 'little')
            return f'MOV {REGISTERS[lo-8]}, {hex(iv)}'
    elif hi == 0xc:
        if lo == 0:
            pass
        elif lo == 2:
            iw = int.from_bytes(raw[1:3], 'little')
            return f'RET {hex(iw)}'
        elif lo == 3:
            return 'RET'
        elif lo == 8:
            iw = int.from_bytes(raw[1:3], 'little')
            ib = raw[3]
            return f'ENTER {hex(iw)}, {hex(ib)}'
        elif lo == 9:
            return 'LEAVE'
        elif lo == 0xa:
            iw = int.from_bytes(raw[1:3], 'little')
            return f'RETF {hex(iw)}'
        elif lo == 0xb:
            return 'RETF'
        elif lo == 0xc:
            return 'INT3'
        elif lo == 0xd:
            return f'INT {hex(raw[1])}'
        elif lo == 0xe:
            return 'INTO'
        elif lo == 0xf:
            return 'IRET'
    elif opcode == 0xf1:
        return 'INT1'
    elif opcode == 0xf4:
        return 'HLT'
    elif opcode == 0xf5:
        return 'CMC'
    elif opcode == 0xf8:
        return 'CLC'
    elif opcode == 0xf9:
        return 'STC'
    elif opcode == 0xfa:
        return 'CLI'
    elif opcode == 0xfb:
        return 'STI'
    elif opcode == 0xfc:
        return 'CLD'
    elif opcode == 0xfd:
        return 'STD'
    else:
        fail(f'ERROR: Unknown opcode {hex(raw[0])}')

if __name__ == '__main__':
    raw = sys.stdin.buffer.read()
    print(disassemble(raw))
