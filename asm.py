#!/usr/bin/env python3

import sys

REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
REGISTERS8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']

def fail(*s):
    print(*s, file=sys.stderr)
    exit(1)

def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return ((value & (sign_bit - 1)) - (value & sign_bit)) & (2**32-1)

def disassemble(raw):
    if len(raw) == 0:
        fail('ERROR: input was empty')

    opcode = raw[0]
    hi = (opcode & 0xF0) >> 4
    lo = (opcode & 0x0F) >> 0

    if hi == 0:
        if lo == 0:
            pass
        elif lo == 4:
            return f'ADD al, {hex(raw[1])}'
        elif lo == 6:
            return 'PUSH es'
        elif lo == 7:
            return 'POP es'
        elif lo == 0xc:
            return f'OR al, {hex(raw[1])}'
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
