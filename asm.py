#!/usr/bin/env python3

import sys

REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

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
            return f'ADD AL, {hex(raw[1])}'
        elif lo == 6:
            return 'PUSH ES'
        elif lo == 7:
            return 'POP ES'
        elif lo == 0xc:
            return f'OR AL, {hex(raw[1])}'
        elif lo == 0xe:
            return 'PUSH CS'
    elif hi == 1:
        if lo == 0:
            pass
        elif lo == 4:
            return f'ADC AL, {hex(raw[1])}'
        elif lo == 6:
            return 'PUSH SS'
        elif lo == 7:
            return 'POP SS'
        elif lo == 0xc:
            return f'SBB AL, {hex(raw[1])}'
        elif lo == 0xe:
            return 'PUSH DS'
        elif lo == 0xf:
            return 'POP DS'
    elif hi == 2:
        if lo == 0:
            pass
        elif lo == 4:
            return f'AND AL, {hex(raw[1])}'
        elif lo == 7:
            return 'DAA'
        elif lo == 0xc:
            return f'SUB AL, {hex(raw[1])}'
        elif lo == 0xf:
            return 'DAS'
    elif hi == 3:
        if lo == 0:
            pass
        elif lo == 4:
            return f'XOR AL, {hex(raw[1])}'
        elif lo == 7:
            return 'AAA'
        elif lo == 0xc:
            return f'CMP AL, {hex(raw[1])}'
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
        elif lo == 0xa:
            ib = raw[1]
            ib = sign_extend(ib, 8)
            return f'PUSH {hex(ib)}'
    elif hi == 9:
        if lo == 0:
            return 'NOP'
        elif lo <= 7:
            return f'XCHG {REGISTERS[lo]}, eax'
        elif lo == 0xb:
            return 'FWAIT'
        elif lo == 0xe:
            return 'SAHF'
        elif lo == 0xf:
            return 'LAHF'
    elif hi == 0xa:
        if lo == 8:
            ib = raw[1]
            return f'TEST AL, {hex(ib)}'
    elif hi == 0xb:
        if lo == 0:
            return f'MOV AL, {hex(raw[1])}'
        elif lo == 1:
            return f'MOV CL, {hex(raw[1])}'
        elif lo == 2:
            return f'MOV DL, {hex(raw[1])}'
        elif lo == 3:
            return f'MOV BL, {hex(raw[1])}'
        elif lo == 4:
            return f'MOV AH, {hex(raw[1])}'
    elif hi == 0xc:
        if lo == 3:
            return 'RET'
        elif lo == 9:
            return 'LEAVE'
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
