#!/usr/bin/env python3

import sys

REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

def fail(*s):
    print(*s, file=sys.stderr)
    exit(1)

def disassemble(raw):
    if len(raw) == 0:
        fail('ERROR: input was empty')

    opcode = raw[0]
    hi = (opcode & 0xF0) >> 4
    lo = (opcode & 0x0F) >> 0

    if opcode == 0x06:
        return 'PUSH ES'
    elif opcode == 0x07:
        return 'POP ES'
    elif opcode == 0x0e:
        return 'PUSH CS'
    elif opcode == 0x16:
        return 'PUSH SS'
    elif opcode == 0x17:
        return 'POP SS'
    elif opcode == 0x1e:
        return 'PUSH DS'
    elif opcode == 0x1f:
        return 'POP DS'
    elif opcode == 0x27:
        return 'DAA'
    elif opcode == 0x2f:
        return 'DAS'
    elif opcode == 0x37:
        return 'AAA'
    elif opcode == 0x3f:
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
    elif opcode == 0x60:
        return 'PUSHA'
    elif opcode == 0x61:
        return 'POPA'
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
