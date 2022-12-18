#!/usr/bin/env python3

import sys

def fail(*s):
    print(*s, file=sys.stderr)
    exit(1)

def disassemble(raw):
    if len(raw) == 0:
        fail('ERROR: input was empty')

    if raw[0] == 0x06:
        return 'PUSH ES'
    elif raw[0] == 0x07:
        return 'POP ES'
    elif raw[0] == 0x0e:
        return 'PUSH CS'
    elif raw[0] == 0x16:
        return 'PUSH SS'
    elif raw[0] == 0x17:
        return 'POP SS'
    elif raw[0] == 0x1e:
        return 'PUSH DS'
    elif raw[0] == 0x1f:
        return 'POP DS'
    elif raw[0] == 0x27:
        return 'DAA'
    elif raw[0] == 0x2f:
        return 'DAS'
    elif raw[0] == 0x37:
        return 'AAA'
    elif raw[0] == 0x3f:
        return 'AAS'
    elif raw[0] == 0x60:
        return 'PUSHA'
    elif raw[0] == 0x61:
        return 'POPA'
    elif raw[0] == 0x90:
        return 'NOP'
    elif raw[0] == 0x9b:
        return 'FWAIT'
    elif raw[0] == 0x9e:
        return 'SAHF'
    elif raw[0] == 0x9f:
        return 'LAHF'
    elif raw[0] == 0xc3:
        return 'RET'
    elif raw[0] == 0xc9:
        return 'LEAVE'
    elif raw[0] == 0xcb:
        return 'RETF'
    elif raw[0] == 0xcc:
        return 'INT3'
    elif raw[0] == 0xce:
        return 'INTO'
    elif raw[0] == 0xcf:
        return 'IRET'
    elif raw[0] == 0xf1:
        return 'INT1'
    elif raw[0] == 0xf4:
        return 'HLT'
    elif raw[0] == 0xf5:
        return 'CMC'
    elif raw[0] == 0xf8:
        return 'CLC'
    elif raw[0] == 0xf9:
        return 'STC'
    elif raw[0] == 0xfa:
        return 'CLI'
    elif raw[0] == 0xfb:
        return 'STI'
    elif raw[0] == 0xfc:
        return 'CLD'
    elif raw[0] == 0xfd:
        return 'STD'
    else:
        fail(f'ERROR: Unknown opcode {hex(raw[0])}')

if __name__ == '__main__':
    raw = sys.stdin.buffer.read()
    print(disassemble(raw))
