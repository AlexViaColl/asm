#!/usr/bin/env python3

import sys

def fail(*s):
    print(*s, file=sys.stderr)
    exit(1)

if __name__ == '__main__':
    raw = sys.stdin.buffer.read()
    if len(raw) == 0:
        fail('ERROR: input was empty')

    if raw[0] == 0x06:
        print('PUSH ES')
    elif raw[0] == 0x07:
        print('POP ES')
    elif raw[0] == 0x0e:
        print('PUSH CS')
    elif raw[0] == 0x16:
        print('PUSH SS')
    elif raw[0] == 0x17:
        print('POP SS')
    elif raw[0] == 0x1e:
        print('PUSH DS')
    elif raw[0] == 0x1f:
        print('POP DS')
    elif raw[0] == 0x27:
        print('DAA')
    elif raw[0] == 0x2f:
        print('DAS')
    elif raw[0] == 0x90:
        print('NOP')
    elif raw[0] == 0xc3:
        print('RET')
    elif raw[0] == 0xcc:
        print('INT3')
    elif raw[0] == 0xf4:
        print('HLT')
    else:
        fail(f'ERROR: Unknown opcode {hex(raw[0])}')
