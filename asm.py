#!/usr/bin/env python3

import sys
from struct import pack
from typing import NamedTuple
from dataclasses import dataclass

VERSION = '0.0.1'
USAGE = '''
Usage: asm [OPTION]...
        -v, --version   Print version information
        -h, --help      Display this information
'''

REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
REGISTERS16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
REGISTERS8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']
SEGMENTS = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', '?', '?']
REGISTERSXMM = ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']
REGISTERSMM = ['mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7']

def fail(*s):
    print(*s, file=sys.stderr)
    exit(1)

@dataclass
class Token:
    token_type: str
    value: str

def ident(s):
    return Token('ident', s)

def literal(s):
    return Token('literal', s)

def symbol(s):
    return Token('symbol', s)

def tokenize(line):
    line = line.strip()
    i = 0
    tokens = []
    curr_token = None
    while i < len(line):
        c = line[i]
        if c == ' ' or c == '\t' or c == '\n' or c == '\r':
            if curr_token != None:
                tokens.append(curr_token)
                curr_token = None
        elif c in '[](),:+-*;#':
            if curr_token != None:
                tokens.append(curr_token)
                curr_token = None
            tokens.append(Token('symbol', c))
        # Number literals
        elif (c >= '0' and c <= '9'):
            if curr_token == None:
                curr_token = Token('literal', c)
            else:
                curr_token.value += c
        # Identifiers
        elif (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '?':
            if curr_token == None:
                curr_token = Token('ident', c)
            else:
                curr_token.value += c

        i += 1
    if curr_token != None:
        tokens.append(curr_token)
    return tokens

class Inst(NamedTuple):
    opcode: str
    operands: list = []
    prefixes: list = []



if __name__ == '__main__':
    #state = {'eip': 191, 'seg': '', 'prefix': ''}
    #print(disassemble(b'\xf6\x45\xd0\x01', state))
    #sys.exit(0)

    show_version = False
    show_usage = False
    base = 0
    skip = 0
    asm_path = None
    if len(sys.argv) > 1:
        args = sys.argv[1:]
        for i, arg in enumerate(args):
            if arg == '-v' or arg == '--version':
                show_version = True
            elif arg == '-h' or arg == '--help':
                show_usage = True
            elif (arg == '-b' or arg == '--base') and len(args) > i:
                base = args[i+1]
                if base.startswith('0x'):
                    base = int(base, base=16)
                elif base.startswith('0b'):
                    base = int(base, base=2)
                else:
                    base = int(base)
            elif (arg == '-s' or arg == '--skip') and len(args) > i:
                skip = args[i+1]
                if skip.startswith('0x'):
                    skip = int(skip, base=16)
                elif skip.startswith('0b'):
                    skip = int(skip, base=2)
                else:
                    skip = int(skip)
            elif (arg == '-a' or arg == '--assemble') and len(args) > i+1:
                asm_path = args[i+1]

    if show_version:
        print(f'asm version {VERSION}')
        sys.exit(0)
    elif show_usage:
        print(USAGE)
        sys.exit(0)

    if asm_path != None:
        with open(asm_path) as f:
            contents = f.read()
        lines = contents.splitlines()
        buf = b''
        state = {}
        for line in lines:
            if line.strip() != '':
                buf += assemble(line, state)
        print(buf.hex(" "))
        sys.exit(0)

    raw = sys.stdin.buffer.read()
    state = {'eip': skip, 'base': skip}
    while state['eip'] != len(raw):
        start = state['eip']
        code = raw[start:]
        state['seg'] = ''
        state['prefix'] = ''
        state['op_size'] = ''
        state['addr_size'] = ''
        #print(code[:8])
        inst = disassemble(code, state)
        end = state['eip']
        if start == end:
            print(code[:8].hex(' '))
            end += 1
        print(f'{base+start:08x}: {raw[start:end].hex(" ") : <30}', end='')
        print(inst)
        #print(state)
