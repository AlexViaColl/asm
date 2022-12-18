#!/usr/bin/env python3

import subprocess
from operator import attrgetter

if __name__ == '__main__':
    instructions = {
        'PUSH ES':  b'\x06',
        'POP ES':   b'\x07',
        'PUSH CS':  b'\x0e',
        'PUSH SS':  b'\x16',
        'POP SS':   b'\x17',
        'PUSH DS':  b'\x1e',
        'POP DS':   b'\x1f',
        'DAA':      b'\x27',
        'DAS':      b'\x2f',
        'AAA':      b'\x37',
        'AAS':      b'\x3f',
        'INC eax':  b'\x40',
        'INC ecx':  b'\x41',
        'INC edx':  b'\x42',
        'INC ebx':  b'\x43',
        'INC esp':  b'\x44',
        'INC ebp':  b'\x45',
        'INC esi':  b'\x46',
        'INC edi':  b'\x47',
        'DEC eax':  b'\x48',
        'DEC ecx':  b'\x49',
        'DEC edx':  b'\x4a',
        'DEC ebx':  b'\x4b',
        'DEC esp':  b'\x4c',
        'DEC ebp':  b'\x4d',
        'DEC esi':  b'\x4e',
        'DEC edi':  b'\x4f',
        'PUSH eax': b'\x50',
        'PUSH ecx': b'\x51',
        'PUSH edx': b'\x52',
        'PUSH ebx': b'\x53',
        'PUSH esp': b'\x54',
        'PUSH ebp': b'\x55',
        'PUSH esi': b'\x56',
        'PUSH edi': b'\x57',
        'POP edi':  b'\x57',
        'POP eax':  b'\x58',
        'POP ecx':  b'\x59',
        'POP edx':  b'\x5a',
        'POP ebx':  b'\x5b',
        'POP esp':  b'\x5c',
        'POP ebp':  b'\x5d',
        'POP esi':  b'\x5e',
        'POP edi':  b'\x5f',
        'PUSHA':    b'\x60',
        'POPA':     b'\x61',
        'NOP':      b'\x90',
        'FWAIT':    b'\x9b',
        'SAHF':     b'\x9e',
        'LAHF':     b'\x9f',
        'RET':      b'\xc3',
        'LEAVE':    b'\xc9',
        'RETF':     b'\xcb',
        'INT3':     b'\xcc',
        'INTO':     b'\xce',
        'IRET':     b'\xcf',
        'INT1':     b'\xf1',
        'HLT':      b'\xf4',
        'CMC':      b'\xf5',
        'CLC':      b'\xf8',
        'STC':      b'\xf9',
        'CLI':      b'\xfa',
        'STI':      b'\xfb',
        'CLD':      b'\xfc',
        'STD':      b'\xfd',
    }
    for inst in instructions:
        raw = instructions[inst]
        res = subprocess.run('./asm.py', input=raw, capture_output=True)
        ret, stdout, stderr = attrgetter('returncode', 'stdout', 'stderr')(res)
        if ret != 0:
            print(f'[ERROR] asm.py failed with error code: {ret}, sderr: {stderr.decode().strip()}')
        elif stdout.decode().strip() != inst:
            print(f'[ERROR] Unexpected disassembly for bytes: {raw.hex(" ")}')
            print(f'  Expected: {inst}')
            print(f'  But got:  {stdout.decode().strip()}')

