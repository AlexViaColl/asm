#!/usr/bin/env python3

import subprocess
from operator import attrgetter

if __name__ == '__main__':
    instructions = {
        'PUSH ES':  b'\x06',
        'NOP':      b'\x90',
        'RET':      b'\xc3',
        'INT3':     b'\xcc',
        'HLT':      b'\xf4',
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

