#!/usr/bin/env python3

import subprocess
from operator import attrgetter

if __name__ == '__main__':
    instructions = {
        'ADD al, 0x0':          b'\x04\x00',
        'ADD al, 0x7f':         b'\x04\x7f',
        'ADD al, 0x80':         b'\x04\x80',
        'ADD al, 0xff':         b'\x04\xff',
        'PUSH es':              b'\x06',
        'POP es':               b'\x07',
        'OR al, 0x0':           b'\x0c\x00',
        'OR al, 0x7f':          b'\x0c\x7f',
        'OR al, 0x80':          b'\x0c\x80',
        'OR al, 0xff':          b'\x0c\xff',
        'PUSH cs':              b'\x0e',
        'ADC al, 0x0':          b'\x14\x00',
        'ADC al, 0x7f':         b'\x14\x7f',
        'ADC al, 0x80':         b'\x14\x80',
        'ADC al, 0xff':         b'\x14\xff',
        'PUSH ss':              b'\x16',
        'POP ss':               b'\x17',
        'SBB al, 0x0':          b'\x1c\x00',
        'SBB al, 0x7f':         b'\x1c\x7f',
        'SBB al, 0x80':         b'\x1c\x80',
        'SBB al, 0xff':         b'\x1c\xff',
        'PUSH ds':              b'\x1e',
        'POP ds':               b'\x1f',
        'AND al, 0x0':          b'\x24\x00',
        'AND al, 0x7f':         b'\x24\x7f',
        'AND al, 0x80':         b'\x24\x80',
        'AND al, 0xff':         b'\x24\xff',
        'DAA':                  b'\x27',
        'SUB al, 0x0':          b'\x2c\x00',
        'SUB al, 0x7f':         b'\x2c\x7f',
        'SUB al, 0x80':         b'\x2c\x80',
        'SUB al, 0xff':         b'\x2c\xff',
        'DAS':                  b'\x2f',
        'XOR al, 0x0':          b'\x34\x00',
        'XOR al, 0x7f':         b'\x34\x7f',
        'XOR al, 0x80':         b'\x34\x80',
        'XOR al, 0xff':         b'\x34\xff',
        'AAA':                  b'\x37',
        'CMP al, 0x0':          b'\x3c\x00',
        'CMP al, 0x7f':         b'\x3c\x7f',
        'CMP al, 0x80':         b'\x3c\x80',
        'CMP al, 0xff':         b'\x3c\xff',
        'AAS':                  b'\x3f',
        'INC eax':              b'\x40',
        'INC ecx':              b'\x41',
        'INC edx':              b'\x42',
        'INC ebx':              b'\x43',
        'INC esp':              b'\x44',
        'INC ebp':              b'\x45',
        'INC esi':              b'\x46',
        'INC edi':              b'\x47',
        'DEC eax':              b'\x48',
        'DEC ecx':              b'\x49',
        'DEC edx':              b'\x4a',
        'DEC ebx':              b'\x4b',
        'DEC esp':              b'\x4c',
        'DEC ebp':              b'\x4d',
        'DEC esi':              b'\x4e',
        'DEC edi':              b'\x4f',
        'PUSH eax':             b'\x50',
        'PUSH ecx':             b'\x51',
        'PUSH edx':             b'\x52',
        'PUSH ebx':             b'\x53',
        'PUSH esp':             b'\x54',
        'PUSH ebp':             b'\x55',
        'PUSH esi':             b'\x56',
        'PUSH edi':             b'\x57',
        'POP edi':              b'\x57',
        'POP eax':              b'\x58',
        'POP ecx':              b'\x59',
        'POP edx':              b'\x5a',
        'POP ebx':              b'\x5b',
        'POP esp':              b'\x5c',
        'POP ebp':              b'\x5d',
        'POP esi':              b'\x5e',
        'POP edi':              b'\x5f',
        'PUSHA':                b'\x60',
        'POPA':                 b'\x61',
        'PUSH 0x0':             b'\x68\x00\x00\x00\x00',
        'PUSH 0x7fffffff':      b'\x68\xff\xff\xff\x7f',
        'PUSH 0x80000000':      b'\x68\x00\x00\x00\x80',
        'PUSH 0xffffffff':      b'\x68\xff\xff\xff\xff',
        'PUSH 0x0':             b'\x6a\x00',
        'PUSH 0x7f':            b'\x6a\x7f',
        'PUSH 0xffffff80':      b'\x6a\x80',
        'PUSH 0xffffffff':      b'\x6a\xff',
        'NOP':                  b'\x90',
        'XCHG ecx, eax':        b'\x91',
        'XCHG edx, eax':        b'\x92',
        'XCHG ebx, eax':        b'\x93',
        'XCHG esp, eax':        b'\x94',
        'XCHG ebp, eax':        b'\x95',
        'XCHG esi, eax':        b'\x96',
        'XCHG edi, eax':        b'\x97',
        'CWDE':                 b'\x98',
        'CDQ':                  b'\x99',
        'FWAIT':                b'\x9b',
        'PUSHF':                b'\x9c',
        'POPF':                 b'\x9d',
        'SAHF':                 b'\x9e',
        'LAHF':                 b'\x9f',
        'TEST al, 0x0':         b'\xa8\x00',
        'TEST al, 0x7f':        b'\xa8\x7f',
        'TEST al, 0x80':        b'\xa8\x80',
        'TEST al, 0xff':        b'\xa8\xff',
        'TEST eax, 0x0':        b'\xa9\x00\x00\x00\x00',
        'TEST eax, 0x7fffffff': b'\xa9\xff\xff\xff\x7f',
        'TEST eax, 0x80000000': b'\xa9\x00\x00\x00\x80',
        'TEST eax, 0xffffffff': b'\xa9\xff\xff\xff\xff',
        'MOV al, 0x0':          b'\xb0\x00',
        'MOV al, 0x7f':         b'\xb0\x7f',
        'MOV al, 0x80':         b'\xb0\x80',
        'MOV al, 0xff':         b'\xb0\xff',
        'MOV cl, 0x0':          b'\xb1\x00',
        'MOV cl, 0x7f':         b'\xb1\x7f',
        'MOV cl, 0x80':         b'\xb1\x80',
        'MOV cl, 0xff':         b'\xb1\xff',
        'MOV dl, 0x0':          b'\xb2\x00',
        'MOV dl, 0x7f':         b'\xb2\x7f',
        'MOV dl, 0x80':         b'\xb2\x80',
        'MOV dl, 0xff':         b'\xb2\xff',
        'MOV bl, 0x0':          b'\xb3\x00',
        'MOV bl, 0x7f':         b'\xb3\x7f',
        'MOV bl, 0x80':         b'\xb3\x80',
        'MOV bl, 0xff':         b'\xb3\xff',
        'MOV ah, 0x0':          b'\xb4\x00',
        'MOV ah, 0x7f':         b'\xb4\x7f',
        'MOV ah, 0x80':         b'\xb4\x80',
        'MOV ah, 0xff':         b'\xb4\xff',
        'MOV ch, 0x0':          b'\xb5\x00',
        'MOV ch, 0x7f':         b'\xb5\x7f',
        'MOV ch, 0x80':         b'\xb5\x80',
        'MOV ch, 0xff':         b'\xb5\xff',
        'MOV dh, 0x0':          b'\xb6\x00',
        'MOV dh, 0x7f':         b'\xb6\x7f',
        'MOV dh, 0x80':         b'\xb6\x80',
        'MOV dh, 0xff':         b'\xb6\xff',
        'MOV bh, 0x0':          b'\xb7\x00',
        'MOV bh, 0x7f':         b'\xb7\x7f',
        'MOV bh, 0x80':         b'\xb7\x80',
        'MOV bh, 0xff':         b'\xb7\xff',
        'MOV eax, 0x0':         b'\xb8\x00\x00\x00\x00',
        'MOV eax, 0x7fffffff':  b'\xb8\xff\xff\xff\x7f',
        'MOV eax, 0x80000000':  b'\xb8\x00\x00\x00\x80',
        'MOV eax, 0xffffffff':  b'\xb8\xff\xff\xff\xff',
        'MOV ecx, 0x0':         b'\xb9\x00\x00\x00\x00',
        'MOV ecx, 0x7fffffff':  b'\xb9\xff\xff\xff\x7f',
        'MOV ecx, 0x80000000':  b'\xb9\x00\x00\x00\x80',
        'MOV ecx, 0xffffffff':  b'\xb9\xff\xff\xff\xff',
        'MOV edx, 0x0':         b'\xba\x00\x00\x00\x00',
        'MOV edx, 0x7fffffff':  b'\xba\xff\xff\xff\x7f',
        'MOV edx, 0x80000000':  b'\xba\x00\x00\x00\x80',
        'MOV edx, 0xffffffff':  b'\xba\xff\xff\xff\xff',
        'MOV ebx, 0x0':         b'\xbb\x00\x00\x00\x00',
        'MOV ebx, 0x7fffffff':  b'\xbb\xff\xff\xff\x7f',
        'MOV ebx, 0x80000000':  b'\xbb\x00\x00\x00\x80',
        'MOV ebx, 0xffffffff':  b'\xbb\xff\xff\xff\xff',
        'MOV esp, 0x0':         b'\xbc\x00\x00\x00\x00',
        'MOV esp, 0x7fffffff':  b'\xbc\xff\xff\xff\x7f',
        'MOV esp, 0x80000000':  b'\xbc\x00\x00\x00\x80',
        'MOV esp, 0xffffffff':  b'\xbc\xff\xff\xff\xff',
        'MOV ebp, 0x0':         b'\xbd\x00\x00\x00\x00',
        'MOV ebp, 0x7fffffff':  b'\xbd\xff\xff\xff\x7f',
        'MOV ebp, 0x80000000':  b'\xbd\x00\x00\x00\x80',
        'MOV ebp, 0xffffffff':  b'\xbd\xff\xff\xff\xff',
        'MOV esi, 0x0':         b'\xbe\x00\x00\x00\x00',
        'MOV esi, 0x7fffffff':  b'\xbe\xff\xff\xff\x7f',
        'MOV esi, 0x80000000':  b'\xbe\x00\x00\x00\x80',
        'MOV esi, 0xffffffff':  b'\xbe\xff\xff\xff\xff',
        'MOV edi, 0x0':         b'\xbf\x00\x00\x00\x00',
        'MOV edi, 0x7fffffff':  b'\xbf\xff\xff\xff\x7f',
        'MOV edi, 0x80000000':  b'\xbf\x00\x00\x00\x80',
        'MOV edi, 0xffffffff':  b'\xbf\xff\xff\xff\xff',
        'RET 0x0':              b'\xc2\x00\x00',
        'RET 0x7fff':           b'\xc2\xff\x7f',
        'RET 0x8000':           b'\xc2\x00\x80',
        'RET 0xffff':           b'\xc2\xff\xff',
        'RET':                  b'\xc3',
        'ENTER 0x0, 0x0':       b'\xc8\x00\x00\x00',
        'ENTER 0x7fff, 0x0':    b'\xc8\xff\x7f\x00',
        'ENTER 0x8000, 0x0':    b'\xc8\x00\x80\x00',
        'ENTER 0xffff, 0x0':    b'\xc8\xff\xff\x00',
        'ENTER 0x0, 0xff':      b'\xc8\x00\x00\xff',
        'ENTER 0x7fff, 0xff':   b'\xc8\xff\x7f\xff',
        'ENTER 0x8000, 0xff':   b'\xc8\x00\x80\xff',
        'ENTER 0xffff, 0xff':   b'\xc8\xff\xff\xff',
        'LEAVE':                b'\xc9',
        'RETF 0x0':             b'\xca\x00\x00',
        'RETF 0x7fff':          b'\xca\xff\x7f',
        'RETF 0x8000':          b'\xca\x00\x80',
        'RETF 0xffff':          b'\xca\xff\xff',
        'RETF':                 b'\xcb',
        'INT3':                 b'\xcc',
        'INT 0x0':              b'\xcd\x00',
        'INT 0xff':             b'\xcd\xff',
        'INTO':                 b'\xce',
        'IRET':                 b'\xcf',
        'INT1':                 b'\xf1',
        'HLT':                  b'\xf4',
        'CMC':                  b'\xf5',
        'CLC':                  b'\xf8',
        'STC':                  b'\xf9',
        'CLI':                  b'\xfa',
        'STI':                  b'\xfb',
        'CLD':                  b'\xfc',
        'STD':                  b'\xfd',
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

