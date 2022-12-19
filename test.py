#!/usr/bin/env python3

import subprocess
from operator import attrgetter

if __name__ == '__main__':
    instructions = {
        'ADD BYTE PTR [eax], al':   b'\x00\x00',
        'ADD BYTE PTR [ecx], al':   b'\x00\x01',
        'ADD BYTE PTR [edx], al':   b'\x00\x02',
        'ADD BYTE PTR [ebx], al':   b'\x00\x03',
        'ADD BYTE PTR [eax+eax*1], al': b'\x00\x04\x00',
        'ADD BYTE PTR [ecx+eax*1], al': b'\x00\x04\x01',
        'ADD BYTE PTR [edx+eax*1], al': b'\x00\x04\x02',
        'ADD BYTE PTR [ebx+eax*1], al': b'\x00\x04\x03',
        'ADD BYTE PTR [esp+eax*1], al': b'\x00\x04\x04',
        # b'\x00\x04\x05',
        'ADD BYTE PTR [esi+eax*1], al': b'\x00\x04\x06',
        'ADD BYTE PTR [edi+eax*1], al': b'\x00\x04\x07',
        'ADD BYTE PTR [eax+ecx*1], al': b'\x00\x04\x08',
        'ADD BYTE PTR [ecx+ecx*1], al': b'\x00\x04\x09',
        'ADD BYTE PTR [edx+ecx*1], al': b'\x00\x04\x0a',
        'ADD BYTE PTR [ebx+ecx*1], al': b'\x00\x04\x0b',
        'ADD BYTE PTR [esp+ecx*1], al': b'\x00\x04\x0c',
        # b'\x00\x04\x0d',
        'ADD BYTE PTR [esi+ecx*1], al': b'\x00\x04\x0e',
        'ADD BYTE PTR [edi+ecx*1], al': b'\x00\x04\x0f',

        'ADD BYTE PTR [eax+edx*1], al': b'\x00\x04\x10',
        'ADD BYTE PTR [ecx+edx*1], al': b'\x00\x04\x11',
        'ADD BYTE PTR [edx+edx*1], al': b'\x00\x04\x12',
        'ADD BYTE PTR [ebx+edx*1], al': b'\x00\x04\x13',
        'ADD BYTE PTR [esp+edx*1], al': b'\x00\x04\x14',
        # b'\x00\x04\x15',
        'ADD BYTE PTR [esi+edx*1], al': b'\x00\x04\x16',
        'ADD BYTE PTR [edi+edx*1], al': b'\x00\x04\x17',
        'ADD BYTE PTR [eax+ebx*1], al': b'\x00\x04\x18',
        'ADD BYTE PTR [ecx+ebx*1], al': b'\x00\x04\x19',
        'ADD BYTE PTR [edx+ebx*1], al': b'\x00\x04\x1a',
        'ADD BYTE PTR [ebx+ebx*1], al': b'\x00\x04\x1b',
        'ADD BYTE PTR [esp+ebx*1], al': b'\x00\x04\x1c',
        # b'\x00\x04\x1d',
        'ADD BYTE PTR [esi+ebx*1], al': b'\x00\x04\x1e',
        'ADD BYTE PTR [edi+ebx*1], al': b'\x00\x04\x1f',

        #'ADD BYTE PTR [eax+eiz*1], al': b'\x00\x04\x20',
        #'ADD BYTE PTR [ecx+eiz*1], al': b'\x00\x04\x21',
        #'ADD BYTE PTR [edx+eiz*1], al': b'\x00\x04\x22',
        #'ADD BYTE PTR [ebx+eiz*1], al': b'\x00\x04\x23',
        #'ADD BYTE PTR [esp], al':       b'\x00\x04\x24',
        # b'\x00\x04\x25',
        #'ADD BYTE PTR [esi+eiz*1], al': b'\x00\x04\x26',
        #'ADD BYTE PTR [edi+eiz*1], al': b'\x00\x04\x27',
        'ADD BYTE PTR [eax+ebp*1], al': b'\x00\x04\x28',
        'ADD BYTE PTR [ecx+ebp*1], al': b'\x00\x04\x29',
        'ADD BYTE PTR [edx+ebp*1], al': b'\x00\x04\x2a',
        'ADD BYTE PTR [ebx+ebp*1], al': b'\x00\x04\x2b',
        'ADD BYTE PTR [esp+ebp*1], al': b'\x00\x04\x2c',
        # b'\x00\x04\x2d',
        'ADD BYTE PTR [esi+ebp*1], al': b'\x00\x04\x2e',
        'ADD BYTE PTR [edi+ebp*1], al': b'\x00\x04\x2f',

        'ADD BYTE PTR [eax+esi*1], al': b'\x00\x04\x30',
        'ADD BYTE PTR [ecx+esi*1], al': b'\x00\x04\x31',
        'ADD BYTE PTR [edx+esi*1], al': b'\x00\x04\x32',
        'ADD BYTE PTR [ebx+esi*1], al': b'\x00\x04\x33',
        'ADD BYTE PTR [esp+esi*1], al': b'\x00\x04\x34',
        # b'\x00\x04\x35',
        'ADD BYTE PTR [esi+esi*1], al': b'\x00\x04\x36',
        'ADD BYTE PTR [edi+esi*1], al': b'\x00\x04\x37',
        'ADD BYTE PTR [eax+edi*1], al': b'\x00\x04\x38',
        'ADD BYTE PTR [ecx+edi*1], al': b'\x00\x04\x39',
        'ADD BYTE PTR [edx+edi*1], al': b'\x00\x04\x3a',
        'ADD BYTE PTR [ebx+edi*1], al': b'\x00\x04\x3b',
        'ADD BYTE PTR [esp+edi*1], al': b'\x00\x04\x3c',
        # b'\x00\x04\x3d',
        'ADD BYTE PTR [esi+edi*1], al': b'\x00\x04\x3e',
        'ADD BYTE PTR [edi+edi*1], al': b'\x00\x04\x3f',

        'ADD BYTE PTR [eax+eax*2], al': b'\x00\x04\x40',

        'ADD BYTE PTR [eax+eax*4], al': b'\x00\x04\x80',

        'ADD BYTE PTR [eax+eax*8], al': b'\x00\x04\xc0',

        'ADD BYTE PTR [edi+ecx*8], al': b'\x00\x04\xcf',
        'ADD BYTE PTR [edi+edi*8], al': b'\x00\x04\xff',

        'ADD BYTE PTR ds:0x0, al':          b'\x00\x05\x00\x00\x00\x00',
        'ADD BYTE PTR ds:0xffffffff, al':   b'\x00\x05\xff\xff\xff\xff',

        'ADD BYTE PTR [esi], al':           b'\x00\x06',
        'ADD BYTE PTR [edi], al':           b'\x00\x07',
        'ADD BYTE PTR [eax], cl':           b'\x00\x08',
        'ADD BYTE PTR [ecx], cl':           b'\x00\x09',
        'ADD BYTE PTR [edx], cl':           b'\x00\x0a',
        'ADD BYTE PTR [ebx], cl':           b'\x00\x0b',
        'ADD BYTE PTR [eax+eax*1], cl':     b'\x00\x0c\x00',
        'ADD BYTE PTR [edi+edi*8], cl':     b'\x00\x0c\xff',
        'ADD BYTE PTR ds:0x0, cl':          b'\x00\x0d\x00\x00\x00\x00',
        'ADD BYTE PTR ds:0xffffffff, cl':   b'\x00\x0d\xff\xff\xff\xff',

        'ADD BYTE PTR [esi], cl':           b'\x00\x0e',
        'ADD BYTE PTR [edi], cl':           b'\x00\x0f',
        'ADD BYTE PTR [eax], dl':           b'\x00\x10',
        'ADD BYTE PTR [edi], dl':           b'\x00\x17',
        'ADD BYTE PTR [eax], bl':           b'\x00\x18',
        'ADD BYTE PTR [edi], bl':           b'\x00\x1f',
        'ADD BYTE PTR [eax], ah':           b'\x00\x20',
        'ADD BYTE PTR [edi], ah':           b'\x00\x27',
        'ADD BYTE PTR [eax], ch':           b'\x00\x28',
        'ADD BYTE PTR [edi], ch':           b'\x00\x2f',
        'ADD BYTE PTR [eax], dh':           b'\x00\x30',
        'ADD BYTE PTR [edi], dh':           b'\x00\x37',
        'ADD BYTE PTR [eax], bh':           b'\x00\x38',
        'ADD BYTE PTR [edi], bh':           b'\x00\x3f',

        'ADD BYTE PTR [eax+0x0], al':       b'\x00\x40\x00',
        'ADD BYTE PTR [eax-0x1], al':       b'\x00\x40\xff',
        'ADD BYTE PTR [ecx+0x0], al':       b'\x00\x41\x00',
        'ADD BYTE PTR [edx+0x0], al':       b'\x00\x42\x00',
        'ADD BYTE PTR [ebx+0x0], al':       b'\x00\x43\x00',

        'ADD BYTE PTR [eax+eax*1+0x0], al': b'\x00\x44\x00\x00',
        'ADD BYTE PTR [edi+edi*8-0x1], al': b'\x00\x44\xff\xff',

        'ADD BYTE PTR [ebp+0x0], al':       b'\x00\x45\x00',
        'ADD BYTE PTR [esi+0x0], al':       b'\x00\x46\x00',
        'ADD BYTE PTR [edi+0x0], al':       b'\x00\x47\x00',
        'ADD BYTE PTR [eax+0x0], cl':       b'\x00\x48\x00',
        'ADD BYTE PTR [edi-0x1], cl':       b'\x00\x4f\xff',
        'ADD BYTE PTR [eax+0x0], dl':       b'\x00\x50\x00',
        'ADD BYTE PTR [edi-0x1], dl':       b'\x00\x57\xff',
        'ADD BYTE PTR [eax+0x0], bl':       b'\x00\x58\x00',

        'ADD BYTE PTR [edi-0x1], bh':       b'\x00\x7f\xff',

        'ADD BYTE PTR [eax+0x0], al':       b'\x00\x80\x00\x00\x00\x00',
        'ADD BYTE PTR [eax+0x7fffffff], al':b'\x00\x80\xff\xff\xff\x7f',
        'ADD BYTE PTR [eax-0x80000000], al':b'\x00\x80\x00\x00\x00\x80',
        'ADD BYTE PTR [eax-0x1], al':       b'\x00\x80\xff\xff\xff\xff',

        'ADD BYTE PTR [ecx+0x0], al':       b'\x00\x81\x00\x00\x00\x00',
        'ADD BYTE PTR [edx+0x0], al':       b'\x00\x82\x00\x00\x00\x00',
        'ADD BYTE PTR [ebx+0x0], al':       b'\x00\x83\x00\x00\x00\x00',
        'ADD BYTE PTR [eax+eax*1+0x0], al': b'\x00\x84\x00\x00\x00\x00\x00',
        'ADD BYTE PTR [edi+edi*8-0x1], al': b'\x00\x84\xff\xff\xff\xff\xff',
        'ADD BYTE PTR [ebp+0x0], al':       b'\x00\x85\x00\x00\x00\x00',
        'ADD BYTE PTR [esi+0x0], al':       b'\x00\x86\x00\x00\x00\x00',
        'ADD BYTE PTR [edi+0x0], al':       b'\x00\x87\x00\x00\x00\x00',
        'ADD BYTE PTR [eax+0x0], cl':       b'\x00\x88\x00\x00\x00\x00',

        'ADD al, al':                       b'\x00\xc0',
        'ADD cl, al':                       b'\x00\xc1',
        'ADD bh, bh':                       b'\x00\xff',

        'ADD eax, eax':                     b'\x01\xc0',
        'ADD al, al':                       b'\x02\xc0',
        'ADD eax, eax':                     b'\x03\xc0',

        'ADD al, 0x0':          b'\x04\x00',
        'ADD al, 0x7f':         b'\x04\x7f',
        'ADD al, 0x80':         b'\x04\x80',
        'ADD al, 0xff':         b'\x04\xff',
        'ADD eax, 0x0':         b'\x05\x00\x00\x00\x00',
        'ADD eax, 0x7fffffff':  b'\x05\xff\xff\xff\x7f',
        'ADD eax, 0x80000000':  b'\x05\x00\x00\x00\x80',
        'ADD eax, 0xffffffff':  b'\x05\xff\xff\xff\xff',
        'PUSH es':              b'\x06',
        'POP es':               b'\x07',
        'OR al, al':            b'\x08\xc0',
        'OR eax, eax':          b'\x09\xc0',
        'OR al, al':            b'\x0a\xc0',
        'OR eax, eax':          b'\x0b\xc0',
        'OR al, 0x0':           b'\x0c\x00',
        'OR al, 0x7f':          b'\x0c\x7f',
        'OR al, 0x80':          b'\x0c\x80',
        'OR al, 0xff':          b'\x0c\xff',
        'OR eax, 0x0':          b'\x0d\x00\x00\x00\x00',
        'OR eax, 0x7fffffff':   b'\x0d\xff\xff\xff\x7f',
        'OR eax, 0x80000000':   b'\x0d\x00\x00\x00\x80',
        'OR eax, 0xffffffff':   b'\x0d\xff\xff\xff\xff',
        'PUSH cs':              b'\x0e',
        'ADC al, al':           b'\x10\xc0',
        'ADC eax, eax':         b'\x11\xc0',
        'ADC al, al':           b'\x12\xc0',
        'ADC eax, eax':         b'\x13\xc0',
        'ADC al, 0x0':          b'\x14\x00',
        'ADC al, 0x7f':         b'\x14\x7f',
        'ADC al, 0x80':         b'\x14\x80',
        'ADC al, 0xff':         b'\x14\xff',
        'ADC eax, 0x0':         b'\x15\x00\x00\x00\x00',
        'ADC eax, 0x7fffffff':  b'\x15\xff\xff\xff\x7f',
        'ADC eax, 0x80000000':  b'\x15\x00\x00\x00\x80',
        'ADC eax, 0xffffffff':  b'\x15\xff\xff\xff\xff',
        'PUSH ss':              b'\x16',
        'POP ss':               b'\x17',
        'SBB al, al':           b'\x18\xc0',
        'SBB eax, eax':         b'\x19\xc0',
        'SBB al, al':           b'\x1a\xc0',
        'SBB eax, eax':         b'\x1b\xc0',
        'SBB al, 0x0':          b'\x1c\x00',
        'SBB al, 0x7f':         b'\x1c\x7f',
        'SBB al, 0x80':         b'\x1c\x80',
        'SBB al, 0xff':         b'\x1c\xff',
        'SBB eax, 0x0':         b'\x1d\x00\x00\x00\x00',
        'SBB eax, 0x7fffffff':  b'\x1d\xff\xff\xff\x7f',
        'SBB eax, 0x80000000':  b'\x1d\x00\x00\x00\x80',
        'SBB eax, 0xffffffff':  b'\x1d\xff\xff\xff\xff',
        'PUSH ds':              b'\x1e',
        'POP ds':               b'\x1f',
        'AND al, al':           b'\x20\xc0',
        'AND eax, eax':         b'\x21\xc0',
        'AND al, al':           b'\x22\xc0',
        'AND eax, eax':         b'\x23\xc0',
        'AND al, 0x0':          b'\x24\x00',
        'AND al, 0x7f':         b'\x24\x7f',
        'AND al, 0x80':         b'\x24\x80',
        'AND al, 0xff':         b'\x24\xff',
        'AND eax, 0x0':         b'\x25\x00\x00\x00\x00',
        'AND eax, 0x7fffffff':  b'\x25\xff\xff\xff\x7f',
        'AND eax, 0x80000000':  b'\x25\x00\x00\x00\x80',
        'AND eax, 0xffffffff':  b'\x25\xff\xff\xff\xff',
        'ADD BYTE PTR es:[eax+0x0], al': b'\x26\x00\x40\x00',
        'DAA':                  b'\x27',
        'SUB al, al':           b'\x28\xc0',
        'SUB eax, eax':         b'\x29\xc0',
        'SUB al, al':           b'\x2a\xc0',
        'SUB eax, eax':         b'\x2b\xc0',
        'SUB al, 0x0':          b'\x2c\x00',
        'SUB al, 0x7f':         b'\x2c\x7f',
        'SUB al, 0x80':         b'\x2c\x80',
        'SUB al, 0xff':         b'\x2c\xff',
        'SUB eax, 0x0':         b'\x2d\x00\x00\x00\x00',
        'SUB eax, 0x7fffffff':  b'\x2d\xff\xff\xff\x7f',
        'SUB eax, 0x80000000':  b'\x2d\x00\x00\x00\x80',
        'SUB eax, 0xffffffff':  b'\x2d\xff\xff\xff\xff',
        'ADD BYTE PTR cs:[eax+0x0], al': b'\x2e\x00\x40\x00',
        'DAS':                  b'\x2f',
        'XOR al, al':           b'\x30\xc0',
        'XOR eax, eax':         b'\x31\xc0',
        'XOR al, al':           b'\x32\xc0',
        'XOR eax, eax':         b'\x33\xc0',
        'XOR al, 0x0':          b'\x34\x00',
        'XOR al, 0x7f':         b'\x34\x7f',
        'XOR al, 0x80':         b'\x34\x80',
        'XOR al, 0xff':         b'\x34\xff',
        'XOR eax, 0x0':         b'\x35\x00\x00\x00\x00',
        'XOR eax, 0x7fffffff':  b'\x35\xff\xff\xff\x7f',
        'XOR eax, 0x80000000':  b'\x35\x00\x00\x00\x80',
        'XOR eax, 0xffffffff':  b'\x35\xff\xff\xff\xff',
        'ADD BYTE PTR ss:[eax+0x0], al': b'\x36\x00\x40\x00',
        'AAA':                  b'\x37',
        'CMP al, al':           b'\x38\xc0',
        'CMP eax, eax':         b'\x39\xc0',
        'CMP al, al':           b'\x3a\xc0',
        'CMP eax, eax':         b'\x3b\xc0',
        'CMP al, 0x0':          b'\x3c\x00',
        'CMP al, 0x7f':         b'\x3c\x7f',
        'CMP al, 0x80':         b'\x3c\x80',
        'CMP al, 0xff':         b'\x3c\xff',
        'CMP eax, 0x0':         b'\x3d\x00\x00\x00\x00',
        'CMP eax, 0x7fffffff':  b'\x3d\xff\xff\xff\x7f',
        'CMP eax, 0x80000000':  b'\x3d\x00\x00\x00\x80',
        'CMP eax, 0xffffffff':  b'\x3d\xff\xff\xff\xff',
        'ADD BYTE PTR ds:[eax+0x0], al': b'\x3e\x00\x40\x00',
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
        'ADD BYTE PTR fs:[eax+0x0], al': b'\x64\x00\x40\x00',
        'ADD BYTE PTR gs:[eax+0x0], al': b'\x65\x00\x40\x00',
        'PUSH 0x0':             b'\x68\x00\x00\x00\x00',
        'PUSH 0x7fffffff':      b'\x68\xff\xff\xff\x7f',
        'PUSH 0x80000000':      b'\x68\x00\x00\x00\x80',
        'PUSH 0xffffffff':      b'\x68\xff\xff\xff\xff',
        'PUSH 0x0':             b'\x6a\x00',
        'PUSH 0x7f':            b'\x6a\x7f',
        'PUSH 0xffffff80':      b'\x6a\x80',
        'PUSH 0xffffffff':      b'\x6a\xff',
        'JO 0x2':               b'\x70\x00',
        'JNO 0x2':              b'\x71\x00',
        'JB 0x2':               b'\x72\x00',
        'JNB 0x2':              b'\x73\x00',
        'JE 0x2':               b'\x74\x00',
        'JNE 0x2':              b'\x75\x00',
        'JBE 0x2':              b'\x76\x00',
        'JNBE 0x2':             b'\x77\x00',
        'JS 0x2':               b'\x78\x00',
        'JNS 0x2':              b'\x79\x00',
        'JP 0x2':               b'\x7a\x00',
        'JNP 0x2':              b'\x7b\x00',
        'JL 0x2':               b'\x7c\x00',
        'JNL 0x2':              b'\x7d\x00',
        'JLE 0x2':              b'\x7e\x00',
        'JNLE 0x2':             b'\x7f\x00',
        'ADD BYTE PTR [eax], 0x0': b'\x80\x00\x00',
        'ADD BYTE PTR [eax+eax*1], 0x0': b'\x80\x04\x00\x00',
        'OR BYTE PTR [eax+eax*1], 0x0':  b'\x80\x0c\x00\x00',
        'ADC BYTE PTR [eax+eax*1], 0x0': b'\x80\x14\x00\x00',
        'SBB BYTE PTR [eax+eax*1], 0x0': b'\x80\x1c\x00\x00',
        'AND BYTE PTR [eax+eax*1], 0x0': b'\x80\x24\x00\x00',
        'SUB BYTE PTR [eax+eax*1], 0x0': b'\x80\x2c\x00\x00',
        'XOR BYTE PTR [eax+eax*1], 0x0': b'\x80\x34\x00\x00',
        'CMP BYTE PTR [eax+eax*1], 0x0': b'\x80\x3c\x00\x00',

        'ADD DWORD PTR [eax+eax*1], 0x0': b'\x81\x04\x00\x00\x00\x00\x00',
        'OR DWORD PTR [eax+eax*1], 0x0':  b'\x81\x0c\x00\x00\x00\x00\x00',
        'ADC DWORD PTR [eax+eax*1], 0x0': b'\x81\x14\x00\x00\x00\x00\x00',
        'SBB DWORD PTR [eax+eax*1], 0x0': b'\x81\x1c\x00\x00\x00\x00\x00',
        'AND DWORD PTR [eax+eax*1], 0x0': b'\x81\x24\x00\x00\x00\x00\x00',
        'SUB DWORD PTR [eax+eax*1], 0x0': b'\x81\x2c\x00\x00\x00\x00\x00',
        'XOR DWORD PTR [eax+eax*1], 0x0': b'\x81\x34\x00\x00\x00\x00\x00',
        'CMP DWORD PTR [eax+eax*1], 0x0': b'\x81\x3c\x00\x00\x00\x00\x00',

        'ADD BYTE PTR [eax+eax*1], 0x0': b'\x82\x04\x00\x00',
        'OR BYTE PTR [eax+eax*1], 0x0':  b'\x82\x0c\x00\x00',
        'ADC BYTE PTR [eax+eax*1], 0x0': b'\x82\x14\x00\x00',
        'SBB BYTE PTR [eax+eax*1], 0x0': b'\x82\x1c\x00\x00',
        'AND BYTE PTR [eax+eax*1], 0x0': b'\x82\x24\x00\x00',
        'SUB BYTE PTR [eax+eax*1], 0x0': b'\x82\x2c\x00\x00',
        'XOR BYTE PTR [eax+eax*1], 0x0': b'\x82\x34\x00\x00',
        'CMP BYTE PTR [eax+eax*1], 0x0': b'\x82\x3c\x00\x00',
        'TEST al, al':          b'\x84\xc0',
        'TEST eax, eax':        b'\x85\xc0',
        'XCHG al, al':          b'\x86\xc0',
        'XCHG eax, eax':        b'\x87\xc0',
        'MOV al, al':           b'\x88\xc0',
        'MOV eax, eax':         b'\x89\xc0',
        'MOV al, al':           b'\x8a\xc0',
        'MOV eax, eax':         b'\x8b\xc0',
        'POP DWORD PTR [eax]':  b'\x8f\x00',
        'POP DWORD PTR [ecx]':  b'\x8f\x01',
        'POP DWORD PTR [edx]':  b'\x8f\x02',
        'POP DWORD PTR [ebx]':  b'\x8f\x03',
        'POP DWORD PTR [eax+eax*1]': b'\x8f\x04\x00',
        'POP DWORD PTR ds:0x0': b'\x8f\x05\x00\x00\x00\x00',
        'POP DWORD PTR [eax+0x0]': b'\x8f\x40\x00',
        'POP eax':              b'\x8f\xc0',
        'POP edi':              b'\x8f\xc7',
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
        'CALL 0x1234:0x7f000000': b'\x9a\x00\x00\x00\x7f\x34\x12',
        'FWAIT':                b'\x9b',
        'PUSHF':                b'\x9c',
        'POPF':                 b'\x9d',
        'SAHF':                 b'\x9e',
        'LAHF':                 b'\x9f',
        'MOV al, ds:0x0':           b'\xa0\x00\x00\x00\x00',
        'MOV al, ds:0x7fffffff':    b'\xa0\xff\xff\xff\x7f',
        'MOV al, ds:0x80000000':    b'\xa0\x00\x00\x00\x80',
        'MOV al, ds:0xffffffff':    b'\xa0\xff\xff\xff\xff',
        'MOV eax, ds:0x0':          b'\xa1\x00\x00\x00\x00',
        'MOV eax, ds:0x7fffffff':   b'\xa1\xff\xff\xff\x7f',
        'MOV eax, ds:0x80000000':   b'\xa1\x00\x00\x00\x80',
        'MOV eax, ds:0xffffffff':   b'\xa1\xff\xff\xff\xff',
        'MOV ds:0x0, al':           b'\xa2\x00\x00\x00\x00',
        'MOV ds:0x7fffffff, al':    b'\xa2\xff\xff\xff\x7f',
        'MOV ds:0x80000000, al':    b'\xa2\x00\x00\x00\x80',
        'MOV ds:0xffffffff, al':    b'\xa2\xff\xff\xff\xff',
        'MOV ds:0x0, eax':          b'\xa3\x00\x00\x00\x00',
        'MOV ds:0x7fffffff, eax':   b'\xa3\xff\xff\xff\x7f',
        'MOV ds:0x80000000, eax':   b'\xa3\x00\x00\x00\x80',
        'MOV ds:0xffffffff, eax':   b'\xa3\xff\xff\xff\xff',
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
        'INC BYTE PTR [eax]':  b'\xfe\x00',
        'INC BYTE PTR [ecx]':  b'\xfe\x01',
        'INC BYTE PTR [edx]':  b'\xfe\x02',
        'INC BYTE PTR [ebx]':  b'\xfe\x03',
        'INC BYTE PTR [eax+eax*1]': b'\xfe\x04\x00',
        'INC DWORD PTR [eax]':  b'\xff\x00',
        'INC DWORD PTR [ecx]':  b'\xff\x01',
        'INC DWORD PTR [edx]':  b'\xff\x02',
        'INC DWORD PTR [ebx]':  b'\xff\x03',
        'INC DWORD PTR [eax+eax*1]': b'\xff\x04\x00',
        'DEC DWORD PTR [eax]':  b'\xff\x08',
        'DEC DWORD PTR [ecx]':  b'\xff\x09',
        'DEC DWORD PTR [edx]':  b'\xff\x0a',
        'DEC DWORD PTR [ebx]':  b'\xff\x0b',
        'DEC DWORD PTR [eax+eax*1]': b'\xff\x0c\x00',
        # TODO: CALL, far CALL, JMP, far JMP
        'PUSH DWORD PTR [eax]':  b'\xff\x30',
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

