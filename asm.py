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

def sign_extend(value, bits, unsigned=True):
    sign_bit = 1 << (bits - 1)
    if unsigned:
        return ((value & (sign_bit - 1)) - (value & sign_bit)) & (2**32-1)
    else:
        return (value & (sign_bit - 1)) - (value & sign_bit)

def modrm(x):
    mod     = (x & 0b11000000) >> 6
    reg_op  = (x & 0b00111000) >> 3
    rm      = (x & 0b00000111) >> 0
    return (mod, reg_op, rm)

def sib(x):
    scale = (x & 0b11000000) >> 6
    index = (x & 0b00111000) >> 3
    base  = (x & 0b00000111) >> 0
    return (scale, index, base)

def sib_str(scale, index, base):
    if base == None:
        return f'{REGISTERS[index]}*{2**scale}'

    if index == 0b100:
        return f'{REGISTERS[base]}'
    else:
        return f'{REGISTERS[base]}+{REGISTERS[index]}*{2**scale}'

def get_regs(s, state):
    if 'op_size' in state and state['op_size'] == 1:
        return REGISTERS16
    return {
        'b': REGISTERS8,
        'w': REGISTERS16,
        'v': REGISTERS,
        'q': REGISTERSMM,
        'p': REGISTERSXMM,
    }[s]

def get_ptr(s, state):
    if 'op_size' in state and state['op_size'] == 1:
        return 'WORD PTR'
    return {
        'b': 'BYTE PTR',
        'w': 'WORD PTR',
        'v': 'DWORD PTR',
        'q': 'QWORD PTR',
        'p': 'XMMWORD PTR',
    }[s]

def get_imm(raw, i, state):
    if 'op_size' in state and state['op_size'] == 1:
        state['eip'] += 2
        return hex(int.from_bytes(raw[:2], 'little'))
    end = {'v': 4, 'z': 4, 'w': 2, 'b': 1}[i]
    state['eip'] += end
    return hex(int.from_bytes(raw[:end], 'little'))

def modrm_op(raw, op, state):
    mod, reg, rm = modrm(raw[0])
    if op[0] == 'E' or op[0] == 'W' or op[0] == 'Q' or op[0] == 'M':
        if mod == 0b00:
            if rm != 0b100 and rm != 0b101:
                return f'{get_ptr(op[1], state)} [{get_regs("v", state)[rm]}]'
            elif rm == 0b100:
                scale, idx, base = sib(raw[1])
                state['eip'] += 1
                disp = ''
                if base == 0b101:
                    base = None
                    disp = hex(int.from_bytes(raw[2:6], 'little'))
                    if disp.startswith('0x'):
                        disp = f'+{disp}'
                    state['eip'] += 4
                return f'{get_ptr(op[1], state)} [{sib_str(scale, idx, base)}{disp}]'
            elif rm == 0b101:
                disp32 = int.from_bytes(raw[1:5], 'little')
                state['eip'] += 4
                return f'{get_ptr(op[1], state)} ds:{hex(disp32)}'
        elif mod == 0b01:
            if rm != 0b100:
                disp = hex(sign_extend(raw[1], 8, unsigned=False))
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                state['eip'] += 1
                return f'{get_ptr(op[1], state)} {state["seg"]}[{get_regs("v", state)[rm]}{disp}]'
            elif rm == 0b100:
                scale, idx, base = sib(raw[1])
                state['eip'] += 1
                disp = hex(sign_extend(raw[2], 8, unsigned=False))
                state['eip'] += 1
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                return f'{get_ptr(op[1], state)} [{sib_str(scale, idx, base)}{disp}]'
        elif mod == 0b10:
            if rm != 0b100:
                disp = hex(sign_extend(int.from_bytes(raw[1:5], 'little'), 32, unsigned=False))
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                state['eip'] += 4
                return f'{get_ptr(op[1], state)} [{get_regs("v", state)[rm]}{disp}]'
            elif rm == 0b100:
                scale, idx, base = sib(raw[1])
                state['eip'] += 1
                disp = hex(sign_extend(int.from_bytes(raw[2:6], 'little'), 32, unsigned=False))
                state['eip'] += 4
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                return f'{get_ptr(op[1], state)} [{sib_str(scale, idx, base)}{disp}]'
        elif mod == 0b11:
            return get_regs(op[1], state)[rm]
    elif op[0] == 'G' or op[0] == 'P':
        return get_regs(op[1], state)[reg]
    elif op[0] == 'V':
        return REGISTERSXMM[reg]

def modrm_dst_src(raw, dst, src, state):
    mod, reg_op, rm = modrm(raw[0])
    state['eip'] += 1
    dst = modrm_op(raw, dst, state) # eax
    src = modrm_op(raw, src, state) # BYTE PTR [ebp-0x4]
    return f'{dst}, {src}'

def dis_modrm_dst_src(raw, op, dst, src, state):
    state['eip'] += 1
    addr = modrm_dst_src(raw[1:], dst, src, state)
    return f'{op} {addr}'

def dis_modrm_dst_ib(raw, op, dst, state):
    state['eip'] += 1
    addr = modrm_op(raw[1:], dst, state)
    imm8 = get_imm(raw[2:], 'b', state)
    state['eip'] += 1
    return f'{op} {addr}, {imm8}'

def dis_con_modrm_dst_src(raw, op, dst, src, state):
    start = state['eip']
    inst = dis_modrm_dst_src(raw, op, dst, src, state)
    return inst, state['eip'] - start

def modrm_addressing(m, rest, state, reg_size=32):
    mod, reg_op, rm = modrm(m)
    if mod == 0b00:
        if rm <= 0b011 or rm >= 0b110:
            return f'[{REGISTERS[rm]}]'
        elif rm == 0b100:
            scale, idx, base = sib(rest[0])
            disp = ''
            if base == 0b101:
                disp32 = int.from_bytes(rest[1:5], 'little')
                disp = f'+{hex(disp32)}'
                base = None
                state['eip'] += 4
            state['eip'] += 1
            return f'[{sib_str(scale, idx, base)}{disp}]'
        elif rm == 0b101:
            disp32 = int.from_bytes(rest[0:4], 'little')
            state['eip'] += 4
            return f'ds:{hex(disp32)}'
    elif mod == 0b01:
        if rm <= 0b011 or rm >= 0b101:
            disp8 = hex(sign_extend(rest[0], 8, unsigned=False))
            if disp8.startswith('0x'):
                disp8 = f'+{disp8}'
            state['eip'] += 1
            return f'[{REGISTERS[rm]}{disp8}]'
        elif rm == 0b100:
            scale, idx, base = sib(rest[0])
            disp8 = hex(sign_extend(rest[1], 8, unsigned=False))
            if disp8.startswith('0x'):
                disp8 = f'+{disp8}'
            state['eip'] += 2
            return f'[{sib_str(scale, idx, base)}{disp8}]'
    elif mod == 0b10:
        if rm <= 0b011 or rm >= 0b101:
            disp32 = hex(sign_extend(int.from_bytes(rest[0:4], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            state['eip'] += 4
            return f'[{REGISTERS[rm]}{disp32}]'
        elif rm == 0b100:
            scale, idx, base = sib(rest[0])
            disp32 = hex(sign_extend(int.from_bytes(rest[1:5], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            state['eip'] += 5
            return f'[{sib_str(scale, idx, base)}{disp32}]'
    elif mod == 0b11:
        regs = {
            8:  REGISTERS8,
            16: REGISTERS16,
            32: REGISTERS,
        }[reg_size]
        return regs[rm]

def disassemble_ex_gx(raw, op, ptr_size, reg_size, state, swap=False):
    seg = state['seg']
    prefix = state['prefix']
    mod, reg_op, rm = modrm(raw[1])
    #print(f'mod={mod}, reg_op={reg_op}, rm={rm}')
    if mod == 0b00:
        if rm <= 0b011 or rm == 0b110 or rm == 0b111:
            dst = f'{ptr_size} [{REGISTERS[rm]}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 2
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            disp = ''
            if base == 0b101:
                disp32 = int.from_bytes(raw[3:7], 'little')
                disp = f'+{hex(disp32)}'
                base = None
                state['eip'] += 4
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 3
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b101:
            disp32 = int.from_bytes(raw[2:6], 'little')
            dst = f'{ptr_size} ds:{hex(disp32)}'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 6
            return f'{prefix}{op} {dst}, {src}'
    elif mod == 0b01:
        if rm <= 0b011 or rm >= 0b101:
            disp = hex(sign_extend(raw[2], 8, unsigned=False))
            if disp.startswith('0x'):
                disp = f'+{disp}'
            dst = f'{ptr_size} {seg}[{REGISTERS[rm]}{disp}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 3
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            disp = hex(sign_extend(raw[3], 8, unsigned=False))
            if disp.startswith('0x'):
                disp = f'+{disp}'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 4
            return f'{prefix}{op} {dst}, {src}'
    elif mod == 0b10:
        if rm <= 0b011 or rm >= 0b101:
            disp32 = hex(sign_extend(int.from_bytes(raw[2:6], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            dst = f'{ptr_size} [{REGISTERS[rm]}{disp32}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 6
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                disp32 = int.from_bytes(raw[3:7], 'little')
                disp = f'+{hex(disp32)}'
            disp32 = hex(sign_extend(int.from_bytes(raw[3:7], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp32}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 7
            return f'{prefix}{op} {dst}, {src}'
    elif mod == 0b11:
        dst = f'{reg_size[rm]}'
        src = f'{reg_size[reg_op]}'
        if swap:
            dst,src = src,dst
        state['eip'] += 2
        return f'{prefix}{op} {dst}, {src}'

def disassemble_ex_ix(raw, op, ptr_size, reg_size, state):
    seg = state['seg']
    prefix = state['prefix']
    mod, reg_op, rm = modrm(raw[1])
    if mod == 0b00:
        if rm <= 0b011 or rm == 0b110 or rm == 0b111:
            dst = f'{ptr_size} [{REGISTERS[rm]}]'
            src = f'{hex(raw[2])}'
            state['eip'] += 3
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}]'
            src = f'{hex(raw[3])}'
            state['eip'] += 4
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b101:
            disp32 = int.from_bytes(raw[2:6], 'little')
            dst = f'{ptr_size} ds:{hex(disp32)}'
            src = f'{hex(raw[6])}'
            state['eip'] += 7
            return f'{prefix}{op} {dst}, {src}'
    elif mod == 0b01:
        if rm <= 0b011 or rm >= 0b101:
            disp = hex(sign_extend(raw[2], 8, unsigned=False))
            if disp.startswith('0x'):
                disp = f'+{disp}'
            dst = f'{ptr_size} {seg}[{REGISTERS[rm]}{disp}]'
            src = f'{hex(raw[3])}'
            state['eip'] += 4
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            disp = hex(sign_extend(raw[3], 8, unsigned=False))
            if disp.startswith('0x'):
                disp = f'+{disp}'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp}]'
            src = f'{hex(raw[4])}'
            state['eip'] += 5
            return f'{prefix}{op} {dst}, {src}'
    elif mod == 0b10:
        if rm <= 0b011 or rm >= 0b101:
            disp32 = hex(sign_extend(int.from_bytes(raw[2:6], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            dst = f'{ptr_size} [{REGISTERS[rm]}{disp32}]'
            src = f'{hex(raw[6])}'
            state['eip'] += 7
            return f'{prefix}{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            disp = ''
            disp32 = hex(sign_extend(int.from_bytes(raw[3:7], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp32}]'
            src = f'{hex(raw[7])}'
            state['eip'] += 8
            return f'{prefix}{op} {dst}, {src}'
    elif mod == 0b11:
        dst = f'{reg_size[rm]}'
        src = f'{hex(raw[2])}'
        state['eip'] += 3
        return f'{prefix}{op} {dst}, {src}'

def disassemble_eb_gb(raw, op, state):
    return disassemble_ex_gx(raw, op, 'BYTE PTR', REGISTERS8, state)

def disassemble_ew_gw(raw, op, state):
    return disassemble_ex_gx(raw, op, 'WORD PTR', REGISTERS16, state)

def disassemble_ev_gv(raw, op, state):
    return disassemble_ex_gx(raw, op, 'DWORD PTR', REGISTERS, state)

def disassemble_gb_eb(raw, op, state):
    return disassemble_ex_gx(raw, op, 'BYTE PTR', REGISTERS8, state, swap=True)

def disassemble_gw_ew(raw, op, state):
    return disassemble_ex_gx(raw, op, 'WORD PTR', REGISTERS16, state, swap=True)

def disassemble_gv_eb(raw, op, state):
    return disassemble_ex_gx(raw, op, 'DWORD PTR', REGISTERS8, state, swap=True)

def disassemble_gv_ew(raw, op, state):
    return disassemble_ex_gx(raw, op, 'WORD PTR', REGISTERS, state, swap=True)

def disassemble_gv_ev(raw, op, state):
    return disassemble_ex_gx(raw, op, 'DWORD PTR', REGISTERS, state, swap=True)

def disassemble_eb_ib(raw, op, state):
    return disassemble_ex_ix(raw, op, 'BYTE PTR', REGISTERS8, state)

def disassemble_ev_iv(raw, op, state):
    return disassemble_ex_ix(raw, op, 'DWORD PTR', REGISTERS, state)

def disassemble_2b(raw, state):
    opcode = raw[0]
    hi = (opcode & 0xF0) >> 4
    lo = (opcode & 0x0F) >> 0

    if hi == 0:
        if lo == 0:
            pass
        elif lo == 1:
            state['eip'] += 2
            return f'SGDTD [ecx]'
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'LAR', 'Gv', 'Ew', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'LSL', 'Gv', 'Ew', state)
        elif lo == 4:
            pass
        elif lo == 5:
            state['eip'] += 1
            return f'SYSCALL'
        elif lo == 6:
            state['eip'] += 1
            return f'CLTS'
        elif lo == 7:
            state['eip'] += 1
            return f'SYSRET'
        elif lo == 8:
            state['eip'] += 1
            return f'INVD'
        elif lo == 9:
            state['eip'] += 1
            return f'WBINVD'
        elif lo == 0xd:
            state['eip'] += 2
            op = modrm_op(raw[1:], 'Ev', state)
            return f'PREFETCHW {op}'.replace('DWORD', 'BYTE')
        elif lo == 0xe:
            state['eip'] += 1
            return f'FEMMS'
        elif lo == 0xf:
            mod, reg_op, rm = modrm(raw[1])
            inst, c = dis_con_modrm_dst_src(raw, 'XXX', 'Pq', 'Wq', state)
            suffix = {
                0x0d: 'PI2FD',
                0x1d: 'PF2ID',
                0x8a: 'PFNACC',
                0x8e: 'PFPNACC',
                0x90: 'PFCMPGE',
                0x94: 'PFMIN',
                0x96: 'PFRCP',
                0x97: 'PFRSQRT',
                0x9a: 'PFSUB',
                0x9e: 'PFADD',
                0xa0: 'PFCMPGT',
                0xa4: 'PFMAX',
                0xa6: 'PFRCPIT1',
                0xa7: 'PFRSQIT1',
                0xaa: 'PFSUBR',
                0xae: 'PFACC',
                0xb0: 'PFCMPEQ',
                0xb4: 'PFMUL',
                0xb6: 'PFRCPIT2',
                0xb7: 'PMULHRW',
                0xbb: 'PSWAPD',
                0xbf: 'PAVGUSB',
            }
            if len(raw) <= c or raw[c] not in suffix:
                state['eip'] -= 2
                return '(bad)'
            state['eip'] += 1
            return inst.replace('XXX', suffix[raw[c]])
    elif hi == 1:
        if lo == 0:
            state['eip'] += 2
            return f'MOVUPS xmm2, XMMWORD PTR [ecx]'
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'MOVUPS', 'Wps', 'Vps', state)
        elif lo == 2:
            state['eip'] += 2
            return f'MOVLPS xmm1, QWORD PTR [eax]'
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'MOVLPS', 'Mq', 'Vq', state)
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'UNPCKLPS', 'Vps', 'Wps', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'UNPCKHPS', 'Vps', 'Wps', state)
        elif lo == 6:
            state['eip'] += 2
            return f'MOVHPS xmm1, QWORD PTR [ecx]'
        elif lo == 7:
            return dis_modrm_dst_src(raw, 'MOVHPS', 'Mq', 'Vq', state)
        elif lo == 8:
            state['eip'] += 3
            return f'reserved NOP'
    elif hi == 2:
        if lo == 0:
            pass
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'MOVAPS', 'Vps', 'Wps', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'MOVAPS', 'Wps', 'Vps', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'CVTPI2PS', 'Vps', 'Qq', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'MOVNTPS', 'Mp', 'Vps', state)
        elif lo == 0xc:
            return dis_modrm_dst_src(raw, 'CVTTPS2PI', 'Pq', 'Wps', state)
        elif lo == 0xd:
            return dis_modrm_dst_src(raw, 'CVTPS2PI', 'Pq', 'Wps', state)
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'UCOMISS', 'Vps', 'Wps', state)
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'COMISS', 'Vps', 'Wps', state)
    elif hi == 3:
        if lo == 0:
            state['eip'] += 1
            return f'WRMSR'
        elif lo == 1:
            state['eip'] += 1
            return f'RDTSC'
        elif lo == 2:
            state['eip'] += 1
            return f'RDMSR'
        elif lo == 3:
            state['eip'] += 1
            return f'RDPMC'
        elif lo == 4:
            state['eip'] += 1
            return f'SYSENTER'
        elif lo == 5:
            state['eip'] += 1
            return f'SYSEXIT'
        elif lo == 7:
            state['eip'] += 1
            return f'GETSEC'
    elif hi == 4:
        inst = [
            'CMOVO', 'CMOVNO', 'CMOVB', 'CMOVAE', 'CMOVE', 'CMOVNE', 'CMOVBE', 'CMOVA',
            'CMOVS', 'CMOVNS', 'CMOVP', 'CMOVNP', 'CMOVL', 'CMOVGE', 'CMOVLE', 'CMOVG',
        ][lo]
        return dis_modrm_dst_src(raw, inst, 'Gv', 'Ev', state)
    elif hi == 5:
        if lo == 0:
            return dis_modrm_dst_src(raw, 'MOVMSKPS', 'Gv', 'Wps', state)
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'SQRTPS', 'Vps', 'Wps', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'RSQRTPS', 'Vps', 'Wps', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'RCPPS', 'Vps', 'Wps', state)
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'ANDPS', 'Vps', 'Wps', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'ANDNPS', 'Vps', 'Wps', state)
        elif lo == 6:
            return dis_modrm_dst_src(raw, 'ORPS', 'Vps', 'Wps', state)
        elif lo == 7:
            return dis_modrm_dst_src(raw, 'XORPS', 'Vps', 'Wps', state)
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'ADDPS', 'Vps', 'Wps', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'MULPS', 'Vps', 'Wps', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'CVTPS2PD', 'Vps', 'Wps', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'CVTDQ2PS', 'Vps', 'Wps', state)
        elif lo == 0xc:
            return dis_modrm_dst_src(raw, 'SUBPS', 'Vps', 'Wps', state)
        elif lo == 0xd:
            return dis_modrm_dst_src(raw, 'MINPS', 'Vps', 'Wps', state)
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'DIVPS', 'Vps', 'Wps', state)
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'MAXPS', 'Vps', 'Wps', state)
    elif hi == 6:
        if lo == 0:
            return dis_modrm_dst_src(raw, 'PUNPCKLBW', 'Pq', 'Wq', state)
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'PUNPCKLWD', 'Pq', 'Wq', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'PUNPCKLDQ', 'Pq', 'Wq', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'PACKSSWB', 'Pq', 'Wq', state)
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'PCMPGTB', 'Pq', 'Wq', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'PCMPGTW', 'Pq', 'Wq', state)
        elif lo == 6:
            return dis_modrm_dst_src(raw, 'PCMPGTD', 'Pq', 'Wq', state)
        elif lo == 7:
            return dis_modrm_dst_src(raw, 'PACKUSWB', 'Pq', 'Wq', state)
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'PUNPCKHBW', 'Pq', 'Wq', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'PUNPCKHWD', 'Pq', 'Wq', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'PUNPCKHDQ ', 'Pq', 'Wq', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'PACKSSDW', 'Pq', 'Wq', state)
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'MOVD', 'Pq', 'Qv', state)
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'MOVQ', 'Pq', 'Qq', state)
    elif hi == 7:
        if lo == 0:
            pass
        elif lo == 1:
            return dis_modrm_dst_ib(raw, 'PSRLW', 'Wq', state)
        elif lo == 2:
            return dis_modrm_dst_ib(raw, 'PSLLD', 'Wq', state)
        elif lo == 3:
            return dis_modrm_dst_ib(raw, 'PSLLQ', 'Wq', state)
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'PCMPEQB', 'Pq', 'Qq', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'PCMPEQW', 'Pq', 'Qq', state)
        elif lo == 6:
            return dis_modrm_dst_src(raw, 'PCMPEQD', 'Pq', 'Qq', state)
        elif lo == 7:
            state['eip'] += 1
            return 'EMMS'
        elif lo == 0xb:
            state['eip'] += 1
            return '(bad)'
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'MOVD', 'Ev', 'Pq', state)
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'MOVQ', 'Qq', 'Pq', state)
    elif hi == 8:
        jmp_type = [
            'JO', 'JNO', 'JB', 'JNB', 'JE', 'JNE', 'JBE', 'JNBE',
            'JS', 'JNS', 'JP', 'JNP', 'JL', 'JNL', 'JLE', 'JNLE',
        ][lo]
        rel32 = int.from_bytes(raw[1:5], 'little')
        state['eip'] += 5
        addr = state['eip'] + rel32
        return f'{jmp_type} {hex(addr)}'
    elif hi == 9:
        set_type = [
            'SETO', 'SETNO', 'SETB', 'SETNB', 'SETE', 'SETNE', 'SETBE', 'SETNBE',
            'SETS', 'SETNS', 'SETP', 'SETNP', 'SETL', 'SETNL', 'SETLE', 'SETNLE',
        ][lo]
        addr = modrm_addressing(raw[1], raw[2:], state, 8)
        state['eip'] += 2
        return f'{set_type} {addr}'
    elif hi == 0xa:
        if lo == 0:
            state['eip'] += 1
            return f'PUSH fs'
        elif lo == 1:
            state['eip'] += 1
            return f'POP fs'
        elif lo == 2:
            state['eip'] += 1
            return f'CPUID'
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'BT', 'Ev', 'Gv', state)
        elif lo == 4:
            state['eip'] += 1
            addr = modrm_dst_src(raw[1:], 'Ev', 'Gv', state)
            imm8 = get_imm(raw[2:], 'b', state)
            return f'SHLD {addr}, {imm8}'
        elif lo == 5:
            inst = dis_modrm_dst_src(raw, 'SHLD', 'Ev', 'Gv', state)
            return f'{inst}, cl'
        elif lo == 8:
            state['eip'] += 1
            return f'PUSH gs'
        elif lo == 9:
            state['eip'] += 1
            return f'POP gs'
        elif lo == 0xa:
            state['eip'] += 1
            return f'RSM'
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'BTS', 'Ev', 'Gv', state)
        elif lo == 0xc:
            inst, c = dis_con_modrm_dst_src(raw, 'SHRD', 'Ev', 'Gv', state)
            ib = hex(raw[c])
            state['eip'] += 1
            return f'{inst}, {ib}'
        elif lo == 0xd:
            inst = disassemble_ev_gv(raw, 'SHRD', state)
            return f'{inst}, cl'
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'IMUL', 'Gv', 'Ev', state)
    elif hi == 0xb:
        if lo == 0:
            pass
        elif lo == 6:
            return dis_modrm_dst_src(raw, 'MOVZX', 'Gv', 'Eb', state)
        elif lo == 7:
            return dis_modrm_dst_src(raw, 'MOVZX', 'Gv', 'Ew', state)
        elif lo == 0xa:
            state['eip'] += 1 # Opcode
            mod, reg_op, rm = modrm(raw[1])
            assert reg_op >= 0b100, 'Invalid encoding'
            inst = ['?', '?', '?', '?', 'BT', 'BTS', 'BTR', 'BTC'][reg_op]
            start = state['eip']
            op = modrm_op(raw[1:], 'Ev', state)
            state['eip'] += 1 # ModRM
            op_sz = state['eip'] - start
            ib = get_imm(raw[1+op_sz:], 'b', state)
            return f'{inst} {op}, {ib}'
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'MOVSX', 'Gv', 'Eb', state)
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'MOVSX', 'Gv', 'Ew', state)
    elif hi == 0xc:
        if lo == 0:
            pass
        elif lo == 2:
            state['eip'] += 1
            return dis_modrm_dst_src(raw, 'CMPLTPS', 'Vps', 'Wps', state)
        elif lo == 6:
            state['eip'] += 3
            return f'SHUFPS xmm2, xmm0, 0x55'
        elif lo >= 8 and lo <= 0xf:
            state['eip'] += 1
            return f'BSWAP {REGISTERS[lo-8]}'
    elif hi == 0xd:
        if lo == 0 and state['prefix'] == '':
            return '(bad)'
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'PSRLW', 'Pq', 'Wq', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'PSRLD', 'Pq', 'Wq', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'PSRLQ', 'Pq', 'Wq', state)
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'PADDQ', 'Pq', 'Wq', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'PMULLW', 'Pq', 'Wq', state)
        elif lo == 7:
            return dis_modrm_dst_src(raw, 'PMOVMSKB', 'Gv', 'Wq', state) # TODO: Gd, Nq
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'PAND', 'Pq', 'Wq', state)
        elif lo == 0xc:
            return dis_modrm_dst_src(raw, 'PADDUSB', 'Pq', 'Wq', state)
        elif lo == 0xd:
            return dis_modrm_dst_src(raw, 'PADDUSW', 'Pq', 'Wq', state)
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'PMAXUB', 'Pq', 'Wq', state)
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'PANDN', 'Pq', 'Wq', state)
    elif hi == 0xe:
        if lo == 0:
            return dis_modrm_dst_src(raw, 'PAVGB', 'Pq', 'Wq', state)
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'PSRAW', 'Pq', 'Wq', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'PSRAD', 'Pq', 'Wq', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'PAVGW', 'Pq', 'Wq', state)
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'PMULHUW', 'Pq', 'Wq', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'PMULHW', 'Pq', 'Wq', state)
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'PSUBSB', 'Pq', 'Wq', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'PSUBSW', 'Pq', 'Wq', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'PMINSW', 'Pq', 'Wq', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'POR', 'Pq', 'Wq', state)
        elif lo == 0xc:
            return dis_modrm_dst_src(raw, 'PADDSB', 'Pq', 'Wq', state)
        elif lo == 0xd:
            return dis_modrm_dst_src(raw, 'PADDSW', 'Pq', 'Wq', state)
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'PMAXSW', 'Pq', 'Wq', state)
        elif lo == 0xf:
            return dis_modrm_dst_src(raw, 'PXOR', 'Pq', 'Wq', state)
    elif hi == 0xf:
        if lo == 0:
            pass
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'PSLLW', 'Pq', 'Wq', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'PSLLD', 'Pq', 'Wq', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'PSLLQ', 'Pq', 'Wq', state)
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'PMULUDQ', 'Pq', 'Wq', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'PMADDWD', 'Pq', 'Wq', state)
        elif lo == 6:
            return dis_modrm_dst_src(raw, 'PSADBW', 'Pq', 'Wq', state)
        elif lo == 7:
            return dis_modrm_dst_src(raw, 'MASKMOVQ', 'Pq', 'Wq', state)
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'PSUBB', 'Pq', 'Wq', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'PSUBW', 'Pq', 'Wq', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'PSUBD', 'Pq', 'Wq', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'PSUBQ', 'Pq', 'Wq', state)
        elif lo == 0xc:
            return dis_modrm_dst_src(raw, 'PADDB', 'Pq', 'Wq', state)
        elif lo == 0xd:
            return dis_modrm_dst_src(raw, 'PADDW', 'Pq', 'Wq', state)
        elif lo == 0xe:
            return dis_modrm_dst_src(raw, 'PADDD', 'Pq', 'Wq', state)

def disassemble(raw, state=None):
    if len(raw) == 0:
        fail('ERROR: input was empty')

    if state is None:
        state = {'seg': '', 'prefix': '', 'eip': 0}
    if 'seg' not in state:
        state['seg'] = ''
    if 'prefix' not in state:
        state['prefix'] = ''
    if 'eip' not in state:
        state['eip'] = 0
    if 'base' not in state:
        state['base'] = 0

    prefix = state['prefix']

    opcode = raw[0]
    hi = (opcode & 0xF0) >> 4
    lo = (opcode & 0x0F) >> 0
    eip = state['eip']

    if hi == 0:
        if lo == 0:
            return dis_modrm_dst_src(raw, 'ADD', 'Eb', 'Gb', state)
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'ADD', 'Ev', 'Gv', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'ADD', 'Gb', 'Eb', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'ADD', 'Gv', 'Ev', state)
        elif lo == 4:
            state['eip'] += 2
            return f'{prefix}ADD al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'{prefix}ADD eax, {hex(iz)}'
        elif lo == 6:
            state['eip'] += 1
            return f'{prefix}PUSH es'
        elif lo == 7:
            state['eip'] += 1
            return f'{prefix}POP es'
        if lo == 8:
            return dis_modrm_dst_src(raw, 'OR', 'Eb', 'Gb', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'OR', 'Ev', 'Gv', state)
        if lo == 0xa:
            return dis_modrm_dst_src(raw, 'OR', 'Gb', 'Eb', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'OR', 'Gv', 'Ev', state)
        elif lo == 0xc:
            state['eip'] += 2
            return f'{prefix}OR al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'{prefix}OR eax, {hex(iz)}'
        elif lo == 0xe:
            state['eip'] += 1
            return f'{prefix}PUSH cs'
        elif lo == 0xf:
            state['eip'] += 1
            return disassemble_2b(raw[1:], state)
    elif hi == 1:
        if lo == 0:
            return dis_modrm_dst_src(raw, 'ADC', 'Eb', 'Gb', state)
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'ADC', 'Ev', 'Gv', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'ADC', 'Gb', 'Eb', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'ADC', 'Gv', 'Ev', state)
        elif lo == 4:
            state['eip'] += 2
            return f'{prefix}ADC al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'{prefix}ADC eax, {hex(iz)}'
        elif lo == 6:
            state['eip'] += 1
            return f'{prefix}PUSH ss'
        elif lo == 7:
            state['eip'] += 1
            return f'{prefix}POP ss'
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'SBB', 'Eb', 'Gb', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'SBB', 'Ev', 'Gv', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'SBB', 'Gb', 'Eb', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'SBB', 'Gv', 'Ev', state)
        elif lo == 0xc:
            state['eip'] += 2
            return f'{prefix}SBB al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'{prefix}SBB eax, {hex(iz)}'
        elif lo == 0xe:
            state['eip'] += 1
            return f'{prefix}PUSH ds'
        elif lo == 0xf:
            state['eip'] += 1
            return f'{prefix}POP ds'
    elif hi == 2:
        if lo == 0:
            return dis_modrm_dst_src(raw, 'AND', 'Eb', 'Gb', state)
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'AND', 'Ev', 'Gv', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'AND', 'Gb', 'Eb', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'AND', 'Gv', 'Ev', state)
        elif lo == 4:
            state['eip'] += 2
            return f'{prefix}AND al, {hex(raw[1])}'
        elif lo == 5:
            state['eip'] += 1
            iz = get_imm(raw[1:], 'z', state)
            return f'{prefix}AND {get_regs("v", state)[0]}, {iz}'
        elif lo == 6:
            state['seg'] = 'es:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 7:
            state['eip'] += 1
            return f'{prefix}DAA'
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'SUB', 'Eb', 'Gb', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'SUB', 'Ev', 'Gv', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'SUB', 'Gb', 'Eb', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'SUB', 'Gv', 'Ev', state)
        elif lo == 0xc:
            state['eip'] += 2
            return f'{prefix}SUB al, {hex(raw[1])}'
        elif lo == 0xd:
            state['eip'] += 5
            iz = int.from_bytes(raw[1:5], 'little')
            return f'{prefix}SUB eax, {hex(iz)}'
        elif lo == 0xe:
            state['seg'] = 'cs:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 0xf:
            state['eip'] += 1
            return f'{prefix}DAS'
    elif hi == 3:
        if lo == 0:
            return dis_modrm_dst_src(raw, 'XOR', 'Eb', 'Gb', state)
        elif lo == 1:
            return dis_modrm_dst_src(raw, 'XOR', 'Ev', 'Gv', state)
        elif lo == 2:
            return dis_modrm_dst_src(raw, 'XOR', 'Gb', 'Eb', state)
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'XOR', 'Gv', 'Ev', state)
        elif lo == 4:
            state['eip'] += 2
            return f'{prefix}XOR al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'{prefix}XOR eax, {hex(iz)}'
        elif lo == 6:
            state['seg'] = 'ss:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 7:
            state['eip'] += 1
            return f'{prefix}AAA'
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'CMP', 'Eb', 'Gb', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'CMP', 'Ev', 'Gv', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'CMP', 'Gb', 'Eb', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'CMP', 'Gv', 'Ev', state)
        elif lo == 0xc:
            state['eip'] += 2
            return f'{prefix}CMP al, {hex(raw[1])}'
        elif lo == 0xd:
            state['eip'] += 1
            r = get_regs('v', state)[0]
            iz = get_imm(raw[1:], 'z', state)
            return f'{prefix}CMP {r}, {iz}'
        elif lo == 0xe:
            state['seg'] = 'ds:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 0xf:
            state['eip'] += 1
            return f'{prefix}AAS'
    elif hi == 4:
        if lo <= 7:
            state['eip'] += 1
            return f'{prefix}INC {REGISTERS[lo]}'
        elif lo <= 0xf:
            state['eip'] += 1
            return f'{prefix}DEC {REGISTERS[lo-8]}'
    elif hi == 5:
        if lo <= 7:
            state['eip'] += 1
            return f'{prefix}PUSH {REGISTERS[lo]}'
        elif lo <= 0xf:
            state['eip'] += 1
            return f'{prefix}POP {REGISTERS[lo-8]}'
    elif hi == 6:
        if lo == 0:
            state['eip'] += 1
            return f'{prefix}PUSHA'
        elif lo == 1:
            state['eip'] += 1
            return f'{prefix}POPA'
        elif lo == 2:
            _, reg_op, _ = modrm(raw[1])
            m = modrm_addressing(raw[1], raw[2:], state)
            state['eip'] += 2
            return f'BOUND {REGISTERS[reg_op]}, QWORD PTR {m}'
        elif lo == 3:
            return dis_modrm_dst_src(raw, 'ARPL', 'Ew', 'Gw', state)
        elif lo == 4:
            state['seg'] = 'fs:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 5:
            state['seg'] = 'gs:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 6:
            state['op_size'] = 1
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 7:
            state['addr_size'] = 1
            return disassemble(raw[1:], state)
        elif lo == 8:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'{prefix}PUSH {hex(iz)}'
        elif lo == 9:
            # TODO: More tests
            inst = disassemble_gv_ev(raw, 'IMUL', state)
            iz = int.from_bytes(raw[state['eip']:state['eip']+4], 'little')
            state['eip'] += 4
            return f'{inst}, {hex(iz)}'
        elif lo == 0xa:
            ib = raw[1]
            ib = sign_extend(ib, 8)
            state['eip'] += 2
            return f'{prefix}PUSH {hex(ib)}'
        elif lo == 0xb:
            start = state['eip']
            inst = dis_modrm_dst_src(raw, 'IMUL', 'Gv', 'Ev', state)
            end = state['eip'] - start
            ib = raw[end]
            ib = hex(sign_extend(ib, 8))
            state['eip'] += 1
            return f'{inst}, {ib}'
        elif lo == 0xc:
            state['eip'] += 1
            return f'INS BYTE PTR es:[edi], dx'
        elif lo == 0xd:
            state['eip'] += 1
            return f'INS DWORD PTR es:[edi], dx'
        elif lo == 0xe:
            state['eip'] += 1
            return f'OUTS dx, BYTE PTR ds:[esi]'
        elif lo == 0xf:
            state['eip'] += 1
            return f'OUTS dx, DWORD PTR ds:[esi]'
    elif hi == 7:
        jmp_type = [
            'JO', 'JNO', 'JB', 'JNB', 'JE', 'JNE', 'JBE', 'JNBE',
            'JS', 'JNS', 'JP', 'JNP', 'JL', 'JNL', 'JLE', 'JNLE',
        ][lo]
        rel8 = raw[1]
        state['eip'] += 2
        addr = state['eip'] + rel8
        return f'{prefix}{jmp_type} {hex(addr)}'
    elif hi == 8:
        if lo == 0:
            start = state['eip']
            state['eip'] += 1
            mod, reg_op, rm = modrm(raw[1])
            op = ['ADD', 'OR', 'ADC', 'SBB', 'AND', 'SUB', 'XOR', 'CMP'][reg_op]
            addr = modrm_op(raw[1:], 'Eb', state)
            state['eip'] += 1
            end = state['eip'] - start
            ib = hex(raw[end])
            state['eip'] += 1
            return f'{op} {addr}, {ib}'
        elif lo == 1:
            prev_eip = state['eip']
            mod, reg_op, rm = modrm(raw[1])
            state['eip'] += 2 # 1-byte opcode + ModRM
            op = ['ADD', 'OR', 'ADC', 'SBB', 'AND', 'SUB', 'XOR', 'CMP'][reg_op]
            dst = modrm_op(raw[1:], 'Ev', state)
            start = state['eip'] - prev_eip
            if 'op_size' in state and state['op_size'] == 1:
                iz = hex(int.from_bytes(raw[start:start+2], 'little'))
                state['eip'] += 2
            else:
                iz = hex(int.from_bytes(raw[start:start+4], 'little'))
                state['eip'] += 4
            return f'{op} {dst}, {iz}'
        elif lo == 2:
            mod, reg_op, rm = modrm(raw[1])
            op = ['ADD', 'OR', 'ADC', 'SBB', 'AND', 'SUB', 'XOR', 'CMP'][reg_op]
            return disassemble_eb_ib(raw, op, state) # TODO: Test
        elif lo == 3:
            state['eip'] += 1 # Opcode
            mod, reg_op, rm = modrm(raw[1])
            op = ['ADD', 'OR', 'ADC', 'SBB', 'AND', 'SUB', 'XOR', 'CMP'][reg_op]
            start = state['eip']
            addr = modrm_op(raw[1:], 'Ev', state)
            state['eip'] += 1 # ModRM
            end = state['eip'] - start
            ib = hex(raw[end+1])
            state['eip'] += 1 # Ib
            return f'{op} {addr}, {ib}'
        elif lo == 4:
            return dis_modrm_dst_src(raw, 'TEST', 'Eb', 'Gb', state)
        elif lo == 5:
            return dis_modrm_dst_src(raw, 'TEST', 'Ev', 'Gv', state)
        elif lo == 6:
            return dis_modrm_dst_src(raw, 'XCHG', 'Eb', 'Gb', state)
        elif lo == 7:
            return dis_modrm_dst_src(raw, 'XCHG', 'Ev', 'Gv', state)
        elif lo == 8:
            return dis_modrm_dst_src(raw, 'MOV', 'Eb', 'Gb', state)
        elif lo == 9:
            return dis_modrm_dst_src(raw, 'MOV', 'Ev', 'Gv', state)
        elif lo == 0xa:
            return dis_modrm_dst_src(raw, 'MOV', 'Gb', 'Eb', state)
        elif lo == 0xb:
            return dis_modrm_dst_src(raw, 'MOV', 'Gv', 'Ev', state)
        elif lo == 0xc:
            _, reg_op, _ = modrm(raw[1])
            inst = disassemble_ew_gw(raw, 'MOV', state) # TODO: Test
            # TODO: No dirty hacks...
            return f'{inst.split(",")[0]}, {SEGMENTS[reg_op]}'
        elif lo == 0xd:
            _, reg_op, _ = modrm(raw[1])
            m = modrm_addressing(raw[1], raw[2:], state)
            state['eip'] += 2 # FIXME: Properly compute depending on addressing mode!
            return f'LEA {REGISTERS[reg_op]}, {m}'
        elif lo == 0xe:
            _, reg_op, _ = modrm(raw[1])
            inst = disassemble_gw_ew(raw, 'MOV', state) # TODO: Test
            # TODO: No dirty hacks...
            return f'MOV {SEGMENTS[reg_op]},{inst.split(",")[1]}'
        elif lo == 0xf:
            mod, reg_op, rm = modrm(raw[1])
            if reg_op == 0b000:
                inst = disassemble_ex_gx(raw, 'POP', 'DWORD PTR', REGISTERS, state)
                return inst.split(',')[0]
            else:
                state['eip'] += 1
                return f'(bad)'
    elif hi == 9:
        if lo == 0:
            state['eip'] += 1
            return f'{prefix}NOP'
        elif lo <= 7:
            state['eip'] += 1
            return f'{prefix}XCHG {REGISTERS[lo]}, eax'
        elif lo == 8:
            state['eip'] += 1
            return f'{prefix}CWDE'
        elif lo == 9:
            state['eip'] += 1
            return f'{prefix}CDQ'
        elif lo == 0xa:
            iv = int.from_bytes(raw[1:5], 'little')
            iw = int.from_bytes(raw[5:7], 'little')
            state['eip'] += 7
            return f'{prefix}CALL {hex(iw)}:{hex(iv)}'
        elif lo == 0xb:
            state['eip'] += 1
            return f'{prefix}FWAIT'
        elif lo == 0xc:
            state['eip'] += 1
            return f'{prefix}PUSHF'
        elif lo == 0xd:
            state['eip'] += 1
            return f'{prefix}POPF'
        elif lo == 0xe:
            state['eip'] += 1
            return f'{prefix}SAHF'
        elif lo == 0xf:
            state['eip'] += 1
            return f'{prefix}LAHF'
    elif hi == 0xa:
        if lo == 0:
            ob = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            seg = state['seg'] or 'ds:'
            return f'{prefix}MOV al, {seg}{hex(ob)}'
        elif lo == 1:
            ob = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            seg = state['seg'] or 'ds:'
            return f'{prefix}MOV eax, {seg}{hex(ob)}'
        elif lo == 2:
            ob = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            seg = state['seg'] or 'ds:'
            return f'{prefix}MOV {seg}{hex(ob)}, al'
        elif lo == 3:
            ob = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            seg = state['seg'] or 'ds:'
            return f'{prefix}MOV {seg}{hex(ob)}, eax'
        elif lo == 4:
            state['eip'] += 1
            return f'MOVS BYTE PTR es:[edi], BYTE PTR ds:[esi]'
        elif lo == 5:
            state['eip'] += 1
            return f'MOVS DWORD PTR es:[edi], DWORD PTR ds:[esi]'
        elif lo == 6:
            state['eip'] += 1
            return f'CMPS BYTE PTR ds:[esi], BYTE PTR es:[edi]'
        elif lo == 7:
            state['eip'] += 1
            return f'CMPS DWORD PTR ds:[esi], DWORD PTR es:[edi]'
        elif lo == 8:
            ib = raw[1]
            state['eip'] += 2
            return f'{prefix}TEST al, {hex(ib)}'
        elif lo == 9:
            state['eip'] += 1
            dst = get_regs('v', state)[0]
            if 'op_size' in state and state['op_size'] == 1:
                iz = hex(int.from_bytes(raw[1:3], 'little'))
                state['eip'] += 2
            else:
                iz = hex(int.from_bytes(raw[1:5], 'little'))
                state['eip'] += 4
            return f'{prefix}TEST {dst}, {iz}'
        elif lo == 0xa:
            state['eip'] += 1
            return f'STOS BYTE PTR es:[edi], al'
        elif lo == 0xb:
            state['eip'] += 1
            return f'STOS DWORD PTR es:[edi], eax'
        elif lo == 0xc:
            state['eip'] += 1
            return f'LODS al, BYTE PTR ds:[esi]'
        elif lo == 0xd:
            state['eip'] += 1
            return f'LODS eax, DWORD PTR ds:[esi]'
        elif lo == 0xe:
            state['eip'] += 1
            return f'SCAS al, BYTE PTR ds:[edi]'
        elif lo == 0xf:
            state['eip'] += 1
            return f'SCAS eax, DWORD PTR ds:[edi]'
    elif hi == 0xb:
        if lo <= 7:
            state['eip'] += 2
            return f'{prefix}MOV {REGISTERS8[lo]}, {hex(raw[1])}'
        elif lo <= 0xf:
            state['eip'] += 1
            imm = get_imm(raw[1:], 'v', state)
            regs = get_regs('v', state)
            return f'{prefix}MOV {regs[lo-8]}, {imm}'
    elif hi == 0xc:
        if lo == 0:
            mod, reg_op, rm = modrm(raw[1])
            #assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            op = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', 'SHL', 'SAR'][reg_op]
            return disassemble_eb_ib(raw, op, state) # TODO: Test
        elif lo == 1:
            mod, reg_op, rm = modrm(raw[1])
            #assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            op = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', 'SHL', 'SAR'][reg_op]
            return disassemble_eb_ib(raw, op, state).replace('BYTE', 'DWORD') # TODO: Test
        elif lo == 2:
            iw = int.from_bytes(raw[1:3], 'little')
            state['eip'] += 3
            return f'{prefix}RET {hex(iw)}'
        elif lo == 3:
            state['eip'] += 1
            return f'{prefix}RET'
        elif lo == 4 or lo == 5:
            # TODO: More tests
            op = ['LES', 'LDS'][lo - 4]
            mod, reg_op, rm = modrm(raw[1])
            m = modrm_addressing(raw[1], raw[2:], state)
            state['eip'] += 2 # FIXME: Properly compute depending on addressing mode!
            return f'{op} {REGISTERS[reg_op]}, FWORD PTR {m}'
        elif lo == 6:
            start = state['eip']
            state['eip'] += 1
            mod, reg_op, rm = modrm(raw[1])
            if reg_op != 0b000:
                return '(bad)'
            assert reg_op == 0b000, 'Invalid Grp 11 MOV'
            addr = modrm_op(raw[1:], 'Eb', state)
            state['eip'] += 1
            end = state['eip'] - start
            ib = hex(raw[end])
            state['eip'] += 1
            return f'MOV {addr}, {ib}'
        elif lo == 7:
            state['eip'] += 1
            mod, reg_op, rm = modrm(raw[1])
            if reg_op != 0b000:
                state['eip'] += 1
                return '(bad)'
            start = state['eip']
            addr = modrm_op(raw[1:], 'Ev', state)
            state['eip'] += 1
            op_sz = state['eip'] - start
            iz = get_imm(raw[1+op_sz:], 'z', state)
            return f'MOV {addr}, {iz}'
        elif lo == 8:
            iw = int.from_bytes(raw[1:3], 'little')
            ib = raw[3]
            state['eip'] += 4
            return f'{prefix}ENTER {hex(iw)}, {hex(ib)}'
        elif lo == 9:
            state['eip'] += 1
            return f'{prefix}LEAVE'
        elif lo == 0xa:
            iw = int.from_bytes(raw[1:3], 'little')
            state['eip'] += 3
            return f'{prefix}RETF {hex(iw)}'
        elif lo == 0xb:
            state['eip'] += 1
            return f'{prefix}RETF'
        elif lo == 0xc:
            state['eip'] += 1
            return f'{prefix}INT3'
        elif lo == 0xd:
            state['eip'] += 2
            return f'{prefix}INT {hex(raw[1])}'
        elif lo == 0xe:
            state['eip'] += 1
            return f'{prefix}INTO'
        elif lo == 0xf:
            state['eip'] += 1
            return f'{prefix}IRET'
    elif hi == 0xd:
        if lo == 0:
            mod, reg_op, rm = modrm(raw[1])
            state['eip'] += 2
            assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            inst = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', '???', 'SAR'][reg_op]
            op = modrm_op(raw[1:], 'Eb', state)
            return f'{inst} {op}, 1'
        elif lo == 1:
            op = modrm_op(raw[1:], 'Ev', state)
            state['eip'] += 2
            return f'SHR {op}, 1'
        elif lo == 2:
            mod, reg_op, rm = modrm(raw[1])
            state['eip'] += 2
            assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            inst = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', '???', 'SAR'][reg_op]
            op = modrm_op(raw[1:], 'Eb', state)
            return f'{inst} {op}, cl'
        elif lo == 3:
            mod, reg_op, rm = modrm(raw[1])
            #assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            inst = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', 'SHL', 'SAR'][reg_op]
            op = modrm_op(raw[1:], 'Ev', state)
            state['eip'] += 2
            return f'{inst} {op}, cl'
            inst = disassemble_ev_gv(raw, op, state).split(',')[0]
            return f'{inst}, cl'
        elif lo == 4:
            state['eip'] += 2
            ib = hex(raw[1])
            return f'AAM {ib}'
        elif lo == 5:
            state['eip'] += 2
            ib = hex(raw[1])
            return f'AAD {ib}'
        elif lo == 6:
            state['eip'] += 1
            return f'{prefix}(bad)'
        elif lo == 7:
            state['eip'] += 1
            return f'XLAT BYTE PTR ds:[ebx]'
        elif lo == 8:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FADD DWORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FMUL DWORD PTR {addr}'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FCOM DWORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FCOMP DWORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FSUB DWORD PTR {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FSUBR DWORD PTR {addr}'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FDIV DWORD PTR {addr}'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FDIVR DWORD PTR {addr}'
            else:
                if raw[1] >= 0xc0 and raw[1] <= 0xc7:
                    state['eip'] += 2
                    return f'FADD st, st({raw[1] - 0xc0})'
                elif raw[1] >= 0xc8 and raw[1] <= 0xcf:
                    state['eip'] += 2
                    return f'FMUL st, st({raw[1] - 0xc8})'
                elif raw[1] >= 0xd0 and raw[1] <= 0xd7:
                    state['eip'] += 2
                    return f'FCOM st({raw[1] - 0xd0})'
                elif raw[1] >= 0xd8 and raw[1] <= 0xdf:
                    state['eip'] += 2
                    return f'FCOMP st({raw[1] - 0xd8})'
                elif raw[1] >= 0xe0 and raw[1] <= 0xe7:
                    state['eip'] += 2
                    return f'FSUB st, st({raw[1] - 0xe0})'
                elif raw[1] >= 0xe8 and raw[1] <= 0xef:
                    state['eip'] += 2
                    return f'FSUBR st, st({raw[1] - 0xe8})'
                elif raw[1] >= 0xf0 and raw[1] <= 0xf7:
                    state['eip'] += 2
                    return f'FDIV st, st({raw[1] - 0xf0})'
                elif raw[1] >= 0xf8 and raw[1] <= 0xff:
                    state['eip'] += 2
                    return f'FDIVR st, st({raw[1] - 0xf8})'
        elif lo == 9:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLD DWORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'(bad)'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FST DWORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FSTP DWORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLDENV {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLDCW WORD PTR {addr}'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FNSTENV {addr}'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FNSTCW WORD PTR {addr}'
            else:
                if raw[1] >= 0xc0 and raw[1] <= 0xc7:
                    state['eip'] += 2
                    return f'FLD st({raw[1]-0xc0})'
                elif raw[1] >= 0xc8 and raw[1] <= 0xcf:
                    state['eip'] += 2
                    return f'FXCH st({raw[1]-0xc8})'
                elif raw[1] == 0xd0:
                    state['eip'] += 2
                    return f'FNOP'
                elif raw[1] == 0xe0:
                    state['eip'] += 2
                    return f'FCHS'
                elif raw[1] == 0xe1:
                    state['eip'] += 2
                    return f'FABS'
                elif raw[1] == 0xe4:
                    state['eip'] += 2
                    return f'FTST'
                elif raw[1] == 0xe5:
                    state['eip'] += 2
                    return f'FXAM'
                elif raw[1] == 0xe8:
                    state['eip'] += 2
                    return f'FLD1'
                elif raw[1] == 0xe9:
                    state['eip'] += 2
                    return f'FLDL2T'
                elif raw[1] == 0xea:
                    state['eip'] += 2
                    return f'FLD12E'
                elif raw[1] == 0xeb:
                    state['eip'] += 2
                    return f'FLDPI'
                elif raw[1] == 0xec:
                    state['eip'] += 2
                    return f'FLDLG2'
                elif raw[1] == 0xed:
                    state['eip'] += 2
                    return f'FLDLN2'
                elif raw[1] == 0xee:
                    state['eip'] += 2
                    return f'FLDZ'
                elif raw[1] == 0xf0:
                    state['eip'] += 2
                    return f'F2XM1'
                elif raw[1] == 0xf1:
                    state['eip'] += 2
                    return f'FY12X'
                elif raw[1] == 0xf2:
                    state['eip'] += 2
                    return f'FPTAN'
                elif raw[1] == 0xf3:
                    state['eip'] += 2
                    return f'FPATAN'
                elif raw[1] == 0xf4:
                    state['eip'] += 2
                    return f'FXTRACT'
                elif raw[1] == 0xf5:
                    state['eip'] += 2
                    return f'FPREM1'
                elif raw[1] == 0xf6:
                    state['eip'] += 2
                    return f'FDECSTP'
                elif raw[1] == 0xf7:
                    state['eip'] += 2
                    return f'FINCSTP'
                elif raw[1] == 0xf8:
                    state['eip'] += 2
                    return f'FPREM'
                elif raw[1] == 0xf9:
                    state['eip'] += 2
                    return f'FYL2XP1'
                elif raw[1] == 0xfa:
                    state['eip'] += 2
                    return f'FSQRT'
                elif raw[1] == 0xfb:
                    state['eip'] += 2
                    return f'FSINCOS'
                elif raw[1] == 0xfc:
                    state['eip'] += 2
                    return f'FRNDINT'
                elif raw[1] == 0xfd:
                    state['eip'] += 2
                    return f'FSCALE'
                elif raw[1] == 0xfe:
                    state['eip'] += 2
                    return f'FSIN'
                elif raw[1] == 0xff:
                    state['eip'] += 2
                    return f'FCOS'
        elif lo == 0xa:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIADD DWORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIMUL DWORD PTR {addr}'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FICOM DWORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FICOMP DWORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISUB DWORD PTR {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISUBR DWORD PTR {addr}'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIDIV DWORD PTR {addr}'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIDIVR DWORD PTR {addr}'
            else:
                if raw[1] >= 0xc0 and raw[1] <= 0xc7:
                    state['eip'] += 2
                    return f'FCMOVB st, st({raw[1] - 0xc0})'
                elif raw[1] >= 0xc8 and raw[1] <= 0xcf:
                    state['eip'] += 2
                    return f'FCMOVE st, st({raw[1] - 0xc8})'
                elif raw[1] >= 0xd0 and raw[1] <= 0xd7:
                    state['eip'] += 2
                    return f'FCMOVBE st, st({raw[1] - 0xd0})'
                elif raw[1] >= 0xd8 and raw[1] <= 0xdf:
                    state['eip'] += 2
                    return f'FCMOVU st, st({raw[1] - 0xd8})'
                elif raw[1] == 0xe9:
                    state['eip'] += 2
                    return f'FUCOMPP'
                else:
                    state['eip'] += 2
                    return '(bad)'
        elif lo == 0xb:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FILD QWORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISTTP DWORD PTR {addr}'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIST DWORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISTP DWORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'(bad)'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLD TBYTE PTR {addr}'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'(bad)'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FSTP TBYTE PTR {addr}'
            else:
                if raw[1] == 0xe2:
                    state['eip'] += 2
                    return f'FNCLEX'
                if raw[1] == 0xe3:
                    state['eip'] += 2
                    return f'FNINIT'
                pass
        elif lo == 0xc:
            _, nnn, _ = modrm(raw[1])
            if raw[1] < 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FADD QWORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FMUL QWORD PTR {addr}'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FCOM QWORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FCOMP QWORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FSUB QWORD PTR {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FSUBR QWORD PTR {addr}'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FDIV QWORD PTR {addr}'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FDIVR QWORD PTR {addr}'
            else:
                if raw[0] >= 0xc0 and raw[1] <= 0xc7:
                    state['eip'] += 2
                    return f'FADD st({raw[1] - 0xc0}), st'
                elif raw[1] >= 0xc8 and raw[1] <= 0xcf:
                    state['eip'] += 2
                    return f'FMUL st({raw[1] - 0xc8}), st'
                elif raw[1] >= 0xe0 and raw[1] <= 0xe7:
                    state['eip'] += 2
                    return f'FSUBR st({raw[1] - 0xe0}), st'
                elif raw[1] >= 0xe8 and raw[1] <= 0xef:
                    state['eip'] += 2
                    return f'FSUB st({raw[1] - 0xe8}), st'
                elif raw[1] >= 0xf0 and raw[1] <= 0xf7:
                    state['eip'] += 2
                    return f'FDIVR st({raw[1] - 0xf0}), st'
                elif raw[1] >= 0xf8 and raw[1] <= 0xff:
                    state['eip'] += 2
                    return f'FDIV st({raw[1] - 0xf8}), st'
        elif lo == 0xd:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLD QWORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISTTP QWORD PTR {addr}'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FST QWORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FSTP QWORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FRSTOR {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'(bad)'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FNSAVE {addr}'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FNSTSW WORD PTR {addr}'
            else:
                if raw[1] >= 0xc0 and raw[1] <= 0xc7:
                    state['eip'] += 2
                    return f'FFREE st({raw[1] - 0xc0})'
                elif raw[1] >= 0xd0 and raw[1] <= 0xd7:
                    state['eip'] += 2
                    return f'FST st({raw[1] - 0xd0})'
                elif raw[1] >= 0xd8 and raw[1] <= 0xdf:
                    state['eip'] += 2
                    return f'FSTP st({raw[1] - 0xd8})'
                elif raw[1] >= 0xe0 and raw[1] <= 0xe7:
                    state['eip'] += 2
                    return f'FUCOM st({raw[1] - 0xe0})'
                elif raw[1] >= 0xe8 and raw[1] <= 0xef:
                    state['eip'] += 2
                    return f'FUCOMP st({raw[1] - 0xe8})'
                else:
                    state['eip'] += 2
                    return f'(bad)'
        elif lo == 0xe:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIADD WORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIMUL WORD PTR {addr}'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FICOM WORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FICOMP WORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISUB WORD PTR {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISUBR WORD PTR {addr}'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIDIV WORD PTR {addr}'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIDIVR WORD PTR {addr}'
            else:
                if raw[1] >= 0xc0 and raw[1] <= 0xc7:
                    state['eip'] += 2
                    return f'FADDP st({raw[1] - 0xc0}), st'
                elif raw[1] >= 0xc8 and raw[1] <= 0xcf:
                    state['eip'] += 2
                    return f'FMULP st({raw[1] - 0xc8}), st'
                elif raw[1] == 0xd9:
                    state['eip'] += 2
                    return f'FCOMPP'
                elif (raw[1] >= 0xd0 and raw[1] <= 0xd8) or (raw[1] >= 0xda and raw[1] <= 0xdf):
                    state['eip'] += 2
                    return f'(bad)'
                elif raw[1] >= 0xe0 and raw[1] <= 0xe7:
                    state['eip'] += 2
                    return f'FSUBRP st({raw[1] - 0xe0}), st'
                elif raw[1] >= 0xe8 and raw[1] <= 0xef:
                    state['eip'] += 2
                    return f'FSUBP st({raw[1] - 0xe8}), st'
                elif raw[1] >= 0xf0 and raw[1] <= 0xf7:
                    state['eip'] += 2
                    return f'FDIVRP st({raw[1] - 0xf0}), st'
                elif raw[1] >= 0xf8 and raw[1] <= 0xff:
                    state['eip'] += 2
                    return f'FDIVP st({raw[1] - 0xf8}), st'
        elif lo == 0xf:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FILD WORD PTR {addr}'
                elif nnn == 0b001:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISTTP WORD PTR {addr}'
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIST WORD PTR {addr}'
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISTP WORD PTR {addr}'
                elif nnn == 0b100:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FBLD TBYTE PTR {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FILD QWORD PTR {addr}'
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FBSTP TBYTE PTR {addr}'
                elif nnn == 0b111:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISTP QWORD PTR {addr}'
            else:
                if raw[1] == 0xe0:
                    state['eip'] += 2
                    return f'FNSTSW ax'
                elif raw[1] >= 0xe8 and raw[1] <= 0xef:
                    state['eip'] += 2
                    return f'FUCOMIP st, st({raw[1] - 0xe8})'
                elif raw[1] >= 0xf0 and raw[1] <= 0xf7:
                    state['eip'] += 2
                    return f'FCOMIP st, st({raw[1] - 0xf0})'
                else:
                    state['eip'] += 2
                    return '(bad)'
            pass
    elif hi == 0xe:
        if lo == 0:
            state['eip'] += 2
            addr = sign_extend(raw[1], 8) + state['eip']
            return f'LOOPNE {hex(addr)}'
        elif lo == 1:
            state['eip'] += 2
            addr = sign_extend(raw[1], 8) + state['eip']
            return f'LOOPE {hex(addr)}'
        elif lo == 2:
            state['eip'] += 2
            addr = sign_extend(raw[1], 8) + state['eip']
            return f'LOOP {hex(addr)}'
        elif lo == 3:
            state['eip'] += 2
            addr = sign_extend(raw[1], 8) + state['eip']
            return f'JECXZ {hex(addr)}'
        elif lo == 4:
            state['eip'] += 1
            ib = get_imm(raw[1:], 'b', state)
            return f'IN {get_regs("b", state)[0]}, {ib}'
        elif lo == 5:
            state['eip'] += 1
            ib = get_imm(raw[1:], 'b', state)
            return f'IN {get_regs("v", state)[0]}, {ib}'
        elif lo == 6:
            state['eip'] += 1
            ib = get_imm(raw[1:], 'b', state)
            return f'OUT {ib}, {get_regs("b", state)[0]}'
        elif lo == 7:
            state['eip'] += 1
            ib = get_imm(raw[1:], 'b', state)
            return f'OUT {ib}, {get_regs("v", state)[0]}'
        elif lo == 8:
            rel32 = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            addr = state['eip'] + rel32
            return f'CALL {hex(addr)}'
        elif lo == 9:
            rel32 = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            addr = state['eip'] + rel32
            return f'JMP {hex(addr)}'
        elif lo == 0xa:
            iv = int.from_bytes(raw[1:5], 'little')
            iw = int.from_bytes(raw[5:7], 'little')
            state['eip'] += 7
            return f'JMP {hex(iw)}:{hex(iv)}'
        elif lo == 0xb:
            rel8 = raw[1]
            state['eip'] += 2
            addr = state['eip'] + rel8
            return f'JMP {hex(addr)}'
        elif lo == 0xc:
            state['eip'] += 1
            return f'IN al, dx'
        elif lo == 0xd:
            state['eip'] += 1
            return f'IN eax, dx'
        elif lo == 0xe:
            state['eip'] += 1
            return f'OUT dx, al'
        elif lo == 0xf:
            state['eip'] += 1
            return f'OUT dx, eax'
    elif hi == 0xf:
        if lo == 0:
            state['prefix'] = 'lock '
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 1:
            state['eip'] += 1
            return f'{prefix}INT1'
        elif lo == 2:
            state['prefix'] = 'repne '
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 3:
            state['prefix'] = 'repe '
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 4:
            state['eip'] += 1
            return f'{prefix}HLT'
        elif lo == 5:
            state['eip'] += 1
            return f'{prefix}CMC'
        elif lo == 6:
            mod, reg_op, rm = modrm(raw[1])
            #assert reg_op != 0b001, 'Invalid Unary Grp 3 Eb op!'
            op = ['TEST', 'TEST', 'NOT', 'NEG', 'MUL', 'IMUL', 'DIV', 'IDIV'][reg_op]
            # TODO: No dirty hacks!
            inst = disassemble_eb_gb(raw, op, state)
            inst = inst.split(',')[0]
            if op == 'TEST':
                ib = raw[state['eip']-eip]
                state['eip'] += 1
                return f'{inst}, {hex(ib)}'
            else:
                return inst
        elif lo == 7:
            mod, reg_op, rm = modrm(raw[1])
            #assert reg_op != 0b001, 'Invalid Unary Grp 3 Eb op!'
            op = ['TEST', 'TEST', 'NOT', 'NEG', 'MUL', 'IMUL', 'DIV', 'IDIV'][reg_op]
            # TODO: No dirty hacks!
            inst = disassemble_ev_gv(raw, op, state)
            inst = inst.split(',')[0]
            if op == 'TEST':
                iz = int.from_bytes(raw[state['eip']:state['eip']+4], 'little')
                state['eip'] += 4
                return f'{inst}, {hex(iz)}'
            else:
                return inst
        elif lo == 8:
            state['eip'] += 1
            return f'{prefix}CLC'
        elif lo == 9:
            state['eip'] += 1
            return f'{prefix}STC'
        elif lo == 0xa:
            state['eip'] += 1
            return f'{prefix}CLI'
        elif lo == 0xb:
            state['eip'] += 1
            return f'{prefix}STI'
        elif lo == 0xc:
            state['eip'] += 1
            return f'{prefix}CLD'
        elif lo == 0xd:
            state['eip'] += 1
            return f'{prefix}STD'
        elif lo == 0xe:
            state['eip'] += 1
            mod, reg_op, rm = modrm(raw[1])
            if reg_op > 0b001:
                return f'(bad)'
            state['eip'] += 1
            mod, reg_op, rm = modrm(raw[1])
            op = ['INC', 'DEC'][reg_op]
            addr = modrm_op(raw[1:], 'Eb', state)
            return f'{op} {addr}'
        elif lo == 0xf:
            mod, reg_op, rm = modrm(raw[1])
            state['eip'] += 2
            assert reg_op != 0b111
            op = ['INC', 'DEC', 'CALL', 'CALL', 'JMP', 'JMP', 'PUSH'][reg_op]
            addr = modrm_op(raw[1:], 'Ev', state)
            return f'{op} {addr}'
    else:
        fail(f'ERROR: Unknown opcode {hex(raw[0])}')

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
        elif (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z'):
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

def assemble(line, state):
    if 'eip' not in state or state['eip'] == None:
        state['eip'] = 0
    tokens = tokenize(line)

    opcode = tokens[0].value.upper()

    if opcode == 'AAA':
        return b'\x37'
    elif opcode == 'AAD':
        if len(tokens) == 1:
            return b'\xd5\x0a'
        else:
            return b'\xd5' + pack('<B', int(tokens[1].value, base=16))
    elif opcode == 'AAM':
        if len(tokens) == 1:
            return b'\xd4\x0a'
        else:
            return b'\xd4' + pack('<B', int(tokens[1].value, base=16))
    elif opcode == 'AAS':
        return b'\x3f'
    elif opcode == 'ADC':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            assert tokens[6].value == ','
            if tokens[7].value in REGISTERS8:
                src = REGISTERS8.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | reg
                return b'\x10' + pack('<B', modrm)
            else:
                modrm = 0b00010000 | reg
                ib = int(tokens[7].value, base=16)
                return b'\x80' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'DWORD':
            # TODO: DRY same as above...
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            assert tokens[6].value == ','
            if tokens[7].value in REGISTERS:
                src = REGISTERS.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | reg
                return b'\x11' + pack('<B', modrm)
            else:
                modrm = 0b00010000 | reg
                im = int(tokens[7].value, base=16)
                if im > 0x7f:
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)
                else:
                    return b'\x83' + pack('<B', modrm) + pack('<B', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000000 | dst << 3 | reg
                return b'\x12' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return b'\x14' + pack('<B', ib)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000000 | dst << 3 | reg
                return b'\x13' + pack('<B', modrm)
            else:
                im = int(tokens[3].value, base=16)
                return b'\x15' + pack('<I', im)
        else:
            assert False, 'Unreachable'
    elif opcode == 'ADCX':
        assert False, 'Not implemented'
    elif opcode == 'ADD':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            assert tokens[6].value == ','
            if tokens[7].value in REGISTERS8:
                src = REGISTERS8.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | reg
                return b'\x00' + pack('<B', modrm)
            else:
                ib = int(tokens[7].value, base=16)
                modrm = 0b00000000
                return b'\x80' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            assert tokens[6].value == ','
            if tokens[7].value in REGISTERS:
                src = REGISTERS.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | reg
                return b'\x01' + pack('<B', modrm)
            else:
                im = int(tokens[7].value, base=16)
                if im <= 0x7f:
                    modrm = 0b00000000
                    return b'\x83' + pack('<B', modrm) + pack('<B', im)
                else:
                    modrm = 0b00000000 | reg
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000000 | dst << 3 | reg
                return b'\x02' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return b'\x04' + pack('<B', ib)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000000 | dst << 3 | reg
                return b'\x03' + pack('<B', modrm)
            elif tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x03' + pack('<B', modrm)
            else:
                im = int(tokens[3].value, base=16)
                if im <= 0x7f:
                    modrm = 0b11000000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<B', im)
                elif dst == REGISTERS.index('eax'):
                    return b'\x05' + pack('<I', im)
                else:
                    modrm = 0b11000000 | dst
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)
        else:
            assert False, 'Unreachable'
    elif opcode in ['ADDPD', 'ADDPS', 'ADDSD', 'ADDSS', 'ADDSUBPD', 'ADDSUBPS']:
        assert False, 'Not implemented'
    elif opcode == 'ADOX':
        assert False, 'Not implemented'
    elif opcode.startswith('AES'):
        assert False, 'Not implemented'
    elif opcode == 'AND':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            assert tokens[6].value == ','
            if tokens[7].value in REGISTERS8:
                src = REGISTERS8.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | reg
                return b'\x20' + pack('<B', modrm)
            else:
                ib = int(tokens[7].value, base=16)
                modrm = 0b00100000
                return b'\x80' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            assert tokens[6].value == ','
            if tokens[7].value in REGISTERS:
                src = REGISTERS.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | reg
                return b'\x21' + pack('<B', modrm)
            else:
                im = int(tokens[7].value, base=16)
                if im <= 0x7f:
                    modrm = 0b00100000
                    return b'\x83' + pack('<B', modrm) + pack('<B', im)
                else:
                    modrm = 0b00100000 | reg
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000000 | dst << 3 | reg
                return b'\x22' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return b'\x24' + pack('<B', ib)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000000 | dst << 3 | reg
                return b'\x23' + pack('<B', modrm)
            elif tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x23' + pack('<B', modrm)
            else:
                im = int(tokens[3].value, base=16)
                if im <= 0x7f:
                    modrm = 0b11100000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<B', im)
                elif im > 0x7fffffff:
                    im = -((~im & 0xffffffff) + 1)
                    modrm = 0b11100000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<b', im)
                else:
                    if dst == 0b000:
                        return b'\x25' + pack('<I', im)
                    else:
                        modrm = 0b11100000 | dst
                        return b'\x81' + pack('<B', modrm) + pack('<I', im)
        else:
            assert False, 'Unreachable'
    elif opcode.startswith('AND'):
        assert False, 'Not implemented'
    elif opcode == 'ARPL':
        assert False, 'Not implemented'
    elif opcode.startswith('B'):
        assert False, 'Not implemented'
    elif opcode == 'CALL':
        if tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    modrm = 0b01010000 | base
                    return b'\xff' + pack('<B', modrm) + pack('<B', disp)
                else:
                    assert False, 'Not implemented yet'
            else:
                assert tokens[3].value == 'ds'
                assert tokens[4].value == ':'
                disp = int(tokens[5].value, base=16)
                return b'\xff\x15' + pack('<I', disp)
        elif tokens[1].value in REGISTERS:
            # CALL r/m32 (FF /2)
            return b'\xff' + pack('<B', 0b11010000 | REGISTERS.index(tokens[1].value))
        else:
            # CALL rel32 (E8 cd)
            rel = int(tokens[1].value, base=16)
            rel = rel - state['eip'] - 5
            return b'\xe8' + pack('<i', rel)
    elif opcode == 'CDQ':
        return b'\x99'
    elif opcode == 'CLAC':
        return b'\x0f\x01\xca'
    elif opcode == 'CLC':
        return b'\xf8'
    elif opcode == 'CLD':
        return b'\xfc'
    elif opcode == 'CLDEMOTE':
        assert False, 'Not implemented'
    elif opcode.startswith('CLFLUSH'):
        assert False, 'Not implemented'
    elif opcode == 'CLI':
        return b'\xfa'
    elif opcode.startswith('CL'):
        assert False, 'Not implemented'
    elif opcode == 'CMC':
        return b'\xf5'
    elif opcode.startswith('CMOV'):
        assert False, 'Not implemented'
    elif opcode == 'CMP':
        if tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = tokens[4].value
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                ib = int(tokens[9].value, base=16)
                modrm = 0b01111000 | REGISTERS.index(reg)
                return b'\x83' + pack('<B', modrm) + pack('<B', disp) + pack('<B', ib)
            elif tokens[5].value == ']':
                assert tokens[6].value == ','
                imm = int(tokens[7].value, base=16)
                return b'\x83' + pack('<B', 0b00111000 | REGISTERS.index(reg)) + pack('<B', imm)
            else:
                assert False, 'Unreachable'
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                return b'\x3b' + pack('<B', 0b11000000 | dst << 3 | src)
            else:
                im = int(tokens[3].value, base=16)
                if im < 0x7f:
                    modrm = 0b11111000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<B', im)
                elif dst == REGISTERS.index('eax'):
                    return b'\x3d' + pack('<I', im)
                else:
                    modrm = 0b11111000 | dst
                    if im > 0x7fffffff:
                        im = -((~im & 0xffffffff) + 1)
                    elif im >= 0x80:
                        return b'\x81' + pack('<B', modrm) + pack('<I', im)
                    return b'\x83' + pack('<B', modrm) + pack('<b', im)
    elif opcode == 'CMPS':
        assert tokens[1].value == 'BYTE'
        assert tokens[2].value == 'PTR'
        assert tokens[3].value == 'ds'
        assert tokens[4].value == ':'
        assert tokens[5].value == '['
        assert tokens[6].value == 'esi'
        assert tokens[7].value == ']'
        assert tokens[8].value == ','
        assert tokens[9].value == 'BYTE'
        assert tokens[10].value == 'PTR'
        assert tokens[11].value == 'es'
        assert tokens[12].value == ':'
        assert tokens[13].value == '['
        assert tokens[14].value == 'edi'
        assert tokens[15].value == ']'
        return b'\xa6'
    elif opcode.startswith('CMP'):
        assert False, 'Not implemented'
    elif opcode.startswith('COMIS'):
        assert False, 'Not implemented'
    elif opcode == 'CPUID':
        return b'\x0f\xa2'
    elif opcode == 'CRC32':
        assert False, 'Not implemented'
    elif opcode.startswith('CVT'):
        assert False, 'Not implemented'
    elif opcode == 'CWDE':
        return b'\x98'
    elif opcode == 'DAA':
        return b'\x27'
    elif opcode == 'DAS':
        return b'\x2f'
    elif opcode == 'DEC':
        # DEC r32 (48 + rd)
        reg = tokens[1].value
        return pack('<B', 0x48 + REGISTERS.index(reg))
    elif opcode == 'DIV':
        if tokens[1].value in REGISTERS:
            modrm = 0b11110000 | REGISTERS.index(tokens[1].value)
            return b'\xf7' + pack('<B', modrm)
    elif opcode.startswith('DIV'):
        assert False, 'Not implemented'
    elif opcode.startswith('DP'):
        assert False, 'Not implemented'
    elif opcode == 'ENTER':
        assert False, 'Not implemented'
    elif opcode.startswith('E'):
        assert False, 'Not implemented'
    elif opcode == 'F2XM1':
        return b'\xd9\xf0'
    elif opcode == 'FABS':
        return b'\xd9\xe1'
    elif opcode.startswith('FADD'):
        assert False, 'Not implemented'
    elif opcode.startswith('FB'):
        assert False, 'Not implemented'
    elif opcode == 'FCHS':
        return b'\xd9\xe0'
    elif opcode == 'FCLEX':
        return b'\x9b\xdb\xe2'
    elif opcode == 'FNCLEX':
        return b'\xdb\xe2'
    elif opcode.startswith('FCMOV'):
        assert False, 'Not implemented'
    elif opcode.startswith('FCOM'):
        assert False, 'Not implemented'
    elif opcode == 'FCOS':
        return b'\xd9\xff'
    elif opcode == 'FDECSTP':
        return b'\xd9\xf6'
    elif opcode.startswith('FDIV'):
        assert False, 'Not implemented'
    elif opcode == 'FFREE':
        assert False, 'Not implemented'
    elif opcode.startswith('FICOM'):
        assert False, 'Not implemented'
    elif opcode == 'FILD':
        assert False, 'Not implemented'
    elif opcode == 'FINCSTP':
        return b'\xd9\xf7'
    elif opcode == 'FINIT':
        return b'\x9b\xdb\xe3'
    elif opcode == 'FNINIT':
        return b'\xdb\xe3'
    elif opcode.startswith('FIST'):
        assert False, 'Not implemented'
    elif opcode == 'FLD':
        if tokens[1].value == 'st':
            assert tokens[2].value == '('
            i = int(tokens[3].value)
            assert tokens[4].value == ')'
            return b'\xd9' + pack('<B', 0xc0 + i)
        elif tokens[1].value in ['DWORD', 'TBYTE', 'QWORD']:
            op, mod = {
                'DWORD': [b'\xd9', 0],
                'TBYTE': [b'\xdb', 5],
                'QWORD': [b'\xdd', 0],
            }[tokens[1].value]
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                if tokens[4].value in REGISTERS:
                    reg = REGISTERS.index(tokens[4].value)
                    if tokens[5].value == ']':
                        return op + pack('<B', 0x0 + reg)
                    elif tokens[5].value == '+':
                        if tokens[6].value in REGISTERS:
                            idx = REGISTERS.index(tokens[6].value)
                            assert tokens[7].value == '*'
                            scale = {
                                '1': 0b00,
                                '2': 0b01,
                                '4': 0b10,
                                '8': 0b11,
                            }[tokens[8].value]
                            if tokens[9].value == '-':
                                ib = (~int(tokens[10].value, base=16) & 0xff) + 1
                            elif tokens[9].value == '+':
                                ib = int(tokens[10].value, base=16)
                            elif tokens[9].value == ']':
                                modrm = 0b00000100
                                sib = 0b00000000 | scale << 6 | idx << 3 | reg
                                return op + pack('<B', modrm) + pack('<B', sib)
                            modrm = 0b01000100
                            sib = 0b00000000 | scale << 6 | idx << 3 | reg
                            return op + pack('<B', modrm) + pack('<B', sib) + pack('<B', ib)
                        else:
                            disp = int(tokens[6].value, base=16)
                            assert tokens[7].value == ']'
                            if reg == REGISTERS.index('esp'):
                                sib = 0b00100100
                                if disp <= 0x7f:
                                    modrm = 0b01000000 | reg
                                    return op + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                                else:
                                    modrm = 0b10000000 | reg
                                    return op + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                            else:
                                if disp <= 0x7f:
                                    modrm = 0b01000000 | reg | mod << 3
                                    return op + pack('<B', modrm) + pack('<B', disp)
                                else:
                                    modrm = 0b10000000 | reg
                                    return op + pack('<B', modrm) + pack('<I', disp)
                    elif tokens[5].value == '*':
                        scale = {
                            '1': 0b00,
                            '2': 0b01,
                            '4': 0b10,
                            '8': 0b11,
                        }[tokens[6].value]
                        assert tokens[7].value == '+'
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b00000100
                        sib = 0b00000101 | scale << 6
                        return op + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        im = int(tokens[6].value, base=16)
                        #print(ib, hex(ib))
                        if im <= 0xff:
                            im = (~im & 0xff) + 1
                            modrm = 0b01000000 | reg
                            return b'\xd9' + pack('<B', modrm) + pack('<B', im)
                        else:
                            im = (~im & 0xffffffff) + 1
                            return b'\xd9\x81' + pack('<I', im)
                else:
                    assert False, 'Not implemented'
            elif tokens[3].value in SEGMENTS:
                seg = SEGMENTS.index(tokens[3].value)
                assert tokens[4].value == ':'
                modrm = 0b00000101
                im = int(tokens[5].value, base=16)
                return op + pack('<B', modrm) + pack('<I', im)
        else:
            assert False, 'Not implemented'
    elif opcode.startswith('FLD'):
        assert False, 'Not implemented'
    elif opcode.startswith('FMUL'):
        assert False, 'Not implemented'
    elif opcode == 'FNOP':
        return b'\xd9\xd0'
    elif opcode == 'FPATAN':
        return b'\xd9\xf3'
    elif opcode == 'FPREM':
        return b'\xd9\xf8'
    elif opcode == 'FPREM1':
        return b'\xd9\xf5'
    elif opcode == 'FPTAN':
        return b'\xd9\xf2'
    elif opcode == 'FRNDINT':
        return b'\xd9\xfc'
    elif opcode == 'FRSTOR':
        assert False, 'Not implemented'
    elif opcode in ['FSAVE', 'FNSAVE']:
        assert False, 'Not implemented'
    elif opcode == 'FSCALE':
        return b'\xd9\xfd'
    elif opcode == 'FSIN':
        return b'\xd9\xfe'
    elif opcode == 'FSINCOS':
        return b'\xd9\xfb'
    elif opcode == 'FSQRT':
        return b'\xd9\xfa'
    elif opcode.startswith('FST'):
        assert False, 'Not implemented'
    elif opcode.startswith('FSUB'):
        assert False, 'Not implemented'
    elif opcode == 'FTST':
        return b'\xd9\xe4'
    elif opcode.startswith('FUCOM'):
        assert False, 'Not implemented'
    elif opcode == 'FWAIT':
        return b'\x9b'
    elif opcode == 'FXAM':
        return b'\xd9\xe5'
    elif opcode.startswith('FXCH'):
        assert False, 'Not implemented'
    elif opcode.startswith('FX'):
        assert False, 'Not implemented'
    elif opcode == 'FYL2X':
        return b'\xd9\xf1'
    elif opcode == 'FYL2XP1':
        return b'\xd9\xf9'
    elif opcode.startswith('GF'):
        assert False, 'Not implemented'
    elif opcode.startswith('HADDP'):
        assert False, 'Not implemented'
    elif opcode == 'HLT':
        return b'\xf4'
    elif opcode == 'HRESET':
        assert False, 'Not implemented'
    elif opcode.startswith('HSUBP'):
        assert False, 'Not implemented'
    elif opcode == 'IDIV':
        assert False, 'Not implemented'
    elif opcode == 'IMUL':
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        src = REGISTERS.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\xaf' + pack('<B', modrm)
    elif opcode == 'IN':
        assert False, 'Not implemented'
    elif opcode == 'INC':
        if tokens[1].value in REGISTERS:
            return pack('<B', 0x40 + REGISTERS.index(tokens[1].value))
        else:
            assert False, 'Not implemented'
    elif opcode.startswith('INCSS'):
        assert False, 'Not implemented'
    elif opcode.startswith('INS'):
        assert False, 'Not implemented'
    elif opcode == 'INT':
        ib = int(tokens[1].value, base=16).to_bytes(1, 'little')
        return b'\xcd' + ib
    elif opcode == 'INT1':
        return b'\xf1'
    elif opcode == 'INT3':
        return b'\xcc'
    elif opcode == 'INTO':
        return b'\xce'
    elif opcode == 'INVD':
        return b'\x0f\x08'
    elif opcode.startswith('INV'):
        assert False, 'Not implemented'
    elif opcode == 'IRET':
        return b'\xcf'
    elif opcode in [
        'JO', 'JNO', 'JB', 'JAE', 'JE', 'JNE', 'JBE', 'JA',
        'JS', 'JNS', 'JP', 'JNP', 'JL', 'JGE', 'JLE', 'JG'
    ]:
        op = {
            'JO':  b'\x70', 'JNO': b'\x71', 'JB':  b'\x72', 'JAE': b'\x73',
            'JE':  b'\x74', 'JNE': b'\x75', 'JBE': b'\x76', 'JA':  b'\x77',
            'JS':  b'\x78', 'JNS': b'\x79', 'JP':  b'\x7a', 'JNP': b'\x7b',
            'JL':  b'\x7c', 'JGE': b'\x7d', 'JLE': b'\x7e', 'JG':  b'\x7f',
        }[opcode]
        rel = int(tokens[1].value, base=16)
        rel = rel - state['eip'] - 2
        if rel > 0x7f or rel < -0x80:
            rel -= 4
            return b'\x0f' + pack('<B', op[0] + 0x10) + pack('<i', rel)
        else:
            return op + pack('<b', rel)
    elif opcode == 'JMP':
        rel = int(tokens[1].value, base=16)
        rel = rel - state['eip'] - 2
        if rel > 0x7f or rel < -0x80:
            rel -= 3
            return b'\xe9' + pack('<I', rel)
        else:
            return b'\xeb' + pack('<b', rel)
    elif opcode.startswith('K'):
        assert False, 'Not implemented'
    elif opcode == 'LAHF':
        return b'\x9f'
    elif opcode == 'LAR':
        assert False, 'Not implemented'
    elif opcode.startswith('LD'):
        assert False, 'Not implemented'
    elif opcode == 'LEA':
        # LEA r32,m (8D /r)
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        assert tokens[3].value == '['
        base = tokens[4].value
        #assert tokens[4].value == 'ebp'
        if tokens[5].value == '-':
            disp = -int(tokens[6].value, base=16)
        elif tokens[5].value == '+':
            if tokens[6].value in REGISTERS:
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '*'
                scale = {
                    '1': 0b00,
                    '2': 0b01,
                    '4': 0b10,
                    '8': 0b11,
                }[tokens[8].value]
                modrm = 0b00000100 | dst << 3
                sib = 0b00000000 | scale << 6 | reg << 3 | REGISTERS.index(base)
                return b'\x8d' + pack('<B', modrm) + pack('<B', sib)
            else:
                disp = int(tokens[6].value, base=16)
        elif tokens[5].value == '*':
            scale = {
                '1': 0b00,
                '2': 0b01,
                '4': 0b10,
                '8': 0b11,
            }[tokens[6].value]
            assert tokens[7].value == '+'
            modrm = 0b00000100 | dst << 3
            sib = 0b00000101 | scale << 6 | REGISTERS.index(base) << 3
            disp = int(tokens[8].value, base=16)
            return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
        else:
            assert False, 'Unreachable'

        if base == 'esp':
            modrm = 0b01000100 | dst << 3
            sib = 0b00100000 | REGISTERS.index(base)
            return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<b', disp)
        else:
            modrm = 0b01000000 | dst << 3 | REGISTERS.index(base)
            return b'\x8d' + pack('<B', modrm) + pack('<b', disp)
    elif opcode == 'LEAVE':
        return b'\xc9'
    elif opcode == 'LFENCE':
        return b'\x0f\xae\xe8'
    elif opcode in ['LGDT', 'LIDT', 'LLDT', 'LMSW', 'LOADIWKEY']:
        assert False, 'Not implemented'
    elif opcode.startswith('LODS'):
        assert False, 'Not implemented'
    elif opcode.startswith('LOOP'):
        assert False, 'Not implemented'
    elif opcode in ['LSL', 'LTR', 'LZCNT']:
        assert False, 'Not implemented'
    elif opcode.startswith('MASK'):
        assert False, 'Not implemented'
    elif opcode.startswith('MAX'):
        assert False, 'Not implemented'
    elif opcode == 'MFENCE':
        return b'\x0f\xae\xf0'
    elif opcode.startswith('MIN'):
        assert False, 'Not implemented'
    elif opcode == 'MONITOR':
        return b'\x0f\x01\xc8'
    elif opcode == 'MOV':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            if tokens[5].value in ['+', '-']:
                sign = tokens[5].value
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = {
                        '1': 0b00,
                        '2': 0b01,
                        '4': 0b10,
                        '8': 0b11,
                    }[tokens[8].value]
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    ib = int(tokens[11].value, base=16)
                    modrm = 0b00000100
                    sib = 0b00000000 | scale << 6 | idx << 3 | reg
                    return b'\xc6' + pack('<B', modrm) + pack('<B', sib) + pack('<B', ib)
                else:
                    disp = int(tokens[6].value, base=16)
                    if sign == '-':
                        disp = ~(disp & 0xff) + 1
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[9].value)
                        modrm = 0b10000100 | src << 3
                        sib = 0b00100000 | reg
                        if disp < 0xff:
                            modrm = 0b01000000 | src << 3 | reg
                            return b'\x88' + pack('<B', modrm) + pack('<B', disp)
                        else:
                            return b'\x88' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        ib = int(tokens[9].value, base=16)
                        if reg == REGISTERS.index('esp'):
                            modrm = 0b01000000 | reg
                            sib = 0b00100100
                            return b'\xc6' + pack('<B', modrm) + pack('<B', sib) + pack('<b', disp) + pack('<B', ib)
                        else:
                            modrm = 0b01000000 | reg
                            return b'\xc6' + pack('<B', modrm) + pack('<b', disp) + pack('<B', ib)
            else:
                assert tokens[5].value == ']'
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[7].value)
                    modrm = 0b000000000 | src << 3 | reg
                    return b'\x88' + pack('<B', modrm)
                else:
                    ib = int(tokens[7].value, base=16)
                    modrm = 0b000000000 | reg
                    return b'\xc6' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                reg = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS:
                        src = REGISTERS.index(tokens[7].value)
                        modrm = 0b000000000 | src << 3 | reg
                        return b'\x89' + pack('<B', modrm)
                    else:
                        im = int(tokens[7].value, base=16)
                        modrm = 0b000000000 | reg
                        return b'\xc7' + pack('<B', modrm) + pack('<I', im)
                elif tokens[5].value == '-':
                    disp = -int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b01000000 | src << 3 | reg
                        return b'\x89' + pack('<B', modrm) + pack('<b', disp)
                    else:
                        modrm = 0b01000000 | reg
                        im = int(tokens[9].value, base=16)
                        return b'\xc7' + pack('<B', modrm) + pack('<b', disp) + pack('<I', im)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = {
                            '2': 0b01,
                            '4': 0b10,
                            '8': 0b11,
                        }[tokens[8].value]
                        assert tokens[9].value == ']'
                        assert tokens[10].value == ','
                        src = REGISTERS.index(tokens[11].value)
                        modrm = 0b00000100 | src << 3
                        sib = 0b000000000 | scale << 6 | idx << 3 | reg
                        return b'\x89' + pack('<B', modrm) + pack('<B', sib)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            modrm = 0b01000000 | src << 3 | reg
                            if reg == REGISTERS.index('esp'):
                                sib = 0b00100100
                                if disp > 0xff:
                                    modrm = 0b10000000 | src << 3 | reg
                                    disp = pack('<I', disp)
                                else:
                                    disp = pack('<B', disp)
                                return b'\x89' + pack('<B', modrm) + pack('<B', sib) + disp
                            else:
                                return b'\x89' + pack('<B', modrm) + pack('<b', disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            sib = 0b00100100
                            if disp <= 0xff:
                                modrm = 0b01000100
                                return b'\xc7' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp) + pack('<I', im)
                            else:
                                modrm = 0b10000100
                                return b'\xc7' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp) + pack('<I', im)
                elif tokens[5].value == '*':
                    scale = {
                        '0': 0b00,
                        '2': 0b01,
                        '4': 0b10,
                        '8': 0b11,
                    }[tokens[6].value]
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    if tokens[11].value in REGISTERS:
                        src = REGISTERS.index(tokens[11].value)
                        modrm = 0b00000100 | src << 3
                        sib = 0b00000101 | scale << 6 | reg << 3
                        return b'\x89' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        assert False, 'Unreachable'
                else:
                    assert False, 'Unreachable'
            elif tokens[3].value in SEGMENTS:
                seg = {
                    'es': b'\x26',
                    'ss': b'\x36',
                    'fs': b'\x64',
                    'gs': b'\x65',
                    'cs': b'\x2e',
                    'ds': b'',
                    #'ds': b'\x3e',
                }[tokens[3].value]
                assert tokens[4].value == ':'
                off = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS:
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return seg + b'\x89' + pack('<B', modrm) + pack('<I', off)
                else:
                    modrm = 0b00000101
                    im = int(tokens[7].value, base=16)
                    return seg + b'\xc7' + pack('<B', modrm) + pack('<I', off) + pack('<I', im)
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            reg = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            assert tokens[6].value == ','
            seg = SEGMENTS.index(tokens[7].value)
            modrm = 0b00000000 | seg << 3 | reg
            return b'\x8c' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | reg
                    return b'\x8a' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    disp8 = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b01000000 | dst << 3 | reg
                    return b'\x8a' + pack('<B', modrm) + pack('<B', disp8)
                else:
                    assert False, 'Not implemented yet'
            elif tokens[3].value in SEGMENTS:
                seg = {
                    'es': b'\x26',
                    'ss': b'\x36',
                    'fs': b'\x64',
                    'gs': b'\x65',
                    'cs': b'\x2e',
                    'ds': b'',
                    #'ds': b'\x3e',
                }[tokens[3].value]
                assert tokens[4].value == ':'
                off = int(tokens[5].value, base=16)
                return seg + b'\xa0' + pack('<I', off)
            elif tokens[3].value in REGISTERS8:
                modrm = 0b11000000 | dst << 3 | REGISTERS8.index(tokens[3].value)
                return b'\x8a' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return pack('<B', 0xb0 + dst) + pack('<B', ib)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == '[':
                    reg = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | reg
                        return b'\x8b' + pack('<B', modrm)
                    elif tokens[7].value == '-':
                        disp = -int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | reg
                        if reg == REGISTERS.index('esp'):
                            assert False, 'Unreachable'
                        else:
                            return b'\x8b' + pack('<B', modrm) + pack('<b', disp)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = {
                                '2': 0b01,
                                '4': 0b10,
                                '8': 0b11,
                            }[tokens[10].value]
                            assert tokens[11].value == ']'
                            modrm = 0b00000100 | dst << 3
                            sib = 0b000000000 | scale << 6 | idx << 3 | reg
                            return b'\x8b' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b01000000 | dst << 3 | reg
                            if reg == REGISTERS.index('esp'):
                                sib = 0b00100100
                                return b'\x8b' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                            else:
                                return b'\x8b' + pack('<B', modrm) + pack('<b', disp)
                    elif tokens[7].value == '*':
                        scale = {
                            '1': 0b00,
                            '2': 0b01,
                            '4': 0b10,
                            '8': 0b11,
                        }[tokens[8].value]
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000101 | scale << 6 | reg << 3
                        return b'\x8b' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        assert False, 'Unreachable'
                elif tokens[5].value in SEGMENTS:
                    seg = {
                        'es': b'\x26',
                        'ss': b'\x36',
                        'fs': b'\x64',
                        'gs': b'\x65',
                        'cs': b'\x2e',
                        'ds': b'',
                        #'ds': b'\x3e',
                    }[tokens[5].value]
                    assert tokens[6].value == ':'
                    im = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return seg + b'\x8b' + pack('<B', modrm) + pack('<I', im)
                else:
                    assert False, 'Unreachable'
            elif tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x8b' + pack('<B', modrm)
            elif tokens[3].value in SEGMENTS:
                seg = {
                    'es': b'\x26',
                    'ss': b'\x36',
                    'fs': b'\x64',
                    'gs': b'\x65',
                    'cs': b'\x2e',
                    'ds': b'',
                    #'ds': b'\x3e',
                }[tokens[3].value]
                assert tokens[4].value == ':'
                off = int(tokens[5].value, base=16)
                return seg + b'\xa1' + pack('<I', off)
            else:
                im = int(tokens[3].value, base=16)
                return pack('<B', 0xb8 + dst) + pack('<I', im)
        elif tokens[1].value in SEGMENTS:
            seg = SEGMENTS.index(tokens[1].value)
            if tokens[2].value == ',':
                assert tokens[3].value == 'WORD'
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                reg = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000000 | seg << 3 | reg
                return b'\x8e' + pack('<B', modrm)
            elif tokens[2].value == ':':
                seg = {
                    'es': b'\x26',
                    'ss': b'\x36',
                    'fs': b'\x64',
                    'gs': b'\x65',
                    'cs': b'\x2e',
                    'ds': b'',
                    #'ds': b'\x3e',
                }[tokens[1].value]
                off = int(tokens[3].value, base=16)
                assert tokens[4].value == ','
                if tokens[5].value == 'al':
                    return seg + b'\xa2' + pack('<I', off)
                elif tokens[5].value == 'eax':
                    return seg + b'\xa3' + pack('<I', off)
                else:
                    assert False, 'Unreachable'
    elif opcode == 'MOVZX':
        return b'\x0f\xb7\x45\xd4'
    elif opcode == 'MOVS':
        return b'\xa5'
    elif opcode == 'MOVSX':
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        assert tokens[3].value == 'BYTE'
        assert tokens[4].value == 'PTR'
        assert tokens[5].value == '['
        reg = REGISTERS.index(tokens[6].value)
        assert tokens[7].value == ']'
        modrm = 0b00000000 | dst << 3 | reg
        return b'\x0f\xbe' + pack('<B', modrm)
    elif opcode.startswith('MOV'):
        assert False, 'Not implemented'
    elif opcode == 'MPSADBW':
        assert False, 'Not implemented'
    elif opcode == 'MUL':
        assert False, 'Not implemented'
    elif opcode.startswith('MUL'):
        assert False, 'Not implemented'
    elif opcode == 'MWAIT':
        return b'\x0f\x01\xc9'
    elif opcode == 'NEG':
        assert False, 'Not implemented'
    elif opcode == 'NOP':
        return b'\x90'
    elif opcode == 'NOT':
        if tokens[1].value in REGISTERS:
            reg = REGISTERS.index(tokens[1].value)
            return b'\xf7' + pack('<B', 0b11010000 | reg)
        else:
            assert False, 'Not implemented'
    elif opcode == 'OR':
        return b'\x83\xc9\xff'
    elif opcode.startswith('OR'):
        assert False, 'Not implemented'
    elif opcode == 'OUT':
        assert False, 'Not implemented'
    elif opcode.startswith('OUTS'):
        assert False, 'Not implemented'
    elif opcode.startswith('PABS'):
        assert False, 'Not implemented'
    elif opcode.startswith('PACK'):
        assert False, 'Not implemented'
    elif opcode.startswith('PADD'):
        assert False, 'Not implemented'
    elif opcode == 'PALIGNR':
        assert False, 'Not implemented'
    elif opcode in ['PAND', 'PANDN']:
        assert False, 'Not implemented'
    elif opcode == 'PAUSE':
        return b'\xf3\x90'
    elif opcode in ['PAVGB', 'PAVGW', 'PBLENDVB', 'PBLENDW', 'PCLMULQDQ', '']:
        assert False, 'Not implemented'
    elif opcode.startswith('PCMP'):
        assert False, 'Not implemented'
    elif opcode == 'PCONFIG':
        return b'\x0f\x01\xc5'
    elif opcode == 'PDEP':
        assert False, 'Not implemented'
    elif opcode.startswith('PEXT'):
        assert False, 'Not implemented'
    elif opcode.startswith('PH'):
        assert False, 'Not implemented'
    elif opcode.startswith('PINS'):
        assert False, 'Not implemented'
    elif opcode.startswith('PM'):
        assert False, 'Not implemented'
    elif opcode == 'POP':
        assert len(tokens) == 2
        if tokens[1].value in REGISTERS:
            reg = REGISTERS.index(tokens[1].value)
            return pack('<B', 0x58 + reg)
    elif opcode == 'POPA':
        return b'\x61'
    elif opcode == 'POPCNT':
        assert False, 'Not implemented'
    elif opcode == 'POPF':
        return b'\x9d'
    elif opcode == 'POR':
        assert False, 'Not implemented'
    elif opcode.startswith('PREFETCH'):
        assert False, 'Not implemented'
    elif opcode.startswith('PS'):
        assert False, 'Not implemented'
    elif opcode.startswith('PT'):
        assert False, 'Not implemented'
    elif opcode.startswith('PUNPCK'):
        assert False, 'Not implemented'
    elif opcode == 'PUSH':
        if tokens[1].value in REGISTERS:
            reg = REGISTERS.index(tokens[1].value)
            return pack('<B', 0x50 + reg)
        elif tokens[1].token_type == 'literal':
            imm = int(tokens[1].value, base=16)
            if (imm >= 0xffffff80 and imm <= 0xffffffff) or (imm >= 0x0 and imm <= 0x7f):
                return b'\x6a' + pack('<B', imm & 0xff)
            else:
                return b'\x68' + pack('<I', imm)
        elif tokens[1].value == 'DWORD':
            return b'\xff\x75\x9c'
    elif opcode == 'PUSHA':
        return b'\x60'
    elif opcode == 'PUSHF':
        return b'\x9c'
    elif opcode == 'PXOR':
        assert False, 'Not implemented'
    elif opcode in ['RCL', 'RCR', 'ROL', 'ROR']:
        assert False, 'Not implemented'
    elif opcode.startswith('RCP'):
        assert False, 'Not implemented'
    elif opcode in ['RDFSBASE', 'RDGSBASE']:
        assert False, 'Not implemented'
    elif opcode == 'RDMSR':
        return b'\x0f\x32'
    elif opcode == 'RDPID':
        assert False, 'Not implemented'
    elif opcode == 'RDPKRU':
        return b'\x0f\x01\xee'
    elif opcode == 'RDPMC':
        return b'\x0f\x33'
    elif opcode == 'RDRAND':
        assert False, 'Not implemented'
    elif opcode == 'RDSEED':
        assert False, 'Not implemented'
    elif opcode.startswith('RDSSP'):
        assert False, 'Not implemented'
    elif opcode == 'RDTSC':
        return b'\x0f\x31'
    elif opcode == 'RDTSCP':
        return b'\x0f\x01\xf9'
    elif opcode == 'REPNZ':
        rem = ' '.join(map(lambda x: x.value, tokens[1:]))
        return b'\xf2' + assemble(rem, state)
    elif opcode == 'REPZ':
        rem = ' '.join(map(lambda x: x.value, tokens[1:]))
        return b'\xf3' + assemble(rem, state)
    elif opcode.startswith('REP'):
        rem = ' '.join(map(lambda x: x.value, tokens[1:]))
        return b'\xf3' + assemble(rem, state)
    elif opcode == 'RET':
        if len(tokens) > 1:
            iw = int(tokens[1].value, base=16)
            return b'\xc2' + pack('<H', iw)
        else:
            return b'\xc3'
    elif opcode == 'RETF':
        return b'\xcb'
    elif opcode.startswith('RO'):
        assert False, 'Not implemented'
    elif opcode == 'RSM':
        return b'\x0f\xaa'
    elif opcode.startswith('RS'):
        assert False, 'Not implemented'
    elif opcode == 'SAHF':
        return b'\x9e'
    elif opcode == 'SAL':
        assert False, 'Not implemented'
    elif opcode == 'SAR':
        if tokens[1].value in REGISTERS:
            # SAR r/m32, imm8 (C1 /r7 ib)
            assert tokens[2].value == ','
            imm = int(tokens[3].value, base=16)
            modrm = 0b11111000 + REGISTERS.index(tokens[1].value)
            if imm == 1:
                return b'\xd1' + pack('<B', modrm)
            else:
                return b'\xc1' + pack('<B', modrm) + pack('<B', imm)
    elif opcode == 'SHL':
        if tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS8:
                # SHL r/m32, CL (D3 /4)
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11100000 | dst
                return b'\xd3' + pack('<B', modrm)
            else:
                # SHL r/m32, imm8 (C1 /4 ib)
                imm = int(tokens[3].value, base=16)
                modrm = 0b11100000 + REGISTERS.index(tokens[1].value)
                return b'\xc1' + pack('<B', modrm) + pack('<B', imm)
    elif opcode == 'SHR':
        if tokens[1].value in REGISTERS:
            # SHR r/m32, imm8 (C1 /r5 ib)
            assert tokens[2].value == ','
            imm = int(tokens[3].value, base=16)
            if imm == 1:
                modrm = 0b11101000 | REGISTERS.index(tokens[1].value)
                return b'\xd1' + pack('<B', modrm)
            else:
                modrm = 0b11101000 + REGISTERS.index(tokens[1].value)
                return b'\xc1' + pack('<B', modrm) + pack('<B', imm)
    elif opcode in ['SARX', 'SHLX', 'SHRX']:
        assert False, 'Not implemented'
    elif opcode == 'SAVEPREVSSP':
        return b'\xf3\x0f\x01\xea'
    elif opcode == 'SBB':
        assert False, 'Not implemented'
    elif opcode.startswith('SCAS'):
        return b'\xae'
    elif opcode == 'SERIALIZE':
        return b'\x0f\x01\xe8'
    elif opcode.startswith('SET'):
        assert False, 'Not implemented'
    elif opcode == 'SFENCE':
        return b'\x0f\xae\xf8'
    elif opcode == 'SGDT':
        assert False, 'Not implemented'
    elif opcode.startswith('SH'):
        assert False, 'Not implemented'
    elif opcode in ['SIDT', 'SLDT', 'SMSW']:
        assert False, 'Not implemented'
    elif opcode.startswith('SQRT'):
        assert False, 'Not implemented'
    elif opcode == 'STAC':
        return b'\x0f\x01\xcb'
    elif opcode == 'STC':
        return b'\xf9'
    elif opcode == 'STD':
        return b'\xfd'
    elif opcode == 'STI':
        return b'\xfb'
    elif opcode.startswith('ST'):
        assert False, 'Not implemented'
    elif opcode == 'SUB':
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERS:
            src = REGISTERS.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x2b' + pack('<B', modrm)
        else:
            imm = int(tokens[3].value, base=16)
            if imm <= 0x7f:
                return b'\x83' + pack('<B', 0b11101000 | dst) + pack('<B', imm)
            else:
                return b'\x81' + pack('<B', 0b11101000 | dst) + pack('<I', imm)
    elif opcode.startswith('SUB'):
        assert False, 'Not implemented'
    elif opcode == 'SWAPGS':
        return b'\x0f\x01\xf8'
    elif opcode == 'SYSCALL':
        return b'\x0f\x05'
    elif opcode == 'SYSENTER':
        return b'\x0f\x34'
    elif opcode == 'SYSEXIT':
        return b'\x0f\x35'
    elif opcode == 'SYSRET':
        return b'\x0f\x07'
    elif opcode == 'TEST':
        if tokens[1].value == 'BYTE':
            # TEST r/m8, imm8 (F6 /0 ib)
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            if tokens[4].value == 'ebp':
                assert tokens[5].value == '-'
                disp = -int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                ib = int(tokens[9].value, base=16)
                modrm = 0b01000101
                return b'\xf6' + pack('<B', modrm) + pack('<b', disp) + pack('<B', ib)
            else:
                assert tokens[5].value == '+'
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                ib = int(tokens[9].value, base=16)
                modrm = 0b01000100
                sib = 0b00100100
                return b'\xf6' + pack('<B', modrm) + pack('<B', sib) + pack('<b', disp) + pack('<B', ib)
        elif tokens[1].value in REGISTERS8:
            # TEST r/m8, r8 (84 /r)
            rm8 = REGISTERS8.index(tokens[1].value)
            r8 = REGISTERS8.index(tokens[3].value)
            modrm = 0b11000000 | r8 << 3 | rm8
            return b'\x84' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS:
            # TEST r/m32, r32 (85 /r)
            rm32 = REGISTERS.index(tokens[1].value)
            r32 = REGISTERS.index(tokens[3].value)
            modrm = 0b11000000 | r32 << 3 | rm32
            return b'\x85' + pack('<B', modrm)
    elif opcode == 'TPAUSE':
        assert False, 'Not implemented'
    elif opcode == 'TZCNT':
        assert False, 'Not implemented'
    elif opcode.startswith('UCOMIS'):
        assert False, 'Not implemented'
    elif opcode.startswith('UD'):
        assert False, 'Not implemented'
    elif opcode == 'UMONITOR':
        assert False, 'Not implemented'
    elif opcode == 'UMWAIT':
        assert False, 'Not implemented'
    elif opcode.startswith('UNPCK'):
        assert False, 'Not implemented'
    elif opcode == 'VZEROALL':
        return b'\xc5\xfc\x77'
    elif opcode == 'VZEROUPPER':
        return b'\xc5\xf8\x77'
    elif opcode.startswith('V'):
        assert False, 'Not implemented'
    elif opcode == 'XLAT':
        return b'\xd7'
    elif opcode in ['WAIT', 'FWAIT']:
        return b'\x9b'
    elif opcode == 'WBINVD':
        return b'\x0f\x09'
    elif opcode == 'WBNOINVD':
        return b'\xf3\x0f\x09'
    elif opcode in ['WRFSBASE', 'WRGSBASE']:
        assert False, 'Not implemented'
    elif opcode == 'WRMSR':
        return b'\x0f\x30'
    elif opcode == 'WRPKRU':
        return b'\x0f\x01\xef'
    elif opcode.startswith('WR'):
        assert False, 'Not implemented'
    elif opcode == 'XACQUIRE':
        return b'\xf2'
    elif opcode == 'XRELEASE':
        return b'\xf3'
    elif opcode == 'XABORT':
        assert False, 'Not implemented'
    elif opcode == 'XADD':
        assert False, 'Not implemented'
    elif opcode == 'XBEGIN':
        assert False, 'Not implemented'
    elif opcode == 'XCHG':
        assert False, 'Not implemented'
    elif opcode == 'XEND':
        return b'\x0f\x01\xd5'
    elif opcode == 'XGETBV':
        return b'\x0f\x01\xd0'
    elif opcode in ['XLAT', 'XLATB']:
        assert False, 'Not implemented'
    elif opcode == 'XOR':
        dst = tokens[1].value
        assert tokens[2].value == ','
        src = tokens[3].value
        assert src.lower() in REGISTERS
        assert dst.lower() in REGISTERS
        modrm = 0b11000000 | REGISTERS.index(src.lower()) << 3 | REGISTERS.index(dst.lower())
        return b'\x33' + pack('<B', modrm)
    elif opcode in ['XORPD', 'XORPS', 'XRSTOR', 'XRSTORS', 'XSAVE', 'XSAVEC', 'XSAVEOPT', 'XSAVES']:
        assert False, 'Not implemented'
    elif opcode == 'XSETBV':
        return b'\x0f\x01\xd1'
    elif opcode == 'XTEST':
        return b'\x0f\x01\xd6'

    return b''

def link():
    code = assemble('mov eax, 1', {})
    code += assemble('mov ebx, 0', {})
    code += assemble('int 0x80', {})

    elf_hdr_sz = 52
    prg_hdr_sz = 32
    sct_hdr_sz = 40
    base  = 0x8048000
    entry = base + elf_hdr_sz + prg_hdr_sz
    code_sz = len(code)
    data_sz = 0
    seg_sz  = elf_hdr_sz + prg_hdr_sz + code_sz + data_sz

    # ELF constants
    ELFCLASS32      = pack('<B', 1)
    ELFCLASS64      = pack('<B', 2)
    ELFDATA2LSB     = pack('<B', 1)
    #EV_CURRENT      = pack('<B', 1)
    ELFOSABI_SYSV   = pack('<B', 0)
    ELFOSABI_LINUX  = pack('<B', 3)
    ET_EXEC         = pack('<H', 2)
    EM_386          = pack('<H', 3)
    EM_ARM          = pack('<H', 40)
    EM_X86_64       = pack('<H', 62)
    EM_AARCH64      = pack('<H', 183)
    #EV_CURRENT      = pack('<I', 1)
    PT_LOAD         = pack('<I', 1)

    b = b''
    # ELF Header
    # e_ident
    b += b'\x7fELF'             # EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3
    b += ELFCLASS32             # EI_CLASS:         ELFCLASS32 (1) / ELFCLASS64
    b += ELFDATA2LSB            # EI_DATA:          ELFDATA2LSB (1)
    b += b'\x01'                # EI_VERSION:       EV_CURRENT (1)
    b += ELFOSABI_LINUX         # EI_OSABI:         ELFOSABI_SYSV (0) / ELFOSABI_LINUX (3)
    b += b'\x00'                # EI_ABIVERSION:    0
    b += b'\x00' * 7            # EI_PAD

    b += ET_EXEC                # e_type:       ET_NONE (0) / ET_REL (1) / ET_EXEC (2) / ET_DYN (3) / ET_CORE (4)
    b += EM_386                 # e_machine:    EM_386 (3) / EM_ARM (40) / EM_X86_64 (62) / EM_AARCH64 (183)
    b += pack('<I', 1)          # e_version:    EV_CURRENT (1)
    b += pack('<I', entry)      # e_entry:      Entry point address: 0x8048054
    b += pack('<I', elf_hdr_sz) # e_phoff:      Start of program headers: Elf32_Ehdr (52), Elf64_Ehdr(64)
    b += pack('<I', 0)          # e_shoff:      Start of section headers: 0
    b += pack('<I', 0)          # flags
    b += pack('<H', elf_hdr_sz) # e_ehsize:     Size of this header: Elf32_Ehdr (52), Elf64_Ehdr(64)
    b += pack('<H', prg_hdr_sz) # e_phentsize:  Size of program headers: Elf32_Phdr (32), Elf64_Phdr (56)
    b += pack('<H', 1)          # e_phnum:      Number of program headers: 1
    b += pack('<H', sct_hdr_sz) # e_shentsize:  Size of section headers: Elf32_Shdr (40), Elf64_Shdr (64)
    b += pack('<H', 0)          # e_shnum:      Number of section headers: 0 (1)
    b += pack('<H', 0)          # e_shstrndx:   Section header string table index: 0 = SHN_UNDEF

    # Section Headers (Overlapping with ELF Header ...)
    # sh_name
    # sh_type
    # sh_flags
    # sh_addr
    # sh_offset
    # sh_size
    # sh_link
    # sh_info
    # sh_addralign
    # sh_entsize

    # Program Headers
    b += PT_LOAD                # p_type    (Type:     LOAD)
    b += pack('<I', 0)          # p_offset  (Offset:   0)
    b += pack('<I', base)       # p_vaddr   (VirtAddr: 0x08048000)
    b += pack('<I', base)       # p_paddr   (PhysAddr: 0x08048000)
    b += pack('<I', seg_sz)     # p_filesz  (FileSize: 0x7c)
    b += pack('<I', seg_sz)     # p_memsz   (MemSize:  0x7c)
    b += pack('<I', 5)          # p_flags   (Flags:    R-X)
    b += pack('<I', 0x1000)     # p_align   (Align:    0x1000)

    # Assembled code goes here!
    b += code

    # Static data goes here!

    return b

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
