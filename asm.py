#!/usr/bin/env python3

import sys

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
    return {'v': REGISTERS, 'w': REGISTERS16, 'b': REGISTERS8}[s]

def get_ptr(s):
    return {'v': 'DWORD PTR', 'w': 'WORD PTR', 'b': 'BYTE PTR'}[s]

def get_imm(raw, i, state):
    if 'op_size' in state and state['op_size'] == 1:
        state['eip'] += 2
        return hex(int.from_bytes(raw[:2], 'little'))
    end = {'v': 4, 'z': 4, 'w': 2, 'b': 1}[i]
    state['eip'] += end
    return hex(int.from_bytes(raw[:end], 'little'))

def modrm_op(raw, op, state):
    mod, reg, rm = modrm(raw[0])
    if op[0] == 'E':
        if mod == 0b00:
            if rm != 0b100 and rm != 0b101:
                return f'{get_ptr(op[1])} [{get_regs("v", state)[rm]}]'
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
                return f'{get_ptr(op[1])} [{sib_str(scale, idx, base)}{disp}]'
            elif rm == 0b101:
                disp32 = int.from_bytes(raw[1:5], 'little')
                state['eip'] += 4
                return f'{get_ptr(op[1])} ds:{hex(disp32)}'
        elif mod == 0b01:
            if rm != 0b100:
                disp = hex(sign_extend(raw[1], 8, unsigned=False))
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                state['eip'] += 1
                return f'{get_ptr(op[1])} [{get_regs("v", state)[rm]}{disp}]'
            elif rm == 0b100:
                scale, idx, base = sib(raw[1])
                state['eip'] += 1
                disp = hex(sign_extend(raw[2], 8, unsigned=False))
                state['eip'] += 1
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                return f'{get_ptr(op[1])} [{sib_str(scale, idx, base)}{disp}]'
        elif mod == 0b10:
            if rm != 0b100:
                disp = hex(int.from_bytes(raw[1:5], 'little'))
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                state['eip'] += 4
                return f'{get_ptr(op[1])} [{get_regs("v", state)[rm]}{disp}]'
            elif rm == 0b100:
                scale, idx, base = sib(raw[1])
                state['eip'] += 1
                if base == 0b101:
                    assert False, 'Not implemented yet'
                disp = hex(int.from_bytes(raw[2:6], 'little'))
                state['eip'] += 4
                if disp.startswith('0x'):
                    disp = f'+{disp}'
                return f'{get_ptr(op[1])} [{sib_str(scale, idx, base)}{disp}]'
        elif mod == 0b11:
            return get_regs(op[1], state)[rm]
    elif op[0] == 'G':
        return get_regs(op[1], state)[reg]

def modrm_dst_src(raw, dst, src, state):
    mod, reg_op, rm = modrm(raw[0])
    state['eip'] += 1

    dst = modrm_op(raw, dst, state) # eax
    src = modrm_op(raw, src, state) # BYTE PTR [ebp-0x4]
    return f'{dst}, {src}'

    if mod == 0b00:
        assert False, 'Not implemented yet!'
    elif mod == 0b01:
        dst = modrm_dst(raw, dst, state) # eax
        src = modrm_src(raw, src, state) # BYTE PTR [ebp-0x4]
        return f'{dst}, {src}'
    elif mod == 0b10:
        assert False, 'Not implemented yet!'
    elif mod == 0b11:
        if dst.startswith('E'):
            return f'{dst_regs[rm]}, {src_regs[reg_op]}'
        elif dst.startswith('G'):
            return f'{dst_regs[reg_op]}, {src_regs[rm]}'

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
            pass
        elif lo == 2:
            pass
        elif lo == 3:
            pass
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
    elif hi == 1:
        pass
    elif hi == 2:
        pass
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
        pass
    elif hi == 5:
        pass
    elif hi == 6:
        pass
    elif hi == 7:
        pass
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
            state['eip'] += 1
            addr = modrm_dst_src(raw[1:], 'Ev', 'Gv', state)
            return f'BT {addr}'
        elif lo == 4:
            state['eip'] += 1
            addr = modrm_dst_src(raw[1:], 'Ev', 'Gv', state)
            imm8 = get_imm(raw[2:], 'b', state)
            return f'SHLD {addr}, {imm8}'
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
            state['eip'] += 1
            addr = modrm_dst_src(raw[1:], 'Ev', 'Gv', state)
            return f'BTS {addr}'
        elif lo == 0xd:
            inst = disassemble_ev_gv(raw, 'SHRD', state)
            return f'{inst}, cl'
        elif lo == 0xf:
            ops = modrm_dst_src(raw[1:], 'Gv', 'Ev', state)
            state['eip'] += 1
            return f'IMUL {ops}'
    elif hi == 0xb:
        if lo == 0:
            pass
        elif lo == 6:
            ops = modrm_dst_src(raw[1:], 'Gv', 'Eb', state)
            state['eip'] += 1
            return f'MOVZX {ops}'
        elif lo == 7:
            ops = modrm_dst_src(raw[1:], 'Gv', 'Ew', state)
            state['eip'] += 1
            return f'MOVZX {ops}'
        elif lo == 0xe:
            ops = modrm_dst_src(raw[1:], 'Gv', 'Eb', state)
            state['eip'] += 1
            return f'MOVSX {ops}'
        elif lo == 0xf:
            ops = modrm_dst_src(raw[1:], 'Gv', 'Ew', state)
            state['eip'] += 1
            return f'MOVSX {ops}'
    elif hi == 0xc:
        pass
    elif hi == 0xd:
        pass
    elif hi == 0xe:
        pass
    elif hi == 0xf:
        pass

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

    prefix = state['prefix']

    opcode = raw[0]
    hi = (opcode & 0xF0) >> 4
    lo = (opcode & 0x0F) >> 0
    eip = state['eip']

    if hi == 0:
        if lo == 0:
            return disassemble_eb_gb(raw, 'ADD', state)
        elif lo == 1:
            return disassemble_ev_gv(raw, 'ADD', state) # TODO: Test
        elif lo == 2:
            return disassemble_gb_eb(raw, 'ADD', state) # TODO: Test
        elif lo == 3:
            return disassemble_gv_ev(raw, 'ADD', state) # TODO: Test
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
            return disassemble_eb_gb(raw, 'OR', state) # TODO: Test
        elif lo == 9:
            return disassemble_ev_gv(raw, 'OR', state) # TODO: Test
        if lo == 0xa:
            return disassemble_gb_eb(raw, 'OR', state) # TODO: Test
        elif lo == 0xb:
            return disassemble_gv_ev(raw, 'OR', state) # TODO: Test
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
            return disassemble_eb_gb(raw, 'ADC', state) # TODO: Test
        elif lo == 1:
            return disassemble_ev_gv(raw, 'ADC', state) # TODO: Test
        elif lo == 2:
            return disassemble_gb_eb(raw, 'ADC', state) # TODO: Test
        elif lo == 3:
            return disassemble_gv_ev(raw, 'ADC', state) # TODO: Test
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
            return disassemble_eb_gb(raw, 'SBB', state) # TODO: Test
        elif lo == 9:
            return disassemble_ev_gv(raw, 'SBB', state) # TODO: Test
        elif lo == 0xa:
            return disassemble_gb_eb(raw, 'SBB', state) # TODO: Test
        elif lo == 0xb:
            return disassemble_gv_ev(raw, 'SBB', state) # TODO: Test
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
            return disassemble_eb_gb(raw, 'AND', state) # TODO: Test
        elif lo == 1:
            return disassemble_ev_gv(raw, 'AND', state) # TODO: Test
        elif lo == 2:
            return disassemble_gb_eb(raw, 'AND', state) # TODO: Test
        elif lo == 3:
            return disassemble_gv_ev(raw, 'AND', state) # TODO: Test
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
            return disassemble_eb_gb(raw, 'SUB', state) # TODO: Test
        elif lo == 9:
            return disassemble_ev_gv(raw, 'SUB', state) # TODO: Test
        elif lo == 0xa:
            return disassemble_gb_eb(raw, 'SUB', state) # TODO: Test
        elif lo == 0xb:
            return disassemble_gv_ev(raw, 'SUB', state) # TODO: Test
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
            return disassemble_eb_gb(raw, 'XOR', state) # TODO: Test
        elif lo == 1:
            return disassemble_ev_gv(raw, 'XOR', state) # TODO: Test
        elif lo == 2:
            return disassemble_gb_eb(raw, 'XOR', state) # TODO: Test
        elif lo == 3:
            return disassemble_gv_ev(raw, 'XOR', state) # TODO: Test
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
            return disassemble_eb_gb(raw, 'CMP', state) # TODO: Test
        elif lo == 9:
            return disassemble_ev_gv(raw, 'CMP', state) # TODO: Test
        elif lo == 0xa:
            return disassemble_gb_eb(raw, 'CMP', state) # TODO: Test
        elif lo == 0xb:
            return disassemble_gv_ev(raw, 'CMP', state) # TODO: Test
        elif lo == 0xc:
            state['eip'] += 2
            return f'{prefix}CMP al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'{prefix}CMP eax, {hex(iz)}'
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
            # TODO: More tests
            return disassemble_ew_gw(raw, 'ARPL', state)
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
            # TODO: More tests
            inst = disassemble_gv_ev(raw, 'IMUL', state)
            ib = raw[state['eip']]
            ib = sign_extend(ib, 8)
            state['eip'] += 1
            return f'{inst}, {hex(ib)}'
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
            mod, reg_op, rm = modrm(raw[1])
            op = ['ADD', 'OR', 'ADC', 'SBB', 'AND', 'SUB', 'XOR', 'CMP'][reg_op]
            return disassemble_eb_ib(raw, op, state) # TODO: Test
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
            mod, reg_op, rm = modrm(raw[1])
            op = ['ADD', 'OR', 'ADC', 'SBB', 'AND', 'SUB', 'XOR', 'CMP'][reg_op]
            # TODO: More tests
            inst = disassemble_ev_gv(raw, op, state)
            inst = inst.split(',')[0]
            ib = raw[state['eip']]
            ib = sign_extend(ib, 8)
            state['eip'] += 1
            return f'{inst}, {hex(ib)}'
        elif lo == 4:
            return disassemble_eb_gb(raw, 'TEST', state) # TODO: Test
        elif lo == 5:
            return disassemble_ev_gv(raw, 'TEST', state) # TODO: Test
        elif lo == 6:
            return disassemble_eb_gb(raw, 'XCHG', state) # TODO: Test
        elif lo == 7:
            return disassemble_ev_gv(raw, 'XCHG', state) # TODO: Test
        elif lo == 8:
            return disassemble_eb_gb(raw, 'MOV', state) # TODO: Test
        elif lo == 9:
            state['eip'] += 1
            addr = modrm_dst_src(raw[1:], 'Ev', 'Gv', state)
            return f'MOV {addr}'
        elif lo == 0xa:
            return disassemble_gb_eb(raw, 'MOV', state) # TODO: Test
        elif lo == 0xb:
            return disassemble_gv_ev(raw, 'MOV', state) # TODO: Test
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
            assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            op = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', '???', 'SAR'][reg_op]
            return disassemble_eb_ib(raw, op, state) # TODO: Test
        elif lo == 1:
            mod, reg_op, rm = modrm(raw[1])
            assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            op = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', '???', 'SAR'][reg_op]
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
            mod, reg_op, rm = modrm(raw[1])
            assert reg_op == 0b000, 'Invalid Grp 11 MOV'
            return disassemble_eb_ib(raw, 'MOV', state) # TODO: Test
        elif lo == 7:
            mod, reg_op, rm = modrm(raw[1])
            assert reg_op == 0b000, 'Invalid Grp 11 MOV'
            inst = disassemble_ev_iv(raw, 'MOV', state) # TODO: Test
            iz = int.from_bytes(raw[state['eip']-1:state['eip']+3], 'little')
            state['eip'] += 3
            # TODO: No dirty hacks!
            return f'{inst.split(",")[0]}, {hex(iz)}'
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
            assert reg_op != 0b110, 'Invalid Shift Grp 2 op!'
            op = ['ROL', 'ROR', 'RCL', 'RCR', 'SHL', 'SHR', '???', 'SAR'][reg_op]
            inst = disassemble_ev_gv(raw, op, state).split(',')[0]
            return f'{inst}, cl'
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
                elif raw[1] >= 0xd0 and raw[1] <= 0xd7:
                    state['eip'] += 2
                    return f'FCOM st({raw[1] - 0xd0})'
                elif raw[1] >= 0xd8 and raw[1] <= 0xdf:
                    state['eip'] += 2
                    return f'FCOMP st({raw[1] - 0xd8})'
                elif raw[1] >= 0xe0 and raw[1] <= 0xe8:
                    state['eip'] += 2
                    return f'FSUB st, st({raw[1] - 0xe0})'
                elif raw[1] >= 0xf0 and raw[1] <= 0xf8:
                    state['eip'] += 2
                    return f'FDIV st, st({raw[1] - 0xf0})'
        elif lo == 9:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLD DWORD PTR {addr}'
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
                    pass
                elif nnn == 0b010:
                    pass
                elif nnn == 0b011:
                    pass
                elif nnn == 0b100:
                    pass
                elif nnn == 0b101:
                    pass
                elif nnn == 0b110:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FIDIV DWORD PTR {addr}'
                elif nnn == 0b111:
                    pass
            else:
                pass
        elif lo == 0xb:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FILD QWORD PTR {addr}'
                elif nnn == 0b001:
                    pass
                elif nnn == 0b010:
                    pass
                elif nnn == 0b011:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FISTP DWORD PTR {addr}'
                elif nnn == 0b101:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLD TBYTE PTR {addr}'
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
                elif raw[1] >= 0xe0 and raw[1] <= 0xe7:
                    state['eip'] += 2
                    return f'FSUBR st({raw[1] - 0xe0}), st'
        elif lo == 0xd:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FLD QWORD PTR {addr}'
                elif nnn == 0b001:
                    pass
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
                    pass
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
                    pass
                elif raw[1] >= 0xd8 and raw[1] <= 0xdf:
                    state['eip'] += 2
                    return f'FSTP st({raw[1] - 0xd8})'
        elif lo == 0xe:
            _, nnn, _ = modrm(raw[1])
            if raw[1] <= 0xbf:
                if nnn == 0b000:
                    pass
                elif nnn == 0b001:
                    pass
                elif nnn == 0b010:
                    addr = modrm_addressing(raw[1], raw[2:], state)
                    state['eip'] += 2
                    return f'FICOM WORD PTR {addr}'
                elif nnn == 0b011:
                    pass
                elif nnn == 0b100:
                    pass
                elif nnn == 0b101:
                    pass
                elif nnn == 0b110:
                    pass
                elif nnn == 0b111:
                    pass
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
            pass
    elif hi == 0xe:
        if lo == 0:
            pass
        elif lo == 1:
            pass
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
            assert reg_op != 0b001, 'Invalid Unary Grp 3 Eb op!'
            op = ['TEST', '???', 'NOT', 'NEG', 'MUL', 'IMUL', 'DIV', 'IDIV'][reg_op]
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
            assert reg_op != 0b001, 'Invalid Unary Grp 3 Eb op!'
            op = ['TEST', '???', 'NOT', 'NEG', 'MUL', 'IMUL', 'DIV', 'IDIV'][reg_op]
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
            mod, reg_op, rm = modrm(raw[1])
            state['eip'] += 2
            if reg_op > 0b001:
                return f'(bad)'
            op = ['INC', 'DEC'][reg_op]
            addr = modrm_op(raw[1:], 'Eb', state)
            return f'{op} {addr}'
        elif lo == 0xf:
            mod, reg_op, rm = modrm(raw[1])
            assert reg_op != 0b111
            op = ['INC', 'DEC', 'CALL', 'CALL', 'JMP', 'JMP', 'PUSH'][reg_op]
            xxx = disassemble_ex_gx(raw, op, 'DWORD PTR', REGISTERS, state)
            return xxx.split(',')[0]
    else:
        fail(f'ERROR: Unknown opcode {hex(raw[0])}')

if __name__ == '__main__':
    #state = {'eip': 191, 'seg': '', 'prefix': ''}
    #print(disassemble(b'\xf6\x45\xd0\x01', state))
    #sys.exit(0)

    show_version = False
    show_usage = False
    base = 0
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

    if show_version:
        print(f'asm version {VERSION}')
        sys.exit(0)
    elif show_usage:
        print(USAGE)
        sys.exit(0)

    raw = sys.stdin.buffer.read()
    state = {'eip': 0}
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
