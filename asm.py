#!/usr/bin/env python3

import sys

REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
REGISTERS8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh']

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
    return f'{REGISTERS[base]}+{REGISTERS[index]}*{2**scale}'

def disassemble_ex_gx(raw, op, ptr_size, reg_size, state, swap=False):
    seg = state['seg']
    mod, reg_op, rm = modrm(raw[1])
    #print(f'mod={mod}, reg_op={reg_op}, rm={rm}')
    if mod == 0b00:
        if rm <= 0b011 or rm == 0b110 or rm == 0b111:
            dst = f'{ptr_size} [{REGISTERS[rm]}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 2
            return f'{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 3
            return f'{op} {dst}, {src}'
        elif rm == 0b101:
            disp32 = int.from_bytes(raw[2:6], 'little')
            dst = f'{ptr_size} ds:{hex(disp32)}'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 6
            return f'{op} {dst}, {src}'
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
            return f'{op} {dst}, {src}'
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
            return f'{op} {dst}, {src}'
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
            return f'{op} {dst}, {src}'
        elif rm == 0b100:
            scale, idx, base = sib(raw[2])
            if base == 0b101:
                assert False, 'Invalid SIB'
            disp32 = hex(sign_extend(int.from_bytes(raw[3:7], 'little'), 32, unsigned=False))
            if disp32.startswith('0x'):
                disp32 = f'+{disp32}'
            dst = f'{ptr_size} [{sib_str(scale, idx, base)}{disp32}]'
            src = f'{reg_size[reg_op]}'
            if swap:
                dst,src = src,dst
            state['eip'] += 7
            return f'{op} {dst}, {src}'
    elif mod == 0b11:
        dst = f'{reg_size[rm]}'
        src = f'{reg_size[reg_op]}'
        if swap:
            dst,src = src,dst
        state['eip'] += 2
        return f'{op} {dst}, {src}'

def disassemble_eb_gb(raw, op, state):
    return disassemble_ex_gx(raw, op, 'BYTE PTR', REGISTERS8, state)

def disassemble_ev_gv(raw, op, state):
    return disassemble_ex_gx(raw, op, 'DWORD PTR', REGISTERS, state)

def disassemble_gb_eb(raw, op, state):
    return disassemble_ex_gx(raw, op, 'BYTE PTR', REGISTERS8, state, swap=True)

def disassemble_gv_ev(raw, op, state):
    return disassemble_ex_gx(raw, op, 'DWORD PTR', REGISTERS, state, swap=True)

def disassemble(raw, state):
    if len(raw) == 0:
        fail('ERROR: input was empty')

    opcode = raw[0]
    hi = (opcode & 0xF0) >> 4
    lo = (opcode & 0x0F) >> 0

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
            return f'ADD al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'ADD eax, {hex(iz)}'
        elif lo == 6:
            state['eip'] += 1
            return 'PUSH es'
        elif lo == 7:
            state['eip'] += 1
            return 'POP es'
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
            return f'OR al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'OR eax, {hex(iz)}'
        elif lo == 0xe:
            state['eip'] += 1
            return 'PUSH cs'
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
            return f'ADC al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'ADC eax, {hex(iz)}'
        elif lo == 6:
            state['eip'] += 1
            return 'PUSH ss'
        elif lo == 7:
            state['eip'] += 1
            return 'POP ss'
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
            return f'SBB al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'SBB eax, {hex(iz)}'
        elif lo == 0xe:
            state['eip'] += 1
            return 'PUSH ds'
        elif lo == 0xf:
            state['eip'] += 1
            return 'POP ds'
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
            return f'AND al, {hex(raw[1])}'
        elif lo == 5:
            state['eip'] += 5
            iz = int.from_bytes(raw[1:5], 'little')
            return f'AND eax, {hex(iz)}'
        elif lo == 6:
            state['seg'] = 'es:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 7:
            state['eip'] += 1
            return 'DAA'
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
            return f'SUB al, {hex(raw[1])}'
        elif lo == 0xd:
            state['eip'] += 5
            iz = int.from_bytes(raw[1:5], 'little')
            return f'SUB eax, {hex(iz)}'
        elif lo == 0xe:
            state['seg'] = 'cs:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 0xf:
            state['eip'] += 1
            return 'DAS'
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
            return f'XOR al, {hex(raw[1])}'
        elif lo == 5:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'XOR eax, {hex(iz)}'
        elif lo == 6:
            state['seg'] = 'ss:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 7:
            state['eip'] += 1
            return 'AAA'
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
            return f'CMP al, {hex(raw[1])}'
        elif lo == 0xd:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'CMP eax, {hex(iz)}'
        elif lo == 0xe:
            state['seg'] = 'ds:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 0xf:
            state['eip'] += 1
            return 'AAS'
    elif hi == 4:
        if lo <= 7:
            state['eip'] += 1
            return f'INC {REGISTERS[lo]}'
        elif lo <= 0xf:
            state['eip'] += 1
            return f'DEC {REGISTERS[lo-8]}'
    elif hi == 5:
        if lo <= 7:
            state['eip'] += 1
            return f'PUSH {REGISTERS[lo]}'
        elif lo <= 0xf:
            state['eip'] += 1
            return f'POP {REGISTERS[lo-8]}'
    elif hi == 6:
        if lo == 0:
            state['eip'] += 1
            return 'PUSHA'
        elif lo == 1:
            state['eip'] += 1
            return 'POPA'
        elif lo == 4:
            state['seg'] = 'fs:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 5:
            state['seg'] = 'gs:'
            state['eip'] += 1
            return disassemble(raw[1:], state)
        elif lo == 8:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'PUSH {hex(iz)}'
        elif lo == 0xa:
            ib = raw[1]
            ib = sign_extend(ib, 8)
            state['eip'] += 2
            return f'PUSH {hex(ib)}'
    elif hi == 7:
        jmp_type = [
            'JO', 'JNO', 'JB', 'JNB', 'JE', 'JNE', 'JBE', 'JNBE',
            'JS', 'JNS', 'JP', 'JNP', 'JL', 'JNL', 'JLE', 'JNLE',
        ][lo]
        rel8 = raw[1]
        state['eip'] += 2
        addr = state['eip'] + rel8
        return f'{jmp_type} {hex(addr)}'
    elif hi == 8:
        if lo == 0:
            pass
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
            return disassemble_ev_gv(raw, 'MOV', state) # TODO: Test
        elif lo == 0xa:
            return disassemble_gb_eb(raw, 'MOV', state) # TODO: Test
        elif lo == 0xb:
            return disassemble_gv_ev(raw, 'MOV', state) # TODO: Test
    elif hi == 9:
        if lo == 0:
            state['eip'] += 1
            return 'NOP'
        elif lo <= 7:
            state['eip'] += 1
            return f'XCHG {REGISTERS[lo]}, eax'
        elif lo == 8:
            state['eip'] += 1
            return 'CWDE'
        elif lo == 9:
            state['eip'] += 1
            return 'CDQ'
        elif lo == 0xb:
            state['eip'] += 1
            return 'FWAIT'
        elif lo == 0xc:
            state['eip'] += 1
            return 'PUSHF'
        elif lo == 0xd:
            state['eip'] += 1
            return 'POPF'
        elif lo == 0xe:
            state['eip'] += 1
            return 'SAHF'
        elif lo == 0xf:
            state['eip'] += 1
            return 'LAHF'
    elif hi == 0xa:
        if lo == 0:
            pass
        elif lo == 8:
            ib = raw[1]
            state['eip'] += 2
            return f'TEST al, {hex(ib)}'
        elif lo == 9:
            iz = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'TEST eax, {hex(iz)}'
    elif hi == 0xb:
        if lo <= 7:
            state['eip'] += 2
            return f'MOV {REGISTERS8[lo]}, {hex(raw[1])}'
        elif lo <= 0xf:
            iv = int.from_bytes(raw[1:5], 'little')
            state['eip'] += 5
            return f'MOV {REGISTERS[lo-8]}, {hex(iv)}'
    elif hi == 0xc:
        if lo == 0:
            pass
        elif lo == 2:
            iw = int.from_bytes(raw[1:3], 'little')
            state['eip'] += 3
            return f'RET {hex(iw)}'
        elif lo == 3:
            state['eip'] += 1
            return 'RET'
        elif lo == 8:
            iw = int.from_bytes(raw[1:3], 'little')
            ib = raw[3]
            state['eip'] += 4
            return f'ENTER {hex(iw)}, {hex(ib)}'
        elif lo == 9:
            state['eip'] += 1
            return 'LEAVE'
        elif lo == 0xa:
            iw = int.from_bytes(raw[1:3], 'little')
            state['eip'] += 3
            return f'RETF {hex(iw)}'
        elif lo == 0xb:
            state['eip'] += 1
            return 'RETF'
        elif lo == 0xc:
            state['eip'] += 1
            return 'INT3'
        elif lo == 0xd:
            state['eip'] += 2
            return f'INT {hex(raw[1])}'
        elif lo == 0xe:
            state['eip'] += 1
            return 'INTO'
        elif lo == 0xf:
            state['eip'] += 1
            return 'IRET'
    elif opcode == 0xf1:
        state['eip'] += 1
        return 'INT1'
    elif opcode == 0xf4:
        state['eip'] += 1
        return 'HLT'
    elif opcode == 0xf5:
        state['eip'] += 1
        return 'CMC'
    elif opcode == 0xf8:
        state['eip'] += 1
        return 'CLC'
    elif opcode == 0xf9:
        state['eip'] += 1
        return 'STC'
    elif opcode == 0xfa:
        state['eip'] += 1
        return 'CLI'
    elif opcode == 0xfb:
        state['eip'] += 1
        return 'STI'
    elif opcode == 0xfc:
        state['eip'] += 1
        return 'CLD'
    elif opcode == 0xfd:
        state['eip'] += 1
        return 'STD'
    else:
        fail(f'ERROR: Unknown opcode {hex(raw[0])}')

if __name__ == '__main__':
    raw = sys.stdin.buffer.read()
    state = {'seg': '', 'eip': 0}
    print(disassemble(raw, state))
