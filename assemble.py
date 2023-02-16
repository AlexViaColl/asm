from struct import pack

from asm import tokenize, REGISTERS8, REGISTERS16, REGISTERS, SEGMENTS, REGISTERSXMM, REGISTERSMM

def get_scale(value):
    return {
        '1': 0b00,
        '2': 0b01,
        '4': 0b10,
        '8': 0b11,
    }[value]

def get_sib(reg):
    return b'\x24' if reg == REGISTERS.index('esp') else b''

def get_sign(t):
    return {'+': 1, '-': -1}[t]

def pack_ib(ib):
    return pack('<B', int(ib, base=16))

def pack_im(im):
    pack_disp(im)

def pack_disp(disp):
    if disp < 0:
        if abs(disp) <= 0x80:
            return pack('<b', disp)
        else:
            return pack('<i', disp)
    else:
        if disp <= 0x7f or disp >= 0xffffff00:
            return pack('<B', disp)
        else:
            return pack('<I', disp)

def pack_modrm(modrm, disp):
    if disp <= 0x7f:
        return pack('<B', modrm | 0b01000000)
    else:
        return pack('<B', modrm | 0b10000000)

def mxxfp(tokens, op_mod):
    if tokens[1].value in ['WORD', 'DWORD', 'TBYTE', 'QWORD']:
        op, mod = op_mod[tokens[1].value]
        assert tokens[2].value == 'PTR'
        prefix = b''
        if tokens[3].value == 'fs':
            prefix = b'\x64'
            tokens = tokens[2:]
        if tokens[3].value == '[':
            if tokens[4].value in REGISTERS:
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    sib = get_sib(base)
                    modrm = 0b00000000 | mod << 3 | base
                    return prefix + op + pack('<B', modrm) + sib
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == '-':
                            im = -int(tokens[10].value, base=16)
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if abs(im) <= 0x7f:
                                modrm = 0b01000100 | mod << 3
                                return prefix + op + pack('<B', modrm) + pack('<B', sib) + pack('<b', im)
                            else:
                                modrm = 0b10000100 | mod << 3
                                return prefix + op + pack('<B', modrm) + pack('<B', sib) + pack('<i', im)
                        elif tokens[9].value == '+':
                            im = int(tokens[10].value, base=16)
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if im <= 0x7f:
                                modrm = 0b01000100 | mod << 3
                                return prefix + op + pack('<B', modrm) + pack('<B', sib) + pack('<B', im)
                            else:
                                modrm = 0b10000100 | mod << 3
                                return prefix + op + pack('<B', modrm) + pack('<B', sib) + pack('<I', im)
                        elif tokens[9].value == ']':
                            modrm = 0b00000100 | mod << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return prefix + op + pack('<B', modrm) + pack('<B', sib)
                        else:
                            assert False, 'Not implemented'
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        modrm = 0b00000000 | mod << 3 | base
                        return prefix + op + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b00000100 | mod << 3
                    sib = 0b00000101 | scale << 6 | base << 3
                    return prefix + op + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                else: # '-'
                    im = int(tokens[6].value, base=16)
                    #print(ib, hex(ib))
                    if im <= 0x7f:
                        im = (~im & 0xff) + 1
                        modrm = 0b01000000 | mod << 3 | base
                        return prefix + op + pack('<B', modrm) + pack('<B', im)
                    else:
                        im = (~im & 0xffffffff) + 1
                        modrm = 0b10000000 | mod << 3 | base
                        return prefix + op + pack('<B', modrm) + pack('<I', im)
            else:
                assert False, 'Not implemented'
        elif tokens[3].value == 'ds':
            seg = SEGMENTS.index(tokens[3].value)
            assert tokens[4].value == ':'
            modrm = 0b00000101 | mod << 3
            im = int(tokens[5].value, base=16)
            return op + pack('<B', modrm) + pack('<I', im)
    assert False, 'Unreachable'

def assemble(line, state):
    if 'eip' not in state or state['eip'] == None:
        state['eip'] = 0
    tokens = tokenize(line)
    # TODO: Strip comments

    opcode = tokens[0].value.upper()

    if opcode == 'AAA':     return b'\x37'
    elif opcode == 'AAD':
        if len(tokens) == 1:
            return b'\xd5\x0a'
        else:
            return b'\xd5' + pack_ib(tokens[1].value)
    elif opcode == 'AAM':
        if len(tokens) == 1:
            return b'\xd4\x0a'
        else:
            return b'\xd4' + pack_ib(tokens[1].value)
    elif opcode == 'AAS':   return b'\x3f'
    elif opcode == 'ADC':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x10' + pack('<B', modrm)
                else:
                    modrm = 0b00010000 | base
                    ib = int(tokens[7].value, base=16)
                    return b'\x80' + pack('<B', modrm) + pack('<B', ib)
            elif tokens[5].value == '+':
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == '+'
                    disp = int(tokens[10].value, base=16)
                    assert tokens[11].value == ']'
                    assert tokens[12].value == ','
                    modrm = 0b00010100
                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                    ib = int(tokens[13].value, base=16)
                    return b'\x82' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', ib)
                else:
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x10' + pack_modrm(modrm, disp) + pack_disp(disp)
                    else:
                        ib = int(tokens[9].value, base=16)
                        return b'\x82\x51' + pack('<B', disp) + pack('<B', ib)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS8.index(tokens[9].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x10' + pack_modrm(modrm, disp) + pack_disp(-disp)
            else:
                assert False
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS:
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x11' + pack('<B', modrm)
                else:
                    modrm = 0b00010000 | base
                    im = int(tokens[7].value, base=16)
                    if im > 0x7f:
                        return b'\x81' + pack('<B', modrm) + pack('<I', im)
                    else:
                        return b'\x83' + pack('<B', modrm) + pack('<B', im)
            elif tokens[5].value == '+':
                if tokens[6].value == 'eiz':
                    return b'\x11\x64\x66\x00'
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                    if tokens[9].value == ']':
                        assert tokens[10].value == ','
                        src = REGISTERS.index(tokens[11].value)
                        modrm = 0b00000100 | src << 3
                        return b'\x11' + pack('<B', modrm) + pack('<B', sib)
                    else:
                        sign = {'+': 1, '-': -1}[tokens[9].value]
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        assert tokens[12].value == ','
                        src = REGISTERS.index(tokens[13].value)
                        modrm = 0b00000100 | src << 3
                        return b'\x11' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(sign*disp)
                else:
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x11' + pack_modrm(modrm, disp) + pack_disp(disp)
                    else:
                        ib = int(tokens[9].value, base=16)
                        return b'\x83\x51' + pack('<B', disp) + pack('<B', ib & 0xff)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                if tokens[9].value in REGISTERS:
                    src = REGISTERS.index(tokens[9].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x11' + pack_modrm(modrm, disp) + pack_disp(-disp)
                else:
                    im = int(tokens[9].value, base=16)
                    modrm = 0b10010000 | base
                    if im <= 0x7f or im > 0xffffff7f:
                        return b'\x83' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<B', im & 0xff)
                    else:
                        return b'\x81' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<I', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                prefix = b''
                if tokens[5].value == 'fs':
                    prefix = b'\x64'
                    tokens = tokens[2:]
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x12' + pack('<B', modrm)
                elif tokens[7].value in ['+', '-']:
                    sign = {'+': 1, '-': -1}[tokens[7].value]
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value == ']':
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x12\x14' + pack('<B', sib)
                        elif tokens[11].value == '+':
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            return b'\x12\x64\x00' + pack('<B', disp)
                        elif tokens[11].value == '-':
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            return b'\x12\x64\x00' + pack('<b', -disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | dst << 3 | base
                        return prefix + b'\x12' + pack_modrm(modrm, disp) + pack_disp(sign*disp)
            elif tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                # TODO: Fix this
                if state['eip'] in [0x7edc00]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x12' + pack('<B', modrm)

                modrm = 0b11000000 | src << 3 | dst
                return b'\x10' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return b'\x14' + pack('<B', ib)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                # TODO: Don't hardcode this
                if state['eip'] in [
                    0x522b4f, 0x5a638c, 0x69d564, 0x6dfed1, 0x7fa2e2, 0x80c782,
                    0x80cba7, 0x80d73b, 0x80d90a, 0x80df0e,
                ]:
                    modrm = 0b11000000 | dst << 3 | src
                    return b'\x13' + pack('<B', modrm)
                elif state['eip'] in [0x69e6d1, 0x7dceb8, 0x7fccb8]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x11' + pack('<B', modrm)

                if dst != REGISTERS.index('edi') and dst != REGISTERS.index('ecx'):
                    modrm = 0b11000000 | dst << 3 | src
                    return b'\x13' + pack('<B', modrm)
                else:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x11' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                prefix = b''
                if tokens[5].value == 'es':
                    prefix = b'\x26'
                    tokens = tokens[2:]

                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    return b'\x13\x05' + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x13' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            if tokens[11].value == ']':
                                modrm = 0b00000100 | dst << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x13' + pack('<B', modrm) + pack('<B', sib)
                            elif tokens[11].value in ['+', '-']:
                                disp = int(tokens[12].value, base=16)
                                return b'\x13\x64\x00' + pack_disp(get_sign(tokens[11].value) * disp)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b01000000 | dst << 3 | base
                            return prefix + b'\x13' + pack('<B', modrm) + pack('<B', disp)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        return b'\x13\x14\x15' + pack('<I', disp)
            else:
                im = int(tokens[3].value, base=16)
                if im <= 0x7f or im > 0xffffff7f:
                    modrm = 0b11010000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                else:
                    return b'\x15' + pack('<I', im)
        else:
            assert False, 'Unreachable'
    elif opcode == 'ADCX':  assert False, 'Not implemented'
    elif opcode == 'ADD':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            if tokens[3].value in SEGMENTS and tokens[4].value == ':' and tokens[5].value != '[':
                assert tokens[4].value == ':'
                prefix = {
                    'ds': b'',
                    'fs': b'\x64',
                    'gs': b'\x65',
                }[tokens[3].value]
                if tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERS8.index(tokens[9].value)
                    modrm = 0b00010000 | src << 3 | base
                    return prefix + b'\x00' + pack('<B', modrm)
                else:
                    m = int(tokens[5].value, base=16)
                    assert tokens[6].value == ','
                    src = REGISTERS8.index(tokens[7].value)

                    if state['eip'] in [0x672417]:
                        modrm = 0b00000110 | src << 3
                        return prefix + b'\x67\x00' + pack('<B', modrm) + pack('<H', m)

                    modrm = 0b00000101 | src << 3
                    return prefix + b'\x00' + pack('<B', modrm) + pack('<I', m)

            prefix = b''
            if tokens[3].value == 'fs':
                prefix = b'\x64'
                tokens = tokens[2:]
            if tokens[3].value == 'gs':
                prefix = b'\x65'
                tokens = tokens[2:]
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                src = REGISTERS8.index(tokens[7].value)
                modrm = 0b00000101 | src << 3
                return b'\x00' + pack('<B', modrm) + pack('<I', m)
            elif tokens[3].value == '[':
                if tokens[4].value =='eiz':
                    assert tokens[5].value == '*'
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    src = REGISTERS8.index(tokens[11].value)
                    modrm = 0b00000100 | src << 3
                    sib = 0b00100101 | scale << 6
                    return prefix + b'\x00' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)

                if tokens[4].value in REGISTERS16:
                    base = REGISTERS16.index(tokens[4].value)
                    if tokens[5].value == '+':
                        if tokens[6].value in REGISTERS16:
                            idx = REGISTERS16.index(tokens[6].value)
                            if tokens[7].value == ']':
                                assert tokens[8].value == ','
                                src = REGISTERS8.index(tokens[9].value)
                                if base == REGISTERS16.index('bp'):
                                    modrm = 0b00000000 | src << 3 | (idx - 4)
                                else:
                                    modrm = 0b00000000 | src << 3 | (idx - 2)
                                return b'\x67\x00' + pack('<B', modrm)
                            elif tokens[7].value in ['+', '-']:
                                sign = get_sign(tokens[7].value)
                                disp = int(tokens[8].value, base=16)
                                assert tokens[9].value == ']'
                                assert tokens[10].value == ','
                                src = REGISTERS8.index(tokens[11].value)
                                modrm = 0b00000001 | src << 3 | (base - 2)
                                if disp <= 0x7f:
                                    return b'\x67\x00' + pack_modrm(modrm, disp) + pack_disp(sign*disp)
                                else:
                                    return b'\x67\x00' + pack_modrm(modrm, disp) + pack('<H', sign*disp)
                        else:
                            disp = int(tokens[6].value, base=16)
                            assert tokens[7].value == ']'
                            assert tokens[8].value == ','
                            src = REGISTERS8.index(tokens[9].value)
                            if disp <= 0x7f:
                                modrm = 0b01000101
                                return b'\x67\x00' + pack('<B', modrm) + pack('<B', disp)
                            else:
                                modrm = 0b10001111
                                return b'\x67\x00' + pack('<B', modrm) + pack('<H', disp)
                    elif tokens[5].value == '-':
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        src = REGISTERS8.index(tokens[9].value)
                        if base == REGISTERS16.index('bp'):
                            modrm = 0b01000110 | src << 3
                        else:
                            modrm = 0b01000000 | src << 3 | (base - 2)
                        return b'\x67\x00' + pack_modrm(modrm, disp) + pack_disp(-disp)

                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == '+':
                    if tokens[6].value in REGISTERS or tokens[6].value == 'eiz':
                        if tokens[6].value == 'eiz':
                            idx = 0b100
                        else:
                            idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value in ['+', '-']:
                            sign = get_sign(tokens[9].value)
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            src = REGISTERS8.index(tokens[13].value)
                            modrm = 0b00000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return prefix + b'\x00' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(sign*disp)
                        elif tokens[9].value == ']':
                            assert tokens[10].value == ','
                            src = REGISTERS8.index(tokens[11].value)
                            modrm = 0b00000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return prefix + b'\x00' + pack('<B', modrm) + pack('<B', sib)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        src = REGISTERS8.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return prefix + b'\x00' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERS8.index(tokens[9].value)
                    modrm = 0b00000000 | src << 3 | base
                    return prefix + b'\x00' + pack_modrm(modrm, disp) + pack_disp(-disp)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    if tokens[7].value in ['+', '-']:
                        sign = get_sign(tokens[7].value)
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        assert tokens[10].value == ','
                        src = REGISTERS8.index(tokens[11].value)
                        modrm = 0b00000100 | src << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return prefix + b'\x00' + pack('<B', modrm) + pack('<B', sib) + pack_disp(sign*disp)
                elif tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return prefix + b'\x00' + pack('<B', modrm)
                    else:
                        ib = int(tokens[7].value, base=16)
                        modrm = 0b00000000
                        return b'\x80' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    src = REGISTERS16.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x66\x01' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        assert False
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        src = REGISTERS16.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x66\x01' + pack_modrm(modrm, disp) + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERS16.index(tokens[9].value)
                    modrm = 0b01000000 | src << 3 | base
                    return b'\x66\x01' + pack('<B', modrm) + pack('<b', -disp)
                else:
                    assert False
            else:
                assert False
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS:
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return b'\x01' + pack('<B', modrm) + pack('<I', m)
                else:
                    im = int(tokens[7].value, base=16)
                    return b'\x83\x05' + pack('<I', m) + pack('<B', im)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == '+':
                    if tokens[6].value in REGISTERS or tokens[6].value == 'eiz':
                        if tokens[6].value == 'eiz':
                            idx = 0b100
                        else:
                            idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == ']':
                            assert tokens[10].value == ','
                            src = REGISTERS.index(tokens[11].value)
                            modrm = 0b00000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x01' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            src = REGISTERS.index(tokens[13].value)
                            modrm = 0b01000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x01' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            sib = get_sib(base)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x01' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            sib = get_sib(base)
                            modrm = 0b00000000 | base
                            if im <= 0x7f or im >= 0xffffff00:
                                return b'\x83' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<B', im & 0xff)
                            else:
                                return b'\x81' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<I', im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x01' + pack_modrm(modrm, disp) + pack_disp(-disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b01000101
                        if im <= 0x7f:
                            return b'\x83' + pack('<B', modrm) + pack('<b', -disp) + pack('<B', im)
                        else:
                            return b'\x81' + pack('<B', modrm) + pack('<b', -disp) + pack('<I', im)
                elif tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS:
                        src = REGISTERS.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x01' + pack('<B', modrm)
                    else:
                        im = int(tokens[7].value, base=16)
                        if im <= 0x7f:
                            modrm = 0b00000000
                            return b'\x83' + pack('<B', modrm) + pack('<B', im)
                        else:
                            modrm = 0b00000000 | base
                            return b'\x81' + pack('<B', modrm) + pack('<I', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)

                if state['eip'] in [
                    0x525213, 0x5a4122, 0x627c5d, 0x63eab4, 0x63eac5, 0x63ebd4, 0x63ebe2, 0x63ecf9,
                    0x63ed07, 0x63ee30, 0x63ee3e, 0x63f36f, 0x63f380, 0x65dfb6, 0x65e612, 0x65e6ac,
                ]:
                    modrm = 0b11000000 | dst << 3 | src
                    return b'\x02' + pack('<B', modrm)

                modrm = 0b11000000 | src << 3 | dst
                return b'\x00' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                prefix = b''
                if tokens[5].value == 'es':
                    prefix = b'\x26'
                    tokens = tokens[2:]
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x02' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x02' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            assert tokens[11].value == ']'
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x02' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b00000000 | dst << 3 | base
                            return prefix + b'\x02' + pack_modrm(modrm, disp) + pack_disp(disp)
            else:
                ib = int(tokens[3].value, base=16)
                if dst == REGISTERS8.index('al'):
                    return b'\x04' + pack('<B', ib)
                else:
                    modrm = 0b11000000 | dst
                    return b'\x80' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'WORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000000 | dst << 3 | base
                return b'\x66\x03' + pack('<B', modrm) + pack('<B', disp)
            elif tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x66\x03' + pack('<B', modrm)
            else:
                assert False
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x03' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x03' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            if tokens[11].value == ']':
                                modrm = 0b00000100 | dst << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x03' + pack('<B', modrm) + pack('<B', sib)
                            elif tokens[11].value == '+':
                                disp = int(tokens[12].value, base=16)
                                assert tokens[13].value == ']'
                                modrm = 0b01000100 | dst << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x03' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                        else:
                            im = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            sib = get_sib(base)
                            if im <= 0x7f:
                                modrm = 0b01000000 | dst << 3 | base
                                return b'\x03' + pack('<B', modrm) + sib + pack('<B', im)
                            else:
                                modrm = 0b10000000 | dst << 3 | base
                                return b'\x03' + pack('<B', modrm) + sib + pack('<I', im)
                    elif tokens[7].value == '-':
                        im = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        if im <= 0x80:
                            modrm = 0b01000000 | dst << 3 | base
                            return b'\x03' + pack('<B', modrm) + pack('<b', -im)
                        else:
                            modrm = 0b10000000 | dst << 3 | base
                            return b'\x03' + pack('<B', modrm) + pack('<i', -im)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x03' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        assert False
            elif tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src

                if state['eip'] in [0x52e238]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x01' + pack('<B', modrm)

                return b'\x03' + pack('<B', modrm)
            else:
                im = int(tokens[3].value, base=16)

                if state['eip'] in [0x459f26, 0x50c47a]:
                    return b'\x05' + pack('<I', im)
                if state['eip'] in [0x46f387, 0x46f3b0, 0x479f11, 0x5e3187]:
                    modrm = 0b11000000 | dst
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)

                if dst == REGISTERS.index('eax') and (im >= 0x80 and im < 0xffffff00):
                    return b'\x05' + pack('<I', im)
                elif im <= 0x7f:# or im > 0xffffff00:
                    modrm = 0b11000000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                #elif im in [0xfffffffe, 0xfffffffc, 0xffffffee, 0xffffffe8, 0xfffffff3, 0xffffffa8]:
                elif im > 0xffffff00:
                    modrm = 0b11000000 | dst
                    im = im & 0xff
                    return b'\x83' + pack('<B', modrm) + pack('<B', im)
                else:
                    modrm = 0b11000000 | dst
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)
        else:
            assert False, 'Unreachable'
    elif opcode == 'ADDR16':
        return b'\x67' + assemble(line[7:], state)
    elif opcode == 'ADDPD':
        return b'\x66\x0f\x58\xc2'
    elif opcode == 'ADDPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x58' + pack('<B', modrm) + pack('<I', m)
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b10000000 | dst << 3 | base
                return b'\x0f\x58' + pack('<B', modrm) + get_sib(base) + pack('<I', disp)

        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x58' + pack('<B', modrm)
    elif opcode == 'ADDSS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
        elif tokens[3].value == 'DWORD':
            m = int(tokens[7].value, base=16)
            return b'\xf3\x0f\x58\x05' + pack('<I', m)
        modrm = 0b11000000 | dst << 3 | src
        return b'\xf3\x0f\x58' + pack('<B', modrm)
    elif opcode in ['ADDPS', 'ADDSD', 'ADDSUBPD', 'ADDSUBPS']:
        assert False, 'Not implemented'
    elif opcode == 'ADOX':
        assert False, 'Not implemented'
    elif opcode.startswith('AES'):
        assert False, 'Not implemented'
    elif opcode == 'AND':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x20' + pack('<B', modrm)
                else:
                    ib = int(tokens[7].value, base=16)
                    modrm = 0b00100000 | base
                    return b'\x80' + pack('<B', modrm) + pack('<B', ib)
            elif tokens[5].value == '+':
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    if tokens[9].value == ']':
                        assert tokens[10].value == ','
                        if tokens[11].value in REGISTERS8:
                            src = REGISTERS8.index(tokens[11].value)
                            modrm = 0b00000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x20' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            im = int(tokens[11].value, base=16)
                            modrm = 0b00100100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x80' + pack('<B', modrm) + pack('<B', sib) + pack('<B', im)
                    elif tokens[9].value == '+':
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        assert tokens[12].value == ','
                        im = int(tokens[13].value, base=16)
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        modrm = 0b00100100
                        return b'\x80' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', im)
                    elif tokens[9].value == '-':
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        assert tokens[12].value == ','
                        im = int(tokens[13].value, base=16)
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if disp <= 0x80:
                            modrm = 0b01100100
                            return b'\x80' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp) + pack('<B', im)
                        else:
                            modrm = 0b10100100
                            return b'\x80' + pack('<B', modrm) + pack('<B', sib) + pack('<i', -disp) + pack('<B', im)
                else:
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[9].value)
                        modrm = 0b01000000 | src << 3 | base
                        return b'\x20' + pack('<B', modrm) + pack('<B', disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b00100000 | base
                        return b'\x80' + pack_modrm(modrm, disp) + pack_disp(disp) + pack('<B', im & 0xff)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                if tokens[9].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[9].value)
                    if disp <= 0x80:
                        modrm = 0b01000000 | src << 3 | base
                        return b'\x20' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        modrm = 0b10000000 | src << 3 | base
                        return b'\x20' + pack('<B', modrm) + pack('<i', -disp)
                else:
                    im = int(tokens[9].value, base=16)
                    if disp <= 0x80:
                        modrm = 0b01100000 | base
                        return b'\x80' + pack('<B', modrm) + pack('<b', -disp) + pack('<B', im)
                    else:
                        modrm = 0b10100101
                        return b'\x80' + pack('<B', modrm) + pack('<i', -disp) + pack('<B', im)
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                assert False
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    im = int(tokens[7].value, base=16)
                    modrm = 0b00100000 | base
                    return b'\x66\x83' + pack('<B', modrm) + pack('<B', im)
                elif tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    im = int(tokens[9].value, base=16)
                    modrm = 0b01100000 | base
                    return b'\x66\x81' + pack('<B', modrm) + pack('<B', disp) + pack('<H', im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    im = int(tokens[9].value, base=16)
                    modrm = 0b01100000 | base
                    return b'\x66\x83' + pack('<B', modrm) + pack('<b', -disp) + pack('<B', im)
                else:
                    assert False
            else:
                assert False
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                assert tokens[4].value == ':'
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS:
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return b'\x21' + pack('<B', modrm) + pack('<I', m)
                else:
                    im = int(tokens[7].value, base=16)
                    return b'\x83\x25' + pack('<I', m) + pack('<B', im & 0xff)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS:
                        src = REGISTERS.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x21' + pack('<B', modrm)
                    else:
                        im = int(tokens[7].value, base=16)
                        modrm = 0b00100000 | base
                        if im <= 0x7f or im >= 0xffffff00:
                            return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                        else:
                            return b'\x81' + pack('<B', modrm) + pack('<I', im)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == ']':
                            assert tokens[10].value == ','
                            im = int(tokens[11].value, base=16)
                            modrm = 0b00100100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x83' + pack('<B', modrm) + pack('<B', sib) + pack('<B', im)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if tokens[13].value in REGISTERS:
                                src = REGISTERS.index(tokens[13].value)
                                modrm = 0b00000100 | src << 3
                                return b'\x21' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                            else:
                                im = int(tokens[13].value, base=16)
                                modrm = 0b00100100
                                return b'\x83' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', im)
                        elif tokens[9].value == '-':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if tokens[13].value in REGISTERS:
                                src = REGISTERS.index(tokens[13].value)
                                modrm = 0b01000100 | src << 3
                                return b'\x21' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp)
                            else:
                                im = int(tokens[13].value, base=16)
                                modrm = 0b01100100
                                return b'\x83' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp) + pack('<B', im)
                    else:
                        sib = get_sib(base)
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            modrm = 0b01000000 | src << 3 | base
                            return b'\x21' + pack('<B', modrm) + sib + pack('<B', disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            modrm = 0b00100000 | base
                            if im <= 0x7f or im >= 0xffffff00:
                                return b'\x83' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<B', im & 0xff)
                            else:
                                return b'\x81' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<I', im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b01000000 | src << 3 | base
                        return b'\x21' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        if disp <= 0x80:
                            modrm = 0b01100000 | base
                            if im <= 0x7f or im >= 0xffffff00:
                                return b'\x83' + pack('<B', modrm) + pack('<b', -disp) + pack('<B', im & 0xff)
                            else:
                                return b'\x81' + pack('<B', modrm) + pack('<b', -disp) + pack('<I', im)
                        else:
                            modrm = 0b10100000 | base
                            if im <= 0x7f or im >= 0xffffff00:
                                return b'\x83' + pack('<B', modrm) + pack('<i', -disp) + pack('<B', im & 0xff)
                            else:
                                return b'\x81' + pack('<B', modrm) + pack('<i', -disp) + pack('<I', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)

                if state['eip'] in [0x69e55d, 0x69e5dd, 0x7fee6c]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x20' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x22' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x22' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        assert tokens[11].value in ['+', '-']
                        sign = {'+': 1, '-': -1}[tokens[11].value]
                        fmt = {'+': '<B', '-': '<b'}[tokens[11].value]
                        disp = int(tokens[12].value, base=16)
                        assert tokens[13].value == ']'
                        return b'\x22\x44\x00' + pack(fmt, sign * disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x22' + pack('<B', modrm) + pack('<B', disp)
                else:
                    assert False
            else:
                ib = int(tokens[3].value, base=16)
                if dst == REGISTERS8.index('al'):
                    return b'\x24' + pack('<B', ib)
                else:
                    modrm = 0b11100000 | dst
                    return b'\x80' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x66\x23' + pack('<B', modrm)
            else:
                im = int(tokens[3].value, base=16)
                if dst == REGISTERS16.index('ax'):
                    if im <= 0x7f:
                        modrm = 0b11100000 | dst
                        return b'\x66\x83' + pack('<B', modrm) + pack('<B', im)
                    else:
                        return b'\x66\x25' + pack('<H', im)

                modrm = 0b11100000 | dst
                return b'\x66\x81' + pack('<B', modrm) + pack('<H', im)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)

                if state['eip'] in [0x40f844, 0x69e6d9]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x21' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x23' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x23' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x23' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS or tokens[8].value == 'eiz':
                            if tokens[8].value == 'eiz':
                                idx = 0b100
                            else:
                                idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            assert tokens[11].value == '+'
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            modrm = 0b01000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x23' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b01000000 | dst << 3 | base
                            sib = get_sib(base)
                            return b'\x23' + pack('<B', modrm) + sib + pack('<B', disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x23' + pack('<B', modrm) + pack('<b', -disp)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x23' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                else:
                    assert False
            else:
                im = int(tokens[3].value, base=16)

                if state['eip'] in [0x67e6f1, 0x67619d]:
                    return b'\x25' + pack('<I', im)

                if im <= 0x7f or im >= 0xffffff00:
                    modrm = 0b11100000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                else:
                    if dst == 0b000:
                        return b'\x25' + pack('<I', im)
                    else:
                        modrm = 0b11100000 | dst
                        return b'\x81' + pack('<B', modrm) + pack('<I', im)
        else:
            assert False, 'Unreachable'
    elif opcode == 'ANDPD':
        return b'\x66\x0f\x54\x05\x00\x9b\x88\x00'
    elif opcode == 'ANDPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x54' + pack('<B', modrm)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000100 | dst << 3
                return b'\x0f\x54' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            elif tokens[5].value == 'ds':
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\x54' + pack('<B', modrm) + pack('<I', m)
        else:
            assert False
    elif opcode == 'ANDNPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        src = REGISTERSXMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x55' + pack('<B', modrm)
    elif opcode.startswith('AND'):
        assert False, 'Not implemented'
    elif opcode == 'ARPL':
        if tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value) 
            src = REGISTERS16.index(tokens[3].value) 
            modrm = 0b11000000 | src << 3 | dst
            return b'\x63' + pack('<B', modrm)
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ss':
                return b'\x36\x63\x00'
            elif tokens[3].value == '[':
                if tokens[4].value in REGISTERS:
                    base = REGISTERS.index(tokens[4].value)
                elif tokens[4].value in REGISTERS16:
                    base = REGISTERS16.index(tokens[4].value)
                    return b'\x67\x63\x66\x00'
                if tokens[5].value == ']':
                    return b'\x63\x00'
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        assert tokens[12].value == ','
                        src = REGISTERS16.index(tokens[13].value)
                        if tokens[9].value == '+':
                            return b'\x63\x6c\x00' + pack('<B', disp)
                        else:
                            return b'\x63\x6c\x00' + pack('<b', -disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        src = REGISTERS16.index(tokens[9].value)
                        modrm = 0b01000000 | src << 3 | base
                        return b'\x63' + pack('<B', modrm) + pack('<B', disp)
                else:
                    assert False
            else:
                assert False
        else:
            assert False
    elif opcode == 'BND':
        state['eip'] += 1
        inst = b'\xf2' + assemble(line[4:], state)
        state['eip'] -= 1
        return inst
    elif opcode == 'BOUND':
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        assert tokens[3].value == 'QWORD'
        assert tokens[4].value == 'PTR'
        assert tokens[5].value == '['
        base = REGISTERS.index(tokens[6].value)
        if tokens[7].value == ']':
            modrm = 0b00000000 | dst << 3 | base
            return b'\x62' + pack('<B', modrm)
        elif tokens[7].value == '+':
            if tokens[8].value in REGISTERS:
                assert tokens[9].value == '*'
                assert tokens[10].value == '1'
                if tokens[11].value == '+':
                    disp = int(tokens[12].value, base=16)
                    return b'\x62\x6c\x00' + pack('<B', disp)
                elif tokens[11].value == '-':
                    disp = -int(tokens[12].value, base=16)
                    return b'\x62\x6c\x00' + pack('<b', disp)
            else:
                disp = int(tokens[8].value, base=16)
                modrm = 0b01000000 | dst << 3 | base
                return b'\x62' + pack('<B', modrm) + pack('<B', disp)
    elif opcode == 'BSWAP':
        modrm = 0xc8 + REGISTERS.index(tokens[1].value)
        return b'\x0f' + pack('<B', modrm)
    elif opcode == 'BT':
        return b'\x0f\xa3\x04\x24'
    elif opcode == 'BTC':
        return b'\x0f\xba\x7f\x00\xf3'
    elif opcode == 'BTS':
        return b'\x0f\xab\x04\x24'
    elif opcode.startswith('B'):
        assert False, 'Not implemented'
    elif opcode == 'CALL':
        if tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            modrm = 0b00010100
                            return b'\xff' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                        elif tokens[9].value == '-':
                            disp = -int(tokens[10].value, base=16)
                            modrm = 0b10010100
                            return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<i', disp)
                        else:
                            assert False, 'Not implemented'
                    else:
                        disp = int(tokens[6].value, base=16)
                        sib = get_sib(base)
                        modrm = 0b00010000 | base
                        return b'\xff' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = -int(tokens[6].value, base=16)
                    if abs(disp) <= 0x7f:
                        modrm = 0b01010000 | base
                        return b'\xff' + pack('<B', modrm) + pack('<b', disp)
                    else:
                        modrm = 0b10010000 | base
                        return b'\xff' + pack('<B', modrm) + pack('<i', disp)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b00010100
                    sib = 0b10000101
                    return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                elif tokens[5].value == ']':
                    modrm = 0b00010000 | base
                    return b'\xff' + pack('<B', modrm)
                else:
                    assert False, 'Not implemented'
            else:
                assert tokens[3].value == 'ds'
                assert tokens[4].value == ':'
                disp = int(tokens[5].value, base=16)
                return b'\xff\x15' + pack('<I', disp)
        elif tokens[1].value in REGISTERS:
            # CALL r/m32 (FF /2)
            return b'\xff' + pack('<B', 0b11010000 | REGISTERS.index(tokens[1].value))
        else:
            if len(tokens) == 2:
                # CALL rel32 (E8 cd)
                to = int(tokens[1].value, base=16)
                rel = to - state['eip'] - 5
                if rel < 0:
                    return b'\xe8' + pack('<i', rel)
                else:
                    return b'\xe8' + pack('<I', rel)
            else:
                ptr1 = int(tokens[1].value, base=16)
                assert tokens[2].value == ':'
                ptr2 = int(tokens[3].value, base=16)
                return b'\x9a' + pack('<H', ptr2 & 0xffff) + pack('<H', ptr2 >> 16) + pack('<H', ptr1)
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
    elif opcode == 'CMOVA':
        dst = REGISTERS.index(tokens[1].value)
        src = REGISTERS.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x47' + pack('<B', modrm)
    elif opcode == 'CMOVB':
        return b'\x0f\x42\xd1'
    elif opcode == 'CMOVE':
        dst = REGISTERS.index(tokens[1].value)
        src = REGISTERS.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x44' + pack('<B', modrm)
    elif opcode == 'CMOVP':
        dst = REGISTERS.index(tokens[1].value)
        src = REGISTERS.index(tokens[6].value)
        modrm = 0b00000000 | dst << 3 | src
        return b'\x0f\x4a' + pack('<B', modrm)
    elif opcode.startswith('CMOV'):
        assert False, 'Not implemented'
    elif opcode == 'CMP':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return b'\x38' + pack('<B', modrm) + pack('<I', m)
                else:
                    im = int(tokens[7].value, base=16)
                    return b'\x80\x3d' + pack('<I', m) + pack('<B', im)
            elif tokens[3].value in SEGMENTS:
                assert False
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x38' + pack('<B', modrm)
                    else:
                        imm = int(tokens[7].value, base=16)
                        return b'\x80' + pack('<B', 0b00111000 | base) + pack('<B', imm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        if tokens[7].value == '*':
                            scale = get_scale(tokens[8].value)
                            if tokens[9].value == ']':
                                assert tokens[10].value == ','
                                if tokens[11].value in REGISTERS:
                                    src = REGISTERS.index(tokens[11].value)
                                    modrm = 0b00000100 | src << 3
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    return b'\x39' + pack('<B', modrm) + pack('<B', sib)
                                elif tokens[11].value in REGISTERS8:
                                    src = REGISTERS8.index(tokens[11].value)
                                    modrm = 0b00000100 | src << 3
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    return b'\x38' + pack('<B', modrm) + pack('<B', sib)
                                else:
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    ib = int(tokens[11].value, base=16)
                                    return b'\x80\x3c' + pack('<B', sib) + pack('<B', ib)
                            elif tokens[9].value == '+':
                                disp = int(tokens[10].value, base=16)
                                assert tokens[11].value == ']'
                                assert tokens[12].value == ','
                                if tokens[13].value in REGISTERS8:
                                    src = REGISTERS8.index(tokens[13].value)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00000100 | src << 3
                                    return b'\x38' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                                else:
                                    im = int(tokens[13].value, base=16)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00111100
                                    return b'\x80' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', im)
                            elif tokens[9].value == '-':
                                disp = int(tokens[10].value, base=16)
                                assert tokens[11].value == ']'
                                assert tokens[12].value == ','
                                if tokens[13].value in REGISTERS8:
                                    src = REGISTERS8.index(tokens[13].value)
                                    modrm = 0b01000100 | src << 3
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    return b'\x38' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp)
                                else:
                                    im = int(tokens[13].value, base=16)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00111100
                                    return b'\x80' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(-disp) + pack('<B', im)
                        else:
                            assert False, 'Not implemented yet'
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            modrm = 0b01000000 | src << 3 | base
                            return b'\x39' + pack('<B', modrm) + pack('<B', disp)
                        elif tokens[9].value in REGISTERS8:
                            src = REGISTERS8.index(tokens[9].value)
                            sib = 0b00100100
                            sib = get_sib(base)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x38' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                        else:
                            ib = int(tokens[9].value, base=16)
                            sib = get_sib(base)
                            modrm = 0b00111000 | base
                            return b'\x80' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<B', ib)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x38' + pack_modrm(modrm, disp) + pack_disp(-disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        if disp <= 0x80:
                            modrm = 0b01111000 | base
                            return b'\x80' + pack('<B', modrm) + pack('<b', -disp) + pack('<B', im)
                        else:
                            modrm = 0b10111000 | base
                            return b'\x80' + pack('<B', modrm) + pack('<i', -disp) + pack('<B', im)
                else:
                    assert False, 'Unreachable'
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                src = REGISTERS16.index(tokens[7].value)
                modrm = 0b00000101 | src << 3
                return b'\x66\x39' + pack('<B', modrm) + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS16:
                        src = REGISTERS16.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x66\x39' + pack('<B', modrm)
                    else:
                        sib = get_sib(base)
                        im = int(tokens[7].value, base=16)
                        if im <= 0x7f:
                            modrm = 0b00111000 | base
                            return b'\x66\x83' + pack('<B', modrm) + sib + pack('<B', im)
                        else:
                            modrm = 0b00111000 | base
                            return b'\x66\x81' + pack('<B', modrm) + sib + pack('<H', im)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == ']':
                            assert tokens[10].value == ','
                            if tokens[11].value in REGISTERS16:
                                src = REGISTERS16.index(tokens[11].value)
                                modrm = 0b00000100 | src << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x66\x39' + pack('<B', modrm) + pack('<B', sib)
                            else:
                                im = int(tokens[11].value, base=16)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00111100
                                if im <= 0x7f:
                                    return b'\x66\x83' + pack('<B', modrm) + pack('<B', sib) + pack('<B', im)
                                else:
                                    return b'\x66\x81' + pack('<B', modrm) + pack('<B', sib) + pack('<H', im)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            im = int(tokens[13].value, base=16)
                            modrm = 0b10111100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x66\x83' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp) + pack('<B', im)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS16:
                            src = REGISTERS16.index(tokens[9].value)
                            sib = get_sib(base)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x66\x39' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            sib = get_sib(base)
                            modrm = 0b00111000 | base
                            if im <= 0x7f:
                                return b'\x66\x83' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<B', im)
                            else:
                                return b'\x66\x81' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<H', im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS16:
                        src = REGISTERS16.index(tokens[9].value)
                        modrm = 0b01000000 | src << 3 | base
                        return b'\x66\x39' + pack('<b', modrm) + pack('<b', -disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b01111000 | base
                        if im <= 0x7f:
                            return b'\x66\x83' + pack('<b', modrm) + pack('<b', -disp) + pack('<B', im)
                        else:
                            return b'\x66\x81' + pack('<b', modrm) + pack('<b', -disp) + pack('<H', im)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    src = REGISTERS16.index(tokens[11].value)
                    modrm = 0b00000100 | src << 3
                    sib = 0b00000101 | scale << 6 | base << 3
                    return b'\x66\x39' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                else:
                    assert False
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value in SEGMENTS:
                seg = SEGMENTS.index(tokens[3].value)
                assert tokens[4].value == ':'
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS:
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return b'\x39' + pack('<B', modrm) + pack('<I', m)
                else:
                    ib = int(tokens[7].value, base=16)
                    if ib <= 0x7f or ib >= 0xffffff00:
                        return b'\x83\x3d' + pack('<I', m) + pack('<B', ib & 0xff)
                    else:
                        return b'\x81\x3d' + pack('<I', m) + pack('<I', ib)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS:
                        src = REGISTERS.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x39' + pack('<B', modrm)
                    else:
                        imm = int(tokens[7].value, base=16)
                        if imm <= 0x7f or imm >= 0xffffff00:
                            return b'\x83' + pack('<B', 0b00111000 | base) + pack('<B', imm & 0xff)
                        else:
                            return b'\x81' + pack('<B', 0b00111000 | base) + pack('<I', imm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        if tokens[7].value == '*':
                            scale = get_scale(tokens[8].value)
                            if tokens[9].value == ']':
                                assert tokens[10].value == ','
                                if tokens[11].value in REGISTERS:
                                    src = REGISTERS.index(tokens[11].value)
                                    modrm = 0b00000100 | src << 3
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    return b'\x39' + pack('<B', modrm) + pack('<B', sib)
                                else:
                                    ib = int(tokens[11].value, base=16)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00111100
                                    if ib <= 0x7f or ib >= 0xffffff00:
                                        return b'\x83' + pack('<B', modrm) + pack('<B', sib) + pack('<B', ib & 0xff)
                                    else:
                                        return b'\x81' + pack('<B', modrm) + pack('<B', sib) + pack('<I', ib)
                            elif tokens[9].value == '+':
                                disp = int(tokens[10].value, base=16)
                                assert tokens[11].value == ']'
                                assert tokens[12].value == ','
                                if tokens[13].value in REGISTERS:
                                    src = REGISTERS.index(tokens[13].value)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00000100 | src << 3
                                    return b'\x39' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                                else:
                                    im = int(tokens[13].value, base=16)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00111100
                                    return b'\x83' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', im)
                            elif tokens[9].value == '-':
                                disp = int(tokens[10].value, base=16)
                                assert tokens[11].value == ']'
                                assert tokens[12].value == ','
                                if tokens[13].value in REGISTERS:
                                    src = REGISTERS.index(tokens[13].value)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00000100 | src << 3
                                    return b'\x39' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(-disp)
                                else:
                                    im = int(tokens[13].value, base=16)
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    modrm = 0b00111100
                                    if disp <= 0x7f:
                                        return b'\x83' + pack_modrm(modrm, disp) + pack('<B', sib) + pack('<b', -disp) + pack('<B', im & 0xff)
                                    else:
                                        return b'\x81' + pack_modrm(modrm, disp) + pack('<B', sib) + pack('<i', -disp) + pack('<I', im)
                        else:
                            assert False, 'Not implemented yet'
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            sib = get_sib(base)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x39' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                        else:
                            ib = int(tokens[9].value, base=16)
                            sib = get_sib(base)
                            modrm = 0b00111000 | base
                            if ib <= 0x7f or ib >= 0xffffff00:
                                return b'\x83' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<B', ib & 0xff)
                            else:
                                return b'\x81' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<I', ib)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x39' + pack_modrm(modrm, disp) + pack_disp(-disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b00111000 | base
                        if im <= 0x7f or im >= 0xffffff00:
                            return b'\x83' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<B', im & 0xff)
                        else:
                            return b'\x81' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<I', im)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    if tokens[11].value in REGISTERS:
                        src = REGISTERS.index(tokens[11].value)
                        modrm = 0b00000100 | src << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x39' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        im = int(tokens[11].value, base=16)
                        modrm = 0b00111100
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x83' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp) + pack('<B', im & 0xff)
                else:
                    assert False, 'Unreachable'
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)

                if state['eip'] in [0x51d5c8, 0x69e7a1, 0x6cfff0, 0x7edc0c, 0x7ff4d8]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x39' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x3b' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                prefix = b''
                if tokens[5].value == 'fs':
                    prefix = b'\x64'
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return prefix + b'\x3b' + pack('<B', modrm) + pack('<I', m)

                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x3b' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x3b' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            if tokens[11].value == ']':
                                modrm = 0b00000100 | dst << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x3b' + pack('<B', modrm) + pack('<B', sib)
                            elif tokens[11].value == '+':
                                disp = int(tokens[12].value, base=16)
                                assert tokens[13].value == ']'
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100 | dst << 3
                                return b'\x3b' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                            elif tokens[11].value == '-':
                                disp = int(tokens[12].value, base=16)
                                assert tokens[13].value == ']'
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100 | dst << 3
                                return b'\x3b' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(-disp)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            sib = get_sib(base)
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x3b' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        if disp <= 0x80:
                            modrm = 0b01000000 | dst << 3 | base
                            return b'\x3b' + pack('<B', modrm) + pack('<b', -disp)
                        else:
                            modrm = 0b10000000 | dst << 3 | base
                            return b'\x3b' + pack('<B', modrm) + pack('<i', -disp)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x3b' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
            else:
                im = int(tokens[3].value, base=16)
                if dst == REGISTERS.index('eax'):
                    if im <= 0x7f or im >= 0xffffff00:
                        modrm = 0b11111000 | dst
                        im = im & 0xff
                        return b'\x83' + pack('<B', modrm) + pack('<B', im)
                    else:
                        return b'\x3d' + pack('<I', im)
                else:
                    if im <= 0x7f or im >= 0xffffff00:
                        modrm = 0b11111000 | dst
                        return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                    else:
                        modrm = 0b11111000 | dst
                        return b'\x81' + pack('<B', modrm) + pack('<I', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)

                if state['eip'] in [
                    0x69e7fd, 0x7c18b6, 0x7c18d6, 0x7c191e, 0x7c1936, 0x7c45e1, 0x7c45ec, 0x7c45fd,
                    0x7c4610, 0x7c4621, 0x7c466b, 0x7c46cb, 0x7c46d3, 0x7c46de, 0x7c46e6, 0x7d28aa,
                    0x7d28ae, 0x7d28b4, 0x7d28b8, 0x7d28be, 0x7d28c7,
                ]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x38' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x3a' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x3a' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x3a' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            if tokens[11].value == '+':
                                disp = int(tokens[12].value, base=16)
                                assert tokens[13].value == ']'
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100 | dst << 3
                                return b'\x3a' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                            elif tokens[11].value == '-':
                                disp = int(tokens[12].value, base=16)
                                assert tokens[13].value == ']'
                                return b'\x3a\x44\x00' + pack('<b', -disp)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            sib = get_sib(base)
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x3a' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x3a' + pack('<B', modrm) + pack('<b', -disp)
            else:
                ib = int(tokens[3].value, base=16)
                modrm = 0b11111000 | dst
                if state['eip'] in [0x7bff8c]:
                    return b'\x82' + pack('<B', modrm) + pack('<B', ib & 0xff)

                if dst == REGISTERS8.index('al'):
                    return b'\x3c' + pack('<B', ib)
                else:
                    return b'\x80' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x66\x3b' + pack('<B', modrm)
            elif tokens[3].value == 'WORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x66\x3b' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x66\x3b' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            assert tokens[11].value == ']'
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x66\x3b' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            sib = get_sib(base)
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x66\x3b' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x66\x3b' + pack('<B', modrm) + pack('<b', -disp)
                        modrm = 0b01000000 | dst << 3 | base
            else:
                ib = int(tokens[3].value, base=16)
                modrm = 0b11111000 | dst

                if state['eip'] in [0x6d7b7d, 0x6d81f1, 0x6d8401]:
                    return b'\x66\x83' + pack('<B', modrm) + pack('<B', ib & 0xff)

                if dst == REGISTERS16.index('ax'):
                    return b'\x66\x3d' + pack('<H', ib)
                else:
                    if ib <= 0x7f:
                        return b'\x66\x83' + pack('<B', modrm) + pack('<B', ib & 0xff)
                    else:
                        return b'\x66\x81' + pack('<B', modrm) + pack('<H', ib)
    elif opcode == 'CMPLEPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xc2' + pack('<B', modrm) + b'\x02'
        else:
            m = int(tokens[7].value, base=16)
            return b'\x0f\xc2\x3d' + pack('<I', m) + b'\x02'
    elif opcode == 'CMPLTPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xc2' + pack('<B', modrm) + b'\x01'
        else:
            modrm = 0b00000101 | dst << 3
            m = int(tokens[7].value, base=16)
            return b'\x0f\xc2' + pack('<B', modrm) + pack('<I', m) + b'\x01'
    elif opcode == 'CMPLTSS':
        return b'\xf3\x0f\xc2\xda\x01'
    elif opcode == 'CMPNEQPS':
        modrm = 0b11000001
        return b'\x0f\xc2' + pack('<B', modrm) + b'\x04'
    elif opcode == 'CMPNLEPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xc2' + pack('<B', modrm) + b'\x06'
        else:
            modrm = 0b10000100 | dst << 3
            return b'\x0f\xc2' + pack('<B', modrm) + b'\x24\xa0\x01\x00\x00\x06'
    elif opcode == 'CMPNLTPS':
        dst = int(tokens[1].value[-1])
        modrm = 0b00000101 | dst << 3
        return b'\x0f\xc2' + pack('<B', modrm) + b'\xe0\x9a\x88\x00\x05'
    elif opcode == 'CMPS':
        if tokens[1].value == 'BYTE':
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
        elif tokens[1].value == 'DWORD':
            return b'\xa7'
    elif opcode.startswith('CMP'):
        assert False, 'Not implemented'
    elif opcode == 'COMISS':
        dst = REGISTERSXMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x2f' + pack('<B', modrm)
        else:
            return b'\x0f\x2f\x2d\xa8\x48\xb5\x00'
    elif opcode.startswith('COMIS'):
        assert False, 'Not implemented'
    elif opcode == 'CPUID':
        return b'\x0f\xa2'
    elif opcode == 'CRC32':
        assert False, 'Not implemented'
    elif opcode == 'CS':
        return b'\x2e' + assemble(line[3:], state)
    elif opcode == 'CVTDQ2PS':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x5b' + pack('<B', modrm)
    elif opcode == 'CVTPD2PS':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x66\x0f\x5a' + pack('<B', modrm)
    elif opcode == 'CVTPI2PS':
        dst = REGISTERSXMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x2a' + pack('<B', modrm)

        if tokens[6].value in REGISTERS:
            src = REGISTERS.index(tokens[6].value)
            modrm = 0b00000000 | dst << 3 | src
            return b'\x0f\x2a' + pack('<B', modrm)
        elif tokens[6].value == ':':
            m = int(tokens[7].value, base=16)
            modrm = 0b00000101 | dst << 3
            return b'\x0f\x2a' + pack('<B', modrm) + pack('<I', m)
    elif opcode == 'CVTPS2PD':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x5a' + pack('<B', modrm)
    elif opcode == 'CVTPS2PI':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x2d' + pack('<B', modrm)
    elif opcode == 'CVTSI2SS':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = REGISTERS.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\xf3\x0f\x2a' + pack('<B', modrm)
    elif opcode == 'CVTTSS2SI':
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\xf3\x0f\x2c' + pack('<B', modrm)
    elif opcode.startswith('CVT'):
        assert False, 'Not implemented'
    elif opcode == 'CWDE':
        return b'\x98'
    elif opcode == 'DAA':
        return b'\x27'
    elif opcode == 'DAS':
        return b'\x2f'
    elif opcode == 'DATA16':
        prefix = b''
        if 'ss:' in line:
            prefix = b'\x36'
        return prefix + b'\x66' + assemble(line[7:], state)
    elif opcode == 'DEC':
        if tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11001000 | dst
            return b'\xfe' + pack('<B', modrm)
        if tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            modrm = 0b01001000 | dst

            if state['eip'] in [0x73cb44, 0x73cb48]:
                modrm = 0b11001000 | dst
                return b'\xff' + pack('<B', modrm)

            return pack('<B', modrm)
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00001000 | base
                    return b'\xfe' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        modrm = 0b01001100
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        return b'\xfe' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00001000 | base
                        return b'\xfe' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    modrm = 0b01001000 | base
                    return b'\xfe' + pack('<B', modrm) + pack('<b', -disp)
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00001000 | base
                    return b'\x66\xff' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if tokens[9].value == ']':
                            modrm = 0b00001100
                            return b'\x66\xff' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            modrm = 0b10001100
                            return b'\x66\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00001000 | base
                        return b'\x66\xff' + pack_modrm(modrm, disp) + sib +  pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    modrm = 0b00000000 | base
                    return b'\x66\xff' + pack_modrm(modrm, disp) + get_sib(base) +  pack_disp(-disp)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return b'\xff\x0d' + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00001000 | base
                    return b'\xff' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if tokens[9].value == ']':
                            modrm = 0b00000100
                            return b'\xff' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[9].value == '-':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            modrm = 0b10000100
                            return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<i', -disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00001000 | base
                        return b'\xff' + pack_modrm(modrm, disp) + sib +  pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    if disp <= 0x80:
                        modrm = 0b01001000 | base
                        return b'\xff' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        modrm = 0b10001000 | base
                        return b'\xff' + pack('<B', modrm) + pack('<i', -disp)
        else:
            assert False, 'Not implemented'
    elif opcode == 'DIV':
        if tokens[1].value in REGISTERS:
            modrm = 0b11110000 | REGISTERS.index(tokens[1].value)
            return b'\xf7' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS8:
            modrm = 0b11110000 | REGISTERS8.index(tokens[1].value)
            return b'\xf6' + pack('<B', modrm)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return b'\xf7\x35' + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    sib = get_sib(base)
                    modrm = 0b00110000 | base
                    return b'\xf7' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    return b'\xf7\x75' + pack('<b', -disp)
    elif opcode.startswith('DIV'):
        assert False, 'Not implemented'
    elif opcode.startswith('DP'):
        assert False, 'Not implemented'
    elif opcode == 'DS':
        state['eip'] += 1
        inst = assemble(line[3:], state)
        state['eip'] -= 1
        return b'\x3e' + inst
    elif opcode == 'EMMS':
        return b'\x0f\x77'
    elif opcode == 'ENTER':
        ib1 = int(tokens[1].value, base=16)
        ib2 = int(tokens[3].value, base=16)
        return b'\xc8' + pack('<H', ib1) + pack('<B', ib2)
    elif opcode == 'ES':
        state['eip'] += 1
        inst = assemble(line[3:], state)
        state['eip'] -= 1
        return b'\x26' + inst
    elif opcode.startswith('E'):
        assert False, 'Not implemented'
    elif opcode == 'F2XM1':
        return b'\xd9\xf0'
    elif opcode == 'FABS':
        return b'\xd9\xe1'
    elif opcode == 'FADD':
        if tokens[1].value == 'st':
            if tokens[2].value == ',':
                assert tokens[3].value == 'st'
                assert tokens[4].value == '('
                i = int(tokens[5].value)
                assert tokens[6].value == ')'
                return b'\xd8' + pack('<B', 0xc0 + i)
            else:
                assert tokens[2].value == '('
                i = int(tokens[3].value)
                assert tokens[4].value == ')'
                assert tokens[5].value == ','
                assert tokens[6].value == 'st'
                return b'\xdc' + pack('<B', 0xc0 + i)
        elif tokens[1].value in ['DWORD', 'QWORD']:
            return mxxfp(tokens, {
                'DWORD': [b'\xd8', 0],
                'QWORD': [b'\xdc', 0],
            })
        else:
            assert False, 'Not implemented'
    elif opcode == 'FADDP':
        assert tokens[1].value == 'st'
        assert tokens[2].value == '('
        i = int(tokens[3].value)
        assert tokens[4].value == ')'
        assert tokens[5].value == ','
        assert tokens[6].value == 'st'
        return b'\xde' + pack('<B', 0xc0 | i)
    elif opcode == 'FBLD':
        assert tokens[1].value == 'TBYTE'
        assert tokens[2].value == 'PTR'
        assert tokens[3].value == '['
        base = REGISTERS.index(tokens[4].value)
        assert tokens[5].value == '-'
        #bcd = int()
        assert tokens[7].value == ']'
        # TODO: Proper implementation
        return b'\xdf\xa5\x53\x00\xf6\xa6'
    elif opcode.startswith('FB'):
        assert False, 'Not implemented'
    elif opcode == 'FCHS':
        return b'\xd9\xe0'
    elif opcode == 'FCLEX':
        return b'\x9b\xdb\xe2'
    elif opcode == 'FNCLEX':
        return b'\xdb\xe2'
    elif opcode == 'FCMOVBE':
        assert tokens[1].value == 'st'
        assert tokens[2].value == ','
        assert tokens[3].value == 'st'
        assert tokens[4].value == '('
        i = int(tokens[5].value)
        assert tokens[6].value == ')'
        return b'\xda' + pack('<B', 0xd0 + i)
    elif opcode == 'FCMOVE':
        assert tokens[1].value == 'st'
        assert tokens[2].value == ','
        assert tokens[3].value == 'st'
        assert tokens[4].value == '('
        i = int(tokens[5].value)
        assert tokens[6].value == ')'
        return b'\xda' + pack('<B', 0xc8 + i)
    elif opcode.startswith('FCMOV'):
        assert False, 'Not implemented'
    elif opcode == 'FCOM':
        if tokens[1].value == 'st':
            assert tokens[2].value == '('
            i = int(tokens[3].value)
            assert tokens[4].value == ')'
            return b'\xd8' + pack('<B', 0xd0 + i)
        elif tokens[1].value in ['DWORD', 'QWORD']:
            op = {'DWORD': b'\xd8', 'QWORD': b'\xdc'}[tokens[1].value]
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return op + b'\x15' + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00010000 | base
                    return op + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | scale << 6 | idx << 3 | base
                        return op + b'\x14' + pack('<B', modrm)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00010000 | base
                        return op + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    modrm = 0b00010000 | base
                    return op + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(-disp)
        else:
            assert False
    elif opcode == 'FCOMP':
        if tokens[1].value == 'st':
            assert tokens[2].value == '('
            i = int(tokens[3].value)
            assert tokens[4].value == ')'
            return b'\xd8' + pack('<B', 0xd8 + i)
        elif tokens[1].value in ['DWORD', 'QWORD']:
            return mxxfp(tokens, {
                'DWORD': [b'\xd8', 3],
                'QWORD': [b'\xdc', 3],
            })
        else:
            assert False, 'Not implemented'
    elif opcode == 'FCOMPP':
        return b'\xde\xd9'
    elif opcode.startswith('FCOM'):
        assert False, 'Not implemented'
    elif opcode == 'FCOS':
        return b'\xd9\xff'
    elif opcode == 'FDECSTP':
        return b'\xd9\xf6'
    elif opcode == 'FDIV':
        if tokens[1].value == 'st':
            assert tokens[2].value == ','
            assert tokens[3].value == 'st'
            assert tokens[4].value == '('
            i = int(tokens[5].value)
            assert tokens[6].value == ')'
            return b'\xd8' + pack('<B', 0xf0 + i)
        elif tokens[1].value in ['DWORD', 'QWORD']:
            op = {'DWORD': b'\xd8', 'QWORD': b'\xdc'}[tokens[1].value]
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return op + b'\x35' + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    return op + pack('<B', 0x30 | base)
                elif tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    sib = get_sib(base)
                    modrm = 0b00110000 | base
                    return op + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    modrm = 0b00110000 | base
                    return op + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(-disp)
    elif opcode == 'FDIVP':
        assert tokens[1].value == 'st'
        assert tokens[2].value == '('
        i = int(tokens[3].value)
        assert tokens[4].value == ')'
        assert tokens[5].value == ','
        assert tokens[6].value == 'st'
        return b'\xde' + pack('<B', 0xf8 + i)
    elif opcode == 'FDIVR':
        if tokens[1].value == 'st':
            assert tokens[2].value == ','
            assert tokens[3].value == 'st'
            assert tokens[4].value == '('
            i = int(tokens[5].value)
            assert tokens[6].value == ')'
            return b'\xd8' + pack('<B', 0xf8 + i)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                assert tokens[5].value == '+'
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                sib = get_sib(base)
                modrm = 0b00111000 | base
                return b'\xd8' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
            elif tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return b'\xd8\x3d' + pack('<I', m)
        elif tokens[1].value == 'QWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return b'\xdc\x3d' + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                assert tokens[5].value == '+'
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                sib = get_sib(base)
                modrm = 0b01111000 | base
                return b'\xdc' + pack('<B', modrm) + sib + pack('<B', disp)
        else:
            assert False
    elif opcode == 'FDIVRP':
        assert tokens[1].value == 'st'
        assert tokens[2].value == '('
        i = int(tokens[3].value)
        assert tokens[4].value == ')'
        assert tokens[5].value == ','
        assert tokens[6].value == 'st'
        return b'\xde' + pack('<B', 0xf0 + i)
    elif opcode.startswith('FDIV'):
        assert False, 'Not implemented'
    elif opcode == 'FEMMS':
        return b'\x0f\x0e'
    elif opcode == 'FFREE':
        assert tokens[1].value == 'st'
        assert tokens[2].value == '('
        i = int(tokens[3].value)
        assert tokens[4].value == ')'
        return b'\xdd' + pack('<B', 0xc0 + i)
    elif opcode == 'FIADD':
        if tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return b'\xda\x05' + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    return b'\xda\x03'
                elif tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    sib = get_sib(base)
                    if disp <= 0xff:
                        modrm = 0b01000000 | base
                        return b'\xda' + pack('<B', modrm) + sib + pack('<B', disp)
                    else:
                        modrm = 0b10000000 | base
                        return b'\xda' + pack('<B', modrm) + sib + pack('<I', disp)
        elif tokens[1].value == 'WORD':
            return b'\xde\x43\x00'
        else:
            assert False
    elif opcode == 'FICOM':
        if tokens[3].value in SEGMENTS:
            return b'\x3e\xda\x52\x00'
        elif tokens[1].value == 'WORD':
            if len(tokens) == 10:
                return b'\xde\x14\x7d\x00\xc8\x14\x7d'
            return b'\xde\x52\x00'
        elif tokens[1].value == 'DWORD':
            base = REGISTERS.index(tokens[4].value)
            disp = int(tokens[6].value, base=16)
            modrm = 0b01010000 | base
            return b'\xda' + pack('<B', modrm) + pack('<B', disp)
    elif opcode.startswith('FICOM'):
        assert False, 'Not implemented'
    elif opcode == 'FIDIV':
        if tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            modrm = 0b00110000 | base
            if tokens[5].value == ']':
                return b'\xda' + pack('<B', modrm)
            elif tokens[5].value == '+':
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == '+'
                    disp = int(tokens[10].value, base=16)
                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                    return b'\xda\x74' + pack('<B', sib) + b'\x08'
                else:
                    disp = int(tokens[6].value, base=16)
                    return b'\xda' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
            elif tokens[5].value == '*':
                scale = get_scale(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                modrm = 0b00110100
                sib = 0b00001101 | scale << 6
                return b'\xda' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
        elif tokens[1].value == 'WORD':
            assert False
        else:
            assert False, 'Not implemented'
    elif opcode == 'FIDIVR':
        return b'\xde\x7f\x00'
    elif opcode == 'FILD':
        if state['eip'] in [0x69e821]:
            return b'\x9b\xdf\x69\x00'

        if tokens[1].value in ['WORD', 'DWORD', 'QWORD']:
            return mxxfp(tokens, {
                'WORD':  [b'\xdf', 0],
                'DWORD': [b'\xdb', 0],
                'QWORD': [b'\xdf', 5],
            })
        else:
            assert False, 'Not implemented'
    elif opcode == 'FIMUL':
        if tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if base == REGISTERS.index('esp'):
                assert tokens[5].value == '+'
                disp = int(tokens[6].value, base=16)
                return b'\xda\x4c\x24' + pack('<B', disp)
            else:
                assert tokens[5].value == '+'
                disp = int(tokens[6].value, base=16)
                modrm = 0b00001000 | base
                return b'\xda' + pack_modrm(modrm, disp) + pack_disp(disp)
        elif tokens[1].value == 'WORD':
            return b'\xde\x4a\x00'
        else:
            assert False, 'Not implemented'
    elif opcode == 'FINCSTP':
        return b'\xd9\xf7'
    elif opcode == 'FINIT':
        return b'\x9b\xdb\xe3'
    elif opcode == 'FNINIT':
        return b'\xdb\xe3'
    elif opcode == 'FIST':
        return b'\xdb\x52\x00'
    elif opcode == 'FISTP':
        if tokens[1].value in ['DWORD', 'QWORD']:
            op = {'DWORD': b'\xdb', 'QWORD': b'\xdf'}[tokens[1].value]
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                if base == REGISTERS.index('esp'):
                    return op + b'\x5c\x24' + pack('<B', disp)
                else:
                    modrm = 0b01011000 | base
                    if tokens[1].value == 'QWORD':
                        modrm |= 0b00100000
                    return op + pack('<B', modrm) + pack('<B', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                if base == REGISTERS.index('esp'):
                    return op + b'\x5c\x24' + pack('<b', -disp)
                else:
                    modrm = 0b01011000 | base
                    if tokens[1].value == 'QWORD':
                        modrm |= 0b00100000
                    return op + pack('<B', modrm) + pack('<b', -disp)
        else:
            assert False
    elif opcode == 'FISTTP':
        op = {'WORD': b'\xdf', 'DWORD': b'\xdb', 'QWORD': b'\xdd'}[tokens[1].value]
        base = REGISTERS.index(tokens[4].value)
        if tokens[1].value == 'WORD':
            modrm = 0b00001000 | base
            return op + pack('<B', modrm)
        else:
            modrm = 0b01001000 | base
            return op + pack('<B', modrm) + b'\x00'
    elif opcode.startswith('FIST'):
        assert False, 'Not implemented'
    elif opcode == 'FISUB':
        base = REGISTERS.index(tokens[4].value)
        sib = get_sib(base)
        if tokens[5].value == '+':
            disp = int(tokens[6].value, base=16)
            modrm = 0b00100000 | base
            return b'\xda' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
        elif tokens[5].value == '-':
            disp = -int(tokens[6].value, base=16)
            return b'\xda\x65' + sib + pack('<b', disp)
        elif tokens[5].value == ']':
            return b'\xda\x27' + sib
    elif opcode == 'FISUBR':
        if tokens[1].value == 'WORD':
            return b'\xde\x69\x00'
        elif tokens[1].value == 'DWORD':
            base = REGISTERS.index(tokens[4].value)
            return b'\xda\x69\x00'
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
                    base = REGISTERS.index(tokens[4].value)
                    if tokens[5].value == ']':
                        if base == REGISTERS.index('esp'):
                            if tokens[1].value == 'TBYTE':
                                return op + b'\x2c\x24'
                            else:
                                return op + b'\x04\x24'
                        else:
                            return op + pack('<B', 0x0 + base)
                    elif tokens[5].value == '+':
                        if tokens[6].value in REGISTERS:
                            idx = REGISTERS.index(tokens[6].value)
                            assert tokens[7].value == '*'
                            scale = get_scale(tokens[8].value)
                            if tokens[9].value == '-':
                                im = int(tokens[10].value, base=16)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                if im <= 0x7f:
                                    modrm = 0b01000100
                                    return op + pack('<B', modrm) + pack('<B', sib) + pack('<b', -im)
                                else:
                                    modrm = 0b10000100
                                    return op + pack('<B', modrm) + pack('<B', sib) + pack('<i', -im)
                            elif tokens[9].value == '+':
                                im = int(tokens[10].value, base=16)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                if im <= 0x7f:
                                    modrm = 0b01000100
                                    return op + pack('<B', modrm) + pack('<B', sib) + pack('<B', im)
                                else:
                                    modrm = 0b10000100
                                    return op + pack('<B', modrm) + pack('<B', sib) + pack('<I', im)
                            elif tokens[9].value == ']':
                                modrm = 0b00000100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return op + pack('<B', modrm) + pack('<B', sib)
                            modrm = 0b01000100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return op + pack('<B', modrm) + pack('<B', sib) + pack('<B', ib)
                        else:
                            disp = int(tokens[6].value, base=16)
                            assert tokens[7].value == ']'
                            sib = get_sib(base)
                            modrm = 0b00000000 | mod << 3 | base
                            return op + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                    elif tokens[5].value == '*':
                        scale = get_scale(tokens[6].value)
                        assert tokens[7].value == '+'
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b00000100
                        #if tokens[1].value == '
                        sib = 0b00000101 | scale << 6 | base << 3
                        return op + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    elif tokens[5].value == '-':
                        im = int(tokens[6].value, base=16)
                        #print(ib, hex(ib))
                        sib = get_sib(base)
                        if im <= 0x7f:
                            modrm = 0b01000000 | base
                            if tokens[1].value == 'TBYTE':
                                modrm |= 0b00101000
                            return op + pack('<B', modrm) + sib + pack('<b', -im)
                        else:
                            modrm = 0b10000000 | base
                            if tokens[1].value == 'TBYTE':
                                modrm |= 0b00101000
                            return op + pack('<B', modrm) + sib + pack('<i', -im)
                else:
                    assert False, 'Not implemented'
            elif tokens[3].value in SEGMENTS:
                seg = SEGMENTS.index(tokens[3].value)
                assert tokens[4].value == ':'
                if tokens[5].value == '[':
                    return b'\x65' + op + b'\x69\x00'
                else:
                    modrm = 0b00000101
                    if tokens[1].value == 'TBYTE':
                        modrm = 0b00101101
                        if tokens[3].value == 'ds':
                            op = b'\xdb'
                    im = int(tokens[5].value, base=16)
                    return op + pack('<B', modrm) + pack('<I', im)
        else:
            assert False, 'Not implemented'
    elif opcode == 'FLD1':
        return b'\xd9\xe8'
    elif opcode == 'FLDCW':
        assert tokens[1].value == 'WORD'
        assert tokens[2].value == 'PTR'
        assert tokens[3].value == '['
        base = REGISTERS.index(tokens[4].value)
        if tokens[5].value == '+':
            sign = 1
        elif tokens[5].value == '-':
            sign = -1
        elif tokens[5].value == ']':
            if base == REGISTERS.index('esp'):
                return b'\xd9\x2c\x24'
            else:
                modrm = 0x2a
                return b'\xd9' + pack('<B', modrm)
        disp = int(tokens[6].value, base=16)
        assert tokens[7].value == ']'
        if state['eip'] == 0x7cee36:
            return b'\x9b\xd9\x6c\x24' + pack('<B', disp)
        modrm = 0b00101000 | base
        return b'\xd9' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(sign * disp)
    elif opcode == 'FLDENV':
        if tokens[2].value == 'esp':
            return b'\xd9\x24\x24'
        else:
            return b'\xd9\x22'
    elif opcode == 'FLDL2E':
        return b'\xd9\xea'
    elif opcode == 'FLDLG2':
        return b'\xd9\xec'
    elif opcode == 'FLDLN2':
        return b'\xd9\xed'
    elif opcode == 'FLDPI':
        return b'\xd9\xeb'
    elif opcode == 'FLDZ':
        return b'\xd9\xee'
    elif opcode.startswith('FLD'):
        assert False, 'Not implemented'
    elif opcode == 'FMUL':
        if tokens[1].value == 'st':
            assert tokens[2].value == ','
            assert tokens[3].value == 'st'
            assert tokens[4].value == '('
            i = int(tokens[5].value)
            assert tokens[6].value == ')'
            return b'\xd8' + pack('<B', 0xc8 + i)
        elif tokens[1].value in ['DWORD', 'QWORD']:
            return mxxfp(tokens, {
                'DWORD': [b'\xd8', 1],
                'QWORD': [b'\xdc', 1],
            })
        else:
            assert False, 'Not implemented'
    elif opcode == 'FMULP':
        if tokens[1].value == 'st':
            assert tokens[2].value == '('
            i = int(tokens[3].value)
            assert tokens[4].value == ')'
            assert tokens[5].value == ','
            assert tokens[6].value == 'st'
            return b'\xde' + pack('<B', 0xc8 + i)
        else:
            assert False, 'Not implemented'
    elif opcode == 'FNOP':
        return b'\xd9\xd0'
    elif opcode == 'FNSTCW':
        if tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                sib = get_sib(base)
                modrm = 0b01111000 | base
                return b'\xd9' + pack('<B', modrm) + sib + pack('<b', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                sib = get_sib(base)
                modrm = 0b01111000 | base
                return b'\xd9' + pack('<B', modrm) + sib + pack('<b', -disp)
            else:
                assert False
        else:
            assert False
    elif opcode == 'FNSTENV':
        return b'\xd9\x34\x24'
    elif opcode == 'FNSTSW':
        if tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            return b'\xdf\xe0'
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                modrm = 0b01111000 | base
                return b'\xdd' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                return b'\xdd\x7d' + pack('<b', -disp)
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
        base = REGISTERS.index(tokens[2].value)
        disp = int(tokens[4].value, base=16)
        modrm = 0b01100000 | base
        return b'\xdd' + pack('<B', modrm) + pack('<B', disp)
    elif opcode == 'FSAVE':
        base = REGISTERS.index(tokens[2].value)
        modrm = 0b01110000 | base
        return b'\x9b\xdd' + pack('<B', modrm) + b'\x08'
    elif opcode == 'FNSAVE':
        assert False, 'Not implemented'
    elif opcode == 'FS':
        state['eip'] += 1
        inst = assemble(line[3:], state)
        state['eip'] -= 1
        return b'\x64' + inst
    elif opcode == 'FSCALE':
        return b'\xd9\xfd'
    elif opcode == 'FSIN':
        return b'\xd9\xfe'
    elif opcode == 'FSINCOS':
        return b'\xd9\xfb'
    elif opcode == 'FSQRT':
        return b'\xd9\xfa'
    elif opcode == 'FST':
        if tokens[1].value == 'st':
            assert tokens[2].value == '('
            i = int(tokens[3].value)
            assert tokens[4].value == ')'
            return b'\xdd' + pack('<B', 0xd0 + i)
        elif tokens[1].value in ['DWORD', 'TBYTE', 'QWORD']:
            return mxxfp(tokens, {
                'DWORD': [b'\xd9', 2],
                'QWORD': [b'\xdd', 2],
            })
        else:
            assert False, 'Not implemented'
    elif opcode == 'FSTCW':
        assert tokens[1].value == 'WORD'
        assert tokens[2].value == 'PTR'
        assert tokens[3].value == '['
        if tokens[4].value == 'esp':
            return b'\x9b\xd9\x3c\x24'
        else:
            assert tokens[5].value == '-'
            disp = int(tokens[6].value, base=16)
            modrm = 0b00111101
            return b'\x9b\xd9' + pack_modrm(modrm, disp) + pack_disp(-disp)
    elif opcode == 'FSTP':
        if tokens[1].value == 'st':
            assert tokens[2].value == '('
            i = int(tokens[3].value)
            assert tokens[4].value == ')'
            return b'\xdd' + pack('<B', 0xd8 + i)
        elif tokens[1].value in ['DWORD', 'TBYTE', 'QWORD']:
            return mxxfp(tokens, {
                'DWORD': [b'\xd9', 3],
                'TBYTE': [b'\xdb', 7],
                'QWORD': [b'\xdd', 3],
            })
        else:
            assert False, 'Not implemented'
    elif opcode == 'FSTSW':
        if tokens[1].value == 'WORD':
            base = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == '-'
            disp = int(tokens[6].value, base=16)
            modrm = 0b00111101
            return b'\x9b\xdd' + pack_modrm(modrm, disp) + pack_disp(-disp)
        if state['eip'] == 0x7ca608:
            return b'\x9b\x9b\xdf\xe0'
        return b'\x9b\xdf\xe0'
    elif opcode.startswith('FST'):
        assert False, 'Not implemented'
    elif opcode == 'FSUB':
        if tokens[1].value == 'st':
            if tokens[2].value == ',':
                assert tokens[3].value == 'st'
                assert tokens[4].value == '('
                i = int(tokens[5].value)
                assert tokens[6].value == ')'
                return b'\xd8' + pack('<B', 0xe0 + i)
            else:
                assert tokens[2].value == '('
                i = int(tokens[3].value)
                assert tokens[4].value == ')'
                assert tokens[5].value == ','
                assert tokens[6].value == 'st'
                return b'\xdc' + pack('<B', 0xe8 + i)
        elif tokens[1].value in ['DWORD', 'QWORD']:
            return mxxfp(tokens, {
                'DWORD': [b'\xd8', 4],
                'QWORD': [b'\xdc', 4],
            })
        else:
            assert False, 'Not implemented'
    elif opcode == 'FSUBP':
        assert tokens[1].value == 'st'
        assert tokens[2].value == '('
        i = int(tokens[3].value)
        assert tokens[4].value == ')'
        assert tokens[5].value == ','
        assert tokens[6].value == 'st'
        return b'\xde' + pack('<B', 0xe8 | i)
    elif opcode == 'FSUBR':
        if tokens[1].value in ['DWORD', 'QWORD']:
            op = {'DWORD': b'\xd8', 'QWORD': b'\xdc'}[tokens[1].value]
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return op + b'\x2d' + pack('<I', m)
            elif tokens[3].value == 'fs':
                return b'\x64' + op + b'\x69\x00'
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00101000 | base
                    return op + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        return op + b'\x2c\x07'
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    sib = get_sib(base)
                    modrm = 0b00101000 | base
                    return op + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    modrm = 0b00101000 | base
                    return op + pack_modrm(modrm, disp) + pack_disp(-disp)
        elif tokens[1].value == 'st':
            if tokens[2].value == ',':
                assert tokens[3].value == 'st'
                assert tokens[4].value == '('
                i = int(tokens[5].value)
                assert tokens[6].value == ')'
                return b'\xd8' + pack('<B', 0xe8 + i)
            elif tokens[2].value == '(':
                i = int(tokens[3].value)
                assert tokens[4].value == ')'
                assert tokens[5].value == ','
                assert tokens[6].value == 'st'
                return b'\xdc' + pack('<B', 0xe0 + i)
        else:
            assert False
    elif opcode == 'FSUBRP':
        assert tokens[1].value == 'st'
        assert tokens[2].value == '('
        i = int(tokens[3].value)
        assert tokens[4].value == ')'
        return b'\xde' + pack('<B', 0xe0 + i)
    elif opcode.startswith('FSUB'):
        assert False, 'Not implemented'
    elif opcode == 'FTST':
        return b'\xd9\xe4'
    elif opcode == 'FUCOMP':
        return b'\xdd\xee'
    elif opcode.startswith('FUCOM'):
        assert False, 'Not implemented'
    elif opcode == 'FWAIT':
        return b'\x9b'
    elif opcode == 'FXAM':
        return b'\xd9\xe5'
    elif opcode == 'FXCH':
        assert tokens[1].value == 'st'
        assert tokens[2].value == '('
        i = int(tokens[3].value)
        assert tokens[4].value == ')'
        return b'\xd9' + pack('<B', 0xc8 | i)
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
    elif opcode == 'GS':
        state['eip'] += 1
        inst = assemble(line[3:], state)
        state['eip'] -= 1
        return b'\x65' + inst
    elif opcode.startswith('HADDP'):
        assert False, 'Not implemented'
    elif opcode == 'HLT':
        return b'\xf4'
    elif opcode == 'HRESET':
        assert False, 'Not implemented'
    elif opcode.startswith('HSUBP'):
        assert False, 'Not implemented'
    elif opcode == 'IDIV':
        if tokens[1].value in REGISTERS:
            reg = REGISTERS.index(tokens[1].value)
            modrm = 0xf8 | reg
            return b'\xf7' + pack('<B', modrm)
        prefix = b''
        if tokens[1].value == 'WORD':
            prefix = b'\x66'
        if tokens[1].value in ['DWORD', 'WORD']:
            assert tokens[2].value == 'PTR'
            if tokens[3].value in SEGMENTS:
                prefix = {'ss': b'\x36'}[tokens[3].value]
                tokens = tokens[2:]
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00111000 | base
                    return b'\xf7' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    sib = get_sib(base)
                    modrm = 0b00111000 | base
                    return prefix + b'\xf7' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
    elif opcode == 'IMUL':
        if tokens[1].value in REGISTERS8:
            assert len(tokens) == 2
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11101000 | dst
            return b'\xf6' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x66\x0f\xaf' + pack('<B', modrm)
            elif tokens[3].value == 'WORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x66\x0f\xaf' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b01000100 | dst << 3
                    sib = get_sib(base)
                    return b'\x66\x0f\xaf' + pack('<B', modrm) + sib + pack('<B', disp)
                else:
                    assert False
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            if len(tokens) == 2:
                modrm = 0b11101000 | dst
                return b'\xf7' + pack('<B', modrm)
            else:
                assert tokens[2].value == ','
                if tokens[3].value in REGISTERS:
                    src = REGISTERS.index(tokens[3].value)
                    if len(tokens) == 4:
                        modrm = 0b11000000 | dst << 3 | src
                        return b'\x0f\xaf' + pack('<B', modrm)
                    else:
                        assert tokens[4].value == ','
                        im = int(tokens[5].value, base=16)
                        modrm = 0b11000000 | dst << 3 | src
                        if im <= 0x7f or im >= 0xffffff00:
                            return b'\x6b' + pack('<B', modrm) + pack('<B', im & 0xff)
                        else:
                            return b'\x69' + pack('<B', modrm) + pack('<I', im)
                elif tokens[3].value == 'DWORD':
                    assert tokens[4].value == 'PTR'
                    assert tokens[5].value == '['
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        if len(tokens) == 8:
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x0f\xaf' + pack('<B', modrm)
                        else:
                            assert tokens[8].value == ','
                            im = int(tokens[9].value, base=16)
                            modrm = 0b00000000 | dst << 3 | base
                            if im <= 0x7f or im >= 0xffffff00:
                                return b'\x6b' + pack('<B', modrm) + pack('<B', im & 0xff)
                            else:
                                return b'\x69' + pack('<B', modrm) + pack('<I', im)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            assert tokens[11].value == ']'
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x0f\xaf' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            if len(tokens) == 10:
                                sib = get_sib(base)
                                modrm = 0b00000000 | dst << 3 | base
                                return b'\x0f\xaf' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                            else:
                                im = int(tokens[11].value, base=16)
                                modrm = 0b01000000 | dst << 3 | base
                                if im <= 0x7f or im > 0xffffff00:
                                    return b'\x6b' + pack('<B', modrm) + pack('<B', disp) + pack('<B', im & 0xff)
                                else:
                                    return b'\x69' + pack('<B', modrm) + pack('<B', disp) + pack('<I', im)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        if len(tokens) == 10:
                            if disp <= 0x80:
                                modrm = 0b01000000 | dst << 3 | base
                                return b'\x0f\xaf' + pack('<B', modrm) + pack('<b', -disp)
                            else:
                                modrm = 0b10000000 | dst << 3 | base
                                return b'\x0f\xaf' + pack('<B', modrm) + pack('<i', -disp)
                        elif tokens[10].value == ',':
                            im = int(tokens[11].value, base=16)
                            modrm = 0b10000000 | dst << 3 | base
                            return b'\x69' + pack('<B', modrm) + pack('<i', -disp) + pack('<I', im)
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                sib = get_sib(base)
                modrm = 0b00101000 | base
                return b'\xf6' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
            elif tokens[5].value == ']':
                modrm = 0b00100000 | base
                return b'\xf6' + pack('<B', modrm)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                sib = get_sib(base)
                modrm = 0b01101000 | base
                return b'\xf7' + pack('<B', modrm) + sib + pack('<B', disp)
            elif tokens[5].value == ']':
                modrm = 0b00100000 | base
                return b'\xf7' + pack('<B', modrm)
    elif opcode == 'IN':
        if tokens[1].value == 'al':
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                return b'\xec'
            else:
                ib = int(tokens[3].value, base=16)
                return b'\xe4' + pack('<B', ib)
        elif tokens[1].value == 'eax':
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                return b'\xed'
            else:
                ib = int(tokens[3].value, base=16)
                return b'\xe5' + pack('<B', ib)
        else:
            assert False, 'Not implemented'
    elif opcode == 'INC':
        if tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11000000 | dst
            return b'\xfe' + pack('<B', modrm)
        if tokens[1].value in REGISTERS:
            return pack('<B', 0x40 + REGISTERS.index(tokens[1].value))
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00000000 | base
                    return b'\xfe' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        modrm = 0b01000100
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        return b'\xfe' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00000000 | base
                        return b'\xfe' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    modrm = 0b01000000 | base
                    return b'\xfe' + pack('<B', modrm) + pack('<b', -disp)
        elif tokens[1].value == 'WORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00000000 | base
                    return b'\x66\xff' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if tokens[9].value == ']':
                            modrm = 0b00000100
                            return b'\x66\xff' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            modrm = 0b10000100
                            return b'\x66\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00000000 | base
                        return b'\x66\xff' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    modrm = 0b00000000 | base
                    return b'\x66\xff' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(-disp)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return b'\xff\x05' + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    modrm = 0b00000000 | base
                    return b'\xff' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if tokens[9].value == ']':
                            modrm = 0b00000100
                            return b'\xff' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[9].value == '-':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            modrm = 0b10000100
                            return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<i', -disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00000000 | base
                        return b'\xff' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    if disp <= 0x80:
                        modrm = 0b01000000 | base
                        return b'\xff' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        modrm = 0b10000000 | base
                        return b'\xff' + pack('<B', modrm) + pack('<i', -disp)
        else:
            assert False, 'Not implemented'
    elif opcode.startswith('INCSS'):
        assert False, 'Not implemented'
    elif opcode == 'INS':
        if tokens[1].value == 'DWORD':
            return b'\x6d'
        elif tokens[6].value in REGISTERS16:
            return b'\x67\x6c'
        else:
            return b'\x6c'
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
        to = int(tokens[1].value, base=16)
        rel = to - state['eip'] - 2

        if opcode == 'JGE' and to == 0x681565:
            rel -= 4
            return b'\x0f' + pack('<B', op[0] + 0x10) + pack('<I', rel)
        if opcode == 'JE' and to > 0x84d000:
            rel -= 4
            return b'\x0f' + pack('<B', op[0] + 0x10) + pack('<I', rel)

        if rel > 0x7f:
            rel -= 4
            return b'\x0f' + pack('<B', op[0] + 0x10) + pack('<I', rel)
        elif rel < -0x80:
            rel -= 4
            return b'\x0f' + pack('<B', op[0] + 0x10) + pack('<i', rel)
        else:
            return op + pack('<b', rel)
    elif opcode == 'JMP':
        if tokens[1].value in REGISTERS:
            reg = REGISTERS.index(tokens[1].value)
            return b'\xff' + pack('<B', 0xe0 | reg)
        elif tokens[1].value == 'FWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            if tokens[4].value in REGISTERS:
                base = REGISTERS.index(tokens[4].value)
                assert tokens[5].value == '+'
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                modrm = 0b01101000 | base
                return b'\xff' + pack('<B', modrm) + pack('<B', disp)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                return b'\xff\x25' + pack('<I', m)
            elif tokens[3].value == '[':
                if tokens[4].value in REGISTERS:
                    base = REGISTERS.index(tokens[4].value)
                    if tokens[5].value == ']':
                        return b'\xff' + pack('<B', 0x20 | base)
                    elif tokens[5].value == '*':
                        scale = get_scale(tokens[6].value)
                        if tokens[7].value == '+':
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b00100100
                            sib = 0b00000101 | scale << 6 | base << 3
                            return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                        else:
                            assert False, 'not implemented yet'
                    elif tokens[5].value == '+':
                        disp = int(tokens[6].value, base=16)
                        modrm = 0b00100000 | base
                        return b'\xff' + pack_modrm(modrm, disp) + pack_disp(disp)
                    else:
                        assert False, 'not implemented yet'
                else:
                    assert False, 'Not implemented yet'
        elif len(tokens) > 2 and tokens[2].value == ':':
            disp = int(tokens[1].value, base=16)
            ptr = int(tokens[3].value, base=16)
            return b'\xea' + pack('<I', ptr) + pack('<H', disp)
        else:
            to = int(tokens[1].value, base=16)
            rel = to - state['eip'] - 2
            if rel > 0x7f or rel < -0x80 or tokens[1].value in [
                '0x4031e0', '0x403610', '0x403ebc', '0x40d470', '0x40d530',
            ] or state['eip'] in [ 0x4199f0, 0x419ab0, 0x41ad70, 0x41b230, 0x41b530, 0x41be40, 0x41bf00, 0x41ca20, 0x41cae0, 0x41ce70, 0x41d670, 0x41dca0, 0x41dd60, 0x41e7f0, 0x41e8b0, 0x41efc0, 0x41f080, 0x421f70, 0x422b10, 0x422bd0, 0x423ad0, 0x424b60, 0x424d30, 0x424df0, 0x4270e0, 0x427d80, 0x429e20, 0x42a180, 0x431190, 0x431250, 0x432550, 0x432610, 0x432770, 0x432830, 0x432f90, 0x433990, 0x433b10, 0x433ca0, 0x436fe0, 0x437900, 0x438a20, 0x438ed0, 0x438f90, 0x439020, 0x43a380, 0x43a440, 0x43d7e0, 0x43d8a0, 0x43e190, 0x43e620, 0x43ed00, 0x43f260, 0x43f410, 0x43f4d0, 0x440b00, 0x4410f0, 0x441400, 0x4414c0, 0x441cd0, 0x441d90, 0x442e50, 0x443d70, 0x443e30, 0x445520, 0x4455e0, 0x447c30, 0x447cf0, 0x44b320, 0x44b3e0, 0x44ca80, 0x44cb40, 0x44fa70, 0x44fb30, 0x450600, 0x4506c0, 0x4514b0, 0x451570, 0x453190, 0x453250, 0x454950, 0x454a10, 0x455510, 0x4555d0, 0x45600a, 0x456b00, 0x457120, 0x4571e0, 0x457950, 0x457a10, 0x459a00, 0x459ac0, 0x45a250, 0x45a3e0, 0x45a4a0, 0x45b640, 0x45bbf0, 0x45bf10, 0x45bfd0, 0x45d780, 0x45d840, 0x45dcb0, 0x45dd70, 0x45e3e0, 0x45e640, 0x45e700, 0x45f690, 0x45f750, 0x460160, 0x460220, 0x4606b0, 0x460770, 0x4615a0, 0x461aa0, 0x461b60, 0x463000, 0x4630c0, 0x4634c0, 0x463580, 0x4660e0, 0x4661a0, 0x466da0, 0x466e60, 0x468040, 0x468100, 0x4682b0, 0x468370, 0x46c2c0, 0x46c6b0, 0x46cb90, 0x46cc50, 0x46d650, 0x46d710, 0x46e6d0, 0x46e803, 0x46e810, 0x46ebb0, 0x46ec70, 0x46f480, 0x46f540, 0x46f9d0, 0x46fa90, 0x4717a0, 0x471c00, 0x471cc0, 0x477540, 0x477600, 0x4794e0, 0x4795a0, 0x479f70, 0x47a030, 0x47a5e0, 0x47a6a0, 0x47b400, 0x47b4c0, 0x47ba20, 0x47bae0, 0x47c8a0, 0x47c960, 0x47ce70, 0x47d7c0, 0x47d880, 0x47dbd0, 0x47dc90, 0x47e540, 0x47e600, 0x4813f0, 0x4817c0, 0x481880, 0x481f00, 0x481fc0, 0x484400, 0x484730, 0x4847f0, 0x487530, 0x4879e0, 0x487aa0, 0x48aba0, 0x48af20, 0x48afe0, 0x48b4f0, 0x48b9c0, 0x48ba80, 0x48c190, 0x48c490, 0x48c550, 0x48fe90, 0x490250, 0x490310, 0x493440, 0x493500, 0x494200, 0x4942c0, 0x494c80, 0x494d40, 0x495f70, 0x496030, 0x497380, 0x497f60, 0x4982a0, 0x4984b0, 0x498a20, 0x498aa0, 0x499843, 0x499850, 0x499910, 0x4b44b0, 0x4b45f3, 0x4b4600, 0x4b46c0, 0x4b5240, 0x4b5300, 0x4b6800, 0x4b68c0, 0x4b6fa0, 0x4b7060, 0x4b7530, 0x4b75f0, 0x4bc450, 0x4bcb70, 0x4bcc30, 0x4bcfd0, 0x4bd090, 0x4be220, 0x4be830, 0x4be8f0, 0x4c0105, 0x4c17d0, 0x4c1890, 0x4c1c70, 0x4c1ef5, 0x4c1f40, 0x4c2465, 0x4c24b0, 0x4c2970, 0x4c2c70, 0x4c2f40, 0x4c3000, 0x4c5740, 0x4c5800, 0x4c6780, 0x4c6840, 0x4c74a0, 0x4c77e0, 0x4c78a0, 0x4c7d9f, 0x4c7de5, 0x4c7f30, 0x4c7ff0, 0x4c83ef, 0x4c8435, 0x4c84b0, 0x4c8570, 0x4c8d60, 0x4c95a0, 0x4c9660, 0x4cb370, 0x4cb430, 0x4cbcf0, 0x4cbdb0, 0x4cd316, 0x4cd344, 0x4cd950, 0x4cda10, 0x4ce1b0, 0x4ce270, 0x4cf320, 0x4cf3e0, 0x4d01f0, 0x4d02b0, 0x4d13e0, 0x4d2f10, 0x4d2fd0, 0x4d36a0, 0x4d3db0, 0x4d3e70, 0x4d44c0, 0x4d4660, 0x4d4720, 0x4d5ca0, 0x4d5e50, 0x4d5f10, 0x4d9bf0, 0x4e5180, 0x4e5240, 0x4e8270, 0x4e8330, 0x4ec825, 0x4ecfc0, 0x4ed9d0, 0x4ede50, 0x4edf60, 0x4ee020, 0x4eff70, 0x4f0790, 0x4f2fc0, 0x4f3080, 0x4f4211, 0x4f422e, 0x4f4830, 0x4f5690, 0x4f6d10, 0x4f7b90, 0x4f7c50, 0x4f8010, 0x4f8b40, 0x4fb5c0, 0x4fb960, 0x4fbbb0, 0x4fcee5, 0x4fcef5, 0x4fcf15, 0x50b490, 0x50b550, 0x50f690, 0x50f7c0, 0x50f9f0, 0x50fad0, 0x50fb40, 0x50fc00, 0x5158f0, 0x515b80, 0x517420, 0x5184d0, 0x518a70, 0x518b30, 0x51f200, 0x5243e3, 0x54b680, 0x54d730, 0x54dba5, 0x54dbf5, 0x54f5a5, 0x54f5d5, 0x54f605, 0x54f635, 0x54f645, 0x54f695, 0x54f6c5, 0x54f8c5, 0x54f905, 0x54ffd5, 0x5506a5, 0x5506e5, 0x550860, 0x55d260, 0x55d610, 0x566625, 0x566635, 0x566665, 0x567525, 0x575735, 0x58b1b5, 0x5944f5, 0x594505, 0x59c0f5, 0x59c125, 0x59c270, 0x59fdd5, 0x5a0165, 0x5a0e35, 0x5a0e45, 0x5a0e65, 0x5a0eb0, 0x5a1af5, 0x5a58d0, 0x5a6cf0, 0x5a70a0, 0x5a7210, 0x5a7850, 0x5a8fa0, 0x5aaac0, 0x5aade0, 0x5ad300, 0x5aec95, 0x5aecf5, 0x5aee10, 0x5b0000, 0x5b0665, 0x5b06a9, 0x5b0855, 0x5b0dd0, 0x5b2680, 0x5b2700, 0x5b3200, 0x5b6130, 0x5b6de0, 0x5b8045, 0x5b8055, 0x5b8075, 0x5b8240, 0x5b8260, 0x5b8280, 0x5bb880, 0x5bc680, 0x5bc6d5, 0x5bc710, 0x5bc730, 0x5c07c5, 0x5c07f5, 0x5c0825, 0x5c0855, 0x5c0885, 0x5c08c5, 0x5c08f5, 0x5c25e0, 0x5c3200, 0x5c3220, 0x5c8150, 0x5c81e0, 0x5c8270, 0x5ca9c5, 0x5d4b60, 0x5e6c60, 0x5e6c95, 0x5ec1e0, 0x5ec210, 0x5ed440, 0x5edd50, 0x5f2920, 0x5f3330, 0x5f3960, 0x5f3f80, 0x5f45f0, 0x5f4610, 0x5f4630, 0x5f4650, 0x5f5590, 0x5f5850, 0x5f5bb0, 0x5f5c40, 0x5f5c60, 0x5f6140, 0x5f63b0, 0x5f6530, 0x5f68d0, 0x5f6f20, 0x5f7240, 0x5f7860, 0x5f7b80, 0x5f81a0, 0x5f8ff0, 0x5face0, 0x5fad50, 0x5fada0, 0x5fc0e0, 0x5fc3a0, 0x5fcf60, 0x5fdbc0, 0x5ff735, 0x5ff775, 0x5ff7c0, 0x604100, 0x6048d5, 0x604905, 0x604ab5, 0x606670, 0x6084d0, 0x609736, 0x609de0, 0x60aa10, 0x60b035, 0x60b065, 0x60b270, 0x60c6c0, 0x617c85, 0x617cb5, 0x617f75, 0x617fa5, 0x618165, 0x6181e5, 0x618215, 0x618415, 0x618445, 0x618605, 0x618645, 0x618675, 0x618875, 0x6188b5, 0x6188e5, 0x618a95, 0x618ac5, 0x618c75, 0x618ca5, 0x618ea0, 0x6190a5, 0x6190e0, 0x619115, 0x619150, 0x619185, 0x6191c0, 0x6191f5, 0x619230, 0x619265, 0x6192a0, 0x6192d5, 0x619310, 0x619345, 0x619380, 0x6193b5, 0x6193f0, 0x619425, 0x619460, 0x619495, 0x6194d0, 0x619505, 0x619540, 0x619575, 0x6195b0, 0x6195e5, 0x619620, 0x619655, 0x619690, 0x61d065, 0x61d795, 0x61d7a5, 0x61d7c5, 0x627770, 0x6427fe, 0x6bae35, 0x6bae75, 0x6baeb5, 0x6baef5, 0x6c57c5, 0x6c5805, 0x6c5845, 0x6c5885, 0x6c58c5, 0x6c5905, 0x6c5945, 0x6c5985, 0x6c59c5, 0x6c5a05, 0x6c5a45, 0x6c5a85, 0x6c5ac5, 0x6cb295, 0x6cb2d5, 0x6cb315, 0x6cb325, 0x6cc325, 0x6cc365, 0x6cc375, 0x6d04e6, 0x6d0755, 0x6d0795, 0x6d1d45, 0x6d1d85, 0x6d1dc5, 0x6d1e05, 0x6d1e45, 0x6d1e85, 0x6d1ec5, 0x6d1f05, 0x6d785e, 0x6e8315, 0x6ee7e5, 0x6ee825, 0x6f0a50, 0x6f22c5, 0x6f2305, 0x6f9980, 0x6fa7f5, 0x6fa835, 0x6fa875, 0x6fa8b5, 0x6fa8f5, 0x6fa935, 0x6fa975, 0x6fa9b5, 0x6fa9f5, 0x6faa35, 0x6faa75, 0x6faab5, 0x6faaf5, 0x701505, 0x701545, 0x701585, 0x7015c5, 0x708225, 0x708265, 0x7082a5, 0x7082e5, 0x708325, 0x7106b5, 0x710b7b, 0x7141a5, 0x7141e5, 0x714225, 0x714265, 0x7142a5, 0x7142e5, 0x714325, 0x714365, 0x7143a5, 0x7143e5, 0x714425, 0x714465, 0x7144a5, 0x71bb25, 0x71bb65, 0x71bba5, 0x724aa0, 0x724ac5, 0x724ad5, 0x724af5, 0x725b05, 0x725b15, 0x725b35, 0x727755, 0x72a645, 0x72b97d, 0x7354e5, 0x735525, 0x742b95, 0x744315, 0x744355, 0x744395, 0x745775, 0x74d026, 0x74f3b5, 0x7500b0, 0x7516a8, 0x7516ca, 0x75aa25, 0x75aa65, 0x75aaa5, 0x75aae5, 0x75ab25, 0x75ab65, 0x75ab75, 0x773e70, 0x781085, 0x7810c5, 0x781105, 0x781145, 0x781185, 0x7811c5, 0x781205, 0x783959, 0x7839d9, 0x783bf9, 0x783e09, 0x784019, 0x784229, 0x784449, 0x784ad5, 0x784ae5, 0x784c15, 0x784cb5, 0x784cf9, 0x784f75, 0x784fa5, 0x785585, 0x7855c9, 0x78d0e7, 0x78d1a9, 0x792265, 0x792295, 0x792b75, 0x792bc0, 0x792c10, 0x792c60, 0x792cb0, 0x792d00, 0x792d50, 0x792da5, 0x792df5, 0x792e55, 0x792ea5, 0x792f05, 0x792f35, 0x7930e5, 0x793115, 0x7932c5, 0x7932f5, 0x799119, 0x79f3a9, 0x7a0a50, 0x7a5b79, 0x7a7fd9, 0x7a8f99, 0x7a9649, 0x7a96f6, 0x7a97b9, 0x7ac0a7, 0x7ad549, 0x7b1b15, 0x7b1b65, 0x7b1bb5, 0x7b1e80, 0x7b2185, 0x7b4559, 0x7b6a09, 0x7b8399, 0x7b8905, 0x7c462e, 0x7c7138, 0x7c74ad, 0x7d3a30, 0x7d3a55, 0x7d3a85, 0x7d3cc0, 0x7d3cf5, 0x7d3d35, 0x7d3d45, 0x7d400c, 0x7d8520, 0x7d8630, 0x7dac10, 0x7df6b5, 0x7e1c65, 0x7e6190, 0x7e61d5, 0x7e68f0, 0x7e70b5, 0x7e70c5, 0x7e7915, 0x7e7945, 0x7e7d40, 0x7e7f93, 0x7eb255, 0x7eb285, 0x7eb490, 0x7ebe15, 0x7ecf15, 0x7ecf60, 0x7ed5f5, 0x7ed605, 0x7ed800, 0x7ee310, 0x7eee10, 0x7f00d0, 0x7f1fc0, 0x7f3050, 0x7f35d0, 0x7f4730, 0x7f4b70, 0x7f65e5, 0x7f8320, 0x800062, 0x800088, 0x800c45, 0x800d35, 0x801c40, 0x802b66, 0x808338, 0x820500, 0x820520, 0x820540, 0x820560, 0x827df0, 0x827e10, 0x827e30, 0x827e50, 0x8290b0, 0x8290d0, 0x8290f0, 0x829110, 0x82c706, 0x82c825, 0x82c835, 0x82cec0, 0x82cee0, 0x82cf00, 0x82cf20, 0x82d7a0, 0x82d7c0, 0x82d7e0, 0x82d800, 0x82fa35, 0x82fa45, 0x832600, 0x832620, 0x832640, 0x832660, 0x833080, 0x8330a0, 0x8330c0, 0x8330e0, 0x833650, 0x833670, 0x833690, 0x8336b0, 0x834250, 0x834270, 0x834290, 0x8342b0, 0x835170, 0x835190, 0x8351b0, 0x8351d0, 0x83cfd2, 0x843629, 0x84d80b, 0x8572f5, 0x86680e, 0x866ea3, 0x86794b, 0x867f16, 0x8680f3, 0x8688c4, 0x86d023, 0x86d5b3]:
                rel -= 3
                return b'\xe9' + pack('<I', rel & 0xffffffff)
            else:
                return b'\xeb' + pack('<b', rel)
    elif opcode == 'JECXZ':
        to = int(tokens[1].value, base=16)
        rel = to - state['eip'] - 2
        return b'\xe3' + pack('<b', rel)
    elif opcode.startswith('K'):
        assert False, 'Not implemented'
    elif opcode == 'LAHF':
        return b'\x9f'
    elif opcode == 'LAR':
        return b'\x0f\x02\x68\x00'
    elif opcode == 'LDS':
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        assert tokens[3].value == 'FWORD'
        assert tokens[4].value == 'PTR'
        if tokens[5].value == '[':
            base = REGISTERS.index(tokens[6].value)
            modrm = 0b01000000 | dst << 3 | base
            assert tokens[7].value == '+'
            if tokens[8].value in REGISTERS:
                return b'\xc5\x54\x00\x90'
            else:
                disp = int(tokens[8].value, base=16)
                return b'\xc5' + pack('<B', modrm) + pack('<B', disp)
        elif tokens[5].value == 'ds':
            return b'\x3e\xc5\x69\x00'
        elif tokens[5].value == 'ss':
            return b'\x36\xc5\x69\x00'
        else:
            assert False
    elif opcode.startswith('LD'):
        assert False, 'Not implemented'
    elif opcode == 'LEA':
        # LEA r32,m (8D /r)
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        assert tokens[3].value == '['
        base = REGISTERS.index(tokens[4].value)
        if tokens[5].value == '-':
            disp = int(tokens[6].value, base=16)
            modrm = 0b00000000 | dst << 3 | base
            return b'\x8d' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(-disp)
        elif tokens[5].value == '+':
            if tokens[6].value in REGISTERS:
                idx = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '*'
                scale = get_scale(tokens[8].value)
                if tokens[9].value == '+':
                    ib = int(tokens[10].value, base=16)
                    if base == REGISTERS.index('esp'):
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if ib <= 0x7f:
                            modrm = 0b01000100 | dst << 3
                            return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<B', ib)
                        else:
                            modrm = 0b10000100 | dst << 3
                            return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<I', ib)
                    else:
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        if ib <= 0x7f:
                            modrm = 0b01000100 | dst << 3
                            return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<B', ib)
                        else:
                            modrm = 0b10000100 | dst << 3
                            return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<I', ib)
                elif tokens[9].value == '-':
                    disp = int(tokens[10].value, base=16)
                    assert tokens[11].value == ']'
                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                    modrm = 0b00000100 | dst << 3
                    return b'\x8d' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(-disp)
                else:
                    modrm = 0b00000100 | dst << 3
                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                    return b'\x8d' + pack('<B', modrm) + pack('<B', sib)
            elif tokens[5].value == '-':
                assert False, 'Unreachable'
            else:
                disp = int(tokens[6].value, base=16)
                sib = 0b00100000 | base
                if dst == REGISTERS.index('esp'):
                    modrm = 0b10000100 | dst << 3
                    return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                sib = get_sib(base)
                if disp != 0 and disp <= 0x7f:
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x8d' + pack('<B', modrm) + sib + pack('<b', disp)
                else:
                    modrm = 0b10000000 | dst << 3 | base
                    return b'\x8d' + pack('<B', modrm) + sib + pack('<I', disp)
        elif tokens[5].value == '*':
            scale = get_scale(tokens[6].value)
            modrm = 0b00000100 | dst << 3
            sib = 0b00000101 | scale << 6 | base << 3
            if tokens[7].value == '+':
                disp = int(tokens[8].value, base=16)
                return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
            elif tokens[7].value == '-':
                disp = -int(tokens[8].value, base=16)
                return b'\x8d' + pack('<B', modrm) + pack('<B', sib) + pack('<i', disp)
            else:
                assert False, 'Unreachable'
        else:
            assert False, 'Unreachable'

    elif opcode == 'LEAVE':
        return b'\xc9'
    elif opcode == 'LES':
        dst = REGISTERS.index(tokens[1].value)
        base = REGISTERS.index(tokens[6].value)
        if tokens[7].value == ']':
            modrm = 0b00000000 | dst << 3 | base
            return b'\xc4' + pack('<B', modrm)
        else:
            if tokens[7].value == '+':
                if tokens[8].value in REGISTERS:
                    return b'\xc4\x54\x00\x58'
                else:
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\xc4' + pack('<B', modrm) + pack('<B', disp)
            elif tokens[7].value == '-':
                disp = -int(tokens[8].value, base=16)
                modrm = 0b10000000 | dst << 3 | base
                return b'\xc4' + pack('<B', modrm) + pack('<i', disp)
    elif opcode == 'LFENCE':
        return b'\x0f\xae\xe8'
    elif opcode in ['LGDT', 'LIDT', 'LLDT', 'LMSW', 'LOADIWKEY']:
        assert False, 'Not implemented'
    elif opcode == 'LOCK':
        state['eip'] += 1
        inst = assemble(line[5:], state)
        state['eip'] -= 1
        return b'\xf0' + inst
    elif opcode == 'LODS':
        if tokens[1].value == 'al':
            return b'\xac'
        elif tokens[1].value == 'eax':
            return b'\xad'
        else:
            assert False
    elif opcode.startswith('LODS'):
        assert False, 'Not implemented'
    elif opcode == 'LOOP':
        to = int(tokens[1].value, base=16)
        rel = to - state['eip'] - 2
        return b'\xe2' + pack('<b', rel)
    elif opcode == 'LOOPE':
        to = int(tokens[1].value, base=16)
        rel = to - state['eip'] - 2
        return b'\xe1' + pack('<b', rel)
    elif opcode == 'LOOPNE':
        to = int(tokens[1].value, base=16)
        rel = to - state['eip'] - 2
        return b'\xe0' + pack('<b', rel)
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
        if state['eip'] == 0x7b1a28:
            return b'\x8c\xf1'
        if state['eip'] in [0x7c8e16, 0x7c8e15]:
            return b'\x8e\x7c\x00\x4c'
        if state['eip'] == 0x7c8e19:
            return b'\x8e\x7c\x00\x54'
        if state['eip'] == 0x7c8e1d:
            return b'\x8e\x7c\x00\x67'
        if state['eip'] == 0x7c8e21:
            return b'\x8e\x7c\x00\x8b'
        if state['eip'] == 0x7c8e7d:
            return b'\x8e\x7c\x00\x8b'
        if state['eip'] == 0x804028:
            return b'\x8e\x3f'

        if tokens[1].value == '?':
            return b'\x8e\xf0'
        elif tokens[3].value == '?':
            return b'\x8c\xfd'
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                assert tokens[4].value == ':'
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return b'\x88' + pack('<B', modrm) + pack('<I', m)
                else:
                    im = int(tokens[7].value, base=16)
                    modrm = 0b00000101
                    return b'\xc6' + pack('<B', modrm) + pack('<I', m) + pack('<B', im)
            else:
                prefix = b''
                if tokens[3].value == 'cs':
                    prefix = b'\x2e'
                    tokens = tokens[2:]
                assert tokens[3].value == '['
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value in ['+', '-']:
                    sign = {'+': 1, '-': -1}[tokens[5].value]
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            if tokens[13].value in REGISTERS8:
                                src = REGISTERS8.index(tokens[13].value)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100 | src << 3
                                return b'\x88' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                            else:
                                ib = int(tokens[13].value, base=16)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100
                                return b'\xc6' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', ib)
                        elif tokens[9].value == '-':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            if tokens[13].value in REGISTERS8:
                                src = REGISTERS8.index(tokens[13].value)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                if disp <= 0x80:
                                    modrm = 0b01000100 | src << 3
                                    return b'\x88' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp)
                                else:
                                    modrm = 0b10000100 | src << 3
                                    return b'\x88' + pack('<B', modrm) + pack('<B', sib) + pack('<i', -disp)
                            else:
                                im = int(tokens[13].value, base=16)
                                modrm = 0b01000100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\xc6' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp) + pack('<B', im)
                        elif tokens[9].value == ']':
                            assert tokens[10].value == ','
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if tokens[11].value in REGISTERS8:
                                src = REGISTERS8.index(tokens[11].value)
                                modrm = 0b00000100 | src << 3
                                return b'\x88' + pack('<B', modrm) + pack('<B', sib)
                            else:
                                modrm = 0b00000100
                                ib = int(tokens[11].value, base=16)
                                return b'\xc6' + pack('<B', modrm) + pack('<B', sib) + pack('<B', ib)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS8:
                            src = REGISTERS8.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return prefix + b'\x88' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(sign*disp)
                        else:
                            ib = int(tokens[9].value, base=16)
                            modrm = 0b00000000 | base
                            return b'\xc6' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(sign*disp) + pack('<B', ib)
                else:
                    assert tokens[5].value == ']'
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[7].value)
                        modrm = 0b000000000 | src << 3 | base
                        return b'\x88' + pack('<B', modrm)
                    else:
                        ib = int(tokens[7].value, base=16)
                        modrm = 0b000000000 | base
                        return b'\xc6' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                sib = get_sib(base)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS:
                        src = REGISTERS.index(tokens[7].value)
                        modrm = 0b000000000 | src << 3 | base
                        return b'\x89' + pack('<B', modrm) + sib
                    else:
                        im = int(tokens[7].value, base=16)
                        modrm = 0b000000000 | base
                        return b'\xc7' + pack('<B', modrm) + sib + pack('<I', im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        if disp <= 0x80:
                            modrm = 0b01000000 | src << 3 | base
                            return b'\x89' + pack('<B', modrm) + pack('<b', -disp)
                        else:
                            modrm = 0b10000000 | src << 3 | base
                            return b'\x89' + pack('<B', modrm) + pack('<i', -disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b00000000 | base
                        return b'\xc7' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<I', im)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == '-':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            if tokens[13].value in REGISTERS:
                                src = REGISTERS.index(tokens[13].value)
                                sib = 0b000000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100 | src << 3
                                return b'\x89' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(-disp)
                            else:
                                im = int(tokens[13].value, base=16)
                                modrm = 0b01000100
                                sib = 0b000000000 | scale << 6 | idx << 3 | base
                                return b'\xc7' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp) + pack('<I', im)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            if tokens[13].value in REGISTERS:
                                src = REGISTERS.index(tokens[13].value)
                                sib = 0b000000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100 | src << 3
                                return b'\x89' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                            else:
                                im = int(tokens[13].value, base=16)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100
                                return b'\xc7' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<I', im)
                        elif tokens[9].value == ']':
                            assert tokens[10].value == ','
                            if tokens[11].value in REGISTERS:
                                src = REGISTERS.index(tokens[11].value)
                                modrm = 0b00000100 | src << 3
                                sib = 0b000000000 | scale << 6 | idx << 3 | base
                                return b'\x89' + pack('<B', modrm) + pack('<B', sib)
                            else:
                                im = int(tokens[11].value, base=16)
                                modrm = 0b00000100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\xc7' + pack('<B', modrm) + pack('<B', sib) + pack('<I', im)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x89' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            modrm = 0b00000000 | base
                            return b'\xc7' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp) + pack('<I', im)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    if tokens[11].value in REGISTERS:
                        src = REGISTERS.index(tokens[11].value)
                        modrm = 0b00000100 | src << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x89' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        im = int(tokens[11].value, base=16)
                        modrm = 0b00000100
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\xc7' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp) + pack('<I', im)
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
            prefix = b'\x66'
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'fs':
                prefix = b'\x64'
                tokens = tokens[2:]
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS16:
                    src = REGISTERS16.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return prefix + b'\x89' + pack('<B', modrm) + pack('<I', m)
                else:
                    im = int(tokens[7].value, base=16)
                    return prefix + b'\xc7\x05' + pack('<I', m) + pack('<H', im)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS16:
                        src = REGISTERS16.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return prefix + b'\x89' + pack('<B', modrm)
                    elif tokens[7].value in SEGMENTS:
                        seg = SEGMENTS.index(tokens[7].value)
                        modrm = 0b00000000 | seg << 3 | base
                        return b'\x8c' + pack('<B', modrm)
                    else:
                        im = int(tokens[7].value, base=16)
                        modrm = 0b00000000 | base
                        return prefix + b'\xc7' + pack('<B', modrm) + pack('<H', im)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == ']':
                            assert tokens[10].value == ','
                            modrm = 0b00000100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if tokens[11].value in REGISTERS16:
                                src = REGISTERS16.index(tokens[11].value)
                                modrm = 0b00000100 | src << 3
                                return prefix + b'\x89' + pack('<B', modrm) + pack('<B', sib)
                            else:
                                im = int(tokens[11].value, base=16)
                                return prefix + b'\xc7' + pack('<B', modrm) + pack('<B', sib) + pack('<H', im)
                        elif tokens[9].value in ['+', '-']:
                            sign = {'+': 1, '-': -1}[tokens[9].value]
                            fmt = {'+': '<B', '-': '<b'}[tokens[9].value]
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            if tokens[13].value in REGISTERS16:
                                src = REGISTERS16.index(tokens[13].value)
                                modrm = 0b01000100 | src << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return prefix + b'\x89' + pack('<B', modrm) + pack('<B', sib) + pack(fmt, sign*disp)
                            else:
                                if tokens[13].value == '?':
                                    return b'\x8c\x7c\x00' + pack(fmt, sign*disp)
                                im = int(tokens[13].value, base=16)
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                modrm = 0b00000100
                                return prefix + b'\xc7' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(sign*disp) + pack('<H', im)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS16:
                            src = REGISTERS16.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return prefix + b'\x89' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                        if tokens[9].value == '?':
                            if prefix == b'\x66':
                                prefix = b''
                            modrm = 0b01111000 | base
                            return prefix + b'\x8c' + pack('<B', modrm) + pack('<B', disp)
                        if tokens[9].value in SEGMENTS:
                            seg = SEGMENTS.index(tokens[9].value)
                            modrm = 0b01000000 | seg << 3 | base
                            return b'\x8c' + pack('<B', modrm) + pack('<B', disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            modrm = 0b00000000 | base
                            return prefix + b'\xc7' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp) + pack('<H', im)
                elif tokens[5].value == '-':
                    sign = {'+': 1, '-': -1}[tokens[5].value]
                    fmt = {'+': '<B', '-': '<b'}[tokens[5].value]
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS16:
                        src = REGISTERS16.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return prefix + b'\x89' + pack_modrm(modrm, disp) + pack_disp(sign*disp)
                    elif tokens[9].value in SEGMENTS:
                        seg = SEGMENTS.index(tokens[9].value)
                        modrm = 0b10000000 | seg << 3 | base
                        return b'\x8c' + pack('<B', modrm) + pack('<i', -disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b01000101
                        return prefix + b'\xc7' + pack('<B', modrm) + pack('<b', -disp) + pack('<H', im)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    src = REGISTERS16.index(tokens[11].value)
                    modrm = 0b00000100 | src << 3
                    sib = 0b00000101 | scale << 6 | base << 3
                    return prefix + b'\x89' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                else:
                    assert False
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    assert tokens[6].value == ':'
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x8a' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x8a' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if tokens[11].value == ']':
                                modrm = 0b00000100 | dst << 3
                                return b'\x8a' + pack('<B', modrm) + pack('<B', sib)
                            elif tokens[11].value in ['+', '-']:
                                sign = {'+': 1, '-': -1}[tokens[11].value]
                                fmt = {'+': '<B', '-': '<b'}[tokens[11].value]
                                disp = int(tokens[12].value, base=16)
                                modrm = 0b00000100 | dst << 3
                                return b'\x8a' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(sign*disp)
                            else:
                                assert False, 'Not implemented'
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x8a' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x8a' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(-disp)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x8a' + pack('<B', modrm) + pack('<B', sib) + pack('<I',disp)
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
                src = REGISTERS8.index(tokens[3].value)
                if state['eip'] in [0x69e591, 0x69e761, 0x69e7bd]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x88' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x8a' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return pack('<B', 0xb0 + dst) + pack('<B', ib)
        elif tokens[1].value in REGISTERS16:
            r16 = tokens[1].value
            line = line.replace(r16, REGISTERS[REGISTERS16.index(r16)], 1)
            line = line.replace('WORD', 'DWORD')
            raw = b'\x66' + assemble(line, state)
            if tokens[3].token_type == 'literal':
                raw = raw[:-2]
            return raw
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    sib = get_sib(base)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x8b' + pack('<B', modrm) + sib
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        sib = get_sib(base)
                        if disp <= 0x80:
                            modrm = 0b01000000 | dst << 3 | base
                            return b'\x8b' + pack('<B', modrm) + sib + pack('<b', -disp)
                        else:
                            modrm = 0b10000000 | dst << 3 | base
                            return b'\x8b' + pack('<B', modrm) + sib + pack('<i', -disp)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            sib = 0b000000000 | scale << 6 | idx << 3 | base
                            if tokens[11].value == ']':
                                modrm = 0b00000100 | dst << 3
                                return b'\x8b' + pack('<B', modrm) + pack('<B', sib)
                            elif tokens[11].value == '+':
                                disp = int(tokens[12].value, base=16)
                                modrm = 0b00000100 | dst << 3
                                return b'\x8b' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                            elif tokens[11].value == '-':
                                disp = int(tokens[12].value, base=16)
                                if disp <= 0x80:
                                    modrm = 0b01000100 | dst << 3
                                    return b'\x8b' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp)
                                else:
                                    modrm = 0b10000100 | dst << 3
                                    return b'\x8b' + pack('<B', modrm) + pack('<B', sib) + pack('<i', -disp)
                            else:
                                assert False, 'Not implemented'
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x8b' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000101 | scale << 6 | base << 3
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
                if state['eip'] in [0x45caf0, 0x7edc04, 0x7edc08]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x89' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x8b' + pack('<B', modrm)
            elif tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
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
                if len(tokens) == 4:
                    modrm = 0b11000000 | SEGMENTS.index(tokens[3].value) << 3 | dst
                    return b'\x8c' + pack('<B', modrm)
                else:
                    assert tokens[4].value == ':'
                    off = int(tokens[5].value, base=16)
                    return seg + b'\xa1' + pack('<I', off)
            else:
                im = int(tokens[3].value, base=16)
                return pack('<B', 0xb8 + dst) + pack('<I', im)
        elif tokens[1].value in SEGMENTS:
            seg = SEGMENTS.index(tokens[1].value)
            if tokens[2].value == ',':
                if tokens[3].value == 'esp':
                    return b'\x8e\xe4'
                elif tokens[3].value == 'WORD':
                    assert tokens[4].value == 'PTR'
                    assert tokens[5].value == '['
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | seg << 3 | base
                        return b'\x8e' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            assert tokens[11].value == ']'
                            modrm = 0b00011100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x8e' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            modrm = 0b01000000 | seg << 3 | base
                            return b'\x8e' + pack('<B', modrm) + pack('<B', disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b10000000 | seg << 3 | base
                        return b'\x8e' + pack('<B', modrm) + pack('<i', -disp)
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
                elif tokens[5].value == 'ax':
                    return b'\x66' + b'\xa3' + pack('<I', off)
                elif tokens[5].value == 'eax':
                    return seg + b'\xa3' + pack('<I', off)
                else:
                    assert False, 'Unreachable'
    elif opcode == 'MOVAPD':
        if tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
            assert tokens[2].value == ','
            assert tokens[3].value == 'XMMWORD'
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                return b'\x66\x0f\x28\x94\x24' + pack('<I', disp)
            elif tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x66\x0f\x28' + pack('<B', modrm) + pack('<I', m)
        elif tokens[1].value == 'XMMWORD':
            base = REGISTERS.index(tokens[4].value)
            disp = int(tokens[6].value, base=16)
            src = REGISTERSXMM.index(tokens[9].value)
            modrm = 0b10000100 | src << 3
            return b'\x66\x0f\x29' + pack('<B', modrm) + get_sib(base) + pack('<I', disp)
    elif opcode == 'MOVAPS':
        if tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        elif tokens[1].value == 'XMMWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                src = REGISTERSXMM.index(tokens[7].value)
                modrm = 0b00000101 | src << 3
                return b'\x0f\x29' + pack('<B', modrm) + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    src = REGISTERSXMM.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x0f\x29' + pack('<B', modrm) + get_sib(base)
                elif tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERSXMM.index(tokens[9].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x0f\x29' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x28' + pack('<B', modrm)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x28' + pack('<B', modrm) + pack('<I', m)
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\x28' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x0f\x28' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
    elif opcode == 'MOVD':
        if tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERSMM.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x0f\x7e' + pack('<B', modrm) + get_sib(base)
            elif tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERSMM.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                return b'\x0f\x7e' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERSMM.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                return b'\x0f\x7e' + pack('<B', modrm) + get_sib(base) + pack('<b', -disp)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | src << 3 | dst
            return b'\x0f\x7e' + pack('<B', modrm)
        elif tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x0f\x6e' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x0f\x6e' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\x6e' + pack('<B', modrm) + get_sib(base)
                    elif tokens[7].value == '+':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\x6e' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
        else:
            assert False
    elif opcode == 'MOVDQA':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x66\x0f\x6f' + pack('<B', modrm)
        else:
            m = int(tokens[7].value, base=16)
            modrm = 0b00000101 | dst << 3
            return b'\x66\x0f\x6f' + pack('<B', modrm) + pack('<I', m)
    elif opcode == 'MOVHLPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        src = REGISTERSXMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x12' + pack('<B', modrm)
    elif opcode == 'MOVHPS':
        if tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        elif tokens[1].value == 'QWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERSXMM.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x0f\x17' + pack('<B', modrm)
            elif tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERSXMM.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                return b'\x0f\x17' + pack('<B', modrm) + pack('<B', disp)

        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x16' + pack('<B', modrm)
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            if tokens[7].value == ']':
                modrm = 0b00000000 | dst << 3 | base
                return b'\x0f\x16' + pack('<B', modrm)
            elif tokens[7].value == '+':
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000000 | dst << 3 | base
                return b'\x0f\x16' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
    elif opcode == 'MOVLHPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        src = REGISTERSXMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x16' + pack('<B', modrm)
    elif opcode == 'MOVLPS':
        if tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        elif tokens[1].value == 'QWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERSXMM.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x0f\x13' + pack('<B', modrm)
            elif tokens[5].value == '+':
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    src = REGISTERSXMM.index(tokens[11].value)
                    modrm = 0b00000100 | scale << 6 | src << 3
                    return b'\x0f\x13' + pack('<B', modrm) + b'\x07'
                    
                else:
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERSXMM.index(tokens[9].value)
                    modrm = 0b01000000 | src << 3 | base
                    return b'\x0f\x13' + pack('<B', modrm) + pack('<B', disp)

        if tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            if tokens[7].value == ']':
                modrm = 0b00000000 | dst << 3 | base
                return b'\x0f\x12' + pack('<B', modrm) + get_sib(base)
            elif tokens[7].value == '+':
                if tokens[8].value in REGISTERS:
                    idx = REGISTERS.index(tokens[8].value)
                    assert tokens[9].value == '*'
                    scale = get_scale(tokens[10].value)
                    modrm = 0b00000100 | scale << 6 | dst << 3
                    return b'\x0f\x12' + pack('<B', modrm) + b'\x16'
                else:
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x0f\x12' + pack('<B', modrm) + pack('<B', disp)
        else:
            assert False
    elif opcode == 'MOVMSKPS':
        dst = REGISTERS.index(tokens[1].value)
        src = REGISTERSXMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x50' + pack('<B', modrm)
    elif opcode == 'MOVQ':
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
            if tokens[3].value in REGISTERSMM:
                src = REGISTERSMM.index(tokens[3].value)
                modrm = 0b11000000 | src << 3 | dst
                return b'\x0f\x7f' + pack('<B', modrm)
            elif tokens[3].value == 'QWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x0f\x6f' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\x6f' + pack('<B', modrm) + get_sib(base)
                    elif tokens[7].value == '+':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\x6f' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\x6f' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(-disp)
            else:
                assert False
        elif tokens[1].value == 'QWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERSMM:
                    src = REGISTERSMM.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x0f\x7f' + pack('<B', modrm) + get_sib(base)
                else:
                    assert False
            elif tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERSMM.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                modrm = 0b00000000 | src << 3 | base
                return b'\x0f\x7f' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERSMM.index(tokens[9].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x0f\x7f' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(-disp)
            else:
                assert False
        else:
            assert False
    elif opcode == 'MOVZX':
        if tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            if tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x0f\xb7' + pack('<B', modrm)
            elif tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x0f\xb6' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\xb6' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value == ']':
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x0f\xb6' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[11].value == '+':
                            disp = int(tokens[12].value, base=16)
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            modrm = 0b00000100 | dst << 3
                            return b'\x0f\xb6' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                        elif tokens[11].value == '-':
                            disp = int(tokens[12].value, base=16)
                            modrm = 0b01000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x0f\xb6' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\xb6' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                elif tokens[7].value == '-':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value == ']':
                            assert False
                        elif tokens[11].value == '+':
                            assert False
                            disp = int(tokens[12].value, base=16)
                            return b'\x0f\xb6\x4c\x01' + pack('<B', disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x0f\xb6' + pack('<B', modrm) + get_sib(base) + pack('<b', -disp)
            elif tokens[3].value == 'WORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x0f\xb7' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\xb7' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            assert tokens[11].value == ']'
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x0f\xb7' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            disp = int(tokens[8].value, base=16)
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x0f\xb7' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x0f\xb7' + pack('<B', modrm) + get_sib(base) + pack('<b', -disp)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        return b'\x0f\xb7\x04\x45' + pack('<I', disp)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x66\x0f\xb6' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x66\x0f\xb6' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x66\x0f\xb6' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            assert tokens[11].value == ']'
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x66\x0f\xb6' + pack('<B', modrm) + pack('<B', sib)
                        else:
                            disp = int(tokens[8].value, base=16)
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x66\x0f\xb6' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x66\x0f\xb6' + pack('<B', modrm) + get_sib(base) + pack('<b', -disp)
    elif opcode == 'MOVS':
        if tokens[1].value == 'BYTE':
            return b'\xa4'
        elif tokens[1].value == 'WORD':
            return b'\x66\xa5'
        else:
            return b'\xa5'
    elif opcode == 'MOVSS':
        if tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERSXMM.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\xf3\x0f\x11' + pack('<B', modrm)
            elif tokens[5].value == '+':
                if tokens[6].value in REGISTERS:
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == '+'
                    disp = int(tokens[10].value, base=16)
                    assert tokens[11].value == ']'
                    assert tokens[12].value == ','
                    src = REGISTERSXMM.index(tokens[13].value)
                    return b'\xf3\x0f\x11\x5c\x07' + pack('<B', disp)
                else:
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERSXMM.index(tokens[9].value)
                    modrm = 0b01000000 | src << 3 | base
                    return b'\xf3\x0f\x11' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)

        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\xf3\x0f\x10' + pack('<B', modrm)
        elif tokens[3].value == 'DWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\xf3\x0f\x10' + pack('<B', modrm) + pack('<I', m)
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\xf3\x0f\x10' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value == ']':
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\xf3\x0f\x10\x04' + pack('<B', sib)
                        elif tokens[11].value == '+':
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            modrm = 0b01000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\xf3\x0f\x10' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        sib = get_sib(base)
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\xf3\x0f\x10' + pack('<B', modrm) + sib + pack('<B', disp)
        else:
            assert False
    elif opcode == 'MOVSX':
        dst = REGISTERS.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERS8:
            src = REGISTERS8.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xbe' + pack('<B', modrm)
        elif tokens[3].value in REGISTERS16:
            src = REGISTERS16.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xbf' + pack('<B', modrm)
        elif tokens[3].value == 'BYTE':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                return b'\x0f\xbe\x15' + pack('<I', m)
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\xbe' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value == ']':
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x0f\xbe' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[11].value == '+':
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            modrm = 0b00000100 | dst << 3
                            return b'\x0f\xbe' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                        elif tokens[11].value == '-':
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            modrm = 0b00000100 | dst << 3
                            return b'\x0f\xbe' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(-disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\xbe' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x0f\xbe' + pack('<B', modrm) + pack('<b', -disp)
        elif tokens[3].value == 'WORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            if tokens[7].value == ']':
                modrm = 0b00000000 | dst << 3 | base
                return b'\x0f\xbf' + pack('<B', modrm)
            elif tokens[7].value == '*':
                scale = get_scale(tokens[8].value)
                assert tokens[9].value == '+'
                disp = int(tokens[10].value, base=16)
                assert tokens[11].value == ']'
                modrm = 0b00000100 | dst << 3
                sib = 0b01000101 | base << 3
                return b'\x0f\xbf' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
            elif tokens[7].value == '+':
                if tokens[8].value in REGISTERS:
                    idx = REGISTERS.index(tokens[8].value)
                    assert tokens[9].value == '*'
                    scale = get_scale(tokens[10].value)
                    if tokens[11].value == ']':
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        return b'\x0f\xbf' + pack('<B', modrm) + pack('<B', sib)
                    elif tokens[11].value == '+':
                        disp = int(tokens[12].value, base=16)
                        assert tokens[13].value == ']'
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        modrm = 0b00000100 | dst << 3
                        return b'\x0f\xbf' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                else:
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    sib = get_sib(base)
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\xbf' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
            elif tokens[7].value == '-':
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000000 | dst << 3 | base
                return b'\x0f\xbf' + pack('<B', modrm) + pack('<b', -disp)
    elif opcode == 'MOVUPS':
        if tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        elif tokens[1].value == 'XMMWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERSXMM.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x0f\x11' + pack('<B', modrm)
            elif tokens[5].value == '+':
                idx = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '*'
                scale = get_scale(tokens[8].value)
                assert tokens[9].value == ']'
                assert tokens[10].value == ','
                src = REGISTERSXMM.index(tokens[11].value)
                modrm = 0b00000100 | src << 3
                return b'\x0f\x11' + pack('<B', modrm) + b'\x07'
        if tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            if tokens[7].value == ']':
                modrm = 0b00000000 | dst << 3 | base
                return b'\x0f\x10' + pack('<B', modrm)
            elif tokens[7].value == '+':
                modrm = 0b01000000 | dst << 3 | base
                disp = int(tokens[8].value, base=16)
                return b'\x0f\x10' + pack('<B', modrm) + pack('<B', disp)
        else:
            assert False
    elif opcode.startswith('MOV'):
        assert False, 'Not implemented'
    elif opcode == 'MPSADBW':
        assert False, 'Not implemented'
    elif opcode == 'MUL':
        if tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            modrm = 0b11100000 | dst
            return b'\xf7' + pack('<B', modrm)
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                modrm = 0b01100000 | base
                return b'\xf6' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            elif tokens[5].value == ']':
                modrm = 0b00100000 | base
                return b'\xf6' + pack('<B', modrm)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                modrm = 0b01100000 | base
                return b'\xf7' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            elif tokens[5].value == ']':
                modrm = 0b00100000 | base
                return b'\xf7' + pack('<B', modrm)
    elif opcode == 'MULPD':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x66\x0f\x59' + pack('<B', modrm)
        else:
            disp = int(tokens[8].value, base=16)
            return b'\x66\x0f\x59\x84\x24' + pack('<I', disp)
    elif opcode == 'MULPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x59' + pack('<B', modrm)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x59' + pack('<B', modrm) + pack('<I', m)
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000100 | dst << 3
                    return b'\x0f\x59' + pack('<B', modrm) + get_sib(base)
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b00000100 | dst << 3
                    return b'\x0f\x59' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
    elif opcode == 'MULSS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\xf3\x0f\x59' + pack('<B', modrm)
        elif tokens[3].value == 'DWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\xf3\x0f\x59' + pack('<B', modrm) + pack('<I', m)
        else:
            assert False
            disp = int(tokens[8].value, base=16)
            return b'\x66\x0f\x59\x84\x24' + pack('<I', disp)
    elif opcode.startswith('MUL'):
        assert False, 'Not implemented'
    elif opcode == 'MWAIT':
        return b'\x0f\x01\xc9'
    elif opcode == 'NEG':
        if tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11011000 | dst
            return b'\xf6' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            modrm = 0b11011000 | dst
            return b'\x66\xf7' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            modrm = 0b11011000 | dst
            return b'\xf7' + pack('<B', modrm)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                modrm = 0b01011000 | base
                return b'\xf7' + pack('<B', modrm) + pack('<B', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                modrm = 0b01011000 | base
                return b'\xf7' + pack('<B', modrm) + pack('<b', -disp)
        else:
            assert False
    elif opcode == 'NOP':
        if len(tokens) == 1:
            return b'\x90'
        else:
            return b'\x0f\x18\x66\x00'
    elif opcode == 'NOT':
        if tokens[1].value in REGISTERS:
            reg = REGISTERS.index(tokens[1].value)
            return b'\xf7' + pack('<B', 0b11010000 | reg)
        elif tokens[1].value in REGISTERS8:
            reg = REGISTERS8.index(tokens[1].value)
            return b'\xf6' + pack('<B', 0b11010000 | reg)
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == ']'
            modrm = 0b00010000 | base
            return b'\xf6' + pack('<B', modrm)
        else:
            assert False, 'Not implemented'
    elif opcode == 'OR':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                im = int(tokens[7].value, base=16)
                return b'\x80\x0d' + pack('<I', m) + pack('<B', im)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x08' + pack('<B', modrm)
                    else:
                        im = int(tokens[7].value, base=16)
                        modrm = 0b00001000 | base
                        return b'\x80' + pack('<B', modrm) + pack('<B', im)
                elif tokens[5].value == '+':
                    if tokens[6].value == 'eiz':
                        return b'\x08\x64\x66\x00'
                    elif tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == ']':
                            assert tokens[10].value == ','
                            if tokens[11].value in REGISTERS8:
                                src = REGISTERS8.index(tokens[11].value)
                                modrm = 0b00000100 | src << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x08' + pack('<B', modrm) + pack('<B', sib)
                            else:
                                im = int(tokens[11].value, base=16)
                                modrm = 0b00001100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x80' + pack('<B', modrm) + pack('<B', sib) + pack('<B', im)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            im = int(tokens[13].value, base=16)
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            modrm = 0b00001100
                            return b'\x80' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', im)
                        else:
                            assert False
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        sib = get_sib(base)
                        if tokens[9].value in REGISTERS8:
                            src = REGISTERS8.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x08' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            modrm = 0b00001000 | base
                            return b'\x80' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + pack('<B', im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[9].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x08' + pack_modrm(modrm, disp) + pack_disp(-disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b00001000 | base
                        return b'\x80' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<B', im)
        elif tokens[1].value in ['DWORD', 'WORD']:
            prefix = b''
            if tokens[1].value == 'WORD':
                prefix = b'\x66'
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS:
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000101
                    return prefix + b'\x09' + pack('<B', modrm) + pack('<I', m)
                else:
                    im = int(tokens[7].value, base=16)
                    if im <= 0x7f or im >= 0xffffff00:
                        return prefix + b'\x83\x0d' + pack('<I', m) + pack('<B', im & 0xff)
                    else:
                        fmt = {'WORD': '<H', 'DWORD': '<I'}[tokens[1].value]
                        return prefix + b'\x81\x0d' + pack('<I', m) + pack(fmt, im)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS:
                        src = REGISTERS.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x09' + pack('<B', modrm)
                    if tokens[7].value in REGISTERS16:
                        src = REGISTERS16.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return prefix + b'\x09' + pack('<B', modrm)
                    else:
                        im = int(tokens[7].value, base=16)
                        if im <= 0x7f or im >= 0xffffff00:
                            modrm = 0b00001000 | base
                            return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                        else:
                            modrm = 0b00001000 | base
                            fmt = '<I'
                            if tokens[1].value == 'WORD':
                                fmt = '<H'
                            return prefix + b'\x81' + pack('<B', modrm) + pack(fmt, im)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == ']':
                            assert tokens[10].value == ','
                            im = int(tokens[11].value, base=16)
                            modrm = 0b00001100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if tokens[1].value == 'WORD':
                                fmt = '<H'
                            else:
                                fmt = '<I'
                            if im <= 0x7f or im >= 0xffffff00:
                                return prefix + b'\x83' + pack('<B', modrm) + pack('<B', sib) + pack('<B', im & 0xff)
                            else:
                                return prefix + b'\x81' + pack('<B', modrm) + pack('<B', sib) + pack(fmt, im)
                        elif tokens[9].value in ['+', '-']:
                            fmt = {'+': '<B', '-': '<b'}[tokens[9].value]
                            sign = {'+': 1, '-': -1}[tokens[9].value]
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            if tokens[13].value in REGISTERS:
                                src = REGISTERS.index(tokens[13].value)
                                modrm = 0b01000100 | src << 3
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x09' + pack('<B', modrm) + pack('<B', sib) + pack(fmt, sign*disp)
                            else:
                                im = int(tokens[13].value, base=16)
                                modrm = 0b01001100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\x83' + pack('<B', modrm) + pack('<B', sib) + pack(fmt, sign*disp) + pack('<B', im & 0xff)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                        elif tokens[9].value in REGISTERS16:
                            src = REGISTERS16.index(tokens[9].value)
                        else:
                            im = int(tokens[9].value, base=16)
                            modrm = 0b00001000 | base
                            if im <= 0x7f or im >= 0xffffff00:
                                return prefix + b'\x83' + pack_modrm(modrm, disp) + pack_disp(disp) + pack('<B', im & 0xff)
                            else:
                                fmt = '<I'
                                if tokens[1].value == 'WORD':
                                    fmt = '<H'
                                return prefix + b'\x81' + pack_modrm(modrm, disp) + pack_disp(disp) + pack(fmt, im)

                        sib = get_sib(base)
                        modrm = 0b00000000 | src << 3 | base
                        return prefix + b'\x09' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b01000101 | src << 3
                        return b'\x09' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b00001000 | base
                        if tokens[1].value == 'WORD':
                            return prefix + b'\x81' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<H', im)
                        else:
                            return prefix + b'\x83' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<B', im & 0xff)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x0a' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0a' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value in ['+', '-']:
                            fmt = {'+': '<B', '-': '<b'}[tokens[11].value]
                            sign = {'+': 1, '-': -1}[tokens[11].value]
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            modrm = 0b01111100
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x0a' + pack('<B', modrm) + pack('<B', sib) + pack(fmt, sign*disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0a' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0a' + pack_modrm(modrm, disp) + pack_disp(-disp)
            else:
                im = int(tokens[3].value, base=16)
                if state['eip'] in [0x69d3d8]:
                    modrm = 0b11001000 | dst
                    return b'\x82' + pack('<B', modrm) + pack('<B', im & 0xff)

                if dst == REGISTERS8.index('al'):
                    return b'\x0c' + pack('<B', im & 0xff)
                else:
                    modrm = 0b11001000 | dst
                    return b'\x80' + pack('<B', modrm) + pack('<B', im & 0xff)
        elif tokens[1].value in REGISTERS16:
            prefix = b'\x66'
            dst = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return prefix + b'\x0b' + pack('<B', modrm)
            else:
                im = int(tokens[3].value, base=16)
                if dst == REGISTERS16.index('ax'):
                    return prefix + b'\x0d' + pack('<H', im)
                else:
                    modrm = 0b11001000 | dst
                    return prefix + b'\x81' + pack('<B', modrm) + pack('<H', im)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)

                if state['eip'] in [0x4ae280, 0x69d438]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x09' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x0b' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0b' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value == ']':
                            modrm = 0b00000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x0b' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[11].value in ['+', '-']:
                            sign = {'+': 1, '-': -1}[tokens[11].value]
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            modrm = 0b00000100 | dst << 3
                            return b'\x0b' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(sign*disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        sib = get_sib(base)
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0b' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0b' + pack_modrm(modrm, disp) + pack_disp(-disp)
                elif tokens[7].value == '*':
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == '+'
                    disp = int(tokens[10].value, base=16)
                    assert tokens[11].value == ']'
                    return b'\x0b\x0c\x0d' + pack('<I', disp)
            else:
                im = int(tokens[3].value, base=16)

                if dst == REGISTERS.index('eax') and im > 0x7f and im <= 0xffffff00:
                    return b'\x0d' + pack('<I', im)

                modrm = 0b11001000 | dst
                if im <= 0x7f or im > 0xffffff00:
                    return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                else:
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)
    elif opcode == 'ORPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x56' + pack('<B', modrm)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            assert tokens[7].value == '+'
            disp = int(tokens[8].value, base=16)
            assert tokens[9].value == ']'
            return b'\x0f\x56\x54\x24' + pack('<B', disp)
        else:
            assert False
    elif opcode.startswith('OR'):
        assert False, 'Not implemented'
    elif opcode == 'OUT':
        if tokens[1].value == 'dx':
            if tokens[3].value == 'eax':
                return b'\xef'
            else:
                return b'\xee'
        elif tokens[3].value == 'al':
            ib = int(tokens[1].value, base=16)
            return b'\xe6' + pack('<B', ib)
        elif tokens[3].value == 'eax':
            ib = int(tokens[1].value, base=16)
            return b'\xe7' + pack('<B', ib)
    elif opcode.startswith('OUTS'):
        if tokens[3].value == 'BYTE':
            return b'\x6e'
        elif tokens[3].value == 'DWORD':
            return b'\x6f'
        else:
            assert False
    elif opcode.startswith('PABS'):
        assert False, 'Not implemented'
    elif opcode == 'PACKSSWB':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x63' + pack('<B', modrm)
    elif opcode == 'PACKSSDW':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x6b' + pack('<B', modrm)
    elif opcode == 'PACKUSWB':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value == 'QWORD':
            return b'\x0f\x67\x00'
        else:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x67' + pack('<B', modrm)
    elif opcode.startswith('PACK'):
        assert False, 'Not implemented'
    elif opcode == 'PADDB':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\xfc' + pack('<B', modrm)
    elif opcode == 'PADDD':
        prefix = b''
        if tokens[1].value in REGISTERSXMM:
            prefix = b'\x66'
            dst = REGISTERSXMM.index(tokens[1].value)
            src = REGISTERSXMM.index(tokens[3].value)
        else:
            dst = REGISTERSMM.index(tokens[1].value)
            if tokens[3].value in REGISTERSMM:
                src = REGISTERSMM.index(tokens[3].value)
            elif tokens[3].value == 'QWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b00000101 | dst << 3
                    sign = {'+': 1, '-': -1}[tokens[7].value]
                    return b'\x0f\xfe' + pack_modrm(modrm, disp) + pack_disp(sign*disp)
                elif tokens[5].value == 'ds':
                    modrm = 0b00000101 | dst << 3
                    m = int(tokens[7].value, base=16)
                    return b'\x0f\xfe' + pack('<B', modrm) + pack('<I', m)
        modrm = 0b11000000 | dst << 3 | src
        return prefix + b'\x0f\xfe' + pack('<B', modrm)
    elif opcode == 'PADDSW':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xed' + pack('<B', modrm)
        if tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\xed' + pack('<B', modrm) + pack('<I', m)
            else:
                assert False
    elif opcode == 'PADDW':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xfd' + pack('<B', modrm)
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\xfd' + pack('<B', modrm) + pack('<I', m)
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == '+':
                    assert False
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b01000101 | dst << 3
                    return b'\x0f\xfd' + pack('<B', modrm) + pack('<b', -disp)
        else:
            assert False
    elif opcode.startswith('PADD'):
        assert False, 'Not implemented'
    elif opcode == 'PALIGNR':
        assert False, 'Not implemented'
    elif opcode == 'PAND':
        prefix = b''
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
        elif tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xdb' + pack('<B', modrm)
        elif tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x66\x0f\xdb' + pack('<B', modrm)
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '-'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000101 | dst << 3
                return b'\x0f\xdb' + pack('<B', modrm) + pack('<b', -disp)
            else:
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return prefix + b'\x0f\xdb' + pack('<B', modrm) + pack('<I', m)
        elif tokens[3].value == 'XMMWORD':
            prefix = b'\x66'
        modrm = 0b00000101 | dst << 3
        m = int(tokens[7].value, base=16)
        return prefix + b'\x0f\xdb' + pack('<B', modrm) + pack('<I', m)
    elif opcode == 'PANDN':
        prefix = b''
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
        elif tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xdf' + pack('<B', modrm)
        elif tokens[3].value == 'QWORD':
            pass
        elif tokens[3].value == 'XMMWORD':
            prefix = b'\x66'
        m = int(tokens[7].value, base=16)
        return prefix + b'\x0f\xdf\x1d' + pack('<I', m)
    elif opcode == 'PAUSE':
        return b'\xf3\x90'
    elif opcode in ['PAVGB', 'PAVGW', 'PBLENDVB', 'PBLENDW', 'PCLMULQDQ', '']:
        assert False, 'Not implemented'
    elif opcode == 'PCMPEQD':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x76' + pack('<B', modrm)
    elif opcode == 'PCMPEQW':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        if tokens[1].value.startswith('x'):
            prefix = b'\x66'
        else:
            prefix = b''
        return prefix + b'\x0f\x75' + pack('<B', modrm)
    elif opcode == 'PCMPGTD':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x66' + pack('<B', modrm)
    elif opcode.startswith('PCMP'):
        assert False, 'Not implemented'
    elif opcode == 'PCONFIG':
        return b'\x0f\x01\xc5'
    elif opcode == 'PDEP':
        assert False, 'Not implemented'
    elif opcode.startswith('PEXT'):
        assert False, 'Not implemented'
    elif opcode == 'PFACC':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xae'
    elif opcode == 'PFADD':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x0f' + pack('<B', modrm) + b'\x9e'
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x0f' + pack('<B', modrm) + pack('<I', m) + b'\x9e'
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000000 | dst << 3 | base
                return b'\x0f\x0f' + pack('<B', modrm) + get_sib(base) + pack('<B', disp) + b'\x9e'
    elif opcode == 'PF2ID':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\x1d'
    elif opcode == 'PFCMPEQ':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xb0'
    elif opcode == 'PFCMPGE':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x0f' + pack('<B', modrm) + b'\x90'
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                modrm = 0b00000110 | dst << 3
                return b'\x0f\x0f' + pack('<B', modrm) + b'\x90'
            elif tokens[5].value == 'ds':
                assert tokens[6].value == ':'
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x0f' + pack('<B', modrm) + pack('<I', m) + b'\x90'
    elif opcode == 'PFCMPGT':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x0f' + pack('<B', modrm) + b'\xa0'
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == 'ds'
            assert tokens[6].value == ':'
            m = int(tokens[7].value, base=16)
            modrm = 0b00000101 | dst << 3
            return b'\x0f\x0f' + pack('<B', modrm) + pack('<I', m) + b'\xa0'
    elif opcode == 'PFMAX':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xa4'
    elif opcode == 'PFMIN':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\x94'
    elif opcode == 'PFMUL':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x0f' + pack('<B', modrm) + pack('<I', m) + b'\xb4'
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\x0f' + pack('<B', modrm) + get_sib(base) + b'\xb4'
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    sib = get_sib(base)
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\x0f' + pack_modrm(modrm, disp) + sib + pack_disp(disp) + b'\xb4'
            else:
                assert False

        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xb4'
    elif opcode == 'PFNACC':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\x8a'
    elif opcode == 'PFPNACC':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\x8e'
    elif opcode == 'PFRCP':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\x96'
    elif opcode == 'PFRCPIT1':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xa6'
    elif opcode == 'PFRCPIT2':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xb6'
    elif opcode == 'PFRSQIT1':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xa7'
    elif opcode == 'PFRSQRT':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\x97'
    elif opcode == 'PFSUB':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x0f' + pack('<B', modrm) + b'\x9a'
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                modrm = 0b00000000 | dst << 3 | base
                return b'\x0f\x0f' + pack('<B', modrm) + b'\x9a'
            elif tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                return b'\x0f\x0f\x05' + pack('<I', m) + b'\x9a'
    elif opcode == 'PFSUBR':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x0f' + pack('<B', modrm) + b'\xaa'
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\x0f' + pack('<B', modrm) + pack('<I', m) + b'\xaa'
            elif tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == ']'
                return b'\x0f\x0f\x01\xaa'
            else:
                assert False
    elif opcode == 'PI2FD':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\x0d'
    elif opcode.startswith('PH'):
        assert False, 'Not implemented'
    elif opcode.startswith('PINS'):
        assert False, 'Not implemented'
    elif opcode == 'PMADDWD':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xf5' + pack('<B', modrm)
        else:
            m = int(tokens[7].value, base=16)
            modrm = 0b00000101 | dst << 3
            return b'\x0f\xf5' + pack('<B', modrm) + pack('<I', m)
    elif opcode == 'PMAXSW':
        dst = int(tokens[1].value[-1])
        if tokens[1].value.startswith('x'):
            prefix = b'\x66'
        else:
            prefix = b''
        modrm = 0b00000101 | dst << 3
        m = int(tokens[-1].value, base=16)
        return prefix + b'\x0f\xee' + pack('<B', modrm) + pack('<I', m)
    elif opcode == 'PMOVMSKB':
        dst = REGISTERS.index(tokens[1].value)
        src = int(tokens[3].value[-1])
        if tokens[3].value.startswith('x'):
            prefix = b'\x66'
        else:
            prefix = b''
        modrm = 0b11000000 | dst << 3 | src
        return prefix + b'\x0f\xd7' + pack('<B', modrm)
    elif opcode == 'PMULHW':
        dst = REGISTERSMM.index(tokens[1].value)
        m = int(tokens[7].value, base=16)
        modrm = 0b00000101 | dst << 3
        return b'\x0f\xe5' + pack('<B', modrm) + pack('<I', m)
    elif opcode == 'PMULLW':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xd5' + pack('<B', modrm)
        else:
            m = int(tokens[7].value, base=16)
            modrm = 0b00000101 | dst << 3
            return b'\x0f\xd5' + pack('<B', modrm) + pack('<I', m)
    elif opcode.startswith('PM'):
        assert False, 'Not implemented'
    elif opcode == 'POP':
        if tokens[1].value in REGISTERS:
            reg = REGISTERS.index(tokens[1].value)
            return pack('<B', 0x58 + reg)
        elif tokens[1].value in REGISTERS16:
            reg = REGISTERS16.index(tokens[1].value)
            return b'\x66' + pack('<B', 0x58 + reg)
        elif tokens[1].value in SEGMENTS:
            seg = SEGMENTS.index(tokens[1].value)
            modrm = 0b00000111 | seg << 3
            return pack('<B', modrm)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == 'fs'
            m = int(tokens[5].value, base=16)
            return b'\x64\x8f\x05' + pack('<I', m)
    elif opcode == 'POPA':
        return b'\x61'
    elif opcode == 'POPCNT':
        assert False, 'Not implemented'
    elif opcode == 'POPF':
        return b'\x9d'
    elif opcode == 'POR':
        prefix = b''
        if tokens[1].value in REGISTERSXMM:
            prefix = b'\x66'
            dst = REGISTERSXMM.index(tokens[1].value)
            src = REGISTERSXMM.index(tokens[3].value)
        elif tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
            if tokens[3].value in REGISTERSMM:
                src = REGISTERSMM.index(tokens[3].value)
            else:
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\xeb' + pack('<B', modrm) + pack('<I', m)
        modrm = 0b11000000 | dst << 3 | src
        return prefix + b'\x0f\xeb' + pack('<B', modrm)
    elif opcode == 'PREFETCHW':
        return b'\x0f\x0d\x0d\x0d\x0d\x0d\x0d'
    elif opcode.startswith('PREFETCH'):
        assert False, 'Not implemented'
    elif opcode == 'PSLLD':
        prefix = b''
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
        elif tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
            prefix = b'\x66'

        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return prefix + b'\x0f\x72' + pack('<B', 0xf0 + dst) + pack('<B', ib)
    elif opcode == 'PSLLQ':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return b'\x0f\x73' + pack('<B', 0xf0 + dst) + pack('<B', ib)
    elif opcode == 'PSLLW':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return b'\x0f\x71' + pack('<B', 0xf0 + dst) + pack('<B', ib)
    elif opcode == 'PSRAD':
        prefix = b''
        if tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
            prefix = b'\x66'
        elif tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
        else:
            assert False
        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return prefix + b'\x0f\x72' + pack('<B', 0xe0 + dst) + pack('<B', ib)
    elif opcode == 'PSRAW':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return b'\x0f\x71' + pack('<B', 0xe0 + dst) + pack('<B', ib)
    elif opcode == 'PSRLD':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return b'\x0f\x72' + pack('<B', 0xd0 + dst) + pack('<B', ib)
    elif opcode == 'PSRLQ':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return b'\x0f\x73' + pack('<B', 0xd0 + dst) + pack('<B', ib)
    elif opcode == 'PSRLW':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        ib = int(tokens[3].value, base=16)
        return b'\x0f\x71' + pack('<B', 0xd0 + dst) + pack('<B', ib)
    elif opcode == 'PSUBD':
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
        elif tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xfa' + pack('<B', modrm)
        elif tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x66\x0f\xfa' + pack('<B', modrm)
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            if tokens[7].value == '+':
                disp = int(tokens[8].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\xfa' + pack_modrm(modrm, disp) + pack_disp(disp)
            elif tokens[7].value == '-':
                disp = int(tokens[8].value, base=16)
                if disp <= 0x7f:
                    modrm = 0x55
                    return b'\x0f\xfa' + pack_modrm(modrm, disp) + pack_disp(-disp)
                else:
                    modrm = 0b00000101 | dst << 3
                    return b'\x0f\xfa' + pack_modrm(modrm, disp) + pack_disp(-disp)
        elif tokens[5].value == 'ds':
            modrm = 0b00000101 | dst << 3
            m = int(tokens[7].value, base=16)
            return b'\x0f\xfa' + pack('<B', modrm) + pack('<I', m)
        elif tokens[5].value == '[':
            base = REGISTERS.index(tokens[6].value)
            if tokens[7].value == '+':
                assert False
            elif tokens[7].value == '-':
                disp = -int(tokens[8].value, base=16)
                modrm = 0b01000101 | dst << 3
                return b'\x0f\xfa' + pack('<B', modrm) + pack('<b', disp)
            else:
                assert False
    elif opcode == 'PSUBSW':
        dst = REGISTERSMM.index(tokens[1].value)
        assert tokens[2].value == ','
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xe9' + pack('<B', modrm)
        elif tokens[5].value == 'ds':
            modrm = 0b00000101 | dst << 3
            m = int(tokens[7].value, base=16)
            return b'\x0f\xe9' + pack('<B', modrm) + pack('<I', m)
        else:
            modrm = 0b01000101 | dst << 3
            return b'\x0f\xe9' + pack('<B', modrm) + b'\xb4'
    elif opcode == 'PSUBW':
        dst = int(tokens[1].value[-1])
        assert tokens[2].value == ','
        src = int(tokens[3].value[-1])
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\xf9' + pack('<B', modrm)
    elif opcode == 'PSWAPD':
        dst = REGISTERSMM.index(tokens[1].value)
        src = REGISTERSMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x0f' + pack('<B', modrm) + b'\xbb'
    elif opcode.startswith('PS'):
        assert False, 'Not implemented'
    elif opcode.startswith('PT'):
        assert False, 'Not implemented'
    elif opcode == 'PUNPCKHBW':
        prefix = b''
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
        elif tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
            prefix = b'\x66'
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x68' + pack('<B', modrm)
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '-'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000101 | dst << 3
                return b'\x0f\x68' + pack('<B', modrm) + b'\xf0'
            elif tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x68' + pack('<B', modrm) + pack('<I', m)
            else:
                assert False
        else:
            assert False
    elif opcode == 'PUNPCKHDQ':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x6a' + pack('<B', modrm)
        elif tokens[3].value in ['DWORD', 'QWORD']:
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\x6a' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x0f\x6a' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x0f\x6a' + pack('<B', modrm) + pack('<b', -disp)
                else:
                    assert False
            elif tokens[5].value == 'ds':
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\x6a' + pack('<B', modrm) + pack('<I', m)
        else:
            assert False
    elif opcode == 'PUNPCKHWD':
        prefix = b''
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
            src = REGISTERSMM.index(tokens[3].value)
        elif tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
            src = REGISTERSXMM.index(tokens[3].value)
            prefix = b'\x66'
        modrm = 0b11000000 | dst << 3 | src
        return prefix + b'\x0f\x69' + pack('<B', modrm)
    elif opcode == 'PUNPCKLBW':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x60' + pack('<B', modrm)
        elif tokens[3].value == 'DWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    return b'\x0f\x60\x00'
                elif tokens[7].value == '+':
                    assert False
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b01000101 | dst << 3
                    return b'\x0f\x60' + pack('<B', modrm) + pack('<b', -disp)
                else:
                    assert False
            elif tokens[5].value == 'ds':
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\x60' + pack('<B', modrm) + pack('<I', m)
        else:
            assert False
    elif opcode == 'PUNPCKLDQ':
        dst = REGISTERSMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x62' + pack('<B', modrm)
        elif tokens[3].value == 'DWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x0f\x62' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x0f\x62' + pack('<B', modrm) + pack('<B', disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x0f\x62' + pack('<B', modrm) + pack('<b', -disp)
                else:
                    assert False
            elif tokens[5].value == 'ds':
                modrm = 0b00000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\x62' + pack('<B', modrm) + pack('<I', m)
        else:
            assert False
    elif opcode == 'PUNPCKLWD':
        prefix = b''
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
        elif tokens[1].value in REGISTERSXMM:
            dst = REGISTERSXMM.index(tokens[1].value)
            prefix = b'\x66'
        if tokens[3].value in REGISTERSMM:
            src = REGISTERSMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x61' + pack('<B', modrm)
        elif tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x66\x0f\x61' + pack('<B', modrm)
        elif tokens[3].value == 'QWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '-'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000101 | dst << 3
                return b'\x0f\x61' + pack('<B', modrm) + b'\xf0'
            elif tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                modrm = 0b00000101 | dst << 3
                return b'\x0f\x61' + pack('<B', modrm) + pack('<I', m)
            else:
                assert False
        else:
            assert False
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
            assert tokens[2].value == 'PTR'
            if tokens[3].value in SEGMENTS:
                prefix = {
                    'ds': b'',
                    'es': b'\x26',
                    'cs': b'\x2e',
                    'ss': b'\x36',
                    #'ds': b'\x3e',
                    'fs': b'\x64',
                    'gs': b'\x65',
                }[tokens[3].value]
                assert tokens[4].value == ':'
                m = int(tokens[5].value, base=16)
                modrm = 0b00110101
                return prefix + b'\xff' + pack('<B', modrm) + pack('<I', m)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if base == REGISTERS.index('esp'):
                    modrm = 0b01110100
                    sib = 0b00100100
                    if tokens[5].value == '+':
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                    elif tokens[5].value == '-':
                        disp = -int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<b', disp)
                    else:
                        assert False, 'Not implemented'
                else:
                    modrm = 0b01110000 | base
                    if tokens[5].value == '+':
                        if tokens[6].value in REGISTERS:
                            idx = REGISTERS.index(tokens[6].value)
                            assert tokens[7].value == '*'
                            scale = get_scale(tokens[8].value)
                            if tokens[9].value == ']':
                                modrm = 0b00110100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                return b'\xff' + pack('<B', modrm) + pack('<B', sib)
                            elif tokens[9].value == '-':
                                disp = -int(tokens[10].value, base=16)
                                modrm = 0b01110100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                if abs(disp) <= 0x7f:
                                    return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<b', disp)
                                else:
                                    modrm = 0b10110100
                                    return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<i', disp)
                            else:
                                disp = int(tokens[10].value, base=16)
                                modrm = 0b01110100
                                sib = 0b00000000 | scale << 6 | idx << 3 | base
                                if abs(disp) <= 0x7f:
                                    return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<b', disp)
                                else:
                                    modrm = 0b10110100
                                    return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<i', disp)
                        else:
                            modrm = 0b00110000 | base
                            disp = int(tokens[6].value, base=16)
                            assert tokens[7].value == ']'
                            return b'\xff' + pack_modrm(modrm, disp) + pack_disp(disp)
                    elif tokens[5].value == '-':
                        disp = -int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        if abs(disp) <= 0x80:
                            return b'\xff' + pack('<B', modrm) + pack('<b', disp)
                        else:
                            modrm = 0b10110101
                            return b'\xff' + pack('<B', modrm) + pack('<i', disp)
                    elif tokens[5].value == '*':
                        scale = get_scale(tokens[6].value)
                        assert tokens[7].value == '+'
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b00110100
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\xff' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    elif tokens[5].value == ']':
                        return b'\xff' + pack('<B', 0x30 | base)
                    else:
                        assert False, 'Not implemented'
        elif tokens[1].value in SEGMENTS:
            return {
                'es': b'\x06',
                'cs': b'\x0e',
                'ss': b'\x16',
                'ds': b'\x1e',
                'fs': b'\x0f\xa0',
                'gs': b'\x0f\xa8',
            }[tokens[1].value]
    elif opcode == 'PUSHA':
        return b'\x60'
    elif opcode == 'PUSHF':
        return b'\x9c'
    elif opcode == 'PXOR':
        prefix = b''
        if tokens[1].value in REGISTERSMM:
            dst = REGISTERSMM.index(tokens[1].value)
            if tokens[3].value in REGISTERSMM:
                src = REGISTERSMM.index(tokens[3].value)
            elif tokens[3].value == 'QWORD':
                tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x0f\xef' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x0f\xef' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        disp = int(tokens[8].value, base=16)
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x0f\xef' + pack('<B', modrm) + pack('<B', disp)
        elif tokens[1].value in REGISTERSXMM:
            prefix = b'\x66'
            dst = REGISTERSXMM.index(tokens[1].value)
            src = REGISTERSXMM.index(tokens[3].value)

        modrm = 0b11000000 | dst << 3 | src
        return prefix + b'\x0f\xef' + pack('<B', modrm)
    elif opcode == 'RCL':
        if tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11010000 | dst
                return b'\xd2' + pack('<B', modrm)
            else:
                return b'\xc0\xd0\x69'
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            prefix = b''
            i = 0
            if tokens[3].value in SEGMENTS:
                prefix = {
                    'ds': b'\x3e',
                    'fs': b'\x64',
                }[tokens[3].value]
                i += 2
            base = REGISTERS.index(tokens[i+4].value)
            if tokens[i+5].value == ']':
                if tokens[i+7].value == 'cl':
                    return b'\xd2\x13'
                else:
                    return b'\xc0\x10\x68'
            else:
                assert tokens[i+5].value == '+'
                disp = int(tokens[i+6].value, base=16)
                assert tokens[i+7].value == ']'
                assert tokens[i+8].value == ','
                modrm = 0x50 | base
                if tokens[i+9].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[i+9].value)
                    return prefix + pack('<B', 0xd1 + src) + pack('<B', modrm) + b'\x00'
                else:
                    return prefix + b'\xd0' + pack('<B', modrm) + b'\x00'
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == '+'
            disp = int(tokens[6].value, base=16)
            assert tokens[8].value == ','
            modrm = 0x50 | base
            if tokens[9].value in REGISTERS8:
                return b'\xd3' + pack('<B', modrm) + b'\x00'
            else:
                return b'\xd1' + pack('<B', modrm) + b'\x00'
    elif opcode == 'ROL':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                return b'\xd0\x07'
            else:
                return b'\xd2\x86\x7f\x00\xbd\x86'
        elif tokens[1].value == 'DWORD':
            return b'\xd3\x42\x00'
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11000000 | dst
            return b'\xd0' + pack('<B', modrm)
        elif tokens[1].value == 'esp':
            return b'\xd1\xc4'
    elif opcode == 'RCPPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x53' + pack('<B', modrm)
        elif tokens[3].value == 'XMMWORD':
            return b'\x0f\x53\x54\x24\x30'
    elif opcode == 'RCPSS':
        dst = REGISTERSXMM.index(tokens[1].value)
        src = REGISTERSXMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\xf3\x0f\x53' + pack('<B', modrm)
    elif opcode.startswith('RCP'):
        assert False, 'Not implemented'
    elif opcode == 'RCR':
        if tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            if tokens[3].value == 'cl':
                return b'\xd3\xdf'
            else:
                modrm = 0b11011000 | dst
                return b'\xd1' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11011000 | dst
            if tokens[3].value == '1':
                return b'\xd0' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return b'\xc0' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'BYTE':
            return b'\xd0\x18'
        else:
            assert False, 'Not implemented'
    elif opcode == 'ROR':
        if tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            if tokens[3].value == 'cl':
                return b'\xd3\xca'
            else:
                ib = int(tokens[3].value, base=16)
                if dst == REGISTERS.index('esp'):
                    return b'\xc1\xcc' + pack('<B', ib)
                else:
                    modrm = 0b11011000 | dst
                    return b'\xc1' + pack('<B', modrm)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11011000 | dst
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11000000 | src << 3 | dst
                return b'\xd2' + pack('<B', modrm)
            elif tokens[3].value == '1':
                return b'\xc0' + pack('<B', modrm)
            else:
                ib = int(tokens[3].value, base=16)
                return b'\xc0' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                if tokens[9].value == 'cl':
                    return b'\xd2\x49\x00'
                elif tokens[9].value == '1':
                    if disp <= 0x7f:
                        return b'\xd0\x49' + pack_disp(disp)
                    else:
                        return b'\xd0\x8d' + pack_disp(disp)
                else:
                    assert False
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                if tokens[9].value == 'cl':
                    return b'\xd2\x49\x00'
                elif tokens[9].value == '1':
                    if disp <= 0x7f:
                        return b'\xd0\x49' + pack_disp(-disp)
                    else:
                        return b'\xd0\x8b' + pack_disp(-disp)
                else:
                    assert False
            else:
                assert False
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                if tokens[9].value == 'cl':
                    return b'\xd3\x4a\x00'
                else:
                    ib = int(tokens[9].value, base=16)
                    if disp <= 0x7f:
                        return b'\xc1\x49' + pack_disp(disp) + pack('<B', ib)
                    else:
                        return b'\xc1\x8a' + pack_disp(disp) + pack('<B', ib)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                if tokens[9].value == '1':
                    modrm = 0b10001000 | base
                    return b'\xd1' + pack('<B', modrm) + pack('<i', -disp)
                else:
                    assert False
            else:
                assert False
        else:
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
    elif opcode in ['REP', 'REPZ']:
        if line == 'repz (bad)': # TODO: FIXME
            return b'\xf3\xd6'

        if 'WORD' in map(lambda x: x.value, tokens[1:]):
            prefix = b'\x66'
            rem = line.replace('WORD', 'DWORD')
            tokens = tokenize(rem)
            tokens = tokenize(rem)
        else:
            prefix = b''
        rem = ' '.join(map(lambda x: x.value, tokens[1:]))
        return prefix + b'\xf3' + assemble(rem, state)
    elif opcode.startswith('REP'):
        assert False, 'Not implemented'
    elif opcode == 'RET':
        if len(tokens) > 1:
            iw = int(tokens[1].value, base=16)
            return b'\xc2' + pack('<H', iw)
        else:
            return b'\xc3'
    elif opcode == 'RETF':
        if len(tokens) == 1:
            return b'\xcb'
        else:
            im = int(tokens[1].value, base=16)
            return b'\xca' + pack('<H', im)
    elif opcode.startswith('RO'):
        assert False, 'Not implemented'
    elif opcode == 'RSM':
        return b'\x0f\xaa'
    elif opcode == 'RSQRTSS':
        dst = REGISTERSXMM.index(tokens[1].value)
        src = REGISTERSXMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\xf3\x0f\x52' + pack('<B', modrm)
    elif opcode.startswith('RS'):
        assert False, 'Not implemented'
    elif opcode == 'SAHF':
        return b'\x9e'
    elif opcode == 'SAL':
        assert False, 'Not implemented'
    elif opcode == 'SHLD':
        dst = REGISTERS.index(tokens[1].value)
        src = REGISTERS.index(tokens[3].value)
        if tokens[5].value in REGISTERS8:
            modrm = 0b11000000 | src << 3 | dst
            return b'\x0f\xa5' + pack('<B', modrm)
        else:
            ib = int(tokens[5].value, base=16)
            modrm = 0b11000000 | src << 3 | dst
            return b'\x0f\xa4' + pack('<B', modrm) + pack('<B', ib)
    elif opcode == 'SHRD':
        dst = REGISTERS.index(tokens[1].value)
        src = REGISTERS.index(tokens[3].value)
        if tokens[5].value in REGISTERS8:
            modrm = 0b11000000 | src << 3 | dst
            return b'\x0f\xad' + pack('<B', modrm)
        else:
            ib = int(tokens[5].value, base=16)
            modrm = 0b11000000 | src << 3 | dst
            return b'\x0f\xac' + pack('<B', modrm) + pack('<B', ib)
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
                if tokens[1].value in ['ebp', 'esi']:
                    modrm = 0b11110000 | dst
                    return b'\xd3' + pack('<B', modrm)
                modrm = 0b11100000 | dst
                return b'\xd3' + pack('<B', modrm)
            else:
                # SHL r/m32, imm8 (C1 /4 ib)
                imm = int(tokens[3].value, base=16)
                modrm = 0b11100000 + REGISTERS.index(tokens[1].value)
                return b'\xc1' + pack('<B', modrm) + pack('<B', imm)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            modrm = 0b11100000 | dst
            if tokens[3].value == 'cl':
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11100000 | dst
                return b'\xd2' + pack('<B', modrm)
            ib = int(tokens[3].value, base=16)
            return b'\xc0' + pack('<B', modrm) + pack('<B', ib)
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
        if tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)

                if state['eip'] in [0x69d354, 0x69d5d4, 0x69e739, 0x7fccbc]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x18' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x1a' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x1a' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value == 'eiz':
                        return b'\x1a\x64\x66\x00'
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x1a' + pack('<B', modrm) + pack('<B', disp)
            else:
                ib = int(tokens[3].value, base=16)
                return b'\x1c' + pack('<B', ib)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)

                if state['eip'] in [0x5dfce0, 0x65c788]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x19' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x1b' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == '*':
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == '+'
                    disp = int(tokens[10].value, base=16)
                    assert tokens[11].value == ']'
                    return b'\x1b\x1c\x1d' + pack('<I', disp)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        if tokens[11].value == ']':
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x1b\x1c' + pack('<B', sib)
                        elif tokens[11].value == '+':
                            disp = int(tokens[12].value, base=16)
                            assert tokens[13].value == ']'
                            modrm = 0b01000100 | dst << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x1b' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x1b' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            else:
                im = int(tokens[3].value, base=16)

                if state['eip'] in [0x69e50d, 0x69e60d]:
                    modrm = 0b11011000 | dst
                    return b'\x81' + pack('<B', modrm) + pack('<I', im)

                if im <= 0x7f or im > 0xffffff7f:
                    modrm = 0b11011000 | dst
                    return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                else:
                    return b'\x1d' + pack('<I', im)
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERS8.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x18' + pack('<B', modrm)
            elif tokens[5].value == '+':
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    if tokens[9].value == ']':
                        assert tokens[10].value == ','
                        src = REGISTERS8.index(tokens[11].value)
                        return b'\x18\x34\x4e'
                    elif tokens[9].value == '-':
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        assert tokens[12].value == ','
                        src = REGISTERS8.index(tokens[13].value)
                        return b'\x18\x64\x00' + pack('<b', -disp)
                else:
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERS8.index(tokens[9].value)
                    modrm = 0b01000000 | src << 3 | base
                    return b'\x18' + pack('<B', modrm) + pack('<B', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS8.index(tokens[9].value)
                if disp <= 0x7f:
                    return b'\x18\x57' + pack_disp(-disp)
                else:
                    return b'\x18\x8e' + pack_disp(-disp)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERS.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x19' + pack('<B', modrm)
            elif tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                return b'\x19' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS.index(tokens[9].value)
                return b'\x19\x8a' + pack('<i', -disp)
    elif opcode == 'SCAS':
        if tokens[1].value == 'eax':
            return b'\xaf'
        else:
            return b'\xae'
    elif opcode.startswith('SCAS'): assert False, 'Not implemented'
    elif opcode == 'SERIALIZE':     return b'\x0f\x01\xe8'
    elif opcode == 'SETA':          return b'\x0f\x97\xc1'
    elif opcode == 'SETB':
        reg = REGISTERS8.index(tokens[1].value)
        return b'\x0f\x92' + pack('<B', 0xc0 + reg)
    elif opcode == 'SETBE':     return b'\x0f\x96\xc0'
    elif opcode == 'SETE':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == '+'
            disp = int(tokens[6].value, base=16)
            assert tokens[7].value == ']'
            modrm = 0b00000100
            return b'\x0f\x94' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
        else:
            reg = REGISTERS8.index(tokens[1].value)
            return b'\x0f\x94' + pack('<B', 0xc0 + reg)
    elif opcode == 'SETG':
        reg = REGISTERS8.index(tokens[1].value)
        return b'\x0f\x9f' + pack('<B', 0xc0 + reg)
    elif opcode == 'SETGE':
        reg = REGISTERS8.index(tokens[1].value)
        return b'\x0f\x9d' + pack('<B', 0xc0 + reg)
    elif opcode == 'SETL':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == '+'
            disp = int(tokens[6].value, base=16)
            assert tokens[7].value == ']'
            return b'\x0f\x9c\x44\x24' + pack('<B', disp)
        else:
            reg = REGISTERS8.index(tokens[1].value)
            return b'\x0f\x9c' + pack('<B', 0xc0 + reg)
    elif opcode == 'SETLE':
        reg = REGISTERS8.index(tokens[1].value)
        return b'\x0f\x9e' + pack('<B', 0xc0 + reg)
    elif opcode == 'SETNE':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            assert tokens[5].value == '+'
            disp = int(tokens[6].value, base=16)
            assert tokens[7].value == ']'
            return b'\x0f\x95\x69' + pack('<B', disp)
        else:
            reg = REGISTERS8.index(tokens[1].value)
            return b'\x0f\x95' + pack('<B', 0xc0 + reg)
    elif opcode == 'SETO':          return b'\x0f\x90\x90\x90\x90\x90\x90'
    elif opcode.startswith('SET'):  assert False, 'Not implemented'
    elif opcode == 'SFENCE':        return b'\x0f\xae\xf8'
    elif opcode == 'SGDTD':
        assert tokens[1].value == '['
        assert tokens[3].value == ']'
        return b'\x0f\x01' + pack('<B', REGISTERS.index(tokens[2].value))
    elif opcode == 'SHUFPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            ib = int(tokens[5].value, base=16)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\xc6' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            assert tokens[7].value == '+'
            disp = int(tokens[8].value, base=16)
            assert tokens[9].value == ']'
            assert tokens[10].value == ','
            ib = int(tokens[11].value, base=16)
            modrm = 0b01000100 | dst << 3
            return b'\x0f\xc6' + pack('<B', modrm) + get_sib(base) + pack('<B', disp) + pack('<B', ib)
    elif opcode.startswith('SH'):
        assert False, 'Not implemented'
    elif opcode in ['SIDT', 'SLDT', 'SMSW']:
        assert False, 'Not implemented'
    elif opcode == 'SQRTPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        src = REGISTERSXMM.index(tokens[3].value)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x51' + pack('<B', modrm)
    elif opcode.startswith('SQRT'): assert False, 'Not implemented'
    elif opcode == 'SS':            return b'\x36' + assemble(line[3:], state)
    elif opcode == 'STAC':          return b'\x0f\x01\xcb'
    elif opcode == 'STC':           return b'\xf9'
    elif opcode == 'STD':           return b'\xfd'
    elif opcode == 'STI':           return b'\xfb'
    elif opcode == 'STOS':
        if tokens[1].value == 'BYTE':
            return b'\xaa'
        elif tokens[1].value == 'DWORD':
            return b'\xab'
        elif tokens[1].value == 'WORD':
            return b'\x66\xab'
    elif opcode.startswith('ST'):   assert False, 'Not implented'
    elif opcode == 'SUB':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERS8.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x28' + pack('<B', modrm)
            elif tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS8.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                return b'\x28' + pack('<B', modrm) + pack('<B', disp)
            elif tokens[5].value == '-':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS8.index(tokens[9].value)
                modrm = 0b10000101 | src << 3
                return b'\x28' + pack('<B', modrm) + pack('<i', -disp)
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS:
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return b'\x29' + pack('<B', modrm) + pack('<I', m)
                else:
                    im = int(tokens[7].value, base=16)
                    return b'\x83\x2d' + pack('<I', m) + pack('<B', im)
            elif tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x29' + pack('<B', modrm)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        assert tokens[12].value == ','
                        im = int(tokens[13].value, base=16)
                        return b'\x81\xac\x00' + pack('<I', disp) + pack('<I', im)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x29' + pack_modrm(modrm, disp) + pack_disp(disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            sib = get_sib(base)
                            modrm = 0b01101000 | base
                            if im <= 0x7f:
                                return b'\x83' + pack('<B', modrm) + sib + pack('<B', disp) + pack('<B', im)
                            else:
                                return b'\x81' + pack('<B', modrm) + sib + pack('<B', disp) + pack('<I', im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b01000000 | src << 3 | base
                        return b'\x29' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        modrm = 0b01000101 | base << 3
                        return b'\x83' + pack('<B', modrm) + pack('<b', -disp) + pack('<B', im)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x2a' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x2a' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        assert tokens[11].value == ']'
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        return b'\x2a' + pack('<B', modrm) + pack('<B', sib)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x2a' + pack('<B', modrm) + pack('<B', disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b10000000 | dst << 3 | base
                    return b'\x2a' + pack('<B', modrm) + pack('<i', -disp)
            else:
                im = int(tokens[3].value, base=16)
                if dst == REGISTERS8.index('al'):
                    return b'\x2c' + pack('<B', im)
                else:
                    modrm = 0b11101000 | dst
                    return b'\x80' + pack('<B', modrm) + pack('<B', im)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x66\x2b' + pack('<B', modrm)
            elif tokens[3].value == 'WORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x66\x2b' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x66\x2b' + pack_modrm(modrm, disp) + pack_disp(disp)
            else:
                im = int(tokens[3].value, base=16)
                if dst == REGISTERS16.index('ax'):
                    return b'\x66\x2d' + pack('<H', im)

                modrm = 0b11101000 | dst
                return b'\x66\x83' + pack('<B', modrm) + pack('<B', im)
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)

                if state['eip'] in [0x69d684, 0x7dce90]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x29' + pack('<B', modrm)

                modrm = 0b11000000 | dst << 3 | src
                return b'\x2b' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                if tokens[5].value == 'ds':
                    m = int(tokens[7].value, base=16)
                    modrm = 0b00000101 | dst << 3
                    return b'\x2b' + pack('<B', modrm) + pack('<I', m)
                elif tokens[5].value == '[':
                    base = REGISTERS.index(tokens[6].value)
                    if tokens[7].value == ']':
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x2b' + pack('<B', modrm)
                    elif tokens[7].value == '+':
                        if tokens[8].value in REGISTERS:
                            idx = REGISTERS.index(tokens[8].value)
                            assert tokens[9].value == '*'
                            scale = get_scale(tokens[10].value)
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            if tokens[11].value == ']':
                                modrm = 0b00000100 | dst << 3
                                return b'\x2b' + pack('<B', modrm) + pack('<B', sib)
                            elif tokens[11].value == '+':
                                disp = int(tokens[12].value, base=16)
                                assert tokens[13].value == ']'
                                modrm = 0b01000100 | dst << 3
                                return b'\x2b' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                            elif tokens[11].value == '-':
                                disp = int(tokens[12].value, base=16)
                                assert tokens[13].value == ']'
                                modrm = 0b01000100 | dst << 3
                                return b'\x2b' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp)
                        else:
                            disp = int(tokens[8].value, base=16)
                            assert tokens[9].value == ']'
                            sib = get_sib(base)
                            modrm = 0b00000000 | dst << 3 | base
                            return b'\x2b' + pack_modrm(modrm, disp) + sib + pack_disp(disp)
                    elif tokens[7].value == '-':
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        if disp <= 0x80:
                            modrm = 0b01000000 | dst << 3 | base
                            return b'\x2b' + pack('<B', modrm) + pack('<b', -disp)
                        else:
                            modrm = 0b10000000 | dst << 3 | base
                            return b'\x2b' + pack('<B', modrm) + pack('<i', -disp)
                    elif tokens[7].value == '*':
                        scale = get_scale(tokens[8].value)
                        assert tokens[9].value == '+'
                        disp = int(tokens[10].value, base=16)
                        assert tokens[11].value == ']'
                        modrm = 0b00000100 | dst << 3
                        sib = 0b00000101 | scale << 6 | base << 3
                        return b'\x2b' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
                    else:
                        return b'\x2b\x78\x00'
            else:
                imm = int(tokens[3].value, base=16)
                if imm <= 0x7f:
                    return b'\x83' + pack('<B', 0b11101000 | dst) + pack('<B', imm)
                else:
                    if dst == REGISTERS.index('eax'):
                        return b'\x2d' + pack('<I', imm)
                    else:
                        return b'\x81' + pack('<B', 0b11101000 | dst) + pack('<I', imm)
    elif opcode == 'SUBPD':
        if tokens[3].value in REGISTERSXMM:
            return b'\x66\x0f\x5c' + pack('<B', 0xd0 + REGISTERSXMM.index(tokens[3].value))
        return b'\x66\x0f\x5c\x94\x24\x30\x01\x00\x00'
    elif opcode == 'SUBPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x5c' + pack('<B', modrm)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == '[':
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b01000100 | dst << 3
                return b'\x0f\x5c' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
            elif tokens[5].value == 'ds':
                m = int(tokens[7].value, base=16)
                return b'\x0f\x5c\x05' + pack('<I', m)
        else:
            assert False
    elif opcode == 'SUBSS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\xf3\x0f\x5c' + pack('<B', modrm)
        elif tokens[3].value == 'DWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            assert tokens[7].value == '+'
            disp = int(tokens[8].value, base=16)
            assert tokens[9].value == ']'
            return b'\xf3\x0f\x5c\x44\x24' + pack('<B', disp)
        else:
            assert False
    elif opcode.startswith('SUB'):  assert False, 'Not implemented'
    elif opcode == 'SWAPGS':        return b'\x0f\x01\xf8'
    elif opcode == 'SYSCALL':       return b'\x0f\x05'
    elif opcode == 'SYSENTER':      return b'\x0f\x34'
    elif opcode == 'SYSEXIT':       return b'\x0f\x35'
    elif opcode == 'SYSRET':        return b'\x0f\x07'
    elif opcode == 'TEST':
        if tokens[1].value == 'BYTE':
            # TEST r/m8, imm8 (F6 /0 ib)
            assert tokens[2].value == 'PTR'
            if tokens[3].value == 'ds':
                m = int(tokens[5].value, base=16)
                assert tokens[6].value == ','
                if tokens[7].value in REGISTERS8:
                    src = REGISTERS8.index(tokens[7].value)
                    modrm = 0b00000101 | src << 3
                    return b'\x84' + pack('<B', modrm) + pack('<I', m)
                else:
                    ib = int(tokens[7].value, base=16)
                    return b'\xf6\x05' + pack('<I', m) + pack('<B', ib)
            elif tokens[3].value in SEGMENTS:
                assert tokens[4].value == ':'
                # ...
                return b'\x65\x84\x00'
            elif tokens[3].value == '[':
                if tokens[4].value == 'esp':
                    base = REGISTERS.index(tokens[4].value)
                    assert tokens[5].value == '+'
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS8:
                        src = REGISTERS8.index(tokens[9].value)
                        modrm = 0b00000100 | src << 3
                        return b'\x84' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
                    else:
                        ib = int(tokens[9].value, base=16)
                        sib = 0b00100100
                        modrm = 0b00000100
                        return b'\xf6' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', ib)
                else:
                    base = REGISTERS.index(tokens[4].value)
                    if tokens[5].value == '+':
                        if tokens[6].value in REGISTERS:
                            idx = REGISTERS.index(tokens[6].value)
                            assert tokens[7].value == '*'
                            scale = get_scale(tokens[8].value)
                            if tokens[9].value == ']':
                                assert tokens[10].value == ','
                                ib = int(tokens[11].value, base=16)
                                return b'\xf6\x04\xb3' + pack('<B', ib)
                            else:
                                assert tokens[9].value == '+'
                                disp = int(tokens[10].value, base=16)
                                assert tokens[11].value == ']'
                                assert tokens[12].value == ','
                                if tokens[13].value in REGISTERS8:
                                    src = REGISTERS8.index(tokens[13].value)
                                    return b'\x84\x94\x01' + pack('<I', disp)
                                else:
                                    sib = 0b00000000 | scale << 6 | idx << 3 | base
                                    ib = int(tokens[13].value, base=16)
                                    modrm = 0b00000100
                                    return b'\xf6' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp) + pack('<B', ib)
                        else:
                            disp = int(tokens[6].value, base=16)
                            assert tokens[7].value == ']'
                            assert tokens[8].value == ','
                            if tokens[9].value in REGISTERS8:
                                src = REGISTERS8.index(tokens[9].value)
                                modrm = 0b00000000 | src << 3 | base
                                return b'\x84' + pack_modrm(modrm, disp) + pack_disp(disp)
                            else:
                                ib = int(tokens[9].value, base=16)

                                if state['eip'] in [
                                    0x4a13c9, 0x4a13cd, 0x4a13d1, 0x4a13d5, 0x4a13d9, 0x4a13e9, 0x7c07d4, 0x7c07d4,
                                ]:
                                    modrm = 0b01001000 | base
                                    return b'\xf6' + pack('<B', modrm) + pack('<b', disp) + pack('<B', ib)

                                modrm = 0b00000000 | base
                                return b'\xf6' + pack_modrm(modrm, disp) + pack_disp(disp) + pack('<B', ib)
                    elif tokens[5].value == '-':
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS8:
                            src = REGISTERS8.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x84' + pack_modrm(modrm, disp) + pack_disp(-disp)
                        else:
                            ib = int(tokens[9].value, base=16)
                            modrm = 0b00000000 | base
                            return b'\xf6' + pack_modrm(modrm, disp) + pack_disp(-disp) + pack('<B', ib)
                    elif tokens[5].value == ']':
                        assert tokens[6].value == ','
                        if tokens[7].value in REGISTERS8:
                            src = REGISTERS8.index(tokens[7].value)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x84' + pack('<B', modrm)
                        else:
                            ib = int(tokens[7].value, base=16)
                            modrm = 0b00000000 | base
                            return b'\xf6' + pack('<B', modrm) + pack('<B', ib)
                    else:
                        assert False
        elif tokens[1].value in REGISTERS8:
            rm8 = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if rm8 == REGISTERS8.index('al') and tokens[3].value not in REGISTERS8:
                ib = int(tokens[3].value, base=16)
                return b'\xa8' + pack('<B', ib)
            else:
                if tokens[3].value in REGISTERS8:
                    # TEST r/m8, r8 (84 /r)
                    r8 = REGISTERS8.index(tokens[3].value)
                    modrm = 0b11000000 | r8 << 3 | rm8
                    return b'\x84' + pack('<B', modrm)
                else:
                    modrm = 0b11000000 | rm8
                    ib = int(tokens[3].value, base=16)
                    return b'\xf6' + pack('<B', modrm) + pack('<B', ib)
        elif tokens[1].value in REGISTERS:
            rm32 = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if rm32 == REGISTERS.index('eax') and tokens[3].value not in REGISTERS:
                im = int(tokens[3].value, base=16)
                return b'\xa9' + pack('<I', im)
            else:
                if tokens[3].value in REGISTERS:
                    # TEST r/m32, r32 (85 /r)
                    r32 = REGISTERS.index(tokens[3].value)
                    modrm = 0b11000000 | r32 << 3 | rm32
                    return b'\x85' + pack('<B', modrm)
                else:
                    modrm = 0b11000000 | rm32
                    im = int(tokens[3].value, base=16)
                    return b'\xf7' + pack('<B', modrm) + pack('<I', im)
        elif tokens[1].value in REGISTERS16:
            rm16 = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if rm16 == REGISTERS16.index('ax') and tokens[3].value not in REGISTERS16:
                im = int(tokens[3].value, base=16)
                if im <= 0xffff:
                    return b'\x66\xa9' + pack('<H', im)
                return b'\x66\xa9' + pack('<I', im)
            else:
                if tokens[3].value in REGISTERS16:
                    # TEST r/m16, r16 (85 /r)
                    r16 = REGISTERS16.index(tokens[3].value)
                    modrm = 0b11000000 | r16 << 3 | rm16
                    return b'\x66\x85' + pack('<B', modrm)
                else:
                    modrm = 0b11000000 | rm16
                    im = int(tokens[3].value, base=16)
                    if im <= 0x7fff:
                        return b'\x66\xf7' + pack('<B', modrm) + pack('<H', im)
                    else:
                        return b'\x66\xf7' + pack('<B', modrm) + pack('<I', im)
        elif tokens[1].value in ['WORD', 'DWORD']:
            prefix = {'WORD': b'\x66', 'DWORD': b''}[tokens[1].value]
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            if tokens[4].value in REGISTERS:
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    if tokens[7].value in REGISTERS:
                        src = REGISTERS.index(tokens[7].value)
                        modrm = 0b00000000 | src << 3 | base
                        return b'\x85' + pack('<B', modrm)
                    else:
                        im = int(tokens[7].value, base=16)
                        modrm = 0b00000000 | base
                        return b'\xf7' + pack('<B', modrm) + pack('<i', im)
                elif tokens[5].value == '*':
                    scale = get_scale(tokens[6].value)
                    assert tokens[7].value == '+'
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    assert tokens[10].value == ','
                    im = int(tokens[11].value, base=16)
                    return prefix + b'\xf7\x04\x45' + pack('<I', disp) + pack('<H', im)
                elif tokens[5].value == '+':
                    if tokens[6].value in REGISTERS:
                        idx = REGISTERS.index(tokens[6].value)
                        assert tokens[7].value == '*'
                        scale = get_scale(tokens[8].value)
                        if tokens[9].value == ']':
                            assert tokens[10].value == ','
                            src = REGISTERS.index(tokens[11].value)
                            modrm = 0b00000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x85' + pack('<B', modrm) + pack('<B', sib)
                        elif tokens[9].value == '+':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            src = REGISTERS.index(tokens[13].value)
                            modrm = 0b01000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x85' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                        elif tokens[9].value == '-':
                            disp = int(tokens[10].value, base=16)
                            assert tokens[11].value == ']'
                            assert tokens[12].value == ','
                            src = REGISTERS.index(tokens[13].value)
                            modrm = 0b01000100 | src << 3
                            sib = 0b00000000 | scale << 6 | idx << 3 | base
                            return b'\x85' + pack('<B', modrm) + pack('<B', sib) + pack('<b', -disp)
                    else:
                        disp = int(tokens[6].value, base=16)
                        assert tokens[7].value == ']'
                        assert tokens[8].value == ','
                        if tokens[9].value in REGISTERS:
                            src = REGISTERS.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return b'\x85' + pack_modrm(modrm, disp) + pack_disp(disp)
                        elif tokens[9].value in REGISTERS16:
                            src = REGISTERS16.index(tokens[9].value)
                            modrm = 0b00000000 | src << 3 | base
                            return prefix + b'\x85' + pack_modrm(modrm, disp) + pack_disp(disp)
                        else:
                            im = int(tokens[9].value, base=16)
                            if disp <= 0x7f:
                                if tokens[4].value in ['ecx']:
                                    modrm = 0b01001000 | base
                                else:
                                    modrm = 0b01000000 | base

                                if state['eip'] in [0x6a0b6b, 0x6a16e3, 0x7c07d4]:
                                    modrm = 0b01000000 | base

                                fmt = '<I'
                                if tokens[1].value == 'WORD':
                                    fmt = '<H'
                                return prefix + b'\xf7' + pack('<B', modrm) + get_sib(base) + pack('<B', disp) + pack(fmt, im)
                            else:
                                if tokens[4].value in ['ecx']:
                                    modrm = 0b10001000 | base
                                else:
                                    modrm = 0b10000000 | base


                                fmt = '<I'
                                if tokens[1].value == 'WORD':
                                    fmt = '<H'
                                return prefix + b'\xf7' + pack('<B', modrm) + pack('<I', disp) + pack(fmt, im)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    if tokens[9].value in REGISTERS:
                        src = REGISTERS.index(tokens[9].value)
                        modrm = 0b01000101 | src << 3
                        return b'\x85' + pack('<B', modrm) + pack('<b', -disp)
                    elif tokens[9].value in REGISTERS16:
                        src = REGISTERS16.index(tokens[9].value)
                        modrm = 0b01000101 | src << 3
                        return prefix + b'\x85' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        im = int(tokens[9].value, base=16)
                        fmt = '<I'
                        if tokens[1].value == 'WORD':
                            fmt = '<H'
                        if disp <= 0x7f:
                            return prefix + b'\xf7\x45' + pack_disp(-disp) + pack(fmt, im)
                        else:
                            return prefix + b'\xf7\x83' + pack_disp(-disp) + pack(fmt, im)
                else:
                    assert False, 'Not implemented'
            else:
                assert False, 'Not implemented'
        else:
            assert False, 'Not implemented'
    elif opcode == 'TPAUSE':            assert False, 'Not implemented'
    elif opcode == 'TZCNT':             assert False, 'Not implemented'
    elif opcode.startswith('UCOMIS'):   assert False, 'Not implemented'
    elif opcode.startswith('UD'):       assert False, 'Not implemented'
    elif opcode == 'UMONITOR':          assert False, 'Not implemented'
    elif opcode == 'UMWAIT':            assert False, 'Not implemented'
    elif opcode == 'UNPCKHPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x15' + pack('<B', modrm)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            assert tokens[7].value == '+'
            disp = int(tokens[8].value, base=16)
            assert tokens[9].value == ']'
            modrm = 0b01000100 | dst << 3
            return b'\x0f\x15' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
    elif opcode == 'UNPCKLPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
            modrm = 0b11000000 | dst << 3 | src
            return b'\x0f\x14' + pack('<B', modrm)
        else:
            assert tokens[4].value == 'PTR'
            assert tokens[5].value == '['
            base = REGISTERS.index(tokens[6].value)
            assert tokens[7].value == '+'
            disp = int(tokens[8].value, base=16)
            assert tokens[9].value == ']'
            modrm = 0b01000100 | dst << 3
            return b'\x0f\x14' + pack('<B', modrm) + get_sib(base) + pack('<B', disp)
    elif opcode.startswith('UNPCK'):
        assert False, 'Not implemented'
    elif opcode == 'VZEROALL':      return b'\xc5\xfc\x77'
    elif opcode == 'VZEROUPPER':    return b'\xc5\xf8\x77'
    elif opcode.startswith('V'):
        assert False, 'Not implemented'
    elif opcode == 'XLAT':          return b'\xd7'
    elif opcode in ['WAIT', 'FWAIT']:
        return b'\x9b'
    elif opcode == 'WBINVD':        return b'\x0f\x09'
    elif opcode == 'WBNOINVD':      return b'\xf3\x0f\x09'
    elif opcode in ['WRFSBASE', 'WRGSBASE']:
        assert False, 'Not implemented'
    elif opcode == 'WRMSR':         return b'\x0f\x30'
    elif opcode == 'WRPKRU':        return b'\x0f\x01\xef'
    elif opcode.startswith('WR'):   assert False, 'Not implemented'
    elif opcode == 'XACQUIRE':      return b'\xf2'
    elif opcode == 'XRELEASE':      return b'\xf3'
    elif opcode == 'XABORT':        assert False, 'Not implemented'
    elif opcode == 'XADD':          assert False, 'Not implemented'
    elif opcode == 'XBEGIN':        assert False, 'Not implemented'
    elif opcode == 'XCHG':
        if tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            src = REGISTERS.index(tokens[3].value)
            return pack('<B', 0x90 | dst)
        elif tokens[1].value in REGISTERS8:
            modrm = 0b11100000
            return b'\x86' + pack('<B', modrm)
        elif tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                if tokens[7].value == 'al':
                    return b'\x86\x00'
                else:
                    assert False
            elif tokens[5].value == '+':
                if tokens[6].value in REGISTERS:
                    idx = REGISTERS.index(tokens[6].value)
                    assert tokens[7].value == '*'
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == '+'
                    disp = int(tokens[10].value, base=16)
                    assert tokens[11].value == ']'
                    assert tokens[12].value == ','
                    src = REGISTERS8.index(tokens[13].value)
                    modrm = 0b00000100 | scale << 6 | src << 3
                    sib = 0b01000000 | idx << 3 | base
                    if disp <= 0xff:
                        return b'\x86' + pack('<B', modrm) + pack('<B', sib) + pack('<B', disp)
                    else:
                        return b'\x86\x8c\x4a' + pack('<I', disp)
                else:
                    disp = int(tokens[6].value, base=16)
                    src = REGISTERS8.index(tokens[9].value)
                    modrm = 0b01000000 | src << 3 | base
                    return b'\x86' + pack('<B', modrm) + pack('<B', disp)
            elif tokens[5].value == '-':
                return b'\x86\xbd\x49\x00\xf3\xbf'
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            if tokens[3].value == '[':
                base = REGISTERS.index(tokens[4].value)
                if tokens[5].value == ']':
                    assert tokens[6].value == ','
                    src = REGISTERS.index(tokens[7].value)
                    modrm = 0b00000000 | src << 3 | base
                    return b'\x87' + pack('<B', modrm) + get_sib(base)
                elif tokens[5].value == '+':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERS.index(tokens[9].value)
                    modrm = 0b01000000 | src << 3 | base
                    return b'\x87' + pack('<B', modrm) + pack('<B', disp)
                elif tokens[5].value == '-':
                    disp = int(tokens[6].value, base=16)
                    assert tokens[7].value == ']'
                    assert tokens[8].value == ','
                    src = REGISTERS.index(tokens[9].value)
                    modrm = 0b10000000 | src << 3 | base
                    if disp <= 0xff:
                        assert False
                    else:
                        return b'\x87' + pack('<B', modrm) + pack('<i', -disp)
            elif tokens[3].value == 'ds':
                return b'\x3e\x87\x4a\x00'
            else:
                assert False
        else:
            assert False
    elif opcode == 'XEND':      return b'\x0f\x01\xd5'
    elif opcode == 'XGETBV':    return b'\x0f\x01\xd0'
    elif opcode in ['XLAT', 'XLATB']:
        assert False, 'Not implemented'
    elif opcode == 'XOR':
        if tokens[1].value == 'BYTE':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERS8.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x30' + pack('<B', modrm)
            elif tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS8.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                return b'\x30' + pack('<B', modrm) + pack('<B', disp)
            elif tokens[5].value == '*':
                scale = get_scale(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                assert tokens[10].value == ','
                src = REGISTERS8.index(tokens[11].value)
                modrm = 0b00000100 | src << 3
                sib = 0b00000101 | scale << 6 | base << 3
                return b'\x30' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
            else:
                assert False
        elif tokens[1].value == 'DWORD':
            assert tokens[2].value == 'PTR'
            assert tokens[3].value == '['
            base = REGISTERS.index(tokens[4].value)
            if tokens[5].value == ']':
                assert tokens[6].value == ','
                src = REGISTERS.index(tokens[7].value)
                modrm = 0b00000000 | src << 3 | base
                return b'\x31' + pack('<B', modrm)
            elif tokens[5].value == '+':
                disp = int(tokens[6].value, base=16)
                assert tokens[7].value == ']'
                assert tokens[8].value == ','
                src = REGISTERS.index(tokens[9].value)
                modrm = 0b01000000 | src << 3 | base
                return b'\x31' + pack('<B', modrm) + pack('<B', disp)
        elif tokens[1].value in REGISTERS8:
            dst = REGISTERS8.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS8:
                src = REGISTERS8.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src

                if state['eip'] in [0x48e034, 0x4fe194, 0x4fe19c, 0x69e565, 0x7fef30, 0x7ff79c]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x30' + pack('<B', modrm)

                return b'\x32' + pack('<B', modrm)
            elif tokens[3].value == 'BYTE':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x32' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b01000000 | dst << 3 | base
                    return b'\x32' + pack('<B', modrm) + pack('<B', disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    modrm = 0b10000000 | dst << 3 | base
                    return b'\x32' + pack('<B', modrm) + pack('<i', -disp)
            else:
                im = int(tokens[3].value, base=16)
                if dst == REGISTERS8.index('al'):
                    return b'\x34' + pack('<B', im)
                else:
                    modrm = 0b11110000 | dst
                    return b'\x80' + pack('<B', modrm) + pack('<B', im)
        elif tokens[1].value in REGISTERS16:
            dst = REGISTERS16.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS16:
                src = REGISTERS16.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src
                return b'\x66\x33' + pack('<B', modrm)
            else:
                assert False
        elif tokens[1].value in REGISTERS:
            dst = REGISTERS.index(tokens[1].value)
            assert tokens[2].value == ','
            if tokens[3].value in REGISTERS:
                src = REGISTERS.index(tokens[3].value)
                modrm = 0b11000000 | dst << 3 | src

                if state['eip'] in [0x69e5e5, 0x69e6e1, 0x7b1a14]:
                    modrm = 0b11000000 | src << 3 | dst
                    return b'\x31' + pack('<B', modrm)

                return b'\x33' + pack('<B', modrm)
            elif tokens[3].value == 'DWORD':
                assert tokens[4].value == 'PTR'
                assert tokens[5].value == '['
                base = REGISTERS.index(tokens[6].value)
                if tokens[7].value == ']':
                    modrm = 0b00000000 | dst << 3 | base
                    return b'\x33' + pack('<B', modrm)
                elif tokens[7].value == '+':
                    if tokens[8].value in REGISTERS:
                        idx = REGISTERS.index(tokens[8].value)
                        assert tokens[9].value == '*'
                        scale = get_scale(tokens[10].value)
                        assert tokens[11].value == '+'
                        disp = int(tokens[12].value, base=16)
                        assert tokens[13].value == ']'
                        sib = 0b00000000 | scale << 6 | idx << 3 | base
                        modrm = 0b00000100 | dst << 3
                        return b'\x33' + pack_modrm(modrm, disp) + pack('<B', sib) + pack_disp(disp)
                    else:
                        disp = int(tokens[8].value, base=16)
                        assert tokens[9].value == ']'
                        modrm = 0b00000000 | dst << 3 | base
                        return b'\x33' + pack_modrm(modrm, disp) + pack_disp(disp)
                elif tokens[7].value == '-':
                    disp = int(tokens[8].value, base=16)
                    assert tokens[9].value == ']'
                    if disp <= 0x80:
                        modrm = 0b01000000 | dst << 3 | base
                        return b'\x33' + pack('<B', modrm) + pack('<b', -disp)
                    else:
                        modrm = 0b10000000 | dst << 3 | base
                        return b'\x33' + pack('<B', modrm) + pack('<i', -disp)
                elif tokens[7].value == '*':
                    scale = get_scale(tokens[8].value)
                    assert tokens[9].value == '+'
                    disp = int(tokens[10].value, base=16)
                    assert tokens[11].value == ']'
                    modrm = 0b00000100 | dst << 3
                    sib = 0b00000101 | scale << 6 | base << 3
                    return b'\x33' + pack('<B', modrm) + pack('<B', sib) + pack('<I', disp)
            else:
                im = int(tokens[3].value, base=16)

                if tokens[1].value == 'eax' and tokens[3].value == '0xffffffff':
                    return b'\x83\xf0\xff'

                if dst == REGISTERS.index('eax'):
                    return b'\x35' + pack('<I', im)
                else:
                    modrm = 0b11110000 | dst
                    if im <= 0x7f or im >= 0xffffff00:
                        return b'\x83' + pack('<B', modrm) + pack('<B', im & 0xff)
                    else:
                        return b'\x81' + pack('<B', modrm) + pack('<I', im)
        else:
            dst = tokens[1].value
            assert tokens[2].value == ','
            src = tokens[3].value
            assert src.lower() in REGISTERS
            assert dst.lower() in REGISTERS
            modrm = 0b11000000 | REGISTERS.index(src.lower()) << 3 | REGISTERS.index(dst.lower())
            return b'\x33' + pack('<B', modrm)
    elif opcode == 'XORPD':     return b'\x66\x0f\x57\xc0'
    elif opcode == 'XORPS':
        dst = REGISTERSXMM.index(tokens[1].value)
        if tokens[3].value in REGISTERSXMM:
            src = REGISTERSXMM.index(tokens[3].value)
        elif tokens[3].value == 'XMMWORD':
            assert tokens[4].value == 'PTR'
            if tokens[5].value == 'ds':
                modrm = 0b000000101 | dst << 3
                m = int(tokens[7].value, base=16)
                return b'\x0f\x57' + pack('<B', modrm) + pack('<I', m)
            else:
                base = REGISTERS.index(tokens[6].value)
                assert tokens[7].value == '+'
                disp = int(tokens[8].value, base=16)
                assert tokens[9].value == ']'
                modrm = 0b00000100 | dst << 3
                return b'\x0f\x57' + pack_modrm(modrm, disp) + get_sib(base) + pack_disp(disp)
        modrm = 0b11000000 | dst << 3 | src
        return b'\x0f\x57' + pack('<B', modrm)
    elif opcode in ['XRSTOR', 'XRSTORS', 'XSAVE', 'XSAVEC', 'XSAVEOPT', 'XSAVES']:
        assert False, 'Not implemented'
    elif opcode == 'XSETBV':    return b'\x0f\x01\xd1'
    elif opcode == 'XTEST':     return b'\x0f\x01\xd6'
