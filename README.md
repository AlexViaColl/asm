# x86-64 Assembly Toolkit

The goal of this project is to understand the x86-64 Instruction Set Architecture (ISA) and create a tiny disassembler and assembler.

## Roadmap
- [ ] x86 Disassembler (Intel syntax)
  - [ ] 1-byte Opcodes 105/181 (58.01%)
    - [x] 00 ADD Eb, Gb
    - [x] 01 ADD Ev, Gv
    - [ ] 02 ADD Gb, Eb
    - [ ] 03 ADD Gv, Ev
    - [x] 04 ADD AL, Ib
    - [x] 05 ADD rAX, Iz
    - [x] 06 PUSH ES
    - [x] 07 POP ES
    - [x] 08 OR Eb, Gb
    - [x] 09 OR Ev, Gv
    - [ ] 0a OR Gb, Eb
    - [ ] 0b OR Gv, Ev
    - [x] 0c OR AL, Ib
    - [x] 0d OR rAX, Iz
    - [x] 0e PUSH CS
    - [ ] 0f 2-byte opcode escape
    - [x] 10 ADC Eb, Gb
    - [x] 11 ADC Ev, Gv
    - [ ] 12 ADC Gb, Eb
    - [ ] 13 ADC Gv, Ev
    - [x] 14 ADC AL, Ib
    - [x] 15 ADC rAX, Iz
    - [x] 16 PUSH SS
    - [x] 17 POP SS
    - [x] 18 SBB Eb, Gb
    - [x] 19 SBB Ev, Gv
    - [ ] 1a SBB Gb, Eb
    - [ ] 1b SBB Gv, Ev
    - [x] 1c SBB AL, Ib
    - [x] 1d SBB rAX, Iz
    - [x] 1e PUSH DS
    - [x] 1f POP DS
    - [x] 20 AND Eb, Gb
    - [x] 21 AND Ev, Gv
    - [ ] 22 AND Gb, Eb
    - [ ] 23 AND Gv, Ev
    - [x] 24 AND AL, Ib
    - [x] 25 AND rAX, Iz
    - [ ] 26 SEG=ES (Prefix)
    - [x] 27 DAA
    - [x] 28 SUB Eb, Gb
    - [x] 29 SUB Ev, Gv
    - [ ] 2a SUB Gb, Eb
    - [ ] 2b SUB Gv, Ev
    - [x] 2c SUB AL, Ib
    - [x] 2d SUB rAX, Iz
    - [ ] 2e SEG=CS (Prefix)
    - [x] 2f DAS
    - [x] 30 XOR Eb, Gb
    - [x] 31 XOR Ev, Gv
    - [ ] 32 XOR Gb, Eb
    - [ ] 33 XOR Gv, Ev
    - [x] 34 XOR AL, Ib
    - [x] 35 XOR rAX, Iz
    - [ ] 36 SEG=SS (Prefix)
    - [x] 37 AAA
    - [x] 38 CMP Eb, Gb
    - [x] 39 CMP Ev, Gv
    - [ ] 3a CMP Gb, Eb
    - [ ] 3b CMP Gv, Ev
    - [x] 3c CMP AL, Ib
    - [x] 3d CMP rAX, Iz
    - [ ] 3e SEG=DS (Prefix)
    - [x] 3f AAS
    - [x] 40-47 INC general register
    - [x] 48-4f DEC general register
    - [x] 50-57 PUSH general register
    - [x] 58-5f POP general register
    - [x] 60 PUSHA
    - [x] 61 POPA
    - [ ] 62 BOUND Gv, Ma
    - [ ] 63 ARPL Ew, Gw
    - [ ] 64 SEG=FS (Prefix)
    - [ ] 65 SEG=GS (Prefix)
    - [ ] 66 Operand Size (Prefix)
    - [ ] 67 Address Size (Prefix)
    - [x] 68 PUSH Iz
    - [ ] 69 IMUL Gv, Ev, Iz
    - [x] 6a PUSH Ib
    - [ ] 6b IMUL Gv, Ev, Ib
    - [ ] 6c INS/INSB Yb, DX
    - [ ] 6d INS/INSW/INSD Yz, DX
    - [ ] 6e OUTS/OUTSB DX, Xb
    - [ ] 6f OUTS/OUTSW/OUTSD DX, Xz
    - [ ] 70-7f JCC
    - [ ] 80 Immediate Grp 1 Eb, Ib
    - [ ] 81 Immediate Grp 1 Ev, Iz
    - [ ] 82 Immediate Grp 1 Eb, Ib
    - [ ] 83 Immediate Grp 1 Ev, Ib
    - [x] 84 TEST Eb, Gb
    - [x] 85 TEST Eb, Gb
    - [ ] 86 XCHG Eb, Gb
    - [ ] 87 XCHG Ev, Gv
    - [ ] 88 MOV Eb, Gb
    - [ ] 89 MOV Ev, Gv
    - [ ] 8a MOV Gb, Eb
    - [ ] 8b MOV Gv, Ev
    - [ ] 8c MOV Ev, Sw
    - [ ] 8d LEA Gv, M
    - [ ] 8e MOV Sw, Ew
    - [ ] 8f Grp 1A POP Ev
    - [x] 90 NOP / XCHG r8, rAX
    - [x] 91 XCHG rCX/r9
    - [x] 92 XCHG rDX/r10
    - [x] 93 XCHG rBX/r11
    - [x] 94 XCHG rSP/r12
    - [x] 95 XCHG rBP/r13
    - [x] 96 XCHG rSI/r14
    - [x] 97 XCHG rDI/r15
    - [x] 98 CBW/CWDE/CDQE *
    - [x] 99 CWD/CDQ/CQO *
    - [ ] 9a far CALL Ap
    - [x] 9b FWAIT/WAIT
    - [x] 9c PUSHF/D/Q/Fv *
    - [x] 9d POPF/D/Q/Fv *
    - [x] 9e SAHF
    - [x] 9f LAHF
    - [ ] a0 MOV AL, Ob
    - [ ] a1 MOV rAX, Ov
    - [ ] a2 MOV Ob, AL
    - [ ] a3 MOV Ov, rAX
    - [ ] a4 MOVS/B Yb, Xb
    - [ ] a5 MOVS/W/D/Q Yv, Xv
    - [ ] a6 CMPS/B Xb, Yb
    - [ ] a7 CMPS/W/D Xv, Yv
    - [x] a8 TEST AL, Ib
    - [x] a9 TEST rAX, Iz
    - [ ] aa STOS/B Yb, AL
    - [ ] ab STOS/W/D/Q Yv, rAX
    - [ ] ac LODS/B AL, Xb
    - [ ] ad LODS/W/D/Q rAX, Xv
    - [ ] ae SCAS/B AL, Yb
    - [ ] af SCAS/W/D/Q rAX, Yv
    - [x] b0 MOV AL/R8B, Ib
    - [x] b1 MOV CL/R9B, Ib
    - [x] b2 MOV DL/R10B, Ib
    - [x] b3 MOV BL/R11B, Ib
    - [x] b4 MOV AH/R12B, Ib
    - [x] b5 MOV CH/R13B, Ib
    - [x] b6 MOV DH/R14B, Ib
    - [x] b7 MOV BH/R15B, Ib
    - [x] b8 MOV rAX/r8, Iv
    - [x] b9 MOV rCX/r9, Iv
    - [x] ba MOV rDX/r10, Iv
    - [x] bb MOV rBX/r11, Iv
    - [x] bc MOV rSP/r12, Iv
    - [x] bd MOV rBP/r13, Iv
    - [x] be MOV rSI/r14, Iv
    - [x] bf MOV rDI/r15, Iv
    - [ ] c0 Shift Grp 2 Eb, Ib
    - [ ] c1 Shift Grp 2 Ev, Iv
    - [x] c2 near RET Iw
    - [x] c3 RET
    - [ ] c4 LES Gz, Mp VEX + 2 byte
    - [ ] c5 LDS Gz, Mp VEX + 1 byte
    - [ ] c6 Grp 11 MOV Eb, Ib
    - [ ] c7 Grp 11 MOV Ev, Iz
    - [x] c8 ENTER Iw, Ib
    - [x] c9 LEAVE
    - [x] ca far RET Iw
    - [x] cb far RET
    - [x] cc INT3
    - [x] cd INT Ib
    - [x] ce INTO
    - [x] cf IRET/D/Q
    - [ ] f0 LOCK (Prefix)
    - [x] f1 INT1
    - [ ] f2 REPNE XACQUIRE (Prefix)
    - [ ] f3 REP/REPE XRELEASE (Prefix)
    - [x] f4 HLT
    - [x] f5 CMC
    - [ ] f6 Unary Grp 3 Eb
    - [ ] f7 Unary Grp 3 Ev
    - [x] f8 CLC
    - [x] f9 STC
    - [x] fa CLI
    - [x] fb STI
    - [x] fc CLD
    - [x] fd STD
    - [ ] fe INC/DEC Grp 4
    - [ ] ff INC/DEC Grp 5
  - [ ] ...
- [ ] x86 Assembler
- [ ] Add x64 support
...

## Quickstart
```console
# Run the tests
$ ./test.py

$ echo -ne '\x90' | ./asm.py
NOP
```

## References
- [Intel Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Defuse (Online x86/x64 Assembler and Disassembler)](https://defuse.ca/online-x86-assembler.htm)
- [GNU Assembler](https://sourceware.org/binutils/docs-2.39/as.html)
- [Capstone](http://www.capstone-engine.org/)
- [Keystone](https://www.keystone-engine.org/)
- [Netwide Assembler (NASM)](https://www.nasm.us/)
- [Flat Assembler (FASM)](https://flatassembler.net/)
- [Microsoft Macro Assembler (MASM)](https://learn.microsoft.com/en-us/cpp/assembler/masm/microsoft-macro-assembler-reference)
- [x64dbg](https://x64dbg.com/)