# x86-64 Assembly Toolkit

The goal of this project is to understand the x86-64 Instruction Set Architecture (ISA) and create a tiny disassembler and assembler.

## Roadmap
- [ ] x86 Disassembler (Intel syntax)
  - [ ] 1-byte Opcodes
    - [x] 06 PUSH ES
    - [x] 07 POP ES
    - [x] 0e PUSH CS
    - [x] 16 PUSH SS
    - [x] 17 POP SS
    - [x] 1e PUSH DS
    - [x] 1f POP DS
    - [x] 27 DAA
    - [x] 2f DAS
    - [x] 90 NOP
    - [x] c3 RET
    - [x] cc INT3
    - [x] f4 HLT
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
