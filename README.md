# x86-64 Assembly Toolkit

The goal of this project is to understand the x86-64 Instruction Set Architecture (ISA) and create a tiny disassembler and assembler.

## Roadmap
- [ ] x86 Disassembler (Intel syntax)
  - [x] [1-byte Opcodes](./doc/op_1.md)
  - [ ] [2-byte Opcodes](./doc/op_2.md)
  - [ ] 3-byte Opcodes
  - [ ] Improve Performance
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

## Using other disassemblers
```console
$ ndisasm -b32 <(echo -ne '\x90')
00000000  90                nop

$ ndisasm -b32 <(echo -ne '\x90') | tr -s ' ' | cut -d ' ' -f3-
nop
```

## Performance (on a 4.5M binary ~ 1.6M asm lines)
```console
$ time $(ndisasm -b 32 <(cat $BINARY) >/dev/null)       # 0m0.783s
$ time $(objdump -d -M i386,intel $BINARY >/dev/null)   # 0m1.375s
$ time $(cat $BINARY | ./asm.py -b 0x401000 >/dev/null) # 2m25.271s
```

## References
- [Intel Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
    - One-byte Opcode Map: 2661, 2662
    - Opcode Extensions by Group Number: 2672
    - ModR/M Addressing Forms (32-bit): 512
    - Key to Abbreviations: 2655
    - FPU x87: 2679
- [Defuse (Online x86/x64 Assembler and Disassembler)](https://defuse.ca/online-x86-assembler.htm)
- [GNU Assembler](https://sourceware.org/binutils/docs-2.39/as.html)
- [Capstone](http://www.capstone-engine.org/)
- [Keystone](https://www.keystone-engine.org/)
- [Netwide Assembler (NASM)](https://www.nasm.us/)
- [Flat Assembler (FASM)](https://flatassembler.net/)
- [Microsoft Macro Assembler (MASM)](https://learn.microsoft.com/en-us/cpp/assembler/masm/microsoft-macro-assembler-reference)
- [x64dbg](https://x64dbg.com/)
- [AMD 3DNow!](https://www.amd.com/system/files/TechDocs/21928.pdf)
- [AMD64 Architecture Programmer's Manual](https://www.amd.com/system/files/TechDocs/26569.pdf)
