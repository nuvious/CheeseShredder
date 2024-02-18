import glob
import os

import cheeseshredder.base
import cheeseshredder.format
import cheeseshredder.arch.x86_64

EXAMPLE_1_OUTPUT = """00000000: 31C0 xor eax,eax
00000002: 01C8 add eax,ecx
00000004: 01D0 add eax,edx
00000006: 55 push ebp
00000007: 89E5 mov ebp,esp
00000009: 52 push edx
0000000A: 51 push ecx
0000000B: B844434241 mov eax,0x41424344
00000010: 8B9508000000 mov edx,[ebp+0x00000008]
00000016: 8B8D0C000000 mov ecx,[ebp+0x0000000c]
0000001C: 01D1 add ecx,edx
0000001E: 89C8 mov eax,ecx
00000020: 5A pop edx
00000021: 59 pop ecx
00000022: 5D pop ebp
00000023: C20800 retn 0x0008
""".splitlines()

EXAMPLE_2_OUTPUT = """00000000: 55 push ebp
00000001: 89E5 mov ebp,esp
00000003: 52 push edx
00000004: 51 push ecx
00000005: 39D1 cmp ecx,edx
00000007: 740F jz offset_00000018h
00000009: B844434241 mov eax,0x41424344
0000000E: 8B5508 mov edx,[ebp+0x00000008]
00000011: 8B4D0C mov ecx,[ebp+0x0000000c]
00000014: 01D1 add ecx,edx
00000016: 89C8 mov eax,ecx
offset_00000018h:
00000018: 5A pop edx
00000019: 59 pop ecx
0000001A: 5D pop ebp
0000001B: C20800 retn 0x0008
""".splitlines()

EXAMPLE_3_OUTPUT = """00000000: E800000000 call func_00000005
func_00000005:
00000005: 55 push ebp
00000006: 89E5 mov ebp,esp
00000008: 57 push edi
00000009: 56 push esi
0000000A: 53 push ebx
0000000B: 52 push edx
0000000C: 51 push ecx
0000000D: 50 push eax
0000000E: E800000000 call func_00000013
func_00000013:
00000013: 5A pop edx
00000014: 8D35CB000000 lea esi,0x000000cb
0000001A: 01D6 add esi,edx
0000001C: 81C6EDFFFFFF add esi,0xffffffed
00000022: 8D0DED000000 lea ecx,0x000000ed
00000028: 01D1 add ecx,edx
0000002A: 81C1EDFFFFFF add ecx,0xffffffed
00000030: 8931 mov [ecx],esi
00000032: B906000000 mov ecx,0x00000006
00000037: 51 push ecx
00000038: 8D0DED000000 lea ecx,0x000000ed
0000003E: 01D1 add ecx,edx
00000040: 81C1EDFFFFFF add ecx,0xffffffed
00000046: FF31 push [ecx]
00000048: 8D0DD1000000 lea ecx,0x000000d1
0000004E: 01D1 add ecx,edx
00000050: 81C1EDFFFFFF add ecx,0xffffffed
00000056: 51 push ecx
00000057: E843000000 call func_0000009f
0000005C: B91C000000 mov ecx,0x0000001c
00000061: 51 push ecx
00000062: 8D0DD1000000 lea ecx,0x000000d1
00000068: 01D1 add ecx,edx
0000006A: 81C1EDFFFFFF add ecx,0xffffffed
00000070: 51 push ecx
00000071: E80C000000 call func_00000082
00000076: 5A pop edx
00000077: 5A pop edx
00000078: 58 pop eax
00000079: 59 pop ecx
0000007A: 5A pop edx
0000007B: 5B pop ebx
0000007C: 5E pop esi
0000007D: 5F pop edi
0000007E: 5D pop ebp
0000007F: C20000 retn 0x0000
func_00000082:
00000082: 55 push ebp
00000083: 89E5 mov ebp,esp
00000085: 50 push eax
00000086: 53 push ebx
00000087: 51 push ecx
00000088: 52 push edx
00000089: B804000000 mov eax,0x00000004
0000008E: BB01000000 mov ebx,0x00000001
00000093: 8B4D08 mov ecx,[ebp+0x00000008]
00000096: 8B550C mov edx,[ebp+0x0000000c]
00000099: 5A pop edx
0000009A: 59 pop ecx
0000009B: 5B pop ebx
0000009C: 58 pop eax
0000009D: 5D pop ebp
0000009E: C3 retn
func_0000009f:
0000009F: 55 push ebp
000000A0: 89E5 mov ebp,esp
000000A2: 57 push edi
000000A3: 56 push esi
000000A4: 53 push ebx
000000A5: 52 push edx
000000A6: 8B4D10 mov ecx,[ebp+0x00000010]
000000A9: 8B750C mov esi,[ebp+0x0000000c]
000000AC: 8B7D08 mov edi,[ebp+0x00000008]
000000AF: 31D2 xor edx,edx
offset_000000b1h:
000000B1: 8B06 mov eax,[esi]
000000B3: BB41000000 mov ebx,0x00000041
000000B8: 31D8 xor eax,ebx
000000BA: 8907 mov [edi],eax
000000BC: 46 inc esi
000000BD: 47 inc edi
000000BE: 42 inc edx
000000BF: 39D1 cmp ecx,edx
000000C1: 75EE jnz offset_000000b1h
000000C3: 5A pop edx
000000C4: 5B pop ebx
000000C5: 5E pop esi
000000C6: 5F pop edi
000000C7: 5D pop ebp
000000C8: C20C00 retn 0x000c
000000CB: 09242D2D2E4100 or [ebp+0x00412e2d],esp
000000D2: 0000 add [eax],eax
000000D4: 0000 add [eax],eax
000000D6: 0000 add [eax],eax
000000D8: 0000 add [eax],eax
000000DA: 0000 add [eax],eax
000000DC: 0000 add [eax],eax
000000DE: 0000 add [eax],eax
000000E0: 0000 add [eax],eax
000000E2: 0000 add [eax],eax
000000E4: 0000 add [eax],eax
000000E6: 0000 add [eax],eax
000000E8: 0000 add [eax],eax
000000EA: 0000 add [eax],eax
000000EC: 0000 add [eax],eax
000000EE: 0000 add [eax],eax
000000F0: None""".splitlines()

EXAMPLE_OFFICE_OUTPUT = """00000000: 55 push ebp
00000001: 57 push edi
00000002: C3 retn
offset_00000003h:
00000003: 8938 mov [eax],edi
00000005: 55 push ebp
00000006: 57 push edi
00000007: 55 push ebp
00000008: EBF9 jmp offset_00000003h""".splitlines()

TEST_FILE_DIR = os.path.dirname(__file__)
POSITIVE_TESTS = [
    (f, f"{f}.s") for f in glob.glob(TEST_FILE_DIR + '/positive/*') if not f.endswith('.s')
]
NEGATIVE_TESTS = [
    (f, f"{f}.s") for f in glob.glob(TEST_FILE_DIR + '/negative/*') if not f.endswith('.s')
]
ALL_TESTS = POSITIVE_TESTS + NEGATIVE_TESTS

def test_dummy_disassembler():
    """Simple smoke-test that the basic base workflow of the disassembler is working.
    """
    disassembler = cheeseshredder.base.Disassember()
    with open(POSITIVE_TESTS[0][0], 'rb') as f:
        program_bytes = f.read()
        _, _, _ = disassembler.disassemble(program_bytes)

def test_nop():
    program_bytes = b'\x90'
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(program_bytes)
    assert len(unparsed_bytes) == 0

def test_fuzz_hit_00():
    # BSWAP has a prefix before a register encoded opcode, test ensures these are hanlded properly
    # 0FCF bswap edi
    program_bytes = b'\x0f\xcf'
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(program_bytes)
    output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
    assert len(unparsed_bytes) == 0

def test_example_1():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'positive/example1'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
        assert len(instructions) == len(EXAMPLE_1_OUTPUT)
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        for instruction_line, line in zip(output, EXAMPLE_1_OUTPUT):
            assert instruction_line == line

def test_example_2():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'positive/example2'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
        assert len(instructions) == len(EXAMPLE_2_OUTPUT) - 1 # Example output 2 has one label
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        for instruction_line, line in zip(output, EXAMPLE_2_OUTPUT):
            assert instruction_line == line
            

def test_example_3():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'positive/example3'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 1 # There is one trailing null byte 
        # example 3 has raw strings encoded at the end, these get interpreted as instructions later
        # Below is just a quick correction since it's expected behavior
        # TODO: See if you can use the system calls to detect memory addresses that are strings
        assert len(instructions) == len(EXAMPLE_3_OUTPUT) - 6 # There are 2 jump labels and 4 function labels
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        for instruction_line, line in zip(output, EXAMPLE_3_OUTPUT):
            assert instruction_line == line

def test_example_office():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'positive/example-office'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
        assert len(instructions) == len(EXAMPLE_OFFICE_OUTPUT) - 1 # There is one label in this output
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        for instruction_line, line in zip(output, EXAMPLE_OFFICE_OUTPUT):
            assert instruction_line == line

def test_example_large():
    # disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    # with open(os.path.join(TEST_FILE_DIR, 'positive/large_example'), 'rb') as f:
    #     instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
    #     assert len(unparsed_bytes) == 0
    pass
