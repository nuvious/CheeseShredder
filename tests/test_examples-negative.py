import os

import cheeseshredder.base
import cheeseshredder.format
import cheeseshredder.arch.x86_64

TEST_FILE_DIR = os.path.dirname(__file__)

BAD_CLFLUSH_OUTPUT="00000000: 0FAEFE clflush (bad)"
BAD_LEA_OUTPUT="00000000: 8DF9 lea (bad)"
CALL_MISSING_BYTES="""00000000: db 0xe8
00000001: 0000 add [eax],eax""".splitlines()
CALL_WITHIN_SELF="""00000000: E8FFFFFFFF call 0x00000004
00000005: 90 nop""".splitlines()
NEG_DISP_OUTPUT="00000000: 897EFC mov [esi+0xfffffffc],edi"

def test_bad_clflush():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'negative/bad_clflush'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
        assert len(instructions) == 1
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        assert len(output) == 1
        assert output[0] == BAD_CLFLUSH_OUTPUT

def test_bad_lea():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'negative/bad_lea'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
        assert len(instructions) == 1
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        assert len(output) == 1
        assert output[0] == BAD_LEA_OUTPUT
        
def test_call_missing_bytes():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'negative/call_missingbytes'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 1 # The e8 byte will get marked as un-parsed
        assert len(instructions) == 1
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        assert len(output) == 2
        for instruction_line, line in zip(output, CALL_MISSING_BYTES):
            assert instruction_line == line

def test_bad_lea():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'negative/call_withinself'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
        assert len(instructions) == 2
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        assert len(output) == 2
        for instruction_line, line in zip(output, CALL_WITHIN_SELF):
            assert instruction_line == line

def test_neg_disp():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'negative/neg_disp'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
        assert len(instructions) == 1
        # When outputs have labels, some lines will contain newlines in them. Join and re-split to get individual lines
        output = "\n".join(cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse)).splitlines()
        assert len(output) == 1
        assert output[0] == NEG_DISP_OUTPUT
