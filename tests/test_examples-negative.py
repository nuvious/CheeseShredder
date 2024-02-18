import glob
import os

import cheeseshredder.base
import cheeseshredder.format
import cheeseshredder.arch.x86_64


TEST_FILE_DIR = os.path.dirname(__file__)

NEG_DISP_OUTPUT="00000000: 897EFC mov [esi+0xfffffffc],edi"

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
