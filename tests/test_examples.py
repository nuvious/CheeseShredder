import glob
import os

import cheeseshredder.base
import cheeseshredder.arch.x86_64

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
        _, _ = disassembler.disassemble(program_bytes)

def test_nop():
    program_bytes = b'\x90'
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    instructions, unparsed_bytes = disassembler.disassemble(program_bytes)
    assert len(unparsed_bytes) == 0

def test_example_1():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'positive/example1'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0

def test_example_2():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'positive/example2'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0


def test_example_3():
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(os.path.join(TEST_FILE_DIR, 'positive/example3'), 'rb') as f:
        instructions, unparsed_bytes, in_order_parse = disassembler.disassemble(f.read())
        assert len(unparsed_bytes) == 0
