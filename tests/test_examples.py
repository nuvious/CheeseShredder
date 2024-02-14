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

def test_initial():
    program_bytes = b'1\xc0\x01\xc8\x01\xd0U\x89\xe5RQ\xb8DCBA\x8b\x95\x08\x00\x00\x00\x8b\x8d\x0c\x00\x00\x00\x01\xd1\x89\xc8ZY]\xc2\x08\x00'
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    instructions, unparsed_bytes = disassembler.disassemble(program_bytes)
    assert len(unparsed_bytes) == 0
