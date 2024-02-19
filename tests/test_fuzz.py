import os
import re

import cheeseshredder.base
import cheeseshredder.format
import cheeseshredder.arch.x86_64

TEST_FILE_DIR = os.path.dirname(__file__)
FUZZ_DIR = os.path.join(TEST_FILE_DIR, "fuzz")
regex = re.compile('test_case_[0-9]+$')

FUZZ_TEST_FILES = []
for root, dirs, files in os.walk(FUZZ_DIR):
  for file in files:
    if regex.match(file):
       FUZZ_TEST_FILES.append(os.path.join(FUZZ_DIR, file))

def test_fuzz():
    for file in FUZZ_TEST_FILES:
        with open(file, 'rb') as f:
            disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
            _, _, _ = disassembler.disassemble(f.read())
