import csv
import copy
from importlib import resources

from . import data
from ...base import Instruction, Disassember

_X86_64_INSTRUCTION_TABLE_CSV_FNAME = "x86-csv/x86.csv"
INSTRUCTION_TABLE = None
_MODRM_32_TABLE_CSV_FNAME = "ModRMTable32.csv"
_MODRM_16_TABLE_CSV_FNAME = "ModRMTable16.csv"
MODRM_TABLE = None
_SIB_TABLE_CSV_FNAME = "SIBTable.csv"
SIB_TABLE = None
_PREFIXES_CSV_FNAME = "Prefixes.csv"
PREFIXES = None
INVALID_ADDRESSING_MODES = [
    "r16",
    "r64",
    "r/m16",
    "r/m64",
    "xmm",
    "ymm"
]
INVALID_VALID_ADDRESS_MODE = \
    lambda inst_str: any([ i in inst_str for i in INVALID_ADDRESSING_MODES])

REGISTERS = [
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi"
]

def _try_parse_hex(raw_str):
    """Tries to parse a string into bytes from hex and if it fails returns the string.

    Args:
        raw_str (str): A hex string

    Returns:
        bytes, tuple of bytes or str:
            The parsed bytes or the string if it could not be parsed from hex.
    """
    try:
        try:
            return bytes.fromhex(raw_str)[0]
        except:
            opcodes = []
            if raw_str.endswith("+rd") or raw_str.endswith("+rw"):
                opcode = int(raw_str[:2], 16)
                for i, _ in enumerate(REGISTERS):
                    opcodes.append(opcode + i)
                return tuple(opcodes)
            else:
                return raw_str
    except:
        print(raw_str)
        raise

def get_prefix_table():
    global PREFIXES
    if not PREFIXES:
        PREFIXES = []
        prefix_file = (resources.files(data) / _PREFIXES_CSV_FNAME)
        with prefix_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                PREFIXES.append(bytes.fromhex(row["HEX"])[0])
    return PREFIXES

def get_sib_table():
    global SIB_TABLE
    if not SIB_TABLE:
        SIB_TABLE = {}
        sib_table_file = (resources.files(data) / _SIB_TABLE_CSV_FNAME)
        with sib_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                SIB_TABLE[bytes.fromhex(row["SIB"])[0]] = row
    return SIB_TABLE

def get_modrm_mapping():
    global MODRM_TABLE
    if not MODRM_TABLE:
        MODRM_TABLE = {
            "32":{},
            "16":{}
        }
        modrm_table_file = (resources.files(data) / _MODRM_32_TABLE_CSV_FNAME)
        with modrm_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                MODRM_TABLE["32"][bytes.fromhex(row["ModR/M"])[0]] = row
        modrm_table_file = (resources.files(data) / _MODRM_16_TABLE_CSV_FNAME)
        with modrm_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                MODRM_TABLE["16"][bytes.fromhex(row["ModR/M"])[0]] = row
    return MODRM_TABLE

def get_instruction_table():
    global INSTRUCTION_TABLE
    if not INSTRUCTION_TABLE:
        INSTRUCTION_TABLE = {}
        instruction_table_file = (resources.files(data) / _X86_64_INSTRUCTION_TABLE_CSV_FNAME)
        with instruction_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if INVALID_VALID_ADDRESS_MODE(row["Instruction"]):
                    continue
                instruction = X86_64Instruction.instruction_from_row(row)
                INSTRUCTION_TABLE[(instruction.opcode, instruction.operands)] = instruction
    return INSTRUCTION_TABLE


class X86_64Disassembler(Disassember):
    def next_instruction(self, program_bytes, max_unparsed_bytes=4):
        byte_count = 1
        possible_instructions = {}
        partial_instructions = {}
        for k, i in INSTRUCTION_TABLE.items():
            result = i.is_valid(program_bytes[:byte_count])
            if result != 0:
                possible_instructions[k] = i
            if result == 1:
                partial_instructions[k] = i
        last_instruction_set = None
        while (
                byte_count < max_unparsed_bytes and
                (
                    len(possible_instructions) > 1 or
                    len(partial_instructions) > 0
                )
            ):
            # Add one more byte to be parsed
            byte_count += 1
            # Clear partial instruction tracker
            partial_instructions = {}
            last_instruction_set = possible_instructions
            for k, i in possible_instructions.items():
                result = i.is_valid(program_bytes[:byte_count])
                if result != 0:
                    possible_instructions[k] = i
                if result == 1:
                    partial_instructions[k] = i
        if len(possible_instructions) == 1 and len(partial_instructions) == 0:
            return (
                program_bytes[byte_count:],
                program_bytes[:byte_count],
                list(possible_instructions.values())[0]
            )
        else:
            return program_bytes[1:], program_bytes[:1], None

class X86_64Instruction(Instruction):
    def instruction_from_row(row):
        # Get the opcode
        opcodes = tuple([
            _try_parse_hex(token) 
            for token in row["Opcode"].split(" ")
            if token != '+'
        ])
        no_prefixes = False
        if no_prefixes := opcodes[0] == "NP":
            opcodes = tuple(opcodes[1:])
        operands = tuple([
            row["Operand 1"] if row["Operand 1"] != "NA" else None,
            row["Operand 2"] if row["Operand 2"] != "NA" else None,
            row["Operand 3"] if row["Operand 3"] != "NA" else None,
            row["Operand 4"] if row["Operand 4"] != "NA" else None
        ])
        kwargs = {
            "mnemonic": row["Instruction"].split(" ")[0],
            "opcode": opcodes,
            "operands": operands,
            "no_prefixes": no_prefixes
        }
        return X86_64Instruction(**kwargs)

    def is_valid(self, instruction_bytes):
        """Returns if the instruction is valid, partial or invalid (2, 1, 0)

        Args:
            instruction_bytes (_type_): _description_
        
        Returns:
            int: Valid, Partial, or Invalid match. (2, 1, 0)
        """
        # Check if opcode is satisfied
        byte_pos = 0
        self.parsed_operands = []
        for b in self.opcode:
            if byte_pos >= len(instruction_bytes):
                return 1 # If we've gotten this far, we have a partial match
            if type(b) is str:
                if b == '/r':
                    for operand in self.operands:
                        if operand:
                            if "ModRM:r/m (r, w)" in operand:
                                # The ModRM byte refers to the source and destination, we're done
                                self.parsed_operands.append(MODRM_TABLE["32"][instruction_bytes[byte_pos]])
                                return 2
                            else:
                                return 0 # TODO: Implement parsing other operands
                        else:
                            return 2 # Once we've run out of operands, call it good
                    return 2
                else:
                    # Sinkhole for string opcode identifiers that aren't implemented
                    return 0
            elif type(b) is tuple:
                if instruction_bytes[byte_pos] not in b:
                    return 0
            else:
                if b != instruction_bytes[byte_pos]:
                    return 0
            byte_pos += 1
        # If we parse successfull 
        if byte_pos == len(instruction_bytes):
            return 2
        else:
            return 1
    
    def __str__(self):
        return f"{self.mnemonic} {self.operands}"

    def __init__(self, *arg, **kwargs):
        self.prefix = None
        self.opcode = None
        self.operands = None
        self.mnemonic = None
        self.parsed_operands = None
        self.no_prefixes = False
        self.sib = None
        self.displacement = None
        for k, v in kwargs.items():
            setattr(self, k, v)

get_sib_table()
get_modrm_mapping()
get_prefix_table()
get_instruction_table()

if __name__ == "__main__":
    print(INSTRUCTION_TABLE)
