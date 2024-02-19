import re
import csv
import copy
import logging
from importlib import resources

from . import data
from ...base import Instruction, Disassember

_log = logging.getLogger(__name__)

_X86_64_INSTRUCTION_TABLE_CSV_FNAME = "x86.csv"
_INSTRUCTION_TABLE = None
_MODRM_32_TABLE_CSV_FNAME = "ModRMTable32.csv"
_MODRM_16_TABLE_CSV_FNAME = "ModRMTable16.csv"
_MODRM_TABLE = None
_SIB_TABLE_CSV_FNAME = "SIBTable.csv"
_SIB_TABLE = None
_PREFIXES_CSV_FNAME = "Prefixes.csv"
_PREFIXES = None
_UNIMPLEMENTED_INSTRUCTION_TOKENS = [
    "r16",
    "r64",
    "r/m16",
    "r/m64",
    "m64",
    "xmm",
    "ymm",
    "ST(i)",
    "ST(0)",
    "rel16",
    " AX, ",
    " AL, ",
    "m2byte",
    "m16int",
    "m32int",
    "m64int",
    "m14/28byte",
    "m94/108byte",
    "m32fp",
    "m64fp",
    "STAC"
]
_CONTAINS_INVALID_INSTRUCTION_TOKENS = \
    lambda inst_str: any([ i in inst_str for i in _UNIMPLEMENTED_INSTRUCTION_TOKENS])

_JHU_REQUIRED_MNEMONICS = ["ADD", "JMP", "POP", "AND", "JZ", "JNZ", "PUSH", "CALL", "LEA", "CMPSD", "CLFLUSH", "MOV",
                           "RETF", "CMP", "MOVSD", "RETN", "DEC", "NOP", "SUB", "IDIV", "NOT", "TEST", "INC", "OR",
                           "XOR"]

_REGISTERS = [
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi"
]
_UNIMPLEMENTED_OPERANDS = [
    "REX.W",
    "REX",
    "VEX"
]
CONTAINS_UNIMPLEMENTED_OPERANDS = \
    lambda inst_str: any([ i in inst_str for i in _UNIMPLEMENTED_OPERANDS])

def _try_parse_hex(raw_str):
    """Tries to parse a string into bytes from hex and if it fails returns the string.

    Args:
        raw_str (str): A hex string

    Returns:
        bytes, tuple of bytes or str:
            The parsed bytes or the string if it could not be parsed from hex.
    """
    if raw_str in ['cb', 'cd']: # Edge case for cb/cd operand. All hex should be upper case
        return raw_str
    try:
        try:
            return bytes.fromhex(raw_str)[0]
        except:
            opcodes = []
            if raw_str.endswith("+rd") or \
                raw_str.endswith("+rw") or \
                raw_str.endswith("+rb"):
                opcode = int(raw_str[:2], 16)
                for i, _ in enumerate(_REGISTERS):
                    opcodes.append(opcode + i)
                return tuple(opcodes)
            else:
                return raw_str
    except:
        print(raw_str)
        raise

def _bytes_to_signed_hex_string(val):
    if type(val) is bytes:
        val = int.from_bytes(val, signed=True)
        return "0x%08x" % (2**32 + val if val < 0 else val)
    else: # Single byte
        val = val if val < 128 else val - 256
        return "0x%08x" % (2**32 + val if val < 0 else val)
        

def get_prefix_table():
    global _PREFIXES
    if not _PREFIXES:
        _PREFIXES = []
        prefix_file = (resources.files(data) / _PREFIXES_CSV_FNAME)
        with prefix_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _PREFIXES.append(bytes.fromhex(row["HEX"])[0])
    return _PREFIXES

def get_sib_table():
    global _SIB_TABLE
    if not _SIB_TABLE:
        _SIB_TABLE = {}
        sib_table_file = (resources.files(data) / _SIB_TABLE_CSV_FNAME)
        with sib_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _SIB_TABLE[bytes.fromhex(row["SIB"])[0]] = row
    return _SIB_TABLE

class ModRM:
    _REGISTER_CHARS = set(c for register in _REGISTERS for c in register)
    SINGLE_REGISTER_MODRM_PATTERN = r'^\[([' + r''.join(_REGISTER_CHARS).upper() + r']{3})\]$'
    DISP8_REGISTER_MODRM_PATTERN = r'^\[([' + r''.join(_REGISTER_CHARS).upper() + r']{3})\]\+disp8$'
    DISP32_REGISTER_MODRM_PATTERN = r'^\[([' + r''.join(_REGISTER_CHARS).upper() + r']{3})\]\+disp32$'
    
    def __init__(self, *args, **kwargs):
        self.mod_rm = int(kwargs['ModR/M (dec)'])
        self.mod = int(kwargs['MOD'])
        self.reg = _REGISTERS[int(kwargs['REG'])]
        self.rm = int(kwargs['RM'])
        self.effective_address = kwargs['Effective Address']
        self.r32 = kwargs['r32']
        self.r16 = kwargs['r32']
        self.r8 = kwargs['r8']
        self.mm = kwargs['mm']
        self.xmm = kwargs['xmm']
        self.digit = kwargs['/digit']
        self.sib_entry = None
    
    def __str__(self):
        if self.mod_rm >= 192:
            return f"{self.effective_address[:3].lower()},{self.r32.lower()}"
        elif re.match(self.SINGLE_REGISTER_MODRM_PATTERN, self.effective_address):
            # ex [EAX]
            reg = self.effective_address[1:4].lower()
            return f"{self.reg},{reg}"
        elif self.effective_address == '[--][--]':
            if self.sib_entry["Base"] == '5': # 101
                if self.mod == 0:
                    return f"[{self.sib_entry['Scaled Index'][1:-1].lower()}SIMM32],{self.reg}"
                elif self.mod == 1:
                    return f"[{self.sib_entry['Scaled Index'][1:-1].lower()}SIMM8+ebp],{self.reg}"
                elif self.mod == 2:
                    return f"[{self.sib_entry['Scaled Index'][1:-1].lower()}SIMM32+ebp],{self.reg}"
                else:
                    raise ValueError("There is no legal SIB state with mod bits set to 11.")
            else:
                return f"{self.reg}, [{self.sib_entry['r32'].lower()}+{self.sib_entry['Scaled Index'][1:-1].lower()}]"
        elif self.effective_address == 'disp32':
            return f"{self.reg},IMM32"
        elif re.match(self.DISP8_REGISTER_MODRM_PATTERN, self.effective_address):
            return f"{self.reg},[{self.effective_address[1:4].lower()}SIMM8]"
        elif re.match(self.DISP32_REGISTER_MODRM_PATTERN, self.effective_address):
            return f"{self.reg},[{self.effective_address[1:4].lower()}SIMM32]"
        else:
            return f"ILLEGAL INSTRUCTION {str(self.__dict__)}"
                
def get_modrm_mapping():
    global _MODRM_TABLE
    if not _MODRM_TABLE:
        _MODRM_TABLE = {
            "32":{},
            "16":{}
        }
        modrm_table_file = (resources.files(data) / _MODRM_32_TABLE_CSV_FNAME)
        with modrm_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _MODRM_TABLE["32"][bytes.fromhex(row["ModR/M"])[0]] = ModRM(**row)
        modrm_table_file = (resources.files(data) / _MODRM_16_TABLE_CSV_FNAME)
        with modrm_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _MODRM_TABLE["16"][bytes.fromhex(row["ModR/M"])[0]] = ModRM(**row)
    return _MODRM_TABLE

def get_instruction_table():
    global _INSTRUCTION_TABLE
    if not _INSTRUCTION_TABLE:
        _INSTRUCTION_TABLE = {}
        instruction_table_file = (resources.files(data) / _X86_64_INSTRUCTION_TABLE_CSV_FNAME)
        with instruction_table_file.open("r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                instruction = X86_64Instruction.instruction_from_row(row)
                if (_CONTAINS_INVALID_INSTRUCTION_TOKENS(row["Instruction"]) or
                    CONTAINS_UNIMPLEMENTED_OPERANDS(row["Opcode"]) or
                    row["Valid 32-bit"] == "Invalid" or
                    instruction.mnemonic not in _JHU_REQUIRED_MNEMONICS
                ):
                    continue
                _INSTRUCTION_TABLE[(instruction.opcode, instruction.operands)] = instruction
    return _INSTRUCTION_TABLE


class X86_64Disassembler(Disassember):
    def __init__(self) -> None:
        super().__init__()
        get_sib_table()
        get_modrm_mapping()
        get_prefix_table()
        get_instruction_table()

    def get_instruction_table(self):
        return _INSTRUCTION_TABLE

class X86_64Instruction(Instruction):
    def instruction_from_row(row):
        # Get the opcode
        opcodes = tuple([
            _try_parse_hex(token) 
            for token in row["Opcode"].split(" ")
            if token != '+'
        ])
        opcode_encoding_with_register = any([type(opcode) == tuple for opcode in opcodes])
        has_immediate = any([opcode in ['id','iw','ib','cw','cb','ci'] for opcode in opcodes])
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
            "no_prefixes": no_prefixes,
            "has_immediate": has_immediate,
            "opcode_encoding_with_register": opcode_encoding_with_register,
            "description": row["Description"]
        }
        return X86_64Instruction(**kwargs)
        
    def is_valid(self, instruction_bytes):
        """Returns if the instruction is valid, partial or invalid (2, 1, 0)

        Args:
            instruction_bytes (_type_): _description_
        
        Returns:
            int: Valid, Partial, or Invalid match. (2, 1, 0)
        """
        # Check for NOP/XCHNG EAX,EAX edge case. Don't match on XCHG
        if self.mnemonic == "XCHG" and instruction_bytes == b'\x90':
            return 0
        
        # Check if opcode is satisfied
        byte_pos = 0
        self.parsed_operands = []
        for b in self.opcode:
            if byte_pos >= len(instruction_bytes):
                return 1 # If we've gotten this far, we have a partial match
            if type(b) is str:
                if b in ['/r', '/0', '/1', '/2', '/3', '/4', '/5', '/6', '/7']:
                    mod_rm_entry = _MODRM_TABLE["32"][instruction_bytes[byte_pos]]
                    if b != '/r':
                        if len(mod_rm_entry.digit) == 0:
                            return 0
                        if not b.endswith(mod_rm_entry.digit):
                            return 0
                    self.parsed_operands.append(mod_rm_entry)
                    
                    if '[--][--]' in mod_rm_entry.effective_address:
                        byte_pos += 1
                        if byte_pos < len(instruction_bytes):
                            sib_entry = _SIB_TABLE[instruction_bytes[byte_pos]]
                            mod_rm_entry.sib_entry = sib_entry
                            if sib_entry['r32'].startswith('A disp32 with'):
                                if mod_rm_entry.mod == 0:
                                    byte_pos += 4
                                elif mod_rm_entry.mod == 1:
                                    byte_pos += 1
                                elif mod_rm_entry.mod == 2:
                                    byte_pos += 4
                        else:
                            return 1

                    if mod_rm_entry.effective_address.endswith("disp32"):
                        byte_pos += 5
                    elif mod_rm_entry.effective_address.endswith("disp8"):
                        byte_pos += 2
                    else:
                        byte_pos += 1
                    continue
                
                elif b in ['cd', 'id']: # imm32
                    if byte_pos + 4 > len(instruction_bytes):
                        return 1
                    else:
                        self.parsed_operands.append(instruction_bytes[byte_pos:byte_pos+4])
                    byte_pos += 4
                    continue
                elif b in ['cw', 'iw']: # imm16
                    if byte_pos + 2 > len(instruction_bytes):
                        return 1
                    else:
                        self.parsed_operands.append(instruction_bytes[byte_pos:byte_pos+2])
                    byte_pos += 2
                    continue
                elif b in  ['cb', 'ib']: # imm8
                    self.parsed_operands.append(instruction_bytes[byte_pos:byte_pos+1])
                    byte_pos += 1
                    continue
                else:
                    raise Exception(f"Operand {b} not implemented!")
            elif type(b) is tuple:
                if instruction_bytes[byte_pos] not in b:
                    return 0
            else:
                if b != instruction_bytes[byte_pos]:
                    return 0
            byte_pos += 1
        # If we parse successfull 
        if byte_pos == len(instruction_bytes):
            self.instruction_bytes = instruction_bytes[:]
            if self.mnemonic.startswith("J") and type(self.parsed_operands[-1]) is bytes:
                self.jump_offset = int.from_bytes(self.parsed_operands[-1], signed=True) + len(instruction_bytes)
            elif self.mnemonic == "CALL" and type(self.parsed_operands[-1]) is bytes:
                self.call_offset = int.from_bytes(self.parsed_operands[-1][::-1], signed=True)
            return 2
        else:
            return 1
    
    def format(self, instruction_bytes, address):
        try:
            instruction_str = f"{instruction_bytes.hex().upper()} {self.mnemonic.lower()} "
            operand_count = 0
            if self.opcode_encoding_with_register:
                # Sometimes these instructions have prefixes like 0FC8+rd for BSWAP, so we have to loop through all
                # opcodes and append.
                for i, o in enumerate(self.opcode):
                    if type(o) is tuple:
                        index = o.index(instruction_bytes[i])
                        instruction_str += _REGISTERS[index].lower()
                        operand_count += 1
            for operand in self.parsed_operands:
                if type(operand) is ModRM:
                    operand_str = ""
                    if '[--][--]' in operand.effective_address:
                        if operand.sib_entry["Base"] == '5': # 101
                            if operand.mod == 0:
                                operand_str =  f"[{operand.sib_entry['Scaled Index'][1:-1].lower()}+disp32],{operand.reg}"
                            elif operand.mod == 1:
                                operand_str = f"[{operand.sib_entry['Scaled Index'][1:-1].lower()}+disp8+ebp],{operand.reg}"
                            elif operand.mod == 2:
                                operand_str = f"[{operand.sib_entry['Scaled Index'][1:-1].lower()}+disp32+ebp],{operand.reg}"
                            else:
                                raise ValueError("There is no legal SIB state with mod bits set to 11.")
                    elif (self.operands[0] and
                        self.operands[1] and
                        "ModRM" in self.operands[0] and
                        "imm" in self.operands[1]):
                        operand_str = operand.effective_address
                    elif(self.operands[0] and "ModRM:reg" in self.operands[0]):
                        if "+disp" in operand.effective_address:
                            operand_str = f"{operand.reg},[{operand.effective_address[1:4]}{operand.effective_address[5:]}]"
                        else:
                            operand_str = f"{operand.reg},{operand.effective_address}"
                    else:
                        if "+disp" in operand.effective_address:
                            operand_str = f"[{operand.effective_address[1:4]}{operand.effective_address[5:]}],{operand.reg}"
                        else:
                            operand_str = f"{operand.effective_address},{operand.reg}"

                    if self.mnemonic == "PUSH":
                        operand_str = operand_str.split(",")[0]
                    if len(instruction_bytes) > 4:
                        operand_str = operand_str.replace("disp32", _bytes_to_signed_hex_string(instruction_bytes[-4:][::-1]))
                    if len(instruction_bytes) > 1:
                        operand_str = operand_str.replace("disp8", _bytes_to_signed_hex_string(instruction_bytes[-1]))
                    instruction_str += f"{operand_str}"
                elif type(operand) is bytes:
                    if self.mnemonic.startswith("J"):
                        # Sepcial handling for jumps
                        jump_addr = '%08x' % (self.jump_offset + address)
                        encoded_operand = f"offset_{jump_addr}h"
                    elif self.mnemonic == "CALL":
                        call_addr = '%08x' % (self.call_offset + len(instruction_bytes) + address)
                        encoded_operand = f"func_{call_addr}"
                    else:
                        encoded_operand = f"0x{operand[::-1].hex().lower()}"
                    instruction_str += encoded_operand if operand_count == 0 else f",{encoded_operand}"
                operand_count += 1
            instruction_str = instruction_str[:-1] if instruction_str.endswith(",") else instruction_str
            return instruction_str.strip()
        except:
            raise Exception(f"This failed: {instruction_bytes.hex()}")
    
    def __repr__(self):
        return f"{self.mnemonic} {self.operands}"
    
    def __str__(self):
        return f"{self.mnemonic} {self.operands}"

    def __init__(self, *arg, **kwargs):
        self.prefix = None
        self.opcode = None
        self.operands = None
        self.has_immediate = False
        self.opcode_encoding_with_register = False
        self.jump_offset = 0
        self.call_offset = 0
        self.instruction_bytes = None
        self.mnemonic = None
        self.parsed_operands = None
        self.description = None
        self.no_prefixes = False
        self.sib = None
        self.displacement = None
        for k, v in kwargs.items():
            setattr(self, k, v)

if __name__ == "__main__":
    print(_INSTRUCTION_TABLE)
