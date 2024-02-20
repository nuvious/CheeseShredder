import re
import csv
import sys
import logging
import pkg_resources

import cheeseshredder
from ...base import Instruction, Disassembler

_log = logging.getLogger(__name__)

_JHU_REQUIRED_MNEMONICS = ["ADD", "JMP", "POP", "AND", "JZ", "JNZ", "PUSH", "CALL", "LEA", "REPNE CMPSD", "CLFLUSH",
                           "MOV", "RETF", "CMP", "MOVSD", "RETN", "DEC", "NOP", "SUB", "IDIV", "NOT", "TEST", "INC",
                           "OR", "XOR"]
_REGISTERS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
_UNIMPLEMENTED_OPERANDS = ["REX.W", "REX", "VEX"]
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
    "r16", "r64", "r/m16", "r/m64", "m64", "xmm", "ymm", "ST(i)", "ST(0)",
    "rel16", " AX,", " AL,", ",AX", ",AL", "m2byte", "m16int", "m32int",
    "m64int", "m14/28byte", "m94/108byte", "m32fp", "m64fp", "STAC"]


def _contains_invalid_instruction_tokens(inst_str):
    """Filters for instructions by keyword that are not supported

    Args:
        inst_str (str): The instruction string; ex 'MOV /r'

    Returns:
        bool: True if any unsupported keywords exist in the instruction.
    """
    return any([i in inst_str for i in _UNIMPLEMENTED_INSTRUCTION_TOKENS])


def _contains_unimplemented_operands(inst_str):
    """Filters for operands by keyword that are not supported

    Args:
        inst_str (str): The instruction string; ex 'MOV /r'

    Returns:
        bool: True if any unsupported keywords exist in the operands
    """
    return any([i in inst_str for i in _UNIMPLEMENTED_OPERANDS])


def _try_parse_opcode_hex(raw_str):
    """Tries to parse an operand string which, normally hex, may include suffixes such as +rd, cw, etc.

    Args:
        raw_str (str): A hex string

    Returns:
        int, tuple of bytes or str:
            The parsed bytes and additional opcodes as a tuple or the string if it could not be parsed from hex.
            ex: _try_parse_opcode_hex('cw') -> 'cw'
            ex: _try_parse_opcode_hex('50+rd') -> (50,51,52,53,54,55,56,57)
            ex: _try_parse_opcode_hex('A7') -> 167
    """
    if raw_str in ['cb', 'cd']:  # Edge case for cb/cd operand. All hex should be upper case
        return raw_str
    try:
        try:
            return int.from_bytes(bytes.fromhex(raw_str), byteorder='big')
        except Exception:
            opcodes = []
            if (raw_str.endswith("+rd") or
                raw_str.endswith("+rw") or
                raw_str.endswith("+rb")):
                opcode = int(raw_str[:2], 16)
                for i, _ in enumerate(_REGISTERS):
                    opcodes.append(opcode + i)
                return tuple(opcodes)
            else:
                return raw_str
    except Exception as e:
        _log.error("Error attempting to parse %s", raw_str, stack_info=True, exc_info=sys.exc_info())
        if cheeseshredder.DEBUG:
            raise e
        else:
            return f"[FAILED HEX PARSE OF {raw_str}]"


def _bytes_to_signed_hex_string(val):
    """Converts a byte string into a 2's compliment bytestring based on the sign.

    Args:
        val (bytes): A byte string in big-endian format

    Returns:
        str:
            A hex bytestring representing the number or it's 2's complement if it's negative.
    """
    if type(val) is bytes:
        val = int.from_bytes(val, signed=True, byteorder='big')
        return "0x%08x" % (2**32 + val if val < 0 else val)
    else:  # Single byte
        val = val if val < 128 else val - 256
        return "0x%08x" % (2**32 + val if val < 0 else val)


class ModRM:
    """A class which holds metadata for a parsed modrm byte
    """
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


def get_sib_table():
    """Gets the SIB mapping table if it hasn't yet been read and assigns it to _SIB_TABLE and returns it.

    Returns:
        dict: Dictionary of bytes->list of str
    """
    global _SIB_TABLE
    if not _SIB_TABLE:
        _SIB_TABLE = {}

        sib_table_file = pkg_resources.resource_filename("cheeseshredder.arch.x86_64.data", _SIB_TABLE_CSV_FNAME)
        with open(sib_table_file, "r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _SIB_TABLE[bytes.fromhex(row["SIB"])[0]] = row
    return _SIB_TABLE


def get_modrm_mapping():
    """Gets the modrm mapping table if it hasn't yet been read and assigns it to _MODRM_TABLE and returns it.

    Returns:
        dict: Dictionary of str->dict of byte->ModRM object. First 2 valid keys are "16" or "32" only.
    """
    global _MODRM_TABLE
    if not _MODRM_TABLE:
        _MODRM_TABLE = {
            "32": {},
            "16": {}
        }
        modrm_table_file = pkg_resources.resource_filename("cheeseshredder.arch.x86_64.data", _MODRM_32_TABLE_CSV_FNAME)
        with open(modrm_table_file, "r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _MODRM_TABLE["32"][bytes.fromhex(row["ModR/M"])[0]] = ModRM(**row)
        modrm_table_file = pkg_resources.resource_filename("cheeseshredder.arch.x86_64.data", _MODRM_16_TABLE_CSV_FNAME)
        with open(modrm_table_file, "r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _MODRM_TABLE["16"][bytes.fromhex(row["ModR/M"])[0]] = ModRM(**row)
    return _MODRM_TABLE


def get_instruction_table():
    """Gets the instruction table if it hasn't yet been read and assigns it to _INSTRUCTION_TABLE and returns it.

    Returns:
        dict: Dictionary of tuple(opcode, operands)->Instruction object
    """
    global _INSTRUCTION_TABLE
    if not _INSTRUCTION_TABLE:
        _INSTRUCTION_TABLE = {}
        instruction_table_file = pkg_resources.resource_filename(
            "cheeseshredder.arch.x86_64.data", _X86_64_INSTRUCTION_TABLE_CSV_FNAME)
        with open(instruction_table_file, "r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                instruction = X86_64Instruction.instruction_from_row(row)
                if (_contains_invalid_instruction_tokens(row["Instruction"]) or
                    _contains_unimplemented_operands(row["Opcode"]) or
                    row["Valid 32-bit"] == "Invalid" or
                    instruction.mnemonic not in _JHU_REQUIRED_MNEMONICS):
                    continue
                _INSTRUCTION_TABLE[(instruction.opcode, instruction.operands)] = instruction
    return _INSTRUCTION_TABLE


def get_prefix_table():
    """Gets the prefix table if it hasn't yet been read and assigns it to _PREFIXES and returns it.

    Returns:
        list of byte
    """
    global _PREFIXES
    if not _PREFIXES:
        _PREFIXES = []
        prefix_file = pkg_resources.resource_filename("cheeseshredder.arch.x86_64.data", _PREFIXES_CSV_FNAME)
        with open(prefix_file, "r", encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                _PREFIXES.append(bytes.fromhex(row["HEX"])[0])
    return _PREFIXES


class X86_64Disassembler(Disassembler):
    """X86_64 disassembler class.
    """
    def __init__(self) -> None:
        super().__init__()
        get_sib_table()
        get_modrm_mapping()
        get_instruction_table()
        get_prefix_table()

    def get_instruction_table(self):
        return _INSTRUCTION_TABLE


class X86_64Instruction(Instruction):
    """X86_64 instruction class.
    """
    def instruction_from_row(row):
        """Takes a row from the instruction table and instantiates an Instruction object.

        Args:
            row (dict): Row of data from the instruction table indexed by column headers.

        Returns:
            cheeseshredder.arch.x86_64.X86_64Instruction: The parsed instruction
        """
        # Get the opcode
        opcodes = tuple([
            _try_parse_opcode_hex(token)
            for token in row["Opcode"].split(" ")
            if token != '+'
        ])
        opcode_encoding_with_register = any([type(opcode) is tuple for opcode in opcodes])
        has_immediate = any([opcode in ['id', 'iw', 'ib', 'cw', 'cb', 'ci'] for opcode in opcodes])
        no_prefixes = False
        if opcodes[0] == "NP":
            no_prefixes = True
            opcodes = tuple(opcodes[1:])
        operands = tuple([
            row["Operand 1"] if row["Operand 1"] != "NA" else None,
            row["Operand 2"] if row["Operand 2"] != "NA" else None,
            row["Operand 3"] if row["Operand 3"] != "NA" else None,
            row["Operand 4"] if row["Operand 4"] != "NA" else None
        ])
        kwargs = {
            # One edge case where we have 2 words in a mnemonic
            "mnemonic": "REPNE CMPSD" if row["Instruction"] == "REPNE CMPSD" else row["Instruction"].split(" ")[0],
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
                return 1  # If we've gotten this far, we have a partial match
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
                            if (sib_entry['r32'].startswith('A disp32 with') and
                                'disp' not in mod_rm_entry.effective_address):
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
                elif b in ['cd', 'id']:  # imm32
                    if byte_pos + 4 > len(instruction_bytes):
                        return 1
                    else:
                        self.parsed_operands.append(instruction_bytes[byte_pos:byte_pos + 4])
                    byte_pos += 4
                    continue
                elif b in ['cw', 'iw']:  # imm16
                    if byte_pos + 2 > len(instruction_bytes):
                        return 1
                    else:
                        self.parsed_operands.append(instruction_bytes[byte_pos:byte_pos + 2])
                    byte_pos += 2
                    continue
                elif b in ['cb', 'ib']:  # imm8
                    self.parsed_operands.append(instruction_bytes[byte_pos:byte_pos + 1])
                    byte_pos += 1
                    continue
                else:
                    raise Exception(f"Operand {b} not implemented! {instruction_bytes}\n{self}")
            elif type(b) is tuple:
                if instruction_bytes[byte_pos] not in b:
                    return 0
            else:
                if b != instruction_bytes[byte_pos]:
                    return 0
            byte_pos += 1
        # If we parse successful
        if byte_pos == len(instruction_bytes):
            self.instruction_bytes = instruction_bytes[:]
            if self.mnemonic.startswith("J") and type(self.parsed_operands[-1]) is bytes:
                self.jump_offset = (int.from_bytes(self.parsed_operands[-1], signed=True, byteorder="big") +
                                    len(instruction_bytes))
            elif self.mnemonic == "CALL" and type(self.parsed_operands[-1]) is bytes:
                self.call_offset = int.from_bytes(self.parsed_operands[-1][::-1], signed=True, byteorder="big")
            _log.debug("%s bytes match instruction %s", instruction_bytes, self)
            return 2
        else:
            return 1

    def sub_disp(self, instruction_bytes, operand_str, byte_offset):
        """Substitutes disp8 and disp32 values in instruction string templates with the appropriate parsed bytes from
        the instruction.

        Args:
            instruction_bytes (bytes): The bytes for the instruction
            operand_str (str): The operand string template
            byte_offset (int): The current byte offset provided by the caller

        Returns:
            str: The operand with disp8 and disp32 appropriately substituted.
        """
        # If it's just a disp32 or disp8 it's a pointer, so wrap in brackets and return it. It will get replaced by
        # other logic
        if operand_str in ["disp32", "disp8"]:
            operand_str = f"[{operand_str}]"

        # Find all occurrences of disp8/disp32
        disp_pattern = r'\b(disp(?:8|32))\b'
        disp_str_matches = re.findall(disp_pattern, operand_str)

        # Break the operand up into components around the disp8/disp32 occurrences
        operand_str_components = re.split(r'disp(?:8|32)', operand_str)

        # Go through the disp occurrences in reverse order (easier to slice the bytes backwards)
        disp_count = 0
        ret_oper_str = [operand_str_components[0]]
        for disp_str in disp_str_matches[::-1]:
            # Insert 4 bytes from the end of the unparsed portion of the instruction
            if disp_str == 'disp32':
                ret_oper_str.append(
                    _bytes_to_signed_hex_string(
                        instruction_bytes[
                            len(instruction_bytes) - 4 - byte_offset:len(instruction_bytes) - byte_offset][::-1]))
                # Increment the byte offset by 4/disp count by 1
                byte_offset += 4
                disp_count += 1
                # Concat the next operand component (if possible)
                if disp_count < len(operand_str_components) - 1:
                    ret_oper_str.append(operand_str_components[disp_count])
            elif disp_str == 'disp8':
                # Insert 1 byte from the end of the unparsed portion of the instruction
                ret_oper_str.append(
                    _bytes_to_signed_hex_string(
                        instruction_bytes[
                            len(instruction_bytes) - 1 - byte_offset:len(instruction_bytes) - byte_offset][::-1]))
                # Increment the byte offset
                byte_offset += 1
                disp_count += 1
                # Concat the next operand component (if possible)
                if disp_count < len(operand_str_components) - 1:
                    ret_oper_str.append(operand_str_components[disp_count])
        # Concat any trailing operand components and return the formatted string
        if disp_count < len(operand_str_components):
            ret_oper_str.append(operand_str_components[disp_count])
        return byte_offset, "".join(ret_oper_str)

    def format(self, instruction_bytes, address, label_jumps=True, label_functions=False):
        """Formats an instruction given an address and instruction bytes.

        Args:
            instruction_bytes (bytes): The bytes for the instruction
            address (int): Address in memory for the instruction (needed for formatting JZ/JE/JNE/JNZ/CALL instructions)
            label_jumps (bool, optional): Whether to labels jumps in 'offset_XXXXXXXXXh' format. Defaults to True.
            label_functions (bool, optional): Whether to label calls in 'func_XXXXXXXX' format. Defaults to False.

        Raises:
            ValueError: Raised when an SIB byte is parsed with an illegal state.

        Returns:
            str: The formatted instruction. Ex:
                    i = ...JMP instruction
                    str = i.format(b'\xE9\x4C\x00\x00\x00', 4)
                    print(str)
                    E94C000000 jmp 0x55
        """
        try:
            # Setup the initial instruction template:
            instruction_str = f"{instruction_bytes.hex().upper()} {self.mnemonic.lower()} "

            # If the opcode is encoded with registers (ex: PUSH/50+rd), loop through and find which one matches so we
            # append the correct register
            operand_count = 0
            if self.opcode_encoding_with_register:
                # Sometimes these instructions have prefixes like 0FC8+rd for BSWAP, so we have to loop through all
                # opcodes and append.
                for i, o in enumerate(self.opcode):
                    if type(o) is tuple:
                        index = o.index(instruction_bytes[i])
                        instruction_str += _REGISTERS[index].lower()
                        operand_count += 1

            # Loop through and append formatted parsed operands
            disp_byte_offset = 0
            formatted_operands = []
            for operand in self.parsed_operands[::-1]:
                # If the operand is a modrm byte:
                if type(operand) is ModRM:
                    # Handle SIB bytes if needed
                    operand_str = ""
                    if '[--][--]' in operand.effective_address:
                        if operand.sib_entry["Base"] == '5':  # 101
                            if operand.mod == 0:
                                operand_str = (f"[{operand.sib_entry['Scaled Index'][1:-1].lower()}+disp32],"
                                               f"{operand.reg}")
                            elif operand.mod == 1:
                                operand_str = (f"[{operand.sib_entry['Scaled Index'][1:-1].lower()}+disp8+ebp],"
                                               f"{operand.reg}")
                            elif operand.mod == 2:
                                operand_str = (f"[{operand.sib_entry['Scaled Index'][1:-1].lower()}+disp32+ebp],"
                                               f"{operand.reg}")
                            else:
                                _log.error(
                                    "Illegal SIB state with mod bits set to 11 when parsing %s as an %s instruction.",
                                    instruction_bytes.hex(), self)
                                if cheeseshredder.DEBUG:
                                    raise ValueError("Illegal SIB state with mod bits set to 11.")
                                else:
                                    operand_str = (f"[{operand.sib_entry['Scaled Index'][1:-1].lower()}+disp32+ebp],"
                                                   f"{operand.reg}")
                        else:
                            operand_str = (
                                f"[{operand.sib_entry['r32'].lower()}+{operand.sib_entry['Scaled Index'][1:-1].lower()}"
                                f"{operand.effective_address[8:]}],{operand.reg}")
                    # If the second operand is an immediate, check if you need to reformat it
                    elif (self.operands[0] and
                          self.operands[1] and
                          "ModRM" in self.operands[0] and
                          "imm" in self.operands[1]):
                        # If it's in the format similar to '[eax]+disp32'...
                        if bool(re.search(r'\[[a-z]{3}\]\+disp\d+', operand.effective_address)):  # ex
                            # ...reformat it to the format '[eax+disp32]' or similar
                            operand_str = re.sub(r'\[([a-z]{3})\](\+disp\d+)', r'[\1\2]', operand.effective_address)
                        else:
                            # Otherwise do not modify the format
                            operand_str = operand.effective_address
                    # If the first operand is a reg operand
                    elif (self.operands[0] and "ModRM:reg" in self.operands[0]):
                        # If it includes disp8/disp32 reformat similar to eax,[ecx+disp32]
                        if "+disp" in operand.effective_address:
                            operand_str = (
                                f"{operand.reg},[{operand.effective_address[1:4]}"
                                f"{operand.effective_address[5:]}]")
                        # Otherwise just reformat it to standard eax,ecx syntax
                        else:
                            operand_str = f"{operand.reg},{operand.effective_address}"
                    # If the operand is disp8 or disp32 by itself, wrap in [] since it's representing a pointer
                    elif (operand in ["disp8", "disp32"]):
                        operand_str = f"[{operand}]"
                    else:
                        # If a disp exists in the effective address reformat similar to:
                        # [eax+disp32],ecx
                        if "+disp" in operand.effective_address:
                            operand_str = (
                                f"[{operand.effective_address[1:4]}"
                                f"{operand.effective_address[5:]}],"
                                f"{operand.reg}")
                        else:
                            # Otherwise just reformat it to standard eax,ecx syntax
                            operand_str = f"{operand.effective_address},{operand.reg}"

                    # Special case for push and pop; they only care about 1 operand even when they have a /r argument
                    if self.mnemonic in ["PUSH", "POP"]:  # Edge case, only one operand in a push/pop
                        operand_str = operand_str.split(",")[0]

                    # Replace disp8/disp32 accordingly and keep track of the byte offset for parsing further operands
                    if "disp" in operand_str:
                        disp_byte_offset, operand_str = self.sub_disp(instruction_bytes, operand_str, disp_byte_offset)

                    # Check for edge cases where addressing mode 11 isn't allowed
                    if operand.mod == 3 and self.mnemonic in ["LEA", "CLFLUSH"]:
                        formatted_operands = ["(bad)"]
                        break

                    formatted_operands = [f"{operand_str}"] + formatted_operands
                # If the operand is a bytestring
                elif type(operand) is bytes:
                    # Special formatting for jumps
                    if self.mnemonic in ["JZ", "JE", "JNZ", "JNE", "JMP"]:
                        encoded_operand = '%08x' % (self.jump_offset + address)
                        if label_jumps:
                            encoded_operand = f"offset_{encoded_operand}h"
                    # Special formatting for calls
                    elif self.mnemonic == "CALL":
                        if label_functions:
                            encoded_operand = 'func_%08x' % (self.call_offset + len(instruction_bytes) + address)
                        else:
                            encoded_operand = '0x%08x' % (self.call_offset + len(instruction_bytes) + address)
                    # Everything else, just encode in lowercase hex
                    else:
                        encoded_operand = f"0x{operand[::-1].hex().lower()}"
                        disp_byte_offset += len(operand)
                    formatted_operands = ([encoded_operand
                                           if operand_count == 0
                                           else f",{encoded_operand}"] + formatted_operands)
                operand_count += 1

            # Combine/append the formatted operands
            instruction_str += ",".join(formatted_operands)
            # Replace any +0x00000000 values with an empty string for better readability
            instruction_str = instruction_str.replace("+0x00000000", "")
            return instruction_str.strip()
        except Exception as e:
            _log.error(
                f"Instruction bytes failed in parsing: {instruction_bytes.hex()}",
                exec_info=sys.exc_info(), stack_info=True)
            if cheeseshredder.DEBUG:
                raise e
            else:
                return f"{instruction_bytes.hex().upper()}"

    def __repr__(self):
        return self.__str__()

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
