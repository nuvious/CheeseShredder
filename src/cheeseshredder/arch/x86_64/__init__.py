import csv
from importlib import resources

from . import data
from ...base import Instruction

_MODRM_32_TABLE_CSV_FNAME = "ModRMTable32.csv"
_MODRM_16_TABLE_CSV_FNAME = "ModRMTable16.csv"
MODRM_TABLE = None
_SIB_TABLE_CSV_FNAME = "SIBTable.csv"
SIB_TABLE = None
_PREFIXES_CSV_FNAME = "Prefixes.csv"
PREFIXES = None

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

class X86_64Disassembler:
    def next_instruction(bytes):
        pass

class X86_64Instruction(Instruction):
    def __init__(self, *arg, **kwargs):
        self.prefx = None
        self.opcode = None
        self.modrm = None
        self.sib = None
        self.displacement = None
        self.immediate = None
