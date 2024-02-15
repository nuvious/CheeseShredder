import argparse
import logging
import sys

import cheeseshredder.format
import cheeseshredder.arch.x86_64

def main():
    parser = argparse.ArgumentParser(
                    prog='CheeseShredder',
                    description='Th',
                    epilog='Text at the bottom of help')
    parser.add_argument('-i', '--input', required=True)
    parser.add_argument('-o', '--output', default=None)
    # parser.add_argument('-a', '--arch') # Reserved for multi-arch feature
    parser.add_argument('-v', '--verbose', action='store_false')
    parser.add_argument('-l', '--log-level', default="INFO")
    args = parser.parse_args()  
    
    # Set Log Level
    level = logging.getLevelNamesMapping().get(args.log_level.upper())
    if level:
        logging.basicConfig(level=level)
    else:
        names = list(logging.getLevelNamesMapping().keys())
        print(f"Loglevel name {args.log_level} not allowed. Allowed log levels are {', '.join(names[:-1])}, and {names[-1]}.")
        exit(1)
    
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(args.input, 'rb') as f:
        _, _, in_order_parse = disassembler.disassemble(f.read())
        for instruction_str in cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse):
            print(instruction_str)
