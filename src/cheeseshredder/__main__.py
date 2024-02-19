import argparse
import logging

import cheeseshredder.format
import cheeseshredder.arch.x86_64

_LOG_LEVEL_NAMES_MAPPING = {
    'CRITICAL': 50,
    'FATAL': 50,
    'ERROR': 40,
    'WARN': 30,
    'WARNING': 30,
    'INFO': 20,
    'DEBUG': 10,
    'NOTSET': 0
}

def _main(args):
    # Set Log Level
    # level = logging.getLevelNamesMapping().get(args.log_level.upper()) # 3.11 only
    level = _LOG_LEVEL_NAMES_MAPPING.get(args.log_level.upper())
    if level:
        logging.basicConfig(level=level)
    else:
        # names = list(logging.getLevelNamesMapping().keys()) # 3.11 only
        names = list(_LOG_LEVEL_NAMES_MAPPING.keys()) # 3.11 only
        print(f"Loglevel name {args.log_level} not allowed. Allowed log levels are {', '.join(names[:-1])}, and {names[-1]}.")
        exit(1)
    
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(args.input, 'rb') as f:
        _, _, in_order_parse = disassembler.disassemble(f.read(), progress=args.progress)
        for instruction_str in cheeseshredder.format.LabeledFormatter().print_instructions(in_order_parse):
            print(instruction_str)

def main():
    parser = argparse.ArgumentParser(
                    prog='CheeseShredder',
                    description='Th',
                    epilog='Text at the bottom of help')
    parser.add_argument(
        '-i', '--input', help="Input file to disassemble.", required=True
    )
    parser.add_argument(
        '-p', '--progress', help="Show progress bar (requires tqdm).", default=False, action='store_true'
    )
    parser.add_argument(
        '-l', '--log-level', help="Set log level.", default="INFO"
    )
    parser.add_arguments(
        '-f', '--label-functions',help="Label function locations and calls with func_%08X.",
        default=False, action='store_true'
    )
    parser.add_argument(
        '-o', '--output', help="Output to a file. If not set output will print to stdout.", default=None
    )
    # parser.add_argument('-a', '--arch') # Reserved for multi-arch feature
    _main(parser.parse_args())
