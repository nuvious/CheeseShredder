import argparse
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
    args = parser.parse_args()  
    disassembler = cheeseshredder.arch.x86_64.X86_64Disassembler()
    with open(args.input, 'rb') as f:
        _, _, in_order_parse = disassembler.disassemble(f.read())
        for address, instruction, parsed_bytes in in_order_parse:
            print(f"{address}: {parsed_bytes.hex()}\t{instruction}")
