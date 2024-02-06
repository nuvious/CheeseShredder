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
    print(cheeseshredder.arch.x86_64.get_sib_table())