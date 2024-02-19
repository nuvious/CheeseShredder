import copy
import logging
import tqdm

_log = logging.getLogger(__name__)

class ModelBase:
    def __str__(self):
        raise NotImplemented(f"The __str__ function is not implemented for {type(self)}.")

class Output:
    def process_instruction(self, instruction):
        """Base class for output.
        Defaults to printing to stdout.

        Args:
            instruction (cheeseshredder.base.Instruction):
                Instruction to output.
        """
        print(instruction)

class Instruction(ModelBase):
    pass

class Disassember():
    def get_instruction_table(self):
        return {}
    
    def next_instruction(self, program_bytes, byte_count=1, max_byte_count=20):
        possible_instructions = self.get_instruction_table()
        while True:
            partial_match = {}
            full_match = {}
            instruction_bytes = program_bytes[:byte_count]
            for k, i in possible_instructions.items():
                result = i.is_valid(instruction_bytes)
                if result == 2:
                    full_match[k] = i
                elif result == 1:
                    partial_match[k] = i
            
            if len(full_match) > 1:
                # Edge case; ex is JE and JZ have the same opcode and function
                desc = None
                for k, i in full_match.items():
                    if desc is None:
                        desc = i.description
                    elif desc != i.description:
                        # Two different instructions fully match, raise an exception and treat as a bug
                        raise Exception(f"Bytes {instruction_bytes} mapped to multiple instructions: {full_match}")
                # All should've matched by this point
                return (
                    program_bytes[byte_count:],
                    instruction_bytes,
                    copy.deepcopy(list(full_match.values())[-1])
                )
            elif byte_count >= max_byte_count and len(full_match) == 0:
                # Exit case, no instruction found
                return program_bytes[1:], program_bytes[:1], None
            elif len(full_match) == 1:
                return (
                    program_bytes[byte_count:],
                    instruction_bytes,
                    copy.deepcopy(list(full_match.values())[0])
                )

            possible_instructions = {**full_match, **partial_match}
            byte_count += 1
    
    def disassemble(self, program_bytes, *args, **kwargs):
        instructions = []
        unparsed_bytes = []
        in_order_parse = []
        address = 0x00
        initial_program_bytes = program_bytes[:]
        progress = tqdm.tqdm(total=len(program_bytes)) if kwargs.get('progress', False) else None
        while len(program_bytes):
            program_bytes, parsed_bytes, instruction = self.next_instruction(program_bytes)
            if instruction:
                instructions.append((address,instruction, parsed_bytes))
                in_order_parse.append((address,instruction, parsed_bytes))
            else:
                unparsed_bytes.append((address, parsed_bytes))
                in_order_parse.append((address, None, parsed_bytes))
            address += len(parsed_bytes)
            if progress:
                progress.update(len(parsed_bytes))
        return instructions, unparsed_bytes, in_order_parse
