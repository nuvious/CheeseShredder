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
    
    def next_instruction(self, program_bytes, max_unparsed_bytes=20):
        """Attempts to parse the next instruction. If it can't, it pops 1 byte off the top of the bytes and returns None 
        for the parsed instruction.

        Args:
            program_bytes (bytes): Bytes left to parse.

        Returns:
            tuple of bytes, bytes, cheeseshredder.base.Instruction or None:
                Returns the un-parsed bytes, parsed bytes, and the Instruction parsed. The Instruction will be None if
                the bytes were not parsable.
        """
        byte_count = 1
        possible_instructions = {}
        partial_instructions = {}
        for k, i in self.get_instruction_table().items():
            result = i.is_valid(program_bytes[:byte_count])
            if result != 0:
                possible_instructions[k] = i
            if result == 1:
                partial_instructions[k] = i
        last_instruction_set = {}
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
            last_instruction_set = copy.deepcopy(possible_instructions)
            possible_instructions = {}
            for k, i in last_instruction_set.items():
                result = i.is_valid(program_bytes[:byte_count])
                if result != 0:
                    possible_instructions[k] = i
                if result == 1:
                    partial_instructions[k] = i
        if len(possible_instructions) == 1 and len(partial_instructions) == 0:
            logging.debug("%s %s", program_bytes[:byte_count].hex(), list(possible_instructions.values())[0])
            return (
                program_bytes[byte_count:],
                program_bytes[:byte_count],
                copy.deepcopy(list(possible_instructions.values())[0])
            )
        else:
            if len(last_instruction_set) > 1:
                # In some cases instructions are synonymous such as JE and JZ. Check to see if the descriptions match.
                desc = None
                for k, i in last_instruction_set.items():
                    if desc is None:
                        desc = i.description
                    elif desc != i.description:
                        
                        return program_bytes[1:], program_bytes[:1], None
                return (
                    program_bytes[byte_count:],
                    program_bytes[:byte_count],
                    copy.deepcopy(list(last_instruction_set.values())[0])
                )
            else:
                # raise Exception(f"Unparsed instrution with bytes {program_bytes[:byte_count]}")
                return program_bytes[1:], program_bytes[:1], None
    
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
