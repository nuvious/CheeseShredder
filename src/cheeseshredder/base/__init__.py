import copy
import logging
import tqdm

import cheeseshredder

_log = logging.getLogger(__name__)


class ModelBase:
    """Base model that enforces explicit definition of __str__ method
    """
    def __str__(self):
        raise NotImplementedError(f"The __str__ function is not implemented for {type(self)}.")


class Instruction(ModelBase):
    """Placeholder base class for Instructions to iterate on later
    """
    pass


class Disassember():
    """Base disassembler class
    """
    def get_instruction_table(self):
        """Gets the instruction table. Abstracted for implementation of other architectures

        Returns:
            dict: Dictionary of tuple(opcode,operands)->Instruction object
        """
        return {}

    def next_instruction(self, program_bytes, byte_count=1, max_byte_count=20):
        """Parses the next instruction from the provided bytes or returns None and decrements the program stack by 1
        byte.

        Args:
            program_bytes (bytes): The raw bytes of the program
            byte_count (int, optional): The starting size of the instruction to parse. Defaults to 1.
            max_byte_count (int, optional):
                The maximum size of the instruction before considering it unparsed. Defaults to 20.

        Raises:
            ValueError: Error raised if multiple instructions map to the same bytestring

        Returns:
            tuple: program_bytes_left_to_parse, parsed_bytes, Instruction or None
        """
        # Start out with all instructions
        possible_instructions = self.get_instruction_table()
        while True:
            # Keep track of partial and full matches
            partial_match = {}
            full_match = {}
            
            # Slice off the instruction bytes we're trying to parse
            instruction_bytes = program_bytes[:byte_count]
            # Check if instructions are partial or full matches
            for k, i in possible_instructions.items():
                result = i.is_valid(instruction_bytes)
                if result == 2:
                    full_match[k] = i
                elif result == 1:
                    partial_match[k] = i

            # If there's more than 1 full match, check some edge cases or log an error if multiple iunstructions map
            # to the same bytes
            if len(full_match) > 1:
                # Edge case; ex is JE and JZ have the same opcode and function
                desc = None
                for k, i in full_match.items():
                    if desc is None:
                        desc = i.description
                    elif desc != i.description:
                        _log.error("Bytes %s mapped to multiple instructions: %s", instruction_bytes.hex(), full_match)
                        if cheeseshredder.DEBUG:
                            # Two different instructions fully match, raise an exception and treat as a bug
                            raise ValueError(f"Bytes {instruction_bytes} mapped to multiple instructions: {full_match}")
                # All should've matched by this point
                return (
                    program_bytes[byte_count:],
                    instruction_bytes,
                    copy.deepcopy(list(full_match.values())[-1])
                )
            # If we've exausted the possible instruction length and still haven't found a match, assume the first byte
            # is unparsable and move on
            elif byte_count >= max_byte_count and len(full_match) == 0:
                # Exit case, no instruction found
                return program_bytes[1:], program_bytes[:1], None
            # If there's exactly one full match, return it.
            elif len(full_match) == 1:
                return (
                    program_bytes[byte_count:],
                    instruction_bytes,
                    copy.deepcopy(list(full_match.values())[0])
                )

            # No matches yet, so take the partial instructions and loop through those adding another byte to parse
            possible_instructions = {**full_match, **partial_match}
            byte_count += 1

    def disassemble(self, program_bytes, *_, **kwargs):
        """Base disassembly fuction.

        Args:
            program_bytes (bytes): The raw bytes of the program to disassemble.

        Returns:
            tuple: list of Instruction, list of unparsed instructions, and in-order list of both
        """
        instructions = []
        unparsed_bytes = []
        in_order_parse = []
        address = 0x00
        progress = tqdm.tqdm(total=len(program_bytes)) if kwargs.get('progress', False) else None
        # While there's still bytes to parse
        while len(program_bytes):
            # Get the next intstruction
            program_bytes, parsed_bytes, instruction = self.next_instruction(program_bytes)
            # Instruction successfully parsed
            if instruction:
                instructions.append((address, instruction, parsed_bytes))
                in_order_parse.append((address, instruction, parsed_bytes))
            # Instruction not parsed
            else:
                unparsed_bytes.append((address, parsed_bytes))
                in_order_parse.append((address, None, parsed_bytes))
            # Increment the address the number of bytes parsed
            address += len(parsed_bytes)
            # Update progress if applicable
            if progress:
                progress.update(len(parsed_bytes))
        return instructions, unparsed_bytes, in_order_parse
