import warnings

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
    def next_instruction(self, program_bytes):
        """Attempts to parse the next instruction. If it can't, it pops 1 byte off the top of the bytes and returns None 
        for the parsed instruction.

        Args:
            program_bytes (bytes): Bytes left to parse.

        Returns:
            tuple of bytes, bytes, cheeseshredder.base.Instruction or None:
                Returns the un-parsed bytes, parsed bytes, and the Instruction parsed. The Instruction will be None if
                the bytes were not parsable.
        """
        warnings.warn("You are using the base class for Disassembler. This is a dummy class that does no parsing.")
        return program_bytes[1:], program_bytes[:1], None
    
    def disassemble(self, program_bytes, *args, **kwargs):
        instructions = []
        unparsed_bytes = []
        address = 0x00
        while len(program_bytes):
            address_hex = "%08X" % address
            program_bytes, parsed_bytes, instruction = self.next_instruction(program_bytes)
            if instruction:
                instructions.append((address_hex,instruction,parsed_bytes))
            else:
                unparsed_bytes.append((address_hex, parsed_bytes.hex()))
            address += len(parsed_bytes)
        return instructions, unparsed_bytes
