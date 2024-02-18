class BaseFormatter:
    def print_instructions(self, instruction_meta):
        """Prints out the instructions

        Args:
            instruction_meta (list of tuple):
                list of tuple of int, bytes, Instruction
        """
        for address, instruction, instruction_bytes in instruction_meta:
            yield f"{'%08X' % address}: {instruction.format(instruction_bytes, address)}"

class LabeledFormatter(BaseFormatter):
    def print_instructions(self, instruction_meta):
        """Prints out the instructions

        Args:
            instruction_meta (list of tuple):
                list of tuple of int, bytes, Instruction
        """
        pending_labels = [
            address + instruction.jump_offset 
            for address, instruction, _ 
            in instruction_meta if instruction and instruction.mnemonic.startswith("J")
        ]
        pending_function_labels = [
            address + instruction.call_offset + len(instruction_bytes)
            for address, instruction, instruction_bytes 
            in instruction_meta if instruction and instruction.mnemonic.startswith("CALL")
        ]
        for address, instruction, instruction_bytes in instruction_meta:
            prefix = ""
            if address in pending_labels:
                prefix += f"offset_{'%08x' % address}h:\n"
            if address in pending_function_labels:
                prefix += f"func_{'%08x' % address}:\n"
            yield prefix + f"{'%08X' % address}: {f'db {instruction_bytes.hex()}' if instruction is None else instruction.format(instruction_bytes, address)}"
