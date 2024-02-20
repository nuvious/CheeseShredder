class BaseFormatter:
    def print_instructions(self, instruction_meta):
        """Prints out the instructions

        Args:
            instruction_meta (list of tuple):
                list of tuple of int, bytes, Instruction

        Yields:
            str:
                A formatted instruction string
        """
        for address, instruction, instruction_bytes in instruction_meta:
            yield (f"{'%08X' % address}:"
                   f"{instruction.format(instruction_bytes, address, label_jumps=False, label_functions=False)}")


class LabeledFormatter(BaseFormatter):
    def print_instructions(self, instruction_meta, label_jumps=True, label_functions=False):
        """Prints out the instructions

        Args:
            instruction_meta (list of tuple):
                list of tuple of int, bytes, Instruction

        Yields:
            str:
                A formatted instruction string
        """
        # Find all the jumps and their associated addresses for labeling
        pending_jump_labels = [
            address + instruction.jump_offset
            for address, instruction, _
            in instruction_meta if instruction and instruction.mnemonic.startswith("J")
        ]
        # Find all the functions and their associated addresses for labeling
        pending_function_labels = [
            address + instruction.call_offset + len(instruction_bytes)
            for address, instruction, instruction_bytes
            in instruction_meta if instruction and instruction.mnemonic.startswith("CALL")
        ]
        # Loop through the instructions and output them
        for address, instruction, instruction_bytes in instruction_meta:
            prefix = ""
            if address in pending_jump_labels:
                if label_jumps:
                    prefix += f"offset_{'%08x' % address}h:\n"
                else:
                    prefix += '0x%08x' % address
            if address in pending_function_labels:
                if label_functions:
                    prefix += f"func_{'%08x' % address}:\n"
                else:
                    prefix += '0x%08x' % address
            instruction_str = (
                f'db 0x{instruction_bytes.hex()}'
                if instruction is None
                else instruction.format(
                    instruction_bytes, address, label_jumps=label_jumps, label_functions=label_functions))
            yield (prefix + f"{'%08X' % address}: {instruction_str}")
