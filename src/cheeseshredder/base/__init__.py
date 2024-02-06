class ModelBase:
    def __str__(self):
        raise NotImplemented(f"The __str__ function is not implemented for {type(self)}.")

class Instruction(ModelBase):
    pass

class Disassember():
    def disassemble(bytes, *args, **kwargs):
        pass
