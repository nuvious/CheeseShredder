import cheeseshredder.arch.x86_64

def test_load_modrm_tables():
    """Naive test to ensure the modrm table is loaded.
    """
    modrm_table = cheeseshredder.arch.x86_64.get_modrm_mapping()
    assert len(modrm_table["16"]) == 256
    assert len(modrm_table["32"]) == 256

def test_load_prefixes():
    """Naive test to ensure the modrm table is loaded.
    """
    prefixes = cheeseshredder.arch.x86_64.get_prefix_table()
    assert len(prefixes) == 18

def test_load_sib_table():
    """Naive test to ensure the modrm table is loaded.
    """
    sibs = cheeseshredder.arch.x86_64.get_sib_table()
    assert len(sibs) == 256