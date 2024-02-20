import cheeseshredder.__main__
import types
import os

TEST_FILE_DIR = os.path.dirname(__file__)

def test_main():
    """
    Very baseic smoke test to ensure the main function works properly in different python versions with tox.
    """
    args = types.SimpleNamespace()
    args.input = os.path.join(TEST_FILE_DIR, 'positive/example1')
    args.log_level = "INFO"
    args.progress = False
    args.debug=False
    cheeseshredder.__main__._main(args)
