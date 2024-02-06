# Cheese Shredder

A decompiler for x86 written in python.

## Usage

```bash
pip install cheeseshredder
cheeseshredder -i my_binary
```

## Testing

```bash
git clone https://github.com/nuvious/CheeseShredder.git
cd CheeseShredder
# Setup a virtual environment if desired
pip install -e .[test,dev]
pytest
```
