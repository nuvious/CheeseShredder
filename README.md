# Cheese Shredder

A decompiler for x86 written in python.

## Usage

```bash
pip install cheeseshredder
cheeseshredder -i my_binary
```

## Testing

### Using Docker/Conda/Tox (Recommended)

```bash
docker run --rm -it \
    -v ${PWD}:/workspace conda/miniconda3:latest \
    /bin/bash -c "pushd workspace; pip install tox-conda; tox"
```

### Locally with Pytest

```bash
git clone https://github.com/nuvious/CheeseShredder.git
cd CheeseShredder
# Setup a virtual environment if desired
pip install -e .[test,dev]
pytest
```

## References

[1] Intel, “Intel® 64 and IA-32 Architectures Software Developer’s Manual,” 2023.
    Available: https://cdrdv2.intel.com/v1/dl/getContent/671110. [Accessed: Jan. 30, 2024]

[2] G. Comer, “GregoryComer/x86-csv,” GitHub, Oct. 23, 2023.
    Available: https://github.com/GregoryComer/x86-csv. [Accessed: Feb. 19, 2024]
