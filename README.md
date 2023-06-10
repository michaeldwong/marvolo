
# Marvolo

Performs mutations on gtirb representations to diversify binaries.

## Installation

Install gtirb and capstone dependencies

    pip3 install -r requirements.txt

To disassemble binaries and emit asm from GTIRB files, please see installation isntructions for [ddisasm](https://github.com/GrammaTech/ddisasm) and [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter).

## Usage

```
python3 mutator/mutate.py -h
usage: mutate.py [-h] [--verbose] [--debug] [-e REORDER] [-q OPAQUE] [-i INLINING] [-o OUTLINING] [-r REASSIGN] [-w SWAP] [-s SUBSTITUTION]
                 [-p OPTIMIZATION] [-t TRANSPOSE] [-d DEADCODE] [-b BALANCE] [-c COVERAGE] [-n NITERS]
                 infile outfile

positional arguments:
  infile
  outfile

optional arguments:
  -h, --help            show this help message and exit
  --verbose
  --debug
  -e REORDER, --reorder REORDER
                        Function swapping
  -q OPAQUE, --opaque OPAQUE
                        Opaque predicate insertion
  -i INLINING, --inlining INLINING
                        Inline simple functions
  -o OUTLINING, --outlining OUTLINING
                        Outlines simple blocks to functions
  -r REASSIGN, --reassign REASSIGN
                        Swap a live register in a block with a new register
  -w SWAP, --swap SWAP  Swap instruction positions
  -s SUBSTITUTION, --substitution SUBSTITUTION
                        Obfuscating instruction substitutions
  -p OPTIMIZATION, --optimization OPTIMIZATION
                        Optimizing instruction substitutions
  -t TRANSPOSE, --transpose TRANSPOSE
                        Partition code into multiple blocks and rearrange them
  -d DEADCODE, --deadcode DEADCODE
                        Inserts dead code blocks
  -b BALANCE, --balance BALANCE
                        Obfuscation vs benign (0 sets obfuscation probabilities to 1 and benign probabilities to 0, 1 sets obfuscation
                        probabilities to 0 and benign probabilities to 1)
  -c COVERAGE, --coverage COVERAGE
                        Indicates how aggressively the binary will be modified
  -n NITERS, --niters NITERS
                        How many transformations will be run. Does not include inline/outline passes
```

infile is the input GTIRB file and outfile is the output name of the modified GTIRB file. 
Each optional argument is a probability (i.e., a float in [0.0, 1.0]) that determines the chances of the corresponding transformation being executed.


## Example

Convert ELF to gtirb representation and perform mutations on it:

    ddisasm sample-binaries/ELF/ex1 --ir ex1.gtirb
    ./mutator/mutate.py ex1.gtirb out.gtirb
    gtirb-pprinter -a out.s -b out out.gtirb

## Test

Run all tests:
        
    python3 -m unittest 

Run ELF tests:

    python3 tests/test_elf.py

Run PE32 tests (requires uasm; see [uasm setup](https://gist.github.com/kwarrick/d2b4b744a31c021c11711f4519db5e71)):

    python3 tests/test_pe32.py

Run PE64 tests (assembler setup needs to be updated before use):

    python3 tests/test_pe64.py


