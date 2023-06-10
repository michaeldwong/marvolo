#!/usr/bin/env python3

from gtirb_rewriting import *

import argparse
import gtirb
import logging
import nop
import subprocess
import transforms

def restricted_float(x):
    """ Restricts inputs to be floats within the range [0.0, 1.0] """
    try:
        x = float(x)
    except ValueError:
        raise argparse.ArgumentTypeError('%r not a floating-point literal' % (x,))
    if x < 0.0 or x > 1.0:
        raise argparse.ArgumentTypeError('%r not in range [0.0, 1.0]' % (x,))
    return x

def coverage_int(x):
    try:
        x = int(x)
    except ValueError:
        raise argparse.ArgumentTypeError('%r not an int literal' % (x,))
    if x < 0 or x > 5:
        raise ArgumentTypeError('%r not in range [0, 5]' % (x,))
    return x

def niters_int(x):
    try:
        x = int(x)
    except ValueError:
        raise argparse.ArgumentTypeError('%r not an int literal' % (x,))
    if x < 0 or x > 12:
        raise ArgumentTypeError('%r not in range [0, 12]' % (x,))
    return x

def init_parameters(args, ir):
    if args.balance == None:
        return transforms.Parameters(
            dead_code_prob=args.deadcode,
            swap_prob=args.swap,
            substitution_prob=args.substitution,
            optimization_prob=args.optimization,
            outlining_prob=args.outlining,
            inlining_prob=args.inlining,
            reassign_prob=args.reassign,
            transpose_prob=args.transpose,
            opaque_prob=args.opaque,
            reorder_functions_prob=args.reorder,
            coverage_level=args.coverage,
            niters=args.niters,
            debug=args.debug,
            isa = ir.modules[0].isa
        )
    print('-b param set; ignoring other transformation parameters')
    benign_prob = args.balance
    obfuscation_prob = 1.0 - args.balance
    return transforms.Parameters(
        dead_code_prob=obfuscation_prob,
        swap_prob=obfuscation_prob,
        substitution_prob=obfuscation_prob,
        optimization_prob=benign_prob,
        outlining_prob=benign_prob,
        inlining_prob=benign_prob,
        reassign_prob=obfuscation_prob,
        transpose_prob=obfuscation_prob,
        opaque_prob=obfuscation_prob,
        reorder_functions_prob=args.reorder,
        coverage_level=args.coverage,
        niters=args.niters,
        debug=args.debug,
        isa = ir.modules[0].isa
    )

def invoke_pprinter(outfile, asm_file):
    retcode = subprocess.call([
        'gtirb-pprinter',
        outfile,
        '--asm',
        asm_file
    ])
    return retcode

def main():

    logging.basicConfig(format="%(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("outfile")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument('-e', 
                    '--reorder',
                    type=restricted_float, 
                    default=0.3,
                    help='Function swapping') 
    ap.add_argument('-q', 
                    '--opaque', 
                    type=restricted_float, 
                    default=0.2, 
                    help='Opaque predicate insertion')
    ap.add_argument('-i', 
                    '--inlining', 
                    type=restricted_float, 
                    default=0.5, 
                    help='Inline simple functions')
    ap.add_argument('-o', 
                    '--outlining', 
                    type=restricted_float, 
                    default=0.5, 
                    help='Outlines simple blocks to functions')
    ap.add_argument('-r', 
                    '--reassign', 
                    type=restricted_float, 
                    default=0.5, 
                    help='Swap a live register in a block with a new register')
    ap.add_argument('-w', 
                    '--swap', 
                    type=restricted_float, 
                    default=0.5, 
                    help='Swap instruction positions')
    ap.add_argument('-s', 
                    '--substitution', 
                    type=restricted_float, 
                    default=0.6, 
                    help='Obfuscating instruction substitutions')
    ap.add_argument('-p', 
                    '--optimization', 
                    type=restricted_float, 
                    default=0.6, 
                    help='Optimizing instruction substitutions')
    ap.add_argument('-t', 
                    '--transpose', 
                    type=restricted_float, 
                    default=0.4, 
                    help='Partition code into multiple blocks and rearrange them')
    ap.add_argument('-d', 
                    '--deadcode', 
                    type=restricted_float, 
                    default=0.3, 
                    help='Inserts dead code blocks')
    ap.add_argument('-b', 
                    '--balance', 
                    type=restricted_float, 
                    help='Obfuscation vs benign (0 sets obfuscation probabilities to 1 and benign probabilities to 0, 1 sets obfuscation probabilities to 0 and benign probabilities to 1)')
    ap.add_argument('-c', 
                    '--coverage', 
                    type=coverage_int, 
                    default=3, 
                    help='Indicates how aggressively the binary will be modified')
    ap.add_argument('-n',
                    '--niters', 
                    type=niters_int, 
                    default=5, 
                    help='How many transformations will be run. Does not include inline/outline passes')
    
    args = ap.parse_args()
    if args.verbose:
        logging.getLogger("gtirb_rewriting").setLevel(logging.DEBUG)

    ir = gtirb.IR.load_protobuf(args.infile)

    if ir.modules[0].isa != gtirb.module.Module.ISA.IA32 and \
       ir.modules[0].isa != gtirb.module.Module.ISA.X64:
        raise ArgumentTypeError(f'{ir.modules[0].isa} is not supported')

    parameters = init_parameters(args, ir)
    transformer = transforms.Transformer(ir, parameters)
    transformer.apply_transformations()
    transformer.write_output(args.outfile, 'out.asm')

if __name__ == "__main__":
    main()


