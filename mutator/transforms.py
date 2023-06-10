
import dead_code 
import gtirb
import inlining
import math
import nop 
import opaque 
import optimizations
import os
import outlining
import reassignment
import reorder_functions
import substitutions 
import subprocess
import swap 
import transpose

from random import *
from gtirb_rewriting import *

class Transformer():
    def __init__(self, ir, parameters):
        self.ir = ir
        self.parameters = parameters
        self.clean_gtirb_str = ''
        self.fix_section_names()

    def apply_transformations(self):
      
        if self.parameters.debug:
            print('\n-------')
            print(self.parameters.param_str()) 

        transform_list = []    
        if random() <= self.parameters.dead_code_prob:
            transform_list.append(self.dead_code_transformation)
        if random() <= self.parameters.opaque_prob:
            transform_list.append(self.opaque_predicate_transformation)
        if random() <= self.parameters.substitution_prob:
            transform_list.append(self.substitution_transformation)
        if random() <= self.parameters.optimization_prob:
            transform_list.append(self.optimization_transformation)
        if random() <= self.parameters.swap_prob:
            transform_list.append(self.swap_transformation)
        if random() <= self.parameters.reassign_prob:
            transform_list.append(self.register_reassignment_transformation)
        if random() <= self.parameters.transpose_prob:
            transform_list.append(self.transposition_transformation)
        if len(transform_list) > 0:
            for _ in range(self.parameters.niters):
                idx = randint(0, len(transform_list) - 1)
                transform = transform_list[idx]
                transform()
        # Only run inlining/outlining once at the end
        if random() <= self.parameters.inlining_prob:
            self.inlining_transformation()
        if random() <= self.parameters.outlining_prob:
            self.outlining_transformation()
        if random() <= self.parameters.reorder_functions_prob:
            self.clean_gtirb_str = self.ir._to_protobuf().SerializeToString()
            self.reorder_functions_transformation()

    def apply_transformations_testing(self):

        transform_list = [ self.substitution_transformation,
                           self.optimization_transformation,
                           self.register_reassignment_transformation,
                           self.swap_transformation,
                           self.opaque_predicate_transformation,
                           self.transposition_transformation,
                           self.dead_code_transformation,
                         ]
        niters = 10
       # Only want opaque to run once
        opaque_used = False

        for _ in range(0, niters):
            idx = randint(0, len(transform_list) - 1)
            transform = transform_list[idx]
            while transform == self.opaque_predicate_transformation and opaque_used:
                idx = randint(0, len(transform_list) - 1)
                transform = transform_list[idx]
            transform()
            if transform == self.opaque_predicate_transformation:
                opaque_used = True

        # Only run inlining once at the end
        if random() <= 0.5:
            self.inlining_transformation()
        if random() <= 0.5:
            self.outlining_transformation()

    def fix_section_names(self):
        for m in self.ir.modules:
            for s in m.sections:
                s.name = s.name.rstrip("\x00")

    def reorder_functions_transformation(self):
        if self.parameters.debug:
            print('Function reordering')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        pass_man.add(reorder_functions.ReorderFunctions())
        self.run_pass(pass_man)

    def outlining_transformation(self):
        if self.parameters.debug:
            print('outlining')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(outlining.OutliningPass(coverage, isa))
        self.run_pass(pass_man)

    def inlining_transformation(self):
        if self.parameters.debug:
            print('inlining')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(inlining.InliningPass(coverage, isa))
        self.run_pass(pass_man)

    def dead_code_transformation(self):
        if self.parameters.debug:
            print('dead code')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(dead_code.DeadCodePass(coverage, isa))
#        pass_man.add(nop.NopPass())
        self.run_pass(pass_man)

    def opaque_predicate_transformation(self):
        if self.parameters.debug:
            print('opaque predicates')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(opaque.OpaquePredicatePass(coverage, isa))
        self.run_pass(pass_man)

    def substitution_transformation(self):
        if self.parameters.debug:
            print('obfuscating substitution')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(substitutions.SubstitutionPass(coverage, isa))
        self.run_pass(pass_man)

    def optimization_transformation(self):
        if self.parameters.debug:
            print('optimizing substitution')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(optimizations.OptimizationPass(coverage, isa))
        self.run_pass(pass_man)

    def swap_transformation(self):
        if self.parameters.debug:
            print('swapping')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(swap.SwapPass(coverage, isa))
        self.run_pass(pass_man)

    def transposition_transformation(self):
        if self.parameters.debug:
            print('transpose')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(transpose.TranspositionPass(coverage, isa))
        self.run_pass(pass_man)

    def register_reassignment_transformation(self):
        if self.parameters.debug:
            print('register reassignment')
        pass_man = PassManager()
        coverage = self.parameters.coverage_level
        isa = self.parameters.isa
        pass_man.add(reassignment.RegisterReassignmentPass(coverage, isa))
        self.run_pass(pass_man)

    def run_pass(self, pass_man):
        try:
            pass_man.run(self.ir)
        except Exception as e:
            print(e)

    def invoke_pprinter(self, outfile, asm_file):
        with open(os.devnull, 'w') as DEVNULL:
            retcode = subprocess.call([
                'gtirb-pprinter',
                outfile,
                '--asm',
                asm_file
            ], stdout=DEVNULL, stderr=DEVNULL)
        return retcode

    def write_output(self, outfile, asmfile):
        self.ir.save_protobuf(outfile)
        retcode = self.invoke_pprinter(outfile, asmfile)
        # In case function reordering fails, default to the output GTIRB
        # prior to the IR modification
        if retcode != 0 and len(self.clean_gtirb_str):
            self.reorder_functions_transformation()
            self.ir.save_protobuf(outfile)
            retcode = self.invoke_pprinter(outfile, asmfile)
            if retcode != 0:
                with open(outfile, 'wb') as f:
                    f.write(self.clean_gtirb_str)
                self.invoke_pprinter(outfile, asmfile)

class Parameters():
    def __init__(self, 
                 dead_code_prob=0.3, 
                 opaque_prob=0.2, 
                 substitution_prob=0.5, 
                 optimization_prob=0.5,
                 swap_prob=0.5, 
                 transpose_prob=0.5, 
                 reassign_prob=0.4, 
                 inlining_prob=0.5, 
                 outlining_prob=0.5,
                 reorder_functions_prob=0.3,
                 coverage_level=3,
                 niters=10,
                 debug=False,
                 isa=gtirb.module.Module.ISA.IA32 
                ):
        self.dead_code_prob = dead_code_prob
        self.opaque_prob = opaque_prob
        self.substitution_prob = substitution_prob
        self.optimization_prob = optimization_prob
        self.swap_prob = swap_prob
        self.transpose_prob = transpose_prob
        self.reassign_prob = reassign_prob
        self.inlining_prob = inlining_prob
        self.outlining_prob = outlining_prob
        self.coverage_level = coverage_level
        self.reorder_functions_prob = reorder_functions_prob
        self.niters = niters
        self.debug = debug
        self.isa = isa

    def hash(self):
        return hash(
            (
            self.dead_code_prob,
            self.opaque_prob,
            self.substitution_prob,
            self.optimization_prob,
            self.swap_prob,
            self.transpose_prob,
            self.reassign_prob,
            self.inlining_prob,
            self.outlining_prob,
            self.coverage_level,
            self.reorder_functions_prob,
            self.niters
            )
        )

    def set(self, i, val):
        if i == 0:
            self.dead_code_prob = val
        elif i == 1:
            self.opaque_prob = val
        elif i == 2:
            self.substitution_prob = val
        elif i == 3:
            self.optimization_prob = val
        elif i == 4:
            self.swap_prob = val
        elif i == 5:
            self.transpose_prob = val
        elif i == 6:
            self.reassign_prob = val
        elif i == 7:
            self.inlining_prob = val
        elif i == 8:
            self.outlining_prob = val
        elif i == 9:
            self.reorder_functions_prob= val
        elif i == 10:
            self.coverage_level = val
        elif i == 11:
            self.niters = val
        else:
            raise Exception(f'Error: mutation parameters does not contain idx {i}')

    def get(self, i):
        if i == 0:
            return self.dead_code_prob
        elif i == 1:
            return self.opaque_prob
        elif i == 2:
            return self.substitution_prob
        elif i == 3:
            return self.optimization_prob
        elif i == 4:
            return self.swap_prob
        elif i == 5:
            return self.transpose_prob
        elif i == 6:
            return self.reassign_prob
        elif i == 7:
            return self.inlining_prob
        elif i == 8:
            return self.outlining_prob
        elif i == 9:
            return self.reorder_functions_prob
        elif i == 10:
            return self.coverage_level
        elif i == 11:
            return self.niters 
        raise Exception('Error: mutation parameters does not contain idx ' + i)

    def param_str(self):
        param_str = ''
        param_str += f'dead_code={self.dead_code_prob}\n' 
        param_str += f'opaque={self.opaque_prob}\n' 
        param_str += f'substitition={self.substitution_prob}\n' 
        param_str += f'optimization={self.optimization_prob}\n' 
        param_str += f'swap_prob={self.swap_prob}\n' 
        param_str += f'inlining={self.inlining_prob}\n' 
        param_str += f'outlining={self.outlining_prob}\n' 
        param_str += f'transpose={self.transpose_prob}\n' 
        param_str += f'reassign={self.reassign_prob}\n' 
        param_str += f'reorder={self.reorder_functions_prob}\n' 
        param_str += f'coverage={self.coverage_level}\n'
        param_str += f'niters={self.niters}\n'
        param_str += f'debug={self.debug}\n'
        param_str += f'isa={self.isa}\n'
        return param_str

    def dist(self, parameters):
        # Returns Euclidian distance
        return math.sqrt(
            (self.get(0) - parameters.get(0)) ** 2 +
            (self.get(1) - parameters.get(1)) ** 2 +
            (self.get(2) - parameters.get(2)) ** 2 +
            (self.get(3) - parameters.get(3)) ** 2 +
            (self.get(4) - parameters.get(4)) ** 2 +
            (self.get(5) - parameters.get(5)) ** 2 +
            (self.get(6) - parameters.get(6)) ** 2 +
            (self.get(7) - parameters.get(7)) ** 2 +
            (self.get(8) - parameters.get(8)) ** 2 +
            (self.get(9) - parameters.get(9)) ** 2 +
            (self.get(10) - parameters.get(10)) ** 2 +
            (self.get(11) - parameters.get(11)) ** 2
        )

    def count_active_params(self):
        """ Number of param probs > 0 affected by niters (doesn't include
            outlining, inlining, reordering)"""
        num_active = 0
        for i in range(0,7):
            if self.get(i) > 0:
                num_active += 1
        return num_active


