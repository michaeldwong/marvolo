
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import utils
from helpers import operands 
from helpers import registers 
from random import *

import gtirb
import math
import symbol_resolution


class OptimizationPass(Pass):
    """ Pass that substitutes an instruction with a semantically equivalent sequence
        of new instructions """
    def __init__(self, coverage_level, isa):
        self.optimization_prob = coverage_level * 0.2        
        self.isa = isa
 
    def begin_module(self, module, functions, context):
        decoder = GtirbInstructionDecoder(module.isa)
        self.operands_queue = []
        self.symbolic_references = []
        for function in functions:
            for block in function.get_all_blocks():
                self.symbolic_references = utils.extract_symbolic_references(block)
                offset = 0
                for instruction in decoder.get_instructions(block):
                    mnemonic = instruction.mnemonic.upper()
                    if mnemonic == 'CMP':
                        break
                    if self.amenable_to_optimization(instruction):
                        self.substitute_at(context, function, block, offset, instruction)
                    offset += instruction.size

    def amenable_to_optimization(self, instruction):
        """ Check if the instruction's mnemonic is supported and that the
            instruction doesn't use any hex operands"""
        if self.optimization_prob != 1 and random() >= self.optimization_prob:
            return False
        mnemonic = instruction.mnemonic.upper()
        if mnemonic not in [ 'MOV', 'ADD', 'SUB', 'IMUL', 'MUL' ]:
            return False
        current_operands = operands.separate_operands(instruction.op_str)
        rsp_not_used = True
        rip_not_used = True
        for op in current_operands:
            rsp_not_used = rsp_not_used and not registers.uses_registers([ 'RSP' ], op) 
            rip_not_used = rip_not_used and not registers.uses_registers([ 'RIP' ], op)
        segments_not_used = not registers.contains_segment_register(instruction.op_str.upper())
        return rsp_not_used and rip_not_used and segments_not_used

    def substitute_at(self, context, function, block, offset, instruction):
        """ Initiates replacement depending on the current mnemonic """
        mnemonic = ''
        op_str = ''
        try:
            (mnemonic, op_str) = symbol_resolution.instruction_to_str(block, 
                instruction, self.symbolic_references)
        except Exception as e:
            return
        current_operands = operands.separate_operands(op_str)
        if self.check_mov_to_xor_swap(mnemonic, current_operands):
            self.operands_queue.append((mnemonic, current_operands))
            context.replace_at(
                function, block, offset, instruction.size, Patch.from_function(self.mov_to_xor_patch)
            )
        elif mnemonic in [ 'ADD', 'SUB', 'IMUL', 'MUL' ]:
            self.op_substitution(context, function, block, offset, instruction)

    def check_mov_to_xor_swap(self, mnemonic, current_operands): 
        """ Checks if a mov,0 instruction exists so that it can be swapped w/ xor """
        if len(current_operands) != 2:
            return False
        uses_proper_operands = current_operands[1] == '0' and registers.is_register(current_operands[0])
        return mnemonic == 'MOV' and uses_proper_operands

    def op_substitution(self, context, function, block, offset, instruction):
        current_operands = operands.separate_operands(instruction.op_str)
        mnemonic = instruction.mnemonic.upper()
        last_op = current_operands[len(current_operands) - 1]
        if not registers.is_invalid_register(last_op):
            patch = None
            if operands.is_immediate(last_op) and random() <= 0.7:
                try:
                    (mnemonic, op_str) = symbol_resolution.instruction_to_str(block, 
                        instruction, self.symbolic_references)
                    current_operands = operands.separate_operands(op_str, capitalize=False)
                except Exception as e:
                    return
                patch = self.sample_optimization_patch(mnemonic, current_operands)
            if patch is not None:
                self.operands_queue.append((mnemonic, current_operands))
                context.replace_at(
                    function, block, offset, instruction.size, Patch.from_function(patch)
                )

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def mov_to_xor_patch(self, context):
        """ Returns xor reg,reg """
        (_, current_operands) = self.operands_queue.pop(0)
        return f"""xor {current_operands[0]},{current_operands[0]}"""

    def sample_optimization_patch(self, mnemonic, current_operands):
        # Symbolic reference. Do not replace
        if 'OFFSET' in current_operands[1]:
            return None
        if mnemonic == 'ADD':
            if registers.is_usable_register(current_operands[0]):
                return self.lea_patch
        elif mnemonic == 'SUB':
            if registers.is_usable_register(current_operands[0]):
                return self.lea_patch
        elif mnemonic == 'IMUL' or mnemonic == 'MUL':
            if self.swap_imul_for_lea(current_operands) and random() <= 0.6:
                return self.lea_patch
            last_op = current_operands[len(current_operands) - 1]
            if utils.is_power_of_two(int(last_op,0)):
                return self.mul_to_shl_patch 
        return None

    def swap_imul_for_lea(self, current_operands):
        """ Looks at current_operands in imul instruction to determine if an lea can be swapped """
        last_op = current_operands[len(current_operands) - 1]
        if not registers.is_usable_register(current_operands[0]) or \
           not isinstance(last_op, int): 
            return False
        scalar = int(last_op,0)
        return scalar in [2, 3, 4, 5, 8, 9]

    def generate_lea_str(self, current_operands):
        """ Generates lea str replacement"""
        last_op = current_operands[len(current_operands) - 1]
        scalar = int(last_op,0)
        if scalar in [2, 4, 8]:
            return f"""lea {current_operands[0]},[{current_operands[0]}*{scalar}]"""
        # scalar must be 3, 5, or 9
        scalar -= 1 
        return f"""lea {current_operands[0]},[{current_operands[0]}+{current_operands[0]}*{scalar}]"""

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def mul_to_shl_patch(self, context):
        """ Replace imul reg,x with shl reg,x """
        (_, current_operands) = self.operands_queue.pop(0)
        op = current_operands[len(current_operands) - 1]
        immediate = math.log2(int(op,0))
        if len(current_operands) == 3 and current_operands[0] != current_operands[1]:
            return f"""mov {current_operands[0]},{current_operands[1]};
                       shl {current_operands[0]}; """
        else:
            return f"""shl {current_operands[0]},{immediate}"""

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def lea_patch(self, context):
        """ Replace add reg,x with lea reg,[reg + x]"""
        (mnemonic, current_operands) = self.operands_queue.pop(0)
        if mnemonic == 'IMUL' or mnemonic == 'MUL':
            return self.generate_lea_str(current_operands) 
        elif mnemonic == 'ADD':
            return f"""lea {current_operands[0]},[{current_operands[0]}+{current_operands[1]}]"""
        else:
            return f"""lea {current_operands[0]},[{current_operands[0]}-{current_operands[1]}]"""

  


