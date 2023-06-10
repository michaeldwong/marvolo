
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from gtirb_rewriting.patches import CallPatch
from helpers import instructions
from helpers import utils
from helpers import registers
from random import *

import gtirb
import symbol_resolution

class OutliningPass(Pass):
    """ Identifies call instructions and performs function inlining"""
    def __init__(self, coverage_level, isa):
        self.outline_prob = coverage_level * 0.2
        self.isa = isa

    def begin_module(self, module, functions, context):
        self.MINIMUM_LENGTH = 3
        self.decoder = GtirbInstructionDecoder(module.isa)
        self.id = 0
        self.function_bodies = [] 
        self.search_for_code_to_outline(functions, context)

    def search_for_code_to_outline(self, functions, context):
        """ Iterates through instructions to find blocks that can be outlined to functions"""
        guarantee_outline = self.outline_prob == 1
        for function in functions:
            if utils.skip_function(function.get_name()):
                continue
            passed_prologue = False
            passed_epilogue = False
            # Blocks may not be ordered and we need them to be to detect
            # the valid patch locations
            blocks = list(function.get_all_blocks());
            blocks.sort(key=lambda b: b.offset)
            function_progress = [ passed_prologue, passed_epilogue ]
            for block in blocks:
                if guarantee_outline or random() <= self.outline_prob:
                    self.search_through_block(block, context, function, function_progress)
            passed_prologue = function_progress[0]
            passed_epilogue = function_progress[1]

    def search_through_block(self, block, context, function, function_progress):
            """ Iterate through instructions in block to find sequences that can be outlined"""
            new_function_str = ''
            size = 0
            length = 0
            offset = 0
            symbolic_references = utils.extract_symbolic_references(block)
            for instruction in self.decoder.get_instructions(block):
                break_from_loop = self.check_parsing_position(instruction, function_progress)
                if break_from_loop:
                    break
                if not function_progress[0]:
                    continue
                assert function_progress[0] 
                assert not function_progress[1] 
                mnemonic = ''
                op_str = ''
                try:
                    (mnemonic, op_str) = symbol_resolution.instruction_to_str(block, 
                        instruction, symbolic_references)
                except Exception as e:
                    if length >= self.MINIMUM_LENGTH:
                        self.perform_outline(new_function_str, context, function, block, offset, size)
                        break
                    else:
                        new_function_str = ''
                        length = 0
                        size += instruction.size
                        continue  
                if len(new_function_str) > 0 and length >= self.MINIMUM_LENGTH and random() <= 0.05 * length:
                    self.perform_outline(new_function_str, context, function, block, offset, size)
                    break
                if length == 0:
                    offset = size
                if self.invalid_instruction(instruction, mnemonic, op_str) and length >= self.MINIMUM_LENGTH:
                    self.perform_outline(new_function_str, context, function, block, offset, size)
                    break
                elif self.invalid_instruction(instruction, mnemonic, op_str) and length < self.MINIMUM_LENGTH:
                    new_function_str = ''
                    length = 0
                    size += instruction.size
                    continue 
                new_function_str += f'{mnemonic} {op_str};\n'
                size += instruction.size
                if instruction.mnemonic != 'nop':
                    length += 1

    def check_parsing_position(self, instruction, function_progress):
        """ Ensures that the loop does not iterate through instructions before the function prologue and 
            after the epilogue """
        passed_prologue = function_progress[0]
        passed_epilogue = function_progress[1]
        break_from_loop = False 
        if not passed_prologue:
            if instructions.is_prologue_instruction(instruction):
                function_progress[0] = True
                break_from_loop = True
        elif not passed_epilogue:
            if instructions.is_epilogue_instruction(instruction):
                function_progress[1] = True
                break_from_loop = True
        if passed_epilogue:
            break_from_loop = True
        return break_from_loop
       
    def invalid_instruction(self, instruction, mnemonic, op_str):
        """ Determines if an individual instruction in a block can be successfully outlined"""
        for bad_register in [ 'RIP', 'RBP', 'RSP' ]:
            register32 = registers.convert_to_register32(bad_register)
            register64 = registers.convert_to_register64(bad_register)
            if register32 in instruction.op_str.upper() or register64 in instruction.op_str.upper():
                return True
        if registers.contains_segment_register(instruction.op_str):
            return True
        return not instructions.is_instruction_relocatable(instruction, instructions.PassType.OUTLINE)

    def perform_outline(self, new_function_str, context, function, block, offset, size):
        """ Initiates the outline by inserting a new function and replacing the old block with a call instruction """
        self.function_bodies.append(new_function_str)
        outline_patch = Patch.from_function(self.create_function)
        symbol = context.register_insert_function('FUNCTION_' + str(self.id), outline_patch)
        context.replace_at(
            function, block, offset, size - offset, CallPatch(symbol) 
        )
        self.id += 1

    def get_stack_registers(self):
        if self.isa == gtirb.module.Module.ISA.IA32:
            return ('EBP', 'ESP')
        return ('RBP', 'RSP')

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def create_function(self, context):
        function_str = self.function_bodies.pop(0)
        (base_register, stack_register) = self.get_stack_registers()
        return f"""push {base_register};
                   mov {base_register},{stack_register};
                   {function_str}
                   mov {stack_register},{base_register};
                   pop {base_register};
                   ret;
               """

