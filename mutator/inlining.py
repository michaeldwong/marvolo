
from gtirb import cfg
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import instructions
from helpers import instruction_lists
from helpers import utils
from helpers import operands 
from random import *

import gtirb
import symbol_resolution


class InliningPass(Pass):
    """ Identifies call instructions and performs function inlining"""
    def __init__(self, coverage_level, isa):
        self.inline_prob = coverage_level * 0.2
        self.isa = isa

    def begin_module(self, module, functions, context):
        self.decoder = GtirbInstructionDecoder(module.isa)
        self.names_to_bodies = self.find_function_bodies(functions)
        self.calls_to_inline = []
        self.search_for_calls(functions, context)

    def search_for_calls(self, functions, context):
        """ Look for call instructions so that functions can be inlined"""
        for function in functions:
            if utils.skip_function(function.get_name()):
                continue
            for block in function.get_all_blocks():
                offset = 0
                symbolic_references = utils.extract_symbolic_references(block)
                for instruction in self.decoder.get_instructions(block):
                    mnemonic = instruction.mnemonic.upper()
                    if mnemonic == 'CMP':
                        break
                    if mnemonic == 'CALL' and self.call_amenable_to_inline(instruction):
                        self.apply_inline(instruction, block, function, context, offset)
                    offset += instruction.size

    def apply_inline(self, instruction, block, function, context, offset):
        """ Gets name of function being called then inline it by replacing
            the call instruction with the function body """
        address = instruction.address - block.byte_interval.address + instruction.imm_offset
        symbolic_expr = block.byte_interval.symbolic_expressions[address]
        if not isinstance(symbolic_expr, gtirb.SymAddrConst):
            return
        target_symbol = symbolic_expr.symbol
        function_name = target_symbol.name
        if function_name in self.names_to_bodies:
            self.calls_to_inline.append(target_symbol.name)
            context.replace_at(
                function, block, offset, instruction.size, Patch.from_function(self.inline_patch)
            )

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def inline_patch(self, context):
        """ Gets the function name of the current call instruction and retrieves
            the function body"""
        function_name = self.calls_to_inline.pop(0)
        function_str = self.names_to_bodies[function_name]
        return function_str

    def call_amenable_to_inline(self, instruction):
        is_hex_operand = operands.is_hex_operand(instruction.op_str)
        if not is_hex_operand:
            return False
        perform_inline = self.inline_prob == 1 or random() <= self.inline_prob
        return perform_inline 

    def find_function_bodies(self, functions):
        """ Iterate through functions and add the function bodies that
            can be inlined """
        names_to_bodies = {}
        for function in functions:
            if utils.skip_function(function.get_name()):
                continue
            function_str = ''
            add_function = True
            found_ret = False
            for block in function.get_all_blocks():
                symbolic_references = utils.extract_symbolic_references(block)
                for instruction in self.decoder.get_instructions(block):
                    mnemonic = ''
                    op_str = ''
                    try:
                        (mnemonic, op_str) = symbol_resolution.instruction_to_str(
                            block, instruction, symbolic_references)
                    except Exception as e:
                        add_function = False
                        break
                    if self.invalid_for_inline(mnemonic, op_str) or \
                        self.invalid_function(found_ret, mnemonic):
                        add_function = False
                        break
                    if self.is_valid_instruction(mnemonic):
                        if 'EBP' in op_str or 'RBP' in op_str:
                            op_str = self.fix_operands(op_str)
                        function_str += f'{mnemonic} {op_str}\n'
                    if mnemonic == 'RET' or mnemonic == 'LEAVE':
                        found_ret = True
            if add_function:
                names_to_bodies[function.get_name()] = function_str
        return names_to_bodies

    def fix_operands(self, op_str):
        """ If the function to be inlined access memory slots above
            the base pointer, adjust accordingly to account for not having
            the return address on the stack pushed by the call instruction"""
        current_operands = operands.separate_operands(op_str)
        for i,op in enumerate(current_operands):
            if operands.is_memory_access(op):
                tokens = operands.extract_expression(op)
                bp_idx = 0
                if 'EBP' in tokens:
                    bp_idx = tokens.index('EBP')
                elif 'RBP' in tokens:
                    bp_idx = tokens.index('RBP')
                else:
                    continue
                if bp_idx + 2 < len(tokens) and tokens[bp_idx + 1] == '+':
                    if tokens[bp_idx + 2].isdigit():
                        new_num = int(tokens[bp_idx + 2]) - 4
                        tokens[bp_idx + 2] = str(new_num)
                        access_type_str = op[:op.index('[')] 
                        current_operands[i] = f'{access_type_str}[{"".join(tokens)}]'

                        return ','.join(current_operands) 
        return op_str

    def invalid_function(self, found_ret, mnemonic):
        """ Sometimes functions have a label after the ret -- this is invalid"""
        return found_ret and mnemonic != 'NOP'
      
    def invalid_for_inline(self, mnemonic, op_str):
        """ If the function body contains an invalid instruction, stop and
            don't populate names_to_bodies with the function """
        invalid_mnemonic = self.invalid_mnemonic(mnemonic) 
        return invalid_mnemonic 

    def invalid_mnemonic(self, mnemonic):
        # TODO: Get the name of the label that will be jumped to. 
        # Then replace the address with that label so that gtirb-rewriting
        # can consume the instruction patch 
        return mnemonic in [ 'CALL' ] or instructions.is_jmp(mnemonic)

    def is_valid_instruction(self, mnemonic):
        """ If individual instruction is valid to add for inlining"""
        return mnemonic not in instruction_lists.inlining_blacklist




