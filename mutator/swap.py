

from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import utils
from helpers import operands 
from helpers import registers
from random import *

import gtirb
import symbol_resolution

class SwapPass(Pass):
    def __init__(self, coverage_level, isa):
        self.swap_prob = coverage_level * 0.2
        self.isa = isa

    def begin_module(self, module, functions, context):
        # TODO: Add support for no-operand opcodes
        self.swappable = [ 'MOV', 'ADD', 'SUB', 'SHL', 'IMUL', \
            'SHR', 'NEG', 'XOR', 'AND', 'OR', 'INC', 'SAL', 'SAR',  \
            'DEC', 'LEA', 'NOT', 'MOVZX', 'MOVSX', 'MOVSD', 'HLT', 'NOT'  ]
        self.swap_pairs = []
        self.decoder = GtirbInstructionDecoder(module.isa)
        self.symbolic_references = []
        for function in functions:
            for block in function.get_all_blocks():
                self.symbolic_references = utils.extract_symbolic_references(block)
                if self.amenable_to_swap(block):
                    self.swap_instructions(context, block, function)

    def amenable_to_swap(self, block):
        perform_swap = self.swap_prob == 1 or random() <= self.swap_prob
        if not perform_swap:
            return False
        return self.initiate_swap(block)
 
    def swap_instructions(self, context, block, function):
        """ Swap 2 instructions within a block """
        offset = 0
        # swap_pairs doesn't get popped from until patches get run.
        # Get the last element to get the proper offsets
        pair_idx = len(self.swap_pairs) - 1

        for instruction in self.decoder.get_instructions(block):
            if offset == self.swap_pairs[pair_idx][0].offset:
                context.replace_at(
                    function, 
                    block, 
                    offset, 
                    instruction.size, 
                    Patch.from_function(self.first_swap)
                )
            if offset == self.swap_pairs[pair_idx][1].offset:
                context.replace_at(
                    function, 
                    block, 
                    offset, 
                    instruction.size, 
                    Patch.from_function(self.second_swap)
                )
            offset += instruction.size

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def first_swap(self, context):
        """ Returns the second instruction in the swap pair """
        return self.swap_pairs[0][1].instruction_str

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def second_swap(self, context):
        """ Returns the first instruction in the swap pair and pops from swap_pairs """
        (swap_instruction1, swap_instruction2) = self.swap_pairs.pop(0)
        return swap_instruction1.instruction_str

    def initiate_swap(self, block):
        """ Finds a sub-block of instructions for swapping. Then randomly swaps
            2 instructions within that sub-block """
        current_block = []
        offset = 0
        # Get the block to extract info from
        for instruction in self.decoder.get_instructions(block):
            if self.is_instruction_invalid(instruction):
                if len(current_block) <= 1:
                    current_block.clear()
                    offset += instruction.size
                    continue
                else:
                    break
            mnemonic = ''
            op_str = ''
            try:
                (mnemonic, op_str) = symbol_resolution.instruction_to_str(block, 
                    instruction, self.symbolic_references)
            except Exception as e:
                current_block.clear()
                offset += instruction.size
                continue
            current_operands = operands.separate_operands(op_str, capitalize=False)
            swappable_instruction = SwappableInstruction(instruction, current_operands, offset)
            current_block.append(swappable_instruction)
            offset += instruction.size
        return self.find_swap_pair(current_block)
    
    def find_swap_pair(self, current_block): 
        # Check for dependencies
        for _ in range (0, int(len(current_block) / 3) + 1):
            if len(current_block) > 1: 
                j = randint(0, len(current_block) - 2)
                k = randint(j + 1, len(current_block) - 1)
                swap_instruction1 = current_block[j]
                swap_instruction2 = current_block[k]
                if swap_instruction1.get_mnemonic() == 'NOP' or \
                   swap_instruction2.get_mnemonic() == 'NOP':
                    continue
                if self.has_dependency(swap_instruction1, swap_instruction2):
                    continue
                sandwich_dependency_found = False
                for i in range(j + 1, k):
                    if self.has_dependency(swap_instruction1, current_block[i]) or \
                       self.has_dependency(swap_instruction2, current_block[i]):
                        sandwich_dependency_found = True
                if sandwich_dependency_found:
                    continue
                self.swap_pairs.append((swap_instruction1, swap_instruction2))
                return True
        return False

    def has_dependency(self, instruction1, instruction2):
        if instruction1.num_operands == 0 or instruction2.num_operands == 0:
            return False
        """ Checks for dependencies between instruction1 and instruction2 """
        if instruction1.src == instruction2.dst or instruction1.dst == instruction2.src or instruction1.dst == instruction2.dst:
            return True
        if self.register_dependency_found(instruction1, instruction2):
            return True
        if self.memory_dependency_found(instruction1, instruction2):
            return True
        return False


    def register_dependency_found(self, instruction1, instruction2):
        if registers.is_register(instruction1.dst) and registers.is_register(instruction2.src):
            if registers.dependency_found(instruction1.dst, instruction2.src):
                return True
        if registers.is_register(instruction1.src) and registers.is_register(instruction2.dst):
            if registers.dependency_found(instruction1.src, instruction2.dst):
                return True
        if registers.is_register(instruction1.dst) and registers.is_register(instruction2.dst):
            if registers.dependency_found(instruction1.dst, instruction2.dst):
                return True
        return False

    def memory_dependency_found(self, instruction1, instruction2):
        """ Checks for dependencies in memory accesses """
        if instruction1.is_dst_mem_access():
            if self.contains_dst_register(instruction1, instruction2):
                return True
        if instruction2.is_dst_mem_access():
            if self.contains_dst_register(instruction2, instruction1):
                return True
        if instruction1.is_src_mem_access():
            if self.contains_src_register(instruction1, instruction2):
                return True
        if instruction2.is_src_mem_access():
            if self.contains_src_register(instruction2, instruction1):
                return True
        return False

    def contains_dst_register(self, instruction1, instruction2):
        """ instruction1 writes to memory """ 
        src_register32 = registers.convert_to_register32(instruction2.src)
        src_register64 = registers.convert_to_register64(instruction2.src)
        dst_register32 = registers.convert_to_register32(instruction2.dst)
        dst_register64 = registers.convert_to_register64(instruction2.dst)
        return instruction1.contains_dst_register(src_register32) or \
               instruction1.contains_dst_register(src_register64) or \
               instruction1.contains_dst_register(dst_register32) or \
               instruction1.contains_dst_register(dst_register64) 

    def contains_src_register(self, instruction1, instruction2):
        """ instruction1 has src memory access """ 
        src_register32 = registers.convert_to_register32(instruction2.src)
        src_register64 = registers.convert_to_register64(instruction2.src)
        dst_register32 = registers.convert_to_register32(instruction2.dst)
        dst_register64 = registers.convert_to_register64(instruction2.dst)
        return instruction1.contains_src_register(src_register32) or \
               instruction1.contains_src_register(src_register64) or \
               instruction1.contains_src_register(dst_register32) or \
               instruction1.contains_src_register(dst_register64) 

    def is_instruction_invalid(self, instruction):
        """ Determines if the instruction should be used for swapping or not """
        if instruction.mnemonic.upper() not in self.swappable or \
            self.has_invalid_operands(instruction):
            return True
        return self.invalid_instruction_exceptions(instruction) 

    def invalid_instruction_exceptions(self, instruction):
        current_operands = operands.separate_operands(instruction.op_str) 
        mnemonic = instruction.mnemonic.upper()
        return (mnemonic == 'MUL' or mnemonic == 'iMUL') and len(current_operands) == 1
    
    def has_invalid_operands(self, instruction):
        """ Determines if the instruction's operands are invalid for swapping """
        current_operands = operands.separate_operands(instruction.op_str)
        for op in current_operands:
            has_invalid_register = registers.is_invalid_register(op)
            has_segment_register = registers.contains_segment_register(op)
 
            if has_segment_register or has_invalid_register or self.is_memory_access_invalid(op):
                return True

        return False

    def is_memory_access_invalid(self, operand):
        """ Determines if the instruction using this memory access is amenable
            to a swap """
        if '[' in operand and ']' in operand:
            if 'RIP' in operand.upper() or 'EIP' in operand.upper() or 'FS:' in operand.upper():
                return True
        return False 

class SwappableInstruction:
    """ This class encapsulates data for an instruction that can
        be swapped with another """
    def __init__(self, instruction, current_operands, offset):
        self.operands = current_operands
        self.num_operands = len(current_operands)
        self.instruction = instruction
        if self.num_operands > 0:
            self.dst = current_operands[0].upper()
            if self.num_operands == 1:
                self.src = None
            else:
                self.src = current_operands[1].upper()
        else:
            self.dst = None
        self.offset = offset 

    def get_op_str(self):
        """ Return operand string """
        return ", ".join(self.operands)

    def get_mnemonic(self):
        """ Return instruction mnemonic """
        return self.instruction.mnemonic.upper()
  
    @property 
    def instruction_str(self):
        """ Return mnemonic + operand string """
        return f"""{self.get_mnemonic()} {self.get_op_str()}"""

    def is_dst_mem_access(self):
        """ Is the dst operand a memeory access """
        if self.dst == None:
            return False
        return '[' in self.dst and ']' in self.dst

    def contains_dst_register(self, register):
        """ Determines if input register is used for dst memory access """
        if self.dst == None or register == None:
            return False
        return register.upper() in self.dst.upper()        

    def is_src_mem_access(self):
        """ Is the src operand a memeory access """
        if self.src == None:
            return False
        return '[' in self.src and ']' in self.src

    def contains_src_register(self, register):
        """ Determines if input register is used for src memory access """
        if self.src == None or register == None:
            return False
        return register.upper() in self.src.upper()        


