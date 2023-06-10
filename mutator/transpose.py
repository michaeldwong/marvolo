

from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import instructions
from helpers import utils
from random import *

import gtirb
import symbol_resolution

class TranspositionPass(Pass):
    """ Takes a basic block and splits it into multiple subslices. Then
        each of these subslices are rearranged and inserted with jmp
        instructions that ensure that the original execution order is preserved """
    def __init__(self, coverage_level, isa):
        self.transpose_prob = coverage_level * 0.2
        self.isa = isa

    def begin_module(self, module, functions, context):
        self.decoder = GtirbInstructionDecoder(module.isa)
        self.symbolic_references = []
        self.replacements = []
        guarantee_transpose = self.transpose_prob == 1
        for function in functions:
            for block in function.get_all_blocks():
                self.symbolic_references = utils.extract_symbolic_references(block) 
                if guarantee_transpose or random() <= self.transpose_prob:
                    replacement_slices = self.transpose_block(context, block)
                    if len(replacement_slices) == 0:
                        continue
                    self.replacements.append(replacement_slices)
                    self.insert_replacement_block(function, context, block)

    @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1)
    def test_patch(self, context, reg1):
        return f"mov {reg1},DWORD PTR .L_405324"
   
    def insert_replacement_block(self, function, context, block):
        """ Retrieves data for replacement and invokes the block 
            replacement patch """
        replacement_block = self.replacements[len(self.replacements) - 1]
        offset = replacement_block[0].offset
        size = sum([
            block_slice.size for block_slice in replacement_block
        ])
        context.replace_at(
            function, block, offset, size, Patch.from_function(self.transpose_patch)
        )


    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def transpose_patch(self, context):
        """ Situates the block slices into new locations and adds
            the jmps that stitch the blocks together """
        replacement_slices = self.replacements.pop(0)
        labels = utils.sample_labels(len(replacement_slices) + 1)
        return self.generate_transpose_str(labels, replacement_slices)

    def generate_transpose_str(self, labels, replacement_slices):
        """ Randomizes the order of the slices and generates the asm
            str to use for the patch"""
        idx_to_slice_str = {}
        for i, replacement_slice in enumerate(replacement_slices):
            slice_str = f"""
                        {labels[i]}:
                        {replacement_slice.block_str};
                        """
            idx_to_slice_str[i] = (labels[i], slice_str)
        keys = list(idx_to_slice_str.keys())
        shuffle(keys)
        if keys[0] == 0:
            shuffle(keys)
        return self.resolve_jmp_locations(labels, keys, idx_to_slice_str)

    def resolve_jmp_locations(self, labels, keys, idx_to_slice_str):
        """ Ensures that the strings for each slice are ended with the 
            jmp instruction to the next slice  """
        entry_point = idx_to_slice_str[0][0]
        block_str = f"""
                    jmp {entry_point};
                    """
        for k in keys:
            block_str += idx_to_slice_str[k][1] 
            if k < len(keys) - 1:
                jmp_dst = idx_to_slice_str[k + 1][0]
            else:
                jmp_dst = labels[-1]
            block_str += f"""
                         jmp {jmp_dst};
                         """
        block_str += f"""
                     {labels[-1]}:
                     nop;
                     """
        return block_str
      
    def transpose_block(self, context, block):
        """ Divides the current basic block into smaller slices 
            that will be rearranged when the patch is invoked. """
        (offset, instruction_block) = self.find_valid_instructions(block)
        if len(instruction_block) < 3:
            return []
        replacement_slices = []
        block_length = len(instruction_block)
        bounds = self.init_bounds(block_length)
        bound_idx = 0
        slice_size = 0
        slice_str = ''
        for i, instruction in enumerate(instruction_block):
            if bound_idx < len(bounds) and i == bounds[bound_idx]:
                replacement = ReplacementSlice(slice_str, offset, slice_size)
                replacement_slices.append(replacement)
                offset += slice_size
                slice_size = 0
                slice_str = ''
                bound_idx += 1
            mnemonic = ''
            op_str = ''
            try:
                (mnemonic, op_str) = symbol_resolution.instruction_to_str(block, 
                    instruction, self.symbolic_references)
            except Exception as e:
                return []
            slice_str += f'{mnemonic} {op_str};\n'
            slice_size += instruction.size

        replacement = ReplacementSlice(slice_str, offset, slice_size)
        replacement_slices.append(replacement)
        return replacement_slices

    def init_bounds(self, block_length):
        """ Returns list of indices used to determine the bounds of each
            slice in the array of instructions"""
        if block_length <= 8 or random() <= 0.4:
            bounds = [ int(block_length / 2) ]
        elif block_length <= 12 or random() <= 0.3:
            bounds = [ int(block_length / 3), 2 * int(block_length / 3) ]
        elif block_length <= 18 or random() <= 0.2:
            bounds = [ int(block_length / 4), int(block_length / 2), 
                       3 * int(block_length / 4) ]
        else:
            bounds = [ int(block_length / 5), 2 * int(block_length / 5), 
                       3 * int(block_length / 5), 4 * int(block_length / 5) ]
        return bounds

    def find_valid_instructions(self, block):
        """ Iterates through block instructions and finds a continuous sub-sequence
            of relocatable instructions that will later be chopped into slices.
            Also returns offset of the sequence 
        """
        minimum_block_size = 4
        instruction_block = []
        offset = 0
        total_offset = 0
        for instruction in self.decoder.get_instructions(block):
            if self.is_instruction_invalid(instruction, block):
                total_offset += instruction.size
                if len(instruction_block) <= minimum_block_size:
                    instruction_block = []
                    continue
                else:
                    break
            if len(instruction_block) == 0:
                offset = total_offset
            total_offset += instruction.size
            instruction_block.append(instruction)
        return (offset, instruction_block)

    def is_instruction_invalid(self, instruction, block):
        invalid_opcode = not instructions.is_instruction_relocatable(
            instruction, instructions.PassType.TRANSPOSE)
        return invalid_opcode 
       
class ReplacementSlice():
    """ Represents a slice subset of instructions within a basic block that will
        be rearranged """
    def __init__(self, block_str, offset, size):
        self.block_str = block_str
        self.offset = offset
        self.size = size

        

