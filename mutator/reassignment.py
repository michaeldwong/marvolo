
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import instructions
from helpers import utils
from helpers import operands 
from helpers import registers
from random import *

import gtirb
import symbol_resolution 

class RegisterReassignmentPass(Pass):

    def __init__(self, coverage_level, isa):

        self.reassign_prob = coverage_level * 0.2
        self.isa = isa
        self.supported_registers = [ 'RCX', 'RBX', 'RDX', 'RSI', 'RDI' ]
        if self.isa != gtirb.module.Module.ISA.IA32:
            self.supported_registers.extend(
                ['R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15' ]
            )

    def begin_module(self, module, functions, context):
        """ Replaces a live register within a block with another
            register not being used """
        self.decoder = GtirbInstructionDecoder(module.isa)
        self.reassignment_blocks = []
        # TODO: fix error with RAX on ex_struct
        for function in functions:
           for block in function.get_all_blocks():
               if self.amenable_to_reassign(block):
                   self.generate_rewrite(context, function, block)
        

    def amenable_to_reassign(self, block):
        perform_reassign = self.reassign_prob == 1 or random() <= self.reassign_prob
        if not perform_reassign:
            return False
        found_valid_instructions = self.find_valid_instructions(block)
        return found_valid_instructions 

    def generate_rewrite(self, context, function, block):
        """ Determine which register to use for the reassignment. Then
            invoke the replacement"""
        valid_registers = self.reassignment_blocks[-1].valid_registers
        if len(valid_registers) > 0: 
            shuffle(self.supported_registers)
            size = self.reassignment_blocks[-1].size
            offset = self.reassignment_blocks[-1].offset 
            for register64 in self.supported_registers:
                if not registers.contains_register(register64, valid_registers):
                    patch = self.find_patch(register64, valid_registers)
                    if patch == None:
                        continue
                    context.replace_at(
                        function, block, offset, size, Patch.from_function(patch)
                    )
                    return
            del self.reassignment_blocks[-1]
        else:
            del self.reassignment_blocks[-1]

    def find_patch(self, register64, valid_registers):
        """ Returns the proper patch to use depending on register64"""
        if register64 == 'RCX':
            return self.substitute_rcx
        elif register64 == 'RBX':
            return self.substitute_rbx
        elif register64 == 'RDX':
            return self.substitute_rdx
        elif register64 == 'RSI':
            return self.substitute_rsi
        elif register64 == 'RDI':
            return self.substitute_rdi
        elif register64 == 'R8':
            return self.substitute_r8
        elif register64 == 'R9':
            return self.substitute_r9
        elif register64 == 'R10':
            return self.substitute_r10
        elif register64 == 'R11':
            return self.substitute_r11
        elif register64 == 'R12':
            return self.substitute_r12
        elif register64 == 'R13':
            return self.substitute_r13
        elif register64 == 'R14':
            return self.substitute_r14
        elif register64 == 'R15':
            return self.substitute_r15
        return None

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['ECX'])
    def substitute_rcx(self, context):
        """ Patch that substitutes RCX """
        return self.generate_patch_str('ECX', 'RCX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EBX'])
    def substitute_rbx(self, context):
        """ Patch that substitutes RBX """
        return self.generate_patch_str('EBX', 'RBX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EDX'])
    def substitute_rdx(self, context):
        """ Patch that substitutes RDX """
        return self.generate_patch_str('EDX', 'RDX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EAX'])
    def substitute_rax(self, context):
        """ Patch that substitutes RAX """
        return self.generate_patch_str('EAX', 'RAX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['ESI'])
    def substitute_rsi(self, context):
        """ Patch that substitutes RSI """
        return self.generate_patch_str('ESI', 'RSI')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EDI'])
    def substitute_rdi(self, context):
        """ Patch that substitutes RDI """
        return self.generate_patch_str('EDI', 'RDI')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R8'])
    def substitute_r8(self, context):
        """ Patch that substitutes R8 """
        return self.generate_patch_str('R8D', 'R8')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R9'])
    def substitute_r9(self, context):
        """ Patch that substitutes R9 """
        return self.generate_patch_str('R9D', 'R9')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R10'])
    def substitute_r10(self, context):
        """ Patch that substitutes R10 """
        return self.generate_patch_str('R10D', 'R10')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R11'])
    def substitute_r11(self, context):
        """ Patch that substitutes R11 """
        return self.generate_patch_str('R11D', 'R11')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R12'])
    def substitute_r12(self, context):
        """ Patch that substitutes R12 """
        return self.generate_patch_str('R12D', 'R12')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R13'])
    def substitute_r13(self, context):
        """ Patch that substitutes R13 """
        return self.generate_patch_str('R13D', 'R13')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R14'])
    def substitute_r14(self, context):
        """ Patch that substitutes R14 """
        return self.generate_patch_str('R14D', 'R14')

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['R15'])
    def substitute_r15(self, context):
        """ Patch that substitutes R15 """
        return self.generate_patch_str('R15D', 'R15')

    def generate_patch_str(self, scratch32, scratch64):
        """ Generates new block str using the replaced registers"""
        patch_str = ''
        reassign_block = self.reassignment_blocks.pop(0)
        valid_registers = reassign_block.valid_registers
        current_register = valid_registers[randint(0, len(valid_registers) - 1)]
        # Make sure reg to be swapped out isn't equal to a scratch reg
        while current_register == scratch32 or current_register == scratch64:
            current_register = valid_registers[randint(0, len(valid_registers) - 1)]
        register32 = registers.convert_to_register32(current_register)
        register64 = registers.convert_to_register64(current_register)
        (replacements32, replacements64) = self.get_replacements(reassign_block, 
            current_register, register32, register64)
        idx32 = 0
        idx64 = 0
        # Iterate through block and replace current instructions w/ new ones that
        # use the scratch register
        for i, (mnemonic,op_str) in enumerate(reassign_block.instruction_data):
            current_operands = operands.separate_operands(op_str, capitalize=False)
            current_instruction = mnemonic + ' '
            idx32 = self.update_operands(i, register32, idx32, current_operands, replacements32, scratch32)
            idx64 = self.update_operands(i, register64, idx64, current_operands, replacements64, scratch64)
            current_instruction += self.construct_operand_str(current_operands)
            patch_str += current_instruction + '\n'
        if self.isa == gtirb.module.Module.ISA.IA32:
            scratch = scratch32
            register = register32
        else:
            scratch = scratch64
            register = register64
        return f"""mov {scratch},{register};
                   {patch_str};
                   mov {register},{scratch};
                """
    def construct_operand_str(self, current_operands):
        operand_str = ''
        for j, op in enumerate(current_operands):
            operand_str += op
            if j == len(current_operands) - 1:
                operand_str += ';'
            else:
                operand_str += ','
        return operand_str


    def update_operands(self, instruction_idx, old_reg, current_idx, current_operands, replacements, scratch): 
        """ Overwrites the operands with the new register """
        while current_idx < len(replacements) and replacements[current_idx][0] == instruction_idx:
            operand_idx = replacements[current_idx][1]
            if operands.is_memory_access(current_operands[operand_idx]):
                current_operands[operand_idx] = operands.replace_register(
                    current_operands[operand_idx], old_reg, scratch)
            else:
                current_operands[operand_idx] = scratch
            current_idx += 1 
        return current_idx

    def get_replacements(self, block, current_register, register32, register64):
        """ Retrieves instruction replacement data for both the 
            32-bit and 64-bit registers """
        replacements32 = []
        replacements64 = []

        if register32 in block.assignments:
            replacements32 = block.assignments[registers.convert_to_register32(current_register)]
        if register64 in block.assignments:
            replacements64 = block.assignments[registers.convert_to_register64(current_register)]
        return (replacements32, replacements64)

    def find_valid_instructions(self, block):
        """ Find a valid block of instructions such that 2 instructions within the block
            can be swapped. Also gather data on the registers being used
            and their positions"""
        # dict from operand name to pair (idx into block, idx of operand)
        assignments = {}
        instruction_data = []
        offset = 0
        total_offset = 0
        instruction_idx = 0
        block_size = 0
        valid_reg_found = False
        symbolic_references = utils.extract_symbolic_references(block)
        for instruction in self.decoder.get_instructions(block):
            if self.is_instruction_invalid(instruction):
                total_offset += instruction.size
                if len(instruction_data) < 4:
                    instruction_idx = 0
                    block_size = 0
                    assignments.clear()
                    instruction_data = []
                    continue
                else:
                    break
            if len(instruction_data) == 0:
                offset = total_offset

            self.populate_reg_assignments(instruction, assignments, instruction_idx)
            block_size += instruction.size 
            total_offset += instruction.size
            instruction_idx += 1
            mnemonic = ''
            op_str = ''
            try:
                (mnemonic, op_str) = symbol_resolution.instruction_to_str(block, 
                    instruction, symbolic_references)
            except Exception as e:
                if len(instruction_data) < 4:
                    instruction_idx = 0
                    block_size = 0
                    assignments.clear()
                    instruction_data = []
                    continue
                else:
                    break
               
            instruction_data.append((mnemonic, op_str))
        new_block = ReassignmentBlock(offset, block_size, instruction_data, assignments) 
        if len(new_block.valid_registers) > 0:
            self.reassignment_blocks.append(new_block)
            return True
        return False

    def is_instruction_invalid(self, instruction):
        """ Determines if an instruction is invalid for reassignment """
        if instructions.is_instruction_relocatable(instruction, instructions.PassType.REASSIGN):
            current_operands = operands.separate_operands(instruction.op_str)
            if len(current_operands) > 0:
                dst = current_operands[0].upper()
                stack_registers_in_dst = 'RSP' in dst or 'RBP' in dst or 'ESP' in dst or 'EBP' in dst
                if stack_registers_in_dst:
                    return True
                if len(current_operands) > 1:
                    src = current_operands[1].upper()
                    stack_registers_in_src = 'RSP' in src or 'RBP' in src or 'ESP' in src or 'EBP' in src
                    if stack_registers_in_src:
                        return True
            return False
        return True

    def populate_reg_assignments(self, instruction, assignments, instruction_idx):
        """ Populate the assignments map to contain the registers along
            with their positions. Position is a pair (i1, i2) where i1
            is the index within the block of instructions and i2 is the index
            within the operand list"""
        current_operands = operands.separate_operands(instruction.op_str)
        for i, op in enumerate(current_operands):
            if registers.is_usable_register(op.upper()):
                op = op.upper()
                if op not in assignments:
                    assignments[op] = []
                assignments[op].append((instruction_idx, i))
            elif operands.is_memory_access(op):
                access_registers = operands.memory_access_registers(op)
                for register in access_registers:
                    if register not in assignments:
                        assignments[register] = []
                    assignments[register].append((instruction_idx, i))

class ReassignmentBlock:
    def __init__(self, offset, size, instruction_data, assignments):
        self.offset = offset
        self.size = size
        self.instruction_data = instruction_data 
        self.assignments = assignments
        self.valid_registers = self.valid_registers()

    def valid_registers(self):
        """ Returns list of registers being used in the block excluding
            RBP, RSP, RIP"""
        available_registers = self.assignments.keys()
        return list(filter(
            lambda r: not registers.is_invalid_register(r), 
            available_registers
        ))

