

from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import instructions
from helpers import utils
from helpers import registers
from random import *

import gtirb

class DeadCodePass(Pass):
    """ Pass that inserts useless garbage instructions that don't change the 
        meaning of the program """
    def __init__(self, coverage_level, isa):
        self.deadcode_prob = coverage_level * 0.2
        self.isa = isa

    def begin_module(self, module, functions, context):
        self.decoder = GtirbInstructionDecoder(module.isa)
        self.one_operand_instructions = [ 'NOT', 'NEG', 'INC', 'DEC' ]
        # Add mov more often
        self.two_operand_instructions = [ 'MOV', 'MOV', 'MOV', 'MOV', 'XOR', \
           'ADD', 'SUB', 'OR', 'AND', 'XCHG', 'IMUL', 'SHL', 'SHR', 'SAR', 'SAL' ]
        guarantee_insertion = self.deadcode_prob == 1
        for function in functions:
            if not utils.skip_function(function.get_name()): 
                if guarantee_insertion or random() <= self.deadcode_prob:
                    self.patch_function(function, context)

    def patch_function(self, function, context):
        """ Applies patches to blocks within the function. Places patches
            between the function prologue and epilogue to prevent errors
            with RBP. """
        passed_prologue = False
        passed_epilogue = False
        # Blocks may not be ordered and we need them to be to detect
        # the valid patch locations
        blocks = list(function.get_all_blocks());
        blocks.sort(key=lambda b: b.offset)
        for block in blocks:
            skip_patch = False
            for instruction in self.decoder.get_instructions(block):
                if not passed_prologue:
                    if instructions.is_prologue_instruction(instruction):
                        skip_patch = True
                        passed_prologue = True
                        break
                elif not passed_epilogue:
                    if instructions.is_epilogue_instruction(instruction):
                        skip_patch = True
                        passed_epilogue = True
                        break
            if passed_prologue and not passed_epilogue and not skip_patch:
                context.register_insert(
                    SingleBlockScope(block, BlockPosition.ANYWHERE),
                    Patch.from_function(self.sample_dead_code_patch())
                )

    def sample_dead_code_patch(self):
        """ Selects a dead code patch """
        patch_prob = random()
        if patch_prob <= 0.3:
            return self.dead_code1 
        elif patch_prob <= 0.6:
            return self.dead_code2
        elif patch_prob <= 0.7:
            return self.dead_code3
        return self.semantic_nop
       
    def generate_random_instruction(self, current_registers):
        """ Generates a random instruction to use in patch """
        use_32bit = self.isa == gtirb.module.Module.ISA.IA32 or random() <= 0.5
        if random() <= 0.3:
            idx = randint(0, len(self.one_operand_instructions) - 1)
            mnemonic = self.one_operand_instructions[idx]
            instruction_str = f'{mnemonic} {current_registers[0]};\n'
        else:
            idx = randint(0, len(self.two_operand_instructions) - 1)
            mnemonic = self.two_operand_instructions[idx]
            (dst, src) = self.determine_instruction_operands(current_registers, mnemonic)
            if (mnemonic == 'MOV' or mnemonic == 'ADD' or mnemonic == 'SUB') and random() <= 0.8:

                if self.isa == gtirb.module.Module.ISA.IA32:
                    offset = 4 * randint(2,20)
                    word_size = 'DWORD'
                    dst = f'{dst}'

                elif random() <= 0.5:
                    offset = 4 * randint(2,20)
                    word_size = 'DWORD'
                    dst = f'{dst:32}'
                else:
                    offset = 8 * randint(0,20)
                    word_size = 'QWORD'
                if self.isa == gtirb.module.Module.ISA.IA32:
                    stack_register = 'ESP'
                else:
                    stack_register = 'RSP'
                src = f'{word_size} PTR [{stack_register} - {offset}];\n'
            instruction_str = f'{mnemonic} {dst},{src};\n'
        return instruction_str

    def determine_instruction_operands(self, current_registers, mnemonic): 
        """ Determines the operands to use for a generated instruction"""
        if len(current_registers) >= 2:
            if self.mnemonic_needs_reg(mnemonic) or random() <= 0.5:
                src = current_registers[0]
                dst = current_registers[1]
            else:
                src = current_registers[1]
                dst = current_registers[0]
            if (self.mnemonic_needs_immediate(mnemonic) or random() <= 0.3) and \
                not self.mnemonic_needs_reg(mnemonic):
                src = randint(0, 30)
        else:
            if mnemonic == 'XCHG':
                dst = current_registers[0]
                src = current_registers[0]
            else:
                dst = current_registers[0]
                src = randint(0, 30)
        return (dst, src)

    def mnemonic_needs_immediate(self, mnemonic):
        """ Determines if instruction needs an immediate src operand """
        return mnemonic in [ 'SHR', 'SAR', 'SHL', 'SAL']

    def mnemonic_needs_reg(self, mnemonic):
        """ Determines if instruction needs a register src operand """
        return mnemonic in [ 'XCHG' ]

    def flanking_semantic_nop(self, current_registers):
        """ A pair of instructions that form a semantic nop that can be used as flanking
            instructions around another semantic nop body"""
        instruction_select = random()
        options = 8
        if instruction_select <= (1 / options):
            return (f'bswap {current_registers[1]};', 
                    f'bswap {current_registers[1]};')
        elif instruction_select <= (2 / options):
            return (f'bswap {current_registers[0]};', 
                    f'bswap {current_registers[0]};')
        elif instruction_select <= (3 / options):
            return (f'xchg {current_registers[0]},{current_registers[1]};', 
                    f'xchg {current_registers[0]},{current_registers[1]};')
        elif instruction_select <= (4 / options):
            return (f'xchg {current_registers[1]},{current_registers[0]};', 
                    f'xchg {current_registers[1]},{current_registers[0]};')
        elif instruction_select <= (5 / options):
            val = randint(0,10000000)
            return (f'add {current_registers[0]},{val};', 
                    f'sub {current_registers[0]},{val};')
        elif instruction_select <= (6 / options):
            val = randint(0,10000000)
            return (f'add {current_registers[1]},{val};', 
                    f'sub {current_registers[1]},{val};')
        elif instruction_select <= (7 / options):
            val = randint(0,10000000)
            return (f'sub {current_registers[0]},{val};', 
                    f'add {current_registers[0]},{val};')
        else:
            val = randint(0,10000000)
            return (f'sub {current_registers[1]},{val};', 
                    f'add {current_registers[1]},{val};')

    def single_semantic_nop(self, current_registers):
        """ A single semantic nop instruction """
        instruction_select = random()
        options = 7
        if instruction_select <= (1 / options):
            return f'mov {current_registers[0]},{current_registers[0]};' 
        elif instruction_select <= (2 / options):
            return f'mov {current_registers[1]},{current_registers[1]};' 
        elif instruction_select <= (3 / options):
            return f'xor {current_registers[0]},0;'
        elif instruction_select <= (4 / options):
            return f'xor {current_registers[1]},0;'
        elif instruction_select <= (5 / options):
            return f'or {current_registers[0]},0;'
        elif instruction_select <= (6 / options):
            return f'or {current_registers[1]},0;'
        return 'nop'

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def semantic_nop(self, context):
        """ Generates semantic nop block (based on CFG in 
            "Optimization-Guided Binary Diversification to Mislead Neural Networks for Malware Detection" """
        patch_str = ''
        if self.isa == gtirb.module.Module.ISA.IA32:
            register1 = registers.sample_register32()
            register2 = registers.sample_register32(register1)
            current_registers = [register1, register2]
        else:
            register1 = registers.sample_register64()
            register2 = registers.sample_register64(register1)
            current_registers = [register1, register2]

        for _ in range(0, randint(2, 4)):
            if random() <= 0.4:
                (f1, f2) = self.flanking_semantic_nop(current_registers)
                patch_str = f1 + '\n' + patch_str + f2 + '\n'
            else:
                patch_str += self.single_semantic_nop(current_registers) + '\n'
        return patch_str
         
    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=1)
    def dead_code1(self, context, register1):
        """ Dead code patch with 1 scratch register """
        patch_str = ''
        if self.isa == gtirb.module.Module.ISA.IA32:
            current_registers = [f'{register1:32}']
        else:
            current_registers = [register1]
        for _ in range(0, randint(4, 6)):
            instruction_str = self.generate_random_instruction(current_registers)
            patch_str += instruction_str 

        return patch_str

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=2)
    def dead_code2(self, context, register1, register2):
        """ Dead code patch with 2 scratch registers """
        patch_str = ''
        if self.isa == gtirb.module.Module.ISA.IA32:
            current_registers = [f'{register1:32}', f'{register2:32}']
        else:
            current_registers = [register1, register2]
        shuffle(current_registers)
        for _ in range(0, randint(4, 6)):
            instruction_str = self.generate_random_instruction(current_registers)
            patch_str += instruction_str 

        return patch_str

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=3)
    def dead_code3(self, context, register1, register2, register3):
        """ Dead code patch with 3 scratch registers """
        patch_str = ''
        if self.isa == gtirb.module.Module.ISA.IA32:
            current_registers = [f'{register1:32}', f'{register2:32}', f'{register3:32}']
        else:
            current_registers = [register1, register2, register3]
        shuffle(current_registers)
        for _ in range(0, randint(4, 8)):
            instruction_str = self.generate_random_instruction(current_registers)
            patch_str += instruction_str 
        return patch_str


