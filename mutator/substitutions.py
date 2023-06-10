
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import utils
from helpers import operands 
from helpers import registers
from random import *

import gtirb
import math
import symbol_resolution

class SubstitutionPass(Pass):
    """ Pass that substitutes an instruction with a semantically equivalent sequence
        of new instructions """
    def __init__(self, coverage_level, isa):
        self.substitute_prob = coverage_level * 0.2
        self.isa = isa
        self.instructions_to_substitute = [ 'MOV', 'ADD', 'SUB', 'XOR',
             'MUL', 'IMUL', 'OR', 'AND', 'NEG' ]
 
    def begin_module(self, module, functions, context):
        decoder = GtirbInstructionDecoder(module.isa)
        self.operands_queue = []
        self.symbolic_references = []
        for function in functions:
            for block in function.get_all_blocks():
                offset = 0
                self.symbolic_references = utils.extract_symbolic_references(block)
                for instruction in decoder.get_instructions(block):
                    if self.amenable_to_substitute(instruction):
                        self.substitute_at(context, function, block, offset, instruction)
                    offset += instruction.size

    def amenable_to_substitute(self, instruction):
        """ Check if the instruction's mnemonic is supported and that the
            instruction doesn't use any hex operands"""
        if self.substitute_prob != 1 and random() >= self.substitute_prob:
            return False
        mnemonic = instruction.mnemonic.upper()
        if mnemonic not in self.instructions_to_substitute:
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
        current_operands = operands.separate_operands(op_str, capitalize=False)
        if self.check_for_expansion(instruction, current_operands):
            access_registers = operands.memory_access_registers(current_operands[0])
            patch = self.sample_expansion_patch(access_registers, current_operands) 
            if patch == None:
                return
            self.operands_queue.append((mnemonic, current_operands))
            context.replace_at(
                function, block, offset, instruction.size, Patch.from_function(patch)
            )
        elif self.check_obfuscating_substitution(instruction, current_operands):
            self.op_substitution(context, function, block, 
                offset, mnemonic, current_operands, instruction)

    def check_for_expansion(self, instruction, current_operands):
        if len(current_operands) != 2:
           return False
        size = operands.operand_data_size(current_operands[0])
        if size < 32:
            return False
        if self.substitute_prob < 1 and random() >= self.substitute_prob:
            return False
        mnemonic = instruction.mnemonic.upper()
        is_decimal = operands.is_decimal(current_operands[1])
        valid_dst = registers.is_usable_register(current_operands[0]) or operands.is_memory_access(current_operands[0])
        has_proper_operands = is_decimal and valid_dst
        if not has_proper_operands:
            return False
        access_registers = operands.memory_access_registers(current_operands[0])
        uses_valid_registers = not self.contains_invalid_registers(access_registers)
        return uses_valid_registers
        
    def check_obfuscating_substitution(self, instruction, current_operands):
        mnemonic = instruction.mnemonic.upper() 
        return mnemonic in [ 'ADD', 'AND', 'SUB', 'OR', 'XOR', 'NEG', 'IMUL', 'MUL' ]
   
    def op_substitution(self, context, function, block, offset, 
                            mnemonic, current_operands, instruction):
        if registers.is_usable_register(current_operands[0]):
            last_op = current_operands[len(current_operands) - 1]
            if len(current_operands) == 1:
                if self.substitute_prob == 1 or random() <= self.substitute_prob:
                    patch = self.sample_single_operand_patch(mnemonic, current_operands)
                    if patch is not None:
                        self.operands_queue.append((mnemonic, current_operands))
                        context.replace_at(
                            function, block, offset, instruction.size, Patch.from_function(patch)
                        )
            elif registers.is_usable_register(last_op):
                # When performing a register-to-register op. If both operands are the same register,
                # use scratch patches to avoid adversely affecting the operations
                if current_operands[1] != current_operands[0]:
                    patch = self.sample_register_patch(mnemonic, current_operands)
                    if patch is not None:
                        self.operands_queue.append((mnemonic, current_operands))
                        context.replace_at(
                            function, block, offset, instruction.size, Patch.from_function(patch)
                        )
            elif not registers.is_invalid_register(last_op):
                patch = None
                if patch is None:
                    patch = self.sample_scratch_patch(mnemonic, current_operands)
                if patch is not None:
                    self.operands_queue.append((mnemonic, current_operands))
                    context.replace_at(
                        function, block, offset, instruction.size, Patch.from_function(patch)
                    )

    def sample_single_operand_patch(self, mnemonic, current_operands):
        if mnemonic == 'NEG' and random() <= self.substitute_prob:
            return self.neg_to_not_patch
        return None

    def sample_expansion_patch(self, access_registers, current_operands):
        if 'OFFSET' in current_operands[1] or (len(current_operands) == 3 and 'OFFSET' in current_operands[2]):
            return None
        patch_to_use = random()
        num_patches = 6
        if 'ECX' not in access_registers and 'RCX' not in access_registers and \
            current_operands[0] != 'ECX' and current_operands[0] != 'RCX' and patch_to_use <= (1 / num_patches):
            return self.expand_immediate_rcx
        elif 'EBX' not in access_registers and 'RBX' not in access_registers and \
            current_operands[0] != 'EBX' and current_operands[0] != 'RBX' and patch_to_use <= (2 / num_patches):
            return self.expand_immediate_rbx
        elif 'EDX' not in access_registers and 'RDX' not in access_registers and \
            current_operands[0] != 'EDX' and current_operands[0] != 'RDX' and patch_to_use <= (3 / num_patches):
            return self.expand_immediate_rdx
        elif 'EAX' not in access_registers and 'RAX' not in access_registers and \
            current_operands[0] != 'EAX' and current_operands[0] != 'RAX' and patch_to_use <= (4 / num_patches):
            return self.expand_immediate_rax
        elif 'ESI' not in access_registers and 'RSI' not in access_registers and \
            current_operands[0] != 'ESI' and current_operands[0] != 'RSI' and patch_to_use <= (5 / num_patches):
            return self.expand_immediate_rsi
        elif 'EDI' not in access_registers and 'RDI' not in access_registers and \
            current_operands[0] != 'EDI' and current_operands[0] != 'RDI':
            return self.expand_immediate_rdi
        return None

    def generate_expansion_str(self, register):
        """ Expand mov instruction to multiple other instructions"""
        if self.isa == gtirb.module.Module.ISA.IA32:
            register = registers.convert_to_register32(register)
        (mnemonic, current_operands) = self.operands_queue.pop(0)
        tmp_register = registers.determine_scratch(current_operands[0], register)
        if random() <= 0.5:
            immediate = int(current_operands[1],0)
            selected_op = random()
            val = randint(0,100000000)
            if immediate % 2 == 0:
                num = immediate / 2
                setup_str = f"""mov {register},{num};
                                add {register},{register}; 
                             """
            else:
                num = (immediate - 1) / 2
                setup_str = f"""mov {register},{num};
                                add {register},{register}; 
                                add {register},1;
                             """
        else:
            setup_str = f'mov {register},{current_operands[1]}'
        return f"""{setup_str}
                   {mnemonic} {current_operands[0]},{tmp_register};
                """

    def contains_invalid_registers(self, access_registers):
        return 'RSP' in access_registers or 'ESP' in access_registers

    def sample_register_patch(self, mnemonic, current_operands):
        """ Returns a substitution patch for a register-to-register instruction """
        if mnemonic == 'ADD':
            return self.sample_add_register_patch()
        if mnemonic == 'SUB':
            return self.sample_sub_register_patch()
        if registers.contains_register('R8', current_operands) or registers.contains_register('R9', current_operands):
            return None
        if mnemonic == 'AND' and not registers.contains_register('RAX', current_operands):
            return self.and_register_patch
        if mnemonic == 'OR' and not registers.contains_register('RSI', current_operands) and \
           not registers.contains_register('RDI', current_operands):
            return self.or_patch
        if mnemonic == 'XOR' and not registers.contains_register('RCX', current_operands) and \
           not registers.contains_register('RDX', current_operands):
            return self.xor_patch
        return None

    def sample_scratch_patch(self, mnemonic, current_operands):
        """ Returns a substitution patch for an instruction using extra scratch registers"""
        if 'OFFSET' in current_operands[1] or (len(current_operands) == 3 and 'OFFSET' in current_operands[2]):
            return None
        if mnemonic == 'ADD':
            return self.sample_add_scratch_patch(current_operands)
        if mnemonic == 'SUB':
            return self.sample_sub_scratch_patch(current_operands)
        if mnemonic == 'AND' and not registers.contains_register('RDX', current_operands) and \
           not registers.contains_register('RBX', current_operands):
            return self.and_scratch_patch
        if mnemonic == 'OR' and not registers.contains_register('RSI', current_operands) and \
           not registers.contains_register('RDI', current_operands):
            return self.or_patch
        if mnemonic == 'XOR' and not registers.contains_register('RCX', current_operands) and \
           not registers.contains_register('RDX', current_operands):
            return self.xor_patch
        return None

    def sample_add_register_patch(self):
        """ Samples an add substitution for a register-to-register add """
        add_patch = random()
        if add_patch <= 0.25:
            return self.add_register_patch_1
        if add_patch <= 0.5:
            return self.add_register_patch_2
        elif add_patch <= 0.75:
            return self.add_register_patch_3
        return self.add_register_patch_4

    def sample_add_scratch_patch(self, current_operands):
        """ Samples an add substitution that uses extra scratch registers """
        scratch_patch = random()
        if scratch_patch <= 0.25 and not registers.contains_register('RAX', current_operands):
            return self.add_scratch_patch_1
        if scratch_patch <= 0.5 and not registers.contains_register('RBX', current_operands):
            return self.add_scratch_patch_2
        if scratch_patch <= 0.75 and not registers.contains_register('RCX', current_operands):
            return self.add_scratch_patch_3
        if not registers.contains_register('RDI', current_operands):
            return self.add_scratch_patch_4
        return None

    def sample_sub_register_patch(self):
        """ Samples a sub substitution for a register-to-register add """
        sub_patch = random()
        if sub_patch <= 0.33:
            return self.sub_register_patch_1
        if sub_patch <= 0.66:
            return self.sub_register_patch_2
        return self.sub_register_patch_3

    def sample_sub_scratch_patch(self, current_operands):
        """ Samples a sub substitution that uses extra scratch registers """
        scratch_patch = random()
        if scratch_patch <= 0.33 and not registers.contains_register('RSI', current_operands):
            return self.sub_scratch_patch_1
        if scratch_patch <= 0.66 and not registers.contains_register('RDX', current_operands):
            return self.sub_scratch_patch_2
        if not registers.contains_register('RBX', current_operands):
            return self.sub_scratch_patch_3
        return None

    @patch_constraints(x86_syntax=X86Syntax.INTEL,
                       clobbers_registers=['EDI'])
    def expand_immediate_rdi(self, context):
        """ Expands op from immediate to op to register then
            mov from register """
        return self.generate_expansion_str('RDI')

    @patch_constraints(x86_syntax=X86Syntax.INTEL,
                       clobbers_registers=['ESI'])
    def expand_immediate_rsi(self, context):
        """ Expands op from immediate to op to register then
            mov from register """
        return self.generate_expansion_str('RSI')

    @patch_constraints(x86_syntax=X86Syntax.INTEL,
                       clobbers_registers=['EDX'])
    def expand_immediate_rdx(self, context):
        """ Expands op from immediate to op to register then
            mov from register """
        return self.generate_expansion_str('RDX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL,
                       clobbers_registers=['EBX'])
    def expand_immediate_rbx(self, context):
        """ Expands op from immediate to op to register then
            mov from register """
        return self.generate_expansion_str('RBX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL,
                       clobbers_registers=['EAX'])
    def expand_immediate_rax(self, context):
        """ Expands op from immediate to op to register then
            mov from register """
        return self.generate_expansion_str('RAX')
 
    @patch_constraints(x86_syntax=X86Syntax.INTEL,
                       clobbers_registers=['ECX'])
    def expand_immediate_rcx(self, context):
        """ Expands op from immediate to op to register then
            mov from register """
        return self.generate_expansion_str('RCX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def neg_to_not_patch(self, context):
        """ Replaces -x with ~x + 1 """
        (_, current_operands) = self.operands_queue.pop(0)
        return f"""not {current_operands[0]};
                   add {current_operands[0]},1;
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def add_one_patch(self, context):
        """ Replace x+1 with -~x """
        (_, current_operands) = self.operands_queue.pop(0)
        return f"""not {current_operands[0]};
                   neg {current_operands[0]}; 
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def sub_one_patch(self, context):
        """ Replace x-1 with ~-x """
        (_, current_operands) = self.operands_queue.pop(0)
        return f"""neg {current_operands[0]};
                   not {current_operands[0]};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def add_immediate_patch(self, context):
        """ Replace add reg,x with sub reg,-x """
        (_, current_operands) = self.operands_queue.pop(0)
        immediate = int(current_operands[1],0) * -1
        return f"""sub {current_operands[0]},{str(immediate)}
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def sub_immediate_patch(self, context):
        """ Replace sub reg,x with add reg,-x """
        (_, current_operands) = self.operands_queue.pop(0)
        immediate = int(current_operands[1],0) * -1
        return f"""add {current_operands[0]},{str(immediate)}
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def add_register_patch_1(self, context):
        """ Returns b - (-c) """
        (_, current_operands) = self.operands_queue.pop(0)
        return f"""neg {current_operands[1]}; 
                   sub {current_operands[0]},{current_operands[1]};
                   neg {current_operands[1]};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def add_register_patch_2(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        return f"""neg {current_operands[1]};
                   neg {current_operands[0]};
                   add {current_operands[0]},{current_operands[1]};
                   neg {current_operands[0]};
                   neg {current_operands[1]};
                """ 

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def add_register_patch_3(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        val = randint(0,100000000)
        return f"""add {current_operands[0]},{val};
                   add {current_operands[0]},{current_operands[1]};
                   sub {current_operands[0]},{val};
                """ 

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def add_register_patch_4(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        val = randint(0,100000000)
        return f"""sub {current_operands[0]},{val};
                   add {current_operands[0]},{current_operands[1]};
                   add {current_operands[0]},{val};
                """ 

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EAX'])
    def add_scratch_patch_1(self, context):
        """ Replaces add instruction w/ immediate or memory"""
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RAX')
        return f"""mov {scratch},{current_operands[1]}; 
                   neg {scratch}; 
                   sub {current_operands[0]},{scratch};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EBX'])
    def add_scratch_patch_2(self, context):
        """ Replaces add instruction w/ immediate or memory"""
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RBX')
        return f"""mov {scratch},{current_operands[1]}; 
                   neg {scratch}; 
                   neg {current_operands[0]};
                   add {current_operands[0]},{scratch};
                   neg {current_operands[0]};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['ECX'])
    def add_scratch_patch_3(self, context):
        """ Replaces add instruction w/ immediate or memory"""
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RCX')
        val = randint(0,100000000)
        return f"""mov {scratch},{current_operands[1]}; 
                   add {current_operands[0]},{val};
                   add {current_operands[0]},{scratch};
                   sub {current_operands[0]},{val};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EDI'])
    def add_scratch_patch_4(self, context):
        """ Replaces add instruction w/ immediate or memory"""
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RDI')
        val = randint(0,100000000)
        return f"""mov {scratch},{current_operands[1]}; 
                   sub {current_operands[0]},{val};
                   add {current_operands[0]},{scratch};
                   add {current_operands[0]},{val};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def sub_register_patch_1(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        return f"""neg {current_operands[1]}; 
                   add {current_operands[0]},{current_operands[1]};
                   neg {current_operands[1]};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def sub_register_patch_2(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        val = randint(0,100000000)
        return f"""add {current_operands[0]},{val}; 
                   sub {current_operands[0]},{current_operands[1]};
                   sub {current_operands[0]},{val};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def sub_register_patch_3(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        val = randint(0,100000000)
        return f"""sub {current_operands[0]},{val}; 
                   sub {current_operands[0]},{current_operands[1]};
                   add {current_operands[0]},{val};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['ESI'])
    def sub_scratch_patch_1(self, context):
        """ Replaces add instruction w/ immediate or memory"""
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RSI')
        return f"""mov {scratch},{current_operands[1]}; 
                   neg {scratch}; 
                   add {current_operands[0]},{scratch};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EDX'])
    def sub_scratch_patch_2(self, context):
        """ Replaces add instruction w/ immediate or memory"""
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RDX')
        val = randint(0,100000000)
        return f"""mov {scratch},{current_operands[1]}; 
                   add {current_operands[0]},{val};
                   sub {current_operands[0]},{scratch};
                   sub {current_operands[0]},{val};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EBX'])
    def sub_scratch_patch_3(self, context):
        """ Replaces add instruction w/ immediate or memory"""
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RBX')
        val = randint(0,100000000)
        return f"""mov {scratch},{current_operands[1]}; 
                   sub {current_operands[0]},{val};
                   sub {current_operands[0]},{scratch};
                   add {current_operands[0]},{val};   
                """


    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EAX'])
    def and_register_patch(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        scratch = registers.determine_scratch(current_operands[0], 'RAX')
        return f"""mov {scratch},{current_operands[0]};
                   not {current_operands[1]}; 
                   xor {current_operands[0]},{current_operands[1]};
                   and {current_operands[0]},{scratch};
                   not {current_operands[1]}; 
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['EDX', 'EBX'])
    def and_scratch_patch(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        scratch1 = registers.determine_scratch(current_operands[0], 'RDX')
        scratch2 = registers.determine_scratch(current_operands[0], 'RBX')

        return f"""mov {scratch1},{current_operands[0]};
                   mov {scratch2},{current_operands[1]};
                   not {scratch2}; 
                   xor {current_operands[0]},{scratch2};
                   and {current_operands[0]},{scratch1};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['ESI', 'EDI'])
    def or_patch(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        scratch1 = registers.determine_scratch(current_operands[0], 'RSI')
        scratch2 = registers.determine_scratch(current_operands[0], 'RDI')
        return f"""mov {scratch1},{current_operands[0]};
                   mov {scratch2},{current_operands[1]};
                   and {current_operands[0]},{scratch2};
                   xor {scratch1},{scratch2};
                   or {current_operands[0]},{scratch1};
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers=['ECX', 'EDX'])
    def xor_patch(self, context):
        (_, current_operands) = self.operands_queue.pop(0)
        scratch1 = registers.determine_scratch(current_operands[0], 'RCX')
        scratch2 = registers.determine_scratch(current_operands[0], 'RDX')
        return f"""mov {scratch1},{current_operands[0]};
                   mov {scratch2},{current_operands[1]};
                   not {current_operands[0]};
                   and {current_operands[0]},{scratch2};
                   not {scratch2};
                   and {scratch1},{scratch2};
                   or {current_operands[0]},{scratch1};
                """
   


