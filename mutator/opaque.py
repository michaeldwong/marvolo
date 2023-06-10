
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import *
from helpers import utils 
from random import *

import gtirb

class OpaquePredicatePass(Pass):
    """ Pass that inserts opaque predicates that jump over a 
        sequence of random instructions 
        
        NOTE: All opaque predicate jump instructions have been replaced with
        unconditional jumps (i.e., jmp). When a conditional jump is
        encountered, gtirb-rewriting can't statically determine that
        the block of data that will be jumped over won't be executed
        and assumes that it is code (instead of data). The bytes are
        then disassembled and emitted as instrucitons in the generated
        asm file which will generate assembler errors. Future support
        may include a custom assembler directive which will allow 
        us to use the conditional jumps whilst ensuring that the bytes
        aren't interpreted as code.
    """
    def __init__(self, coverage_level, isa):
        # The opaque predicates add a lot of stuff to the binary
        # so use it more sparingly (0.05 vs 0.2 for other transforms) 
        self.opaque_prob = coverage_level * 0.05
        self.MIN_BYTES = coverage_level * 4 + 5
        self.MAX_BYTES = self.MIN_BYTES * 3
        self.isa = isa

    def begin_module(self, module, functions, context):
        decoder = GtirbInstructionDecoder(module.isa)
        guaranteed_insertion = self.opaque_prob == 1
        for function in functions:
            for block in function.get_all_blocks():
                if guaranteed_insertion or random() <= self.opaque_prob:
                    patch = self.sample_patch()
                    context.register_insert(
                        SingleBlockScope(block, BlockPosition.ANYWHERE),
                        Patch.from_function(patch)
                    )

    def sample_patch(self):
        """ Randomly generates an opaque predicate patch along w/ junk instructions """
        # NOTE: Adding opaque predicates frequently leads to incorrect results
        # for PE32s. For now, just insert unconditional jmp w/ bytes
        if self.isa == gtirb.module.Module.ISA.IA32 and random() <= 0.3:
            return self.simple_byte_jmp
        patch_type = random()
        num_patches = 12

        if patch_type <= (1 / num_patches):
            return self.sample_simple_predicate
        elif patch_type <= (2 / num_patches):
            return self.invariant_predicate_1
        elif patch_type <= (3 / num_patches):
            return self.invariant_predicate_2
        elif patch_type <= (4 / num_patches):
            return self.invariant_predicate_3
        elif patch_type <= (5 / num_patches):
            return self.invariant_predicate_4
        elif patch_type <= (6 / num_patches):
            return self.invariant_predicate_5
        elif patch_type <= (7 / num_patches):
            return self.invariant_predicate_6
        elif patch_type <= (8 / num_patches):
            return self.invariant_predicate_7
        elif patch_type <= (9 / num_patches):
            return self.contextual_predicate_1
        elif patch_type <= (10 / num_patches):
            return self.contextual_predicate_2
        elif patch_type <= (11 / num_patches):
            return self.contextual_predicate_3
        return self.contextual_predicate_4

    def get_usable_register(self, register):
        if self.isa == gtirb.module.Module.ISA.IA32:
            return f'{register:32}'
        return register

    def get_div_registers(self):
        """ Gets the proper version of RAX and RDX depending on whether
            binary is 32-bit or 64-bit"""
        if self.isa == gtirb.module.Module.ISA.IA32:
            return ('EAX', 'EDX')
        return ('RAX', 'RDX')

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def simple_byte_jmp(self, context):
        label = utils.sample_labels()[0]
        junk_data = self.generate_junk_data()
        return f"""jmp {label};
                   {junk_data};
                   {label}:
                """      

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=1)
    def sample_simple_predicate(self, context, register1):
        """ Generates a simple opaque predicate """
        label = utils.sample_labels()[0]
        register = self.get_usable_register(register1)
        opaque_predicate_str = self.invariant_predicate_simple(register, label)
        junk_data = self.generate_junk_data()
        return f"""{opaque_predicate_str}; 
                   {junk_data};
                   {label}:
                """
               
    def invariant_predicate_simple(self, register1, label):
        """ Generates simple opaque predicate that uses different jmp instructions """
        val1 = randint(0, 10)
        val2 = randint(0, 10)
        jmp_type = random()
        if val1 < val2:
            if jmp_type <= 0.4:
                jmp_instruction = 'jl'
            elif jmp_type <= 0.8:
                jmp_instruction = 'jle' 
            else:
                jmp_instruction = 'jne'
        elif val1 > val2:
            if jmp_type <= 0.4:
                jmp_instruction = 'jg'
            elif jmp_type <= 0.8:
                jmp_instruction = 'jge' 
            else:
                jmp_instruction = 'jne'
        else:
            jmp_instruction = 'je'
           
        return f"""mov {register1},{val1}; 
                   cmp {register1},{val2}; 
                   jmp {label}; 
                """
    
    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=1)
    def invariant_predicate_1(self, context, register1):
        """ x^2 >= 0 """
        junk_data = self.generate_junk_data()
        val = randint(0, 10000000)
        register = self.get_usable_register(register1)
        label = utils.sample_labels()[0]
        return f"""mov {register},{val};
                   imul {register},{register};
                   cmp {register},0;
                   jmp {label};
                   {junk_data};
                   {label}:
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers={'EAX', 'EDX'}, 
                       scratch_registers=1)
    def invariant_predicate_2(self, context, register1):
        """ (x^2 + 1) % 7 != 0 """ 
        junk_data = self.generate_junk_data()
        val = randint(0,10000000)
        register = self.get_usable_register(register1)
        (rax_register, rdx_register) = self.get_div_registers()
        label = utils.sample_labels()[0]
        return f"""mov {rax_register},{val};
                   imul {rax_register},{rax_register};
                   add {rax_register},1;
                   xor {rdx_register},{rdx_register};
                   mov {register},7;
                   div {register};
                   cmp {rdx_register},0;
                   jmp {label};
                   {junk_data};
                   {label}:
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers={'EAX', 'EDX'}, 
                       scratch_registers=1)
    def invariant_predicate_3(self, context, register1):
        """ (4x^2 + 4) % 19 != 0 """
        junk_data = self.generate_junk_data()
        val = randint(0,10000000)
        (rax_register, rdx_register) = self.get_div_registers()
        register = self.get_usable_register(register1)
        label = utils.sample_labels()[0]
        return f"""mov {rax_register},{val};
                   imul {rax_register},{rax_register};
                   imul {rax_register},4;
                   add {rax_register},4;
                   xor {rdx_register},{rdx_register};
                   mov {register},19;
                   div {register};
                   cmp {rdx_register},0;
                   jmp {label};
                   {junk_data};
                   {label}:
                 """       

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers={'EAX', 'EDX'}, 
                       scratch_registers=1)
    def invariant_predicate_4(self, context, register1):
        """ (x^2 + x + 7) % 81 != 0 """
        junk_data = self.generate_junk_data()
        val = randint(0,10000000)
        (rax_register, rdx_register) = self.get_div_registers()
        register = self.get_usable_register(register1)
        label = utils.sample_labels()[0]
        return f"""mov {rax_register},{val};
                   mov {register},{rax_register};
                   imul {rax_register},{rax_register};
                   add {rax_register},{register};
                   add {rax_register},7;
                   xor {rdx_register},{rdx_register};
                   mov {register},81;
                   div {register};
                   cmp {rdx_register},0;
                   jmp {label};
                   {junk_data};
                   {label}:
                 """
   
    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers={'EAX', 'EDX'}, 
                       scratch_registers=1)
    def invariant_predicate_5(self, context, register1):
        """ 2 | x (x + 1) """
        junk_data = self.generate_junk_data()
        val = randint(0,10000000)
        register = self.get_usable_register(register1)
        (rax_register, rdx_register) = self.get_div_registers()
        label = utils.sample_labels()[0]
        return f"""mov {rax_register},{val};
                   mov {register},{rax_register};
                   add {rax_register},1;
                   imul {rax_register},{register};
                   xor {rdx_register},{rdx_register};
                   mov {register},2;
                   div {register};
                   cmp {rdx_register},0;
                   jmp {label};
                   {junk_data};
                   {label}:
                 """ 

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers={'EAX', 'EDX'}, 
                       scratch_registers=1)
    def invariant_predicate_6(self, context, register1):
        """ 3 | x (x + 1) (x + 2) """
        junk_data = self.generate_junk_data()
        val = randint(0,10000000)
        (rax_register, rdx_register) = self.get_div_registers()
        register = self.get_usable_register(register1)
        label = utils.sample_labels()[0]
        return f"""mov {rax_register},{val};
                   mov {register},{rax_register};
                   add {rax_register},1;
                   imul {rax_register},{register};
                   add {register},2;
                   imul {rax_register},{register};
                   xor {rdx_register},{rdx_register};
                   mov {register},3;
                   div {register};
                   cmp {rdx_register},0;
                   jmp {label};
                   {junk_data}; 
                   {label}:
                 """ 

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers={'EAX', 'EDX'}, 
                       scratch_registers=1)
    def invariant_predicate_7(self, context, register1):
        """ 4 | x^2 (x + 1) (x + 1) """
        junk_data = self.generate_junk_data()
        val = randint(0,10000000)
        (rax_register, rdx_register) = self.get_div_registers()
        register = self.get_usable_register(register1)
        label = utils.sample_labels()[0]
        return f"""mov {rax_register},{val};
                   mov {register},{rax_register};
                   imul {rax_register},{rax_register};
                   add {register},1;
                   imul {rax_register},{register};
                   imul {rax_register},{register};
                   xor {rdx_register},{rdx_register};
                   mov {register},4;
                   div {register};
                   cmp {rdx_register},0;
                   jmp {label};
                   {junk_data};
                   {label}:
                 """ 


    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=1)
    def contextual_predicate_1(self, context, register1):
        """ x > 5 => x > 0 """
        junk_data = self.generate_junk_data()
        val = randint(6, 10000000)
        register = self.get_usable_register(register1)
        label = utils.sample_labels()[0]
        return f"""mov {register},{val};
                   cmp {register},5;
                   jmp {label};
                   {junk_data};
                   {label}:
                """


    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=2)
    def contextual_predicate_2(self, context, register1, register2):
        """ x > 3 => x^2 - 4x + 3 > 0 """
        val = randint(4, 10000000) 
        junk_data = self.generate_junk_data()
        register1 = self.get_usable_register(register1)
        register2 = self.get_usable_register(register2)
        label = utils.sample_labels()[0]
        return f"""mov {register1},{val};
                   mov {register2},{register1};
                   imul {register1},{register1};
                   imul {register2},4;
                   sub {register1},{register2};
                   add {register1},3;
                   cmp {register1},0;
                   jmp {label};
                   {junk_data};
                   {label}:
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       scratch_registers=3)
    def contextual_predicate_3(self, context, register1, register2, register3):
        """ (NOT 2 | x and NOT 2 | y) => x^2 + y^2 != z^2 """
        junk_data = self.generate_junk_data()
        val1 = randint(0,10000000)
        val2 = randint(0,10000000)
        register1 = self.get_usable_register(register1)
        register2 = self.get_usable_register(register2)
        register3 = self.get_usable_register(register3)
        label = utils.sample_labels()[0]
        return f"""mov {register1},{val1};
                   mov {register2},{val2};
                   imul {register1},{register1};
                   imul {register2},{register2};
                   add {register1},{register2};
                   imul {register3},{register3};
                   cmp {register1},{register3};
                   jmp {label};
                   {junk_data};
                   {label}:
                """

    @patch_constraints(x86_syntax=X86Syntax.INTEL, 
                       clobbers_registers={'EAX', 'EDX'}, 
                       scratch_registers=1)
    def contextual_predicate_4(self, context, register1):
        """ x % divisor * k == 0 => x % divisor = 0 """
        divisor = randint(2, 9)
        dividend = divisor * randint(0, 20)  
        register = self.get_usable_register(register1)
        (rax_register, rdx_register) = self.get_div_registers()
        junk_data = self.generate_junk_data()
        label = utils.sample_labels()[0]
        return f"""mov {rax_register},{dividend};
                   mov {register},{divisor};  
                   xor {rdx_register},{rdx_register};
                   div {register};
                   cmp {rdx_register},0;
                   jmp {label};
                   {junk_data};
                   {label}: 
                """ 

    def generate_junk_data(self):
        """ Samples a random byte sequence """
        num_bytes = randint(self.MIN_BYTES, self.MAX_BYTES)
        byte_sequence = '' 
        for i in range(num_bytes):
            byte_sequence += self.sample_asm_byte() + ';\n'
        return byte_sequence

    def sample_asm_byte(self): 
        """ Samples random byte and returns in string: .byte 0x00 """
        rand_byte_str = str(hex(randint(0,255)))
        l = len(rand_byte_str)
        # String is in format: "b'\\x00'"; need to extract the 2 bytes
        # for the hex byte
        short_str = rand_byte_str[l-2 : l]
        # This mnemonic is invalid
        if short_str[0] == 'x':
            return '.BYTE 0x' + short_str[1].upper()
        return '.BYTE 0x' + short_str.upper()
          


