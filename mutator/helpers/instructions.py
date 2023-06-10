
from enum import Enum, auto
from helpers import instruction_lists
from helpers import registers
from helpers import operands

import gtirb

def is_jmp(mnemonic):
    """ Determines if mnemonic is jmp instruction """
    mnemonic = mnemonic.upper() 
    return mnemonic[0] == 'J' or 'JMP' in mnemonic

class PassType(Enum):
    OUTLINE = auto()
    REASSIGN = auto()
    TRANSPOSE = auto()

def is_instruction_relocatable(instruction, pass_type=PassType.REASSIGN):
    """ Determines if the given instruction is able to be relocated to
        another position within a block. This is used to determine valid
        slices for the transposition pass and register reassignment pass.
        Currently doesn't support registers using 8-bit and 16-bit registers
        as operands """
    assert pass_type in [ 
        PassType.OUTLINE, 
        PassType.REASSIGN, 
        PassType.TRANSPOSE 
    ]
    if pass_type == PassType.REASSIGN:
        allowed_instructions = [ insn for insn in instruction_lists.relocatable_whitelist 
                if insn not in instruction_lists.reassignment_blacklist ]
    elif pass_type == PassType.OUTLINE:
        allowed_instructions = [ insn for insn in instruction_lists.relocatable_whitelist 
                if insn not in instruction_lists.outlining_blacklist ]
    else:
        allowed_instructions = instruction_lists.relocatable_whitelist
    mnemonic = instruction.mnemonic.upper()
    if mnemonic in allowed_instructions:
        current_operands = operands.separate_operands(instruction.op_str)
        if invalid_reassign_exceptions(mnemonic, current_operands, pass_type):
            return False
        for op in current_operands:
            op = op.upper()
            if pass_type == PassType.REASSIGN and \
               (op in registers.registers16 or op in registers.registers8):
                return False
            if registers.contains_segment_register(op) or 'RIP' in op or 'EIP' in op:
                return False
        return True
    return False

def invalid_reassign_exceptions(mnemonic, current_operands, pass_type):
    """ Specific cases where the instruction is invalid for reassignment
    despite being a valid mnemonic """
    if pass_type != 'REASSIGN':
        return False
    # imul with 1 operand affects RDX:RAX so reassignment could mess up semantics
    if mnemonic == 'IMUL' or mnemonic == 'MUL' and len(current_operands) == 1:
        return True
    return False

def is_prologue_instruction(instruction):
    """ Determines if an instruction belongs in the function prologue. I.e., 
        returns true if instruction is "push RBP" or "mov RBP,RSP" """
    mnemonic = instruction.mnemonic.upper()
    is_push = mnemonic == 'PUSH'
    is_mov = mnemonic == 'MOV'
    if is_push or is_mov:
        current_operands = operands.separate_operands(instruction.op_str)
        first_operand = current_operands[0].upper()
        modifies_rbp = first_operand == 'RBP' or first_operand == 'EBP'
        return modifies_rbp
    is_enter = mnemonic == 'ENTER'
    if is_enter:
        return True
    return False

def is_epilogue_instruction(instruction):
    """ Determines if an instruction belongs in the function epilogue. I.e., 
        returns true if instruction is "pop RBP" or "mov RSP,RBP" """
    mnemonic = instruction.mnemonic.upper()
    is_pop = mnemonic == 'POP'
    is_mov = mnemonic == 'MOV'
    is_leave = mnemonic == 'LEAVE'
    if is_leave:
        return True
    if is_pop or is_mov:
        current_operands = operands.separate_operands(instruction.op_str)
        first_operand = current_operands[0].upper()
        modifies_rsp = first_operand == 'RSP' or first_operand == 'ESP'
        return modifies_rsp
    return False

