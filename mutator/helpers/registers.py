

from helpers import operands 
from random import *

import re

invalid_registers = [ 'EBP', 'RBP', 'ESP,' 'RSP', 'EIP', 'RIP', 
    'BP', 'SP', 'IP' ]
usable_registers64 = [ 'RAX', 'RDX', 'RDI', 'RBX', 'RCX', 'RSI', 
    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15' ]
usable_registers32 = [ 'EAX', 'EDX', 'EDI', 'EBX', 'ECX', 'ESI',  
    'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D' ]
added_registers64 = [ 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 
    'R14', 'R15' ]
added_registers32 = [ 'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 
    'R14D', 'R15D' ]
orig_registers64 = [ 'RAX', 'RBX', 'RCX', 'RDX', 'RBP', 'RSP', 
    'RSI', 'RDI', 'RIP' ]
orig_registers32 = [ 'EAX', 'EBX', 'ECX', 'EDX', 'EBP', 'ESP', 
    'ESI', 'EDI', 'EIP' ]
registers16 = [ 'AX', 'BX', 'CX', 'DX', 'SI', 'DI', 'SP', 'BP', 'IP' ]
registers8 = [ 'AH', 'AL', 'BH', 'BL', 'CH', 'CL', 'DH', 'DL' ]
segment_registers = [ 'FS', 'CS', 'GS', 'SS', 'DS', 'ES' ]

# Used to determine which registers share the same storage space
register_buckets = {
    'RAX' : 0, 'EAX' : 0, 'AX' : 0, 'AH' : 0, 'AL' : 0,
    'RBX' : 1, 'EBX' : 1, 'BX' : 1, 'BH' : 1, 'BL' : 1,
    'RCX' : 2, 'ECX' : 2, 'CX' : 2, 'CH' : 2, 'CL' : 2,
    'RDX' : 3, 'EDX' : 3, 'DX' : 3, 'DH' : 3, 'DL' : 3,
    'RSI' : 4, 'ESI' : 4, 'SI' : 4,
    'RDI' : 4, 'EDI' : 4, 'DI' : 4,
    'RBP' : 4, 'EBP' : 4, 'BP' : 4,
    'RSP' : 4, 'ESP' : 4, 'SP' : 4,
    'R8' : 5, 'R8D' : 5, 'R9' : 6, 'R9D' : 6,
    'R10' : 7, 'R10D' : 7, 'R11' : 8, 'R11D' : 8,
    'R12' : 9, 'R12D' : 9, 'R13': 10, 'R13D' : 10,
    'R14' : 10, 'R14D' : 10, 'R15' : 11, 'R15D' : 11
}


def is_usable_register(operand):
    if operand == None:
        return False
    op = operand.upper()
    return op in usable_registers64 or op in usable_registers32

def is_added_register(operand):
    if operand == None:
        return False
    op = operand.upper()
    return op in added_registers64 or op in added_registers32

def sample_register64(current_register=''):
    """ Need to manually sample a scratch register so we don't
        get one that's the same as current register"""
    idx = randint(0, len(usable_registers64) - 1)
    tmp_register = usable_registers64[idx]
    while current_register == tmp_register:
        idx = randint(0, len(usable_registers64) - 1)
        tmp_register = usable_registers64[idx]
    return tmp_register

def sample_register32(current_register=''):
    """ Need to manually sample a scratch register so we don't
        get one that's the same as current register"""
    idx = randint(0, len(usable_registers32) - 1)
    tmp_register = usable_registers32[idx]
    # R8-R15 registers not allowed in 32-bit
    while current_register == tmp_register or tmp_register in added_registers32:
        # index 5 marks the end of valid IA32 registers
        idx = randint(0, 5)
        tmp_register = usable_registers32[idx]
    return tmp_register

def is_register(operand):
    """ Determines if operand is a valid register for patching. Doesn't include
        segment registers """
    if operand == None:
        return False
    return operand in usable_registers32 or \
           operand in registers16 or \
           operand in registers8 or \
           operand in usable_registers64 

def is_invalid_register(operand):
    """ Determines if operand is an invalid register for patching """
    return operand in invalid_registers

def is_register32(operand):
    """ Determines if operand is a 32-bit register """
    if operand == None:
        return False
    return operand in usable_registers32 or operand in [ 'ESP', 'EIP', 'EBP' ]

def is_register64(operand):
    """ Determines if operand is a 64-bit register """
    if operand == None:
        return False
    return operand in usable_registers64 or operand in [ 'RSP', 'RIP', 'RBP' ]

def convert_to_register64(operand):
    """ Converts a string register operand to 64-bit string representation """
    if operand == None:
        return None
    operand = operand.upper()
    if operand in orig_registers64 or operand in added_registers64:
        return operand
    elif operand in orig_registers32:
        new_register = 'R'
        new_register += operand[1:]
        return new_register
    elif operand in added_registers32:
        return operand[:-1]
    return operand

def convert_to_register32(operand):
    """ Converts a string register operand to 64-bit string representation """
    if operand == None:
        return operand
    operand = operand.upper()
    if operand in orig_registers32 or operand in added_registers32:
        return operand
    elif operand in orig_registers64:
        new_register = 'E'
        new_register += operand[1:]
        return new_register
    elif operand in added_registers64:
        return operand + 'D'
    return operand

def register_size_differ(register1, register2):
    """ Determines if the registers are of different sizes """
    return len(register1) != len(register2) or register1[0] != register2[0]

def dependency_found(register1, register2):
    """ Determines if the register names alias the same register.
        For instance, rax and eax are determined to be equal. """
    if register1 == None or register2 == None:
        return False
    if register1 == register2:
        return True
    if register1 in register_buckets and register2 in register_buckets:
        return register_buckets[register1] == register_buckets[register2]
    return False

def contains_register(register, current_operands):
    """ Checks if a list of operands contains register """
    register32 = convert_to_register32(register)
    register64 = convert_to_register64(register)
    return register32 in current_operands or register64 in current_operands

def uses_registers(registers, operand):
    """ Checks if a list of registers are used in the operand"""
    for register in registers:
        if not contains_register(register, operand):
            return False
    return True

def contains_segment_register(op_str):
    """ Checks if segment register is being used in operand str """
    if op_str == None:
        return False
    op_str = op_str.upper()
    for register in segment_registers:
        if register + ':' in op_str:
            return True
    return False

def determine_scratch(operand, clobbered_register):
    """ Given an existing operand, determine its data size and use
        that info to return the correct sized version of clobbered_register"""
    if operand == None:
        return clobbered_register
    if operands.operand_data_size(operand) == 32:
        return convert_to_register32(clobbered_register)
    return clobbered_register


