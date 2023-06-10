
from helpers import registers
from random import *

import re

immediate_operands = "^[0-9]+$"
hex_immediate_operands = "^0(x|X)[0-9a-fA-F]+$"
hex_immediate = "0(x|X)[0-9a-fA-F]+"

def separate_operands(op_str, capitalize=True):
    """ Takes in a comma-separated operand string from an instruction 
        and produces a list containing all of the elements """
    if len(op_str) == 0:
        return []
    return list(map(lambda s: 
        s.strip().upper() if capitalize else s.strip(), 
        op_str.split(',')
    )) 

def is_decimal(operand):
    """ Determines if operand is an immediate in decimal form"""
    if operand == None:
        return False
    return re.search(immediate_operands, operand) 

def is_immediate(operand):
    """ Determines if operand is an immediate """
    if operand == None:
        return False
    return re.search(immediate_operands, operand) or \
           re.search(hex_immediate_operands, operand)

def contains_hex(operand):
    """ Checks if the string contains any hex values. These values
        are normally constant offsets. """
    if operand == None:
        return False
    return re.search(hex_immediate, operand)

def is_hex_operand(operand):
    """ Checks if the string is a hex value """
    if operand == None:
        return False
    return re.search(hex_immediate_operands, operand)

def is_memory_access(operand):
    """ Determines if operand is a word ptr """
    return '[' in operand and ']' in operand 

def memory_access_registers(operand):
    """ Gets the register containing the memory address """
    if not is_memory_access(operand):
        return []
    start = operand.index('[')
    end = operand.index(']')
    access_registers = []
    register = ''
    for c in operand[start+1:end]:
        register += c.upper()
        if not register.isalnum():
            register = ''
            continue
        if registers.is_usable_register(register) or registers.is_invalid_register(register):
            access_registers.append(register)
            register = ''
    return access_registers

def extract_expression(operand):
    """ Gets the tokens from an expr used in a memory access.
        E.g., input operand of DWORD PTR[EBP + 8] results in
        [ EBP, +, 8 ] """
    if not is_memory_access(operand):
        return []
    start = operand.index('[')
    end = operand.index(']')
    tokens = []
    current_token = ''
    for c in operand[start+1:end]:
        if c == ' ':
            continue
        if is_operator(c):
            add_access_token(current_token, tokens)
            if tokens[-1] == '+' and c == '-':
                tokens[-1] = '-'
            else:
                tokens.append(c)
            current_token = ''
            continue
        current_token += c.upper()
        if registers.is_usable_register(current_token) or registers.is_invalid_register(current_token):
            add_access_token(current_token, tokens)
            current_token = ''
    add_access_token(current_token, tokens)
    return tokens

def add_access_token(current_token, tokens): 
    if len(current_token) > 0:
        if is_hex_operand(current_token):
            tokens.append(str(int(current_token, 16)))
        else:
            tokens.append(current_token)

def operand_data_size(operand):
    """ Determines the data size used in the operand """ 
    operand = operand.upper()
    if operand == None:
        return 0
    if registers.is_register64(operand) or 'QWORD PTR' in operand:
        return 64
    elif registers.is_register32(operand) or 'DWORD PTR' in operand:
        return 32
    elif operand in registers.registers16 or 'WORD PTR' in operand:
        return 16
    elif operand in registers.registers8 or 'BYTE PTR' in operand:
        return 8
    return 0

def replace_register(operand, old_register, new_register):
    """ Takes in a memory access and replaces the src register 
        with new_register """
    if old_register == None or new_register == None or operand == None:
        return None
    # Since 32-bit added registers just consist of the 64-bit register
    # name with a 'd' at the end, need to ignore cases where the operand
    # contains the 32-bit name if old_register is the 64-bit name
    if old_register in registers.added_registers64:
        register32 = registers.convert_to_register32(old_register)
        if register32 in operand.upper():
            return operand
    return operand.replace(old_register, new_register)


def is_operator(op):
    """ Check if str is an arith operator. Add more as needed """
    return op == '+' or op == '-' or op == '*' or op == '/'


