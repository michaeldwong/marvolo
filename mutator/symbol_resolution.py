
from helpers import instructions
from helpers import operands 
from typing import Optional

import capstone
import capstone.x86
import gtirb

def operand_size_to_str(size: int, instruction) -> str:
    """
    Gets the assembly operand type for a given size in bytes.
    """
    if size == 1:
        return "BYTE"
    if size == 2:
        return "WORD"
    if size == 4:
        return "DWORD"
    if size == 8:
        return "QWORD"
    if size == 10:
        return "XWORD"
    if size == 16:
        return "XMMWORD"
    if size == 32:
        return "YMMWORD"
    if size == 64:
        return "ZMMWORD"
    print(f'Unsupported size: {size} --- {instruction.opcode} {instruction.op_str}')
    raise ValueError(f"unsupported size: {size}")

def hex_if_needed(value: int) -> str:

    if abs(value) >= 10:
        return hex(value)
    return str(value)

def symbolic_expression_to_str(
    expression: gtirb.SymbolicExpression, extra_displacement: int = 0
) -> str:
    """
    Converts a symbolic expression to an equivalent assembly string (in Intel
    syntax).
    """
    # TODO: Deal with symbolic expression attributes
    if expression.attributes:
        pass
#        raise NotImplementedError(
#            "symbolic expression attributes not supported"
#        )

    if isinstance(expression, gtirb.SymAddrConst):
        result = expression.symbol.name
        offset = expression.offset + extra_displacement
        if offset:
            result += f" + {offset}"
        return result

    elif isinstance(expression, gtirb.SymAddrAddr):
        # TODO: Implement this once gtirb-rewriting supports it
        raise NotImplementedError("SymAddrAddr not supported")
    else:
        assert False, "Unsupported symbolic expression type"

def mem_access_to_str(
    instruction: capstone.CsInsn,
    mem: capstone.x86.X86OpMem,
    symbolic_expression: gtirb.SymbolicExpression = None,
    extra_displacement: int = 0,
) -> str:
    """
    Converts a Capstone memory reference into an equivalent assembly
    string (in Intel syntax).
    :param instruction: The insnruction containing the operand.
    :param mem: The memory operation.
    :param symbolic_expression: The symbolic expression for the displacement.
    :param extra_displacement: A value to be added to the displacement.
    """

    fields = []
    if mem.base != capstone.x86.X86_REG_INVALID:
        fields.append(instruction.reg_name(mem.base).upper())

    if mem.index != capstone.x86.X86_REG_INVALID:
        index_and_scale = instruction.reg_name(mem.index).upper()
        if mem.scale != 1:
            index_and_scale += "*" + str(mem.scale)
        fields.append(index_and_scale)
    if symbolic_expression:
        fields.append(symbolic_expression_to_str(symbolic_expression, extra_displacement))
    elif mem.disp + extra_displacement:
        fields.append(hex_if_needed(mem.disp + extra_displacement))
    elif not fields:
        fields.append("0")

    segment = ""
    if mem.segment != capstone.x86.X86_REG_INVALID:
        segment = instruction.reg_name(mem.segment).upper() + ":"

    return f"{segment}[" + " + ".join(fields) + "]"

def operand_to_str(
    instruction: capstone.CsInsn,
    operand: capstone.x86.X86Op,
    symbolic_expression: gtirb.SymbolicExpression,
    idx: int,
    extra_displacement: int = 0
) -> str:

    """
    Converts a Capstone operand into an equivalent assembly string (in Intel
    syntax).
    :param instruction: The insnruction containing the operand.
    :param op: The operand.
    :param symbolic_expression: The symbolic expression for the operand.
    :param extra_displacement: An extra displacement to use for memory
           operands.
    """

    if operand.type == capstone.x86.X86_OP_MEM:
        mem = mem_access_to_str(instruction, operand.mem, symbolic_expression, extra_displacement)
        size = operand_size_to_str(operand.size, instruction)
        return f"{size} PTR {mem}"

    if operand.type == capstone.x86.X86_OP_REG:
        assert not extra_displacement
        assert not symbolic_expression
        return instruction.reg_name(operand.reg).upper()

    if operand.type == capstone.x86.X86_OP_IMM:
        assert not extra_displacement
        if symbolic_expression:
            mnemonic = instruction.mnemonic.upper()
            if not instructions.is_jmp(mnemonic) and mnemonic != 'CALL' and idx == len(instruction.operands) - 1:
                new_ref = f'OFFSET {symbolic_expression_to_str(symbolic_expression)}'
            else:
                new_ref = f'{symbolic_expression_to_str(symbolic_expression)}'
            return new_ref
        return hex_if_needed(operand.imm)
    raise ValueError(f"unsupported operand type: {operand.type}")

def operand_symbolic_expression(
    block: gtirb.CodeBlock, instruction: capstone.CsInsn, operand: capstone.x86.X86Op
) -> Optional[gtirb.SymbolicExpression]:

    instruction_offset = instruction.address - block.byte_interval.address
    byte_interval_disp = instruction.address - block.byte_interval.address + instruction.disp_offset
    byte_interval_imm = instruction.address - block.byte_interval.address + instruction.imm_offset
    block_disp = instruction.address - block.address + instruction.disp_offset
    block_imm = instruction.address - block.address + instruction.imm_offset
    if operand.type == capstone.x86.X86_OP_MEM:
        if byte_interval_disp in block.byte_interval.symbolic_expressions:
            return block.byte_interval.symbolic_expressions.get(
                byte_interval_disp, None
            )
    if operand.type == capstone.x86.X86_OP_IMM:
        if byte_interval_imm in block.byte_interval.symbolic_expressions:
            return block.byte_interval.symbolic_expressions.get(
                byte_interval_imm, None
            )
    return None

def try_operand_to_symbolic_str(operand, symbolic_references):
    
    if operands.is_memory_access(operand):
        start = operand.index('[')
        end = operand.index(']')
        val = operand[start+1:end]
        if len(val) > 6 and operands.is_hex_operand(val):
            symbol = '.L_' + val[2:].lower()
            if symbol in symbolic_references:
                return f'{operand[:start+1]}{symbol}{operand[end:]}'
    else:
        # Immediate operand
        if len(val) > 6 and operands.is_hex_operand(val):
            symbol = '.L_' + val[2:].lower()
            if symbol in symbolic_references:
                return f'OFFSET {symbol}'
    return None

def instruction_to_str(block: gtirb.CodeBlock, instruction: capstone.CsInsn, 
                    symbolic_references: [str]) -> str:
    op_strs = []
    for i,op in enumerate(instruction.operands):
        symbolic_expression = operand_symbolic_expression(block, instruction, op)
        if symbolic_expression == None and op.type == capstone.x86.X86_OP_MEM:
            new = try_operand_to_symbolic_str(current_operands[i], symbolic_references)
            if new != None:
                op_strs.append(new)
                continue
        op_strs.append(operand_to_str(instruction, op, symbolic_expression, i))
    return (instruction.mnemonic.upper(), ", ".join(op_strs))


