

from gtirb_rewriting import *

import re

functions_to_ignore = [ 'deregister_tm_clones', 'register_tm_clones', '_init', '__libc_csu_init', 
        '__do_global_dtors_aux', 'frame_dummy', '_start', '__libc_csu_fini'
                      ]
label_id = 0

def skip_function(function_name):
    """ True if the current function is one that won't impact the binary"""
    return function_name in functions_to_ignore


def sample_labels(num_labels=1):
    """ Generates fresh labels """
    global label_id
    labels = []
    for _ in range(0, num_labels):
        current_id = label_id
        label_id += 1
        labels.append('.L_' + str(current_id))
    return labels

def is_power_of_two(x):
    """ Determines if x is a power of 2 or not """
    if not isinstance(x, int):
        return False
    return x and (not (x & (x - 1))) 


def extract_symbolic_references(block):
    return [
        v.symbol.name 
            for v in block.byte_interval.symbolic_expressions.values()
                if hasattr(v, 'name')
    ]

