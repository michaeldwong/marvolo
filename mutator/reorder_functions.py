
from gtirb_rewriting import *
from random import *

import gtirb
import gtirb_functions

# TODO: This is still incomplete. Some functions are not reordered properly and 
# this reordering implementation can result in errors. Currently transforms.py 
# just rolls back the GTIRB representation to the previous version if function
# reordering introduces errors which is not ideal 

class ReorderFunctions(Pass):

    def begin_module(self, module, functions, context):
        self.reorder(module, functions)

    def reorder(self, module, functions):
        order_of_blocks = {}
        order_range = [ x for x in range(1, len(functions) + 1) ]
        shuffle(order_range)
        for idx, function in enumerate(functions):
            for block in function.get_all_blocks():
                order_of_blocks[block] = idx + 1
        alignment = None
        if "alignment" in module.aux_data:
            alignment = module.aux_data["alignment"].data
        text = next(
            sect for sect in module.sections if sect.name == ".text"
        )
        for interval in list(text.byte_intervals):
            def rank_bi(bi):
                for block in bi.blocks:
                    if block in order_of_blocks:
                        return order_of_blocks[block]
                return 0 
            partition = split_byte_interval(interval, alignment)
            partition.sort(key=rank_bi)
            join_byte_intervals(partition, ABI.get(module).nop(), alignment)
            for interval in partition[1:]:
                interval.section = None


