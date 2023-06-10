
from gtirb_rewriting import *

import gtirb

class NopPass(Pass):

    """ Pass that inserts nops in random locations """
    def begin_module(self, module, functions, context):
        context.register_insert(
            AllBlocksScope(BlockPosition.ANYWHERE),
            Patch.from_function(self.nop_patch)            
        )

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def nop_patch(self, context):
        return "nop"

