"""IDA Pro plugin entry point for the Obfuscation Detector.

Install by copying this file *and* the sibling `obfuscation_detection_ida/`
package into ``$IDA_USER_DIR/plugins/`` (e.g. ``~/.idapro/plugins/``).

Once loaded, an "Obfuscation Detection" submenu appears under Edit > Plugins,
and each heuristic is available from there. Findings are printed to the
Output window and attached to functions as repeatable comments prefixed with
``[obfdet]``.
"""

import os
import sys

import ida_idaapi
import ida_kernwin

# Make sure the sibling package is importable when IDA loads this file
# directly from the plugins directory.
_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from obfuscation_detection_ida import (
    compute_section_entropy,
    find_complex_arithmetic_expressions,
    find_complex_functions,
    find_duplicated_subgraphs,
    find_entry_functions,
    find_instruction_overlapping,
    find_irreducible_loops,
    find_large_basic_blocks,
    find_leaf_functions,
    find_loop_frequency_functions,
    find_most_called_functions,
    find_rc4,
    find_recursive_functions,
    find_state_machines,
    find_uncommon_instruction_sequences,
    find_xor_decryption_loops,
    run_all,
)


PLUGIN_NAME = "Obfuscation Detection"
PLUGIN_HOTKEY = ""
PLUGIN_VERSION = "1.0"


_ACTIONS = [
    # (id, label, callable, tooltip)
    ("obfdet:all", "All heuristics + utils", run_all, "Run every heuristic and utility"),
    ("obfdet:state_machine", "State Machine", find_state_machines, "Detect state machines / control-flow flattening"),
    ("obfdet:complex_function", "Complex Function", find_complex_functions, "Rank functions by cyclomatic complexity"),
    ("obfdet:large_basic_block", "Large Basic Block", find_large_basic_blocks, "Functions with unusually large basic blocks"),
    ("obfdet:overlapping", "Overlapping Instruction", find_instruction_overlapping, "Bytes decoded as multiple instructions"),
    ("obfdet:uncommon_seq", "Uncommon Instruction Sequence", find_uncommon_instruction_sequences, "Rare 3-gram opcode sequences"),
    ("obfdet:most_called", "Most Called Function", find_most_called_functions, "Functions with the most callers"),
    ("obfdet:loop_freq", "Loop Frequency", find_loop_frequency_functions, "Functions with many natural loops"),
    ("obfdet:irreducible", "Irreducible Loop", find_irreducible_loops, "Functions containing irreducible loops"),
    ("obfdet:xor_loop", "XOR Decryption Loop", find_xor_decryption_loops, "Loops that XOR by a constant"),
    ("obfdet:mba", "Complex Arithmetic Expression", find_complex_arithmetic_expressions, "Mixed-boolean-arithmetic (Hex-Rays required)"),
    ("obfdet:duplicate", "Duplicate Subgraph", find_duplicated_subgraphs, "Repeated CFG substructures"),
    ("obfdet:entry", "Utils/Entry Function", find_entry_functions, "Functions without callers"),
    ("obfdet:leaf", "Utils/Leaf Function", find_leaf_functions, "Functions without callees"),
    ("obfdet:recursive", "Utils/Recursive Function", find_recursive_functions, "Self-recursive functions"),
    ("obfdet:entropy", "Utils/Section Entropy", compute_section_entropy, "Entropy of each segment"),
    ("obfdet:rc4", "Utils/RC4", find_rc4, "Possible RC4 KSA / PRGA implementations"),
]


class _Handler(ida_kernwin.action_handler_t):
    def __init__(self, fn):
        ida_kernwin.action_handler_t.__init__(self)
        self._fn = fn

    def activate(self, ctx):
        try:
            self._fn()
        except Exception as ex:
            print("[obfdet] %s failed: %s" % (self._fn.__name__, ex))
            import traceback
            traceback.print_exc()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def _register_actions():
    for aid, label, fn, tip in _ACTIONS:
        desc = ida_kernwin.action_desc_t(aid, label, _Handler(fn), None, tip, -1)
        ida_kernwin.unregister_action(aid)  # idempotent
        ida_kernwin.register_action(desc)
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/Obfuscation Detection/" + label,
            aid,
            ida_kernwin.SETMENU_APP,
        )


def _unregister_actions():
    for aid, label, _, _ in _ACTIONS:
        ida_kernwin.detach_action_from_menu(
            "Edit/Plugins/Obfuscation Detection/" + label, aid
        )
        ida_kernwin.unregister_action(aid)


class ObfuscationDetectionPlugin(ida_idaapi.plugin_t):
    # PLUGIN_HIDE stops IDA from auto-adding an "Obfuscation Detection" leaf
    # under Edit > Plugins that would otherwise fire run() and block us from
    # attaching a real submenu at the same path.
    flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_FIX
    comment = "Automatically detect obfuscated code and other interesting constructs"
    help = "See README.md"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        _register_actions()
        print("[obfdet] Obfuscation Detection %s loaded." % PLUGIN_VERSION)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        run_all()

    def term(self):
        _unregister_actions()


def PLUGIN_ENTRY():
    return ObfuscationDetectionPlugin()
