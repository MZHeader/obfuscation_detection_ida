"""IDA Pro plugin entry point for the Obfuscation Detector.

Install by copying this file *and* the sibling `obfuscation_detection_ida/`
package into ``$IDA_USER_DIR/plugins/`` (e.g. ``~/.idapro/plugins/``).

Once loaded, an "Obfuscation Detection" entry appears under Edit > Plugins.
Clicking it opens a picker listing every heuristic so you can pick the one
you want (or "All heuristics + utils" to run everything).
"""

import os
import sys

import ida_idaapi
import ida_kernwin

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
from obfuscation_detection_ida.helpers import invalidate_function_cache
from obfuscation_detection_ida.views import show as show_results_view


PLUGIN_NAME = "Obfuscation Detection"
PLUGIN_HOTKEY = ""
PLUGIN_VERSION = "1.0"


# (label, callable, tooltip)
_ACTIONS = [
    ("Show Results View", show_results_view, "Open the dockable table of all findings"),
    ("All heuristics + utils", run_all, "Run every heuristic and utility"),
    ("State Machine", find_state_machines, "Detect state machines / control-flow flattening"),
    ("Complex Function", find_complex_functions, "Rank functions by cyclomatic complexity"),
    ("Large Basic Block", find_large_basic_blocks, "Functions with unusually large basic blocks"),
    ("Overlapping Instruction", find_instruction_overlapping, "Bytes decoded as multiple instructions"),
    ("Uncommon Instruction Sequence", find_uncommon_instruction_sequences, "Rare 3-gram opcode sequences"),
    ("Most Called Function", find_most_called_functions, "Functions with the most callers"),
    ("Loop Frequency", find_loop_frequency_functions, "Functions with many natural loops"),
    ("Irreducible Loop", find_irreducible_loops, "Functions containing irreducible loops"),
    ("XOR Decryption Loop", find_xor_decryption_loops, "Loops that XOR by a constant"),
    ("Complex Arithmetic Expression", find_complex_arithmetic_expressions, "Mixed-boolean-arithmetic (Hex-Rays required)"),
    ("Duplicate Subgraph", find_duplicated_subgraphs, "Repeated CFG substructures"),
    ("Utils: Entry Function", find_entry_functions, "Functions without callers"),
    ("Utils: Leaf Function", find_leaf_functions, "Functions without callees"),
    ("Utils: Recursive Function", find_recursive_functions, "Self-recursive functions"),
    ("Utils: Section Entropy", compute_section_entropy, "Entropy of each segment"),
    ("Utils: RC4", find_rc4, "Possible RC4 KSA / PRGA implementations"),
]


class _HeuristicChooser(ida_kernwin.Choose):
    def __init__(self):
        ida_kernwin.Choose.__init__(
            self,
            "Obfuscation Detection",
            [["Heuristic", 35 | ida_kernwin.Choose.CHCOL_PLAIN],
             ["Description", 65 | ida_kernwin.Choose.CHCOL_PLAIN]],
            flags=ida_kernwin.Choose.CH_MODAL,
        )
        self.items = [[label, tip] for label, _, tip in _ACTIONS]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]


def _open_chooser():
    ch = _HeuristicChooser()
    idx = ch.Show(modal=True)
    if idx < 0:
        return
    label, fn, _ = _ACTIONS[idx]
    # Opening the results view is a UI action, not an analysis pass; skip
    # the cache flush so it stays snappy.
    if fn is not show_results_view:
        invalidate_function_cache()
    try:
        fn()
    except Exception as ex:
        print("[obfdet] %s failed: %s" % (fn.__name__, ex))
        import traceback
        traceback.print_exc()


class ObfuscationDetectionPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Automatically detect obfuscated code and other interesting constructs"
    help = "See README.md"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print("[obfdet] Obfuscation Detection %s loaded." % PLUGIN_VERSION)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _open_chooser()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ObfuscationDetectionPlugin()
