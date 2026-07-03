"""User-facing entry points: print findings, tag functions, colour overlapping
instructions in the disassembly view."""

import ida_bytes
import idautils
import idc

from .helpers import compute_overlapping_instruction_addresses
from .reports import (
    find_complex_arithmetic_expression_reports,
    find_complex_function_reports,
    find_duplicate_subgraph_reports,
    find_fragmented_function_reports,
    find_instruction_overlapping_reports,
    find_irreducible_loop_reports,
    find_large_basic_block_reports,
    find_loop_frequency_reports,
    find_most_called_function_reports,
    find_state_machine_reports,
    find_uncommon_instruction_sequence_reports,
    find_xor_decryption_loop_reports,
)
from .tagging import (
    TAG_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_COMPLEX_FUNCTION,
    TAG_DUPLICATE_SUBGRAPH,
    TAG_IRREDUCIBLE_LOOP,
    TAG_LARGE_BASIC_BLOCK,
    TAG_LOOP_FREQUENCY,
    TAG_MOST_CALLED_FUNCTION,
    TAG_OVERLAPPING_INSTRUCTION,
    TAG_STATE_MACHINE,
    TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
    TAG_XOR_DECRYPTION_LOOP,
    TAG_FRAGMENTED_FUNCTION,
    annotate_ea,
    clear_heuristic_tags,
    tag_function,
)
from .views import results_view

_HIGHLIGHT_COLOUR = 0x00FFFF  # RGB yellow (BGR in set_color)


def _print_banner(name):
    print("=" * 80)
    print(name)


def _print_finding(finding, extra_key=None):
    addr = finding["address"]
    name = finding["name"]
    if extra_key and extra_key in finding:
        print("Function %s (%s) => %s: %s" % (addr, name, extra_key, finding[extra_key]))
    else:
        print("Function %s (%s)" % (addr, name))


def _apply(findings, tag_type, extra_key=None):
    clear_heuristic_tags(idautils.Functions(), tag_type)
    view = results_view()
    if view is not None:
        view.begin_batch(tag_type)
    for finding in findings:
        _print_finding(finding, extra_key)
        start = int(finding["address"], 16)
        tag_function(start, tag_type, finding["description"])
        # If the finding pinpoints specific instructions, annotate each one.
        for anchor in finding.get("anchor_addresses", ()):
            annotate_ea(anchor, tag_type, finding["description"])
        if view is not None:
            view.add_finding(finding, tag_type, extra_key)
    if view is not None:
        view.end_batch()


def find_state_machines():
    _print_banner("State Machine")
    _apply(find_state_machine_reports(), TAG_STATE_MACHINE, "state_machine_score")


def find_complex_functions():
    _print_banner("Complex Function")
    _apply(find_complex_function_reports(), TAG_COMPLEX_FUNCTION, "cyclomatic_complexity")


def find_large_basic_blocks():
    _print_banner("Large Basic Block")
    _apply(find_large_basic_block_reports(), TAG_LARGE_BASIC_BLOCK, "avg_instructions_per_block")


def find_duplicated_subgraphs():
    _print_banner("Duplicate Subgraph")
    _apply(find_duplicate_subgraph_reports(), TAG_DUPLICATE_SUBGRAPH, "num_duplicate_subgraphs")


def find_instruction_overlapping():
    _print_banner("Overlapping Instruction")
    # Highlight overlapping bytes in the disassembly view.
    for addr in compute_overlapping_instruction_addresses():
        try:
            idc.set_color(addr, idc.CIC_ITEM, _HIGHLIGHT_COLOUR)
        except Exception:
            pass
    _apply(find_instruction_overlapping_reports(), TAG_OVERLAPPING_INSTRUCTION)


def find_uncommon_instruction_sequences():
    _print_banner("Uncommon Instruction Sequence")
    _apply(find_uncommon_instruction_sequence_reports(), TAG_UNCOMMON_INSTRUCTION_SEQUENCE, "uncommon_sequences_score")


def find_most_called_functions():
    _print_banner("Most Called Function")
    _apply(find_most_called_function_reports(), TAG_MOST_CALLED_FUNCTION, "num_callers")


def find_xor_decryption_loops():
    _print_banner("XOR Decryption Loop")
    _apply(find_xor_decryption_loop_reports(), TAG_XOR_DECRYPTION_LOOP)


def find_complex_arithmetic_expressions():
    _print_banner("Complex Arithmetic Expression")
    _apply(find_complex_arithmetic_expression_reports(), TAG_COMPLEX_ARITHMETIC_EXPRESSION, "num_mba_instructions")


def find_loop_frequency_functions():
    _print_banner("Loop Frequency")
    _apply(find_loop_frequency_reports(), TAG_LOOP_FREQUENCY, "num_loops")


def find_irreducible_loops():
    _print_banner("Irreducible Loop")
    _apply(find_irreducible_loop_reports(), TAG_IRREDUCIBLE_LOOP, "num_irreducible_loops")


def find_fragmented_functions():
    _print_banner("Fragmented Function")
    _apply(find_fragmented_function_reports(), TAG_FRAGMENTED_FUNCTION, "fragmentation_ratio")
