"""IDA has no first-class "tags"; we approximate by prefixing the function
comment with a stable marker and by bookmarking the function start."""

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import idc

TAG_COMPLEX_ARITHMETIC_EXPRESSION = "Heuristic: Complex Arithmetic Expression"
TAG_COMPLEX_FUNCTION = "Heuristic: Complex Function"
TAG_STATE_MACHINE = "Heuristic: State Machine"
TAG_DUPLICATE_SUBGRAPH = "Heuristic: Duplicate Subgraph"
TAG_ENTRY_FUNCTION = "Heuristic: Entry Function"
TAG_IRREDUCIBLE_LOOP = "Heuristic: Irreducible Loop"
TAG_LARGE_BASIC_BLOCK = "Heuristic: Large Basic Block"
TAG_LEAF_FUNCTION = "Heuristic: Leaf Function"
TAG_LOOP_FREQUENCY = "Heuristic: Loop Frequency"
TAG_MOST_CALLED_FUNCTION = "Heuristic: Most Called Function"
TAG_OVERLAPPING_INSTRUCTION = "Heuristic: Overlapping Instruction"
TAG_RC4_KSA = "Heuristic: RC4 KSA"
TAG_RC4_PRGA = "Heuristic: RC4 PRGA"
TAG_RECURSIVE_FUNCTION = "Heuristic: Recursive Function"
TAG_UNCOMMON_INSTRUCTION_SEQUENCE = "Heuristic: Uncommon Instruction Sequence"
TAG_XOR_DECRYPTION_LOOP = "Heuristic: XOR Decryption Loop"

TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION = "num_mba_instructions: {score} | may indicate: mixed-boolean-arithmetic obfuscation, crypto"
TAG_DESC_COMPLEX_FUNCTION = "cyclomatic_complexity: {score} | may indicate: complex protocols, state machines, opaque predicates"
TAG_DESC_STATE_MACHINE = "state_machine_score: {score:.2f} | may indicate: control-flow flattening, state machines, dispatcher loops"
TAG_DESC_DUPLICATE_SUBGRAPH = "num_duplicate_subgraphs: {score} | may indicate: cloned obfuscation stubs, unrolled loops"
TAG_DESC_ENTRY_FUNCTION = "no known callers | may indicate: entry point, indirect jump target"
TAG_DESC_IRREDUCIBLE_LOOP = "num_irreducible_loops: {score} | may indicate: hand-written asm, obfuscation"
TAG_DESC_LARGE_BASIC_BLOCK = "avg_instructions_per_block: {score} | may indicate: unrolled code, crypto"
TAG_DESC_LEAF_FUNCTION = "no known callees | may indicate: outlined functions, trampolines"
TAG_DESC_LOOP_FREQUENCY = "num_loops: {score} | may indicate: complex parsing, intensive algorithms"
TAG_DESC_MOST_CALLED_FUNCTION = "num_callers: {score} | may indicate: string decryption routines"
TAG_DESC_OVERLAPPING_INSTRUCTION = "may indicate: broken disassembly, opaque predicates"
TAG_DESC_RC4_KSA = "may indicate: RC4 key scheduling"
TAG_DESC_RC4_PRGA = "may indicate: RC4 pseudo-random generation"
TAG_DESC_RECURSIVE_FUNCTION = "self-recursive | may indicate: recursion, obfuscation"
TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE = "uncommon_sequences_score: {score} | may indicate: crypto, arithmetic obfuscation"
TAG_DESC_XOR_DECRYPTION_LOOP = "may indicate: string decryption, code decryption stubs"

_TAG_MARKER = "[obfdet]"


def _prefix_line(tag_type, data):
    return "{marker} {tag}: {data}".format(marker=_TAG_MARKER, tag=tag_type, data=data)


def tag_function(function, tag_type, data=""):
    """Append a marker line to the function's repeatable comment (deduplicated).

    `function` may be a FunctionGraph, an ida_funcs.func_t, or a raw start ea.
    """
    if isinstance(function, int):
        ea = function
    elif hasattr(function, "start"):
        ea = function.start
    else:
        ea = function.start_ea
    line = _prefix_line(tag_type, data)
    existing = idc.get_func_cmt(ea, 1) or ""
    for present in existing.splitlines():
        if present.startswith(_TAG_MARKER) and tag_type in present:
            # already tagged; refresh with new data
            new_lines = [l for l in existing.splitlines() if not (l.startswith(_TAG_MARKER) and tag_type in l)]
            new_lines.append(line)
            idc.set_func_cmt(ea, "\n".join(new_lines), 1)
            return
    if existing:
        idc.set_func_cmt(ea, existing.rstrip() + "\n" + line, 1)
    else:
        idc.set_func_cmt(ea, line, 1)


def clear_heuristic_tags(function_iter, tag_type):
    """Strip every function's comment of the given tag line.

    `function_iter` yields FunctionGraph/func_t objects or start eas.
    """
    for function in function_iter:
        if isinstance(function, int):
            ea = function
        elif hasattr(function, "start"):
            ea = function.start
        else:
            ea = function.start_ea
        existing = idc.get_func_cmt(ea, 1) or ""
        if _TAG_MARKER not in existing or tag_type not in existing:
            continue
        new_lines = [
            l for l in existing.splitlines()
            if not (l.startswith(_TAG_MARKER) and tag_type in l)
        ]
        idc.set_func_cmt(ea, "\n".join(new_lines), 1)
