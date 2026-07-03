"""Structured findings (as plain dicts) for every heuristic. Consumers can
render them however they like — the printer/heuristics modules just format
these dicts."""

from math import ceil

from .helpers import (
    calc_average_instructions_per_block,
    calc_cyclomatic_complexity,
    calc_state_machine_score,
    calc_uncommon_instruction_sequences_score,
    calculate_complex_arithmetic_expressions,
    calculate_entropy,
    callees_of,
    callers_of,
    compute_overlapping_instruction_addresses,
    contains_xor_decryption_loop,
    count_context_signature_duplicates,
    find_rc4_ksa,
    find_rc4_prga,
    functions_containing,
    get_top_10_functions,
    iter_functions,
    iter_segments,
    rc4_ksa_sites,
    rc4_prga_sites,
    xor_decryption_loop_sites,
)
from .loop_analysis import compute_irreducible_loops, compute_number_of_natural_loops
from .ngrams import determine_ngram_database, ida_arch_name
from .tagging import (
    TAG_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_COMPLEX_FUNCTION,
    TAG_DUPLICATE_SUBGRAPH,
    TAG_ENTRY_FUNCTION,
    TAG_IRREDUCIBLE_LOOP,
    TAG_LARGE_BASIC_BLOCK,
    TAG_LEAF_FUNCTION,
    TAG_LOOP_FREQUENCY,
    TAG_MOST_CALLED_FUNCTION,
    TAG_OVERLAPPING_INSTRUCTION,
    TAG_RC4_KSA,
    TAG_RC4_PRGA,
    TAG_RECURSIVE_FUNCTION,
    TAG_STATE_MACHINE,
    TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
    TAG_XOR_DECRYPTION_LOOP,
    TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_DESC_COMPLEX_FUNCTION,
    TAG_DESC_DUPLICATE_SUBGRAPH,
    TAG_DESC_ENTRY_FUNCTION,
    TAG_DESC_IRREDUCIBLE_LOOP,
    TAG_DESC_LARGE_BASIC_BLOCK,
    TAG_DESC_LEAF_FUNCTION,
    TAG_DESC_LOOP_FREQUENCY,
    TAG_DESC_MOST_CALLED_FUNCTION,
    TAG_DESC_OVERLAPPING_INSTRUCTION,
    TAG_DESC_RC4_KSA,
    TAG_DESC_RC4_PRGA,
    TAG_DESC_RECURSIVE_FUNCTION,
    TAG_DESC_STATE_MACHINE,
    TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE,
    TAG_DESC_XOR_DECRYPTION_LOOP,
)


def function_finding(function, tag_type, description, **fields):
    finding = {
        "address": hex(function.start),
        "name": function.name,
        "tag_type": tag_type,
        "description": description,
    }
    finding.update(fields)
    return finding


def section_finding(section, entropy):
    return {
        "name": section["name"],
        "address": hex(section["start"]),
        "length": section["size"],
        "entropy": entropy,
    }


def _functions():
    # iter_functions() already caches — just materialize the generator.
    return list(iter_functions())


# Minimum absolute score a function needs to keep after the top-10% ranking.
# Real obfuscation samples score much higher than "top decile of an ordinary
# binary", so these gates are deliberately strict. Edit the constants in this
# file to loosen them if you're studying a codebase where obfuscation is
# subtle. Also see MIN_BLOCKS_* which require the function to be big enough
# for the score to be meaningful in the first place.
MIN_STATE_MACHINE_SCORE = 0.65           # dispatcher dominates >=65% of CFG
MIN_STATE_MACHINE_BLOCKS = 15            # need a real CFG, not a 4-block stub
MIN_CYCLOMATIC_COMPLEXITY = 30           # normal functions rarely hit 30+
MIN_COMPLEX_FUNCTION_BLOCKS = 15
MIN_AVG_BLOCK_INSTRUCTIONS = 30          # crypto / unrolled code territory
MIN_LARGE_BLOCK_BLOCKS = 3               # single-block functions don't count
MIN_UNCOMMON_SEQ_SCORE = 0.50            # >=50% of 3-grams unseen in reference
MIN_CALLERS = 20                         # library-tier helpers, not "used twice"
MIN_LOOPS = 4                            # 1-3 loops is routine
MIN_IRREDUCIBLE_LOOPS = 1                # already guarded; kept for symmetry
MIN_DUPLICATE_SUBGRAPHS = 1              # already guarded


def _above(score, threshold):
    try:
        return float(score) >= threshold
    except (TypeError, ValueError):
        return False


def _has_blocks(function, minimum):
    try:
        return len(function.basic_blocks) >= minimum
    except Exception:
        return False


def find_state_machine_reports():
    return [
        function_finding(
            f,
            TAG_STATE_MACHINE,
            TAG_DESC_STATE_MACHINE.format(score=score),
            state_machine_score=score,
        )
        for f, score in get_top_10_functions(_functions(), calc_state_machine_score)
        if _above(score, MIN_STATE_MACHINE_SCORE)
        and _has_blocks(f, MIN_STATE_MACHINE_BLOCKS)
    ]


def find_complex_function_reports():
    return [
        function_finding(
            f,
            TAG_COMPLEX_FUNCTION,
            TAG_DESC_COMPLEX_FUNCTION.format(score=score),
            cyclomatic_complexity=score,
        )
        for f, score in get_top_10_functions(_functions(), calc_cyclomatic_complexity)
        if _above(score, MIN_CYCLOMATIC_COMPLEXITY)
        and _has_blocks(f, MIN_COMPLEX_FUNCTION_BLOCKS)
    ]


def find_large_basic_block_reports():
    return [
        function_finding(
            f,
            TAG_LARGE_BASIC_BLOCK,
            TAG_DESC_LARGE_BASIC_BLOCK.format(score=ceil(score)),
            avg_instructions_per_block=ceil(score),
        )
        for f, score in get_top_10_functions(
            _functions(), calc_average_instructions_per_block
        )
        if _above(score, MIN_AVG_BLOCK_INSTRUCTIONS)
        and _has_blocks(f, MIN_LARGE_BLOCK_BLOCKS)
    ]


def find_duplicate_subgraph_reports():
    return [
        function_finding(
            f,
            TAG_DUPLICATE_SUBGRAPH,
            TAG_DESC_DUPLICATE_SUBGRAPH.format(score=score),
            num_duplicate_subgraphs=score,
        )
        for f, score in get_top_10_functions(
            _functions(), count_context_signature_duplicates
        )
        if score != 0
    ]


def find_instruction_overlapping_reports():
    reports_by_function = {}
    by_start = {f.start: f for f in _functions()}
    for address in sorted(compute_overlapping_instruction_addresses()):
        for func_ea in functions_containing(address):
            f = by_start.get(func_ea)
            if f is None:
                continue
            report = reports_by_function.setdefault(
                f.start,
                function_finding(
                    f,
                    TAG_OVERLAPPING_INSTRUCTION,
                    TAG_DESC_OVERLAPPING_INSTRUCTION,
                    overlapping_instruction_addresses=[],
                    anchor_addresses=[],
                ),
            )
            report["overlapping_instruction_addresses"].append(hex(address))
            report["anchor_addresses"].append(address)
    return [reports_by_function[addr] for addr in sorted(reports_by_function)]


def find_uncommon_instruction_sequence_reports():
    use_llil, db = determine_ngram_database(ida_arch_name())
    if use_llil:
        # The IDA port has no LLIL; without a matching assembly database this
        # heuristic would flag every function. Skip cleanly on unsupported
        # architectures instead of emitting noise.
        print(
            "[obfdet] Uncommon Instruction Sequence: no 3-gram database for "
            "architecture '%s'; skipping." % ida_arch_name()
        )
        return []
    return [
        function_finding(
            f,
            TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
            TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE.format(score=score),
            uncommon_sequences_score=score,
        )
        for f, score in get_top_10_functions(
            _functions(),
            lambda f: calc_uncommon_instruction_sequences_score(f, db),
        )
        if _above(score, MIN_UNCOMMON_SEQ_SCORE)
    ]


def find_most_called_function_reports():
    return [
        function_finding(
            f,
            TAG_MOST_CALLED_FUNCTION,
            TAG_DESC_MOST_CALLED_FUNCTION.format(score=score),
            num_callers=score,
        )
        for f, score in get_top_10_functions(
            _functions(), lambda f: len(callers_of(f))
        )
        if _above(score, MIN_CALLERS)
    ]


def find_xor_decryption_loop_reports():
    findings = []
    for f in _functions():
        sites = xor_decryption_loop_sites(f)
        if not sites:
            continue
        findings.append(
            function_finding(
                f,
                TAG_XOR_DECRYPTION_LOOP,
                TAG_DESC_XOR_DECRYPTION_LOOP,
                anchor_addresses=sites,
            )
        )
    return findings


def find_complex_arithmetic_expression_reports():
    return [
        function_finding(
            f,
            TAG_COMPLEX_ARITHMETIC_EXPRESSION,
            TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION.format(score=score),
            num_mba_instructions=score,
        )
        for f, score in get_top_10_functions(
            _functions(), calculate_complex_arithmetic_expressions
        )
        if score != 0
    ]


def find_loop_frequency_reports():
    return [
        function_finding(
            f,
            TAG_LOOP_FREQUENCY,
            TAG_DESC_LOOP_FREQUENCY.format(score=score),
            num_loops=score,
        )
        for f, score in get_top_10_functions(
            _functions(), compute_number_of_natural_loops
        )
        if _above(score, MIN_LOOPS)
    ]


def find_irreducible_loop_reports():
    return [
        function_finding(
            f,
            TAG_IRREDUCIBLE_LOOP,
            TAG_DESC_IRREDUCIBLE_LOOP.format(score=score),
            num_irreducible_loops=score,
        )
        for f, score in filter(
            lambda x: x[1] > 0,
            get_top_10_functions(
                _functions(), lambda x: len(compute_irreducible_loops(x))
            ),
        )
    ]


def find_entry_function_reports():
    return [
        function_finding(f, TAG_ENTRY_FUNCTION, TAG_DESC_ENTRY_FUNCTION)
        for f in _functions()
        if len(callers_of(f)) == 0
    ]


def find_leaf_function_reports():
    return [
        function_finding(f, TAG_LEAF_FUNCTION, TAG_DESC_LEAF_FUNCTION)
        for f in _functions()
        if len(callees_of(f)) == 0 and sum(1 for _ in f.instruction_addresses()) > 1
    ]


def find_recursive_function_reports():
    return [
        function_finding(f, TAG_RECURSIVE_FUNCTION, TAG_DESC_RECURSIVE_FUNCTION)
        for f in _functions()
        if f.start in callees_of(f)
    ]


def find_section_entropy_reports():
    entries = [(s, calculate_entropy(s["data"])) for s in iter_segments()]
    entries.sort(key=lambda x: x[1], reverse=True)
    return [section_finding(s, e) for s, e in entries]


def find_rc4_ksa_reports():
    findings = []
    for f in _functions():
        sites = rc4_ksa_sites(f)
        if not sites:
            continue
        findings.append(
            function_finding(f, TAG_RC4_KSA, TAG_DESC_RC4_KSA, anchor_addresses=sites)
        )
    return findings


def find_rc4_prga_reports():
    findings = []
    for f in _functions():
        sites = rc4_prga_sites(f)
        if not sites:
            continue
        findings.append(
            function_finding(f, TAG_RC4_PRGA, TAG_DESC_RC4_PRGA, anchor_addresses=sites)
        )
    return findings
