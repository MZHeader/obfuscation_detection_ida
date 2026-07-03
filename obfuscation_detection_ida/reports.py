"""Structured findings (as plain dicts) for every heuristic. Consumers can
render them however they like — the printer/heuristics modules just format
these dicts."""

from math import ceil

from .helpers import (
    calc_average_instructions_per_block,
    calc_cyclomatic_complexity,
    calc_fragmentation_ratio,
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
    _xor_instruction_info,
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
    TAG_FRAGMENTED_FUNCTION,
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
    TAG_DESC_FRAGMENTED_FUNCTION,
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


# Hard cap on how many findings any single heuristic can produce. Even after
# the score gates below, a very large binary can leave dozens of "top decile"
# hits per heuristic; we truncate to the highest-scoring N so the results
# view stays reviewable.
MAX_FINDINGS_PER_HEURISTIC = 30

# Minimum absolute score a function needs to keep after the top-10% ranking.
# Real obfuscation samples score much higher than "top decile of an ordinary
# binary", so these gates are deliberately strict. Edit the constants in this
# file to loosen them if you're studying a codebase where obfuscation is
# subtle. Also see MIN_BLOCKS_* which require the function to be big enough
# for the score to be meaningful in the first place.
MIN_STATE_MACHINE_SCORE = 0.75           # dispatcher dominates >=75% of CFG
MIN_STATE_MACHINE_BLOCKS = 20            # need a real CFG, not a 4-block stub
MIN_CYCLOMATIC_COMPLEXITY = 50           # ordinary code rarely reaches 50+
MIN_COMPLEX_FUNCTION_BLOCKS = 20
MIN_AVG_BLOCK_INSTRUCTIONS = 40          # crypto / unrolled code territory
MIN_LARGE_BLOCK_BLOCKS = 1               # a single 800-instruction block is
                                         # exactly what this heuristic should
                                         # catch (fully-unrolled MD5, AES,
                                         # SHA, custom crypto). Excluding
                                         # them was a real miss.
MIN_UNCOMMON_SEQ_SCORE = 0.85            # 0.75 still catches hex parsers,
                                         # whitespace tokenizers, string trim;
                                         # 0.85+ isolates crypto/hash-shaped code
MIN_CALLERS = 30                         # library-tier helpers, not "used twice"
MOST_CALLED_REQUIRE_XOR_LOOP = True      # only tag popular helpers if they also
                                         # look like decoders; otherwise "many
                                         # callers" catches every utility
MIN_LOOPS = 5                            # 1-4 loops is routine
MIN_IRREDUCIBLE_LOOPS = 1                # already guarded; kept for symmetry
MIN_DUPLICATE_SUBGRAPHS = 4              # 2-3 duplicates is call-site clustering,
                                         # not obfuscation
MIN_MBA_INSTRUCTIONS = 5                 # a single mixed op is any normal xor/shift
MIN_LEAF_INSTRUCTIONS = 20               # tiny leaves are helpers, not outlined code
MIN_LEAF_CALLERS = 2                     # a leaf with a single caller is just an
                                         # un-inlined helper the compiler happened
                                         # to keep out-of-line. Real "outlined
                                         # stubs / trampolines" are shared across
                                         # multiple call sites — that's what makes
                                         # them worth outlining.
MAX_LEAF_CALLERS = 5                     # a leaf called 10+ times is a plain utility
                                         # (memcpy-like helper), not an outlined stub
                                         # or trampoline
MIN_ENTRY_INSTRUCTIONS = 5               # ditto for uncalled entry-like fragments
MIN_FRAGMENTATION_RATIO = 8              # ratio of blocks to cyclomatic complexity
                                         # (normal code is ~1-3; block splitting
                                         # pushes it to double digits)
MIN_FRAGMENTATION_BLOCKS = 50            # skip small functions where the ratio
                                         # isn't statistically meaningful


def _cap(findings, key=None):
    """Keep the top MAX_FINDINGS_PER_HEURISTIC results by `key` (descending)."""
    if key is not None:
        findings = sorted(findings, key=key, reverse=True)
    return findings[:MAX_FINDINGS_PER_HEURISTIC]


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
    findings = [
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
    return _cap(findings)


def find_complex_function_reports():
    findings = [
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
    return _cap(findings)


def find_large_basic_block_reports():
    findings = [
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
    return _cap(findings)


def find_duplicate_subgraph_reports():
    findings = [
        function_finding(
            f,
            TAG_DUPLICATE_SUBGRAPH,
            TAG_DESC_DUPLICATE_SUBGRAPH.format(score=score),
            num_duplicate_subgraphs=score,
        )
        for f, score in get_top_10_functions(
            _functions(), count_context_signature_duplicates
        )
        if _above(score, MIN_DUPLICATE_SUBGRAPHS)
    ]
    return _cap(findings)


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
    findings = [
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
    return _cap(findings)


def find_most_called_function_reports():
    def _keep(f, score):
        if not _above(score, MIN_CALLERS):
            return False
        if MOST_CALLED_REQUIRE_XOR_LOOP and not contains_xor_decryption_loop(f):
            return False
        return True

    findings = [
        function_finding(
            f,
            TAG_MOST_CALLED_FUNCTION,
            TAG_DESC_MOST_CALLED_FUNCTION.format(score=score),
            num_callers=score,
        )
        for f, score in get_top_10_functions(
            _functions(), lambda f: len(callers_of(f))
        )
        if _keep(f, score)
    ]
    return _cap(findings)


def find_xor_decryption_loop_reports():
    # First pass: collect (site, xor-constant) pairs across every function
    # so we can filter out constants that appear in many functions.
    #
    # Real string / code decryption almost always uses a per-function key.
    # Hash polynomials (FNV, CRC32, jenkins) get INLINED into dozens of
    # callers, producing the same constant over and over. Dropping the
    # cross-function-shared constants kills the biggest FP class on large
    # C++ binaries without hurting real decryption stubs or SHA/HMAC
    # constants (which appear once or twice at most).
    per_func_sites = []  # list of (f, [(site_ea, const_value_or_None), ...])
    const_freq = {}
    for f in _functions():
        sites = xor_decryption_loop_sites(f)
        if not sites:
            continue
        annotated = []
        seen_consts_here = set()
        for s in sites:
            info = _xor_instruction_info(s)
            cv = info["const_value"] if (info and info["has_const"]) else None
            annotated.append((s, cv))
            if cv is not None and cv not in seen_consts_here:
                const_freq[cv] = const_freq.get(cv, 0) + 1
                seen_consts_here.add(cv)
        per_func_sites.append((f, annotated))

    # A constant appearing in 3+ distinct functions is almost certainly a
    # shared polynomial / hash-init value, not a per-function decryption
    # key. Real SHA/HMAC constants appear at most once or twice.
    SHARED_CONST_THRESHOLD = 3
    shared_consts = {
        c for c, n in const_freq.items() if n >= SHARED_CONST_THRESHOLD
    }

    findings = []
    for f, annotated in per_func_sites:
        kept_sites = [s for s, cv in annotated if cv not in shared_consts]
        if not kept_sites:
            continue
        findings.append(
            function_finding(
                f,
                TAG_XOR_DECRYPTION_LOOP,
                TAG_DESC_XOR_DECRYPTION_LOOP,
                anchor_addresses=kept_sites,
            )
        )
    return _cap(findings)


def find_complex_arithmetic_expression_reports():
    findings = [
        function_finding(
            f,
            TAG_COMPLEX_ARITHMETIC_EXPRESSION,
            TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION.format(score=score),
            num_mba_instructions=score,
        )
        for f, score in get_top_10_functions(
            _functions(), calculate_complex_arithmetic_expressions
        )
        if _above(score, MIN_MBA_INSTRUCTIONS)
    ]
    return _cap(findings)


def find_loop_frequency_reports():
    findings = [
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
    return _cap(findings)


def find_fragmented_function_reports():
    """Functions with an abnormally high basic-block-count vs. cyclomatic
    complexity ratio — the signature of block-splitting obfuscation.

    Also requires at least one natural loop. Real block-splitting obfuscation
    is applied to loop bodies (VM dispatchers, decrypt loops); loop-free
    high-fragmentation functions are almost always compiler-emitted
    jump-table switches (X509/error-code lookups, curl_easy_strerror, etc.)
    which give the same blocks/cc ratio but are legitimate code.
    """
    findings = [
        function_finding(
            f,
            TAG_FRAGMENTED_FUNCTION,
            TAG_DESC_FRAGMENTED_FUNCTION.format(score=score),
            fragmentation_ratio=score,
            block_count=len(f.basic_blocks),
        )
        for f, score in get_top_10_functions(_functions(), calc_fragmentation_ratio)
        if _above(score, MIN_FRAGMENTATION_RATIO)
        and _has_blocks(f, MIN_FRAGMENTATION_BLOCKS)
        and compute_number_of_natural_loops(f) >= 1
    ]
    return _cap(findings)


def find_irreducible_loop_reports():
    findings = [
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
    return _cap(findings)


def _instruction_count(function):
    return sum(1 for _ in function.instruction_addresses())


def _has_any_data_ref(function):
    """True if any data reference targets the function start.

    In obfuscated binaries most functions with "no callers" turn out to be
    vtable / dispatch-table members: something like `mov ecx, offset f`
    stores their address for later indirect call. Those aren't hidden entry
    points; they're just called through a pointer. A truly interesting
    Entry Function is orphan in *both* code and data — likely shellcode or
    dead-code-fragment.
    """
    import idautils
    for _ in idautils.DataRefsTo(function.start):
        return True
    return False


def find_entry_function_reports():
    # On large clean C++ binaries IDA's caller analysis leaves hundreds of
    # legitimate static/private functions orphaned; rank by instruction
    # count and cap so a "real shellcode / dead-code fragment" (typically
    # the biggest orphan) surfaces first instead of being buried under 150
    # tiny helpers.
    scored = []
    for f in _functions():
        if len(callers_of(f)) != 0:
            continue
        insns = _instruction_count(f)
        if insns < MIN_ENTRY_INSTRUCTIONS:
            continue
        if _has_any_data_ref(f):
            continue
        scored.append((insns, f))
    scored.sort(key=lambda x: -x[0])
    return [
        function_finding(f, TAG_ENTRY_FUNCTION, TAG_DESC_ENTRY_FUNCTION)
        for _, f in scored[:MAX_FINDINGS_PER_HEURISTIC]
    ]


def find_leaf_function_reports():
    scored = []
    for f in _functions():
        if len(callees_of(f)) != 0:
            continue
        insns = _instruction_count(f)
        if insns < MIN_LEAF_INSTRUCTIONS:
            continue
        callers = len(callers_of(f))
        if callers < MIN_LEAF_CALLERS or callers > MAX_LEAF_CALLERS:
            continue
        if _has_any_data_ref(f):
            continue
        scored.append((insns, f))
    # Cap to the top MAX_FINDINGS_PER_HEURISTIC by instruction count. A
    # 200-instruction leaf is more likely a real outlined helper than one
    # of a thousand 20-insn getters in a large C++ codebase.
    scored.sort(key=lambda x: -x[0])
    return [
        function_finding(f, TAG_LEAF_FUNCTION, TAG_DESC_LEAF_FUNCTION)
        for _, f in scored[:MAX_FINDINGS_PER_HEURISTIC]
    ]


def find_recursive_function_reports():
    # Rank by instruction count so we surface the *interesting* recursives
    # on huge C++ codebases (game engines, LLVM). Every template-traversal
    # helper is technically self-recursive; without a cap the report is
    # unreadable on binaries with hundreds of thousands of functions.
    scored = []
    for f in _functions():
        if f.start not in callees_of(f):
            continue
        scored.append((_instruction_count(f), f))
    scored.sort(key=lambda x: -x[0])
    return [
        function_finding(f, TAG_RECURSIVE_FUNCTION, TAG_DESC_RECURSIVE_FUNCTION)
        for _, f in scored[:MAX_FINDINGS_PER_HEURISTIC]
    ]


def find_section_entropy_reports():
    entries = [(s, calculate_entropy(s["data"])) for s in iter_segments()]
    entries.sort(key=lambda x: x[1], reverse=True)
    return [section_finding(s, e) for s, e in entries]


def find_rc4_ksa_reports():
    scored = []
    for f in _functions():
        sites = rc4_ksa_sites(f)
        if not sites:
            continue
        scored.append((len(sites), f, sites))
    scored.sort(key=lambda x: -x[0])
    return [
        function_finding(f, TAG_RC4_KSA, TAG_DESC_RC4_KSA, anchor_addresses=sites)
        for _, f, sites in scored[:MAX_FINDINGS_PER_HEURISTIC]
    ]


def find_rc4_prga_reports():
    scored = []
    for f in _functions():
        sites = rc4_prga_sites(f)
        if not sites:
            continue
        scored.append((len(sites), f, sites))
    # Rank by anchor-site count; functions with more byte-XOR sites are the
    # more RC4-shaped candidates. On large clean binaries this caps a
    # heuristic that would otherwise fire on every byte-XOR crypto primitive
    # (AES round helpers, XOR128, HMAC, memcmp-style constant-time ops).
    scored.sort(key=lambda x: -x[0])
    return [
        function_finding(f, TAG_RC4_PRGA, TAG_DESC_RC4_PRGA, anchor_addresses=sites)
        for _, f, sites in scored[:MAX_FINDINGS_PER_HEURISTIC]
    ]
