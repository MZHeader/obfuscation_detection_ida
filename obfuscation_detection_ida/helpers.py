"""IDA ports of the obfuscation-detection heuristic primitives.

Where the original Binary Ninja implementation leaned on LLIL/HLIL, we do our
best at the assembly level and optionally use Hex-Rays microcode for
mixed-boolean-arithmetic detection.
"""

from collections import Counter
from hashlib import md5
from math import ceil, log2

import ida_bytes
import ida_funcs
import ida_ida
import ida_lines
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

from .graph import FunctionGraph
from .loop_analysis import (
    compute_blocks_in_natural_loops,
    compute_number_of_natural_loops,
)
from .ngrams import determine_ngram_database, ida_arch_name


# ---------------------------------------------------------------------------
# Function iteration helpers
# ---------------------------------------------------------------------------


_FUNCTION_GRAPH_CACHE = {}
_FUNCTION_LIST_CACHE = None

# IDA function-flag bits we always want to exclude from scoring: recognised
# library code (FLIRT / IDA Teams / user-marked), and thunks / wrappers.
_SKIP_FUNC_FLAGS = ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK

# Only score functions whose name is IDA's auto-generated placeholder. In a
# reverse-engineering session the placeholders are the ones you haven't
# analysed yet; anything IDA has resolved from PDB / FLIRT / mangling, or
# that you renamed by hand, is by definition either library code or already
# understood. Set to False if you want to score everything (e.g. for a
# non-malware binary where symbols are user code).
SKIP_NAMED_FUNCTIONS = False

# Prefixes IDA uses for its automatic per-address names. Anything starting
# with one of these is treated as unnamed / unanalysed. Used as a fallback
# when the ida_bytes flag-based check isn't available.
_AUTO_NAME_PREFIXES = (
    "sub_",
    "loc_",
    "locret_",
    "nullsub_",
    "j_",
    "def_",
    "unknown_libname_",
    "start_",  # IDA's auto-numbered secondary entry points
)


def _has_user_name(ea):
    """True if IDA marks this address as having a user/library-supplied name.

    Prefers the flag-based check (which correctly identifies PDB/FLIRT/user
    names of any shape) and falls back to prefix matching on older IDA
    builds that don't expose `has_user_name` on `ida_bytes`.
    """
    try:
        flags = ida_bytes.get_flags(ea)
    except Exception:
        flags = None
    if flags is not None:
        checker = getattr(ida_bytes, "has_user_name", None)
        if checker is not None:
            return bool(checker(flags))
    name = ida_funcs.get_func_name(ea) or ""
    return not name.startswith(_AUTO_NAME_PREFIXES)


def invalidate_function_cache():
    """Drop the cached FunctionGraph objects.

    The chooser calls this once per user action so a fresh analysis reflects
    any renames or newly-defined functions since the last click. Individual
    heuristics reuse the cache within a single run.
    """
    global _FUNCTION_LIST_CACHE
    _FUNCTION_GRAPH_CACHE.clear()
    _FUNCTION_LIST_CACHE = None
    _NGRAM_CACHE.clear()


def _build_function_graph(ea):
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    try:
        return FunctionGraph(func)
    except Exception as ex:
        print("[obfdet] Skipping 0x%x: %s" % (ea, ex))
        return None


def _has_auto_name(ea):
    name = ida_funcs.get_func_name(ea) or ""
    return name.startswith(_AUTO_NAME_PREFIXES)


def _is_scorable(func):
    """True if the function should participate in obfuscation heuristics.

    Excludes library-tagged functions (FLIRT hits, imports) and thunks. Also
    excludes anything IDA (or the user) has already given a real name if
    SKIP_NAMED_FUNCTIONS is enabled.
    """
    if func is None:
        return False
    if func.flags & _SKIP_FUNC_FLAGS:
        return False
    if SKIP_NAMED_FUNCTIONS and not _has_auto_name(func.start_ea):
        return False
    return True


def iter_functions():
    """Yield FunctionGraph wrappers for every scorable function.

    Skips FUNC_LIB and FUNC_THUNK, since those are recognised runtime /
    wrapper code rather than analysis targets. Results are cached; subsequent
    calls in the same run reuse the same FunctionGraph objects instead of
    rebuilding FlowChart + dominators.
    """
    global _FUNCTION_LIST_CACHE
    if _FUNCTION_LIST_CACHE is not None:
        for graph in _FUNCTION_LIST_CACHE:
            yield graph
        return

    graphs = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not _is_scorable(func):
            continue
        graph = _FUNCTION_GRAPH_CACHE.get(ea)
        if graph is None:
            graph = _build_function_graph(ea)
            if graph is None:
                continue
            _FUNCTION_GRAPH_CACHE[ea] = graph
        graphs.append(graph)
        yield graph
    _FUNCTION_LIST_CACHE = graphs


def callers_of(function):
    """Set of caller identities for `function`.

    Each caller is a function start ea when the calling site sits inside a
    known function, or the raw source ea when it sits in code IDA hasn't
    associated with any function (common in obfuscated binaries: thunks and
    stubs that jmp to a dispatcher often live outside function boundaries).
    """
    result = set()
    for xref in idautils.XrefsTo(function.start, 0):
        if xref.iscode and xref.type in (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF):
            f = ida_funcs.get_func(xref.frm)
            if f is None:
                # orphan caller (code outside any function). Still a caller.
                result.add(xref.frm)
            elif f.start_ea != function.start:
                result.add(f.start_ea)
    return result


_CALL_XREF_TYPES = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMP_XREF_TYPES = (ida_xref.fl_JN, ida_xref.fl_JF)


def callees_of(function):
    """Set of function start eas invoked from `function`.

    Follows both calls and tail-call jumps (jumps whose target is the entry
    of a *different* function). Intra-function jumps are ignored so we don't
    manufacture spurious self-references.
    """
    result = set()
    for block in function.basic_blocks:
        for ea in block.instruction_addresses():
            for xref in idautils.XrefsFrom(ea, 0):
                if not xref.iscode:
                    continue
                if xref.type in _CALL_XREF_TYPES:
                    callee = ida_funcs.get_func(xref.to)
                    if callee is not None:
                        result.add(callee.start_ea)
                    else:
                        # call into orphan code (packer stub, shellcode, etc.)
                        result.add(xref.to)
                elif xref.type in _JUMP_XREF_TYPES:
                    callee = ida_funcs.get_func(xref.to)
                    if (
                        callee is not None
                        and callee.start_ea == xref.to
                        and callee.start_ea != function.start
                    ):
                        result.add(callee.start_ea)
    return result


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


_MIN_DISPATCHER_SUCCESSORS = 3

# Signature thresholds for the compiler-emitted binary-tree-cascade shape
# of CFF (Emotet's state dispatchers, where a switch got compiled as
# `if(r>K) ... else if(r>L) ...` chains). Real CFF has three properties:
#   * many natural loops (one back-edge per state case)
#   * many back-edges into a SINGLE dispatcher head (state cases all
#     funnel back)
#   * many duplicated subgraphs (cloned state-transition handlers)
# The duplicate-subgraph requirement is what separates CFF cascades from
# ordinary parser loops (`while (tok = next()) switch (tok) { ... }`),
# which also have many back-edges to one head but distinct case bodies.
_CFF_CASCADE_MIN_LOOPS = 10
_CFF_CASCADE_MIN_BACKEDGES = 5
_CFF_CASCADE_MIN_DUPLICATES = 10


def calc_state_machine_score(function):
    """Score a function's resemblance to a dispatcher-driven state machine.

    Two families of dispatcher are recognised:

    1. Jump-table switch: some block has >= `_MIN_DISPATCHER_SUCCESSORS`
       outgoing edges and dominates most of the CFG (with a back-edge from
       within its dominated set). Ordinary while-loops branch only two ways
       (body / exit); real jump tables fan out much wider.
    2. Binary-comparison cascade: no single block has that fanout because
       the compiler emitted the switch as `if r>K ... else if r>L ...`
       (Emotet's C2 dispatchers look like this). Detect it by a block that
       dominates most of the CFG combined with a high natural-loop count
       (one back-edge per state case). Simple while-loops have 1-2 loops;
       CFF cascades have dozens.
    """
    total = len(function.basic_blocks)
    if total == 0:
        return 0.0
    score = 0.0
    # Pre-compute the set of blocks that participate in a natural loop.
    # A wide-fanout dispatcher may not have back-edges pointing directly
    # at itself (the compiler often emits `while(1) { switch(state) {} }`
    # where the back-edge targets the LOOP HEAD, not the dispatch block
    # nested inside it). PlugX's VM interpreter has exactly that shape.
    loop_blocks = set()
    for block in compute_blocks_in_natural_loops(function):
        loop_blocks.add(block)
    for block in function.basic_blocks:
        if len(block.successors) < _MIN_DISPATCHER_SUCCESSORS:
            continue
        dominated = function.dominated_by(block)
        has_direct_backedge = any(edge.source in dominated for edge in block.incoming_edges)
        in_loop = block in loop_blocks
        if not has_direct_backedge and not in_loop:
            continue
        score = max(score, len(dominated) / total)
    if score > 0:
        return score

    # Cascade fallback: no wide-fanout dispatcher found. Check for the CFF
    # cascade signature — dominator with many back-edges from within its
    # dominated set (state cases all funnelling back to one head), many
    # natural loops overall, AND many duplicated subgraphs. Without the
    # duplicate-subgraph check we would also fire on ordinary parsers
    # (`while (tok = next()) switch (tok) { ... }`) which structurally
    # look like cascades but have distinct case bodies.
    n_loops = compute_number_of_natural_loops(function)
    if n_loops < _CFF_CASCADE_MIN_LOOPS:
        return 0.0
    if count_context_signature_duplicates(function) < _CFF_CASCADE_MIN_DUPLICATES:
        return 0.0
    for block in function.basic_blocks:
        # Skip trivial single-successor prolog / entry blocks; the real
        # cascade head has at least a 2-way test.
        if len(block.successors) < 2:
            continue
        dominated = function.dominated_by(block)
        back_edges = 0
        for edge in block.incoming_edges:
            if edge.source in dominated:
                back_edges += 1
        if back_edges < _CFF_CASCADE_MIN_BACKEDGES:
            continue
        score = max(score, len(dominated) / total)
    return score


# ---------------------------------------------------------------------------
# Cyclomatic complexity / average block size
# ---------------------------------------------------------------------------


def calc_cyclomatic_complexity(function):
    num_blocks = len(function.basic_blocks)
    num_edges = sum(len(b.outgoing_edges) for b in function.basic_blocks)
    return num_edges - num_blocks + 2


def calc_average_instructions_per_block(function):
    num_blocks = max(1, len(function.basic_blocks))
    num_instructions = sum(b.instruction_count for b in function.basic_blocks)
    return num_instructions / num_blocks


def calc_fragmentation_ratio(function):
    """Ratio of basic-block count to cyclomatic complexity.

    Well-structured code has ratio close to 1 (each block reflects real
    branching). Block-splitting obfuscation produces many tiny blocks
    connected by unconditional jumps, driving the ratio way up: e.g. 990
    blocks / cc 18 = 55. That means most "blocks" carry no branching
    information — they exist purely to shatter the linear flow.

    Returns 0 for tiny functions and for functions whose IDA flowchart
    has more nodes than edges (`cc` computes to <=0). The latter can
    happen when many blocks are dead-ends (ret / int3 / noreturn calls)
    that IDA didn't attach outgoing edges to — the ratio is meaningless
    in that case, and functions like these are what falsely tripped the
    heuristic on tiny gcc utility routines with negative cc.
    """
    num_blocks = len(function.basic_blocks)
    if num_blocks < 3:
        return 0.0
    cc = calc_cyclomatic_complexity(function)
    if cc <= 0:
        return 0.0
    return num_blocks / cc


# ---------------------------------------------------------------------------
# XOR decryption loops (assembly-level detection)
# ---------------------------------------------------------------------------


_DTYPE_SIZES = {
    ida_ua.dt_byte: 1,
    ida_ua.dt_word: 2,
    ida_ua.dt_dword: 4,
    ida_ua.dt_qword: 8,
    ida_ua.dt_float: 4,
    ida_ua.dt_double: 8,
}


def _dtype_size(dtype):
    return _DTYPE_SIZES.get(dtype, 0)


_UA_MAXOP = getattr(ida_ua, "UA_MAXOP", 8)


def _xor_instruction_info(ea):
    """Inspect a candidate XOR instruction. Returns dict or None."""
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        return None
    mnem = insn.get_canon_mnem().lower()
    if mnem not in ("xor", "eor", "eors"):
        return None
    has_const = False
    op_reprs = []
    size = 0
    for i in range(_UA_MAXOP):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        # Fingerprint the operand by its rendered text so that distinct
        # memory operands (e.g. [rdi] vs [rsi]) don't collide.
        text = idc.print_operand(ea, i) or ""
        op_reprs.append((op.type, text))
        if op.type == ida_ua.o_imm:
            has_const = True
        size = max(size, _dtype_size(op.dtype))
    const_value = None
    if has_const:
        for i in range(_UA_MAXOP):
            op = insn.ops[i]
            if op.type == ida_ua.o_void:
                break
            if op.type == ida_ua.o_imm:
                const_value = op.value
                break
    return {
        "has_const": has_const,
        "const_value": const_value,
        "size": size,
        "op_reprs": op_reprs,
    }


# Constants a real decryption stub would never use. All three families of
# noise this rejects come up constantly on Go / Rust / C++ stdlib:
#   * 0 is a no-op, 1 / -1 are boolean-flip and bitwise-NOT idioms
#     (`xor eax, 1` after a conditional).
#   * 2, 3 are small bit-flag toggles (`flags ^= EPOLLERR`).
#   * 0xFFFF / 0xFFFFFFFF / 0xFFFF...FF are word/dword/qword full-width
#     masks used in memcmp fast-paths and endian tricks.
# Real byte or dword decryption keys are virtually always outside this set;
# a genuine byte-mask decoder uses 0x80, 0xAA, 0x5A, etc. — never 1..3.
_TRIVIAL_XOR_CONSTS = {
    0, 1, 2, 3, -1,
    # Single-bit / small-power-of-two flag toggles (`flags ^= FLAG_X`)
    4, 8, 0x10, 0x20, 0x40, 0x80,
    # Common nibble/byte inversion patterns
    0x0F, 0xF0,
    # Full-width word/dword/qword masks (bitwise-NOT idioms)
    0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
}


def _computes_xor_const(ea):
    info = _xor_instruction_info(ea)
    if not (info and info["has_const"]):
        return False
    if info["const_value"] in _TRIVIAL_XOR_CONSTS:
        return False
    return True


def _computes_rc4_xor(ea):
    """Byte-sized XOR of two distinct non-immediate operands."""
    info = _xor_instruction_info(ea)
    if not info:
        return False
    if info["has_const"]:
        return False
    if info["size"] != 1:
        return False
    if len(info["op_reprs"]) < 2:
        return False
    return info["op_reprs"][0] != info["op_reprs"][1]


def contains_xor_decryption_loop(function, xor_check=_computes_xor_const):
    return bool(xor_decryption_loop_sites(function, xor_check))


def xor_decryption_loop_sites(function, xor_check=_computes_xor_const):
    """Return the list of instruction addresses inside natural loops that
    match `xor_check`. Empty list means "no XOR-loop detected"."""
    sites = []
    for block in compute_blocks_in_natural_loops(function):
        for ea in block.instruction_addresses():
            if xor_check(ea):
                sites.append(ea)
    return sites


# ---------------------------------------------------------------------------
# RC4 heuristics
# ---------------------------------------------------------------------------


def _iter_immediates(ea):
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        return
    for i in range(_UA_MAXOP):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        if op.type == ida_ua.o_imm:
            yield op.value


# RC4 KSA is compact — a huge function that happens to have two loops and a
# 256-byte allocation somewhere is almost never doing key scheduling. Real
# implementations fit within a few dozen blocks.
_RC4_KSA_MAX_BLOCKS = 50

# Real RC4 KSA references 0x100 at least twice: as the S-box init loop bound
# and again in the permutation loop bound. A lone 0x100 (stack allocation,
# ASCII/unicode threshold, single loop cap) doesn't qualify.
_RC4_KSA_MIN_HITS = 2


def find_rc4_ksa(function):
    return bool(rc4_ksa_sites(function))


_STORE_MNEMS = {"mov", "movs", "movsb", "stosb", "stos"}


def _has_byte_indexed_store(function):
    """True if the function contains a byte-sized memory write with a
    register-index component — i.e. `mov [reg + reg*scale + off], al/bl/...`
    or `stosb`.

    RC4 KSA fills a 256-byte S-box with `S[i] = i` (byte store). Regex bit-
    state resets, hash-table inits, etc. all write DWORD/QWORD elements,
    never bytes. So this filter cleanly separates RC4 candidates from
    similarly-shaped Go/Rust/C++ container inits without hurting fidelity.

    Only operand 0 (destination on x86 MOV) is checked, so we don't
    misclassify byte LOADs like `movzx eax, byte ptr [rcx+rax]`.

    The store must be inside a natural loop — RC4 KSA's S-box init lives
    in the KSA loop. A byte store elsewhere in the function (e.g. an
    unrelated `memcpy`-style byte fill in a hashtable initializer) does
    not qualify.
    """
    for block in compute_blocks_in_natural_loops(function):
        for ea in block.instruction_addresses():
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                continue
            mnem = insn.get_canon_mnem().lower()
            if mnem == "stosb":
                return True  # unconditional byte-store to [rdi]
            if mnem not in _STORE_MNEMS:
                continue
            op = insn.ops[0]  # destination
            if op.type not in (ida_ua.o_phrase, ida_ua.o_displ):
                continue
            if _dtype_size(op.dtype) != 1:
                continue
            if getattr(op, "specflag1", 0):  # SIB byte present → indexed
                return True
    return False


def rc4_ksa_sites(function):
    """Return the addresses of instructions that carry the `0x100` immediate
    inside a function with exactly two natural loops. Empty list means no
    RC4 KSA candidate.

    The function must also contain at least one byte-sized indexed memory
    write — the S-box store. This filter kills the common shape-lookalike
    (regex bit-state reset, hash-table inits) which have 2 loops and 256
    immediates but store DWORDs/QWORDs, never bytes.
    """
    if compute_number_of_natural_loops(function) != 2:
        return []
    if len(function.basic_blocks) > _RC4_KSA_MAX_BLOCKS:
        return []
    sites = []
    for ea in function.instruction_addresses():
        for c in _iter_immediates(ea):
            if c == 0x100:
                sites.append(ea)
                break
    if len(sites) < _RC4_KSA_MIN_HITS:
        return []
    if not _has_byte_indexed_store(function):
        return []
    return sites


def _loop_has_byte_indexed_load(function):
    """True if any instruction inside a natural loop reads a byte from a
    base+index address (SIB byte present, dtype == 1).

    This is the signature of an RC4-style S-box lookup: `movzx r, byte ptr
    [rdi+rax]` / `mov al, byte ptr [rdi+rcx]`. It cleanly separates real
    RC4 PRGA from other byte-XOR loops we consistently mis-tag as RC4:
        * AES MixColumns — all reg-reg XORs, no byte-indexed loads
        * CRYPTO_memcmp  — byte XOR with `[reg]`, no index register
        * xor128_encrypt — byte XOR with `[reg]`, single-base addressing
        * HMAC ipad/opad — byte XOR with immediate constants
    """
    for block in compute_blocks_in_natural_loops(function):
        for ea in block.instruction_addresses():
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                continue
            for i in range(_UA_MAXOP):
                op = insn.ops[i]
                if op.type == ida_ua.o_void:
                    break
                if op.type not in (ida_ua.o_phrase, ida_ua.o_displ):
                    continue
                if _dtype_size(op.dtype) != 1:
                    continue
                if getattr(op, "specflag1", 0):  # SIB byte → base+index
                    return True
    return False


def find_rc4_prga(function):
    return bool(rc4_prga_sites(function))


def rc4_prga_sites(function):
    """RC4 PRGA candidate sites.

    Requires both a byte-XOR of two distinct non-immediate operands inside
    a natural loop AND a byte-sized base+index load somewhere in the loop
    body (the S-box lookup). Without the load constraint this heuristic
    over-matches every byte-XOR construct — see _loop_has_byte_indexed_load
    docstring for the specific FP families it eliminates.
    """
    sites = xor_decryption_loop_sites(function, xor_check=_computes_rc4_xor)
    if not sites:
        return []
    if not _loop_has_byte_indexed_load(function):
        return []
    return sites


# ---------------------------------------------------------------------------
# Opcode utilities / n-grams
# ---------------------------------------------------------------------------


def sliding_window(values, window_size):
    for index in range(len(values) - window_size + 1):
        yield values[index : index + window_size]


def opcode_at(ea):
    m = idc.print_insn_mnem(ea) or ""
    return m.replace(" ", "").lower()


_NGRAM_CACHE = {}  # (function.start, n) -> Counter


def invalidate_ngram_cache():
    _NGRAM_CACHE.clear()


def calc_ngrams(function, n):
    key = (function.start, n)
    cached = _NGRAM_CACHE.get(key)
    if cached is not None:
        return cached
    opcodes = []
    for ea in function.instruction_addresses():
        op = opcode_at(ea)
        if op:
            opcodes.append(op)
    counter = Counter("".join(w) for w in sliding_window(opcodes, n))
    _NGRAM_CACHE[key] = counter
    return counter


def calc_global_ngrams(functions, n):
    global_grams = Counter()
    for f in functions:
        global_grams.update(calc_ngrams(f, n))
    return global_grams


_MIN_NGRAM_TOTAL = 30  # a function needs enough instructions before its
                       # ngram score is statistically meaningful


def calc_uncommon_instruction_sequences_score(function, ngram_database):
    function_ngrams = calc_ngrams(function, 3)
    total = sum(function_ngrams.values())
    if total < _MIN_NGRAM_TOTAL:
        return 0.0
    count = sum(v for gram, v in function_ngrams.items() if gram not in ngram_database)
    return count / total


# ---------------------------------------------------------------------------
# Duplicate subgraphs via iterative context signatures
# ---------------------------------------------------------------------------


def compute_local_signature(block):
    return "".join(opcode_at(ea) for ea in block.instruction_addresses())


def compute_context_signatures(function, num_iterations):
    # Hash the raw local signatures up-front so every iteration works on
    # fixed 32-char hex strings. Otherwise a function with a single
    # 3000-instruction block (unrolled crypto) produces a multi-KB local
    # signature that then gets concatenated across neighbours — memory grew
    # multiplicatively per iteration on huge functions before this change.
    context_signatures = {
        b: md5(compute_local_signature(b).encode()).hexdigest()
        for b in function.basic_blocks
    }
    for _ in range(num_iterations):
        new_ctx = {}
        for b in function.basic_blocks:
            succ_sigs = sorted(context_signatures[edge.target] for edge in b.outgoing_edges)
            combined = context_signatures[b] + "|" + "|".join(succ_sigs)
            new_ctx[b] = md5(combined.encode()).hexdigest()
        context_signatures = new_ctx
    return context_signatures


def count_context_signature_duplicates(function, num_iterations=2):
    sigs = compute_context_signatures(function, num_iterations)
    if not sigs:
        return 0
    return len(sigs) - len(set(sigs.values()))


# ---------------------------------------------------------------------------
# Mixed boolean arithmetic via Hex-Rays microcode (optional)
# ---------------------------------------------------------------------------

_ARITH_OPS = None
_BOOL_OPS = None


def _init_mba_opsets():
    global _ARITH_OPS, _BOOL_OPS
    if _ARITH_OPS is not None:
        return True
    try:
        import ida_hexrays
    except ImportError:
        return False
    if not ida_hexrays.init_hexrays_plugin():
        return False
    _ARITH_OPS = {
        ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_mul,
        ida_hexrays.m_udiv, ida_hexrays.m_sdiv, ida_hexrays.m_umod,
        ida_hexrays.m_smod, ida_hexrays.m_neg,
    }
    _BOOL_OPS = {
        ida_hexrays.m_bnot, ida_hexrays.m_and, ida_hexrays.m_or,
        ida_hexrays.m_xor, ida_hexrays.m_shl, ida_hexrays.m_shr,
        ida_hexrays.m_sar,
    }
    return True


# MBA (Hex-Rays microcode) heuristic can crash IDA. The crash happens inside
# Hex-Rays' native C++ code (stkret / stack-return analysis on Go-produced
# functions, non-standard ABIs, etc.) so Python try/except cannot catch it —
# once it fires, IDA is gone. Defences in ascending order of severity:
#
#   * _MBA_MAX_BLOCKS         block-count ceiling. Real MBA crypto stays
#                             under ~150 blocks even fully-inlined; anything
#                             bigger is a switch dispatcher / goroutine
#                             trampoline Hex-Rays occasionally chokes on.
#   * MBA_SKIP_NAME_SUBSTRINGS names known to crash Hex-Rays on Go binaries.
#   * MBA_CRASH_JOURNAL_PATH  file listing addresses that crashed IDA on a
#                             previous run. Populate manually or by writing
#                             the address printed just before the crash.
#   * ENABLE_MBA_HEURISTIC    master kill-switch. Set OBFDET_NO_MBA=1 in
#                             the env, or edit this file, to skip MBA
#                             entirely for a binary known to crash it.
import os as _os

ENABLE_MBA_HEURISTIC = _os.environ.get("OBFDET_NO_MBA") is None

_MBA_MIN_BLOCKS = 3    # skip trivial functions to avoid decompiling everything
_MBA_MAX_BLOCKS = 200  # cap on function size handed to Hex-Rays; real MBA
                       # crypto (SHA/AES fully-inlined) stays under ~150 blocks

MBA_SKIP_NAME_SUBSTRINGS = (
    # Go runtime pieces known to trip Hex-Rays stack-return analysis:
    "runtime.reflectcall",
    "runtime.duffcopy",
    "runtime.duffzero",
    "runtime.morestack",
    "runtime.mcall",
    "runtime.gogo",
    "runtime.systemstack",
    "runtime.asmcgocall",
    "runtime.cgocallback",
    "runtime.stackcheck",
    "runtime_callbackasm",
    "runtime.tstart",
    "runtime.rt0_",
    "type:.eq.",
    "type..eq.",
    ".deferwrap",
    ".gowrap",
    # Non-standard ABI trampolines the decompiler stumbles on:
    "callbackasm",
    "stdcall_trampoline",
)


def calculate_complex_arithmetic_expressions(function):
    """Count microcode instructions that mix arithmetic and boolean ops.

    Requires Hex-Rays. Returns 0 if the decompiler is unavailable, if the
    function is outside the size band, if its name matches a known Hex-Rays
    crasher, or if the master switch is off. Prints the address of every
    function it's about to hand to Hex-Rays so that if IDA crashes, the
    last printed address is a poison candidate to add to the skip list.
    """
    if not ENABLE_MBA_HEURISTIC:
        return 0
    n_blocks = len(function.basic_blocks)
    if n_blocks < _MBA_MIN_BLOCKS or n_blocks > _MBA_MAX_BLOCKS:
        return 0
    try:
        import ida_funcs
        name = ida_funcs.get_func_name(function.start) or ""
    except Exception:
        name = ""
    if any(sub in name for sub in MBA_SKIP_NAME_SUBSTRINGS):
        return 0
    if not _init_mba_opsets():
        return 0
    try:
        import ida_hexrays
    except ImportError:
        return 0
    # Flush the address BEFORE the call. If Hex-Rays segfaults, this will be
    # the last line in the log — telling the user which function to add to
    # MBA_SKIP_NAME_SUBSTRINGS or which run to disable with OBFDET_NO_MBA.
    import sys as _sys
    print("[obfdet] MBA gen_microcode: 0x%x (%s) [%d blocks]" % (
        function.start, name, n_blocks))
    _sys.stdout.flush()
    try:
        hf = ida_hexrays.hexrays_failure_t()
        mbr = ida_hexrays.mba_ranges_t(function.func)
        mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_LVARS)
    except Exception as ex:
        print("[obfdet] MBA gen_microcode failed at 0x%x: %s" % (function.start, ex))
        return 0
    if mba is None:
        return 0
    counter = [0]

    def visit_insn(minsn):
        uses_arith = [False]
        uses_bool = [False]

        def walk(op):
            if op is None:
                return
            if op.t == ida_hexrays.mop_d and op.d is not None:
                if op.d.opcode in _ARITH_OPS:
                    uses_arith[0] = True
                elif op.d.opcode in _BOOL_OPS:
                    uses_bool[0] = True
                walk(op.d.l)
                walk(op.d.r)
                walk(op.d.d)

        if minsn.opcode in _ARITH_OPS:
            uses_arith[0] = True
        elif minsn.opcode in _BOOL_OPS:
            uses_bool[0] = True
        walk(minsn.l)
        walk(minsn.r)
        walk(minsn.d)
        if uses_arith[0] and uses_bool[0]:
            counter[0] += 1

    try:
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            cur = blk.head
            while cur is not None:
                visit_insn(cur)
                cur = cur.next
    except Exception as ex:
        print("[obfdet] MBA walk failed at 0x%x: %s" % (function.start, ex))
        return 0
    return counter[0]


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


def calculate_entropy(data):
    if not data:
        return 0.0
    byte_count = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in byte_count.values():
        p = count / total
        entropy -= p * log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def get_top_10_functions(functions, scoring_function):
    scored = sorted(((f, scoring_function(f)) for f in functions), key=lambda x: x[1])
    bound = max(min(ceil((len(scored) * 10) / 100), 1000), 10)
    for function, score in list(reversed(scored))[:bound]:
        yield function, score


def sort_elements(iterator, scoring_function):
    scored = sorted(((elem, scoring_function(elem)) for elem in iterator), key=lambda x: x[1])
    for element, score in list(reversed(scored)):
        yield element, score


# ---------------------------------------------------------------------------
# Overlapping instructions
# ---------------------------------------------------------------------------


def compute_overlapping_instruction_addresses():
    """Return the set of addresses that appear both as an instruction start
    and as the middle byte of some other instruction."""
    seen = {}
    overlapping = set()
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue
        for ea in idautils.FuncItems(func_ea):
            length = ida_bytes.get_item_size(ea)
            if length <= 0:
                length = 1
            if ea not in seen:
                seen[ea] = 1
            elif seen[ea] == 0:
                overlapping.add(ea)
            for offset in range(1, length):
                b = ea + offset
                if b in seen and seen[b] == 1:
                    overlapping.add(b)
                else:
                    seen[b] = 0
    return overlapping


def functions_containing(ea):
    """Return function eas whose body includes `ea` (usually one, but IDA
    can associate an address with multiple func chunks)."""
    result = []
    func = ida_funcs.get_func(ea)
    if func is not None:
        result.append(func.start_ea)
    return result


# ---------------------------------------------------------------------------
# Sections (segments in IDA)
# ---------------------------------------------------------------------------


def iter_segments():
    """Yield (name, start, size, bytes) for each segment."""
    import ida_segment
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg) or ("seg_%x" % seg.start_ea)
        size = seg.end_ea - seg.start_ea
        data = ida_bytes.get_bytes(seg.start_ea, size) or b""
        yield {"name": name, "start": seg.start_ea, "size": size, "data": data}
