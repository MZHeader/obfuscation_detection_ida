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


def iter_functions():
    """Yield FunctionGraph wrappers for every non-external function."""
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func is None:
            continue
        if func.flags & ida_funcs.FUNC_THUNK:
            # Still include thunks; they're routinely obfuscation targets.
            pass
        try:
            yield FunctionGraph(func)
        except Exception as ex:
            print("[obfdet] Skipping 0x%x: %s" % (ea, ex))
            continue


def callers_of(function):
    """Set of function start eas that call `function`."""
    result = set()
    for xref in idautils.XrefsTo(function.start, 0):
        if xref.iscode and xref.type in (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF):
            f = ida_funcs.get_func(xref.frm)
            if f is not None and f.start_ea != function.start:
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


def calc_state_machine_score(function):
    score = 0.0
    for block in function.basic_blocks:
        dominated = function.dominated_by(block)
        if not any(edge.source in dominated for edge in block.incoming_edges):
            continue
        if len(function.basic_blocks) == 0:
            continue
        score = max(score, len(dominated) / len(function.basic_blocks))
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
    return {
        "has_const": has_const,
        "size": size,
        "op_reprs": op_reprs,
    }


def _computes_xor_const(ea):
    info = _xor_instruction_info(ea)
    return bool(info and info["has_const"])


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
    for block in compute_blocks_in_natural_loops(function):
        for ea in block.instruction_addresses():
            if xor_check(ea):
                return True
    return False


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


def find_rc4_ksa(function):
    if compute_number_of_natural_loops(function) != 2:
        return False
    for ea in function.instruction_addresses():
        for c in _iter_immediates(ea):
            if c == 0x100:
                return True
    return False


def find_rc4_prga(function):
    return contains_xor_decryption_loop(function, xor_check=_computes_rc4_xor)


# ---------------------------------------------------------------------------
# Opcode utilities / n-grams
# ---------------------------------------------------------------------------


def sliding_window(values, window_size):
    for index in range(len(values) - window_size + 1):
        yield values[index : index + window_size]


def opcode_at(ea):
    m = idc.print_insn_mnem(ea) or ""
    return m.replace(" ", "").lower()


def calc_ngrams(function, n):
    opcodes = []
    for ea in function.instruction_addresses():
        op = opcode_at(ea)
        if op:
            opcodes.append(op)
    return Counter("".join(w) for w in sliding_window(opcodes, n))


def calc_global_ngrams(functions, n):
    global_grams = Counter()
    for f in functions:
        global_grams.update(calc_ngrams(f, n))
    return global_grams


def calc_uncommon_instruction_sequences_score(function, ngram_database):
    function_ngrams = calc_ngrams(function, 3)
    total = sum(function_ngrams.values())
    if total < 5:
        return 0.0
    count = sum(v for gram, v in function_ngrams.items() if gram not in ngram_database)
    return count / total


# ---------------------------------------------------------------------------
# Duplicate subgraphs via iterative context signatures
# ---------------------------------------------------------------------------


def compute_local_signature(block):
    return "".join(opcode_at(ea) for ea in block.instruction_addresses())


def compute_context_signatures(function, num_iterations):
    local_signatures = {b: compute_local_signature(b) for b in function.basic_blocks}
    context_signatures = local_signatures.copy()
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


def calculate_complex_arithmetic_expressions(function):
    """Count microcode instructions that mix arithmetic and boolean ops.

    Requires Hex-Rays. Returns 0 if decompiler is unavailable.
    """
    if not _init_mba_opsets():
        return 0
    try:
        import ida_hexrays
    except ImportError:
        return 0
    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t(function.func)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_LVARS)
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

    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        cur = blk.head
        while cur is not None:
            visit_insn(cur)
            cur = cur.next
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
