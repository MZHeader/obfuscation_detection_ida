"""Utility detections: entry / leaf / recursive functions, RC4, section entropy."""

import idautils

from .helpers import (
    calculate_entropy,
    callees_of,
    callers_of,
    find_rc4_ksa,
    find_rc4_prga,
    iter_functions,
    iter_segments,
)
from .tagging import (
    TAG_ENTRY_FUNCTION,
    TAG_LEAF_FUNCTION,
    TAG_RC4_KSA,
    TAG_RC4_PRGA,
    TAG_RECURSIVE_FUNCTION,
    TAG_DESC_ENTRY_FUNCTION,
    TAG_DESC_LEAF_FUNCTION,
    TAG_DESC_RC4_KSA,
    TAG_DESC_RC4_PRGA,
    TAG_DESC_RECURSIVE_FUNCTION,
    clear_heuristic_tags,
    tag_function,
)


def _print_banner(name):
    print("=" * 80)
    print(name)


def find_entry_functions():
    _print_banner("Entry Function")
    clear_heuristic_tags(idautils.Functions(), TAG_ENTRY_FUNCTION)
    for f in iter_functions():
        if len(callers_of(f)) != 0:
            continue
        print("Function 0x%x (%s) has no known callers." % (f.start, f.name))
        tag_function(f, TAG_ENTRY_FUNCTION, TAG_DESC_ENTRY_FUNCTION)


def find_leaf_functions():
    _print_banner("Leaf Function")
    clear_heuristic_tags(idautils.Functions(), TAG_LEAF_FUNCTION)
    for f in iter_functions():
        if len(callees_of(f)) == 0 and sum(1 for _ in f.instruction_addresses()) > 1:
            print("Function 0x%x (%s) has no known callees." % (f.start, f.name))
            tag_function(f, TAG_LEAF_FUNCTION, TAG_DESC_LEAF_FUNCTION)


def find_recursive_functions():
    _print_banner("Recursive Function")
    clear_heuristic_tags(idautils.Functions(), TAG_RECURSIVE_FUNCTION)
    for f in iter_functions():
        if f.start in callees_of(f):
            print("Function 0x%x (%s) is recursive." % (f.start, f.name))
            tag_function(f, TAG_RECURSIVE_FUNCTION, TAG_DESC_RECURSIVE_FUNCTION)


def compute_section_entropy():
    _print_banner("Section Entropy")
    entries = [(s, calculate_entropy(s["data"])) for s in iter_segments()]
    for s, e in sorted(entries, key=lambda x: x[1], reverse=True):
        print("Section %s has an entropy of %.2f." % (s["name"], e))


def find_rc4():
    _print_banner("RC4")
    clear_heuristic_tags(idautils.Functions(), TAG_RC4_KSA)
    clear_heuristic_tags(idautils.Functions(), TAG_RC4_PRGA)
    for f in iter_functions():
        if find_rc4_ksa(f):
            print("Function %s (0x%x) might implement RC4 KSA." % (f.name, f.start))
            tag_function(f, TAG_RC4_KSA, TAG_DESC_RC4_KSA)
        if find_rc4_prga(f):
            print("Function %s (0x%x) might implement RC4 PRGA." % (f.name, f.start))
            tag_function(f, TAG_RC4_PRGA, TAG_DESC_RC4_PRGA)
