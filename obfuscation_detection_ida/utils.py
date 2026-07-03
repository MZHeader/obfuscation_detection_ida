"""Utility detections: entry / leaf / recursive functions, RC4, section entropy.

These wrap the corresponding builders in reports.py so any thresholds and
filters defined there apply uniformly whether the user invokes a heuristic
individually from the chooser or via `run_all` / `run_utils`.
"""

import idautils

from .helpers import calculate_entropy, iter_segments
from .reports import (
    find_entry_function_reports,
    find_leaf_function_reports,
    find_recursive_function_reports,
    find_rc4_ksa_reports,
    find_rc4_prga_reports,
)
from .tagging import (
    TAG_ENTRY_FUNCTION,
    TAG_LEAF_FUNCTION,
    TAG_RC4_KSA,
    TAG_RC4_PRGA,
    TAG_RECURSIVE_FUNCTION,
    annotate_ea,
    clear_heuristic_tags,
    tag_function,
)


def _print_banner(name):
    print("=" * 80)
    print(name)


def _apply_findings(findings, tag_type, extra_key=None):
    """Clear old tags for this heuristic and re-tag from `findings`.

    Kept local so utils.py doesn't depend on heuristics.py's `_apply`. Any
    anchor addresses in a finding get a per-line annotation as well.
    """
    clear_heuristic_tags(idautils.Functions(), tag_type)
    for finding in findings:
        start = int(finding["address"], 16)
        extra = ("%s=%s " % (extra_key, finding[extra_key])) if extra_key and extra_key in finding else ""
        print("Function 0x%x (%s) %s" % (start, finding["name"], extra))
        tag_function(start, tag_type, finding["description"])
        for anchor in finding.get("anchor_addresses", ()):
            annotate_ea(anchor, tag_type, finding["description"])


def find_entry_functions():
    _print_banner("Entry Function")
    _apply_findings(find_entry_function_reports(), TAG_ENTRY_FUNCTION)


def find_leaf_functions():
    _print_banner("Leaf Function")
    _apply_findings(find_leaf_function_reports(), TAG_LEAF_FUNCTION)


def find_recursive_functions():
    _print_banner("Recursive Function")
    _apply_findings(find_recursive_function_reports(), TAG_RECURSIVE_FUNCTION)


def compute_section_entropy():
    _print_banner("Section Entropy")
    entries = [(s, calculate_entropy(s["data"])) for s in iter_segments()]
    for s, e in sorted(entries, key=lambda x: x[1], reverse=True):
        print("Section %s has an entropy of %.2f." % (s["name"], e))


def find_rc4():
    _print_banner("RC4")
    _apply_findings(find_rc4_ksa_reports(), TAG_RC4_KSA)
    _apply_findings(find_rc4_prga_reports(), TAG_RC4_PRGA)
