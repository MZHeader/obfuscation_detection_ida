"""Obfuscation detection heuristics ported to IDA Pro.

Exposes both the individual heuristics and an aggregate `run_all()` helper."""

from .heuristics import (
    find_complex_arithmetic_expressions,
    find_complex_functions,
    find_duplicated_subgraphs,
    find_instruction_overlapping,
    find_irreducible_loops,
    find_large_basic_blocks,
    find_loop_frequency_functions,
    find_most_called_functions,
    find_state_machines,
    find_uncommon_instruction_sequences,
    find_xor_decryption_loops,
)
from .utils import (
    compute_section_entropy,
    find_entry_functions,
    find_leaf_functions,
    find_recursive_functions,
    find_rc4,
)


def run_heuristics():
    find_state_machines()
    find_complex_functions()
    find_large_basic_blocks()
    find_uncommon_instruction_sequences()
    find_instruction_overlapping()
    find_most_called_functions()
    find_loop_frequency_functions()
    find_irreducible_loops()
    find_xor_decryption_loops()
    find_complex_arithmetic_expressions()
    find_duplicated_subgraphs()


def run_utils():
    find_entry_functions()
    find_leaf_functions()
    find_recursive_functions()
    compute_section_entropy()
    find_rc4()


def run_all():
    run_heuristics()
    run_utils()
