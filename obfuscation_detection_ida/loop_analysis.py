"""Natural loops, SCCs, and irreducible loop detection over FunctionGraph."""

from collections import namedtuple
from functools import reduce


def compute_number_of_natural_loops(function):
    return sum(1 for _ in compute_natural_loop_back_edges(function))


def compute_natural_loop_back_edges(function):
    df = function.dominance_frontier()
    for block in function.basic_blocks:
        if block not in df.get(block.id, set()):
            continue
        for edge in block.incoming_edges:
            if function.is_back_edge(edge):
                yield edge


def compute_natural_loop_body(function, back_edge):
    if back_edge.source == back_edge.target:
        return {back_edge.target}
    loop_body = {back_edge.target, back_edge.source}
    todo = [back_edge.source]
    while todo:
        block = todo.pop()
        for edge in block.incoming_edges:
            if edge.source == back_edge.target:
                continue
            if edge.source not in loop_body:
                loop_body.add(edge.source)
                todo.append(edge.source)
    return loop_body


def compute_natural_loops(function):
    return {
        back_edge: compute_natural_loop_body(function, back_edge)
        for back_edge in compute_natural_loop_back_edges(function)
    }


def compute_blocks_in_natural_loops(function):
    return reduce(
        lambda x, y: x | y,
        (v for v in compute_natural_loops(function).values()),
        set(),
    )


def compute_strongly_connected_components(function):
    """Iterative Gabow SCC."""
    stack = []
    boundaries = []
    counter = len(function.basic_blocks)
    index = {b: 0 for b in function.basic_blocks}

    VISIT, HANDLE_RECURSION, MERGE = 0, 1, 2
    BlockState = namedtuple("BlockState", ["state", "block"])

    for block in function.basic_blocks:
        if index[block]:
            continue
        todo = [BlockState(VISIT, block)]
        done = set()
        while todo:
            current = todo.pop()
            if current.block in done:
                continue
            if current.state == VISIT:
                stack.append(current.block)
                index[current.block] = len(stack)
                boundaries.append(index[current.block])
                todo.append(BlockState(MERGE, current.block))
                for edge in current.block.outgoing_edges:
                    todo.append(BlockState(HANDLE_RECURSION, edge.target))
            elif current.state == HANDLE_RECURSION:
                if index[current.block] == 0:
                    todo.append(BlockState(VISIT, current.block))
                else:
                    while index[current.block] < boundaries[-1]:
                        boundaries.pop()
            else:
                if index[current.block] == boundaries[-1]:
                    boundaries.pop()
                    counter += 1
                    scc = set()
                    while index[current.block] <= len(stack):
                        popped = stack.pop()
                        index[popped] = counter
                        scc.add(popped)
                        done.add(current.block)
                    yield scc


def scc_is_loop(scc):
    return len(scc) > 1 or any(
        edge.target == block for block in scc for edge in block.outgoing_edges
    )


def compute_irreducible_loops(function):
    blocks_in_natural_loops = compute_blocks_in_natural_loops(function)
    return [
        scc
        for scc in compute_strongly_connected_components(function)
        if scc_is_loop(scc) and not scc.issubset(blocks_in_natural_loops)
    ]
