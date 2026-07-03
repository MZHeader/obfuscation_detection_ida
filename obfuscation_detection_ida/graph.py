"""CFG abstraction over IDA's FlowChart, plus dominator / dominance-frontier /
back-edge / SCC utilities.

The heuristics ported from the Binary Ninja plugin rely heavily on graph
primitives that Binary Ninja exposes directly (dominator_tree_children,
dominance_frontier, edge.back_edge). IDA's SDK does not, so we compute them
ourselves and wrap FlowChart in a friendlier `FunctionGraph` object.
"""

from collections import namedtuple

import ida_bytes
import ida_funcs
import idaapi

Edge = namedtuple("Edge", ["source", "target"])


class Block(object):
    """Basic-block wrapper. `id` is the FlowChart node index, unique per function."""

    __slots__ = ("id", "start", "end", "graph", "_succ_ids", "_pred_ids")

    def __init__(self, graph, node):
        self.graph = graph
        self.id = node.id
        self.start = node.start_ea
        self.end = node.end_ea
        self._succ_ids = [s.id for s in node.succs()]
        self._pred_ids = [p.id for p in node.preds()]

    @property
    def successors(self):
        return [self.graph.blocks[i] for i in self._succ_ids]

    @property
    def predecessors(self):
        return [self.graph.blocks[i] for i in self._pred_ids]

    @property
    def outgoing_edges(self):
        return [Edge(self, s) for s in self.successors]

    @property
    def incoming_edges(self):
        return [Edge(p, self) for p in self.predecessors]

    @property
    def instruction_count(self):
        n = 0
        ea = self.start
        while ea != idaapi.BADADDR and ea < self.end:
            n += 1
            ea = ida_bytes.next_head(ea, self.end)
        return n

    def instruction_addresses(self):
        ea = self.start
        while ea != idaapi.BADADDR and ea < self.end:
            yield ea
            ea = ida_bytes.next_head(ea, self.end)

    def __hash__(self):
        return hash((self.graph.start, self.id))

    def __eq__(self, other):
        return isinstance(other, Block) and other.graph.start == self.graph.start and other.id == self.id

    def __repr__(self):
        return "Block(0x%x-0x%x)" % (self.start, self.end)


class FunctionGraph(object):
    """Wrap an ida_funcs.func_t so it looks like the Binary Ninja Function
    objects the heuristics were written against."""

    def __init__(self, func):
        self.func = func
        self.start = func.start_ea
        self.end = func.end_ea
        self.name = ida_funcs.get_func_name(func.start_ea) or ("sub_%x" % func.start_ea)
        # Build FlowChart, ignoring external blocks.
        fc = idaapi.FlowChart(func, flags=idaapi.FC_PREDS | idaapi.FC_NOEXT)
        self.blocks = []
        self._entry_id = None
        for node in fc:
            b = Block(self, node)
            # extend list to hold this id
            while len(self.blocks) <= node.id:
                self.blocks.append(None)
            self.blocks[node.id] = b
            if node.start_ea == func.start_ea:
                self._entry_id = node.id
        # Drop any Nones (shouldn't happen but be safe)
        self.blocks = [b for b in self.blocks if b is not None]
        # Fix up entry: FlowChart's node 0 is usually the entry.
        if self._entry_id is None and self.blocks:
            self._entry_id = self.blocks[0].id

        self._dom = None            # immediate dominator: id -> id
        self._dom_tree = None       # id -> [child ids]
        self._dom_frontier = None   # id -> set(ids)
        self._back_edges = None     # list of Edge

    # ---------- accessors used by heuristics ----------

    @property
    def basic_blocks(self):
        return self.blocks

    def entry_block(self):
        for b in self.blocks:
            if b.id == self._entry_id:
                return b
        return self.blocks[0] if self.blocks else None

    def instruction_addresses(self):
        for b in self.blocks:
            for ea in b.instruction_addresses():
                yield ea

    # ---------- dominators ----------

    def _compute_dominators(self):
        """Cooper–Harvey–Kennedy iterative dominator algorithm."""
        if not self.blocks:
            self._dom = {}
            return
        entry = self.entry_block()
        # Reverse-post-order from entry.
        order = self._reverse_postorder(entry)
        rpo_index = {b.id: i for i, b in enumerate(order)}
        dom = {b.id: None for b in self.blocks}
        dom[entry.id] = entry.id

        def intersect(b1, b2):
            f1, f2 = b1, b2
            while f1 != f2:
                while rpo_index[f1] > rpo_index[f2]:
                    f1 = dom[f1]
                while rpo_index[f2] > rpo_index[f1]:
                    f2 = dom[f2]
            return f1

        changed = True
        while changed:
            changed = False
            for b in order:
                if b is entry:
                    continue
                new_idom = None
                for p in b.predecessors:
                    if p.id not in rpo_index:
                        continue
                    if dom[p.id] is None:
                        continue
                    new_idom = p.id if new_idom is None else intersect(p.id, new_idom)
                if new_idom is not None and dom[b.id] != new_idom:
                    dom[b.id] = new_idom
                    changed = True
        self._dom = dom

    def _reverse_postorder(self, entry):
        visited = set()
        order = []

        def dfs(b):
            stack = [(b, iter(b.successors))]
            visited.add(b.id)
            while stack:
                node, it = stack[-1]
                try:
                    nxt = next(it)
                    if nxt.id not in visited:
                        visited.add(nxt.id)
                        stack.append((nxt, iter(nxt.successors)))
                except StopIteration:
                    order.append(node)
                    stack.pop()

        dfs(entry)
        order.reverse()
        return order

    def immediate_dominators(self):
        if self._dom is None:
            self._compute_dominators()
        return self._dom

    def dominator_tree(self):
        if self._dom_tree is not None:
            return self._dom_tree
        idom = self.immediate_dominators()
        tree = {b.id: [] for b in self.blocks}
        for node, parent in idom.items():
            if parent is None or parent == node:
                continue
            tree[parent].append(node)
        self._dom_tree = tree
        return tree

    def dominated_by(self, block):
        """All blocks that `block` dominates (transitively, including itself)."""
        tree = self.dominator_tree()
        out = set()
        stack = [block.id]
        while stack:
            i = stack.pop()
            if i in out:
                continue
            out.add(i)
            for c in tree.get(i, ()):
                stack.append(c)
        return {self.blocks_by_id()[i] for i in out}

    def blocks_by_id(self):
        return {b.id: b for b in self.blocks}

    def dominates(self, a, b):
        idom = self.immediate_dominators()
        cur = b.id
        while cur is not None:
            if cur == a.id:
                return True
            parent = idom.get(cur)
            if parent == cur:
                return cur == a.id
            cur = parent
        return False

    # ---------- dominance frontier ----------

    def dominance_frontier(self):
        if self._dom_frontier is not None:
            return self._dom_frontier
        idom = self.immediate_dominators()
        df = {b.id: set() for b in self.blocks}
        by_id = self.blocks_by_id()
        for b in self.blocks:
            preds = b.predecessors
            if len(preds) < 2:
                continue
            for p in preds:
                if p.id not in idom or idom[p.id] is None:
                    continue
                runner = p.id
                while runner != idom.get(b.id) and runner is not None:
                    df[runner].add(b.id)
                    nxt = idom.get(runner)
                    if nxt == runner:
                        break
                    runner = nxt
        self._dom_frontier = {i: {by_id[j] for j in ids if j in by_id} for i, ids in df.items()}
        return self._dom_frontier

    def block_in_own_dominance_frontier(self, block):
        df = self.dominance_frontier()
        return block in df.get(block.id, set())

    # ---------- back edges ----------

    def back_edges(self):
        """Edges (u -> v) where v dominates u."""
        if self._back_edges is not None:
            return self._back_edges
        idom = self.immediate_dominators()
        by_id = self.blocks_by_id()
        result = []
        for u in self.blocks:
            for v in u.successors:
                cur = u.id
                while cur is not None:
                    if cur == v.id:
                        result.append(Edge(u, v))
                        break
                    parent = idom.get(cur)
                    if parent is None or parent == cur:
                        break
                    cur = parent
        self._back_edges = result
        return result

    def is_back_edge(self, edge):
        return any(e.source is edge.source and e.target is edge.target for e in self.back_edges())
