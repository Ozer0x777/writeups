#!/usr/bin/env python3
"""Control-flow de-flattening for the AgentTesla stage-2 .NET switch(state) pattern.

Unlike the AutoIt/AsgardProtector case (1 real branch + N decoys per Switch,
resolved by matching a computed initial value against Case constants), this
C# obfuscator produces genuine control-flow flattening: every case is real
code, chained together via assignments to a state variable, with real
conditional branches (an if/else inside a case can send execution to two
different next-states). Case labels and next-state assignments are plain
integer literals here (no signed-int reinterpretation needed).

Strategy:
1. Find every `switch (VAR) { case N: ... }` block in the file.
2. Split each block into per-case bodies (a case body runs until the next
   `case`/`default` label at the same brace depth, or the closing `}` of the
   switch).
3. Within each body, find every assignment `VAR = <int literal>;` and record
   it together with its brace depth *relative to the case body* (depth 0 =
   unconditional / always executes; depth > 0 = inside an if/else, i.e. a
   real branch).
4. Depth-0 assignments -> the "default" successor of that case (only one is
   expected; if the case body has zero depth-0 state assignments and ends
   in break/return, it's a terminal node for this switch).
   Depth>0 assignments -> additional possible successors (branches); the
   guarding `if (...)` text is captured on a best-effort basis for context.
5. Emit a per-switch report: node count, how many are linear (single
   successor) vs branching (multiple) vs terminal, and a graph dump.
"""
import re
import sys
from dataclasses import dataclass, field

SRC = sys.argv[1] if len(sys.argv) > 1 else "stage2.cs"

CASE_RE = re.compile(r'^\s*case\s+(-?\d+)\s*:\s*$')
DEFAULT_RE = re.compile(r'^\s*default\s*:\s*$')
SWITCH_RE = re.compile(r'^\s*switch\s*\(\s*(\w+)\s*\)\s*$')


@dataclass
class CaseNode:
    ids: list          # one body can be labelled by several stacked case N:
    body: list = field(default_factory=list)   # raw lines
    default_edge: object = None      # ('CASE', N) | ('EXIT', desc) | None
    branch_edges: list = field(default_factory=list)  # [('CASE', N) | ('EXIT', desc), ...]
    terminal: bool = False   # exits the dispatch loop unconditionally
    data_dependent: bool = False   # only non-literal assignment(s) found: next
                                    # state depends on runtime data (stream/array
                                    # read, etc.), not statically resolvable


def find_matching_brace(lines, open_line_idx):
    """Given the index of a line containing the opening '{' of a block,
    return the index of the line containing its matching closing '}'."""
    depth = 0
    started = False
    for i in range(open_line_idx, len(lines)):
        for ch in lines[i]:
            if ch == '{':
                depth += 1
                started = True
            elif ch == '}':
                depth -= 1
                if started and depth == 0:
                    return i
    return None


def find_switch_blocks(lines):
    """Yield (state_var, header_idx, brace_open_idx, brace_close_idx)."""
    for i, line in enumerate(lines):
        m = SWITCH_RE.match(line)
        if not m:
            continue
        # the opening brace is expected on the next non-blank line
        j = i + 1
        while j < len(lines) and lines[j].strip() == '':
            j += 1
        if j >= len(lines) or '{' not in lines[j]:
            continue
        close = find_matching_brace(lines, j)
        if close is None:
            continue
        yield m.group(1), i, j, close


def split_cases(lines, var, open_idx, close_idx):
    """Split a switch body into CaseNode objects. open_idx/close_idx are the
    lines with the switch's outer { and }."""
    nodes = []
    cur_ids = []
    cur_body = []
    base_depth = None  # brace depth right inside the switch (case labels live here)
    depth = 0
    i = open_idx
    # compute depth at the line right after the opening brace
    for ch in lines[open_idx]:
        if ch == '{':
            depth += 1
    base_depth = depth  # depth==1 means "directly inside switch"

    def flush():
        if cur_ids:
            nodes.append(CaseNode(ids=list(cur_ids), body=list(cur_body)))

    i = open_idx + 1
    while i < close_idx:
        line = lines[i]
        stripped = line.strip()
        if depth == base_depth and (CASE_RE.match(stripped) or DEFAULT_RE.match(stripped)):
            m = CASE_RE.match(stripped)
            if m:
                if cur_body:  # a new label starts a new node, unless stacked labels with empty body
                    flush()
                    cur_ids = []
                    cur_body = []
                cur_ids.append(int(m.group(1)))
            else:
                if cur_body:
                    flush()
                    cur_ids = []
                    cur_body = []
                cur_ids.append(None)  # default
        else:
            cur_body.append(line)
        for ch in line:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
        i += 1
    flush()
    return nodes


# Literal integer assignment to the state var, with optional C# numeric
# suffix (0u, 1L, 2UL...) which an earlier version of this regex missed,
# silently dropping those assignments and mislabelling their case as
# terminal even though a real (just non-numeric-looking) transition existed.
LITERAL_ASSIGN_RE = re.compile(r'\b(\w+)\s*=\s*([+-]?\d+)[uUlL]*\s*;')
# Any assignment at all to the state var, literal or not (data reads,
# expressions...) -- used only to detect the "data-dependent" case.
ANY_ASSIGN_RE = re.compile(r'\b(\w+)\s*=\s*[^;=][^;]*;')
# `goto case N;` -- an explicit jump to another case, found by manual
# cross-check (Partie "verification manuelle") to be missed entirely by the
# first version of this script, silently mislabelling branching/terminal
# nodes that use goto instead of a state-variable reassignment.
GOTO_CASE_RE = re.compile(r'\bgoto\s+case\s+(-?\d+)\s*;')
# `goto SomeLabel;` -- jump out of the switch entirely to a label elsewhere
# in the method (e.g. `goto end_IL_0014;`). Treated as an EXIT edge: we
# don't attempt to resolve what happens after the label, just record that
# this path leaves the dispatch loop through it.
GOTO_LABEL_RE = re.compile(r'\bgoto\s+(?!case\b)(\w+)\s*;')
RETURN_RE = re.compile(r'\breturn\b[^;]*;')
THROW_RE = re.compile(r'\bthrow\b[^;]*;')


def analyze_case(node: CaseNode, var: str):
    depth = 0
    edges = []        # (depth, ('CASE', n) | ('EXIT', desc))
    any_found = 0      # count of non-literal assignments to var (data-dependent signal)
    for line in node.body:
        stripped = line.strip()
        for m in LITERAL_ASSIGN_RE.finditer(stripped):
            if m.group(1) == var:
                edges.append((depth, ('CASE', int(m.group(2)))))
        for m in ANY_ASSIGN_RE.finditer(stripped):
            if m.group(1) == var:
                any_found += 1
        for m in GOTO_CASE_RE.finditer(stripped):
            edges.append((depth, ('CASE', int(m.group(1)))))
        for m in GOTO_LABEL_RE.finditer(stripped):
            edges.append((depth, ('EXIT', f'goto {m.group(1)}')))
        if RETURN_RE.search(stripped):
            edges.append((depth, ('EXIT', 'return')))
        if THROW_RE.search(stripped):
            edges.append((depth, ('EXIT', 'throw')))
        for ch in line:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1

    unconditional = [e for d, e in edges if d == 0]
    conditional = [e for d, e in edges if d > 0]
    if unconditional:
        node.default_edge = unconditional[-1]
    node.branch_edges = conditional

    if not edges:
        if any_found:
            # only non-literal (data-dependent) assignments to the state
            # var found, and no goto/return/throw either: the next state
            # depends on runtime data, not statically resolvable.
            node.data_dependent = True
        else:
            # no edge of any kind detected -- genuinely falls off the end
            # of the case body (only valid for the last case before the
            # switch's closing brace, otherwise indicates a gap in the
            # regexes above rather than a real property of the code).
            node.terminal = True
    elif node.default_edge is not None and node.default_edge[0] == 'EXIT' and not node.branch_edges:
        node.terminal = True


def main():
    text = open(SRC, encoding='utf-8', errors='replace').read()
    lines = text.split('\n')

    total_switches = 0
    report = []
    for var, header_idx, open_idx, close_idx in find_switch_blocks(lines):
        nodes = split_cases(lines, var, open_idx, close_idx)
        if len(nodes) < 5:
            continue  # too small to be a flattening dispatcher, skip (real small switches)
        total_switches += 1
        for n in nodes:
            analyze_case(n, var)
        linear = sum(1 for n in nodes if n.default_edge is not None and not n.branch_edges and not n.terminal)
        branching = sum(1 for n in nodes if n.branch_edges)
        terminal = sum(1 for n in nodes if n.terminal)
        data_dep = sum(1 for n in nodes if n.data_dependent)
        unresolved = len(nodes) - linear - branching - terminal - data_dep
        report.append((header_idx + 1, var, len(nodes), linear, branching, terminal, data_dep, unresolved))

    print(f"Switches de dispatch detectes (>=5 cases): {total_switches}")
    print(f"{'ligne':>6} {'var':>6} {'cases':>6} {'lineaires':>9} {'branchants':>10} {'terminaux':>9} {'donnee-dep':>10} {'non-resolus':>11}")
    tot_cases = tot_lin = tot_branch = tot_term = tot_dd = tot_unres = 0
    for line_no, var, n, lin, br, term, dd, unres in report:
        print(f"{line_no:>6} {var:>6} {n:>6} {lin:>9} {br:>10} {term:>9} {dd:>10} {unres:>11}")
        tot_cases += n; tot_lin += lin; tot_branch += br; tot_term += term; tot_dd += dd; tot_unres += unres
    print("-" * 70)
    print(f"TOTAL   cases={tot_cases} lineaires={tot_lin} branchants={tot_branch} terminaux={tot_term} donnee_dependants={tot_dd} non_resolus={tot_unres}")


if __name__ == '__main__':
    main()
