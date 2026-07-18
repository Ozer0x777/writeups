#!/usr/bin/env python3
"""Linearize the flattened switch(state) dispatchers found by deflatten_cs.py.

deflatten_cs.py answers "what does the graph look like" (node counts,
linear/branching/terminal/data-dependent tally). This script actually walks
each graph from its entry state and emits the case bodies in traversal
order, with the dispatcher bookkeeping (`var = N; break;` / `goto case N;`)
stripped and replaced by an explicit `// edges: ...` line per block --
turning one opaque 4000-line switch into a sequence of labelled basic
blocks that read top to bottom, closer in spirit to what `deobfuscate.py`
did for the AutoIt Switch blocks (strip the flattening scaffold, keep the
real logic, make branch points explicit) even though the underlying
transform is a different, harder kind of obfuscation (real CFG flattening,
not "1 live branch + N decoys").

Iterative DFS (not recursive) because some chains here are hundreds of
nodes long -- a recursive walk would risk hitting Python's recursion limit.
"""
import re
import sys

sys.path.insert(0, "/home/ozer/ctf-reverse/tools")
from deflatten_cs import find_switch_blocks, split_cases, analyze_case  # noqa: E402

SRC = sys.argv[1] if len(sys.argv) > 1 else "stage2.cs"
OUT = sys.argv[2] if len(sys.argv) > 2 else "stage2_linearized.txt"

# Both regexes accept an optional leading type token (`int num2 = num;` is a
# *declaration*, not a plain reassignment `num2 = num;` -- the first version
# only matched the latter form and so silently failed to follow the very
# copy chains (`int num2 = num; ... int num3 = num2;`) this function exists
# to walk, on every switch in the file.
ASSIGN_COPY_RE = re.compile(r'^\s*(?:[\w<>\[\],\.]+\s+)?(\w+)\s*=\s*(\w+)\s*;\s*$')
LITERAL_INT_RE = re.compile(r'^\s*(?:[\w<>\[\],\.]+\s+)?(\w+)\s*=\s*([+-]?\d+)[uUlL]*\s*;\s*$')
STATE_BOOKKEEPING_RE_TMPL = r'^\s*{var}\s*=\s*[+-]?\d+[uUlL]*\s*;\s*$|^\s*break\s*;\s*$|^\s*goto\s+case\s+-?\d+\s*;\s*$'


METHOD_START_RE = re.compile(
    r'^\s*(?:\[[^\]]*\]\s*)*'
    r'(?:public|private|internal|protected|static|sealed|virtual|override|'
    r'abstract|async|unsafe|new|extern|\s)*'
    r'[\w<>\[\],\.\?]+\s+[\w<>\[\]]+\s*\([^;{]*\)\s*$'
)


def method_start_before(lines, idx):
    """Find the nearest enclosing method signature line at or before idx,
    used to bound the backward search for the state var's literal seed.
    A first version of this used a fixed 60-line window (copied from the
    AutoIt deobfuscator) which was nowhere near enough here: this file's
    methods have huge local-variable declaration blocks, and the literal
    seed for the biggest switch sits 114 lines before its header -- almost
    2x that window. Bounding by the actual method start instead of a magic
    number avoids having to guess a new, still possibly-wrong constant."""
    for i in range(idx, -1, -1):
        if METHOD_START_RE.match(lines[i]):
            return i
    return max(0, idx - 500)  # fallback if no signature matched


def find_entry_value(lines, var, header_idx):
    """Walk backward from the switch header, following simple copy chains
    (`x = y;`) back to the literal that seeds the dispatch variable. Bounded
    by the enclosing method's start rather than a fixed line count."""
    lower_bound = method_start_before(lines, header_idx)
    target = var
    for i in range(header_idx - 1, lower_bound - 1, -1):
        line = lines[i].strip()
        m = LITERAL_INT_RE.match(line)
        if m and m.group(1) == target:
            return int(m.group(2))
        m = ASSIGN_COPY_RE.match(line)
        if m and m.group(1) == target:
            target = m.group(2)
    return None


def strip_bookkeeping(body_lines, var):
    pat = re.compile(STATE_BOOKKEEPING_RE_TMPL.format(var=re.escape(var)))
    return [l for l in body_lines if not pat.match(l.strip())]


def edge_desc(edge):
    if edge is None:
        return None
    kind, val = edge
    return f"etat {val}" if kind == 'CASE' else str(val)


def linearize_switch(lines, var, header_idx, open_idx, close_idx, out):
    nodes = split_cases(lines, var, open_idx, close_idx)
    by_id = {}
    default_node = None
    for n in nodes:
        analyze_case(n, var)
        for cid in n.ids:
            if cid is None:
                default_node = n
            else:
                by_id[cid] = n

    entry = find_entry_value(lines, var, header_idx)
    out.append(f"\n// {'='*70}\n// switch({var}) @ ligne source {header_idx + 1} -- {len(nodes)} cases\n// {'='*70}")

    if entry is None:
        out.append("// point d'entree NON RESOLU -- aucune linearisation possible pour ce switch")
        return

    out.append(f"// point d'entree detecte: etat {entry}")

    seen = set()
    order = []
    stack = [entry]
    while stack:
        cid = stack.pop()
        if cid in seen or cid not in by_id:
            continue
        seen.add(cid)
        order.append(cid)
        node = by_id[cid]
        targets = [v for k, v in node.branch_edges if k == 'CASE']
        if node.default_edge and node.default_edge[0] == 'CASE':
            targets.append(node.default_edge[1])
        for t in reversed(targets):
            if t not in seen:
                stack.append(t)

    for cid in order:
        node = by_id[cid]
        out.append(f"\n// -- etat {cid} " + "-" * 50)
        body = strip_bookkeeping(node.body, var)
        out.extend(body)
        edges = []
        if node.default_edge:
            edges.append(f"defaut -> {edge_desc(node.default_edge)}")
        for e in node.branch_edges:
            edges.append(f"branche -> {edge_desc(e)}")
        if node.terminal:
            edges.append("TERMINAL")
        if node.data_dependent:
            edges.append("etat suivant determine a l'execution (donnee runtime, non resolvable statiquement)")
        out.append(f"// edges: {' | '.join(edges) if edges else '(aucune trouvee)'}")

    all_ids = set(by_id.keys())
    orphans = sorted(all_ids - seen)
    out.append(f"\n// Etats atteints depuis l'entree: {len(seen)}/{len(all_ids)}")
    if orphans:
        preview = orphans[:40]
        suffix = " ..." if len(orphans) > 40 else ""
        out.append(f"// Etats JAMAIS atteints depuis ce point d'entree (code mort potentiel, "
                    f"ou entree secondaire non detectee -- a verifier, pas a supposer mort) : {preview}{suffix}")

    if default_node is not None:
        out.append(f"\n// -- case 'default' (repli si aucun case litteral ne correspond) " + "-" * 10)
        out.extend(strip_bookkeeping(default_node.body, var))
        edges = []
        if default_node.default_edge:
            edges.append(f"defaut -> {edge_desc(default_node.default_edge)}")
        for e in default_node.branch_edges:
            edges.append(f"branche -> {edge_desc(e)}")
        out.append(f"// edges: {' | '.join(edges) if edges else '(aucune trouvee)'}")


def main():
    text = open(SRC, encoding='utf-8', errors='replace').read()
    lines = text.split('\n')
    out = []
    n_switches = 0
    for var, header_idx, open_idx, close_idx in find_switch_blocks(lines):
        preview = split_cases(lines, var, open_idx, close_idx)
        if len(preview) < 5:
            continue
        n_switches += 1
        linearize_switch(lines, var, header_idx, open_idx, close_idx, out)

    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    print(f"{n_switches} switch(es) linearise(s)")
    print(f"Wrote {OUT} ({len(out)} lignes, vs {len(lines)} lignes dans le fichier decompile source)")


if __name__ == '__main__':
    main()
