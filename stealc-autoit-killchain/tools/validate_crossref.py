#!/usr/bin/env python3
"""Cross-validation for the StealC/AutoIt Switch-resolution hypothesis.

For every flattened Switch block in script.au3, independently compute:
  Method A: arithmetic match (reinterpret near-2^32/2^64 literals as signed, evaluate
            the initial state expression and every Case expression, find the Case
            whose value equals the initial state).
  Method B: structural heuristic (the Case containing ExitLoop/Return is presumed live,
            since dead/decoy branches never end the flattening loop).

Then compare A vs B across the WHOLE file (not just hand-picked examples) and report
how often they agree, disagree, or are inconclusive on one side.
"""
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "script.au3"

TWO_31, TWO_32, TWO_63, TWO_64 = 2**31, 2**32, 2**63, 2**64

def fix_int(v: int) -> int:
    if TWO_63 <= v < TWO_64:
        return v - TWO_64
    if TWO_31 <= v < TWO_32:
        return v - TWO_32
    return v

TOKEN_RE = re.compile(r'''
    (?P<num>\d+)
  | (?P<bitxor>BitXOR)
  | (?P<bitshift>BitShift)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<comma>,)
  | (?P<op>[+\-*/])
''', re.VERBOSE)

class ParseError(Exception):
    pass

class ExprParser:
    def __init__(self, text):
        self.tokens = [(m.lastgroup, m.group()) for m in TOKEN_RE.finditer(text)]
        self.pos = 0
    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)
    def next(self):
        t = self.peek(); self.pos += 1; return t
    def parse(self):
        return self.expr()
    def expr(self):
        v = self.term()
        while self.peek()[0] == 'op' and self.peek()[1] in '+-':
            op = self.next()[1]; rhs = self.term()
            v = v + rhs if op == '+' else v - rhs
        return v
    def term(self):
        v = self.factor()
        while self.peek()[0] == 'op' and self.peek()[1] in '*/':
            op = self.next()[1]; rhs = self.factor()
            v = v * rhs if op == '*' else v / rhs
        return v
    def factor(self):
        kind, val = self.peek()
        if kind == 'op' and val in '+-':
            self.next(); f = self.factor(); return f if val == '+' else -f
        if kind == 'num':
            self.next(); return fix_int(int(val))
        if kind == 'lparen':
            self.next(); v = self.expr(); assert self.next()[0] == 'rparen'; return v
        if kind == 'bitxor':
            self.next(); assert self.next()[0] == 'lparen'
            a = self.expr(); assert self.next()[0] == 'comma'
            b = self.expr(); assert self.next()[0] == 'rparen'
            return float(int(a) ^ int(b))
        if kind == 'bitshift':
            self.next(); assert self.next()[0] == 'lparen'
            a = self.expr(); assert self.next()[0] == 'comma'
            b = self.expr(); assert self.next()[0] == 'rparen'
            return float(int(a) >> int(b))
        raise ParseError(f"unexpected token {kind!r} {val!r}")

def safe_eval(expr_text: str):
    return ExprParser(expr_text).parse()

def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip('\t'))

def find_switches(lines):
    """Yield (switch_line_idx, var, init_val_or_None, cases) for every Switch block.
    cases is a list of (expr_text, body_lines)."""
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        m = re.match(r'Switch \$(\w+)$', stripped)
        if not m:
            i += 1
            continue
        switch_indent = indent_of(line)
        var = m.group(1)

        init_val = None
        # look upward for the nearest preceding "$VAR = <expr>" (search further back:
        # an earlier bug capped this at 5 lines and produced false "unresolved" blocks
        # whenever the assignment sat just outside that window, e.g. inside a preceding
        # If/Else branch)
        for k in range(i - 1, max(-1, i - 60), -1):
            prev = lines[k].strip()
            pm = re.match(rf'\${re.escape(var)} = (.+)$', prev)
            if pm:
                try:
                    init_val = safe_eval(pm.group(1))
                except Exception:
                    init_val = None
                break

        j = i + 1
        cases = []
        cur_expr, cur_body = None, []
        while j < n:
            l2 = lines[j]
            s2 = l2.strip()
            ind2 = indent_of(l2)
            if ind2 == switch_indent and s2 == 'EndSwitch':
                if cur_expr is not None:
                    cases.append((cur_expr, cur_body))
                break
            cm = re.match(r'Case (.+)$', s2)
            if ind2 == switch_indent and cm:
                if cur_expr is not None:
                    cases.append((cur_expr, cur_body))
                cur_expr, cur_body = cm.group(1), []
            else:
                cur_body.append(l2)
            j += 1
        else:
            i += 1
            continue

        yield i, var, init_val, cases
        i = j + 1

def method_a(init_val, cases):
    """Arithmetic match: returns index of matching case, or None/'ambiguous'."""
    if init_val is None:
        return None
    matches = []
    for idx, (expr_text, _) in enumerate(cases):
        try:
            if safe_eval(expr_text) == init_val:
                matches.append(idx)
        except Exception:
            continue
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return 'ambiguous'
    return None

def method_b(cases):
    """Structural heuristic: returns index of the Case containing ExitLoop/Return."""
    matches = [idx for idx, (_, body) in enumerate(cases)
               if any('ExitLoop' in bl or 'Return' in bl for bl in body)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return 'ambiguous'
    return None

def main():
    text = open(SRC, encoding='utf-8', errors='replace').read()
    lines = text.split('\n')

    total = 0
    both_found = 0
    agree = 0
    disagree = 0
    a_only = 0
    b_only = 0
    neither = 0
    disagreements = []

    for switch_idx, var, init_val, cases in find_switches(lines):
        total += 1
        a = method_a(init_val, cases)
        b = method_b(cases)

        a_ok = isinstance(a, int)
        b_ok = isinstance(b, int)

        if a_ok and b_ok:
            both_found += 1
            if a == b:
                agree += 1
            else:
                disagree += 1
                disagreements.append((switch_idx, var, a, b))
        elif a_ok and not b_ok:
            a_only += 1
        elif b_ok and not a_ok:
            b_only += 1
        else:
            neither += 1

    print(f"Total Switch blocks found: {total}")
    print(f"Both methods gave a unique answer: {both_found}")
    print(f"  - agree:    {agree}")
    print(f"  - disagree: {disagree}")
    print(f"Only method A (arithmetic) resolved: {a_only}")
    print(f"Only method B (ExitLoop/Return) resolved: {b_only}")
    print(f"Neither method resolved: {neither}")
    if disagreements:
        print("\nDisagreements (line, var, method A index, method B index):")
        for d in disagreements:
            print(" ", d)

if __name__ == '__main__':
    main()
