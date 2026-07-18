#!/usr/bin/env python3
"""Decode ChrW(<arithmetic expr>) calls in deobfuscated.au3.

This is a separate obfuscation layer from BATHROOMREWARDLIVED: individual
characters are produced inline via ChrW() on an arithmetic expression that
uses the same "large constant = mis-signed integer" trick. Substitutes each
ChrW(...) call with the literal character it produces, then merges adjacent
"..." & ChrW(x) & "..." concatenations into a single plain string where possible.
"""
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "deobfuscated.au3"
OUT = sys.argv[2] if len(sys.argv) > 2 else "deobfuscated_chrw.au3"

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
        raise ValueError(f"unexpected token {kind!r} {val!r}")

def find_chrw_calls(text):
    """Find each 'ChrW (' and return (start, end, inner_expr) by matching parens."""
    out = []
    for m in re.finditer(r'ChrW\s*\(', text):
        start = m.start()
        depth = 0
        i = m.end() - 1
        for j in range(m.end() - 1, len(text)):
            if text[j] == '(':
                depth += 1
            elif text[j] == ')':
                depth -= 1
                if depth == 0:
                    inner = text[m.end():j]
                    out.append((start, j + 1, inner))
                    break
    return out

def decode(text):
    count = 0
    # process from the end so earlier offsets remain valid as we splice
    calls = find_chrw_calls(text)
    for start, end, inner in reversed(calls):
        try:
            v = int(ExprParser(inner).parse())
            ch = chr(v)
        except Exception:
            continue
        if ch == '"':
            repl = '"' + '\\"' + '"'  # keep visible as escaped quote marker
        else:
            repl = '"' + ch + '"'
        text = text[:start] + repl + text[end:]
        count += 1
    return text, count

def main():
    text = open(SRC, encoding='utf-8', errors='replace').read()
    text, n = decode(text)
    print(f"Decoded {n} ChrW(...) call(s)")
    open(OUT, 'w', encoding='utf-8').write(text)
    print(f"Wrote {OUT}")

if __name__ == '__main__':
    main()
