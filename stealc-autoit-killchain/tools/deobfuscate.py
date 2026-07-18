#!/usr/bin/env python3
"""Deobfuscator for the StealC/AutoIt loader crypter (Quotes.a3x -> script.au3).

Two passes:
1. Decrypt every BATHROOMREWARDLIVED("0xHEX","key") call inline (repeating-key XOR).
2. Resolve flattened Switch blocks: reinterpret near-2^32 / near-2^64 literals as
   signed integers, evaluate each Case constant, keep only the live branch.
"""
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "script.au3"
OUT = sys.argv[2] if len(sys.argv) > 2 else "deobfuscated.au3"

# ---------- Pass 1: string decryption ----------

def xor_decrypt(hexstr: str, key: str) -> str:
    data = bytes.fromhex(hexstr)
    klen = len(key)
    return "".join(chr(b ^ ord(key[i % klen])) for i, b in enumerate(data))

def au3_quote(s: str) -> str:
    return '"' + s.replace('"', '""') + '"'

CALL_RE = re.compile(r'BATHROOMREWARDLIVED\s*\(\s*"0x([0-9A-Fa-f]+)"\s*,\s*"([^"]*)"\s*\)')

def decrypt_pass(text: str) -> tuple[str, int]:
    count = 0
    def repl(m):
        nonlocal count
        hexstr, key = m.group(1), m.group(2)
        try:
            plain = xor_decrypt(hexstr, key)
        except Exception:
            return m.group(0)
        count += 1
        return au3_quote(plain)
    new_text = CALL_RE.sub(repl, text)
    return new_text, count

# ---------- Pass 2: flattened Switch resolution ----------

TWO_31 = 2**31
TWO_32 = 2**32
TWO_63 = 2**63
TWO_64 = 2**64

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
    """Tiny recursive-descent parser for integer-literal-only arithmetic,
    with fix_int() applied to every literal (AutoIt obfuscator constants)."""

    def __init__(self, text):
        self.tokens = [ (m.lastgroup, m.group()) for m in TOKEN_RE.finditer(text) ]
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def next(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self):
        v = self.expr()
        return v

    def expr(self):  # + -
        v = self.term()
        while self.peek()[0] == 'op' and self.peek()[1] in '+-':
            op = self.next()[1]
            rhs = self.term()
            v = v + rhs if op == '+' else v - rhs
        return v

    def term(self):  # * /
        v = self.factor()
        while self.peek()[0] == 'op' and self.peek()[1] in '*/':
            op = self.next()[1]
            rhs = self.factor()
            v = v * rhs if op == '*' else v / rhs
        return v

    def factor(self):
        kind, val = self.peek()
        if kind == 'op' and val in '+-':
            self.next()
            f = self.factor()
            return f if val == '+' else -f
        if kind == 'num':
            self.next()
            return fix_int(int(val))
        if kind == 'lparen':
            self.next()
            v = self.expr()
            assert self.next()[0] == 'rparen'
            return v
        if kind == 'bitxor':
            self.next()
            assert self.next()[0] == 'lparen'
            a = self.expr()
            assert self.next()[0] == 'comma'
            b = self.expr()
            assert self.next()[0] == 'rparen'
            return float(int(a) ^ int(b))
        if kind == 'bitshift':
            self.next()
            assert self.next()[0] == 'lparen'
            a = self.expr()
            assert self.next()[0] == 'comma'
            b = self.expr()
            assert self.next()[0] == 'rparen'
            return float(int(a) >> int(b))
        raise ParseError(f"unexpected token {kind!r} {val!r}")


def safe_eval(expr_text: str):
    p = ExprParser(expr_text)
    v = p.parse()
    return v


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip('\t'))


def resolve_switches(lines: list[str]) -> tuple[list[str], int, int]:
    out = []
    i = 0
    resolved = 0
    ambiguous = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        m = re.match(r'Switch \$(\w+)$', stripped)
        if not m:
            out.append(line)
            i += 1
            continue

        switch_indent = indent_of(line)
        var = m.group(1)

        # find init expr: nearest preceding "$VAR = <expr>" among already-emitted lines.
        # An earlier version only checked out[-1] (the single immediately preceding
        # line) and missed assignments sitting a few lines further back (e.g. across
        # an If/Else branch), producing false "unresolved" blocks.
        init_val = None
        for prev_raw in reversed(out[-60:]):
            prev = prev_raw.strip()
            pm = re.match(rf'\${re.escape(var)} = (.+)$', prev)
            if pm:
                try:
                    init_val = safe_eval(pm.group(1))
                except Exception:
                    init_val = None
                break

        # collect Case blocks until EndSwitch at same indent
        j = i + 1
        cases = []  # (case_expr_text, body_lines)
        cur_expr = None
        cur_body = []
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
                cur_expr = cm.group(1)
                cur_body = []
            else:
                cur_body.append(l2)
            j += 1
        else:
            # no EndSwitch found - bail, emit unchanged
            out.append(line)
            i += 1
            continue

        endswitch_idx = j

        live_body = None
        if init_val is not None:
            matches = []
            for expr_text, body in cases:
                try:
                    cv = safe_eval(expr_text)
                except Exception:
                    continue
                if cv == init_val:
                    matches.append(body)
            if len(matches) == 1:
                live_body = matches[0]
                resolved += 1
            elif len(matches) > 1:
                ambiguous += 1

        if live_body is None:
            # fallback heuristic: case containing ExitLoop/Return
            candidates = [b for _, b in cases if any('ExitLoop' in bl or 'Return' in bl for bl in b)]
            if len(candidates) == 1:
                live_body = candidates[0]
                resolved += 1
            else:
                ambiguous += 1

        if live_body is not None:
            out.append(f"{'	'*switch_indent}' -- resolved Switch (var {var}) --")
            # strip trailing dead state-mutation lines like "$VAR = $VAR + (...)"
            for bl in live_body:
                bls = bl.strip()
                if re.match(rf'\${re.escape(var)} = \${re.escape(var)}', bls):
                    continue
                out.append(bl)
        else:
            out.append(line)
            for l2 in lines[i+1:endswitch_idx+1]:
                out.append(l2)

        i = endswitch_idx + 1
    return out, resolved, ambiguous


def main():
    text = open(SRC, encoding='utf-8', errors='replace').read()
    text, n_strings = decrypt_pass(text)
    print(f"[pass1] decrypted {n_strings} BATHROOMREWARDLIVED string(s)")

    lines = text.split('\n')
    new_lines, resolved, ambiguous = resolve_switches(lines)
    print(f"[pass2] resolved {resolved} Switch block(s), {ambiguous} ambiguous/unresolved")

    open(OUT, 'w', encoding='utf-8').write('\n'.join(new_lines))
    print(f"Wrote {OUT} ({len(new_lines)} lines, was {len(lines)})")

if __name__ == '__main__':
    main()
