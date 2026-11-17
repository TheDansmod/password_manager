"""What counts as production code (shared by loc_budget.py and coverage).

Spec Section 14.13: coverage's denominator is "the same lines T-ENG-6
counts: every src/*.rs file, minus #[cfg(test)] items, comments, and blank
lines", plus code compiled only under cfg(miri) excluded, and "the report
script uses the same stripping logic as scripts/loc_budget.py, so the two
definitions cannot drift apart". Both scripts therefore import the item
stripping from here (M9; moved unchanged out of loc_budget.py).

Standard library only. Scripts run with `python3 -I`, which (3.11+) does not
put the script's directory on sys.path, so importers add it explicitly.
"""

TEST_MARKER = "#[cfg(test)]"
MIRI_MARKER = "#[cfg(miri)]"


def _item_end(text: str, k: int) -> int:
    """Index just past the item that starts at `k` (after an attribute).

    The item ends at the first `;` at brace depth 0 or at the `}` closing the
    first top-level brace. Braces inside string/char literals and comments
    are skipped.
    """
    n = len(text)
    depth = 0
    seen_brace = False
    while k < n:
        c = text[k]
        if text.startswith("//", k):
            k = text.find("\n", k)
            k = n if k < 0 else k
            continue
        if text.startswith("/*", k):
            e = text.find("*/", k + 2)
            k = n if e < 0 else e + 2
            continue
        if c == '"':
            k += 1
            while k < n and text[k] != '"':
                k += 2 if text[k] == "\\" else 1
            k += 1
            continue
        if c == "'" and k + 2 < n and (text[k + 2] == "'" or text[k + 1] == "\\"):
            e = text.find("'", k + 2)
            k = n if e < 0 else e + 1
            continue
        if c == "{":
            depth += 1
            seen_brace = True
        elif c == "}":
            depth -= 1
            if seen_brace and depth == 0:
                return k + 1
        elif c == ";" and depth == 0:
            return k + 1
        k += 1
    return k


def item_spans(text: str, marker: str) -> list:
    """(start, end) character spans of each `marker` attribute and its item."""
    spans = []
    i = 0
    while True:
        j = text.find(marker, i)
        if j < 0:
            return spans
        k = _item_end(text, j + len(marker))
        spans.append((j, k))
        i = k


def strip_cfg(text: str, marker: str) -> str:
    """Remove each `marker` attribute and the item it annotates, keeping the
    line structure (each removed item becomes as many newlines)."""
    out = []
    i = 0
    for j, k in item_spans(text, marker):
        out.append(text[i:j])
        out.append("\n" * text[j:k].count("\n"))
        i = k
    out.append(text[i:])
    return "".join(out)


def strip_cfg_test(text: str) -> str:
    """Remove each `#[cfg(test)]` attribute and the item it annotates."""
    return strip_cfg(text, TEST_MARKER)


def item_lines(text: str, marker: str) -> set:
    """1-based line numbers covered by `marker` items (attribute included)."""
    lines = set()
    for j, k in item_spans(text, marker):
        first = text.count("\n", 0, j) + 1
        last = text.count("\n", 0, max(j, k - 1)) + 1
        lines.update(range(first, last + 1))
    return lines


def code_lines(text: str) -> set:
    """1-based line numbers holding code once comments are removed.

    Removes `//` comments (doc comments included) and nested `/* */`
    comments; string, raw string and char literals count as code.
    """
    lines = set()
    n = len(text)
    i, line, depth = 0, 1, 0
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if depth:
            if text.startswith("*/", i):
                depth -= 1
                i += 2
            elif text.startswith("/*", i):
                depth += 1
                i += 2
            else:
                i += 1
            continue
        if text.startswith("//", i):
            e = text.find("\n", i)
            i = n if e < 0 else e
            continue
        if text.startswith("/*", i):
            depth = 1
            i += 2
            continue
        if c.isspace():
            i += 1
            continue
        lines.add(line)
        if c == "r" and (text.startswith('r"', i) or text.startswith('r#', i)):
            h = 0
            while i + 1 + h < n and text[i + 1 + h] == "#":
                h += 1
            if i + 1 + h < n and text[i + 1 + h] == '"':
                close = '"' + "#" * h
                e = text.find(close, i + 2 + h)
                e = n if e < 0 else e + len(close)
                for _ in range(text.count("\n", i, e)):
                    line += 1
                    lines.add(line)
                i = e
                continue
        if c == '"':
            k = i + 1
            while k < n and text[k] != '"':
                if text[k] == "\n":
                    line += 1
                    lines.add(line)
                k += 2 if text[k] == "\\" else 1
            i = k + 1
            continue
        if c == "'" and i + 2 < n and (text[i + 2] == "'" or text[i + 1] == "\\"):
            e = text.find("'", i + 2)
            i = n if e < 0 else e + 1
            continue
        i += 1
    return lines


def production_lines(text: str) -> set:
    """Code lines outside `#[cfg(test)]` and `#[cfg(miri)]` items."""
    excluded = item_lines(text, TEST_MARKER) | item_lines(text, MIRI_MARKER)
    return code_lines(text) - excluded


def self_test() -> None:
    src = 'fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() { let _ = "}"; }\n}\nfn c() {}\n'
    stripped = strip_cfg_test(src)
    assert "fn a()" in stripped and "fn c()" in stripped, stripped
    assert "mod tests" not in stripped and "fn b()" not in stripped, stripped
    assert stripped.count("\n") == src.count("\n")
    one = strip_cfg_test("#[cfg(test)]\nuse x::y;\nfn d() {}\n")
    assert "use x::y" not in one and "fn d()" in one, one
    assert item_lines(src, TEST_MARKER) == {2, 3, 4, 5}, item_lines(src, TEST_MARKER)
    m = "fn a() {}\n#[cfg(miri)]\nfn m() {\n    x();\n}\nfn z() {}\n"
    assert production_lines(m) == {1, 6}, production_lines(m)
    c = ('// c\nfn f() { /* a\n b */ g(); }\n/// doc\n\n/* x /* y */ z\n*/ h();\n'
         'let s = "a // b\nc";\nlet r = r#"q\n"#;\nlet q = \'"\';\n')
    got = code_lines(c)
    assert got == {2, 3, 7, 8, 9, 10, 11, 12}, sorted(got)
