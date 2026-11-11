#!/usr/bin/env python3
"""T-ENG-6: enforce the LOC caps of spec Section 3 using tokei.

Counts production code only: blank lines and comments are excluded by tokei
(tokei 15 also excludes `///` and `//!` doc comments, which it classifies as
embedded Markdown), and every `#[cfg(test)]` item (typically `mod tests { ... }`) is removed
before counting. Exits 1 if any hard cap is exceeded; prints a table either way.

Usage: python3 -I scripts/loc_budget.py [path/to/src]
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

# (group name, files, target, hard cap). lib.rs is crate glue and is charged
# to the cli + main group, the conservative choice (DESIGN_NOTES.md).
GROUPS = [
    ("sys + secmem + alloc", ["sys.rs", "secmem.rs", "alloc.rs"], 400, 800),
    ("crypto + format", ["crypto.rs", "format.rs"], 450, 750),
    ("store", ["store.rs"], 250, 450),
    ("vault", ["vault.rs"], 250, 500),
    ("gen", ["gen.rs"], 150, 200),
    ("term + clip", ["term.rs", "clip.rs"], 300, 350),
    ("cli + main", ["cli.rs", "main.rs", "lib.rs"], 400, 500),
]
TOTAL_TARGET, TOTAL_CAP = 2200, 3200


def strip_cfg_test(text: str) -> str:
    """Remove each `#[cfg(test)]` attribute and the item it annotates.

    The item ends at the first `;` at brace depth 0 or at the `}` closing the
    first top-level brace. Braces inside string/char literals and comments
    are skipped.
    """
    out = []
    i, n = 0, len(text)
    marker = "#[cfg(test)]"
    while i < n:
        j = text.find(marker, i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = j + len(marker)
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
                    k += 1
                    break
            elif c == ";" and depth == 0:
                k += 1
                break
            k += 1
        # Keep line structure stable (not required, but eases debugging).
        out.append("\n" * text[j:k].count("\n"))
        i = k
    return "".join(out)


def tokei_code_lines(directory: str) -> dict:
    res = subprocess.run(
        ["tokei", "--output", "json", "--types", "Rust", directory],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(res.stdout)
    counts = {}
    for report in data.get("Rust", {}).get("reports", []):
        counts[os.path.basename(report["name"])] = report["stats"]["code"]
    return counts


def self_test() -> None:
    src = 'fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() { let _ = "}"; }\n}\nfn c() {}\n'
    stripped = strip_cfg_test(src)
    assert "fn a()" in stripped and "fn c()" in stripped, stripped
    assert "mod tests" not in stripped and "fn b()" not in stripped, stripped
    one = strip_cfg_test("#[cfg(test)]\nuse x::y;\nfn d() {}\n")
    assert "use x::y" not in one and "fn d()" in one, one


def main() -> int:
    self_test()
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "src"
    )
    src = os.path.abspath(src)
    files = sorted(f for f in os.listdir(src) if f.endswith(".rs"))
    known = {f for _, fs, _, _ in GROUPS for f in fs}
    unknown = [f for f in files if f not in known]
    if unknown:
        print(f"FAIL: source files not assigned to a LOC group: {unknown}")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        for f in files:
            with open(os.path.join(src, f), encoding="utf-8") as fh:
                text = fh.read()
            with open(os.path.join(tmp, f), "w", encoding="utf-8") as fh:
                fh.write(strip_cfg_test(text))
        if shutil.which("tokei") is None:
            print("FAIL: tokei not found on PATH (cargo install --locked tokei)")
            return 1
        counts = tokei_code_lines(tmp)

    ok = True
    total = 0
    print(f"{'group':<24}{'LOC':>6}{'target':>8}{'cap':>6}  status")
    for name, fs, target, cap in GROUPS:
        loc = sum(counts.get(f, 0) for f in fs)
        total += loc
        status = "ok" if loc <= cap else "OVER CAP"
        ok &= loc <= cap
        print(f"{name:<24}{loc:>6}{target:>8}{cap:>6}  {status}")
    status = "ok" if total <= TOTAL_CAP else "OVER CAP"
    ok &= total <= TOTAL_CAP
    print(f"{'total':<24}{total:>6}{TOTAL_TARGET:>8}{TOTAL_CAP:>6}  {status}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
