#!/usr/bin/env python3
"""T-COV-6 (spec 14.13; M9): fuzz corpus coverage, report-only.

Reads `llvm-cov export -format=text` JSON of one fuzz target replaying its
corpus (`cargo fuzz coverage`), and reports region coverage of `format.rs`
and `vault.rs` (production regions, as in coverage_report.py). Compares with
the previous night's figures (if given) and flags a drop of more than 2
percentage points, which suggests a lost corpus. Always exits 0 unless the
input is unreadable: the spec makes T-COV-6 report-only.

Usage: fuzz_cov.py TARGET EXPORT.json OUT.json [PREVIOUS.json] >> summary.md
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # `python3 -I` does not add it
import prodcode  # noqa: E402
from coverage_report import parse_json  # noqa: E402

FILES = ["format.rs", "vault.rs"]
DROP_PP = 2.0


def figures(export):
    regions, _, _ = parse_json(export)
    out = {}
    for f in FILES:
        with open(os.path.join(os.path.dirname(HERE), "src", f), encoding="utf-8") as fh:
            prod = prodcode.production_lines(fh.read())
        rs = [c for k, c in regions.items() if k[0] == f and k[1] in prod]
        cov = sum(1 for c in rs if c > 0)
        out[f] = {"covered": cov, "total": len(rs),
                  "percent": round(100.0 * cov / len(rs), 2) if rs else None}
    return out


def main(argv):
    target, export_path, out_path = argv[:3]
    prev_path = argv[3] if len(argv) > 3 else None
    with open(export_path, encoding="utf-8") as f:
        now = figures(json.load(f))
    prev = {}
    if prev_path and os.path.isfile(prev_path):
        with open(prev_path, encoding="utf-8") as f:
            prev = json.load(f).get("files", {})
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"target": target, "files": now}, f, indent=2, sort_keys=True)
    print(f"### T-COV-6: corpus coverage of `{target}` (report-only)\n")
    print("| File | Regions | Previous night | Change |")
    print("| --- | --- | --- | --- |")
    for name, fig in now.items():
        p = prev.get(name, {}).get("percent")
        cur = fig["percent"]
        change, flag = "-", ""
        if p is not None and cur is not None:
            d = cur - p
            change = f"{d:+.2f} pp"
            if d < -DROP_PP:
                flag = " **dropped more than 2 pp: corpus lost?**"
                print(f"::warning::T-COV-6 {target} {name}: {d:+.2f} pp", file=sys.stderr)
        shown = "n/a" if cur is None else f"{cur:.2f} % ({fig['covered']}/{fig['total']})"
        print(f"| {name} | {shown} | {'-' if p is None else f'{p:.2f} %'} | {change}{flag} |")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
