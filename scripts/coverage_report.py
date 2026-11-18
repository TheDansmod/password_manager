#!/usr/bin/env python3
"""Coverage report and gates T-COV-1 .. T-COV-5 (spec Section 14.13; M9).

Input: one directory per coverage run (a CI job of the `coverage` or
`coverage-branch` matrix), each holding what scripts/coverage_run.sh wrote:
  lcov.info          `cargo llvm-cov report --lcov` (line counts)
  cov.json           `cargo llvm-cov report --json` (functions, regions,
                     branches, with their source spans)
  meta.json          run name, features, toolchain and tool versions, seeds
  unsafe_blocks.tsv  T-COV-3: the `unsafe` blocks T-ENG-2's scanner finds
                     (tests/eng.rs, t_cov_3_unsafe_blocks_listed)
  test.log           the run's test output (`test ... ok` lines only matter)

The runs are separate jobs, so they are merged here (spec: "the reporting
job merges them by line"): a line is covered if any run executed it. Regions,
functions and branches are merged the same way, keyed by their exact source
span: the source is identical in every run, and a span that exists only in
some configurations (cfg(feature)) is counted once.

Denominator: production lines only (scripts/prodcode.py, shared with
T-ENG-6): code lines of src/*.rs outside #[cfg(test)] and #[cfg(miri)]
items, intersected with the lines LLVM instruments. Regions, functions and
branches count if they start on a production line.

Exit 1 if any gate fails. Never prints program output: inputs are counts,
spans, and test names.

Usage:
  coverage_report.py --runs DIR [--branch-runs DIR] [--baseline FILE]
      [--notes docs/DESIGN_NOTES.md] [--logs FILE...] [--jobs needs.json]
      [--summary OUT.md] [--merged-lcov OUT] [--new-baseline OUT.json]
      [--badges DIR] [--mutants FILE]
  coverage_report.py --self-test

--mutants FILE: the latest completed run of the weekly workflow mutants.yml
on `main` (a JSON object with `conclusion`, `head_sha`, `updated_at`,
`html_url`, as the GitHub API returns it; `{}` if there is none). T-MUT-1
lives in that workflow, so this is how the report learns its result.
"""

import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)  # `python3 -I` does not add it
import prodcode  # noqa: E402
import test_ids  # noqa: E402
from loc_budget import GROUPS  # noqa: E402  (Section 3 groups, one source)

GATED = ["format.rs", "crypto.rs", "gen.rs", "store.rs", "vault.rs"]
LINE_MIN_GATED = 95.0
LINE_MIN_OVERALL = 85.0
TOLERANCE_PP = 0.5  # T-COV-4
CODE_REGION = 0  # LLVM region kind: CodeRegion
MUTANTS_MAX_AGE_DAYS = 8  # T-MUT-1 is weekly; an older run counts as not run


# ----------------------------------------------------------------- inputs

def src_name(path):
    """`x.rs` if `path` is <repo>/src/x.rs, else None."""
    parent, name = os.path.split(path)
    if os.path.basename(parent) != "src" or not name.endswith(".rs"):
        return None
    if os.path.basename(os.path.dirname(parent)) == "fuzz":
        return None
    return name


def parse_lcov(text):
    """{file: {line: count}} for src files."""
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("SF:"):
            cur = src_name(line[3:].strip())
        elif line.startswith("DA:") and cur:
            n, c = line[3:].split(",")[:2]
            d = out.setdefault(cur, {})
            d[int(n)] = max(d.get(int(n), 0), int(c))
        elif line == "end_of_record":
            cur = None
    return out


def parse_json(data):
    """(regions, functions, branches) for src files, each a dict keyed by
    (file, line_start, col_start, line_end, col_end):
    regions -> count, functions -> count, branches -> (true, false)."""
    regions, functions, branches = {}, {}, {}
    for d in data.get("data", []):
        for fn in d.get("functions", []):
            names = fn.get("filenames", [])
            first = None
            for r in fn.get("regions", []):
                ls, cs, le, ce, count, fid = r[0], r[1], r[2], r[3], r[4], r[5]
                kind = r[7] if len(r) > 7 else CODE_REGION
                f = src_name(names[fid]) if fid < len(names) else None
                if f is None or kind != CODE_REGION:
                    continue
                k = (f, ls, cs, le, ce)
                regions[k] = max(regions.get(k, 0), count)
                if first is None and fid == 0:
                    first = k
            if first is not None:
                functions[first] = max(functions.get(first, 0), fn.get("count", 0))
            for b in fn.get("branches", []):
                ls, cs, le, ce, t, fa, fid = b[0], b[1], b[2], b[3], b[4], b[5], b[6]
                f = src_name(names[fid]) if fid < len(names) else None
                if f is None:
                    continue
                k = (f, ls, cs, le, ce)
                ot, of = branches.get(k, (0, 0))
                branches[k] = (max(ot, t), max(of, fa))
    return regions, functions, branches


class Runs:
    """Merged data of a set of run directories."""

    def __init__(self, root):
        self.names, self.meta, self.logs, self.per_run = [], [], [], {}
        self.lines, self.regions, self.functions, self.branches = {}, {}, {}, {}
        self.unsafe = set()
        if not root or not os.path.isdir(root):
            return
        for name in sorted(os.listdir(root)):
            d = os.path.join(root, name)
            if not os.path.isfile(os.path.join(d, "cov.json")):
                continue
            self.names.append(name)
            meta_path = os.path.join(d, "meta.json")
            if os.path.isfile(meta_path):
                with open(meta_path, encoding="utf-8") as f:
                    self.meta.append(json.load(f))
            with open(os.path.join(d, "lcov.info"), encoding="utf-8") as f:
                lines = parse_lcov(f.read())
            with open(os.path.join(d, "cov.json"), encoding="utf-8") as f:
                regions, functions, branches = parse_json(json.load(f))
            self.per_run[name] = (lines, regions)
            for file, ls in lines.items():
                m = self.lines.setdefault(file, {})
                for n, c in ls.items():
                    m[n] = max(m.get(n, 0), c)
            for k, c in regions.items():
                self.regions[k] = max(self.regions.get(k, 0), c)
            for k, c in functions.items():
                self.functions[k] = max(self.functions.get(k, 0), c)
            for k, (t, fa) in branches.items():
                ot, of = self.branches.get(k, (0, 0))
                self.branches[k] = (max(ot, t), max(of, fa))
            tsv = os.path.join(d, "unsafe_blocks.tsv")
            if os.path.isfile(tsv):
                with open(tsv, encoding="utf-8") as f:
                    for row in f:
                        if row.strip():
                            fl, a, b = row.split("\t")
                            self.unsafe.add((fl, int(a), int(b)))
            log = os.path.join(d, "test.log")
            if os.path.isfile(log):
                self.logs.append(log)


# ---------------------------------------------------------------- figures

class Source:
    """Production-line sets of src/*.rs (prodcode.py)."""

    def __init__(self, src_dir):
        self.files, self.prod, self.miri, self.test, self.text = [], {}, {}, {}, {}
        for f in sorted(os.listdir(src_dir)):
            if not f.endswith(".rs"):
                continue
            with open(os.path.join(src_dir, f), encoding="utf-8") as fh:
                t = fh.read()
            self.files.append(f)
            self.text[f] = t.split("\n")
            self.prod[f] = prodcode.production_lines(t)
            self.miri[f] = prodcode.item_lines(t, prodcode.MIRI_MARKER)
            self.test[f] = prodcode.item_lines(t, prodcode.TEST_MARKER)

    def line_text(self, f, n):
        lines = self.text.get(f, [])
        return lines[n - 1].strip() if 0 < n <= len(lines) else ""


def ratio(cov, tot):
    return 100.0 * cov / tot if tot else 100.0


def file_figures(src, runs, f):
    """{metric: (covered, total)} for one file, plus its uncovered lines."""
    prod = src.prod[f]
    da = {n: c for n, c in runs.lines.get(f, {}).items() if n in prod}
    regs = {k: c for k, c in runs.regions.items() if k[0] == f and k[1] in prod}
    fns = {k: c for k, c in runs.functions.items() if k[0] == f and k[1] in prod}
    brs = {k: v for k, v in runs.branches.items() if k[0] == f and k[1] in prod}
    fig = {
        "lines": (sum(1 for c in da.values() if c > 0), len(da)),
        "regions": (sum(1 for c in regs.values() if c > 0), len(regs)),
        "functions": (sum(1 for c in fns.values() if c > 0), len(fns)),
        "branches": (sum((t > 0) + (fa > 0) for t, fa in brs.values()), 2 * len(brs)),
    }
    uncovered = sorted(n for n, c in da.items() if c == 0)
    missed_fns = sorted(k[1] for k, c in fns.items() if c == 0)
    return fig, uncovered, missed_fns


def add(a, b):
    return {k: (a[k][0] + b[k][0], a[k][1] + b[k][1]) for k in a}


def pct(fig):
    c, t = fig
    return "n/a" if not t else f"{ratio(c, t):.2f} % ({c}/{t})"


# ------------------------------------------------------------- exceptions

EXC_ROW = re.compile(r"^\|\s*`?src/(\w+\.rs):(\d+)(?:-(\d+))?`?\s*\|\s*(line|function)\s*\|")


def exceptions(notes_path):
    """{(file, kind): set(lines)} from DESIGN_NOTES' "Coverage exceptions"
    tables: rows `| src/x.rs:N[-M] | line|function | date | reason |`."""
    out = {}
    if not notes_path:
        return out
    if not os.path.isfile(notes_path):
        # A cited document that is missing is an error, not "no exceptions"
        # (review finding R-01).
        sys.exit(f"--notes {notes_path}: no such file")
    with open(notes_path, encoding="utf-8") as f:
        text = f.read()
    for m in re.finditer(r"^#+ .*Coverage exceptions.*$", text, re.M):
        for row in text[m.end():].split("\n"):
            row = row.strip()
            if row and not row.startswith("|"):
                if row.startswith("#"):
                    break
                continue
            em = EXC_ROW.match(row)
            if em:
                a = int(em.group(2))
                b = int(em.group(3) or a)
                out.setdefault((em.group(1), em.group(4)), set()).update(range(a, b + 1))
    return out


# ---------------------------------------------------------------- report

def block_span(lines, a, b):
    """((a, first col), (b, col after the closing brace)) of the
    `unsafe { .. }` block starting on line `a` and ending on line `b`
    (1-based lines, 1-based byte columns as in llvm-cov), or None if it
    cannot be placed. String and char literals and `//` comments are
    skipped while matching braces; the T-ENG-2 scanner found the block."""
    if not (0 < a <= b <= len(lines)):
        return None
    first = lines[a - 1].encode()
    m = re.search(rb"\bunsafe\s*\{", first)
    if not m:
        return None
    depth, start = 0, None
    for n in range(a, b + 1):
        s = lines[n - 1].encode()
        i = m.end() - 1 if n == a else 0
        in_str = False
        while i < len(s):
            c = s[i:i + 1]
            if in_str:
                if c == b"\\":
                    i += 1
                elif c == b'"':
                    in_str = False
            elif c == b'"':
                in_str = True
            elif s[i:i + 2] == b"//":
                break
            elif c == b"'" and s[i + 2:i + 3] == b"'":
                i += 2  # a char literal such as '{'
            elif c == b"{":
                depth += 1
                start = start or (a, m.start() + 1)
            elif c == b"}":
                depth -= 1
                if depth == 0:
                    return (start, (n, i + 2)) if n == b else None
            i += 1
    return None


def unsafe_status(src, runs, block):
    """T-COV-3 status of one block: 'covered', 'miri-only', or a failure.
    Counted: the block's lines and every region overlapping the block's own
    column span, so code after the closing brace on the same line (such as
    `.map_err(..)?` of the call's error path) is judged by T-COV-1, not here."""
    f, a, b = block
    span = set(range(a, b + 1))
    if span & src.miri.get(f, set()):
        return "miri-only (excluded; T-SAN-2)"
    cols = block_span(src.text.get(f, []), a, b)
    if cols is None:
        regs = [c for k, c in runs.regions.items() if k[0] == f and a <= k[1] <= b]
    else:
        lo, hi = cols
        regs = [c for k, c in runs.regions.items()
                if k[0] == f and (k[1], k[2]) < hi and (k[3], k[4]) > lo]
    lines = [c for n, c in runs.lines.get(f, {}).items() if a <= n <= b]
    if not regs and not lines:
        return "FAIL: no coverage data"
    if any(c == 0 for c in regs) or any(c == 0 for c in lines):
        return "FAIL: not fully covered"
    return "covered"


def own_cov_verdict(tid, verdict, fails, branches_measured):
    """Verdict of T-COV-1 .. T-COV-5 from this report's gate failures (each
    failure text names the IDs it fails); other IDs keep `verdict`. A passing
    gate keeps `verdict`, so other evidence (T-COV-3's tests, the
    `coverage-branch` job) still counts. T-COV-5 is "not run" without
    branch data (push runs)."""
    m = re.fullmatch(r"T-COV-([1-5])", tid)
    if not m:
        return verdict
    if tid == "T-COV-5" and not branches_measured:
        return "not run"
    named = {n for x in fails for n in re.findall(r"T-COV-([1-5])", x)}
    return "fail" if m.group(1) in named else verdict


def mutants_result(path, now):
    """(job result for `mutants`, note) from the latest completed mutants.yml
    run (see --mutants). "success"/"failure" from a run that finished at
    most MUTANTS_MAX_AGE_DAYS before `now`; "skipped" (T-MUT-1: not run) if
    there is no such run, it was cancelled, or it is older."""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return "skipped", "T-MUT-1: the latest mutants.yml run could not be read"
    concl = d.get("conclusion") if isinstance(d, dict) else None
    if not concl:
        return "skipped", "T-MUT-1: no completed mutants.yml run on `main`"
    when = d.get("updated_at") or d.get("created_at") or ""
    sha = (d.get("head_sha") or "")[:12]
    about = f"mutants.yml run {d.get('html_url', '?')} (commit `{sha}`, finished {when}): {concl}"
    try:
        done = datetime.datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        return "skipped", f"T-MUT-1: not counted, no finishing time; {about}"
    if (now - done).total_seconds() > MUTANTS_MAX_AGE_DAYS * 86400:
        return "skipped", (f"T-MUT-1: not counted, older than {MUTANTS_MAX_AGE_DAYS} days; "
                           f"{about}")
    result = {"success": "success", "failure": "failure"}.get(concl, "skipped")
    return result, f"T-MUT-1 from {about}"


def badge(label, value, color):
    """A flat SVG badge (no third-party service; spec 14.13)."""
    def width(s):
        return 10 + int(6.5 * len(s))
    lw, vw = width(label), width(value)
    w = lw + vw
    esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")  # noqa: E731
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" '
        f'aria-label="{esc(label)}: {esc(value)}"><title>{esc(label)}: {esc(value)}</title>'
        f'<rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        '<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" '
        'font-size="11">'
        f'<text x="{lw / 2:.1f}" y="14">{esc(label)}</text>'
        f'<text x="{lw + vw / 2:.1f}" y="14">{esc(value)}</text></g></svg>\n'
    )


def report(args):
    src = Source(os.path.join(ROOT, "src"))
    runs = Runs(args["runs"])
    branch_runs = Runs(args.get("branch_runs"))
    out = []
    fails = []
    if not runs.names:
        print("no coverage runs found")
        return 1
    notes = exceptions(args.get("notes"))
    baseline = None
    if args.get("baseline") and os.path.isfile(args["baseline"]):
        with open(args["baseline"], encoding="utf-8") as f:
            baseline = json.load(f)

    per_file, uncovered, missed = {}, {}, {}
    for f in src.files:
        per_file[f], uncovered[f], missed[f] = file_figures(src, runs, f)
        if branch_runs.names:
            per_file[f]["branches"] = file_figures(src, branch_runs, f)[0]["branches"]
    zero = {k: (0, 0) for k in ("lines", "regions", "functions", "branches")}
    total = zero
    for f in src.files:
        total = add(total, per_file[f])

    # 1. Tables per Section 3 group, then per file.
    out.append("## Coverage (spec 14.13)\n")
    out.append(f"Runs merged: {', '.join(runs.names)}.")
    out.append("Branches: " + (", ".join(branch_runs.names) if branch_runs.names
                              else "not measured in this run (nightly `coverage-branch`)") + ".\n")
    out.append("| Group / file | Lines | Regions | Functions | Branches | Threshold | "
               "vs baseline (lines / regions / branches) | Result |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    new_base = {"modules": {}}
    for gname, gfiles, _, _ in GROUPS:
        g = zero
        for f in gfiles:
            g = add(g, per_file[f])
        out.append(f"| **{gname}** | {pct(g['lines'])} | {pct(g['regions'])} | "
                   f"{pct(g['functions'])} | {pct(g['branches'])} | | | |")
        for f in gfiles:
            fig = per_file[f]
            lp, rp = ratio(*fig["lines"]), ratio(*fig["regions"])
            bp = ratio(*fig["branches"]) if fig["branches"][1] else None
            new_base["modules"][f] = {"lines": round(lp, 2), "regions": round(rp, 2)}
            if bp is not None:
                new_base["modules"][f]["branches"] = round(bp, 2)
            res, thr = [], ""
            if f in GATED:
                thr = f"lines >= {LINE_MIN_GATED:g} %, functions 100 %"
                if lp < LINE_MIN_GATED:
                    res.append("T-COV-1")
                exc = notes.get((f, "function"), set())
                if any(n not in exc for n in missed[f]):
                    res.append("T-COV-2")
            delta = "no baseline"
            if baseline is not None:
                b = baseline.get("modules", {}).get(f)
                if b is None:
                    delta, _ = "not in baseline", res.append("T-COV-4")
                else:
                    parts = []
                    for metric, cur in (("lines", lp), ("regions", rp), ("branches", bp)):
                        if cur is None or metric not in b:
                            parts.append("-")
                            continue
                        d = cur - b[metric]
                        parts.append(f"{d:+.2f}")
                        if d < -TOLERANCE_PP:
                            res.append("T-COV-4" if metric != "branches" else "T-COV-5")
                    delta = " / ".join(parts)
            verdict = "pass" if not res else "FAIL " + ", ".join(sorted(set(res)))
            if res:
                fails.append(f"{f}: {verdict}")
            out.append(f"| {f} | {pct(fig['lines'])} | {pct(fig['regions'])} | "
                       f"{pct(fig['functions'])} | {pct(fig['branches'])} | {thr} | "
                       f"{delta} | {verdict} |")
    overall = ratio(*total["lines"])
    ok_overall = overall >= LINE_MIN_OVERALL
    out.append(f"| **Total** | {pct(total['lines'])} | {pct(total['regions'])} | "
               f"{pct(total['functions'])} | {pct(total['branches'])} | lines >= "
               f"{LINE_MIN_OVERALL:g} % | | {'pass' if ok_overall else 'FAIL T-COV-1'} |")
    if not ok_overall:
        fails.append(f"overall line coverage {overall:.2f} % < {LINE_MIN_OVERALL:g} %")
    if baseline is None:
        fails.append("T-COV-4: no committed baseline (coverage/baseline.json)")
    out.append("\nExcluded from the denominator: `#[cfg(test)]` items, comments, blank "
               "lines, `tests/`, `fuzz/`, `tools/`, `scripts/`, and these `#[cfg(miri)]`-only "
               "lines (verified by T-SAN-2): " +
               ", ".join(f"`{f}:{min(s)}-{max(s)}`" for f, s in sorted(src.miri.items()) if s)
               + ".\n")

    # 2. T-COV-3.
    out.append("### T-COV-3: `unsafe` blocks (T-ENG-2's scanner)\n")
    if not runs.unsafe:
        fails.append("T-COV-3: no unsafe block list (unsafe_blocks.tsv) in any run")
        out.append("No list of `unsafe` blocks was found.\n")
    else:
        out.append("| Block | Status |")
        out.append("| --- | --- |")
        for blk in sorted(runs.unsafe):
            if blk[1] in src.test.get(blk[0], set()):
                continue  # test code, not production
            st = unsafe_status(src, runs, blk)
            if st.startswith("FAIL"):
                fails.append(f"T-COV-3: {blk[0]}:{blk[1]}-{blk[2]} {st}")
            out.append(f"| `{blk[0]}:{blk[1]}-{blk[2]}` | {st} |")
        out.append("")

    # 3. Uncovered lines and functions in the gated modules.
    out.append("### Uncovered production lines and functions in the gated modules\n")
    out.append("| Location | Kind | Code | Justified (DESIGN_NOTES, Coverage exceptions) |")
    out.append("| --- | --- | --- | --- |")
    unjustified = 0
    for f in GATED:
        for kind, items in (("line", uncovered[f]), ("function", missed[f])):
            exc = notes.get((f, kind), set())
            for n in items:
                ok = n in exc
                unjustified += not ok
                code = src.line_text(f, n).replace("|", "\\|")[:80]
                out.append(f"| `src/{f}:{n}` | {kind} | `{code}` | {'yes' if ok else '**no**'} |")
    if unjustified:
        fails.append(f"T-COV-1/T-COV-2: {unjustified} uncovered lines or functions in the "
                     "gated modules are not justified")
    out.append("")

    # 4. Toolchains and seeds.
    out.append("### Toolchains and seeds\n")
    for m in runs.meta + branch_runs.meta:
        out.append("- " + "; ".join(f"{k}: `{v}`" for k, v in sorted(m.items())))
    out.append("")

    # 5. Section 14 test IDs.
    jobs = {}
    if args.get("jobs") and os.path.isfile(args["jobs"]):
        with open(args["jobs"], encoding="utf-8") as f:
            jobs = {k: v.get("result") for k, v in json.load(f).items()}
    # T-COV-1 .. T-COV-5 come from this report's own gates, one ID at a
    # time: a failure of one gate must not mark the others failed (M9 CI
    # round 3 showed T-COV-5 "fail" on a push, where it is not measured).
    jobs["coverage-report"] = "success"
    mut_note = None
    if args.get("mutants"):
        jobs["mutants"], mut_note = mutants_result(
            args["mutants"], datetime.datetime.now(datetime.timezone.utc))
    rows = [(tid, ms, own_cov_verdict(tid, v, fails, bool(branch_runs.names)))
            for tid, ms, v in test_ids.verdicts(list(args.get("logs", [])) + runs.logs, jobs)]
    passing = sum(1 for r in rows if r[2] == "pass")
    out.append(f"### Section 14 test IDs ({passing} of {len(rows)} passing)\n")
    if mut_note:
        out.append(mut_note + "\n")
    out.append("| ID | Milestone | Status |")
    out.append("| --- | --- | --- |")
    for tid, ms, v in rows:
        out.append(f"| {tid} | {ms} | {v} |")
    out.append("")

    out.insert(0, "# " + ("Coverage gates: FAIL" if fails else "Coverage gates: pass") + "\n")
    if fails:
        out.insert(1, "\n".join(f"- {x}" for x in fails) + "\n")
    text = "\n".join(out) + "\n"
    if args.get("summary"):
        with open(args["summary"], "a", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if args.get("new_baseline"):
        new_base["recorded_from"] = runs.names + branch_runs.names
        with open(args["new_baseline"], "w", encoding="utf-8") as f:
            json.dump(new_base, f, indent=2, sort_keys=True)
            f.write("\n")
    if args.get("merged_lcov"):
        with open(args["merged_lcov"], "w", encoding="utf-8") as f:
            for file in sorted(runs.lines):
                f.write(f"SF:src/{file}\n")
                for n, c in sorted(runs.lines[file].items()):
                    f.write(f"DA:{n},{c}\n")
                f.write("end_of_record\n")
    if args.get("badges"):
        os.makedirs(args["badges"], exist_ok=True)
        color = "#4c1" if overall >= 95 else ("#dfb317" if overall >= LINE_MIN_OVERALL else "#e05d44")
        with open(os.path.join(args["badges"], "coverage.svg"), "w", encoding="utf-8") as f:
            f.write(badge("coverage", f"{overall:.1f}%", color))
        tcol = "#4c1" if passing == len(rows) else "#dfb317"
        with open(os.path.join(args["badges"], "test-ids.svg"), "w", encoding="utf-8") as f:
            f.write(badge("test IDs", f"{passing}/{len(rows)} passing", tcol))
    for x in fails:
        print("FAIL:", x)
    return 1 if fails else 0


# ------------------------------------------------------------- self-test

def self_test():
    prodcode.self_test()
    lc = parse_lcov("SF:/w/pwv/src/a.rs\nDA:1,0\nDA:2,3\nend_of_record\n"
                    "SF:/w/pwv/tests/b.rs\nDA:1,1\nend_of_record\n"
                    "SF:/w/pwv/fuzz/src/c.rs\nDA:1,1\nend_of_record\n")
    assert lc == {"a.rs": {1: 0, 2: 3}}, lc
    data = {"data": [{"functions": [
        {"name": "f", "count": 2, "filenames": ["/w/src/a.rs"],
         "regions": [[1, 1, 3, 2, 2, 0, 0, 0], [2, 5, 2, 9, 0, 0, 0, 0],
                     [2, 1, 2, 3, 0, 0, 0, 2]],
         "branches": [[2, 5, 2, 9, 1, 0, 0, 0, 4]]},
        {"name": "g", "count": 0, "filenames": ["/w/src/a.rs"],
         "regions": [[5, 1, 6, 2, 0, 0, 0, 0]], "branches": []},
        {"name": "f2", "count": 0, "filenames": ["/w/src/a.rs"],
         "regions": [[1, 1, 3, 2, 0, 0, 0, 0], [2, 5, 2, 9, 4, 0, 0, 0]],
         "branches": [[2, 5, 2, 9, 0, 6, 0, 0, 4]]}]}]}
    regions, functions, branches = parse_json(data)
    assert regions == {("a.rs", 1, 1, 3, 2): 2, ("a.rs", 2, 5, 2, 9): 4,
                       ("a.rs", 5, 1, 6, 2): 0}, regions
    assert functions == {("a.rs", 1, 1, 3, 2): 2, ("a.rs", 5, 1, 6, 2): 0}, functions
    assert branches == {("a.rs", 2, 5, 2, 9): (1, 6)}, branches
    notes = ("x\n## Coverage exceptions\n\n| Location | Kind | Date | Reason |\n"
             "| --- | --- | --- | --- |\n| `src/a.rs:7` | line | 2026-11-17 | r |\n"
             "| `src/a.rs:9-11` | function | 2026-11-17 | r |\n\n## Next\n"
             "| `src/a.rs:99` | line | d | not in the section |\n")
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, "n.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(notes)
        e = exceptions(p)
    assert e == {("a.rs", "line"): {7}, ("a.rs", "function"): {9, 10, 11}}, e
    assert badge("coverage", "97.1%", "#4c1").startswith("<svg")
    # T-COV-3 spans (shapes from M9 CI round 2, sys.rs:379 and :423).
    text = ["    fn f() {",
            "            unsafe { m(ptr, len, advice) }.map_err(|_| E::Advise)?;",
            "        unsafe { s(\"}\", '{', x) } // }",
            "        let a = unsafe {",
            "            g({ 1 })",
            "        };"]
    assert block_span(text, 2, 2) == ((2, 13), (2, 43)), block_span(text, 2, 2)
    assert block_span(text, 3, 3) == ((3, 9), (3, 34)), block_span(text, 3, 3)
    assert block_span(text, 4, 6) == ((4, 17), (6, 10)), block_span(text, 4, 6)
    assert block_span(text, 4, 5) is None and block_span(text, 1, 1) is None

    class R:
        pass
    src, runs = R(), R()
    src.miri, src.text = {}, {"a.rs": text}
    runs.lines = {"a.rs": {2: 5, 3: 0}}
    runs.regions = {("a.rs", 2, 13, 2, 43): 5, ("a.rs", 2, 44, 2, 63): 5,
                    ("a.rs", 2, 88, 2, 89): 0, ("a.rs", 1, 12, 7, 6): 5}
    assert unsafe_status(src, runs, ("a.rs", 2, 2)) == "covered"
    runs.regions[("a.rs", 2, 20, 2, 30)] = 0
    assert unsafe_status(src, runs, ("a.rs", 2, 2)).startswith("FAIL")
    assert unsafe_status(src, runs, ("a.rs", 3, 3)) == "FAIL: not fully covered"
    fails = ["format.rs: FAIL T-COV-1, T-COV-2", "T-COV-4: no committed baseline"]
    assert own_cov_verdict("T-COV-1", "pass", fails, False) == "fail"
    assert own_cov_verdict("T-COV-3", "pass", fails, False) == "pass"
    assert own_cov_verdict("T-COV-3", "fail", [], False) == "fail"
    assert own_cov_verdict("T-COV-5", "fail", fails, False) == "not run"
    assert own_cov_verdict("T-COV-5", "pass", [], True) == "pass"
    assert own_cov_verdict("T-COV-5", "pass", ["T-COV-5: x"], True) == "fail"
    assert own_cov_verdict("T-COV-6", "not run", fails, False) == "not run"
    assert own_cov_verdict("T-FMT-1", "pass", fails, False) == "pass"
    # T-MUT-1 from the latest mutants.yml run.
    now = datetime.datetime(2026, 11, 28, 12, tzinfo=datetime.timezone.utc)
    run = {"conclusion": "success", "head_sha": "a" * 40, "html_url": "u",
           "updated_at": "2026-11-21T07:00:00Z"}
    verdict = {r[0]: r[2] for r in test_ids.verdicts([], {})}
    assert verdict["T-MUT-1"] == "job", verdict["T-MUT-1"]
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, "m.json")
        for d, want in [(run, "success"), (dict(run, conclusion="failure"), "failure"),
                        (dict(run, conclusion="cancelled"), "skipped"),
                        (dict(run, updated_at="2026-11-19T07:00:00Z"), "skipped"),
                        ({}, "skipped")]:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(d, f)
            got, _ = mutants_result(p, now)
            assert got == want, (d, got)
            verdict = {r[0]: r[2] for r in test_ids.verdicts([], {"mutants": got})}
            assert verdict["T-MUT-1"] == {"success": "pass", "failure": "fail"}.get(
                got, "not run"), (got, verdict["T-MUT-1"])
        assert mutants_result(os.path.join(t, "missing.json"), now)[0] == "skipped"
    print("coverage_report self-test ok")


def main(argv):
    if "--self-test" in argv:
        self_test()
        return 0
    args, key = {"logs": []}, None
    flags = {"--runs": "runs", "--branch-runs": "branch_runs", "--baseline": "baseline",
             "--notes": "notes", "--logs": "logs", "--jobs": "jobs", "--summary": "summary",
             "--merged-lcov": "merged_lcov", "--new-baseline": "new_baseline",
             "--badges": "badges", "--mutants": "mutants"}
    for a in argv:
        if a in flags:
            key = flags[a]
        elif key == "logs":
            args["logs"].append(a)
        elif key:
            args[key], key = a, None
        else:
            print(f"unexpected argument: {a}")
            return 2
    if "runs" not in args:
        print(__doc__)
        return 2
    return report(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
