#!/usr/bin/env python3
"""T-MUT-1 gate (spec 14.11; M9): every mutant that survived the full suite
(scripts/mutants.sh writes them to survivors.txt) must be justified in
DESIGN_NOTES.md, in a table under a heading containing "Surviving mutants",
one row per mutant with its exact cargo-mutants name in backticks:

  | `src/store.rs:466:9: delete fsync in save` | 2026-11-20 | reason |

Usage: mutants_check.py DESIGN_NOTES.md SURVIVORS.txt...
Exit 1 if any survivor is not justified.
"""

import re
import sys


def justified(notes):
    names = set()
    for m in re.finditer(r"^#+ .*Surviving mutants.*$", notes, re.M):
        for row in notes[m.end():].split("\n"):
            row = row.strip()
            if row.startswith("#"):
                break
            r = re.match(r"^\|\s*`([^`]+)`\s*\|", row)
            if r:
                names.add(r.group(1))
    return names


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        ok = justified(f.read())
    bad = 0
    for path in argv[1:]:
        with open(path, encoding="utf-8") as f:
            for name in (line.strip() for line in f):
                if not name:
                    continue
                if name in ok:
                    print(f"justified: {name}")
                else:
                    print(f"NOT JUSTIFIED: {name}")
                    bad += 1
    print(f"{bad} unjustified surviving mutants")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
