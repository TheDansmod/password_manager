#!/bin/sh
# Sets pwv's version for a release (DEVELOPMENT.md, "Releasing"), without
# cargo, a Rust toolchain, or network access:
#
#   sh scripts/set_version.sh 0.1.0-rc.1
#
# Edits exactly three lines: `version` in Cargo.toml's [package] section,
# and pwv's `version` in Cargo.lock and fuzz/Cargo.lock. pwv is a path
# package there (no checksum, no source), so that line is all `cargo update
# -p pwv` would change; CI builds with `--locked` and fails if a lock file
# disagrees. Then tag the commit `v<version>` (release-build.yml checks it).
set -eu

new=${1:?usage: sh scripts/set_version.sh X.Y.Z[-pre]}
# SemVer 2.0: MAJOR.MINOR.PATCH, optional -prerelease and +build.
if ! printf '%s\n' "$new" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "not a SemVer version (no leading v): $new" >&2
  exit 1
fi
root=$(cd "$(dirname "$0")/.." && pwd)

# set FILE MODE: MODE `toml` = first `version =` after `[package]`;
# MODE `lock` = the `version =` right after `name = "pwv"`. Keeps a CR at the
# end of a line (checkouts with CRLF endings). Fails unless exactly one line
# changed.
set_in() {
  file=$1 mode=$2
  awk -v new="$new" -v mode="$mode" '
    BEGIN { n = 0; armed = 0 }
    {
      line = $0; cr = ""
      if (sub(/\r$/, "", line)) cr = "\r"
      if (mode == "toml") {
        if (line ~ /^\[package\]$/) armed = 1
        else if (line ~ /^\[/) armed = 0
      }
      if (armed && line ~ /^version = "[^"]*"$/) {
        line = "version = \"" new "\""; n++; armed = 0
      }
      if (mode == "lock") armed = (line == "name = \"pwv\"")
      print line cr
    }
    END { if (n != 1) exit 3 }
  ' "$file" > "$file.tmp" || { rm -f "$file.tmp"; echo "pwv's version line not found in $file" >&2; exit 1; }
  mv "$file.tmp" "$file"
}

old=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"\r*$/\1/p' "$root/Cargo.toml" | head -n 1)
set_in "$root/Cargo.toml" toml
set_in "$root/Cargo.lock" lock
set_in "$root/fuzz/Cargo.lock" lock
echo "version $old -> $new in Cargo.toml, Cargo.lock, fuzz/Cargo.lock"
echo "next: commit, push, wait for CI, then: git tag -a v$new -m \"pwv $new\" && git push origin v$new"
