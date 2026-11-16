#!/bin/sh
# Runs a command under a memory guard: `scripts/ci_guard.sh <command...>`.
#
# Why: in M7 CI round 1 the `test` job ended with "The hosted runner lost
# communication with the server", which leaves no evidence in the log
# (DESIGN_NOTES, M7 CI round 1). While the command runs, this script
#   - prints one line a minute to stderr (time, available memory, load), so
#     the log shows the state of the machine shortly before any such loss;
#   - if available memory falls below LOW_MIB, names the largest process
#     started from the cargo target directory (a test binary or pwv), and
#     below KILL_MIB kills it, so the step fails with a named culprit
#     instead of taking the runner down.
# It reads /proc only, prints no process arguments (rule 9), and returns
# the command's exit status.
set -u

LOW_MIB=${PWV_GUARD_LOW_MIB:-2048}
KILL_MIB=${PWV_GUARD_KILL_MIB:-1024}
PERIOD=${PWV_GUARD_PERIOD:-5}
TARGET=${CARGO_TARGET_DIR:-$PWD/target}

avail_mib() {
    awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo
}

# "<rss MiB> <pid> <program>" of the largest process run from $TARGET.
largest() {
    for d in /proc/[0-9]*; do
        exe=$(tr '\0' '\n' 2>/dev/null <"$d/cmdline" | head -n 1)
        case "$exe" in
            "$TARGET"/*) ;;
            *) continue ;;
        esac
        rss=$(awk '/^VmRSS:/ { print int($2 / 1024) }' "$d/status" 2>/dev/null)
        echo "${rss:-0} ${d#/proc/} ${exe#"$TARGET"/}"
    done | sort -rn | head -n 1
}

watch() {
    ticks=0
    while :; do
        sleep "$PERIOD"
        ticks=$((ticks + PERIOD))
        avail=$(avail_mib)
        if [ "$ticks" -ge 60 ]; then
            ticks=0
            echo "ci_guard: $(date -u +%H:%M:%S) available ${avail} MiB, load $(cut -d' ' -f1-3 /proc/loadavg)" >&2
        fi
        [ "$avail" -lt "$LOW_MIB" ] || continue
        set -- $(largest)
        echo "ci_guard: LOW MEMORY: available ${avail} MiB; largest: ${3:-none} (pid ${2:-0}, ${1:-0} MiB)" >&2
        if [ "$avail" -lt "$KILL_MIB" ] && [ "${2:-0}" -gt 1 ]; then
            echo "ci_guard: killing pid $2 ($3)" >&2
            kill -KILL "$2" 2>/dev/null
        fi
    done
}

watch &
guard=$!
"$@"
status=$?
kill "$guard" 2>/dev/null
wait "$guard" 2>/dev/null
exit "$status"
