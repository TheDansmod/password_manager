#!/usr/bin/env python3
"""Inventory of the spec's Section 14 test IDs (M9, step 1).

For every test ID: the milestone whose gate it belongs to (spec Section 16)
and its evidence, which is one or more of
  - ("test", file, name): a `#[test] fn name` in `file`; CI shows it passed
    by a line `test [path::]name ... ok` in a test log;
  - ("job", text): a CI job or step whose success is the result (a gate
    that is not a test function, such as clippy or fuzzing);
  - ("test", file, name, job): such a test that acts only in that CI job
    (elsewhere it returns at once, e.g. without LazyFS); its status is the
    job's result, not a log line;
  - ("todo", text): not implemented yet (M9).

Uses (standard library only):
  python3 -I scripts/test_ids.py --check            # every named test exists
  python3 -I scripts/test_ids.py --check --spec S   # and S's IDs are all here
  python3 -I scripts/test_ids.py --markdown         # table for DESIGN_NOTES
  python3 -I scripts/test_ids.py --matrix S         # spec S's Section 13 rows,
      # each with its verifying IDs, their tests, and the CI job that checks
      # each test by name (exit 1 if a row names an unknown ID)
  python3 -I scripts/test_ids.py --logs a.txt ...   # pass/fail from test logs
  python3 -I scripts/test_ids.py --require T-KAT-1,T-FMT-2 --logs a.txt ...
      # gate by name: every named test of these IDs has an `ok` line in the
      # logs and none has `FAILED`; exit 1 otherwise

`--check` also reads .github/workflows/ci.yml and reports which named tests
are not yet listed in any "gate by name" step (`for t in ...; do`).
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def t(file, *names):
    return [("test", file, n) for n in names]


def tj(job, file, *names):
    """Tests that act only in CI job `job` (see the module docstring)."""
    return [("test", file, n, job) for n in names]


# (ID, milestone, evidence). Order follows Section 14.
IDS = [
    # 14.1
    ("T-KAT-1", "M3", t("tests/crypto.rs", "t_kat_1_argon2id_rfc9106")),
    ("T-KAT-2", "M3", t("tests/crypto.rs", "t_kat_2_xchacha20poly1305_draft_a31")),
    ("T-COMPAT-1", "M3", t("tests/crypto.rs", "t_compat_1_golden_vaults")
     + [("job", "compat")]),
    # 14.2
    ("T-FMT-1", "M2", t("tests/format.rs",
                        "t_fmt_1_parse_of_serialize_is_identity",
                        "t_fmt_1_serialize_of_parse_is_identity",
                        "t_fmt_1_samples_round_trip_and_mutations_can_still_parse")),
    ("T-FMT-2", "M2", t("tests/format.rs",
                        "t_fmt_2_empty_body_is_valid", "t_fmt_2_body_magic",
                        "t_fmt_2_body_length", "t_fmt_2_unsorted_names",
                        "t_fmt_2_duplicate_names", "t_fmt_2_case_folded_duplicate_keys",
                        "t_fmt_2_bad_utf8", "t_fmt_2_control_characters",
                        "t_fmt_2_name_whitespace", "t_fmt_2_field_flags",
                        "t_fmt_2_non_zero_padding", "t_fmt_2_non_minimal_padding",
                        "t_fmt_2_trailing_bytes_and_count_mismatch",
                        "t_fmt_2_name_len_0_max_max_plus_1",
                        "t_fmt_2_field_count_0_max_max_plus_1",
                        "t_fmt_2_key_len_0_max_max_plus_1",
                        "t_fmt_2_value_len_0_max_max_plus_1",
                        "t_fmt_2_content_len_0_max_max_plus_1",
                        "t_fmt_2_entry_count_0_max_max_plus_1",
                        "t_fmt_2_body_len_max", "t_fmt_2_error_metadata_is_content_free",
                        "t_fmt_2_header_fixed_fields", "t_fmt_2_header_kdf_bounds",
                        "t_fmt_2_header_generation_and_payload_len",
                        "t_fmt_2_file_length_exact")),
    ("T-FMT-3", "M2", t("tests/format.rs", "t_fmt_3_truncated_file_at_every_offset",
                        "t_fmt_3_truncated_body_at_every_offset")),
    ("T-FMT-4", "M2", t("tests/format_alloc.rs",
                        "t_fmt_4_hostile_headers_rejected_before_large_allocation")),
    # 14.3
    ("T-CRY-1", "M3", t("tests/crypto.rs", "t_cry_1_every_bit_flip_fails")),
    ("T-CRY-2", "M3", t("tests/crypto.rs", "t_cry_2_wrong_password_equals_damaged_payload")
     + t("tests/e2e.rs", "t_cry_2_wrong_password_and_damage_look_the_same")),
    ("T-CRY-3", "M3", t("tests/crypto.rs", "t_cry_3_nonces_fresh_over_100k_saves")),
    ("T-CRY-4", "M3", t("tests/crypto.rs", "t_cry_4_passwd_rotates_everything")),
    ("T-CRY-5", "M3", t("tests/crypto.rs",
                        "t_cry_5_header_tamper_detected_at_the_right_layer")),
    ("T-CRY-6", "M3", t("tests/crypto.rs", "t_cry_6_nfc_composed_vs_decomposed")),
    # 14.4
    ("T-GEN-1", "M6", t("tests/gen.rs", "t_gen_1_byte_mapping_is_exact_for_every_n",
                        "t_gen_1_word_mapping_is_exact_over_24_bits")),
    ("T-GEN-2", "M6", t("tests/gen.rs", "t_gen_2_exhaustive_uniformity")),
    ("T-GEN-3", "M6", t("tests/gen.rs", "t_gen_3_chi_square_default_policy")),
    ("T-GEN-4", "M6", t("tests/gen.rs", "t_gen_4_valid_policies_produce_valid_output",
                        "t_gen_4_invalid_policies_return_err",
                        "t_gen_4_each_constraint_at_its_limits")),
    ("T-GEN-5", "M6", t("tests/gen.rs", "t_gen_5_inclusion_exclusion_matches_brute_force")),
    ("T-GEN-6", "M6", t("tests/gen.rs", "t_gen_6_word_list_integrity")),
    # 14.5
    ("T-STORE-1", "M4", t("tests/store.rs", "t_store_1_modes",
                          "t_store_1_wrong_owner_root_directory",
                          "t_store_1_symlinks_and_file_types",
                          "t_store_1_statfs_classifier",
                          "t_store_1_foreign_fs_real_mount")
     + t("src/store.rs", "t_store_1_wrong_owner_via_uid_override")),
    ("T-STORE-2", "M4", t("src/store.rs", "t_store_2_crash_at_every_step")),
    ("T-STORE-3", "M4", t("tests/store.rs", "t_store_3_kill_loop")
     + [("job", "durability (5,000 iterations)")]),
    ("T-STORE-4", "M4", t("tests/store.rs", "t_store_4_second_process_refused")),
    ("T-STORE-5", "M4", t("tests/store.rs", "t_store_5_rollback_detected",
                          "t_store_5_state_never_regresses_and_tracks_vaults_separately")
     + t("tests/e2e.rs", "t_store_5_rollback_warning_no_exits_3_yes_continues")),
    ("T-STORE-6", "M4", t("tests/store.rs", "t_store_6_stale_temp_files_removed")),
    ("T-STORE-7", "M4", t("tests/store.rs", "t_store_7_seven_saves_keep_five_backups")
     + t("src/store.rs", "t_store_7_copy_fallback_without_hard_links")),
    ("T-STORE-8", "M9", tj("durability", "tests/store.rs",
                           "t_store_8_kill_loop_with_power_loss")),
    ("T-STORE-9", "M4", t("tests/store.rs", "t_store_9_read_only_sessions_do_not_write")
     + t("tests/e2e.rs", "t_store_9_read_only_commands_never_write")),
    # 14.6
    ("T-VAULT-1", "M5", t("tests/vault.rs", "t_vault_1_model_matches_reference",
                          "t_vault_1_parts_cover_every_segment_once",
                          "t_vault_1_ci_ranges_cover_every_segment_once")),
    ("T-VAULT-2", "M5", t("tests/vault.rs",
                          "t_vault_2_collisions_leave_model_and_file_identical",
                          "t_vault_2_random_models")),
    # 14.7
    ("T-E2E-1", "M7", t("tests/e2e.rs", "t_e2e_1_init_weak_password_refused",
                        "t_e2e_1_init_mismatch_refused",
                        "t_e2e_1_init_weak_password_needs_flag_and_sentence",
                        "t_e2e_1_init_generated_passphrase_accepted",
                        "t_e2e_1_init_refuses_existing_vault")),
    ("T-E2E-2", "M7", t("tests/e2e.rs",
                        "t_e2e_2_missing_vault_names_init_and_creates_nothing")),
    ("T-E2E-3", "M7", t("tests/e2e.rs", "t_e2e_3_ls_names_only_and_show_masks")),
    ("T-E2E-4", "M7", t("tests/e2e.rs",
                        "t_e2e_4_reveal_once_then_clears_screen_and_scrollback")),
    ("T-E2E-5", "M7", t("tests/e2e.rs", "t_e2e_5_add_and_set_errors_keep_the_session",
                        "t_e2e_5_set_replacing_a_sensitive_value_needs_confirmation",
                        "t_e2e_5_overlong_password_line_is_rejected_not_truncated")),
    ("T-E2E-6", "M7", t("tests/e2e.rs", "t_e2e_6_idle_timeout_locks_and_exits_0")
     + t("tests/clip.rs", "t_e2e_6_idle_exit_clears_the_clipboard")),
    ("T-E2E-7", "M7", t("tests/e2e.rs", "t_e2e_7_sigint_cancels_the_command",
                        "t_e2e_7_sigterm_sighup_sigquit_exit_cleanly_and_restore_termios")),
    ("T-E2E-8", "M7", t("tests/e2e.rs",
                        "t_e2e_8_control_and_bidi_characters_are_shown_as_escapes")),
    ("T-E2E-9", "M7", t("tests/e2e.rs",
                        "t_e2e_9_rm_needs_the_exact_name_and_there_is_no_export")),
    ("T-E2E-10", "M8", t("tests/e2e.rs", "t_e2e_10_import_valid_invalid_and_tty",
                         "t_e2e_10_import_reads_the_pipe_before_asking_for_the_master_password")
     + t("tests/mig.rs", "t_mig_1_a_vault_larger_than_the_pipe_buffer_arrives_whole")),
    ("T-E2E-11", "M7", t("tests/e2e.rs", "t_e2e_11_passwd_then_only_the_new_password_opens")),
    ("T-E2E-12", "M7", t("tests/e2e.rs", "t_e2e_12_no_terminal_is_exit_4")),
    # 14.8
    ("T-CLIP-1", "M7", t("tests/clip.rs", "t_clip_1_copy_sets_the_history_exclusion_hint")),
    ("T-CLIP-2", "M7", t("tests/clip.rs", "t_clip_2_clipboard_is_cleared_after_the_timeout")),
    ("T-CLIP-3", "M7", t("tests/clip.rs", "t_clip_3_a_foreign_value_is_not_cleared")),
    ("T-CLIP-4", "M7", t("tests/clip.rs",
                         "t_clip_4_the_clipboard_manager_receives_nothing_sensitive_at_exit")),
    # 14.9
    ("T-MEM-1", "M1", t("tests/secmem.rs",
                        "t_mem_1_smaps_locked_dontdump_wipeonfork_guards")),
    ("T-MEM-2", "M1", t("tests/secmem.rs", "t_mem_2_write_past_last_slot_faults",
                        "t_mem_2_write_before_first_slot_faults")),
    ("T-MEM-3", "M1", t("tests/secmem.rs",
                        "t_mem_3_slot_drop_then_arena_drop_leave_all_zero",
                        "t_mem_3_arena_drop_wipes_even_if_slot_drop_was_skipped")),
    ("T-MEM-4", "M8", t("tests/mem.rs", "t_mem_4_canary_scan_mid_session_and_after_lock",
                        "t_mem_4_signal_eof_and_idle_exits_are_wiped",
                        "t_mem_4_passwd_add_gen_names_and_keys",
                        "t_mem_4_init_import_and_refusals_are_wiped",
                        "scan_skips_guard_pages_and_nothing_else")),
    ("T-MEM-5", "M1", t("tests/harden.rs", "t_mem_5_core_limit_ptrace_mem_and_sigsegv")
     + [("job", "coredump (no coredumpctl entry)")]),
    ("T-MEM-6", "M1", t("tests/alloc.rs", "t_mem_6_verifying_layer_is_active")
     + t("tests/eng.rs", "t_mem_6_every_test_crate_installs_verifying_allocator")),
    ("T-MEM-7", "M3", t("tests/kdf_region.rs", "t_mem_7_kdf_region_unmapped_after_unlock")),
    # 14.10
    ("T-FUZZ-1", "M2", [("job", "fuzz-smoke (fuzz_header)")]
     + t("tests/format.rs", "fuzz_corpus_seeds_are_committed")),
    ("T-FUZZ-2", "M2", [("job", "fuzz-smoke (fuzz_body)")]),
    ("T-FUZZ-3", "M3", [("job", "fuzz-smoke (fuzz_open, --features testkdf)")]
     + t("tests/crypto.rs", "golden_vectors_and_fuzz_open_seeds")),
    ("T-FUZZ-4", "M7", [("job", "fuzz-smoke (fuzz_tokenizer)")]
     + t("tests/cli.rs", "tokenizer_and_parser_on_every_truncation",
         "tokenizer_properties", "fuzz_corpus_seeds_are_committed")),
    ("T-FUZZ-5", "M7", [("job", "fuzz-smoke (fuzz_sanitize)")]
     + t("tests/cli.rs", "sanitize_every_unsafe_character",
         "sanitize_properties_and_truncation")),
    ("T-FUZZ-6", "M5", [("job", "fuzz-smoke (fuzz_import)")]
     + t("tests/vault.rs", "import_rejects_invalid_bodies_and_every_truncation",
         "fuzz_import_corpus_seeds_are_committed")),
    # 14.11
    ("T-ENG-1", "M0", [("job", "lint: rustfmt and clippy steps")]),
    ("T-ENG-2", "M0", t("tests/eng.rs", "t_eng_2_unsafe_confined_and_justified",
                        "selftest_unsafe_checker")),
    ("T-ENG-3", "M0", t("tests/eng.rs", "t_eng_3_layering", "t_eng_3_no_global_state",
                        "selftest_global_state_checker")),
    ("T-ENG-4", "M0", t("tests/eng.rs", "t_eng_4_ban_exemptions_scoped",
                        "t_eng_4_file_primitives_only_in_store")
     + [("job", "lint: clippy steps (clippy.toml bans)")]),
    ("T-ENG-5", "M1", [("job", "test: tests/secmem.rs compiles (assert_not_impl_any!)")]),
    ("T-ENG-6", "M0", [("job", "lint: T-ENG-6 LOC budget")]),
    ("T-ENG-7", "M9", [("job", "release-check (T-ENG-7 ok; also in release.yml)")]),
    ("T-SAN-1", "M9", [("job", "sanitizers-asan (four configurations)")]),
    ("T-SAN-2", "M2", [("job", "sanitizers (Miri matrix)")]),
    ("T-MUT-1", "M9", [("job", "mutants (weekly workflow mutants.yml)")]),
    ("T-COV-1", "M9", [("job", "coverage-report (merged coverage runs)")]),
    ("T-COV-2", "M9", [("job", "coverage-report (merged coverage runs)")]),
    ("T-COV-3", "M9", [("job", "coverage-report (unsafe block list)")]
     + t("tests/eng.rs", "t_cov_3_unsafe_blocks_listed", "selftest_unsafe_uses")),
    ("T-COV-4", "M9", [("job", "coverage-report (coverage/baseline.json)")]),
    ("T-COV-5", "M9", [("job", "coverage-branch (nightly)"),
                       ("job", "coverage-report (branch figures)")]),
    ("T-COV-6", "M9", [("job", "fuzz-long (report-only)")]),
    # 14.12
    ("T-SUPPLY-1", "M0", [("job", "supply")]),
    ("T-REPRO-1", "M9", [("job", "release-check (T-REPRO-1 ok; also in release.yml)")]),
    ("T-PERF-1", "M9", tj("perf", "tests/perf.rs", "t_perf_1_unlock_at_default_parameters",
                          "t_perf_1_save_1000_entries_on_tmpfs",
                          "t_perf_1_allocator_overhead")),
    ("T-MIG-1", "M8", t("tests/mig.rs",
                        "t_mig_1_legacy_fixture_imports_the_expected_model_with_its_warning",
                        "t_mig_1_key_case_collision_and_invalid_entries_are_refused",
                        "t_mig_1_wrong_legacy_passphrase_imports_nothing",
                        "t_mig_1_a_vault_larger_than_the_pipe_buffer_arrives_whole")),
    ("T-MIG-2", "M8", t("tests/mig.rs", "t_mig_2_malicious_pickle_aborts_and_creates_no_marker",
                        "t_mig_2_script_has_no_code_executing_parser")),
    ("T-MIG-3", "M8", t("tests/mig.rs", "t_mig_3_stdout_must_be_a_pipe")),
]

ID_RE = re.compile(r"\bT-[A-Z0-9]+-(?:\d+|\*)")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_fns(text):
    """Names of the functions annotated `#[test]` (attributes may follow)."""
    names = set()
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.strip() != "#[test]":
            continue
        for nxt in lines[i + 1:i + 12]:
            m = re.match(r"\s*(?:pub\s+)?fn\s+(\w+)", nxt)
            if m:
                names.add(m.group(1))
                break
    return names


def gated_names():
    """Test names listed in the workflow's gate-by-name loops."""
    ci = read(".github/workflows/ci.yml")
    names = set()
    for m in re.finditer(r"for t in (.*?); do", ci, re.S):
        names.update(m.group(1).replace("\\", " ").split())
    # `--require ID,ID,...` steps name every test of those IDs.
    table = {tid: ev for tid, _, ev in IDS}
    for m in re.finditer(r"--require\s+([A-Z0-9,-]+)", ci):
        for tid in m.group(1).split(","):
            names.update(e[2] for e in table.get(tid, []) if e[0] == "test")
    return {n.rsplit("::", 1)[-1] for n in names}


def spec_ids(path):
    """Test IDs defined in the spec's Section 14 (expanding `T-X-1 – T-X-6`)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    sec = text[text.index("## 14. Testing"):text.index("## 15. ")]
    ids = set()
    for m in re.finditer(r"(T-[A-Z0-9]+-)(\d+) [–-] T-[A-Z0-9]+-(\d+)", sec):
        ids.update(f"{m.group(1)}{k}" for k in range(int(m.group(2)), int(m.group(3)) + 1))
    for m in re.finditer(r"T-FUZZ-(\d)", sec):
        ids.add(f"T-FUZZ-{m.group(1)}")
    for m in re.finditer(r"^\| (T-[A-Z0-9]+-\d+)", sec, re.M):
        ids.add(m.group(1))
    return ids


def check(spec):
    errors = []
    ids = [i for i, _, _ in IDS]
    if len(ids) != len(set(ids)):
        errors.append("duplicate ID in the table")
    cache = {}
    for tid, _, ev in IDS:
        for e in ev:
            if e[0] != "test":
                continue
            fns = cache.setdefault(e[1], test_fns(read(e[1])))
            if e[2] not in fns:
                errors.append(f"{tid}: no #[test] fn {e[2]} in {e[1]}")
    if spec:
        want = spec_ids(spec)
        for missing in sorted(want - set(ids)):
            errors.append(f"spec ID not in the table: {missing}")
        for extra in sorted(set(ids) - want):
            errors.append(f"table ID not in the spec: {extra}")
    gated = gated_names()
    ungated = [(tid, e[2]) for tid, _, ev in IDS for e in ev
               if e[0] == "test" and e[2] not in gated]
    for e in errors:
        print("ERROR:", e)
    print(f"{len(IDS)} IDs; {sum(1 for _, _, ev in IDS if ev[0][0] == 'todo')} not "
          f"implemented; {len(ungated)} named tests in no gate-by-name step")
    for tid, name in ungated:
        print(f"  not gated by name: {tid} {name}")
    return 1 if errors else 0


def markdown():
    gated = gated_names()
    print("| ID | Milestone | Evidence | Gated by name |")
    print("| --- | --- | --- | --- |")
    for tid, ms, ev in IDS:
        parts, flags = [], []
        for e in ev:
            if e[0] == "test":
                parts.append(f"`{os.path.basename(e[1])[:-3]}::{e[2]}`")
                flags.append(e[2] in gated)
            elif e[0] == "job":
                parts.append(f"job: {e[1]}")
            else:
                parts.append(f"**to do:** {e[1]}")
        g = "n/a" if not flags else ("yes" if all(flags) else
                                     ("partly" if any(flags) else "no"))
        print(f"| {tid} | {ms} | {'<br>'.join(parts)} | {g} |")


def read_logs(paths):
    text = ""
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            text += f.read()
    return text


def job_result(evidence, jobs):
    """Result of the CI job an evidence text names (its first word, e.g.
    `fuzz-smoke` in "fuzz-smoke (fuzz_header)", `lint` in "lint: clippy"),
    from `jobs` = {job id: result}; None if unknown."""
    name = re.split(r"[ :(]", evidence.strip(), maxsplit=1)[0]
    return jobs.get(name)


def verdicts(paths, jobs=None):
    """(ID, milestone, verdict) per ID. Named tests: pass if every one has
    an `ok` line in the logs, fail if any has `FAILED`, else not run. Jobs:
    the job's result when `jobs` ({job id: "success"/"failure"/"skipped"/
    ...}) knows it and the job ran; a test tied to a job takes that job's
    result (skipped: not run); an ID with no result is "job". To-dos:
    "to do"."""
    text = read_logs(paths)
    jobs = jobs or {}
    out = []
    for tid, ms, ev in IDS:
        res = []
        for e in ev:
            if e[0] == "test" and len(e) == 4:
                r = jobs.get(e[3])
                res.append({"success": "pass", "failure": "fail"}.get(r, "not run"))
            elif e[0] == "test":
                name = re.escape(e[2])
                if re.search(rf"^test (\S+::)?{name} \.\.\. FAILED$", text, re.M):
                    res.append("fail")
                elif re.search(rf"^test (\S+::)?{name} \.\.\. ok$", text, re.M):
                    res.append("pass")
                else:
                    res.append("not run")
            elif e[0] == "job":
                # A job skipped in this run (nightly-only on a push) adds
                # nothing if the ID also has tests, whose log lines decide;
                # for an ID proven by jobs alone it means "not run".
                r = job_result(e[1], jobs)
                if r in ("success", "failure"):
                    res.append("pass" if r == "success" else "fail")
                elif r is not None and all(x[0] == "job" for x in ev):
                    res.append("not run")
        kinds = {e[0] for e in ev}
        if "todo" in kinds:
            verdict = "to do"
        elif not res:
            verdict = "job"
        elif "fail" in res:
            verdict = "fail"
        elif all(r == "pass" for r in res):
            verdict = "pass"
        else:
            verdict = "not run"
        out.append((tid, ms, verdict))
    return out


def from_logs(paths):
    """Prints the verdict per ID; exit 1 if any ID failed."""
    status = 0
    for tid, ms, verdict in verdicts(paths):
        status |= verdict == "fail"
        print(f"{tid}\t{ms}\t{verdict}")
    return status


def require(ids, paths):
    text = read_logs(paths)
    table = {tid: ev for tid, _, ev in IDS}
    bad = 0
    for tid in ids:
        if tid not in table:
            print(f"unknown ID: {tid}")
            bad += 1
            continue
        names = [e[2] for e in table[tid] if e[0] == "test" and len(e) == 3]
        if not names:
            print(f"{tid}: no named test to require")
            bad += 1
        for name in names:
            n = re.escape(name)
            failed = re.search(rf"^test (\S+::)?{n} \.\.\. FAILED$", text, re.M)
            ok = re.search(rf"^test (\S+::)?{n} \.\.\. ok$", text, re.M)
            if failed or not ok:
                print(f"missing: {tid} {name}" + (" (FAILED)" if failed else ""))
                bad += 1
    print(f"{len(ids)} IDs required; {bad} problems")
    return 1 if bad else 0


def job_blocks():
    """{job id: its text} of .github/workflows/ci.yml (top-level jobs)."""
    ci = read(".github/workflows/ci.yml")
    body = ci[ci.index("\njobs:\n"):]
    blocks, name = {}, None
    for line in body.split("\n"):
        m = re.match(r"^  ([a-z0-9-]+):\s*$", line)
        if m:
            name = m.group(1)
            blocks[name] = ""
        elif name:
            blocks[name] += line + "\n"
    return blocks


def gating_jobs(tid, name, blocks):
    """CI jobs whose gate-by-name steps name test `name` (of ID `tid`)."""
    out = []
    for job, text in blocks.items():
        loops = " ".join(m.group(1) for m in re.finditer(r"for t in (.*?); do", text, re.S))
        loops = {n.rsplit("::", 1)[-1] for n in loops.replace("\\", " ").split()}
        req = {i for m in re.finditer(r"--require\s+([A-Z0-9,-]+)", text)
               for i in m.group(1).split(",")}
        if name in loops or tid in req:
            out.append(job)
    return out


def expand(cell):
    """Test IDs named in a Section 13 cell: `T-FMT-1–4`, `T-COV-1 – T-COV-5`,
    `T-FUZZ-\\*` (every T-FUZZ ID), single IDs."""
    ids = []
    cell = cell.replace("\\*", "*")
    for m in re.finditer(r"(T-[A-Z0-9]+-)(\d+|\*)(?:\s*[–-]\s*(?:T-[A-Z0-9]+-)?(\d+))?", cell):
        pre, a, b = m.group(1), m.group(2), m.group(3)
        if a == "*":
            ids += [i for i, _, _ in IDS if i.startswith(pre)]
        elif b:
            ids += [f"{pre}{k}" for k in range(int(a), int(b) + 1)]
        else:
            ids.append(f"{pre}{a}")
    return ids


def matrix(spec):
    with open(spec, encoding="utf-8") as f:
        text = f.read()
    sec = text[text.index("## 13. Traceability"):text.index("## 14. ")]
    table = {tid: ev for tid, _, ev in IDS}
    blocks = job_blocks()
    bad = 0
    print("| Finding | Section | Verifying IDs | Tests (CI job checking each by name) |")
    print("| --- | --- | --- | --- |")
    for row in sec.split("\n"):
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if len(cells) != 4 or not re.match(r"^[SRBE]\d|^Generator", cells[0]):
            continue
        finding, _, section, tests = cells
        ids = expand(tests)
        parts = []
        for tid in ids:
            if tid not in table:
                print(f"ERROR: {finding}: unknown ID {tid}", file=sys.stderr)
                bad += 1
                continue
            for e in table[tid]:
                if e[0] == "test":
                    jobs = gating_jobs(tid, e[2], blocks)
                    if len(e) == 4:
                        jobs = jobs or [e[3]]
                    parts.append(f"`{e[2]}` ({', '.join(jobs) or 'not gated by name'})")
                elif e[0] == "job":
                    parts.append(f"job: {e[1]}")
        if not ids:
            print(f"ERROR: {finding}: no test ID", file=sys.stderr)
            bad += 1
        print(f"| {finding} | {section} | {', '.join(ids)} | {'<br>'.join(parts)} |")
    return 1 if bad else 0


def main(argv):
    if "--matrix" in argv:
        return matrix(argv[argv.index("--matrix") + 1])
    if "--require" in argv:
        ids = argv[argv.index("--require") + 1].split(",")
        return require(ids, argv[argv.index("--logs") + 1:])
    if "--markdown" in argv:
        markdown()
        return 0
    if "--logs" in argv:
        return from_logs(argv[argv.index("--logs") + 1:])
    spec = argv[argv.index("--spec") + 1] if "--spec" in argv else None
    return check(spec)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
