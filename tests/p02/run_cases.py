#!/usr/bin/env python3
"""P02 tiered runner and bounded diagnostic receipt (bead ffw-jub): the "owned test assets" and "Logging" clauses of the original acceptance.

    run_cases.py [--tier smoke|full|soak] [--list] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds and boots nothing and never invokes cargo. The Rust runs only through the centralized RCH path (the
plan is printed by ``scripts/e2e/p02 --plan``); its result enters here only as the retained ``cargo test`` log(s) given with ``--judge``:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --locked --offline -p franken-platform -p franken-platform-linux -p franken-speaker -- --nocapture

This is the same adapter as ``tests/n01/run_cases.py`` (and ``tests/d01``, ``tests/s02``): the named-test judge, the explicit tiers and the case
log on the existing Q00 ``DiagnosticSink`` (``case_log.py``). It reuses the existing logging backend and names the original P02 requirements here.

Tiers (explicit; ``scripts/e2e/p02 --tier ...``):

  smoke  the clause map is whole (every requirement id names Rust tests that the sources define, each once in the whole workspace) and the
         existing Python host cross-checks of ``tests/p02`` pass. Seconds; needs no log.
  full   smoke, and one case per requirement id of the acceptance, each decided from the named Rust tests in the retained cargo log(s).
         Without a log those cases are BLOCKED: counted, named, never passed.
  soak   selectable, says why nothing runs, exits 4. It is never a pass.

Rust-backed cases. A requirement passes only when every test it names is reported ``ok`` by the log(s). A test the log does not report, or whose
name was printed with no result (a cut-off run), BLOCKS the case: evidence is missing. A test reported ``FAILED``, a test reported ``ignored``
(a required test someone switched off is a weakened assertion, not missing evidence), and a test the logs report with two different results,
FAIL it; the first causal event of a failure is cargo's panic location and message. The floor case ``P02-RUST-ALL`` requires every test of P02's
own files, so a requirement map cannot silently leave one out. Tests of other crates, P06's modules (``net``, ``durable``), N07's datagram modules and unrelated
ignored tests in the same log are not judged and cannot affect a verdict.

Every decided case writes a CRITICAL begin and end event through the shared Q00 sink; a run whose log lost critical evidence (dropped, torn,
unreadable, never closed, hung, or an event count that is not the cases' own) is NOT QUALIFIED. A run that is not a pass prints RETAINED FOR
REPLAY: the first failure or block, the replay command, the versions and the sha256 of every artifact and log judged. ``--receipts DIR`` also
writes a JSON receipt next to the JSONL diagnostic log; neither names a local path or a worker. Without ``--receipts`` the JSONL log is kept in a fresh
``mkdtemp`` directory whose path is printed; the runner never deletes it.

Exit codes: 0 every case passed and the diagnostic log is complete; 1 a case failed or the log lost critical evidence; 3 the only non-passes are
blocked cases; 4 ``--tier soak``; 2 usage.

What a pass is not. The artifact digests bind the files this checkout holds when it judges; they do not prove that the judged log was produced
from them (the log's own tree is the supervisor's central-run record). The Rust tests drive scripted doubles and the leaf's number tables: no
kernel, board or provider ran anything here, and a green log says nothing about the stock kernels the contract leaves unqualified
(``docs/contracts/p02.md``, "Known limits"). The soak tier is NOT RUN.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TIERS = ("smoke", "full", "soak")
RUN_TIERS = ("smoke", "full")
SOAK_EXIT = 4
SOAK_NOT_RUN = (
    "P02 soak: NOT RUN. P02 owns no long-running test: its Rust tests are scripted-double unit tests that finish in seconds, and the kernel-facing "
    "evidence is two bounded QEMU speaker smoke runs recorded under toolchain/results/runs (docs/contracts/p02.md). Nothing here soaks. "
    "This is not a pass.")
RECEIPT_SCHEMA = "ffw.p02.receipt.v1"
MAX_PRINTED = 12
UNIT_TIMEOUT_S = 600
CONTRACT = "docs/contracts/p02.md"

# P02's own Rust files (repo-relative). Their libtest names are derived from the path: `src/lib.rs` is the crate root, any other `src/x.rs` is
# module `x`, and inline `mod tests { ... }` blocks add their own segment. `net.rs` and `durable.rs` belong to P06; `datagram.rs` and
# `datagram_route.rs` belong to N07. They are not judged here; `wall_clock.rs` is P02's (original acceptance, wall-clock confidence kept apart
# from monotonic audio time). The source-coverage meta-test names these four exclusions and catches an omitted P02 module.
CLI_TESTS = frozenset({
    "platform_diagnose_is_a_real_command_with_a_safe_action_for_an_unavailable_backend",
    "both_platform_commands_reject_malformed_provider_arguments_before_startup",
})
GROUPS: Dict[str, List[str]] = {
    "platform": ["crates/franken-platform/src/%s.rs" % m for m in ("abi", "clock", "entropy", "layer", "lib", "ops", "sim", "socket", "wait", "wake", "wall_clock")],
    "linux": ["crates/franken-platform-linux/src/%s.rs" % m for m in ("lib", "numbers", "socket_route", "sys", "wait_route")],
    "speaker": ["crates/franken-speaker/src/platform_start.rs", "crates/franken-speaker/tests/cli_services.rs"],
}
JUDGED_ARTIFACTS = tuple(
    ["tests/p02/run_cases.py", "tests/p02/case_log.py", "tests/p02/test_run_cases.py", "scripts/e2e/p02", "scripts/test/test_support/diagnostics.py", CONTRACT, "Cargo.lock", "rust-toolchain.toml",
     "crates/franken-platform/Cargo.toml", "crates/franken-platform-linux/Cargo.toml", "crates/franken-speaker/Cargo.toml",
     "crates/franken-speaker/src/main.rs"]
    + [rel for files in GROUPS.values() for rel in files])

# The original acceptance, requirement by requirement (bead ffw-jub "Acceptance" and the "Acceptance map" of docs/contracts/p02.md), each decided from
# named Rust tests (libtest names). Every name must be defined in P02's files, once in the whole workspace (P02-META-MAP).
REQUIREMENTS: List[Tuple[str, str, List[str]]] = [
    ("P02-AC-ENTROPY", "no insecure entropy fallback: one explicitly selected provider, no other source tried after a failure, nothing cached, no byte survives an error, an unseeded pool is an error",
     ["entropy::tests::an_unseeded_pool_is_an_error_with_no_bytes_and_no_other_source_tried", "entropy::tests::a_failure_after_partial_bytes_still_zeroes_the_whole_buffer",
      "entropy::tests::a_success_that_produced_one_repeated_byte_is_degenerate_not_entropy", "entropy::tests::matrix_status_maps_to_availability_and_absent_with_fallback_is_unavailable",
      "entropy::tests::a_getrandom_failure_never_selects_the_legacy_provider", "entropy::tests::a_legacy_failure_never_falls_back_to_getrandom",
      "entropy::tests::nothing_is_cached_between_calls_a_seeded_answer_is_asked_again", "entropy::tests::the_profile_decides_availability_and_only_getrandom_reads_the_matrix",
      "entropy::tests::no_error_and_no_call_record_can_carry_the_bytes_a_call_received", "entropy::tests::bytes_received_before_a_failure_never_survive_it",
      "entropy::tests::a_missing_device_is_reported_as_such_and_no_other_file_is_tried",
      "layer::tests::entropy_that_the_matrix_says_is_unavailable_is_refused_without_a_kernel_call_and_with_no_bytes",
      "layer::tests::an_unseeded_pool_is_asked_again_every_time_and_never_remembered_or_papered_over",
      "layer::tests::the_default_provider_is_getrandom_and_selecting_another_makes_no_kernel_call",
      "layer::tests::an_unqualified_legacy_provider_is_refused_without_a_kernel_call_even_if_getrandom_would_work",
      "layer::tests::a_getrandom_layer_that_is_unavailable_never_opens_the_legacy_device",
      "tests::secure_entropy_follows_getrandom_alone_and_never_the_urandom_liveness_status", "tests::an_unseeded_status_is_not_a_pass_for_any_capability_the_gate_requires",
      "platform_start::tests::an_unseeded_pool_is_a_retryable_refusal_and_is_never_answered_with_a_seeded_value",
      "platform_start::tests::a_getrandom_failure_at_startup_never_opens_the_legacy_device"]),
    ("P02-AC-NO-FAKE-SUCCESS", "no fake syscall success: success only on an exact decode, malformed returns never coerced, short or oversized returns are errors, doubles say they are simulated",
     ["abi::tests::a_non_negative_return_is_a_result_and_zero_is_not_an_error", "abi::tests::a_negative_value_that_is_not_an_errno_is_malformed_and_never_coerced",
      "clock::tests::success_is_exactly_zero_and_other_returns_are_not_a_time", "clock::tests::a_timespec_outside_the_valid_range_is_never_turned_into_a_time",
      "entropy::tests::a_kernel_that_reports_more_than_was_asked_or_nothing_at_all_is_an_error", "entropy::tests::a_return_value_that_is_not_an_errno_is_malformed_never_success",
      "entropy::tests::a_read_that_reports_more_than_was_asked_or_nothing_is_an_error_and_the_device_is_still_closed",
      "wake::tests::a_short_or_failed_write_is_an_error_not_a_wake", "wake::tests::an_eventfd_read_that_is_not_one_nonzero_counter_is_an_error",
      "wake::tests::a_close_is_issued_once_even_when_it_answers_eintr_and_a_nonzero_return_is_not_success",
      "socket::tests::a_descriptor_above_i32_max_is_not_a_result", "socket::tests::accept4_passes_other_errnos_through_and_refuses_what_is_not_a_result",
      "layer::tests::a_double_reports_itself_as_simulated_through_the_layer",
      "sim::tests::the_double_says_it_is_simulated_and_names_no_abi_so_it_cannot_be_taken_for_a_kernel",
      "platform_start::tests::a_device_build_wired_to_a_simulated_backend_is_refused_before_any_kernel_call"]),
    ("P02-AC-ABSENT", "absent syscalls: ENOSYS in the guest's own numbering is absence (EINVAL is absence only for accept4), absence is reported once and no other mechanism is tried",
     ["abi::tests::enosys_is_absence_only_in_the_guests_own_numbering",
      "clock::tests::an_absent_clock_is_an_error_in_the_guests_own_numbering_and_there_is_no_wall_clock_to_use",
      "entropy::tests::absence_is_the_guest_abis_own_enosys_and_never_another_abis", "entropy::tests::einval_is_not_absence_and_other_errnos_keep_their_number",
      "wake::tests::an_absent_admitted_call_is_reported_and_no_other_mechanism_is_tried", "wake::tests::an_absence_that_follows_an_interruption_is_still_absence",
      "socket::tests::a_socket_call_the_kernel_does_not_have_is_absent_after_one_call", "socket::tests::accept4_enosys_is_absent_and_no_second_call_is_issued",
      "socket::tests::accept4_einval_is_absent_and_no_second_call_is_issued", "socket::tests::only_accept4_reads_einval_as_absent",
      "platform_start::tests::a_clock_that_is_absent_is_a_typed_refusal_and_the_other_capabilities_are_still_tried",
      "platform_start::tests::an_entropy_call_that_is_absent_or_degenerate_is_refused_not_papered_over"]),
    ("P02-AC-EINTR", "interrupted calls: EINTR is repeated at most the contract's bound and then reported, per capability; close is issued once",
     ["abi::tests::a_call_is_retried_only_while_it_is_interrupted_and_only_a_bounded_number_of_times", "clock::tests::an_interruption_storm_is_reported_after_the_bounded_attempts",
      "entropy::tests::an_interrupted_call_is_retried_a_bounded_number_of_times", "entropy::tests::an_interrupted_read_is_repeated_a_bounded_number_of_times_and_then_reported",
      "entropy::tests::an_interrupted_open_is_repeated_a_bounded_number_of_times_and_no_read_or_close_follows",
      "entropy::tests::closing_is_part_of_the_call_a_failed_close_discards_the_bytes_and_an_eintr_close_does_not",
      "wake::tests::an_interrupted_write_is_retried_then_reported_after_the_bound", "wake::tests::an_interrupted_eventfd2_is_repeated_unchanged_then_reported_after_the_bound",
      "wake::tests::an_interrupted_pipe2_is_repeated_unchanged_then_reported_after_the_bound",
      "wake::tests::an_interrupted_eventfd_write_is_repeated_with_the_same_counter_then_reported_after_the_bound",
      "wake::tests::an_interrupted_eventfd_read_is_repeated_then_reported_after_the_bound_and_is_not_nothing_pending",
      "wake::tests::an_interrupted_self_pipe_read_is_repeated_then_reported_after_the_bound", "wake::tests::the_bound_every_count_above_is_relative_to_is_the_contracts_eight",
      "socket::tests::socket_interruptions_are_bounded_and_the_last_attempt_still_counts", "socket::tests::bind_and_listen_interruptions_are_bounded_and_the_last_attempt_still_counts",
      "socket::tests::accept4_interruptions_are_bounded_and_the_last_attempt_still_counts", "socket::tests::recv_datagram_interruptions_are_bounded_and_the_last_attempt_still_counts"]),
    ("P02-AC-ACCEPT-FCNTL", "accept/fcntl concurrency: the section is documented, and the policy sets nonblock and close-on-exec in the creating call (no fcntl fix-up), accept4 only, with the unsupported route refused by name",
     ["socket::tests::open_socket_sets_nonblock_and_cloexec_in_the_call_itself_on_both_abis", "socket::tests::a_socket_refused_with_einval_is_reported_and_never_made_plainly_and_fixed_up",
      "socket::tests::accept4_sets_both_flags_in_the_call_and_returns_the_descriptor", "socket::tests::accept4_with_nothing_pending_would_block_and_is_not_absence",
      "socket::tests::a_server_is_four_calls_in_order_and_nothing_else_issues_a_call",
      "wake::tests::the_eventfd_is_opened_nonblocking_and_cloexec_in_each_abis_own_flags", "wake::tests::the_self_pipe_is_opened_with_pipe2_nonblocking_and_cloexec",
      "numbers::tests::accept4_is_on_neither_stock_route_and_every_other_call_of_the_plan_is",
      "socket_route::tests::the_socketcall_route_is_refused_by_name_on_v2_6_27_and_its_neighbours_are_admitted",
      "socket_route::tests::a_release_that_cannot_rule_out_v2_6_27_is_not_admitted_for_the_socketcall_route"]),
    ("P02-AC-ABI", "explicit ABI per big-endian target: per-ABI errno and flag tables equal the oracle's vectors, the two ABIs really differ, a backend for the other ABI or a non-legacy triple is refused before any call",
     ["abi::tests::the_transient_and_argument_errnos_are_the_same_on_both_abis_and_einval_is_not_absence", "abi::tests::the_generic_errno_constants_match_both_tables",
      "abi::tests::each_table_has_unique_names_and_unique_numbers_and_the_two_abis_really_differ", "abi::tests::the_nonblock_flag_is_each_abis_own_and_cloexec_is_shared",
      "abi::tests::the_tables_and_flags_equal_the_committed_vectors_generated_from_the_e03_oracle", "abi::tests::only_the_two_big_endian_musl_triples_name_an_abi",
      "layer::tests::a_backend_compiled_for_the_other_abi_is_refused_before_any_kernel_call", "layer::tests::a_triple_that_is_not_a_legacy_abi_is_refused_before_any_kernel_call",
      "numbers::tests::each_abi_gets_its_own_table_and_the_tables_differ_in_every_call", "numbers::tests::mips_numbers_are_four_thousand_based_and_powerpc_numbers_are_not",
      "numbers::tests::the_numbers_are_the_ones_the_audited_guest_probes_issued"]),
    ("P02-AC-STARTUP", "the device speaker takes clock, wakeup and entropy from the platform layer, not stand-ins: typed refusals, a simulated backend refused, one construction site each",
     ["platform_start::tests::the_default_selection_prints_no_provider_token_and_never_opens_the_legacy_device",
      "platform_start::tests::a_kernel_declaring_backend_starts_and_every_capability_reports_kernel",
      "platform_start::tests::a_device_build_wired_to_a_simulated_backend_is_refused_before_any_kernel_call",
      "platform_start::tests::a_kernel_backend_that_names_no_abi_is_refused_before_any_kernel_call",
      "platform_start::tests::a_wake_source_the_kernel_cannot_open_refuses_the_platform_on_its_typed_code",
      "platform_start::tests::an_unseeded_pool_is_a_retryable_refusal_and_is_never_answered_with_a_seeded_value",
      "platform_start::tests::every_refusal_code_has_one_safe_next_action_and_only_not_seeded_says_to_start_again",
      "platform_start::tests::a_refused_report_names_the_capability_the_reason_and_the_next_action_and_the_markers_stay_as_they_were",
      "platform_start::tests::the_speaker_builds_a_layer_and_the_backend_in_exactly_one_place_each",
      "platform_start::tests::every_reason_code_is_produced_by_some_error_and_belongs_to_its_capabilitys_closed_set",
      "platform_start::tests::the_committed_marker_examples_are_exactly_what_each_scenario_prints_and_the_reason_set_matches",
      *sorted(CLI_TESTS)]),
    ("P02-AC-MEMORY", "kernel allocation failure stays typed; memory admission preserves the safety floor, exact headroom and overflow refusal",
     ["socket::tests::kernel_allocation_failure_is_typed_without_retry_or_invented_descriptor",
      "tests::the_budget_edge_is_inclusive_and_the_refusal_carries_the_numbers_it_was_decided_on",
      "tests::extreme_nominal_ram_does_not_hide_overflow_or_a_small_deficit"]),
]
WALL_CASE = ("P02-AC-WALL-TIME", "wall-clock confidence kept apart from monotonic audio time: unknown until authenticated, replay and bad input never authenticate, large corrections and monotonic regression withdraw trust, credential validity needs the whole interval (every test of wall_clock.rs)")
LINUX_CASE = ("P02-AC-REAL-BACKEND", "real Linux syscalls behind the boundary: every test of the leaf (number tables per ABI, the socket plan and its routes, the host build with no backend)")
ALL_CASE = ("P02-RUST-ALL", "every test of P02's own files reported ok (franken-platform, franken-platform-linux, franken-speaker platform_start)")
PYTHON_CASE = ("P02-REF-PYTHON", "the existing host cross-checks of tests/p02 (errno and syscall numbers against the oracle, guest evidence, marker grammar, legacy provider, socket slice)")
META_CASE = ("P02-META-MAP", "every requirement names tests that exist, once in the whole workspace; the contract documents the accept/fcntl implications")
DOC_HEADINGS = {"P02-AC-ACCEPT-FCNTL": "## Accept and fcntl: concurrency implications"}


# ---- the Rust tests defined in P02's own files --------------------------------------------------------------------------------------------
MOD_OPEN = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*\{")
FN_NAME = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")


def test_functions(text: str) -> List[Tuple[str, Tuple[str, ...]]]:
    """Every `#[test]` function of one source file with the inline `mod x { ... }` blocks it sits in (tracked by brace depth)."""
    found: List[Tuple[str, Tuple[str, ...]]] = []
    stack: List[Tuple[str, int]] = []
    depth, armed = 0, False
    for line in text.splitlines():
        stripped = line.strip()
        opened = MOD_OPEN.match(stripped)
        if stripped.startswith("#[test]"):
            armed, stripped = True, stripped[len("#[test]"):].strip()
        if armed:
            named = FN_NAME.match(stripped)
            if named:
                found.append((named.group(1), tuple(n for n, _ in stack)))
                armed = False
        if opened:
            stack.append((opened.group(1), depth))
        depth += line.count("{") - line.count("}")
        while stack and depth <= stack[-1][1]:
            stack.pop()
    return found


def module_prefix(rel: str) -> str:
    """The libtest module path of a source file: `crates/x/src/lib.rs` and `main.rs` are the crate root (""), `src/a/b.rs` is `a::b`, `src/a/mod.rs` is
    `a`; a file outside `src` (an integration test) is its own crate root."""
    parts = rel.split("/")
    if "src" not in parts:
        return ""
    sub = parts[parts.index("src") + 1:]
    sub[-1] = sub[-1][:-3]
    if sub[-1] in ("lib", "main", "mod"):
        sub = sub[:-1]
    return "::".join(sub)


def tests_of(text: str, rel: str) -> List[str]:
    prefix = module_prefix(rel)
    return ["::".join(([prefix] if prefix else []) + list(inline) + [name]) for name, inline in test_functions(text)]


def own_tests(repo: str = REPO) -> Dict[str, List[str]]:
    """group -> the libtest names its files define."""
    out: Dict[str, List[str]] = {}
    for group, files in GROUPS.items():
        out[group] = []
        for rel in files:
            with open(os.path.join(repo, rel), encoding="utf-8") as handle:
                names = tests_of(handle.read(), rel)
                # The service-selection feature matrix in this integration file
                # belongs to P01. P02 owns these two default-host CLI cases.
                if rel.endswith("tests/cli_services.rs"):
                    names = [name for name in names if name in CLI_TESTS]
                out[group] += names
    return out


def workspace_definitions(repo: str = REPO) -> Dict[str, List[str]]:
    """libtest name -> the files of the whole workspace (`crates/**/*.rs`) that define it: a combined cargo log cannot tell two such tests apart."""
    seen: Dict[str, List[str]] = {}
    for path in sorted(glob.glob(os.path.join(repo, "crates", "**", "*.rs"), recursive=True)):
        rel = os.path.relpath(path, repo).replace(os.sep, "/")
        try:
            with open(path, encoding="utf-8") as handle:
                names = tests_of(handle.read(), rel)
        except (OSError, UnicodeDecodeError):
            continue
        for name in names:
            seen.setdefault(name, []).append(rel)
    return seen


# ---- the cargo log, read the way libtest writes it -----------------------------------------------------------------------------------
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TEST_START = re.compile(r"^test (\S+) \.\.\. ?(.*)$")
RESULT_WORD = re.compile(r"^(ok|FAILED|ignored)\b")
SUMMARY = re.compile(r"^test result: ")
PANIC = re.compile(r"thread '([^']+)'(?: \(\d+\))? panicked at (.*)$")
MAX_PANIC_LINES, MAX_PANIC_CHARS = 6, 240


class Logs:
    """The retained ``cargo test -- --nocapture`` log(s). libtest writes ``test NAME ... `` and, when the test ends, its result word, from one
    thread while other tests print from theirs, so the word may sit alone on a later line: it belongs to the one open name. A name that never
    gets its word is ``unterminated`` and never a pass; two different results for one test are ``conflict``, in either log order."""

    def __init__(self) -> None:
        self.files: List[Tuple[str, str]] = []
        self.results: Dict[str, List[str]] = {}
        self.unterminated: List[str] = []
        self.summaries = 0
        self.panics: Dict[str, List[str]] = {}

    def add(self, path: str) -> None:
        with open(path, "rb") as handle:
            raw = handle.read()
        self.files.append((path, hashlib.sha256(raw).hexdigest()))
        self.add_text(raw.decode("utf-8", errors="replace"))

    def add_text(self, text: str) -> None:
        pending: Optional[str] = None
        panic: Optional[List[Any]] = None
        for raw in text.splitlines():
            line = ANSI.sub("", raw)
            started = TEST_START.match(line)
            if started:
                if pending is not None:
                    self.unterminated.append(pending)
                    pending = None
                name, rest = started.groups()
                word = RESULT_WORD.match(rest.strip())
                if word:
                    self.results.setdefault(name, []).append(word.group(1))
                else:
                    pending = name
            elif pending is not None and line.strip() in ("ok", "FAILED", "ignored"):
                self.results.setdefault(pending, []).append(line.strip())
                pending = None
            if SUMMARY.match(line):
                self.summaries += 1
            found = PANIC.search(line)
            if found:
                where = found.group(2).strip()
                panic = [found.group(1), MAX_PANIC_LINES]
                self.panics.setdefault(panic[0], [where[:MAX_PANIC_CHARS]] if where else [])
            elif panic is not None:
                body = line.strip()
                if panic[1] <= 0 or not body or body.startswith("note:") or TEST_START.match(line) or body in ("ok", "FAILED", "ignored"):
                    panic = None
                else:
                    self.panics[panic[0]].append(body[:MAX_PANIC_CHARS])
                    panic[1] -= 1
        if pending is not None:
            self.unterminated.append(pending)

    def status(self, name: str) -> Optional[str]:
        seen = self.results.get(name)
        if not seen:
            return None
        return seen[0] if len(set(seen)) == 1 else "conflict"


# ---- cases ---------------------------------------------------------------------------------------------------------------------------
def safe_detail(text: str) -> str:
    """Use the existing Q00 policy before any human/receipt output, not only JSONL."""
    try:
        return load_case_log().load(REPO).redact_text(text)
    except Exception:
        # An unavailable sanitizer must never release raw external diagnostics.
        return "Diagnostic detail withheld: redaction is unavailable."


class Result:
    def __init__(self, case_id: str, status: str, detail: str = "", group: str = ""):
        self.case_id, self.status, self.detail, self.group = case_id, status, safe_detail(detail) if detail else "", group

    def as_dict(self) -> dict:
        return {"case": self.case_id, "status": self.status, "detail": self.detail, "group": self.group}


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


Runner = Callable[[List[str], str, int], Tuple[int, str]]


def run_process(argv: List[str], cwd: str, timeout: int) -> Tuple[int, str]:
    """(exit code, stdout+stderr), bounded in time; a timeout is exit 124 with a sentence, never a hang."""
    try:
        done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout} s"
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def tail(text: str, limit: int = 400) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else "..." + text[-limit:]


def unit_modules() -> List[str]:
    """The Python test modules of tests/p02 except this runner's own (which would run the runner)."""
    return sorted(os.path.basename(p)[:-3] for p in glob.glob(os.path.join(HERE, "test_*.py")) if os.path.basename(p) != "test_run_cases.py")


def python_case(runner: Runner) -> Result:
    modules = unit_modules()
    code, out = runner([sys.executable, "-B", "-m", "unittest"] + modules, HERE, UNIT_TIMEOUT_S)
    ran = re.search(r"Ran (\d+) tests?", out)
    if code == 0 and ran and int(ran.group(1)) > 0:
        return Result(PYTHON_CASE[0], "passed", "", "python")
    return Result(PYTHON_CASE[0], "failed", "unittest of %d module(s) exit %d%s: %s" % (len(modules), code, (", ran " + ran.group(1)) if ran else ", ran nothing", tail(out)), "python")


def judge_names(case_id: str, group: str, names: List[str], logs: Optional[Logs]) -> Result:
    """FAILED, ignored or contradictory -> failed (with the first causal event); anything unreported -> blocked; else passed."""
    if logs is None:
        return Result(case_id, "blocked", "no retained cargo log supplied (--judge LOG)", group)
    failed = [n for n in names if logs.status(n) in ("FAILED", "ignored", "conflict")]
    if failed:
        first = failed[0]
        state = logs.status(first)
        why = ("reported conflicting results by the logs" if state == "conflict"
               else "reported ignored (a required test is switched off)" if state == "ignored" else "cargo reported FAILED")
        cause = logs.panics.get(first)
        extra = "; first causal event: " + " | ".join(cause[:MAX_PANIC_LINES]) if cause else ""
        more = " (+%d more)" % (len(failed) - 1) if len(failed) > 1 else ""
        return Result(case_id, "failed", "test %s %s%s%s" % (first, why, more, extra), group)
    missing = [n for n in names if logs.status(n) != "ok"]
    if missing:
        cut = "; the log has no `test result:` line, so the run was cut off or never reached the end" if logs.summaries == 0 else ""
        unfinished = [n for n in missing if n in logs.unterminated]
        why = "not reported ok in the supplied logs (%d of %d)" % (len(missing), len(names)) + (", %d with a name and no result" % len(unfinished) if unfinished else "")
        return Result(case_id, "blocked", "%s: %s%s" % (why, ", ".join(missing[:3]) + (" ..." if len(missing) > 3 else ""), cut), group)
    return Result(case_id, "passed", "", group)


def case_plan(repo: str = REPO) -> Tuple[List[Tuple[str, str, List[str]]], Dict[str, List[str]]]:
    """The Rust-backed cases (id, description, required names) and the tests P02's own files define."""
    groups = own_tests(repo)
    every = [n for g in ("platform", "linux", "speaker") for n in groups[g]]
    plan = [(i, d, list(n)) for i, d, n in REQUIREMENTS]
    plan.append((WALL_CASE[0], WALL_CASE[1], [n for n in groups["platform"] if n.startswith("wall_clock::")]))
    plan.append((LINUX_CASE[0], LINUX_CASE[1], list(groups["linux"])))
    plan.append((ALL_CASE[0], ALL_CASE[1], every))
    return plan, groups


def meta_map(plan: List[Tuple[str, str, List[str]]], groups: Dict[str, List[str]], repo: str = REPO,
             workspace: Optional[Dict[str, List[str]]] = None) -> Result:
    defined = {n for names in groups.values() for n in names}
    problems: List[str] = []
    for case_id, _desc, names in plan:
        if not names:
            problems.append("%s names no test" % case_id)
        gone = sorted(set(names) - defined)
        if gone:
            problems.append("%s names tests that are not in P02's files: %s" % (case_id, ", ".join(gone[:3])))
        dup = sorted({n for n in names if names.count(n) > 1})
        if dup:
            problems.append("%s lists %s twice" % (case_id, dup[0]))
    for case_id in ("P02-AC-ENTROPY", "P02-AC-NO-FAKE-SUCCESS", "P02-AC-ABSENT", "P02-AC-EINTR", "P02-AC-ACCEPT-FCNTL", "P02-AC-WALL-TIME"):
        if case_id not in {i for i, _d, _n in plan}:
            problems.append("the acceptance requirement %s has no case" % case_id)  # the bead's four named criteria and its documentation duty
    workspace = workspace if workspace is not None else workspace_definitions(repo)
    ambiguous = sorted(n for n in defined if len(workspace.get(n, [])) > 1)
    if ambiguous:  # a libtest name defined twice in the workspace could not be told apart in a combined log
        problems.append("%s is defined in more than one file of the workspace (%s)" % (ambiguous[0], ", ".join(workspace[ambiguous[0]][:2])))
    try:
        with open(os.path.join(repo, CONTRACT), encoding="utf-8") as handle:
            contract = handle.read()
    except OSError:
        contract = ""
        problems.append("%s cannot be read" % CONTRACT)
    for case_id, heading in DOC_HEADINGS.items():
        if contract and not any(line.startswith(heading) for line in contract.splitlines()):
            problems.append("%s: %s has no section %r" % (case_id, CONTRACT, heading[3:]))
    return Result(META_CASE[0], "failed" if problems else "passed", "; ".join(problems[:3]), "meta")


def run(tier: str, logs: Optional[Logs], runner: Optional[Runner] = None, repo: str = REPO) -> Tuple[List[Result], dict]:
    if tier not in RUN_TIERS:
        raise ValueError("tier %r judges nothing (the soak tier is not run)" % tier)
    runner = runner or run_process  # looked up at call time, so a test can replace it
    plan, groups = case_plan(repo)
    results = [meta_map(plan, groups, repo), python_case(runner)]
    if tier == "full":
        for case_id, _desc, names in plan:
            results.append(judge_names(case_id, "rust", names, logs))
    return results, {"planned": len(results), "rust_tests_required": len(next(n for i, _d, n in plan if i == ALL_CASE[0]))}


def planned_ids(tier: str) -> List[str]:
    plan, _groups = case_plan()
    return [META_CASE[0], PYTHON_CASE[0]] + ([i for i, _d, _n in plan] if tier == "full" else [])


def descriptions() -> Dict[str, str]:
    out = {META_CASE[0]: META_CASE[1], PYTHON_CASE[0]: PYTHON_CASE[1]}
    for case_id, desc, _names in REQUIREMENTS + [(WALL_CASE[0], WALL_CASE[1], []), (LINUX_CASE[0], LINUX_CASE[1], []), (ALL_CASE[0], ALL_CASE[1], [])]:
        out[case_id] = desc
    return out


# ---- reporting -----------------------------------------------------------------------------------------------------------------------
def summarize(results: List[Result]) -> Dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in ("passed", "failed", "blocked")}


def exit_code(results: List[Result]) -> int:
    counts = summarize(results)
    return 1 if counts["failed"] else 3 if counts["blocked"] else 0


def final_exit(results: List[Result], evidence: Optional[Any]) -> int:
    """The cases' exit code, except that a pass cannot rest on a diagnostic log that lost critical evidence."""
    code = exit_code(results)
    return 1 if code == 0 and evidence is not None and not evidence.complete else code


def artifact_digests() -> Dict[str, str]:
    return {rel: (sha256_file(os.path.join(REPO, rel)) if os.path.isfile(os.path.join(REPO, rel)) else "missing") for rel in JUDGED_ARTIFACTS}


def artifact_set_digest(digests: Dict[str, str]) -> str:
    return hashlib.sha256("".join("%s %s\n" % (rel, d) for rel, d in sorted(digests.items())).encode("utf-8")).hexdigest()


def versions() -> Dict[str, Any]:
    return {"python": platform.python_version(), "receipt_schema": RECEIPT_SCHEMA}


def replay_log_name(path: str, digest: Optional[str] = None) -> str:
    relative = os.path.relpath(os.path.realpath(path), REPO)
    if relative != os.pardir and not relative.startswith(os.pardir + os.sep):
        return relative
    # External artifacts are named by basename+digest without disclosing their
    # private location. retained_lines states the setup needed before replay.
    return "p02-log-%s.txt" % digest if digest is not None else os.path.basename(path)


def replay_command(tier: str, logs: Optional[Logs]) -> str:
    names = [replay_log_name(path, digest) for path, digest in logs.files] if logs else []
    return "scripts/e2e/p02 --tier %s" % tier + (" --judge " + " ".join(shlex.quote(n) for n in names) if names else "")


def retained_lines(results: List[Result], tier: str, logs: Optional[Logs], meta: dict) -> List[str]:
    bad = [r for r in results if r.status == "failed"] or [r for r in results if r.status == "blocked"]
    if not bad:
        return []
    first = bad[0]
    lines = ["RETAINED FOR REPLAY. First %s case: %s: %s" % (first.status, first.case_id, first.detail), "  replay: " + replay_command(tier, logs)]
    for path, digest in (logs.files if logs else []):
        replay_name = replay_log_name(path, digest)
        lines.append("  judged log %s sha256 %s" % (replay_name, digest))
        if replay_name.startswith("p02-log-"):
            lines.append("  replay setup: place the retained log with this digest in the checkout root as " + replay_name)
    v = meta["versions"]
    lines.append("  versions: python %s; receipt %s" % (v["python"], v["receipt_schema"]))
    for rel, digest in meta["artifacts"].items():
        lines.append("  artifact %s sha256 %s" % (rel, digest))
    return lines


def report(results: List[Result], tier: str, logs: Optional[Logs] = None, meta: Optional[dict] = None, evidence: Optional[Any] = None) -> None:
    counts = summarize(results)
    for status, label in (("failed", "FAIL"), ("blocked", "BLOCKED")):
        rows = [r for r in results if r.status == status]
        for r in rows[:MAX_PRINTED]:
            print("%-8s %s  %s" % (label, r.case_id, r.detail))
        if len(rows) > MAX_PRINTED:
            print("%-8s ... and %d more %s case(s)" % (label, len(rows) - MAX_PRINTED, status))
    for r in results:
        if r.status == "passed" and r.detail:
            print("%-8s %s  %s" % ("NOTE", r.case_id, r.detail))
    if meta is not None:
        for line in retained_lines(results, tier, logs, meta):
            print(line)
    verdict = "QUALIFIED" if final_exit(results, evidence) == 0 else "NOT QUALIFIED"
    note = ""
    if evidence is not None:
        print(evidence.summary)
        if not evidence.complete:
            note = "  [diagnostic evidence INCOMPLETE: " + ", ".join(evidence.reasons) + "]"
    print("P02 e2e tier=%s: %s  planned=%d passed=%d failed=%d blocked=%d%s" % (tier, verdict, len(results), counts["passed"], counts["failed"], counts["blocked"], note))


def write_receipt(directory: str, tier: str, results: List[Result], meta: dict, logs: Optional[Logs], run_id: str, evidence: Optional[Any]) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "p02-%s.json" % run_id)
    doc = {"schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": tier,
           "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "counts": summarize(results), "exit_code": final_exit(results, evidence),
           "judged_logs": [{"path": replay_log_name(p, h), "sha256": h} for p, h in (logs.files if logs else [])],
           "replay": replay_command(tier, logs), **meta, "results": [r.as_dict() for r in results]}
    if evidence is not None:
        doc["diagnostics"] = {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log,
                              "file": os.path.basename(evidence.path) if evidence.path else None}
    with open(path, "x", encoding="utf-8") as handle:  # never overwrites an earlier run's receipt
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def load_case_log() -> Any:
    sys.path.insert(0, HERE)
    import case_log  # noqa: PLC0415 - loaded by name from this directory
    return case_log


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="P02 tiered runner and judge (ffw-jub)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--list", action="store_true", help="list the planned case ids of the tier and exit")
    parser.add_argument("--judge", nargs="+", metavar="LOG", help="retained `cargo test -- --nocapture` output file(s) to judge")
    parser.add_argument("--receipts", metavar="DIR", help="write a JSON receipt and the JSONL diagnostic log here")
    args = parser.parse_args(argv)

    if args.tier not in RUN_TIERS:
        print(SOAK_NOT_RUN)
        return SOAK_EXIT
    logs: Optional[Logs] = None
    if args.judge:
        logs = Logs()
        for path in args.judge:
            if not os.path.isfile(path):
                print("error: log not found: %s" % path, file=sys.stderr)
                return 2
            logs.add(path)
    if args.list:
        text = descriptions()
        for case_id in planned_ids(args.tier):
            print("%-24s %s" % (case_id, text[case_id]))
        return 0
    results, meta = run(args.tier, logs)
    meta["versions"] = versions()
    meta["artifacts"] = artifact_digests()
    case_log = load_case_log()
    run_id = secrets.token_hex(8)
    log = case_log.CaseLog.open(REPO, run_id, args.tier, args.receipts, header_extra={
        "python": meta["versions"]["python"], "tier": args.tier, "artifact_count": len(meta["artifacts"]),
        "artifact_set_sha256": artifact_set_digest(meta["artifacts"])})
    for r in results:
        log.record(r.case_id, r.group, r.status, r.detail)
    evidence = log.finish(summarize(results))
    report(results, args.tier, logs, meta, evidence)
    if evidence.path and not args.receipts:
        print("diagnostic log kept:", evidence.path)
    code = final_exit(results, evidence)
    if args.receipts:
        try:
            print("receipt:", write_receipt(args.receipts, args.tier, results, meta, logs, run_id, evidence))
        except OSError as err:
            print("error: the receipt could not be written under %s: %s" % (args.receipts, type(err).__name__), file=sys.stderr)
            return code or 1
    return code


if __name__ == "__main__":
    sys.exit(main())
