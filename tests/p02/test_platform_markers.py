#!/usr/bin/env python3
"""P02 (ffw-jub): the FFW_PLATFORM:* markers `franken-speaker --platform-startup` prints, and a reference judge for them.

`crates/franken-speaker/tests/vectors/p02_platform_markers.json` pins example outputs; the Rust unit tests in `platform_start.rs`
hold the speaker to them. This file holds the examples to the grammar and defines `judge` / `judge_for_guest`, the reference check a
QEMU speaker-smoke runner can adopt (the runner is DarkPeak's; names and shape are agreed with them, see the P02 contract). Planted
faults (a simulated provenance on a PASS line, a missing or reordered line, an unknown reason, a contradictory END) must each be
reported, so a judge that passes everything cannot pass here. Offline, stdlib only.

`BEGIN` records `kernel=<running release>`: 1 to 64 bytes of [A-Za-z0-9._+-], or the literal `invalid`. It is evidence of which kernel
answered. It is never compared and never a reason to refuse, so no verdict here depends on its value (a test substitutes values and
requires the same verdict). The file also pins the construction rule: `platform_start::bring_up_device` is the only place in the
speaker crate that builds a platform layer or the Linux backend, so every start, `--platform-startup` included, goes through it.

`judge_for_guest` encodes the E03-derived expectation: on PowerPC (getrandom seeded in run 1412ac47) every capability passes; on MIPS
(getrandom UNSEEDED there) entropy may pass or be refused with reason not_seeded, and nothing else may be refused.
"""
import json
import os
import re
import unittest

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
VECTORS = os.path.join(ROOT, "crates", "franken-speaker", "tests", "vectors", "p02_platform_markers.json")
SPEAKER_RS = os.path.join(ROOT, "crates", "franken-speaker", "src", "platform_start.rs")

STATUS = r"(PASS|REFUSED|NOT_RUN)"
REASON = r"(?: reason=([a-z_]+))?"
PROV = r"(kernel|simulated|none)"
LINE_RES = {
    "BEGIN": re.compile(r"^FFW_PLATFORM:BEGIN abi=(mips32|powerpc32|none) evidence=(harness-mips-4\.19|harness-ppc-4\.9|none) backend=(kernel|simulated) kernel=([A-Za-z0-9._+-]{1,64})$"),
    "KERNEL": re.compile(r"^FFW_PLATFORM:KERNEL status=%s%s$" % (STATUS, REASON)),
    "CLOCK": re.compile(r"^FFW_PLATFORM:CLOCK status=%s provenance=%s%s$" % (STATUS, PROV, REASON)),
    "ENTROPY": re.compile(r"^FFW_PLATFORM:ENTROPY status=%s provenance=%s%s$" % (STATUS, PROV, REASON)),
    "WAKE": re.compile(r"^FFW_PLATFORM:WAKE status=%s provenance=%s mechanism=(eventfd|self_pipe|none)%s$" % (STATUS, PROV, REASON)),
    "END": re.compile(r"^FFW_PLATFORM:END started=(1|0)(?: refused=(kernel|clock|entropy|wake):([a-z_]+))?$"),
}
ORDER = ["BEGIN", "KERNEL", "CLOCK", "ENTROPY", "WAKE", "END"]
CAPABILITIES = ["kernel", "clock", "entropy", "wake"]


def load_vectors():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def parse(lines):
    """({name: groups}, problems) for six marker lines; groups come from LINE_RES."""
    problems = []
    if len(lines) != 6:
        problems.append("expected 6 lines, got %d" % len(lines))
    parsed = {}
    for name, line in zip(ORDER, lines):
        match = LINE_RES[name].match(line)
        if not match:
            problems.append("line %s does not match the grammar: %r" % (name, line))
        else:
            parsed[name] = match.groups()
    return parsed, problems


def judge(lines, reasons):
    """Problems with one platform-startup output (empty list = well formed and self-consistent). `reasons` is the closed reason map."""
    parsed, problems = parse(lines)
    if problems:
        return problems
    backend = parsed["BEGIN"][2]
    outcomes = {
        "kernel": (parsed["KERNEL"][0], parsed["KERNEL"][1], None),
        "clock": (parsed["CLOCK"][0], parsed["CLOCK"][2], parsed["CLOCK"][1]),
        "entropy": (parsed["ENTROPY"][0], parsed["ENTROPY"][2], parsed["ENTROPY"][1]),
        "wake": (parsed["WAKE"][0], parsed["WAKE"][3], parsed["WAKE"][1]),
    }
    for name, (status, reason, provenance) in outcomes.items():
        if (status == "REFUSED") != (reason is not None):
            problems.append("%s: a reason goes with REFUSED and only with REFUSED" % name)
        if reason is not None and reason not in reasons.get(name, []):
            problems.append("%s: reason %r is not in the closed set" % (name, reason))
        if provenance is not None:
            if status == "PASS" and provenance != "kernel":
                problems.append("%s: a PASS with provenance=%s (only kernel is acceptable)" % (name, provenance))
            if status == "NOT_RUN" and provenance not in ("none",):
                problems.append("%s: NOT_RUN with provenance=%s" % (name, provenance))
            if status == "REFUSED" and provenance != "kernel":
                # a capability can only be refused after the layer exists, and a simulated backend is refused at KERNEL before any layer
                problems.append("%s: a REFUSED capability line must carry provenance=kernel, got provenance=%s" % (name, provenance))
    if backend == "simulated" and outcomes["kernel"][0] != "REFUSED":
        problems.append("a simulated backend must be refused at KERNEL")
    first = next(((n, outcomes[n][1]) for n in CAPABILITIES if outcomes[n][0] == "REFUSED"), None)
    started, refused_cap, refused_code = parsed["END"]
    all_pass = all(outcomes[n][0] == "PASS" for n in CAPABILITIES)
    if started == "1":
        if not all_pass or first is not None or refused_cap is not None:
            problems.append("END started=1 but a capability did not pass")
    else:
        if all_pass:
            problems.append("END started=0 but every capability passed")
        if first is not None and (refused_cap, refused_code) != first:
            problems.append("END refused=%s:%s but the first refusal is %s:%s" % (refused_cap, refused_code, first[0], first[1]))
        if first is None and refused_cap is not None:
            problems.append("END names a refusal that no line shows")
    if outcomes["kernel"][0] != "PASS":
        later = [n for n in ("clock", "entropy", "wake") if outcomes[n][0] != "NOT_RUN"]
        if later:
            problems.append("KERNEL did not pass but %s ran" % later)
    refused_before = False
    for name in CAPABILITIES:
        status = outcomes[name][0]
        if status == "NOT_RUN" and not refused_before:
            problems.append("%s is NOT_RUN but no earlier line is REFUSED to explain it" % name)
        refused_before = refused_before or status == "REFUSED"
    return problems


def judge_for_guest(lines, guest, reasons):
    """`judge`, plus the E03-derived expectation for a harness guest ('ppc' or 'mips'): the outcomes a healthy guest may show."""
    problems = judge(lines, reasons)
    if problems:
        return problems
    parsed, _ = parse(lines)
    if (parsed["BEGIN"][0], parsed["BEGIN"][1], parsed["BEGIN"][2]) != {
        "ppc": ("powerpc32", "harness-ppc-4.9", "kernel"),
        "mips": ("mips32", "harness-mips-4.19", "kernel"),
    }[guest]:
        problems.append("BEGIN names the wrong ABI, evidence or backend for the %s guest" % guest)
    for name in ("KERNEL", "CLOCK", "WAKE"):
        if parsed[name][0] != "PASS":
            problems.append("%s must PASS on a healthy %s guest, got %s" % (name, guest, parsed[name][0]))
    entropy = parsed["ENTROPY"]
    if guest == "ppc":
        if entropy[0] != "PASS":
            problems.append("ENTROPY must PASS on the ppc guest (getrandom was seeded in run 1412ac47)")
    elif not (entropy[0] == "PASS" or (entropy[0] == "REFUSED" and entropy[2] == "not_seeded")):       # (status, provenance, reason)
        problems.append("ENTROPY on the mips guest must PASS or be REFUSED with reason=not_seeded")
    return problems


class GrammarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()
        cls.reasons = cls.vectors["reason_codes"]

    def test_every_committed_example_is_well_formed_and_self_consistent(self):
        for name, example in self.vectors["examples"].items():
            self.assertEqual(judge(example["lines"], self.reasons), [], name)
            started = example["lines"][-1].startswith("FFW_PLATFORM:END started=1")
            self.assertEqual(example["exit"], 0 if started else 3, name)

    def test_the_examples_cover_a_pass_a_typed_refusal_a_simulated_backend_and_a_stock_kernel_per_guest_shape(self):
        examples = self.vectors["examples"]
        self.assertEqual(sorted(examples), sorted([
            "powerpc_all_pass", "mips_all_pass", "mips_entropy_not_seeded", "simulated_backend_refused",
            "stock_kernel_release_recorded_not_refused", "unreadable_kernel_release_recorded_as_invalid",
            "wake_source_absent_powerpc", "clock_absent_powerpc", "wake_not_observed_powerpc"]))

    def test_the_reason_sets_in_the_vector_file_are_the_ones_in_the_rust_source(self):
        with open(SPEAKER_RS, encoding="utf-8") as fh:
            source = fh.read()
        block = source[source.index("pub const REASON_CODES"):source.index("/// What startup checks.")]
        for capability, codes in self.reasons.items():
            section = re.search(r'\(\s*"%s",\s*&\[(.*?)\],\s*\)' % capability, block, re.S)
            self.assertIsNotNone(section, capability)
            self.assertEqual(re.findall(r'"([a-z_]+)"', section.group(1)), codes, capability)

    def test_no_reason_code_names_the_kernel_release(self):
        # The speaker never refuses on the running kernel's release, so no closed-set code can say it did.
        for capability, codes in self.reasons.items():
            for code in codes:
                self.assertNotIn("release", code, "%s:%s" % (capability, code))
                self.assertNotIn("mismatch", code.replace("abi_mismatch", ""), "%s:%s" % (capability, code))

    def test_the_kernel_field_never_changes_the_verdict(self):
        # Same output, different kernel= value (a stock kernel, the other harness kernel, the literal invalid, the longest legal
        # value): the judge's answer is identical. The field is recorded, never compared.
        for name, example in self.vectors["examples"].items():
            baseline = judge(example["lines"], self.reasons)
            for value in ("2.6.14.7", "4.19.0-21-4kc-malta", "4.9.0-0.bpo.6-powerpc", "invalid", "x" * 64, "a+b_c-1.2"):
                lines = list(example["lines"])
                lines[0] = re.sub(r" kernel=\S+$", " kernel=" + value, lines[0])
                self.assertEqual(judge(lines, self.reasons), baseline, "%s kernel=%s" % (name, value))
                guest = "mips" if "mips" in name else "ppc"
                if name in ("powerpc_all_pass", "mips_all_pass", "mips_entropy_not_seeded"):
                    self.assertEqual(judge_for_guest(lines, guest, self.reasons),
                                     judge_for_guest(example["lines"], guest, self.reasons), "%s kernel=%s" % (name, value))

    def test_no_example_prints_a_value_only_statuses_and_fixed_names(self):
        for name, example in self.vectors["examples"].items():
            for line in example["lines"]:
                self.assertNotRegex(line, r"(ns|bytes|value|seed|rand)=", "%s: %s" % (name, line))


class GuestJudgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()
        cls.reasons = cls.vectors["reason_codes"]

    def lines(self, name):
        return list(self.vectors["examples"][name]["lines"])

    def test_the_healthy_outcomes_pass_the_guest_judge(self):
        self.assertEqual(judge_for_guest(self.lines("powerpc_all_pass"), "ppc", self.reasons), [])
        self.assertEqual(judge_for_guest(self.lines("mips_all_pass"), "mips", self.reasons), [])
        # E03's MIPS pool was unseeded at PID-1 boot: a refusal with reason not_seeded is the honest, degraded outcome there.
        self.assertEqual(judge_for_guest(self.lines("mips_entropy_not_seeded"), "mips", self.reasons), [])

    def test_everything_else_fails_the_guest_judge(self):
        for name, guest in (
            ("simulated_backend_refused", "ppc"), ("wake_source_absent_powerpc", "ppc"), ("clock_absent_powerpc", "ppc"),
            ("wake_not_observed_powerpc", "ppc"), ("mips_entropy_not_seeded", "ppc"), ("powerpc_all_pass", "mips"),
        ):
            self.assertNotEqual(judge_for_guest(self.lines(name), guest, self.reasons), [], "%s as %s" % (name, guest))

    def test_a_stock_or_unreadable_kernel_release_on_a_healthy_guest_is_not_a_failure(self):
        # The ppc ABI with a release the harness never ran: the speaker recorded it and started, so the judge agrees.
        for name in ("stock_kernel_release_recorded_not_refused", "unreadable_kernel_release_recorded_as_invalid"):
            self.assertEqual(judge_for_guest(self.lines(name), "ppc", self.reasons), [], name)

    def test_a_non_not_seeded_entropy_refusal_on_mips_is_not_excused(self):
        lines = self.lines("mips_entropy_not_seeded")
        lines[3] = lines[3].replace("reason=not_seeded", "reason=absent")
        lines[5] = lines[5].replace("entropy:not_seeded", "entropy:absent")
        self.assertEqual(judge(lines, self.reasons), [])                       # well formed...
        self.assertNotEqual(judge_for_guest(lines, "mips", self.reasons), [])  # ...but not an excused outcome


class PlantedFaultTests(unittest.TestCase):
    """Each plant changes one healthy output in one way; the judge must report it."""

    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()
        cls.reasons = cls.vectors["reason_codes"]
        cls.healthy = list(cls.vectors["examples"]["powerpc_all_pass"]["lines"])

    def plant(self, edit):
        lines = list(self.healthy)
        edit(lines)
        return judge(lines, self.reasons)

    def test_the_unplanted_output_is_clean(self):
        self.assertEqual(judge(self.healthy, self.reasons), [])

    def test_each_plant_is_reported(self):
        plants = {
            "simulated provenance on a PASS": lambda l: l.__setitem__(2, l[2].replace("provenance=kernel", "provenance=simulated")),
            "no provenance on a PASS": lambda l: l.__setitem__(3, l[3].replace("provenance=kernel", "provenance=none")),
            "a missing line": lambda l: l.pop(3),
            "an extra line": lambda l: l.append("FFW_PLATFORM:END started=1"),
            "two lines swapped": lambda l: l.__setitem__(slice(2, 4), [l[3], l[2]]),
            "an unknown reason": lambda l: (l.__setitem__(3, "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=made_up"),
                                            l.__setitem__(5, "FFW_PLATFORM:END started=0 refused=entropy:made_up")),
            "a reason on a PASS": lambda l: l.__setitem__(2, l[2] + " reason=absent"),
            "a REFUSED without a reason": lambda l: l.__setitem__(2, "FFW_PLATFORM:CLOCK status=REFUSED provenance=kernel"),
            "started=1 with a refusal": lambda l: (l.__setitem__(3, "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=not_seeded")),
            "started=0 with every capability passing": lambda l: l.__setitem__(5, "FFW_PLATFORM:END started=0"),
            "END names another refusal": lambda l: (l.__setitem__(2, "FFW_PLATFORM:CLOCK status=REFUSED provenance=kernel reason=absent"),
                                                    l.__setitem__(5, "FFW_PLATFORM:END started=0 refused=entropy:absent")),
            "a simulated backend that was admitted": lambda l: l.__setitem__(0, l[0].replace("backend=kernel", "backend=simulated")),
            "capabilities ran after KERNEL was refused": lambda l: (l.__setitem__(1, "FFW_PLATFORM:KERNEL status=REFUSED reason=abi_mismatch"),
                                                                    l.__setitem__(5, "FFW_PLATFORM:END started=0 refused=kernel:abi_mismatch")),
            "a release-based refusal (not in the closed set)": lambda l: (l.__setitem__(1, "FFW_PLATFORM:KERNEL status=REFUSED reason=kernel_release_mismatch"),
                                                                           l.__setitem__(2, "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=none"),
                                                                           l.__setitem__(3, "FFW_PLATFORM:ENTROPY status=NOT_RUN provenance=none"),
                                                                           l.__setitem__(4, "FFW_PLATFORM:WAKE status=NOT_RUN provenance=none mechanism=none"),
                                                                           l.__setitem__(5, "FFW_PLATFORM:END started=0 refused=kernel:kernel_release_mismatch")),
            "a NOT_RUN that no earlier REFUSED explains": lambda l: (l.__setitem__(2, "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=none"),
                                                                     l.__setitem__(5, "FFW_PLATFORM:END started=0")),
            "a NOT_RUN placed before the REFUSED that explains it": lambda l: (l.__setitem__(2, "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=none"),
                                                                               l.__setitem__(4, "FFW_PLATFORM:WAKE status=REFUSED provenance=kernel mechanism=eventfd reason=sys"),
                                                                               l.__setitem__(5, "FFW_PLATFORM:END started=0 refused=wake:sys")),
            "BEGIN without kernel=": lambda l: l.__setitem__(0, re.sub(r" kernel=\S+$", "", l[0])),
            "kernel= empty": lambda l: l.__setitem__(0, re.sub(r" kernel=\S+$", " kernel=", l[0])),
            "kernel= longer than 64 bytes": lambda l: l.__setitem__(0, re.sub(r" kernel=\S+$", " kernel=" + "9" * 65, l[0])),
            "kernel= with a byte outside the charset": lambda l: l.__setitem__(0, re.sub(r" kernel=\S+$", " kernel=4.9;0", l[0])),
            "kernel= with a space (a second field)": lambda l: l.__setitem__(0, l[0] + " 2.6"),
            "kernel= non-ASCII": lambda l: l.__setitem__(0, re.sub(r" kernel=\S+$", " kernel=4.9\u00e9", l[0])),
            "trailing space": lambda l: l.__setitem__(1, l[1] + " "),
            "a lowercase status": lambda l: l.__setitem__(1, l[1].replace("PASS", "pass")),
            "a clock value leaked": lambda l: l.__setitem__(2, l[2] + " ns=123456"),
        }
        for name, edit in plants.items():
            self.assertNotEqual(self.plant(edit), [], name)


class RefusedLineProvenanceTests(unittest.TestCase):
    """A REFUSED capability line is always `provenance=kernel`: the layer exists by then (`simulated` is what a test double prints, red anywhere; `none` belongs to
    NOT_RUN lines only). DarkPeak's judge found this reference judge accepting both on `ENTROPY REFUSED` (their 4852). Each plant has its control: the unplanted line."""

    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()
        cls.reasons = cls.vectors["reason_codes"]
        cls.refused = [(name, index, line) for name, example in cls.vectors["examples"].items() for index, line in enumerate(example["lines"])
                       if index in (2, 3, 4) and " status=REFUSED " in line]

    def test_the_committed_examples_have_exactly_these_refused_capability_lines(self):
        self.assertEqual({(name, index) for name, index, _ in self.refused},
                         {("clock_absent_powerpc", 2), ("mips_entropy_not_seeded", 3), ("wake_not_observed_powerpc", 4)})

    def test_a_refused_capability_line_with_provenance_simulated_or_none_is_red_and_the_unplanted_line_is_green(self):
        for name, index, line in self.refused:
            example = self.vectors["examples"][name]
            self.assertIn("provenance=kernel", line, name)
            self.assertEqual(judge(example["lines"], self.reasons), [], "%s: the unplanted example must be clean" % name)             # the control
            for bad in ("simulated", "none"):
                lines = list(example["lines"])
                lines[index] = line.replace("provenance=kernel", "provenance=" + bad)
                self.assertNotEqual(lines[index], line)
                problems = judge(lines, self.reasons)
                self.assertTrue(any("a REFUSED capability line must carry provenance=kernel, got provenance=" + bad in p for p in problems), (name, bad, problems))
                self.assertEqual(len(problems), 1, (name, bad, problems))         # only that fault, not a side effect of the plant

    def test_the_mips_degraded_outcome_is_accepted_only_with_provenance_kernel(self):
        lines = list(self.vectors["examples"]["mips_entropy_not_seeded"]["lines"])
        self.assertEqual(judge_for_guest(lines, "mips", self.reasons), [])                   # the permitted positive: degraded, kernel
        for bad in ("simulated", "none"):
            planted = list(lines)
            planted[3] = planted[3].replace("provenance=kernel", "provenance=" + bad)
            self.assertNotEqual(judge_for_guest(planted, "mips", self.reasons), [], bad)


SPEAKER_SRC = os.path.join(ROOT, "crates", "franken-speaker", "src")
SPEAKER_TESTS = os.path.join(ROOT, "crates", "franken-speaker", "tests")
BUILDS_A_LAYER = re.compile(r"PlatformLayer\s*::\s*admit\s*\(")
BUILDS_THE_BACKEND = re.compile(r"LinuxKernel\s*::\s*new\s*\(|LinuxKernel\s*\{|\bLinuxKernel\s*::\s*default\s*\(")


def speaker_sources():
    """(relative path, text) of every .rs file in the speaker crate's src/ and tests/."""
    found = []
    for base in (SPEAKER_SRC, SPEAKER_TESTS):
        for dirpath, _, names in os.walk(base):
            for name in sorted(names):
                if name.endswith(".rs"):
                    path = os.path.join(dirpath, name)
                    with open(path, encoding="utf-8") as fh:
                        found.append((os.path.relpath(path, ROOT), fh.read()))
    return found


def code_outside_comments(text):
    """The text with `//` comments (including doc comments) removed, so prose cannot count as a construction site."""
    return "\n".join(re.sub(r"//.*$", "", line) for line in text.splitlines())


def production_part(text):
    """platform_start.rs up to its `#[cfg(test)]` module."""
    return text.split("#[cfg(test)]", 1)[0]


def construction_sites(sources):
    """[(path, kind)] for every place the given sources build a layer or the Linux backend; platform_start.rs counts only before its tests."""
    sites = []
    for path, text in sources:
        code = code_outside_comments(production_part(text) if path.endswith("src/platform_start.rs") else text)
        sites += [(path, "layer") for _ in BUILDS_A_LAYER.finditer(code)]
        sites += [(path, "backend") for _ in BUILDS_THE_BACKEND.finditer(code)]
    return sites


class OneConstructionSiteTests(unittest.TestCase):
    """Normal startup and `--platform-startup` are the same path: the speaker builds a layer in exactly one function."""

    def test_the_speaker_builds_a_layer_and_the_backend_in_exactly_one_place_each(self):
        sites = construction_sites(speaker_sources())
        self.assertEqual(sorted(sites), [("crates/franken-speaker/src/platform_start.rs", "backend"),
                                          ("crates/franken-speaker/src/platform_start.rs", "layer")], sites)

    def test_the_callers_name_neither_the_backend_crate_nor_a_simulation(self):
        for path, text in speaker_sources():
            if path.endswith("src/platform_start.rs"):
                continue
            code = code_outside_comments(text)
            self.assertNotIn("franken_platform_linux", code, path)
            self.assertNotIn("SeededSim", code, path)
            self.assertNotIn("ScriptedOps", code, path)

    def test_main_reaches_the_layer_only_through_check_device(self):
        with open(os.path.join(SPEAKER_SRC, "main.rs"), encoding="utf-8") as fh:
            code = code_outside_comments(fh.read())
        self.assertIn("platform_start::check_device()", code)
        self.assertNotIn("bring_up", code)       # it does not assemble a start itself
        self.assertNotIn("PlatformLayer", code)

    def test_the_construction_pin_catches_a_second_site(self):
        base = speaker_sources()
        plants = {
            "a second layer in main.rs": ("crates/franken-speaker/src/main.rs", "let l = PlatformLayer::admit(&m, ops);"),
            "a second backend in main.rs": ("crates/franken-speaker/src/main.rs", "let b = franken_platform_linux::LinuxKernel::new();"),
            "a backend built by struct literal": ("crates/franken-speaker/src/lib.rs", "let b = LinuxKernel {};"),
            "a layer built in an integration test": ("crates/franken-speaker/tests/x.rs", "let l = PlatformLayer :: admit (&m, ops);"),
        }
        for name, (path, line) in plants.items():
            planted = [(p, t + "\n" + line if p == path else t) for p, t in base]
            if not any(p == path for p, _ in base):
                planted.append((path, line))
            self.assertGreater(len(construction_sites(planted)), 2, name)
        # A comment that merely mentions the call is not a site.
        prose = [(p, t + "\n// PlatformLayer::admit(...) is called once, in bring_up" if p.endswith("main.rs") else t) for p, t in base]
        self.assertEqual(len(construction_sites(prose)), 2)


if __name__ == "__main__":
    unittest.main()
