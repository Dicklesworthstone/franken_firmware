#!/usr/bin/env python3
"""P02 (ffw-jub): the explicitly selected legacy `/dev/random` entropy provider (root decision 5126, `ffw-jub` comment 205), held on the host.

What this file pins, and what it does not:
* the legacy marker examples (`p02_legacy_entropy_markers.json`) are well formed under the reference judge, use only the closed reason
  set of the main vectors (no code was added), carry `provider=` on the ENTROPY line alone, and are all REJECTED by the default-smoke
  judge `judge_for_guest` (a default run never selects a legacy provider, so such a line is some other run or a silent switch);
* the source rules that make "no insecure entropy fallback" true of this code: no insecure source is named in the provider code, neither
  provider's fill reaches for the other, `open_dev_random` has one production caller, the leaf opens exactly one constant path, and the
  legacy provider is constructed in one place. Each rule is a detector over source text and each has a planted violation it must report;
* the limits and the contract text agree (the read budget is below the request limit, so `ReadBudget` is reachable; the contract cites the
  kernel sources it relied on).
It proves nothing about a kernel: the Rust unit tests are central, and the real adapter reading `/dev/random` is a QEMU guest run.
Offline, stdlib only.
"""
import json
import os
import re
import unittest

import test_platform_markers as PM

ROOT = PM.ROOT
LEGACY_VECTORS = os.path.join(ROOT, "crates", "franken-speaker", "tests", "vectors", "p02_legacy_entropy_markers.json")
PLATFORM_SRC = os.path.join(ROOT, "crates", "franken-platform", "src")
LEAF_SRC = os.path.join(ROOT, "crates", "franken-platform-linux", "src")
SPEAKER_SRC = os.path.join(ROOT, "crates", "franken-speaker", "src")
P02_DOC = os.path.join(ROOT, "docs", "contracts", "p02.md")
PROVIDERS = ["legacy_dev_random", "legacy_dev_random_test_environment"]
# Names that must not appear in the code (comments removed) of the provider and the leaf's syscall file: each is a way to make bytes that are
# not the kernel's seeded entropy.
INSECURE = ["/dev/urandom", "GRND_INSECURE", "GRND_RANDOM", "RNDADDENTROPY", "SystemTime", "Instant", "process::id", "getpid", "thread_rng", "rand::"]


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def code_of(text):
    """Production code of a Rust source: up to its `#[cfg(test)]` module, with `//` comments (doc comments included) removed."""
    return "\n".join(re.sub(r"//.*$", "", line) for line in text.split("#[cfg(test)]", 1)[0].splitlines())


def function_body(code, name):
    """The text between the braces of `fn <name>`, or None."""
    match = re.search(r"\bfn\s+%s\b" % re.escape(name), code)
    if not match:
        return None
    start = code.index("{", match.end())
    depth = 0
    for index in range(start, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[start + 1:index]
    return None


def sources():
    return {
        "entropy.rs": read(os.path.join(PLATFORM_SRC, "entropy.rs")),
        "layer.rs": read(os.path.join(PLATFORM_SRC, "layer.rs")),
        "ops.rs": read(os.path.join(PLATFORM_SRC, "ops.rs")),
        "sim.rs": read(os.path.join(PLATFORM_SRC, "sim.rs")),
        "sys.rs": read(os.path.join(LEAF_SRC, "sys.rs")),
        "platform_start.rs": read(os.path.join(SPEAKER_SRC, "platform_start.rs")),
        "main.rs": read(os.path.join(SPEAKER_SRC, "main.rs")),
    }


# ---- the detectors: each returns the problems it finds, [] for a clean source ----

def insecure_sources(srcs):
    problems = []
    for name in ("entropy.rs", "sys.rs"):
        code = code_of(srcs[name])
        problems += ["%s names %s" % (name, token) for token in INSECURE if token in code]
    return problems


def provider_independence(srcs):
    code = code_of(srcs["entropy.rs"])
    bodies = {name: function_body(code, name) for name in ("fill_inner", "fill_legacy", "read_legacy", "fill_with")}
    problems = ["no body for %s" % name for name, body in bodies.items() if body is None]
    if problems:
        return problems
    for token in ("open_dev_random", "fill_legacy", "read_legacy"):
        if token in bodies["fill_inner"]:
            problems.append("the getrandom path (fill_inner) reaches for the legacy provider: %s" % token)
    for name in ("fill_legacy", "read_legacy"):
        for token in ("getrandom", "fill_inner"):
            if token in bodies[name]:
                problems.append("the legacy path (%s) reaches for getrandom: %s" % (name, token))
    if bodies["fill_with"].count("=>") != 2 or "EntropyProvider::Getrandom => fill_inner(" not in bodies["fill_with"] \
            or "EntropyProvider::LegacyDevRandom => fill_legacy(" not in bodies["fill_with"]:
        problems.append("fill_with is not exactly one arm per provider")
    # Each provider's fill is called exactly once in fill_with: a second call (an `.or_else(|_| fill_legacy(..))` after the getrandom arm,
    # for instance) would be a fallback written where the arms cannot see it.
    if bodies["fill_with"].count("fill_inner(") != 1 or bodies["fill_with"].count("fill_legacy(") != 1:
        problems.append("fill_with calls a provider's fill other than exactly once: a fallback between providers")
    for name in ("fill_inner", "fill_legacy"):
        # The definition is generic (`fn name<O ...>(`), so only a call matches `name(`: exactly one, in fill_with.
        if len(re.findall(r"\b%s\(" % name, code)) != 1:
            problems.append("%s is called other than exactly once" % name)
    return problems


def open_callers(srcs):
    """Production call sites of `.open_dev_random(` in the platform crate."""
    return sorted(name for name in ("entropy.rs", "layer.rs", "ops.rs", "sim.rs")
                  for _ in re.finditer(r"\.open_dev_random\(", code_of(srcs[name])))


def leaf_path_problems(srcs):
    code = code_of(srcs["sys.rs"])
    literals = re.findall(r'b"([^"]*)"', code)
    problems = []
    if literals != ["/dev/random\\0"]:
        problems.append("the leaf's byte-string literals are %r, not exactly the constant /dev/random path" % literals)
    if "&[u8; 12]" not in code:
        problems.append("DEV_RANDOM is not a 12-byte constant (/dev/random plus its NUL)")
    body = function_body(code, "open_dev_random")
    if body is None or "DEV_RANDOM.as_ptr()" not in body:
        problems.append("open_dev_random does not pass the DEV_RANDOM constant")
    signature = re.search(r"fn\s+open_dev_random\s*\(([^)]*)\)", code)
    if not signature or signature.group(1).replace(" ", "") != "flags:u32":
        problems.append("open_dev_random takes something other than flags: u32 (a path parameter would name another file)")
    return problems


def selection_problems(srcs):
    problems = []
    start = code_of(srcs["platform_start.rs"])
    if len(re.findall(r"EntropyProfile::LegacyDevRandom\(", start)) != 2:
        problems.append("platform_start.rs does not construct the legacy profile in exactly the two arms of EntropySelection::profile")
    if len(re.findall(r"\.with_entropy_profile\(", start)) != 1:
        problems.append("platform_start.rs selects an entropy profile in other than exactly one place (bring_up_with)")
    for name in ("layer.rs", "main.rs"):
        if re.search(r"LegacyDevRandom\(", code_of(srcs[name])):
            problems.append("%s constructs the legacy profile" % name)
    layer = code_of(srcs["layer.rs"])
    if "EntropyProfile::Getrandom" not in layer or layer.count("with_entropy_profile") != 1:
        problems.append("layer.rs does not default to Getrandom and offer exactly one explicit selection")
    fill_random = function_body(layer, "fill_random") or ""
    if "self.entropy_profile.provider()" not in fill_random or "entropy::fill_with(" not in fill_random or "entropy::fill(" in fill_random:
        problems.append("fill_random does not route by the explicitly selected provider")
    if not re.search(r"pub const LEGACY_DEV_RANDOM_QUALIFICATION:\s*ProviderQualification\s*=\s*ProviderQualification::Unqualified;", start):
        problems.append("the speaker's evidence-qualified legacy selection is not Unqualified (no observation of the device exists)")
    return problems


def main_wiring_problems(srcs):
    """`main()` has no host test, so the path from the command line to the layer is pinned on the text: the arguments after
    `--platform-startup` go through `parse_startup_args`, an error exits with the usage status and starts nothing, and the parsed selection is
    what `platform_startup` hands to `check_device_with` (never a default substituted for it)."""
    code = code_of(srcs["main.rs"])
    problems = []
    if "parse_startup_args(&args[2..])" not in code:
        problems.append("main does not parse the arguments after --platform-startup")
    if "Ok(selection) => platform_startup(selection)" not in code:
        problems.append("main does not hand the parsed selection to platform_startup")
    if "ExitCode::from(franken_speaker::platform_start::EXIT_USAGE)" not in code:
        problems.append("a malformed --platform-startup argument does not exit with the usage status")
    body = function_body(code, "platform_startup") or ""
    if "check_device_with(selection)" not in body:
        problems.append("platform_startup does not pass its selection to check_device_with")
    if "EntropySelection::default()" in code or "EntropySelection::Getrandom" in code:
        problems.append("main substitutes a provider for the one the command line named")
    return problems


class LegacyMarkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(LEGACY_VECTORS, encoding="utf-8") as fh:
            cls.legacy = json.load(fh)
        cls.main = PM.load_vectors()
        cls.reasons = cls.main["reason_codes"]

    def test_every_legacy_example_is_well_formed_under_the_reference_judge_and_adds_no_reason_code(self):
        self.assertEqual(self.legacy["schema"], "ffw.p02.legacy-entropy-markers.v1")
        self.assertEqual(self.legacy["provider_values"], PROVIDERS)
        self.assertEqual(sorted(self.legacy["examples"]), sorted([
            "legacy_test_environment_all_pass_powerpc", "legacy_test_environment_not_seeded_mips", "legacy_evidence_qualified_unavailable_powerpc",
            "legacy_device_absent_mips", "legacy_selected_with_a_simulated_backend_refused"]))
        for name, example in self.legacy["examples"].items():
            self.assertEqual(PM.judge(example["lines"], self.reasons), [], name)
            started = example["lines"][-1].startswith("FFW_PLATFORM:END started=1")
            self.assertEqual(example["exit"], 0 if started else 3, name)

    def test_the_provider_token_is_on_the_entropy_line_alone_and_takes_only_the_two_values(self):
        for name, example in self.legacy["examples"].items():
            for line in example["lines"]:
                has = " provider=" in line
                self.assertEqual(has, line.startswith("FFW_PLATFORM:ENTROPY "), "%s: %s" % (name, line))
                if has:
                    self.assertIn(re.search(r" provider=(\S+)", line).group(1), PROVIDERS, name)

    def test_every_legacy_example_prints_the_provider_even_when_the_line_was_not_run(self):
        # NOT_RUN, REFUSED and PASS alike: a transcript always shows which provider was selected.
        statuses = {re.search(r"status=(\S+)", ex["lines"][3]).group(1) for ex in self.legacy["examples"].values()}
        self.assertEqual(statuses, {"PASS", "REFUSED", "NOT_RUN"})

    def test_the_default_smoke_judge_rejects_every_legacy_example(self):
        for name, example in self.legacy["examples"].items():
            guest = "mips" if "mips" in name else "ppc"
            problems = PM.judge_for_guest(example["lines"], guest, self.reasons)
            self.assertNotEqual(problems, [], name)
        # The control: the default example of the same guest is accepted, and adding only the token turns it red.
        for guest, name in (("ppc", "powerpc_all_pass"), ("mips", "mips_all_pass")):
            lines = list(self.main["examples"][name]["lines"])
            self.assertEqual(PM.judge_for_guest(lines, guest, self.reasons), [], name)
            lines[3] += " provider=legacy_dev_random"
            lines[3] = lines[3].replace("status=PASS provenance=kernel provider=legacy_dev_random", "status=PASS provenance=kernel provider=legacy_dev_random")
            self.assertTrue(any("provider=legacy_dev_random" in p for p in PM.judge_for_guest(lines, guest, self.reasons)), name)

    def test_the_main_vectors_the_smoke_judge_reads_carry_no_provider_token(self):
        for name, example in self.main["examples"].items():
            for line in example["lines"]:
                self.assertNotIn("provider=", line, name)

    def test_each_planted_fault_in_a_legacy_line_is_reported(self):
        healthy = list(self.legacy["examples"]["legacy_test_environment_all_pass_powerpc"]["lines"])
        self.assertEqual(PM.judge(healthy, self.reasons), [])
        plants = {
            "an unknown provider value": lambda l: l.__setitem__(3, l[3].replace("legacy_dev_random_test_environment", "urandom")),
            "an empty provider value": lambda l: l.__setitem__(3, l[3].replace("provider=legacy_dev_random_test_environment", "provider=")),
            "an uppercase provider value": lambda l: l.__setitem__(3, l[3].replace("legacy_dev_random_test_environment", "LEGACY_DEV_RANDOM")),
            "the token on the CLOCK line": lambda l: l.__setitem__(2, l[2] + " provider=legacy_dev_random"),
            "the token on the WAKE line": lambda l: l.__setitem__(4, l[4].replace(" mechanism=eventfd", " provider=legacy_dev_random mechanism=eventfd")),
            "the token twice": lambda l: l.__setitem__(3, l[3] + " provider=legacy_dev_random"),
            "the token after the reason": lambda l: (l.__setitem__(3, "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=not_seeded provider=legacy_dev_random"),
                                                      l.__setitem__(5, "FFW_PLATFORM:END started=0 refused=entropy:not_seeded")),
            "the token before the provenance": lambda l: l.__setitem__(3, "FFW_PLATFORM:ENTROPY status=PASS provider=legacy_dev_random provenance=kernel"),
            "a simulated provenance on a legacy PASS": lambda l: l.__setitem__(3, l[3].replace("provenance=kernel", "provenance=simulated")),
        }
        for name, edit in plants.items():
            lines = list(healthy)
            edit(lines)
            self.assertNotEqual(PM.judge(lines, self.reasons), [], name)


class NoInsecureFallbackSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srcs = sources()

    def planted(self, name, old, new):
        srcs = dict(self.srcs)
        self.assertIn(old, srcs[name], "the plant's anchor is gone: %r" % old)
        srcs[name] = srcs[name].replace(old, new, 1)
        return srcs

    def test_no_insecure_source_is_named_in_the_provider_code_or_the_leafs_syscalls(self):
        self.assertEqual(insecure_sources(self.srcs), [])
        for token in INSECURE:
            planted = self.planted("entropy.rs", "fn is_degenerate(", "fn planted() { let _ = \"%s\"; }\nfn is_degenerate(" % token)
            self.assertTrue(any(token in p for p in insecure_sources(planted)), token)
        planted = self.planted("sys.rs", "/// `eventfd2(initval, flags)`.", "const BAD: &[u8; 14] = b\"/dev/urandom\\0\";\n/// `eventfd2(initval, flags)`.")
        self.assertTrue(any("/dev/urandom" in p for p in insecure_sources(planted)))

    def test_neither_provider_reaches_for_the_other(self):
        self.assertEqual(provider_independence(self.srcs), [])
        planted = self.planted("entropy.rs", "    let mut filled = 0usize;\n    while filled < buf.len() {",
                               "    let _ = ops.open_dev_random(0);\n    let mut filled = 0usize;\n    while filled < buf.len() {")
        self.assertTrue(any("getrandom path" in p for p in provider_independence(planted)))
        planted = self.planted("entropy.rs", "    let flags = abi.o_nonblock() | O_CLOEXEC;", "    let _ = ops.getrandom(buf, 1);\n    let flags = abi.o_nonblock() | O_CLOEXEC;")
        self.assertTrue(any("legacy path (fill_legacy)" in p for p in provider_independence(planted)))
        planted = self.planted("entropy.rs", "        EntropyProvider::LegacyDevRandom => fill_legacy(ops, abi, buf),",
                               "        EntropyProvider::LegacyDevRandom => fill_legacy(ops, abi, buf),\n        EntropyProvider::Getrandom => fill_legacy(ops, abi, buf),")
        self.assertTrue(any("one arm per provider" in p for p in provider_independence(planted)))
        # A fallback written inside fill_with, after the getrandom arm: the arms still read as one per provider, so only the call count sees it.
        planted = self.planted("entropy.rs", "        EntropyProvider::Getrandom => fill_inner(ops, abi, buf),",
                               "        EntropyProvider::Getrandom => fill_inner(ops, abi, buf).or_else(|_| fill_legacy(ops, abi, buf)),")
        self.assertTrue(any("a fallback between providers" in p for p in provider_independence(planted)), provider_independence(planted))

    def test_the_legacy_open_has_one_production_caller_and_it_is_the_legacy_fill(self):
        self.assertEqual(open_callers(self.srcs), ["entropy.rs"])
        planted = self.planted("layer.rs", "        entropy::fill_with(", "        let _ = self.ops.open_dev_random(0);\n        entropy::fill_with(")
        self.assertEqual(open_callers(planted), ["entropy.rs", "layer.rs"])
        body = function_body(code_of(self.srcs["entropy.rs"]), "fill_legacy")
        self.assertEqual(len(re.findall(r"\.open_dev_random\(", body)), 1)

    def test_the_leaf_opens_exactly_one_constant_path_and_the_method_takes_no_path(self):
        self.assertEqual(leaf_path_problems(self.srcs), [])
        planted = self.planted("sys.rs", "pub(crate) fn open_dev_random(flags: u32) -> isize {", "pub(crate) fn open_dev_random(path: &[u8], flags: u32) -> isize {")
        self.assertTrue(any("path parameter" in p for p in leaf_path_problems(planted)))
        planted = self.planted("sys.rs", "pub(crate) const DEV_RANDOM: &[u8; 12] = b\"/dev/random\\0\";",
                               "pub(crate) const DEV_RANDOM: &[u8; 12] = b\"/dev/random\\0\";\nconst OTHER: &[u8; 5] = b\"/etc\\0\";")
        self.assertTrue(any("byte-string literals" in p for p in leaf_path_problems(planted)))
        planted = self.planted("sys.rs", "DEV_RANDOM.as_ptr() as usize", "OTHER.as_ptr() as usize")
        self.assertTrue(any("does not pass the DEV_RANDOM" in p for p in leaf_path_problems(planted)))

    def test_main_hands_the_parsed_selection_to_startup_and_substitutes_nothing(self):
        self.assertEqual(main_wiring_problems(self.srcs), [])
        planted = self.planted("main.rs", "Ok(selection) => platform_startup(selection),",
                               "Ok(_) => platform_startup(franken_speaker::platform_start::EntropySelection::default()),")
        problems = main_wiring_problems(planted)
        self.assertTrue(any("does not hand the parsed selection" in p for p in problems), problems)
        self.assertTrue(any("substitutes a provider" in p for p in problems), problems)
        planted = self.planted("main.rs", "let report = franken_speaker::platform_start::check_device_with(selection);",
                               "let report = franken_speaker::platform_start::check_device();")
        self.assertTrue(any("does not pass its selection" in p for p in main_wiring_problems(planted)))
        planted = self.planted("main.rs", "ExitCode::from(franken_speaker::platform_start::EXIT_USAGE)", "ExitCode::SUCCESS")
        self.assertTrue(any("usage status" in p for p in main_wiring_problems(planted)))
        planted = self.planted("main.rs", "parse_startup_args(&args[2..])", "parse_startup_args(&[])")
        self.assertTrue(any("does not parse the arguments" in p for p in main_wiring_problems(planted)))

    def test_the_legacy_provider_is_constructed_and_selected_in_one_place(self):
        self.assertEqual(selection_problems(self.srcs), [])
        planted = self.planted("main.rs", "fn main() -> ExitCode {", "fn main() -> ExitCode {\n    let _p = EntropyProfile::LegacyDevRandom(x);")
        self.assertTrue(any("main.rs constructs the legacy profile" in p for p in selection_problems(planted)))
        planted = self.planted("platform_start.rs", "        Ok(layer) => layer.with_entropy_profile(selection.profile()),",
                               "        Ok(layer) => layer.with_entropy_profile(selection.profile()).with_entropy_profile(EntropyProfile::Getrandom),")
        self.assertTrue(any("other than exactly one place" in p for p in selection_problems(planted)))
        planted = self.planted("layer.rs", "            entropy_profile: EntropyProfile::Getrandom,", "            entropy_profile: EntropyProfile::LegacyDevRandom(x),")
        self.assertTrue(any("layer.rs constructs the legacy profile" in p for p in selection_problems(planted)))
        # fill_random must route by the selected provider: a layer that ignores the selection and always asks getrandom is a silent switch.
        planted = self.planted("layer.rs", "self.entropy_profile.provider(),", "EntropyProvider::Getrandom,")
        self.assertTrue(any("does not route by the explicitly selected provider" in p for p in selection_problems(planted)))
        # The evidence-qualified selection stays Unqualified until a matching-guest observation exists.
        planted = self.planted("platform_start.rs", "ProviderQualification::Unqualified;", "ProviderQualification::TestEnvironment;")
        self.assertTrue(any("is not Unqualified" in p for p in selection_problems(planted)))


class LimitsAndContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entropy = read(os.path.join(PLATFORM_SRC, "entropy.rs"))
        cls.start = read(os.path.join(SPEAKER_SRC, "platform_start.rs"))
        cls.doc = read(P02_DOC)

    def const(self, text, name):
        return int(re.search(r"pub const %s: usize = (\d+);" % name, text).group(1))

    def test_the_read_budget_is_below_the_request_limit_so_the_budget_error_is_reachable_and_a_startup_request_always_fits(self):
        reads, request, probe = (self.const(self.entropy, "LEGACY_MAX_READS"), self.const(self.entropy, "LEGACY_MAX_REQUEST_BYTES"),
                                 self.const(self.start, "ENTROPY_PROBE_BYTES"))
        self.assertEqual((reads, request), (16, 64))
        self.assertLess(reads, request)          # every successful read yields at least one byte: otherwise ReadBudget could never happen
        self.assertLessEqual(probe, reads)       # the startup probe (16 bytes) can always complete within the budget
        self.assertLessEqual(probe, request)

    def test_the_contract_names_the_selection_the_sources_and_what_stays_unproven(self):
        for needle in ("legacy_dev_random", "legacy_dev_random_test_environment", "v2.6.35", "v2.6.14", "random_read", "SEC_XFER_SIZE",
                       "a9b39865d4f1426a", "3611d2b6a49022eb", "No insecure entropy fallback", "--entropy-provider",
                       "NOT proven", "ffw.p02.legacy-entropy-markers.v1"):
            self.assertIn(needle, self.doc, needle)

    def test_the_reason_set_gained_no_code_for_the_legacy_provider(self):
        main = PM.load_vectors()["reason_codes"]["entropy"]
        self.assertEqual(main, ["zero_length", "unavailable", "not_seeded", "absent", "interrupted", "invalid", "no_progress", "over_long",
                                "degenerate", "failed", "malformed"])


if __name__ == "__main__":
    unittest.main()
