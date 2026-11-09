"""The caps the caller-driven probe states, read from its source text, and the figures the judge pins for them. Standard library only, offline, no cargo.

    cd tests/p05 && python3 -B -m unittest -v test_caller_driven_probe_caps

The judge pins four figures of the caller-driven run that no source fixes by itself: `PROFILE_ACCEPT worst_case_stack_bytes` and `budget` (1048576),
`RUNTIME_AUDIT global_queue=256/256` and `blocking_queue=0/0`. They are the probe's own choices, and the audit would pass with others, because it
ignores the stated blocking stack and queue of a forbidden pool (`LegacyCaps::observable`). So a caps list copied with `..caps()` would print
`blocking_queue=0/1` beside `audit_ok=true` and the judge would refuse an honest run. This test reads `caps()` and `caller_driven_caps()` from
`toolchain/src/p05-runtime/src/main.rs`, derives the figures those rows print from them, and judges the derived rows with the judge's own
`runtime_phase_problems`. It does NOT compile or run the probe: the carried half of each figure is what the Asupersync source gives a forbidden-pool
caller-driven runtime (workers, blocking threads and the global queue carry what was stated; a forbidden pool reads a blocking queue of 0), and the
`violations=0` of `PROFILE_ACCEPT` is the judge's own pin. Every plant is a change to a COPY of the source text and has a control.
"""
import ast
import importlib.util
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
MAIN = os.path.join(REPO, "toolchain", "src", "p05-runtime", "src", "main.rs")
SPEC = importlib.util.spec_from_file_location("p05_judge_for_caller_driven_caps", os.path.join(REPO, "toolchain", "src", "measure-p05-target.py"))
JUDGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = JUDGE
SPEC.loader.exec_module(JUDGE)

FIELDS = ("worker_threads", "thread_stack_bytes", "blocking_max_threads", "blocking_thread_stack_bytes", "global_queue_limit", "blocking_max_queued")
EXPLICIT = {"worker_threads": 1, "blocking_max_threads": 0, "blocking_thread_stack_bytes": 0, "blocking_max_queued": 0}   # hand-written: what must be stated


def function_body(text, signature):
    start = text.index(signature)
    return text[start:text.index("\n}\n", start)]


def evaluate(expression, constants):
    """An integer Rust expression made of literals, constants, `*` and `/` (integer division), as `caps()` writes them."""
    def walk(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name) and node.id in constants:
            return constants[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Div)):
            left, right = walk(node.left), walk(node.right)
            return left * right if isinstance(node.op, ast.Mult) else left // right
        raise ValueError(f"cannot evaluate {expression!r}")
    return walk(ast.parse(expression.strip(), mode="eval").body)


def struct_fields(body, constants):
    """`{name: value}` for each `name: expr,` line of the struct literal in `body`, and the function named by a `..base()` line, if any."""
    found = {name: evaluate(expr, constants) for name, expr in re.findall(r"^\s+(\w+): (.+),$", body, re.MULTILINE)}
    base = re.search(r"^\s+\.\.(\w+)\(\)$", body, re.MULTILINE)
    return found, base[1] if base else None


def stated_caps(text):
    """(all six stated caps, the ones `caller_driven_caps` writes out itself), as the source text states them."""
    constants = {"MIB": evaluate(re.search(r"^const MIB: usize = (.+);$", text, re.MULTILINE)[1], {})}
    base, _ = struct_fields(function_body(text, "fn caps() -> LegacyCaps {"), constants)
    own, rest = struct_fields(function_body(text, "fn caller_driven_caps() -> LegacyCaps {"), constants)
    assert rest == "caps", rest
    return {**base, **own}, own


def printed_rows(caps):
    """The `PROFILE_ACCEPT` and `RUNTIME_AUDIT` rows of a caller-driven run over `caps`: the stated half from the caps, the carried half from the source."""
    worst = caps["worker_threads"] * caps["thread_stack_bytes"] + caps["blocking_max_threads"] * caps["blocking_thread_stack_bytes"]
    accept = f"status=ok violations=0 worst_case_stack_bytes={worst} budget={worst}"
    carried_queue = 0       # a forbidden pool reads a blocking queue of 0, whatever was stated
    audit = (f"status=ok audit_ok=true workers={caps['worker_threads']}/{caps['worker_threads']} "
             f"blocking_threads={caps['blocking_max_threads']}/{caps['blocking_max_threads']} "
             f"global_queue={caps['global_queue_limit']}/{caps['global_queue_limit']} "
             f"blocking_queue={carried_queue}/{caps['blocking_max_queued']} (carried/stated)")
    return {"PROFILE_ACCEPT": accept, "RUNTIME_AUDIT": audit}


def judged_problems(text):
    caps, _ = stated_caps(text)
    problems = []
    for name, detail in printed_rows(caps).items():
        problems += JUDGE.runtime_phase_problems(name, JUDGE.parse_pairs(detail), detail, JUDGE.RUNTIME_CALLER_DRIVEN)
    return problems


def mutated(text, signature, old, new):
    """`text` with `old` replaced by `new` once, inside the body of the function that starts with `signature` and nowhere else."""
    body = function_body(text, signature)
    assert body.count(old) == 1, (signature, old, body.count(old))
    return text.replace(body, body.replace(old, new))


CAPS = "fn caps() -> LegacyCaps {"
CALLER_DRIVEN_CAPS = "fn caller_driven_caps() -> LegacyCaps {"


class CallerDrivenProbeCaps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(MAIN, encoding="utf-8") as source:
            cls.text = source.read()

    def test_control_the_stated_caps_are_the_ones_the_judge_pins_and_the_derived_rows_are_accepted(self):
        caps, own = stated_caps(self.text)
        self.assertEqual(sorted(caps), sorted(FIELDS), "all six caps are stated, so the parse is not vacuous")
        self.assertEqual(caps, {"worker_threads": 1, "thread_stack_bytes": 1048576, "blocking_max_threads": 0, "blocking_thread_stack_bytes": 0,
                                "global_queue_limit": 256, "blocking_max_queued": 0})
        rows = printed_rows(caps)
        self.assertIn("worst_case_stack_bytes=1048576 budget=1048576", rows["PROFILE_ACCEPT"])
        self.assertIn("workers=1/1 blocking_threads=0/0 global_queue=256/256 blocking_queue=0/0", rows["RUNTIME_AUDIT"])
        self.assertEqual(judged_problems(self.text), [])
        for name, value in EXPLICIT.items():
            self.assertEqual(own.get(name), value, f"`caller_driven_caps` must state {name}: {value} itself, not inherit it from `caps()`")

    def test_a_caller_driven_caps_list_that_inherits_the_blocking_queue_prints_0_over_1_and_is_refused_for_that_reason(self):
        """DarkPeak 16859: the `..caps()` idiom without the explicit queue. The audit would pass; the judge refuses the stated half."""
        planted = mutated(self.text, CALLER_DRIVEN_CAPS, "        blocking_max_queued: 0,\n        ..caps()", "        ..caps()")
        caps, own = stated_caps(planted)
        self.assertEqual((caps["blocking_max_queued"], "blocking_max_queued" in own), (1, False))
        self.assertIn("blocking_queue=0/1", printed_rows(caps)["RUNTIME_AUDIT"])
        self.assertIn("audit_ok=true", printed_rows(caps)["RUNTIME_AUDIT"], "the audit still passes on that row")
        self.assertIn("RUNTIME_AUDIT.blocking_queue=0/1 expected=0/0", judged_problems(planted))
        self.assertEqual(judged_problems(self.text), [], "control")

    def test_each_other_planted_change_to_a_stated_cap_is_refused_by_the_figure_it_moves(self):
        plants = (
            ("a second worker", CALLER_DRIVEN_CAPS, "        worker_threads: 1,", "        worker_threads: 2,",
             "RUNTIME_AUDIT.workers=2/2 expected=1/1"),
            ("a blocking thread", CALLER_DRIVEN_CAPS, "        blocking_max_threads: 0,", "        blocking_max_threads: 1,",
             "RUNTIME_AUDIT.blocking_threads=1/1 expected=0/0"),
            ("a blocking thread with a stack", CALLER_DRIVEN_CAPS,
             "        blocking_max_threads: 0,\n        blocking_thread_stack_bytes: 0,",
             "        blocking_max_threads: 1,\n        blocking_thread_stack_bytes: MIB / 2,",
             "PROFILE_ACCEPT.worst_case_stack_bytes=1572864 expected=1048576"),
            ("another global queue", CAPS, "        global_queue_limit: 256,", "        global_queue_limit: 512,",
             "RUNTIME_AUDIT.global_queue=512/512 expected=256/256"),
            ("another worker stack", CAPS, "        thread_stack_bytes: MIB,", "        thread_stack_bytes: MIB / 2,",
             "PROFILE_ACCEPT.worst_case_stack_bytes=524288 expected=1048576"),
        )
        self.assertEqual(judged_problems(self.text), [], "control: the unplanted source, once before the plants")
        for label, signature, old, new, reason in plants:
            with self.subTest(plant=label):
                self.assertIn(reason, judged_problems(mutated(self.text, signature, old, new)))
                self.assertEqual(judged_problems(self.text), [], "the plant is a copy: the unplanted source is still accepted")

    def test_the_budget_of_the_caller_driven_profile_is_the_worst_case_the_judge_expects_it_to_equal(self):
        signature = "fn caller_driven_profile() -> Option<LegacyProfile> {"
        shape = r"\.worst_case_stack_bytes\(\)\s*\.map\(\|budget\| LegacyProfile::new\(stated, budget\)\.caller_driven\(\)\)"
        self.assertRegex(function_body(self.text, signature), shape)
        planted = mutated(self.text, signature, "LegacyProfile::new(stated, budget)", "LegacyProfile::new(stated, budget + 1)")
        self.assertNotRegex(function_body(planted, signature), shape)
        self.assertRegex(function_body(self.text, signature), shape, "control: the unplanted source still has the shape")


if __name__ == "__main__":
    unittest.main()
