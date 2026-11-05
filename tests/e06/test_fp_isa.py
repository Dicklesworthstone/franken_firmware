"""E06 floating-point ABI probe tests (scripts/e06/fp_isa.py).

The classifier is tested on hand-written assembly and on a stub compiler, so each verdict is exercised by input the real
toolchain would not produce (a soft call on PowerPC, a spec that contradicts the codegen). One live test runs the real
toolchain and pins today's facts; if a future nightly changes a target's float default, that test failing is the signal.
"""
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("ffw_e06_fp_isa", os.path.join(ROOT, "scripts", "e06", "fp_isa.py"))
FP = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = FP
spec.loader.exec_module(FP)

PPC_HARD = """\
\t.text
add_f32:
.Lfunc_begin0:
\tfadds 1, 1, 2
\tblr
.Lfunc_end0:
mul_f64:
.Lfunc_begin1:
\tfmul 1, 1, 2
\tblr
"""
PPC_SOFT = """\
add_f32:
\tmflr 0
\tbl __addsf3
\tblr
mul_f64:
\tmflr 0
\tbl __muldf3
\tblr
"""
MIPS_SOFT = """\
add_f32:
\tlw\t$25, %call16(__addsf3)($gp)
\t.reloc $tmp0, R_MIPS_JALR, __addsf3
\tjalr\t$25
mul_f64:
\tlw\t$25, %call16(__muldf3)($gp)
\tjalr\t$25
"""
MIPS_HARD = """\
add_f32:
\tadd.s\t$f0, $f12, $f14
\tjr\t$ra
mul_f64:
\tmul.d\t$f0, $f12, $f14
\tjr\t$ra
"""


class ClassifyAsmTests(unittest.TestCase):
    def test_each_arch_and_abi_is_read_from_its_own_instructions(self):
        for asm, arch, want in ((PPC_HARD, "powerpc", "hard"), (PPC_SOFT, "powerpc", "soft"),
                                (MIPS_SOFT, "mips", "soft"), (MIPS_HARD, "mips", "hard")):
            with self.subTest(arch=arch, want=want):
                result = FP.classify_asm(asm, arch)
                self.assertEqual(result["overall"], want)
                self.assertEqual(set(result["functions"].values()), {want})

    def test_the_evidence_is_the_instruction_that_decided_it(self):
        self.assertEqual(FP.classify_asm(PPC_HARD, "powerpc")["evidence"],
                         {"add_f32": "fadds 1, 1, 2", "mul_f64": "fmul 1, 1, 2"})
        self.assertIn("__addsf3", FP.classify_asm(MIPS_SOFT, "mips")["evidence"]["add_f32"])

    def test_mixed_missing_or_unrecognised_is_unknown_never_guessed(self):
        mixed = PPC_HARD.replace("fmul 1, 1, 2", "bl __muldf3")                # one hardware, one soft
        self.assertEqual(FP.classify_asm(mixed, "powerpc")["overall"], "unknown")
        both = PPC_HARD.replace("fadds 1, 1, 2", "fadds 1, 1, 2\n\tbl __addsf3")  # hardware AND a soft call in one body
        self.assertEqual(FP.classify_asm(both, "powerpc")["functions"]["add_f32"], "unknown")
        self.assertEqual(FP.classify_asm("add_f32:\n\tblr\n", "powerpc")["overall"], "unknown")   # neither, and one missing
        self.assertEqual(FP.classify_asm(PPC_HARD, "mips")["overall"], "unknown")                 # the wrong arch's mnemonics
        self.assertEqual(FP.classify_asm("", "powerpc")["overall"], "unknown")

    def test_directives_local_labels_and_look_alike_mnemonics_do_not_count(self):
        decoy = "add_f32:\n\t.ascii \"fadds\"\n# fadds in a comment\n\tfaddsx 1, 1, 2\n\tblr\nmul_f64:\n\tfmul 1, 1, 2\n"
        self.assertEqual(FP.classify_asm(decoy, "powerpc")["functions"]["add_f32"], "unknown")

    def test_zig_macros_decide_soft_or_hard(self):
        self.assertEqual(FP.classify_zig_macros(["_SOFT_FLOAT", "__NO_FPRS__"]), "soft")
        self.assertEqual(FP.classify_zig_macros(["__mips_soft_float"]), "soft")
        self.assertEqual(FP.classify_zig_macros(["__mips_hard_float", "__linux__"]), "hard")
        self.assertEqual(FP.classify_zig_macros([]), "hard")


STUB = r'''#!/usr/bin/env python3
import json, os, sys
cfg = json.loads(os.environ["FP_STUB"])
args = sys.argv[1:]
target = args[args.index("--target") + 1] if "--target" in args else None
if "-vV" in args:
    print("rustc 0.0.0-stub\nrelease: 0.0.0-stub\ncommit-hash: " + "0" * 40)
elif "--print" in args:
    spec = cfg["spec"][target]
    if spec is None:
        sys.stderr.write("error: no spec\n"); sys.exit(1)
    print(json.dumps(spec))
elif any(a.startswith("--emit=") for a in args):
    if cfg["asm"][target] is None:
        sys.stderr.write("error: probe failed\n"); sys.exit(1)
    open(args[args.index("-o") + 1], "w").write(cfg["asm"][target])
'''


class StubbedRecordTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.rustc = os.path.join(self._tmp.name, "rustc")
        with open(self.rustc, "w") as fh:
            fh.write(STUB)
        os.chmod(self.rustc, os.stat(self.rustc).st_mode | stat.S_IXUSR)

    def record(self, mips_spec, mips_asm, ppc_spec, ppc_asm):
        cfg = {"spec": {"mips-unknown-linux-musl": mips_spec, "powerpc-unknown-linux-musl": ppc_spec},
               "asm": {"mips-unknown-linux-musl": mips_asm, "powerpc-unknown-linux-musl": ppc_asm}}
        old = os.environ.get("FP_STUB")
        os.environ["FP_STUB"] = json.dumps(cfg)
        try:
            return FP.record(use_zig=False, rustc=self.rustc)
        finally:
            if old is None:
                del os.environ["FP_STUB"]
            else:
                os.environ["FP_STUB"] = old

    def test_the_two_targets_get_their_own_verdicts_and_the_board_is_never_claimed(self):
        rec = self.record({"features": "+mips32r2,+soft-float"}, MIPS_SOFT, {"arch": "powerpc"}, PPC_HARD)
        mips, ppc = rec["targets"]["mips"], rec["targets"]["powerpc"]
        self.assertEqual((mips["rust_float_abi"], ppc["rust_float_abi"]), ("soft", "hard"))
        self.assertTrue(mips["spec"]["says_soft_float"])
        self.assertFalse(ppc["spec"]["says_soft_float"])
        self.assertFalse(ppc["spec"]["says_anything_about_float"], "a silent spec must be reported as silent")
        self.assertEqual((mips["spec_consistent"], ppc["spec_consistent"]), (True, True))
        for t in (mips, ppc):
            self.assertIn("not established", t["board_fpu"])
        self.assertEqual(rec["rustc"], "0.0.0-stub")

    def test_a_spec_that_contradicts_the_codegen_is_surfaced(self):
        rec = self.record({"features": "+soft-float"}, MIPS_HARD, {"arch": "powerpc"}, PPC_HARD)
        mips = rec["targets"]["mips"]
        self.assertTrue(mips["spec"]["says_soft_float"])
        self.assertEqual(mips["rust_float_abi"], "hard")
        self.assertFalse(mips["spec_consistent"])

    def test_a_probe_that_does_not_compile_or_a_missing_spec_is_unknown_not_a_default(self):
        rec = self.record(None, None, {"arch": "powerpc"}, PPC_SOFT)
        mips = rec["targets"]["mips"]
        self.assertEqual(mips["spec"]["outcome"], "unavailable")
        self.assertEqual(mips["codegen"]["outcome"], "failed")
        self.assertEqual(mips["rust_float_abi"], "unknown")
        self.assertEqual(rec["targets"]["powerpc"]["rust_float_abi"], "soft")


class CommandLineAndLiveTests(unittest.TestCase):
    def test_json_is_written_once_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "fp.json")
            with open(out, "w") as fh:
                fh.write("keep")
            proc = subprocess.run([sys.executable, "-B", "-I", os.path.join(ROOT, "scripts", "e06", "fp_isa.py"), "--no-zig", "--json", out],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 2)
            with open(out) as fh:
                self.assertEqual(fh.read(), "keep")

    @unittest.skipUnless(subprocess.run(["rustc", "+nightly", "-vV"], capture_output=True).returncode == 0
                         if __import__("shutil").which("rustc") else False, "no nightly rustc")
    def test_the_real_toolchain_today(self):
        """Pins today's facts. A failure means a nightly changed a target's float default: read it, do not 'fix' it."""
        rec = FP.record(use_zig=False)
        self.assertEqual(rec["targets"]["mips"]["rust_float_abi"], "soft")
        self.assertTrue(rec["targets"]["mips"]["spec"]["says_soft_float"])
        self.assertEqual(rec["targets"]["powerpc"]["rust_float_abi"], "hard")
        self.assertFalse(rec["targets"]["powerpc"]["spec"]["says_soft_float"])
        self.assertFalse(rec["targets"]["powerpc"]["spec"]["says_anything_about_float"])
        self.assertTrue(all(t["spec_consistent"] for t in rec["targets"].values()))


COMMITTED = os.path.join(ROOT, "toolchain", "results", "e06", "fp-isa")


@unittest.skipUnless(os.path.isdir(COMMITTED), "the committed float-ABI evidence is not present")
class CommittedRecordTests(unittest.TestCase):
    """The committed record, its README and the tool agree, and the README does not claim a board FPU."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(COMMITTED, "fp-isa.json"), encoding="utf-8") as fh:
            cls.rec = json.load(fh)
        with open(os.path.join(COMMITTED, "README.md"), encoding="utf-8") as fh:
            cls.readme = fh.read()

    def test_the_record_states_the_two_float_abis_and_which_zig_spellings_match(self):
        t = self.rec["targets"]
        self.assertEqual((t["mips"]["rust_float_abi"], t["powerpc"]["rust_float_abi"]), ("soft", "hard"))
        self.assertEqual(t["mips"]["zig_spellings_matching_rust"], ["mips-linux-musleabi"])
        self.assertIn("mips-linux-musl", t["mips"]["zig_spellings_mismatching_rust"])      # the trap: bare mips musl is hard
        self.assertEqual(t["powerpc"]["zig_spellings_matching_rust"], ["powerpc-linux-musl", "powerpc-linux-musleabihf"])
        self.assertEqual(t["powerpc"]["zig_spellings_mismatching_rust"], ["powerpc-linux-musleabi"])
        for arch in t:
            self.assertTrue(t[arch]["spec_consistent"], arch)
            self.assertIn("not established", t[arch]["board_fpu"])

    def test_the_record_and_readme_carry_no_local_path_and_the_readme_says_what_is_not_known(self):
        import re
        leak = re.compile(r"/Users/|/private/|/home/|jemanuel|claude-501|scratchpad")
        self.assertIsNone(leak.search(json.dumps(self.rec)))
        self.assertIsNone(leak.search(self.readme))
        for must in ("silent on float", "hard-float", "internally inconsistent", "MPC8272EC", "not silicon-verified",
                     "bare `mips-linux-musl` is hard-float", "not established"):
            self.assertIn(must, self.readme, must)
        self.assertNotIn("has an FPU", self.readme.replace("If the board has an FPU", ""), "the README must not assert a board FPU")


if __name__ == "__main__":
    unittest.main()
