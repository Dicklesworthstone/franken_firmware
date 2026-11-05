"""Tests for toolchain/src/softfloat-record.py and for the committed record under toolchain/results/d02/softfloat-53f83cf/.

The generator is exercised on artefacts built here (the same ELF and `ar` builders as test_softfloat_symbols.py, so no real
build is needed) with a MANIFEST.txt and rustc-vV.txt shaped like the ones softfloat-build.sh leaves, INCLUDING the machine paths
and the worker id those files carry. The redaction is checked against a leak list written out here, not taken from the script,
and each class of leak is planted next to a clean control. The committed record is checked for its shape, its redaction, its
arithmetic, and that RESULT.md quotes its numbers. Host-only, standard library only; nothing is compiled.

    python3 -B -I tests/d02/test_softfloat_record.py
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCRIPT = REPO / "toolchain" / "src" / "softfloat-record.py"
COMMITTED = REPO / "toolchain" / "results" / "d02" / "softfloat-53f83cf"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tsf = load(HERE / "test_softfloat_symbols.py", "tsf_for_the_record_tests")
rec = load(SCRIPT, "softfloat_record_under_test")

# What a committed record must not contain, written out here independently of the script's own list.
LEAKS = [r"/Users/", r"/private/", r"/tmp/", r"/scratch/", r"/home/", r"/var/", r"\.rch", r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
         r"\b(?:trj|ts1|hz3|hz4|ovh-a|mminiold)\b", r"\bvmi\d+\b"]


def leaks(text):
    return sorted({m.group(0) for pattern in LEAKS for m in re.finditer(pattern, text)})


MANIFEST = """mode: {mode}
target: mips-unknown-linux-musl
artifact: {name}
artifact-found-at: /private/tmp/some-build-host/build/softfloat-target/mips-unknown-linux-musl/release/build/franken-dsp/abc/out/{name}
found-by: cargo --message-format=json (compiler-artifact of franken_dsp), not by a path glob
deviation: lto=off. The shipped ELF is fat-LTO'd and may inline differently.{leak}
deviation: strip=none (profile.release.strip="none"). No code-generation effect.
deviation: symbol-mangling-version=legacy (with -Z unstable-options ahead of it). Names only.
cargo-config: profile.release.lto="off" profile.release.strip="none" target.mips-unknown-linux-musl.rustflags=["-C","target-feature=+crt-static"]
files: 1
{sha}  {name}
{messages}  cargo-messages.jsonl
"""
RUSTC = """rustc 1.101.0-nightly (708c94ef0 2026-11-03)
binary: rustc
commit-hash: 708c94ef093ecc42fb8851e17d8383d999727abc
commit-date: 2026-11-03
host: x86_64-unknown-linux-gnu
release: 1.101.0-nightly
LLVM version: 23.1.5
cargo 1.101.0-nightly (31d3246e0 2026-10-27)
CARGO_HOME: /scratch/tmp/rch-cargo-cache-trj
"""
CODE_NAME = "franken_dsp-4ba94165e5b2af33.franken_dsp.1e8c1debe93f1cd1-cgu.0.rcgu.o"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def wrapper(self, section):
        return tsf.elf([], abiflags=False, pdr_decoy=False, extra_sections=[(section, b"m" * 40)])

    def artefacts(self, rlib_code=None, obj_code=None, leak="", rustc=RUSTC, obj_rustc=None, obj_leak=None):
        """A kept rlib and a kept object, each in its own directory with a MANIFEST.txt and rustc-vV.txt beside it."""
        code = tsf.control_object(fp_abi=0, pic=True)
        rlib = tsf.ar([("lib.rmeta", self.wrapper(".rmeta")), ("lib.rmeta-link", self.wrapper(".rmeta-link")), (CODE_NAME, rlib_code or code)])
        obj = obj_code or code
        out = {}
        for kind, name, data, extra, text in (("rlib", "libfranken_dsp-4ba94165e5b2af33.rlib", rlib, leak, rustc),
                                              ("obj", "franken_dsp-5b4f199e070ecefc.o", obj, leak if obj_leak is None else obj_leak,
                                               rustc if obj_rustc is None else obj_rustc)):
            directory = self.root / kind
            directory.mkdir()
            (directory / name).write_bytes(data)
            (directory / "MANIFEST.txt").write_text(MANIFEST.format(mode=kind, name=name, leak=extra, sha=hashlib.sha256(data).hexdigest(),
                                                                    messages=hashlib.sha256(kind.encode()).hexdigest()))
            (directory / "rustc-vV.txt").write_text(text)
            out[kind] = directory / name
        return out

    def run_record(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rec.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def record_of(self, paths, *extra):
        target = self.root / "record.json"
        code, out, err = self.run_record("--revision", "53f83cf", *extra, "--out", target, *paths)
        return code, out, err, target


class Generator(Fixture):
    def test_the_record_is_derived_from_the_checker_and_the_files(self):
        paths = self.artefacts()
        code, _, err, target = self.record_of([paths["rlib"], paths["obj"]], "--note", "context line")
        self.assertEqual((code, err), (0, ""), err)
        record = json.loads(target.read_text())
        self.assertEqual((record["schema"], record["revision"], record["notes"]), ("ffw.d02.softfloat.record.v1", "53f83cf", ["context line"]))
        self.assertEqual(record["toolchain"]["release"], "1.101.0-nightly")
        self.assertEqual(record["toolchain"]["llvm_version"], "23.1.5")
        self.assertEqual(record["toolchain"]["cargo_home"], "the worker's rch cargo cache (path not recorded)")
        self.assertEqual(len(record["build"]["deviations"]), 3)
        self.assertEqual(record["build"]["modes"], ["obj", "rlib"])
        by_name = {a["name"]: a for a in record["artefacts"]}
        for kind, path in paths.items():
            self.assertEqual(by_name[path.name]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(by_name[path.name]["bytes"], path.stat().st_size)
        for name, reading in record["readings"].items():
            self.assertEqual((reading["verdict"], reading["exit_code"], reading["violations"]), ("PASS", 0, []), name)
            self.assertEqual(reading["f64_helper_call_sites_on_the_path"], {"__adddf3": 2, "__extendsfdf2": 1, "__muldf3": 5, "__subdf3": 2, "__truncdfsf2": 1})
        rlib_reading = record["readings"][paths["rlib"].name]
        self.assertEqual([n["member"] for n in rlib_reading["non_code_members"]], ["lib.rmeta", "lib.rmeta-link"])
        self.assertEqual(rlib_reading["objects_with_code"][0]["member"], CODE_NAME, "members are named, never given as paths")
        self.assertTrue(record["cross_check"]["byte_equal"])
        users = rlib_reading["f64_users_on_the_path"]
        self.assertEqual([u["call_path"] for u in users], [[tsf.sf.demangle(tsf.RENDER), tsf.sf.demangle(tsf.SECTION)]], "how each f64 user is reached")
        self.assertEqual(record["limits"], tsf.sf.LIMITS, "the record carries the checker's limits verbatim")
        self.assertEqual(record["checker"]["sha256"], hashlib.sha256((REPO / "toolchain/src/check-softfloat-symbols.py").read_bytes()).hexdigest())

    def test_a_fail_reading_is_recorded_as_a_fail_not_hidden_or_refused(self):
        plant = tsf.elf([tsf.func(tsf.RENDER, [tsf.SECTION, tsf.CONVERT]), tsf.func(tsf.SECTION, tsf.SECTION_OPS), tsf.func(tsf.CONVERT, ["__divdf3"])],
                        fp_abi=0)
        paths = self.artefacts(obj_code=plant, rlib_code=plant)
        code, _, err, target = self.record_of([paths["obj"]])
        self.assertEqual((code, err), (0, ""), err)
        reading = next(iter(json.loads(target.read_text())["readings"].values()))
        self.assertEqual((reading["verdict"], reading["exit_code"]), ("FAIL", 1))
        self.assertEqual([(v["rule"], v["helper"]) for v in reading["violations"]], [("helper-outside-section-set", "__divdf3")])

    def test_the_build_script_identity_is_the_committed_scripts(self):
        paths = self.artefacts()
        _, _, _, target = self.record_of([paths["obj"]])
        self.assertEqual(json.loads(target.read_text())["build"]["build_script_sha256"],
                         hashlib.sha256((REPO / "toolchain/src/softfloat-build.sh").read_bytes()).hexdigest())

    def test_the_record_is_deterministic(self):
        paths = self.artefacts()
        _, _, _, target = self.record_of([paths["rlib"], paths["obj"]])
        first = target.read_bytes()
        self.record_of([paths["rlib"], paths["obj"]])
        self.assertEqual(target.read_bytes(), first)

    def test_no_machine_path_or_worker_id_from_the_inputs_survives(self):
        paths = self.artefacts()
        for forbidden in ("/private/tmp", "/scratch/tmp", "rch-cargo-cache-trj", "artifact-found-at"):
            self.assertTrue(any(forbidden in p.parent.joinpath(f).read_text() for p in paths.values() for f in ("MANIFEST.txt", "rustc-vV.txt")),
                            f"the input files really do carry {forbidden}: otherwise this test proves nothing")
        _, _, _, target = self.record_of([paths["rlib"], paths["obj"]])
        text = target.read_text()
        self.assertEqual(leaks(text), [])
        self.assertNotIn(str(self.root), text)

    def test_a_leak_in_any_class_is_refused_and_nothing_is_written_and_the_clean_control_is_written(self):
        control = self.artefacts()
        code, _, _, written = self.record_of([control["rlib"]])
        self.assertEqual(code, 0, "the control, with no leak, is written")
        self.assertTrue(written.exists())
        for leak in ("/Users/someone/work", "/private/tmp/x", "/private/etc/hosts", "/tmp/y", "/scratch/data/z", "/scratch/tmp/z", "/home/ubuntu", "/var/folders/q", ".rch/shims/cargo",
                     "10.20.30.40", "built on trj", "built on hz3", "built on vmi1227854", "built on ovh-a", "built on mminiold", "built on ts1"):
            with self.subTest(leak=leak):
                self.tearDown_dirs = None
                sub = Fixture()
                sub.setUp()
                try:
                    paths = sub.artefacts(leak=f" {leak}")
                    code, _, err, target = sub.record_of([paths["rlib"], paths["obj"]])
                    self.assertEqual(code, 2, err)
                    self.assertIn("nothing was written", err)
                    self.assertFalse(target.exists(), "a record that would leak is never written")
                finally:
                    sub.tmp.cleanup()

    def test_a_leak_in_a_note_is_refused_too(self):
        paths = self.artefacts()
        code, _, err, target = self.record_of([paths["rlib"]], "--note", "run from /Users/someone/work")
        self.assertEqual(code, 2)
        self.assertFalse(target.exists())
        self.assertIn("a local home path", err)

    def test_a_refused_artefact_is_not_a_reading_and_is_not_recorded(self):
        paths = self.artefacts(rlib_code=tsf.BC_MAGIC + b"\0" * 28)  # a bitcode member
        code, _, err, target = self.record_of([paths["obj"], paths["rlib"]])
        self.assertEqual(code, 2)
        self.assertIn("bitcode-member", err)
        self.assertIn("a refusal is not a reading", err)
        self.assertFalse(target.exists())

    def test_missing_sidecar_files_are_refused(self):
        paths = self.artefacts()
        (paths["obj"].parent / "MANIFEST.txt").unlink()
        code, _, err, target = self.record_of([paths["obj"]])
        self.assertEqual(code, 2)
        self.assertIn("MANIFEST.txt", err)
        self.assertFalse(target.exists())

    def test_artefacts_built_by_different_compilers_cannot_share_a_record(self):
        paths = self.artefacts(obj_rustc=RUSTC.replace("708c94ef0", "deadbeef0").replace("1.101.0-nightly", "1.102.0-nightly"))
        code, _, err, _ = self.record_of([paths["rlib"], paths["obj"]])
        self.assertEqual(code, 2)
        self.assertIn("different compilers", err)

    def test_different_build_deviations_cannot_share_a_record(self):
        paths = self.artefacts(obj_leak="")
        text = (paths["obj"].parent / "MANIFEST.txt").read_text().replace("lto=off.", "lto=thin.")
        (paths["obj"].parent / "MANIFEST.txt").write_text(text)
        code, _, err, _ = self.record_of([paths["rlib"], paths["obj"]])
        self.assertEqual(code, 2)
        self.assertIn("different targets, cargo configurations or deviations", err)

    def test_the_cross_check_says_so_when_the_code_differs(self):
        other = tsf.control_object(fp_abi=0, pic=True, rela=True)  # different bytes, same reading
        paths = self.artefacts(obj_code=other)
        _, _, _, target = self.record_of([paths["rlib"], paths["obj"]])
        cross = json.loads(target.read_text())["cross_check"]
        self.assertFalse(cross["byte_equal"])
        self.assertIn("differs", cross["meaning"])

    def test_a_single_artefact_has_no_cross_check(self):
        paths = self.artefacts()
        _, _, _, target = self.record_of([paths["obj"]])
        self.assertEqual(json.loads(target.read_text())["cross_check"], {})


class CommittedRecord(unittest.TestCase):
    """toolchain/results/d02/softfloat-53f83cf/: the evidence the D02 and D01 soft-float rows cite."""

    def setUp(self):
        self.raw = (COMMITTED / "softfloat-record.json").read_text(encoding="utf-8")
        self.record = json.loads(self.raw)
        self.md = (COMMITTED / "RESULT.md").read_text(encoding="utf-8")

    def test_shape_and_identity(self):
        self.assertEqual(self.record["schema"], "ffw.d02.softfloat.record.v1")
        self.assertEqual(self.record["revision"], "53f83cf")
        self.assertIn("no device", self.record["scope"])
        self.assertEqual(self.record["toolchain"]["release"], "1.101.0-nightly")
        self.assertRegex(self.record["toolchain"]["commit_hash"], r"^[0-9a-f]{40}$")
        for item in self.record["artefacts"]:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
        for key in ("sha256", "script"):
            self.assertTrue(self.record["checker"][key])
        self.assertRegex(self.record["build"]["build_script_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(self.record["build"]["deviations"]), 3)
        self.assertTrue(self.record["build"]["deviations"][0].startswith("lto=off."))

    def test_nothing_that_identifies_the_machine_or_the_fleet(self):
        self.assertEqual(leaks(self.raw), [])
        self.assertEqual(leaks(self.md), [])

    def test_every_reading_is_a_pass_and_its_arithmetic_is_sound(self):
        self.assertEqual(len(self.record["readings"]), 2)
        for name, r in self.record["readings"].items():
            with self.subTest(name=name):
                self.assertEqual((r["verdict"], r["exit_code"], r["violations"]), ("PASS", 0, []))
                totals = {}
                for user in r["f64_users_on_the_path"]:
                    for helper, n in user["helpers"].items():
                        totals[helper] = totals.get(helper, 0) + n
                    self.assertEqual(user["call_path"][0], "franken_dsp::protection::runtime::ProtectedBoardDsp::render_into")
                    self.assertTrue(user["call_path"][-1].endswith(user["function"].rsplit("::", 1)[-1]))
                self.assertEqual(totals, r["f64_helper_call_sites_on_the_path"], "the per-function counts add up to the total")
                self.assertTrue(set(totals) <= set(r["allowed_helpers"]), "no helper outside the allowed five")
                self.assertEqual(len(r["objects_with_code"]), 1)
                self.assertEqual(r["objects_with_code"][0]["code_sections"], r["code_sections"])
                names = {u["function"] for u in r["f64_users_on_the_path"]}
                self.assertFalse([f for f in r["convert_functions_on_the_path"] if f in names], "no conversion function is an f64 user")
                self.assertGreaterEqual(len(r["convert_functions_on_the_path"]), 1, "the conversion is on the path as symbols, so it was read directly")

    def test_the_render_path_reading_matches_the_source(self):
        r = next(iter(self.record["readings"].values()))
        users = {u["function"].rsplit("::", 2)[-2] + "::" + u["function"].rsplit("::", 1)[-1]: u for u in r["f64_users_on_the_path"]}
        render = users["ProtectedBoardDsp::render_into"]
        self.assertEqual(render["helpers"], {"__extendsfdf2": 1, "__muldf3": 5, "__adddf3": 2, "__subdf3": 2, "__truncdfsf2": 1},
                         "Section::process: 1 widen, 5 mul, 2 add, 2 sub, 1 narrow")
        self.assertEqual(render["section_process_copies"], 1)
        stored = users["Section::from_stored"]
        self.assertEqual(stored["helpers"], {"__extendsfdf2": 5}, "five `as f64` casts")
        self.assertEqual([p.rsplit("::", 1)[-1] for p in stored["call_path"]], ["render_into", "install", "from_stored"])

    def test_the_two_artefacts_carry_the_same_machine_code(self):
        cross = self.record["cross_check"]
        self.assertTrue(cross["byte_equal"])
        shas = {r["objects_with_code"][0]["sha256"] for r in self.record["readings"].values()}
        self.assertEqual(shas, {cross["rlib_code_member_sha256"]})
        self.assertEqual(cross["rlib_code_member_sha256"], cross["separately_built_object_sha256"])

    def test_the_limits_are_in_the_record(self):
        text = " ".join(self.record["limits"])
        for needle in ("not the final LTO'd and linked speaker ELF", "fat-LTO'd and may inline differently", "CALL SITES", "indirect call"):
            self.assertIn(needle, text)

    def test_result_md_quotes_the_record_and_says_what_it_does_not_show(self):
        r = self.record["readings"][next(a["name"] for a in self.record["artefacts"] if a["kind"] == "rlib")]
        self.assertIn(str(r["code_sections"]), self.md)
        self.assertIn(str(r["reachable_sections"]), self.md)
        for helper, n in r["f64_helper_call_sites_on_the_path"].items():
            self.assertIn(f"`{helper}` {n}", self.md)
        for item in self.record["artefacts"]:
            self.assertIn(item["sha256"][:16], self.md)
            self.assertIn(f"{item['bytes']:,}", self.md)
        self.assertIn(self.record["cross_check"]["rlib_code_member_sha256"][:16], self.md)
        self.assertIn(str(r["objects_with_code"][0]["executable_words_scanned"]).replace("26881", "26,881"), self.md)
        for needle in ("LTO off", "not the shipped fat-LTO speaker ELF", "Nothing was executed", "call sites", "doubled", "owner's decision",
                       "ProtectedBoardDsp::render_into", "Section::from_stored", "f32_to_s16", "f32_to_int", "pending.take()"):
            self.assertIn(needle, self.md)


if __name__ == "__main__":
    unittest.main()
