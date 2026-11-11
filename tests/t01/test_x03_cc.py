"""Tests of the PowerPC C compiler adapter for the T01-X03 big-endian builds (tests/tailscale-fixtures/x03/cc/zig-cc-powerpc-be-ccrs, bead ffw-32a).
Standard library only, offline, no cargo, no Zig: the adapter runs against a stand-in `zig` that prints its arguments.

Run: python3 -B -W error -m unittest tests/t01/test_x03_cc.py   (from the repository root)

The adapter exists because cc-rs appends `--target=powerpc-unknown-linux-musl`, which Zig cannot parse (the same failure the first MIPS C attempt had, tests/t01
test_t01.py). It is the PowerPC twin of x01-cc/zig-cc-mips-be-ccrs-v2 and is NOT under x01-cc/, whose file list the X01 build judge pins. These tests pin its
bytes, its exact Zig target and its refusal of every other target override, each beside a planted negative and a control (the real file passes, a changed copy
is refused for the named reason). The pinned hash is hand-written: a change to the adapter must change it here on purpose.
"""
import hashlib
import os
import re
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ADAPTER = os.path.join(REPO, "tests", "tailscale-fixtures", "x03", "cc", "zig-cc-powerpc-be-ccrs")
LINKER = os.path.join(REPO, "toolchain", "linker", "zig-cc-powerpc-be")
PINNED_SHA256 = "9ab422ba8d25a45c33122722002ecf9b8f2a9b70198359f3df390ccfd85a1005"
ZIG_TARGET = "powerpc-linux-musleabihf"  # zig's hard-float big-endian ppc32 musl target: the float ABI the repository's linker driver and rustc's spec agree on
RUST_SPELLING = "--target=powerpc-unknown-linux-musl"
STAND_IN_ZIG = '#!/bin/sh\nif [ "$1" = version ]; then printf "%s\\n" "$FAKE_ZIG_VERSION"; exit 0; fi\nprintf "ARG:%s\\n" "$@"\n'


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def run(adapter, version, *args, interpreter="sh"):
    """Run one adapter with a stand-in `zig` first on PATH. Returns (exit code, the arguments the stand-in zig received, stderr)."""
    with tempfile.TemporaryDirectory() as tmp:
        fake = os.path.join(tmp, "zig")
        with open(fake, "w", encoding="utf-8") as handle:
            handle.write(STAND_IN_ZIG)
        os.chmod(fake, 0o755)
        argv = [interpreter, adapter, *args] if interpreter else [adapter, *args]
        done = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60,
                              env={"PATH": tmp + os.pathsep + "/usr/bin:/bin", "FAKE_ZIG_VERSION": version, "HOME": tmp})
    return done.returncode, [line[4:] for line in done.stdout.splitlines() if line.startswith("ARG:")], done.stderr


def problems(adapter):
    """Everything the adapter must do, as a list of the contract lines it breaks; empty for the real one."""
    found = []
    code, args, _ = run(adapter, "0.14.1", "-O0", RUST_SPELLING, "-c", "x.c")
    if (code, args) != (0, ["cc", "-target", ZIG_TARGET, "-O0", "-c", "x.c"]):
        found.append(f"the Rust target spelling is not dropped, or the target or the order is wrong: {(code, args)}")
    code, args, _ = run(adapter, "0.14.1", f"--target={ZIG_TARGET}", "-c", "x.c")
    if (code, args) != (0, ["cc", "-target", ZIG_TARGET, "-c", "x.c"]):
        found.append(f"the Zig spelling of the same target is not accepted once: {(code, args)}")
    code, args, _ = run(adapter, "0.14.1", "-DTARGET=1", "-Itarget/include", "-Wno-error=target", "-c", "x.c")
    if (code, args) != (0, ["cc", "-target", ZIG_TARGET, "-DTARGET=1", "-Itarget/include", "-Wno-error=target", "-c", "x.c"]):
        found.append(f"a flag that only mentions target is not forwarded: {(code, args)}")
    code, args, _ = run(adapter, "0.14.1", "-DNAME=two words", "-I", "a dir", "-c", "x.c")
    if (code, args) != (0, ["cc", "-target", ZIG_TARGET, "-DNAME=two words", "-I", "a dir", "-c", "x.c"]):
        found.append(f"an argument with a space is not kept whole: {(code, args)}")
    for override in (["--target=powerpc-unknown-linux-gnu"], ["--target", "powerpc-unknown-linux-gnu"], ["-target", "powerpc-unknown-linux-gnu"],
                     ["-target=powerpc-unknown-linux-gnu"], ["--target"], ["-target"], ["--target", "powerpc-unknown-linux-musl"]):
        code, args, err = run(adapter, "0.14.1", "-O0", *override, "-c", "x.c")
        if (code, args, "unsupported target override" in err) != (98, [], True):
            found.append(f"the target override {override} is not refused with exit 98 before Zig runs: {(code, args)}")
    code, args, err = run(adapter, "0.15.0", "-c", "x.c")
    if (code, args, "zig 0.14.1 required, found 0.15.0" in err) != (97, [], True):
        found.append(f"a different Zig is not refused with exit 97: {(code, args)}")
    return found


class TheAdapterFile(unittest.TestCase):
    def test_the_bytes_the_mode_and_the_shell_are_the_pinned_ones(self):
        with open(ADAPTER, "rb") as handle:
            body = handle.read()
        self.assertEqual(hashlib.sha256(body).hexdigest(), PINNED_SHA256)
        self.assertEqual(stat.S_IMODE(os.stat(ADAPTER).st_mode), 0o755)
        self.assertTrue(body.startswith(b"#!/bin/sh\n"))
        self.assertEqual(subprocess.run(["sh", "-n", ADAPTER], capture_output=True, timeout=60).returncode, 0)
        text = body.decode("utf-8")
        self.assertIn("want=0.14.1", text)                                                         # the Zig version is enforced by the file, like the other wrappers
        self.assertEqual(re.findall(r"zig cc -target (\S+)", text), [ZIG_TARGET])                  # exactly one compiler invocation, with exactly this target

    def test_it_runs_as_a_program_and_under_dash_as_well_as_sh(self):
        for interpreter in ("sh", "dash", None):                                                   # None: executed directly through its shebang and its mode
            if interpreter == "dash" and not os.path.exists("/bin/dash"):
                continue
            with self.subTest(interpreter=interpreter):
                self.assertEqual(run(ADAPTER, "0.14.1", RUST_SPELLING, "-c", "x.c", interpreter=interpreter)[:2], (0, ["cc", "-target", ZIG_TARGET, "-c", "x.c"]))

    def test_its_zig_target_is_the_one_the_repositorys_linker_driver_uses(self):
        linker_targets = re.findall(r"zig cc -target (\S+)", read(LINKER))
        self.assertEqual(linker_targets, [ZIG_TARGET])                                             # the final link and the C objects agree on the float ABI
        self.assertEqual(re.findall(r"zig cc -target (\S+)", read(ADAPTER)), linker_targets)


class TheAdapterBehaviour(unittest.TestCase):
    def test_soft_float_overrides_are_refused_without_blocking_hard_float(self):
        for flag in ("-msoft-float", "-mfloat-abi=soft", "-mfloat-abi=softfp"):
            with self.subTest(flag=flag):
                code, args, err = run(ADAPTER, "0.14.1", "-c", flag, "x.c")
                self.assertEqual((code, args), (98, []))
                self.assertIn("unsupported float ABI override", err)
        code, args, _ = run(ADAPTER, "0.14.1", "-mhard-float", "-DNAME=-msoft-float", "-c", "x.c")
        self.assertEqual((code, args), (0, ["cc", "-target", ZIG_TARGET, "-mhard-float", "-DNAME=-msoft-float", "-c", "x.c"]))

    def test_the_real_adapter_breaks_none_of_its_contract(self):
        self.assertEqual(problems(ADAPTER), [])

    def test_each_planted_change_is_refused_for_its_named_reason_and_the_control_passes(self):
        original = read(ADAPTER)
        plants = {
            "soft float": (f"exec zig cc -target {ZIG_TARGET}", "exec zig cc -target powerpc-linux-musleabi", "or the target"),
            "the Rust spelling forwarded": (f"{RUST_SPELLING}|--target={ZIG_TARGET}) ;;", f"--target={ZIG_TARGET}) ;;", "Rust target spelling is not dropped"),
            "an override accepted": ("--target=*|--target|-target|-target=*)", "--never-matches)", "is not refused with exit 98"),
            "another Zig accepted": ("want=0.14.1", "want=0.15.0", "a different Zig is not refused"),
            "arguments split at spaces": ('*) set -- "$@" "$arg" ;;', '*) set -- "$@" $arg ;;', "not kept whole"),
        }
        self.assertEqual(problems(ADAPTER), [])
        for label, (old, new, words) in plants.items():
            with self.subTest(label):
                self.assertEqual(original.count(old), 1, old)                                      # a plant that changes nothing must not be mistaken for a rule that holds
                with tempfile.TemporaryDirectory() as tmp:
                    planted = os.path.join(tmp, "adapter")
                    with open(planted, "w", encoding="utf-8") as handle:
                        handle.write(original.replace(old, new, 1))
                    found = problems(planted)
                    self.assertTrue(found, label)
                    self.assertIn(words, " | ".join(found), label)
                    with open(planted, "w", encoding="utf-8") as handle:
                        handle.write(original)                                                      # the plant, undone
                    self.assertEqual(problems(planted), [], label)

    def test_a_changed_byte_moves_the_pinned_hash_even_when_the_behaviour_is_unchanged(self):
        original = read(ADAPTER)
        changed = original.replace("# Plain sh", "# plain sh", 1)                                  # a comment only: every behaviour check still passes
        self.assertNotEqual(changed, original)
        self.assertNotEqual(hashlib.sha256(changed.encode("utf-8")).hexdigest(), PINNED_SHA256)
        self.assertEqual(hashlib.sha256(original.encode("utf-8")).hexdigest(), PINNED_SHA256)


if __name__ == "__main__":
    unittest.main()
