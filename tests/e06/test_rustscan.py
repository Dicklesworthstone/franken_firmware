"""E06 lexer tests.  Every input is hand-written; every expected value is stated here, not derived from the
code under test.  The lexer is judged on the facts the audit relies on, one planted trap at a time."""
import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
SCAN = os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts", "e06", "rustscan.py")
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("ffw_e06_rustscan", SCAN)
RS = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = RS
_spec.loader.exec_module(RS)


def unsafe_lines(src):
    return RS.scan_source(src).unsafe_lines


class UnsafeKeywordTests(unittest.TestCase):
    def test_real_unsafe_constructs_are_each_counted_with_their_line(self):
        src = "fn a() { unsafe { x() } }\nunsafe fn b() {}\nunsafe impl Send for T {}\nunsafe trait U {}\n"
        self.assertEqual(unsafe_lines(src), [1, 2, 3, 4])

    def test_edition_2024_unsafe_attribute_and_extern_block_are_counted(self):
        src = '#[unsafe(no_mangle)]\npub extern "C" fn f() {}\nunsafe extern "C" { fn g(); }\n'
        self.assertEqual(unsafe_lines(src), [1, 3])

    def test_the_lint_name_is_not_the_keyword(self):
        self.assertEqual(unsafe_lines("#![forbid(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n"), [])

    def test_comments_do_not_count_including_nested_block_and_doc_comments(self):
        src = ("// unsafe\n/// unsafe { }\n//! unsafe\n/* unsafe /* unsafe */ still comment unsafe */\n"
               "fn ok() {}\n")
        self.assertEqual(unsafe_lines(src), [])

    def test_a_real_unsafe_after_a_nested_comment_is_still_found_on_the_right_line(self):
        src = "/* a /* b */ c\n d */\nunsafe fn f() {}\n"
        self.assertEqual(unsafe_lines(src), [3])

    def test_string_and_raw_string_literals_do_not_count(self):
        src = ('const A: &str = "unsafe { }";\nconst B: &str = r#"unsafe " still inside"#;\n'
               'const C: &[u8] = b"unsafe";\nconst D: &str = r"unsafe";\nfn ok() {}\n')
        self.assertEqual(unsafe_lines(src), [])

    def test_code_after_a_raw_string_that_contains_a_quote_is_not_swallowed(self):
        src = 'const B: &str = r#"has " quote"#;\nunsafe fn f() {}\n'
        self.assertEqual(unsafe_lines(src), [2])

    def test_escaped_quote_inside_a_string_does_not_end_it_early(self):
        src = 'const S: &str = "a \\" unsafe \\" b";\nunsafe fn f() {}\n'
        self.assertEqual(unsafe_lines(src), [2])

    def test_char_literals_and_lifetimes_are_told_apart(self):
        # 'a' is a char; 'a is a lifetime; '\'' is an escaped quote char.  None may swallow the unsafe that follows.
        src = "fn f<'a>(x: &'a u8) -> char { let c = 'a'; let q = '\\''; let u = '\\u{1F600}'; c }\nunsafe fn g() {}\n"
        self.assertEqual(unsafe_lines(src), [2])

    def test_a_raw_identifier_named_unsafe_is_a_name_not_the_keyword(self):
        self.assertEqual(unsafe_lines("let r#unsafe = 1;\n"), [])

    def test_unsafe_inside_a_macro_body_is_found_because_the_body_is_in_the_source(self):
        src = "macro_rules! m { () => { unsafe { 1 } }; }\n"
        self.assertEqual(unsafe_lines(src), [1])


class FloatAndAllocTests(unittest.TestCase):
    def facts(self, src):
        return RS.scan_source(src)

    def test_float_types_and_literals_are_floats(self):
        for src in ("let x: f32 = 0;", "let x = 1.5;", "let x = 2e3;", "let x = 3f64;", "let x = 1_000.0_f32;"):
            with self.subTest(src=src):
                self.assertTrue(self.facts(src).uses_float)

    def test_integers_ranges_tuple_indexes_and_method_calls_are_not_floats(self):
        for src in ("let x = 10;", "let r = 0..1;", "let y = t.0.1;", "let z = 1.max(2);", "let h = 0x1f32;",
                    "let u = 5usize;", 'let s = "f32 1.5";', "// f64 2.5\nfn f() {}"):
            with self.subTest(src=src):
                self.assertFalse(self.facts(src).uses_float)

    def test_alloc_references(self):
        self.assertTrue(self.facts("extern crate alloc;").uses_alloc)
        self.assertTrue(self.facts("use alloc::vec::Vec;").uses_alloc)
        self.assertFalse(self.facts("use core::fmt;").uses_alloc)
        self.assertFalse(self.facts('const A: &str = "alloc::Vec";').uses_alloc)


class CrateAttributeTests(unittest.TestCase):
    def facts(self, src):
        return RS.scan_source(src)

    def test_unconditional_no_std(self):
        f = self.facts("#![no_std]\nfn f() {}\n")
        self.assertTrue(f.no_std)
        self.assertEqual(f.cfg_no_std, [])

    def test_conditional_no_std_is_recorded_with_its_predicate(self):
        f = self.facts('#![cfg_attr(not(feature = "std"), no_std)]\n')
        self.assertFalse(f.no_std)
        self.assertEqual([RS.cfg_text(e) for e in f.cfg_no_std], ['not(feature = "std")'])

    def test_forbid_deny_and_allow_lints_are_recorded_by_level(self):
        f = self.facts("#![forbid(unsafe_code)]\n#![deny(missing_docs, clippy::unwrap_used)]\n#![allow(dead_code)]\n")
        self.assertEqual([(lvl, name) for lvl, name, _ in f.lints],
                         [("forbid", "unsafe_code"), ("deny", "missing_docs"), ("deny", "clippy::unwrap_used"),
                          ("allow", "dead_code")])

    def test_a_conditional_forbid_keeps_its_condition_and_is_not_unconditional(self):
        f = self.facts('#![cfg_attr(feature = "strict", forbid(unsafe_code))]\n')
        self.assertEqual([(lvl, name, RS.cfg_text(c)) for lvl, name, c in f.lints],
                         [("forbid", "unsafe_code", 'feature = "strict"')])

    def test_an_inner_attribute_inside_a_block_is_not_a_crate_attribute(self):
        f = self.facts("mod m { #![no_std] }\nfn f() { #![forbid(unsafe_code)] }\n")
        self.assertFalse(f.no_std)
        self.assertEqual(f.lints, [])

    def test_attribute_text_in_a_string_or_comment_is_not_an_attribute(self):
        f = self.facts('// #![no_std]\nconst S: &str = "#![forbid(unsafe_code)]";\n')
        self.assertFalse(f.no_std)
        self.assertEqual(f.lints, [])


class ExternStdTests(unittest.TestCase):
    """A #![no_std] crate can bring std back under a feature; the gate must be recorded, not ignored."""

    def gates(self, src):
        return [None if g is None else RS.cfg_text(g) for g in RS.scan_source(src).extern_std]

    def test_a_feature_gated_extern_crate_std_records_its_gate(self):
        self.assertEqual(self.gates('#![no_std]\n#[cfg(feature = "std")]\nextern crate std;\n'), ['feature = "std"'])

    def test_an_unconditional_extern_crate_std_has_no_gate(self):
        self.assertEqual(self.gates("#![no_std]\nextern crate std;\n"), [None])

    def test_other_attributes_between_the_gate_and_the_item_are_skipped_and_gates_are_anded(self):
        src = '#[cfg(feature = "a")]\n#[macro_use]\n#[cfg(not(test))]\nextern crate std;\n'
        self.assertEqual(self.gates(src), ['all(feature = "a", not(test))'])

    def test_a_gate_belonging_to_the_previous_item_does_not_leak_onto_the_next(self):
        src = '#[cfg(feature = "x")]\nfn f() {}\nextern crate std;\n'
        self.assertEqual(self.gates(src), [None])

    def test_mentions_in_strings_and_comments_and_other_crates_are_not_extern_crate_std(self):
        src = '// extern crate std;\nconst S: &str = "extern crate std;";\nextern crate alloc;\nextern crate core;\n'
        self.assertEqual(self.gates(src), [])

    def test_a_disjunction_gate_as_memchr_spells_it(self):
        self.assertEqual(self.gates('#[cfg(any(test, feature = "std"))]\nextern crate std;\n'),
                         ['any(test, feature = "std")'])


class CfgEvaluationTests(unittest.TestCase):
    def ev(self, text, features=()):
        expr, _ = RS.parse_cfg(RS.tokenize(text))
        return RS.eval_cfg(expr, set(features))

    def test_feature_predicates(self):
        self.assertIs(self.ev('feature = "std"', ["std"]), True)
        self.assertIs(self.ev('feature = "std"', []), False)
        self.assertIs(self.ev('not(feature = "std")', []), True)
        self.assertIs(self.ev('all(feature = "a", feature = "b")', ["a"]), False)
        self.assertIs(self.ev('any(feature = "a", feature = "b")', ["b"]), True)

    def test_known_build_flags(self):
        self.assertIs(self.ev("test"), False)
        self.assertIs(self.ev("not(test)"), True)
        self.assertIs(self.ev('not(any(feature = "std", test))', []), True)

    def test_unmodelled_predicates_stay_unknown_and_never_become_a_guess(self):
        self.assertIsNone(self.ev('target_os = "linux"'))
        self.assertIsNone(self.ev('not(target_os = "linux")'))
        self.assertIsNone(self.ev('all(feature = "std", target_os = "linux")', ["std"]))
        # ... but a False operand still decides `all` and a True operand still decides `any`.
        self.assertIs(self.ev('all(feature = "std", target_os = "linux")', []), False)
        self.assertIs(self.ev('any(feature = "std", target_os = "linux")', ["std"]), True)

    def test_text_round_trip(self):
        expr, _ = RS.parse_cfg(RS.tokenize('all(not(feature = "std"), any(test, feature = "x"))'))
        self.assertEqual(RS.cfg_text(expr), 'all(not(feature = "std"), any(test, feature = "x"))')


class BuildScriptSignalTests(unittest.TestCase):
    def sig(self, src):
        return RS.scan_build_script(src)

    def test_a_probe_only_script_has_no_native_signal(self):
        s = self.sig('fn main() { println!("cargo:rustc-cfg=has_foo"); println!("cargo:rerun-if-changed=build.rs"); }')
        self.assertEqual((s.link_directives, s.spawns_process, s.native_tooling), ([], False, []))

    def test_link_directives_are_found_inside_string_literals(self):
        s = self.sig('fn main() { println!("cargo:rustc-link-lib=static=z"); println!("cargo:rustc-link-search=/x"); }')
        self.assertEqual(sorted(s.link_directives), ["rustc-link-lib", "rustc-link-search"])

    def test_process_spawn_and_native_tooling_paths(self):
        s = self.sig('use std::process::Command;\nfn main() { cc::Build::new().file("a.c").compile("a"); '
                     'let _ = Command::new("pkg-config"); pkg_config::probe_library("z"); }')
        self.assertTrue(s.spawns_process)
        self.assertEqual(sorted(s.native_tooling), ["cc", "pkg_config"])

    def test_a_typed_variable_named_cc_is_not_a_tooling_path(self):
        self.assertEqual(self.sig("fn main() { let cc: u8 = 1; }").native_tooling, [])

    def test_markers_in_comments_do_not_count(self):
        self.assertEqual(self.sig('// println!("cargo:rustc-link-lib=z");\nfn main() {}').link_directives, [])


if __name__ == "__main__":
    unittest.main()
