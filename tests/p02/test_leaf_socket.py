#!/usr/bin/env python3
"""P02 (ffw-jub): the Linux leaf's socket backend, the Python half.  Contract: docs/contracts/p02.md, "The socket capability", "The leaf backend".

The leaf's socket code exists only on the big-endian MIPS and PowerPC targets, the Rust is never compiled here, and no guest has issued a `socketcall`.
What a host can hold, this file holds:

* `sys.rs` keeps the leaf's unsafe small and checkable: the two trampolines and ONE executor are the only `unsafe fn`; every `unsafe` block has a SAFETY
  comment; the five socket wrappers call the executor and nothing else, type no number (they build their words with `socket_route`, which takes the route from
  the plan), and a compile-time assertion checks each route fits the trampoline; no `fcntl`, `accept` or `uname` appears.
* `socket_route.rs` has no `unsafe`; `issue_for` types no number; `admit` decides by the route (sub-call 18 through `socketcall`), not by the ABI's name.
* The admission is held to an independent model built from the kernel evidence (`tests/p02/socket_kernel_evidence.json`): the kernel whose sub-call 18 is
  `paccept`, the first kernel where it is `accept4`, the largest `nargs` entry, and the sub-call number are DERIVED from those lines and compared with the Rust
  constants; every release string in the Rust tests is classified by the model and must land where the test puts it.
* The Rust test that pins the issued words is held to the plan's rows (parsed from `numbers.rs`).
* The contract's counts and cited test names equal the files'.
Each check has a planted fault that it must report.  Offline, stdlib only."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_socket_slice as tss  # noqa: E402  (the kernel facts derived from the evidence lines, and the source helpers)
import test_syscall_numbers as tsn  # noqa: E402

ROOT = tsn.ROOT
LEAF_SRC = os.path.join(ROOT, "crates", "franken-platform-linux", "src")
SYS_RS = os.path.join(LEAF_SRC, "sys.rs")
ROUTE_RS = os.path.join(LEAF_SRC, "socket_route.rs")
LEAF_LIB = os.path.join(LEAF_SRC, "lib.rs")
READ = tsn.read
BUILDER_CALLS = {"socket": "socket_args(domain, kind, protocol)", "bind": "bind_args(fd, addr.as_ptr() as usize, addr.len())", "listen": "listen_args(fd, backlog)",
                 "accept4": "accept4_args(fd, flags)", "recv": "recv_args(fd, buf.as_mut_ptr() as usize, buf.len(), flags)"}
SOCKET_CALLS = {"socket": "sys::socket(domain, kind, protocol)", "bind": "sys::bind(fd, addr)", "listen": "sys::listen(fd, backlog)", "accept4": "sys::accept4(fd, flags)",
                "recv": "sys::recv(fd, buf, flags)"}
KERNEL_CALLS = {"provenance": "self.kernel.provenance()", "backend_abi": "self.kernel.backend_abi()", "clock_gettime_monotonic": "self.kernel.clock_gettime_monotonic(out)",
                "getrandom": "self.kernel.getrandom(buf, flags)", "open_dev_random": "self.kernel.open_dev_random(flags)", "eventfd2": "self.kernel.eventfd2(initval, flags)",
                "pipe2": "self.kernel.pipe2(fds, flags)", "write": "self.kernel.write(fd, buf)", "read": "self.kernel.read(fd, buf)", "close": "self.kernel.close(fd)"}
OPS = (("socket", "Socket", "socket_args"), ("bind", "Bind", "bind_args"), ("listen", "Listen", "listen_args"), ("accept4", "Accept4", "accept4_args"),
       ("recv", "Recv", "recv_args"))


def fn_body(code, name):
    """The brace-matched body of the first `fn <name>(` in `code` (comments already stripped), or None."""
    match = re.search(r"\bfn %s\s*(?:<[^>]*>)?\(" % re.escape(name), code)
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


def non_test(source):
    return source.split("#[cfg(test)]\nmod tests {", 1)[0]


def typed_numbers(body):
    """Integer literals in `body` other than 0, ignoring array indices (`args[3]`)."""
    return re.findall(r"(?<![\w.])(?!0\b)\d+\b", re.sub(r"\[\d+\]", "[]", body))


# ---- sys.rs -----------------------------------------------------------------------------------------------------------------------------

def sys_problems(src):
    code = tss.code_only(src)
    out = []
    names = sorted(re.findall(r"\bunsafe fn (\w+)", code))
    if names != ["execute", "raw5", "raw5"]:
        out.append("the unsafe fns are %s, expected exactly the two raw5 trampolines and execute" % names)
    lines = src.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\bunsafe \{", line) and not line.strip().startswith("//") and "SAFETY" not in "\n".join(lines[max(0, i - 4):i]):
            out.append("the unsafe block at line %d has no SAFETY comment above it" % (i + 1))
    for name, op, builder in OPS:
        body = fn_body(code, name)
        if body is None:
            out.append("sys.rs has no wrapper %s" % name)
            continue
        if "raw5(" in body:
            out.append("the %s wrapper calls raw5 itself instead of the executor" % name)
        if len(re.findall(r"unsafe \{ execute\(issue\) \}", body)) != 1:
            out.append("the %s wrapper does not end in exactly one `unsafe { execute(issue) }`" % name)
        if "issue_for(COMPILED_ABI, SocketOp::%s," % op not in re.sub(r"\s+", " ", body).replace("issue_for( COMPILED_ABI", "issue_for(COMPILED_ABI"):
            out.append("the %s wrapper does not ask issue_for for SocketOp::%s on COMPILED_ABI" % (name, op))
        if BUILDER_CALLS[name] not in re.sub(r"\s+", " ", body):
            out.append("the %s wrapper does not build its words with %s" % (name, BUILDER_CALLS[name]))
        if typed_numbers(body):
            out.append("the %s wrapper types a number: %s" % (name, typed_numbers(body)))
    execute = fn_body(code, "execute")
    if execute is None:
        out.append("sys.rs has no executor")
    else:
        if len(re.findall(r"\braw5\(", execute)) != 2:
            out.append("execute must call raw5 exactly twice (direct, socketcall)")
        if "Issue::Direct" not in execute or "Issue::SocketCall" not in execute or execute.count("block.as_ptr() as usize") != 1:
            out.append("execute does not match both Issue arms or does not pass the block's address once")
        if typed_numbers(execute):
            out.append("execute types a number: %s" % typed_numbers(execute))
    assertions = re.findall(r"assert!\(plan\.(\w+)\.fits_the_leaf\(\)\);", code)
    if sorted(assertions) != sorted(name for name, _, _ in OPS):
        out.append("the compile-time fit assertions are %s, expected one per socket route" % sorted(assertions))
    if re.search(r"\bfcntl\b|\buname\b|\baccept\(", code):
        out.append("sys.rs mentions fcntl, uname or a plain accept in code")
    if "5. A `socketcall` block" not in src:
        out.append("the module documentation lacks invariant 5 (the socketcall block)")
    if len(re.findall(r"pub\(crate\) fn (?:%s)\(" % "|".join(name for name, _, _ in OPS), code)) != 5:
        out.append("sys.rs must have exactly the five socket wrappers as pub(crate) fns")
    return out


def route_problems(src):
    code = tss.code_only(non_test(src))
    out = []
    if re.search(r"\bunsafe\b", code):
        out.append("socket_route.rs mentions unsafe in code")
    issue = fn_body(code, "issue_for")
    if issue is None or "socket_plan_for(abi)" not in issue or "Route::Direct" not in issue or "Route::ViaSocketCall" not in issue:
        out.append("issue_for does not route by the plan (socket_plan_for(abi), both Route arms)")
    elif typed_numbers(issue):
        out.append("issue_for types a number: %s" % typed_numbers(issue))
    admit = fn_body(code, "admit")
    if admit is None or "Route::ViaSocketCall" not in admit or "ACCEPT4_SUBCALL" not in admit:
        out.append("admit does not decide by the route (a socketcall route through sub-call 18)")
    elif re.search(r"\bAbi::", admit):
        out.append("admit decides by the ABI's name instead of the route")
    return out


def rust_version(src, constant):
    match = re.search(r"pub const %s: KernelVersion = KernelVersion \{\s*major: (\d+),\s*minor: (\d+),\s*patch: (\d+),?\s*\};" % constant, src)
    return tuple(int(group) for group in match.groups()) if match else None


def tag_version(tag):
    return tuple(int(part) for part in tag.split("_"))


class SysShapeTests(unittest.TestCase):
    def setUp(self):
        self.src = READ(SYS_RS)

    def test_the_real_sys_rs_keeps_the_leafs_unsafe_small_and_checkable(self):
        self.assertEqual(sys_problems(self.src), [])

    def test_each_planted_fault_in_sys_rs_is_reported(self):
        plants = [
            ("a wrapper calls raw5 itself", "    // SAFETY: invariants 1 and 5; no address word.\n    unsafe { execute(issue) }\n}\n\n/// `bind(",
             "    // SAFETY: invariants 1 and 5; no address word.\n    unsafe { raw5(1, 2, 3, 4, 0, 0) }\n}\n\n/// `bind(", "raw5 itself"),
            ("a second executor", "unsafe fn execute(issue: Issue) -> isize {", "unsafe fn execute_again(issue: Issue) -> isize {\n    execute(issue)\n}\n\nunsafe fn execute(issue: Issue) -> isize {", "unsafe fns"),
            ("an unsafe block loses its SAFETY comment", "    // SAFETY: invariants 1 and 5; no address word.\n    unsafe { execute(issue) }\n}\n\n/// `bind(",
             "    unsafe { execute(issue) }\n}\n\n/// `bind(", "SAFETY"),
            ("a number is typed in a wrapper", "fn listen(fd: i32, backlog: i32) -> isize {\n    let issue = issue_for(COMPILED_ABI, SocketOp::Listen, listen_args(fd, backlog));",
             "fn listen(fd: i32, backlog: i32) -> isize {\n    let issue = issue_for(COMPILED_ABI, SocketOp::Listen, listen_args(fd, backlog + 128));", "types a number"),
            ("the wrapper asks for the wrong op", "SocketOp::Accept4,", "SocketOp::Listen,", "SocketOp::Accept4"),
            ("bind swaps the address and its length", "bind_args(fd, addr.as_ptr() as usize, addr.len())", "bind_args(fd, addr.len(), addr.as_ptr() as usize)", "bind_args(fd, addr.as_ptr()"),
            ("listen swaps the descriptor and the backlog", "listen_args(fd, backlog)", "listen_args(backlog, fd)", "listen_args(fd, backlog)"),
            ("recv passes the length for the buffer", "recv_args(fd, buf.as_mut_ptr() as usize, buf.len(), flags)", "recv_args(fd, buf.len(), buf.as_mut_ptr() as usize, flags)", "recv_args(fd, buf.as_mut_ptr()"),
            ("a fit assertion is dropped", "    assert!(plan.recv.fits_the_leaf());\n", "", "fit assertions"),
            ("a uname appears", "/// `listen(fd, backlog)`.", "/// `uname`.\nfn uname_probe() { let uname = 1; let _ = uname; }\n\n/// `listen(fd, backlog)`.", "uname"),
            ("the executor drops the block address", "block.as_ptr() as usize", "0", "block's address"),
            ("invariant 5 is dropped from the documentation", "5. A `socketcall` block", "5. A block", "invariant 5"),
        ]
        for name, old, new, word in plants:
            bad = self.src.replace(old, new, 1)
            self.assertNotEqual(bad, self.src, name)
            problems = sys_problems(bad)
            self.assertTrue(any(word in line for line in problems), "%s: %s" % (name, problems))

    def test_the_trampolines_are_still_the_audited_two_and_no_wider_one_exists(self):
        self.assertEqual(len(re.findall(r"unsafe fn raw5\(", self.src)), 2)
        self.assertNotRegex(self.src, r"unsafe fn raw[6-9]\(")
        self.assertEqual(len(re.findall(r"syscall with up to five arguments", self.src)), 2)

    def test_the_legacy_entropy_path_rules_still_hold_with_the_socket_wrappers_in_the_file(self):
        literals = re.findall(r'b"([^"]*)"', tss.code_only(self.src))
        self.assertEqual(literals, ["/dev/random\\0"], "no byte-string literal other than the one constant path")


class RouteShapeTests(unittest.TestCase):
    def setUp(self):
        self.src = READ(ROUTE_RS)

    def test_the_real_socket_route_has_no_unsafe_types_no_number_and_decides_by_the_route(self):
        self.assertEqual(route_problems(self.src), [])

    def test_each_planted_fault_in_socket_route_is_reported(self):
        plants = [
            ("unsafe appears", "pub const BLOCK_WORDS: usize = 6;", "pub const BLOCK_WORDS: usize = 6;\n\nfn bad() { unsafe { } }", "unsafe"),
            ("issue_for types a number", "number: call.number,", "number: 4334,", "types a number"),
            ("issue_for ignores the plan", "    let plan = socket_plan_for(abi);\n    let route = match op {", "    let plan = socket_plan_for(Abi::PowerPc32);\n    let route = match op {", "route by the plan"),
            ("admit decides by the ABI's name", "    let uses_sub_call_18 = matches!(", "    let by_name = abi == Abi::PowerPc32;\n    let uses_sub_call_18 = by_name || matches!(", "ABI's name"),
            ("admit forgets the sub-call", "Route::ViaSocketCall { sub, .. } if sub == ACCEPT4_SUBCALL", "Route::ViaSocketCall { sub, .. } if sub == 17", "route"),
        ]
        for name, old, new, word in plants:
            bad = self.src.replace(old, new, 1)
            self.assertNotEqual(bad, self.src, name)
            problems = route_problems(bad)
            self.assertTrue(any(word in line for line in problems), "%s: %s" % (name, problems))


def lib_problems(src):
    code = tss.code_only(src)
    out = []
    if len(re.findall(r"\bSocketKernel \{ kernel", code)) != 1:
        out.append("a SocketKernel must be built in exactly one place (admit_sockets)")
    if len(re.findall(r"\bpub struct SocketKernel\b", code)) != 1:
        out.append("SocketKernel is not defined exactly once")
    if len(re.findall(r"\bimpl SocketOps for SocketKernel\b", code)) != 1 or re.search(r"\bimpl SocketOps for LinuxKernel\b", code):
        out.append("SocketOps must be implemented for SocketKernel only, never for LinuxKernel")
    admit = fn_body(code, "admit_sockets")
    if admit is None or not re.search(r"socket_route::admit\(sys::COMPILED_ABI, release\)\?;\s*Ok\(SocketKernel \{ kernel: self \}\)", admit):
        out.append("admit_sockets must call socket_route::admit(..)? and only then build the SocketKernel")
    ops = re.search(r"impl SocketOps for SocketKernel \{(.*?)\n    \}\n", code, re.S)
    for name, call in SOCKET_CALLS.items():
        body = fn_body(ops.group(1), name) if ops else None
        if body is None or body.strip() != call:
            out.append("the SocketOps method %s must be exactly `%s` (the five sys socket wrappers, arguments in order)" % (name, call))
    kernel_ops = re.search(r"impl KernelOps for SocketKernel \{(.*?)\n    \}\n", code, re.S)
    for name, call in KERNEL_CALLS.items():
        body = fn_body(kernel_ops.group(1), name) if kernel_ops else None
        if body is None or body.strip() != call:
            out.append("the KernelOps method %s of SocketKernel must be exactly `%s` (ten delegations)" % (name, call))
    if "pub use backend::{LinuxKernel, SocketKernel};" not in code:
        out.append("SocketKernel is not exported")
    return out


class LibShapeTests(unittest.TestCase):
    def setUp(self):
        self.src = READ(LEAF_LIB)

    def test_the_real_backend_admits_before_it_builds_and_only_socket_kernel_has_socket_ops(self):
        self.assertEqual(lib_problems(self.src), [])

    def test_each_planted_fault_in_the_backend_is_reported(self):
        plants = [
            ("socket ops for the raw kernel", "    impl SocketOps for SocketKernel {", "    impl SocketOps for LinuxKernel {\n        fn socket(&mut self, d: u32, k: u32, p: u32) -> isize { sys::socket(d, k, p) }\n    }\n\n    impl SocketOps for SocketKernel {", "never for LinuxKernel"),
            ("admission skipped", "            socket_route::admit(sys::COMPILED_ABI, release)?;\n", "", "admit_sockets must call"),
            ("a second construction", "    impl Default for LinuxKernel {", "    fn forge(kernel: LinuxKernel) -> SocketKernel {\n        SocketKernel { kernel }\n    }\n\n    impl Default for LinuxKernel {", "exactly one place"),
            ("a socket method calls the wrong wrapper", "            sys::listen(fd, backlog)", "            sys::bind(fd, &[])", "SocketOps method listen"),
            ("a socket method swaps its arguments", "            sys::recv(fd, buf, flags)", "            sys::recv(flags as i32, buf, 0)", "SocketOps method recv"),
            ("a kernel op is not delegated", "            self.kernel.close(fd)", "            0", "KernelOps method close"),
            ("a kernel op calls the wrong delegate", "            self.kernel.write(fd, buf)", "            self.kernel.read(fd, &mut [])", "KernelOps method write"),
        ]
        for name, old, new, word in plants:
            bad = self.src.replace(old, new, 1)
            self.assertNotEqual(bad, self.src, name)
            problems = lib_problems(bad)
            self.assertTrue(any(word in line for line in problems), "%s: %s" % (name, problems))


class EvidenceConstantTests(unittest.TestCase):
    """The Rust constants against the kernel facts derived from the committed evidence lines."""

    def setUp(self):
        self.src = READ(ROUTE_RS)
        self.facts = tss.KERNEL_SOCKET

    def test_the_paccept_kernel_and_the_first_accept4_kernel_are_the_ones_the_evidence_names(self):
        paccept = [tag for tag in tss.TAGS if self.facts["subcall18_" + tag.replace(".", "_")] == "PACCEPT"]
        accept4 = sorted(tag_version(tag.replace(".", "_")) for tag in tss.TAGS if self.facts["subcall18_" + tag.replace(".", "_")] == "ACCEPT4")
        self.assertEqual([tag_version(tag.replace(".", "_")) for tag in paccept], [(2, 6, 27)])
        self.assertEqual(rust_version(self.src, "PACCEPT_KERNEL"), (2, 6, 27))
        self.assertEqual(rust_version(self.src, "ACCEPT4_FIRST_KERNEL"), accept4[0])

    def test_the_block_size_and_the_sub_call_are_the_evidences(self):
        widest = max(max(self.facts["nargs_" + tag.replace(".", "_")]) for tag in tss.TAGS)
        self.assertEqual(widest, 6)
        self.assertIn("pub const BLOCK_WORDS: usize = %d;" % widest, self.src)
        self.assertEqual(self.facts["subcalls_2_6_35"]["accept4"], 18)
        self.assertIn("pub const ACCEPT4_SUBCALL: usize = 18;", self.src)
        # the paccept block is wider than accept4's, which is why a six-word block is always passed
        self.assertGreater(self.facts["subcall18_words_2_6_27"], self.facts["subcall18_words_2_6_28"])

    def test_the_pinned_issued_words_are_the_plan_rows(self):
        source = READ(tsn.NUMBERS_RS)
        ppc = tsn.rust_p06(source, "P06_POWERPC32")
        mips = tsn.rust_p06(source, "P06_MIPS32_O32")
        ppc_server = tss.rust_server(source, "SERVER_POWERPC32")
        mips_server = tss.rust_server(source, "SERVER_MIPS32_O32")
        body = fn_body(tss.code_only(self.src), "each_op_is_issued_as_the_plan_routes_it_with_the_words_in_the_syscalls_own_order")
        self.assertIsNotNone(body)
        flat = re.sub(r"\s+", " ", body)
        self.assertIn("number: 102,", flat)
        self.assertEqual(ppc["socketcall"]["number"], 102)
        for call in ("socket", "bind", "recv"):
            self.assertIn("ppc(%d, [" % ppc[call]["sub"], flat, call)
            self.assertIn("mips(%d, [" % mips[call]["number"], flat, call)
        for call in ("listen", "accept4"):
            self.assertIn("ppc(%d, [" % ppc_server[call]["sub"], flat, call)
            self.assertIn("mips(%d, [" % mips_server[call]["number"], flat, call)


def model_version(text):
    match = re.match(r"^\s*(\d{1,9})\.(\d{1,9})\.(\d{1,9})(.*)$", text, re.S)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3))), match.group(4).strip().startswith("-rc")


def model_admit(facts, abi, release):
    """The rule, written from the evidence and not from the Rust: only a route through socketcall sub-call 18 is concerned (PowerPC); there, refuse the kernel whose
    sub-call 18 is paccept ('paccept'), and what cannot be told from it ('unverified'): no release, a text that is not a version, a release candidate of the first
    accept4 kernel; admit the rest ('ok')."""
    if abi == "mips":
        return "ok"
    paccept = {tag_version(t.replace(".", "_")) for t in tss.TAGS if facts["subcall18_" + t.replace(".", "_")] == "PACCEPT"}
    first_accept4 = min(tag_version(t.replace(".", "_")) for t in tss.TAGS if facts["subcall18_" + t.replace(".", "_")] == "ACCEPT4")
    if release is None:
        return "unverified"
    parsed = model_version(release)
    if parsed is None:
        return "unverified"
    version, rc = parsed
    if version in paccept:
        return "paccept"
    if version == first_accept4 and rc:
        return "unverified"
    return "ok"


class AdmissionModelTests(unittest.TestCase):
    def setUp(self):
        self.src = READ(ROUTE_RS)
        self.facts = tss.KERNEL_SOCKET

    def strings(self, name):
        body = fn_body(self.src, name)
        self.assertIsNotNone(body, name)
        return body

    def test_the_releases_in_the_refusal_test_are_refused_by_the_model_and_their_neighbours_are_admitted(self):
        body = self.strings("the_socketcall_route_is_refused_by_name_on_v2_6_27_and_its_neighbours_are_admitted")
        refused_part, admitted_part = body.split("Admitted:", 1)
        refused = [s for s in re.findall(r'"([^"{}]*)"', refused_part) if s]
        admitted = [s for s in re.findall(r'"([^"{}]*)"', admitted_part) if s]
        self.assertEqual(len(refused), 4)
        self.assertEqual(len(admitted), 8)
        for text in refused:
            self.assertEqual(model_admit(self.facts, "powerpc", text), "paccept", text)
        for text in admitted:
            self.assertEqual(model_admit(self.facts, "powerpc", text), "ok", text)

    def test_the_releases_in_the_unverified_test_are_unverified_by_the_model_and_the_pairs_are_admitted(self):
        body = self.strings("a_release_that_cannot_rule_out_v2_6_27_is_not_admitted_for_the_socketcall_route")
        unverified_part, pairs_part = body.split("The permitted pairs", 1)
        unverified = re.findall(r'"([^"{}]*)"', unverified_part)
        pairs = re.findall(r'Some\("([^"]*)"\)', pairs_part)
        self.assertIn("", unverified)
        self.assertEqual(sorted(set(unverified) - {""}), ["2.6", "2.6.28-rc1", "2.6.28-rc7", "garbage"])
        self.assertEqual(pairs, ["2.6.28", "2.6.29-rc1"])
        self.assertEqual(model_admit(self.facts, "powerpc", None), "unverified")
        for text in unverified:
            self.assertEqual(model_admit(self.facts, "powerpc", text), "unverified", text)
        for text in pairs:
            self.assertEqual(model_admit(self.facts, "powerpc", text), "ok", text)

    def test_the_direct_route_is_admitted_by_the_model_on_every_release_the_rust_test_names(self):
        body = self.strings("the_direct_route_does_not_depend_on_the_release")
        releases = re.findall(r'Some\("([^"]*)"\)', body)
        self.assertIn("2.6.27", releases)
        for text in releases + [None]:
            self.assertEqual(model_admit(self.facts, "mips", text), "ok", text)

    def test_every_kernel_whose_source_was_read_is_classified_as_the_evidence_says(self):
        expected = {"2.6.14": "ok", "2.6.26": "ok", "2.6.27": "paccept", "2.6.28": "ok", "2.6.35": "ok"}
        for tag, verdict in expected.items():
            self.assertEqual(model_admit(self.facts, "powerpc", tag), verdict, tag)

    def test_the_model_reports_a_planted_wrong_rule(self):
        # The control: change what the evidence says sub-call 18 is at v2.6.28, and the model's verdicts move, so the table tests above cannot pass by accident.
        tampered = dict(self.facts)
        tampered["subcall18_2_6_28"] = "PACCEPT"
        self.assertEqual(model_admit(tampered, "powerpc", "2.6.28"), "paccept")
        self.assertEqual(model_admit(self.facts, "powerpc", "2.6.28"), "ok")


# ---- the contract -----------------------------------------------------------------------------------------------------------------------

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.doc = READ(tsn.P02_MD)
        self.section = self.doc.split("## The socket capability", 1)[1].split("\n## ", 1)[0]

    def test_the_contract_describes_the_leaf_backend_and_what_it_does_not_show(self):
        for phrase in ("**The leaf backend", "`LinuxKernel::admit_sockets(release)`", "`SubCall18IsPaccept`", "`ReleaseNotVerified`", "socket_route::issue_for",
                       "**No guest has issued a `socketcall`", "**The release is\nthe caller's input**", "written, **not compiled**"):
            self.assertIn(phrase, self.section, phrase)
        self.assertNotIn("No `unsafe`, no leaf implementation", self.doc)
        self.assertIn("* **The leaf backend is written, not compiled.**", self.section)

    def test_the_contract_counts_equal_the_files_counts(self):
        route_tests = len(re.findall(r"#\[test\]", READ(ROUTE_RS)))
        python_tests = len(re.findall(r"^    def test_", READ(__file__), re.M))
        self.assertIn("%d Rust tests in `socket_route.rs`" % route_tests, self.section)
        self.assertIn("%d Python tests in `tests/p02/test_leaf_socket.py`" % python_tests, self.section)

    def test_every_leaf_test_name_the_contract_cites_exists(self):
        known = set(re.findall(r"#\[test\]\s*fn ([a-z0-9_]+)\(", READ(ROUTE_RS)))
        cited = set(re.findall(r"`([a-z][a-z0-9_]{24,})`", self.section.split("**The leaf backend", 1)[1].split("**What this slice leaves", 1)[0]))
        self.assertEqual(sorted(known - cited), [], "a leaf Rust test the contract does not name")
        self.assertEqual(sorted(cited - known), [], "names that are not leaf tests")

    def test_the_file_table_and_the_unsafe_surface_paragraph_say_twelve(self):
        row = next(line for line in self.doc.splitlines() if line.startswith("| `crates/franken-platform-linux/` |"))
        self.assertIn("twelve typed wrappers", row)
        self.assertIn("socket route plan and the release admission", row)
        self.assertIn("**plus twelve typed wrappers**", self.doc)
        self.assertIn("the only\nother `unsafe` site", self.doc)


if __name__ == "__main__":
    unittest.main()
