#!/usr/bin/env python3
"""P06 (ffw-2nw): the readiness and datagram ABI of crates/franken-platform/src/net.rs has more than one witness.

The Rust is held to the committed vector file by its own unit tests; this file holds the vector file, and the Rust text, to
sources that are not the Rust:

* an independent model of every byte layout and decoder here (`struct.pack`, ceilings, the retry arithmetic), written from the
  contract and not from the Rust,
* the E03 guest probe source (the constants and the `pollfd` shape the real BE guests ran with),
* the `libc` crate's per-architecture files in the local cargo registry (the numbers the Rust musl targets use),
* the Rust source text itself (so the unit tests cannot be edited around without this noticing).

Offline, stdlib only, no cargo, no QEMU. A source that is missing is SKIPPED, and the runner (run_cases.py) reports a skip as
BLOCKED and exits 3: a check that did not run never passes. "Sensitivity" tests plant a wrong number in each source and require
the comparison to report it, after first requiring the unplanted comparison to be clean.
"""
import copy
import glob
import importlib.util
import json
import os
import re
import struct
import sys
import unittest

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
VECTORS = os.path.join(ROOT, "crates", "franken-platform", "tests", "vectors", "p06_net_abi.json")
NET_RS = os.path.join(ROOT, "crates", "franken-platform", "src", "net.rs")
PROBE = os.path.join(ROOT, "toolchain", "src", "ffw-hello-init", "src", "main.rs")
ORACLE = os.path.join(ROOT, "tests", "e03", "abi.py")
CASES = os.path.join(ROOT, "tests", "p06", "cases.json")

ABIS = ("powerpc32", "mips32")
ARCH = {"powerpc32": "powerpc", "mips32": "mips"}
SO_NAMES = {"reuseaddr": "SO_REUSEADDR", "broadcast": "SO_BROADCAST", "sndbuf": "SO_SNDBUF", "rcvbuf": "SO_RCVBUF",
            "rcvtimeo": "SO_RCVTIMEO_OLD", "sndtimeo": "SO_SNDTIMEO_OLD", "error": "SO_ERROR", "type": "SO_TYPE"}
NET_ERRNOS = ("EMSGSIZE", "EADDRINUSE", "EADDRNOTAVAIL", "ENETUNREACH", "ECONNRESET", "ENOBUFS", "ENOTCONN", "ETIMEDOUT",
              "ECONNREFUSED", "EINPROGRESS")
MAX_INTERRUPTED_ATTEMPTS = 8       # franken-platform/src/abi.rs; cross-checked against the Rust text below
MAX_DATAGRAM = 65535 - 8           # the 16-bit IPv6 payload length (no jumbograms) minus the UDP header
# Where the oldest admitted kernel turns a long finite wait into "forever" (stock 2.6.14, read with 2.6.35), derived from the
# kernel's own tests, not copied from the Rust: sys_poll keeps a timeout only if `timeout < MAX_SCHEDULE_TIMEOUT / HZ` and
# sock_set_timeout only if `tv_sec < MAX_SCHEDULE_TIMEOUT / HZ - 1`; MAX_SCHEDULE_TIMEOUT is LONG_MAX of a 32-bit ABI and HZ is
# at most 1000 on these platforms (a smaller HZ allows more, so the bound is safe for every configuration).
LONG_MAX = 2**31 - 1
HZ_MAX = 1000
POLL_MAX_MS = LONG_MAX // HZ_MAX - 1
TIMEVAL_MAX_SEC = LONG_MAX // HZ_MAX - 2


def load_vectors():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def load_oracle():
    spec = importlib.util.spec_from_file_location("ffw_p06_e03_abi", ORACLE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ffw_p06_e03_abi"] = module
    spec.loader.exec_module(module)
    return module


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def ceil_div(a, b):
    return -(-a // b)


# ------------------------------------------------------------------------------------------- the independent model

def model_pollfd(fd, events, revents):
    return struct.pack(">iHH", fd, events, revents).hex()


def model_sockaddr_in(addr, port):
    return struct.pack(">HH4s8s", 2, port, bytes(addr), bytes(8)).hex()


def model_sockaddr_in6(addr_hex, port, flowinfo, scope_id):
    return struct.pack(">HHI16sI", 10, port, flowinfo, bytes.fromhex(addr_hex), scope_id).hex()


def model_timeval32(nanos):
    """('ok', hex) | ('err', name): zero is refused, seconds past the kernel's own 'no timeout' threshold (which is below 32 bits)
    are refused, microseconds round up."""
    if nanos == 0:
        return ("err", "zero_timeout")
    micros = ceil_div(nanos, 1000)
    sec, usec = divmod(micros, 1_000_000)
    if sec > TIMEVAL_MAX_SEC:
        return ("err", "time_width")
    return ("ok", struct.pack(">ii", sec, usec).hex())


def model_poll_timeout(nanos):
    if nanos == 0:
        return ("ok", 0)
    millis = ceil_div(nanos, 1_000_000)
    if millis > POLL_MAX_MS:
        return ("err", "time_width")
    return ("ok", millis)


def model_decode(arch, raw, oracle):
    if raw >= 0:
        return ("ok", raw)
    if raw < -4095:
        return ("err", "malformed")
    errno = -raw
    if errno == oracle.errno_number(arch, "ENOSYS"):
        return ("err", "absent")
    return ("err", {4: "interrupted", 11: "would_block", 22: "invalid"}.get(errno, "errno:%d" % errno))


def model_poll_decode(arch, raw, requested, oracle):
    kind, value = model_decode(arch, raw, oracle)
    if kind == "ok" and value > requested:
        return ("err", "ready_above_requested")
    return (kind, value)


def model_recv(arch, raw, buf, oracle):
    kind, value = model_decode(arch, raw, oracle)
    if kind == "err":
        return ("err", value)
    if value > MAX_DATAGRAM:
        return ("err", "datagram_length")
    return ("complete", value) if value <= buf else ("truncated", (buf, value))


def model_retry(arch, case, oracle):
    """The retry arithmetic, restated: each call gets what is left of the timeout, rounded up to a millisecond."""
    timeout = case["timeout_ms"]
    left = timeout
    calls, script = [], case["script"]
    for index in range(MAX_INTERRUPTED_ATTEMPTS):
        calls.append(left)
        step = script[index]
        kind, value = model_poll_decode(arch, step["raw"], case["requested"], oracle)
        if (kind, value) != ("err", "interrupted"):
            return calls, (kind, value)
        if timeout > 0:
            left = max(0, timeout - step["elapsed_ms"])
        # timeout == 0 (immediate) and timeout == -1 (infinite) never change
    return calls, ("err", "interrupted")


def expected_pair(expect):
    if "ok" in expect:
        return ("ok", expect["ok"])
    return ("err", expect["err"])


class ModelAgreesWithTheVectors(unittest.TestCase):
    """The vector file is hand-written; an independent restatement of every layout and decoder must reach the same answers."""

    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()
        cls.oracle = load_oracle()

    def test_pollfd_bytes(self):
        for case in self.v["pollfd"]:
            self.assertEqual(case["bytes"], model_pollfd(case["fd"], case["events"], case["revents"]), case)

    def test_sockaddr_in_bytes_and_rejections(self):
        for case in self.v["sockaddr_in"]:
            self.assertEqual(case["bytes"], model_sockaddr_in(case["addr"], case["port"]), case)
        good = self.v["sockaddr_in"][0]["bytes"]
        by_name = {c["name"]: c for c in self.v["sockaddr_in_reject"]}
        self.assertEqual(len(bytes.fromhex(by_name["fifteen bytes"]["bytes"])), 15)
        self.assertEqual(by_name["fifteen bytes"]["bytes"], good[:-2])
        self.assertEqual(len(bytes.fromhex(by_name["seventeen bytes"]["bytes"])), 17)
        self.assertEqual(by_name["an IPv6 family"]["bytes"][:4], "000a")
        self.assertEqual(by_name["a host-little-endian family"]["bytes"][:4], "0200")
        self.assertEqual(by_name["padding that is not zero"]["bytes"], good[:-2] + "01")
        for case in self.v["sockaddr_in_reject"]:
            self.assertIn(case["expect"]["err"], ("bad_length", "bad_family", "non_zero_padding"), case)

    def test_sockaddr_in6_bytes_and_rejections(self):
        for case in self.v["sockaddr_in6"]:
            self.assertEqual(case["bytes"], model_sockaddr_in6(case["addr"], case["port"], case["flowinfo"], case["scope_id"]), case)
        good = self.v["sockaddr_in6"][0]["bytes"]
        by_name = {c["name"]: c for c in self.v["sockaddr_in6_reject"]}
        self.assertEqual(len(bytes.fromhex(by_name["twenty-seven bytes"]["bytes"])), 27)
        self.assertEqual(by_name["twenty-seven bytes"]["bytes"], good[:-2])
        self.assertEqual(by_name["an IPv4 family"]["bytes"], "0002" + good[4:])

    def test_timeval32(self):
        for case in self.v["timeval32"]:
            kind, value = model_timeval32(case["nanos"])
            if "bytes" in case:
                self.assertEqual((kind, value), ("ok", case["bytes"]), case)
            else:
                self.assertEqual((kind, value), ("err", case["err"]), case)
        for case in self.v["timeval32_read"]:
            sec, usec = struct.unpack(">ii", bytes.fromhex(case["bytes"]))
            valid = sec >= 0 and 0 <= usec < 1_000_000
            self.assertEqual(valid, "err" not in case, case)
            if valid:
                self.assertEqual((sec, usec), (case["sec"], case["usec"]), case)

    def test_the_kernels_forever_thresholds_are_the_vectors(self):
        lf = self.v["legacy_forever"]
        self.assertEqual((lf["long_max"], lf["hz_max"]), (LONG_MAX, HZ_MAX))
        self.assertEqual(lf["poll_max_ms"], POLL_MAX_MS)
        self.assertEqual(lf["timeval_max_sec"], TIMEVAL_MAX_SEC)
        self.assertEqual(lf["max_datagram"], MAX_DATAGRAM)
        # the edges are in the rows: the last finite value is accepted, one more is refused
        self.assertEqual(model_poll_timeout(POLL_MAX_MS * 1_000_000), ("ok", POLL_MAX_MS))
        self.assertEqual(model_poll_timeout(POLL_MAX_MS * 1_000_000 + 1), ("err", "time_width"))
        self.assertEqual(model_timeval32(TIMEVAL_MAX_SEC * 10**9 + 999_999_000)[0], "ok")
        self.assertEqual(model_timeval32((TIMEVAL_MAX_SEC + 1) * 10**9), ("err", "time_width"))
        for edge in (POLL_MAX_MS * 1_000_000, POLL_MAX_MS * 1_000_000 + 1, TIMEVAL_MAX_SEC * 10**9 + 999_999_000,
                     (TIMEVAL_MAX_SEC + 1) * 10**9):
            in_rows = [c for c in self.v["poll_timeout"] + self.v["timeval32"] if c["nanos"] == edge]
            self.assertTrue(in_rows, "the vectors do not name the edge %d" % edge)
        for raw in (MAX_DATAGRAM, MAX_DATAGRAM + 1):
            self.assertTrue([c for c in self.v["recv_decode"] if c["raw"] == raw], "no recv row at %d" % raw)

    def test_poll_timeout(self):
        for case in self.v["poll_timeout"]:
            self.assertEqual(model_poll_timeout(case["nanos"]), expected_pair(case["expect"]), case)

    def test_poll_decode(self):
        for case in self.v["poll_decode"]:
            got = model_poll_decode(ARCH[case["abi"]], case["raw"], case["requested"], self.oracle)
            self.assertEqual(got, expected_pair(case["expect"]), case)

    def test_poll_retry(self):
        for case in self.v["poll_retry"]:
            calls, result = model_retry(ARCH[case["abi"]], case, self.oracle)
            self.assertEqual(calls, case["calls_ms"], case["name"])
            self.assertEqual(result, expected_pair(case["expect"]), case["name"])
            if result == ("err", "interrupted"):
                self.assertEqual(len(calls), MAX_INTERRUPTED_ATTEMPTS, case["name"])

    def test_recv_decode(self):
        for case in self.v["recv_decode"]:
            got = model_recv(ARCH[case["abi"]], case["raw"], case["buf"], self.oracle)
            expect = case["expect"]
            if "complete" in expect:
                want = ("complete", expect["complete"])
            elif "truncated" in expect:
                want = ("truncated", (expect["truncated"]["stored"], expect["truncated"]["real"]))
            else:
                want = ("err", expect["err"])
            self.assertEqual(got, want, case)

    def test_the_e03_loopback_fact_is_in_the_vectors(self):
        # tests/e03/abi.py: UDP_LOOPBACK passes only with rc == 24, a 24-byte datagram read into a 16-byte buffer.
        self.assertTrue(self.oracle.PROBES["UDP_LOOPBACK"][3](24))
        self.assertFalse(self.oracle.PROBES["UDP_LOOPBACK"][3](16))
        facts = [c for c in self.v["recv_decode"] if c["raw"] == 24 and c["buf"] == 16]
        self.assertTrue(facts)
        for case in facts:
            self.assertEqual(case["expect"], {"truncated": {"stored": 16, "real": 24}})

    def test_the_errno_classification_vectors(self):
        by_abi = {a: {name: self.v["abi"][a]["errno"][name] for name in NET_ERRNOS} for a in ABIS}
        for case in self.v["net_errno"]:
            table = {number: name for name, number in by_abi[case["abi"]].items()}
            self.assertEqual(table.get(case["errno"]), case["expect"], case)
        # the two sets of ten numbers do not overlap: a number is a network error on at most one ABI
        self.assertFalse(set(by_abi["powerpc32"].values()) & set(by_abi["mips32"].values()))

    def test_the_socket_type_argument_vectors(self):
        for case in self.v["socket_type_arg"]:
            row = self.v["abi"][case["abi"]]
            value = row["sock_" + case["kind"]]
            if case["nonblock"]:
                value |= row["sock_nonblock"]
            if case["cloexec"]:
                value |= row["sock_cloexec"]
            self.assertEqual(value, case["value"], case)

    def test_the_known_poll_bits_differ_where_the_abis_do(self):
        common = self.v["common"]
        base = (common["pollin"] | common["pollpri"] | common["pollout"] | common["pollerr"] | common["pollhup"]
                | common["pollnval"] | common["pollrdnorm"] | common["pollrdband"])
        known = {a: base | self.v["abi"][a]["pollwrnorm"] | self.v["abi"][a]["pollwrband"] for a in ABIS}
        for case in self.v["poll_ready_bits"]:
            ok = case["revents"] & ~known[case["abi"]] == 0
            self.assertEqual(ok, "ok" in case["expect"], case)
        for case in self.v["pollfd_request"]:
            events = case["events"]
            outputs = events & (common["pollerr"] | common["pollhup"] | common["pollnval"])
            unknown = events & ~known[case["abi"]]
            if case["fd"] < 0:
                want = "negative_descriptor"
            elif outputs:
                want = "output_only_event"
            elif unknown:
                want = "unknown_event_bits"
            else:
                want = None
            self.assertEqual(want, case["expect"].get("err"), case)


# --------------------------------------------------------------------------------------- the sources that are not Rust

def parse_consts(text):
    """{NAME: int} for every `[pub] const NAME: type = <int literal>;` in `text` (decimal, 0x and 0o literals)."""
    found = {}
    pattern = re.compile(r"^\s*(?:pub\s+)?const\s+([A-Z0-9_]+)\s*:\s*[A-Za-z0-9_]+\s*=\s*(0x[0-9a-fA-F_]+|0o[0-7_]+|[0-9][0-9_]*)\s*;", re.M)
    for name, literal in pattern.findall(text):
        literal = literal.replace("_", "")
        value = int(literal, 16) if literal.startswith("0x") else int(literal, 8) if literal.startswith("0o") else int(literal)
        found.setdefault(name, []).append(value)
    return found


def libc_candidates():
    paths = []
    override = os.environ.get("FFW_LIBC_SRC")
    if override:
        paths.append(override)
    paths += sorted(glob.glob(os.path.join(os.path.expanduser("~"), ".cargo", "registry", "src", "*", "libc-*")), reverse=True)
    return paths


LIBC_FILES = {
    "mips_sock": "src/new/musl/arch/mips/bits/socket.rs",
    "generic_sock": "src/new/musl/sys/socket.rs",
    "mips_so": "src/new/linux_uapi/arch/mips/asm/socket.rs",
    "ppc_so": "src/new/linux_uapi/arch/powerpc/asm/socket.rs",
    "generic_so": "src/new/linux_uapi/asm/socket.rs",
    "mips_errno": "src/unix/linux_like/linux/musl/b32/mips/mod.rs",
    "ppc_errno": "src/unix/linux_like/linux/musl/b32/powerpc.rs",
    "common": "src/unix/linux_like/mod.rs",
}


def find_libc():
    """(root, {key: text}) for the newest cached libc crate that has every file this check reads, or None."""
    for root in libc_candidates():
        if all(os.path.isfile(os.path.join(root, rel)) for rel in LIBC_FILES.values()):
            return root, {key: read(os.path.join(root, rel)) for key, rel in LIBC_FILES.items()}
    return None


def one(consts, name, where):
    values = consts.get(name)
    if not values or len(set(values)) != 1:
        raise AssertionError("%s: %s is %r" % (where, name, values))
    return values[0]


def problems_against_libc(v, files):
    """Every number in the vector file that the libc crate's files do not state the same way; empty when they agree."""
    out = []
    mips_sock, generic_sock = parse_consts(files["mips_sock"]), parse_consts(files["generic_sock"])
    mips_so, ppc_so, generic_so = parse_consts(files["mips_so"]), parse_consts(files["ppc_so"]), parse_consts(files["generic_so"])
    mips_errno, ppc_errno, common = parse_consts(files["mips_errno"]), parse_consts(files["ppc_errno"]), parse_consts(files["common"])

    def check(label, got, want):
        if got != want:
            out.append("%s: vector %r, libc %r" % (label, got, want))

    ppc, mips = v["abi"]["powerpc32"], v["abi"]["mips32"]
    check("mips SOCK_STREAM", mips["sock_stream"], one(mips_sock, "SOCK_STREAM", "mips bits"))
    check("mips SOCK_DGRAM", mips["sock_dgram"], one(mips_sock, "SOCK_DGRAM", "mips bits"))
    check("mips SOCK_NONBLOCK", mips["sock_nonblock"], one(mips_sock, "SOCK_NONBLOCK", "mips bits"))
    check("mips SOCK_CLOEXEC", mips["sock_cloexec"], one(mips_sock, "SOCK_CLOEXEC", "mips bits"))
    check("ppc SOCK_STREAM", ppc["sock_stream"], one(generic_sock, "SOCK_STREAM", "generic socket"))
    check("ppc SOCK_DGRAM", ppc["sock_dgram"], one(generic_sock, "SOCK_DGRAM", "generic socket"))
    check("ppc SOCK_NONBLOCK", ppc["sock_nonblock"], one(generic_sock, "SOCK_NONBLOCK", "generic socket"))
    check("ppc SOCK_CLOEXEC", ppc["sock_cloexec"], one(generic_sock, "SOCK_CLOEXEC", "generic socket"))
    check("mips SOL_SOCKET", mips["sol_socket"], one(mips_so, "SOL_SOCKET", "mips asm/socket"))
    check("ppc SOL_SOCKET", ppc["sol_socket"], one(generic_so, "SOL_SOCKET", "generic asm/socket"))
    for key, name in SO_NAMES.items():
        check("mips " + name, mips["so"][key], one(mips_so, name, "mips asm/socket"))
        # PowerPC differs from the generic file only in the receive and send timeouts, which its own file defines
        source = ppc_so if name in ppc_so else generic_so
        check("ppc " + name, ppc["so"][key], one(source, name, "powerpc/generic asm/socket"))
    for name in NET_ERRNOS:
        check("mips " + name, mips["errno"][name], one(mips_errno, name, "mips musl b32"))
        check("ppc " + name, ppc["errno"][name], one(ppc_errno, name, "powerpc musl b32"))
    check("mips POLLWRNORM", mips["pollwrnorm"], one(mips_errno, "POLLWRNORM", "mips musl b32"))
    check("mips POLLWRBAND", mips["pollwrband"], one(mips_errno, "POLLWRBAND", "mips musl b32"))
    check("ppc POLLWRNORM", ppc["pollwrnorm"], one(ppc_errno, "POLLWRNORM", "powerpc musl b32"))
    check("ppc POLLWRBAND", ppc["pollwrband"], one(ppc_errno, "POLLWRBAND", "powerpc musl b32"))
    for key, name in (("af_inet", "AF_INET"), ("af_inet6", "AF_INET6"), ("msg_peek", "MSG_PEEK"), ("msg_trunc", "MSG_TRUNC"),
                      ("msg_dontwait", "MSG_DONTWAIT"), ("pollin", "POLLIN"), ("pollpri", "POLLPRI"), ("pollout", "POLLOUT"),
                      ("pollerr", "POLLERR"), ("pollhup", "POLLHUP"), ("pollnval", "POLLNVAL"), ("pollrdnorm", "POLLRDNORM"),
                      ("pollrdband", "POLLRDBAND")):
        check(name, v["common"][key], one(common, name, "linux_like"))
    check("SO_RCVTIMEO_NEW", v["never_used_sockopts"]["so_rcvtimeo_new"], one(generic_so, "SO_RCVTIMEO_NEW", "generic asm/socket"))
    check("SO_SNDTIMEO_NEW", v["never_used_sockopts"]["so_sndtimeo_new"], one(generic_so, "SO_SNDTIMEO_NEW", "generic asm/socket"))
    return out


def problems_against_probe(v, text):
    """The E03 guest probe's own constants and its `pollfd` shape, against the vector file."""
    out = []
    blocks = text.split("mod sys {")[1:]
    seen = {}
    for block in blocks:
        consts = parse_consts(block)
        nr_poll = consts.get("NR_POLL", [None])[0]
        abi = {4188: "mips32", 167: "powerpc32"}.get(nr_poll)
        if abi is None:
            continue
        seen[abi] = consts
    for abi in ABIS:
        if abi not in seen:
            out.append("the probe has no sys module for %s" % abi)
            continue
        row = v["abi"][abi]
        if seen[abi]["O_NONBLOCK"][0] != row["sock_nonblock"]:
            out.append("%s O_NONBLOCK: probe %r, vector %r" % (abi, seen[abi]["O_NONBLOCK"], row["sock_nonblock"]))
        if seen[abi]["SOCK_DGRAM"][0] != row["sock_dgram"]:
            out.append("%s SOCK_DGRAM: probe %r, vector %r" % (abi, seen[abi]["SOCK_DGRAM"], row["sock_dgram"]))
    shape = re.search(r"struct PollFd \{\s*fd: i32,\s*events: i16,\s*revents: i16,\s*\}", text)
    if not shape:
        out.append("the probe's PollFd is not { fd: i32, events: i16, revents: i16 }")
    return out


class OtherSourcesAgreeWithTheVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()

    def test_the_e03_probe_source_agrees(self):
        text = read(PROBE)
        self.assertEqual(problems_against_probe(self.v, text), [])

    def test_the_probe_check_is_sensitive(self):
        text = read(PROBE)
        self.assertEqual(problems_against_probe(self.v, text), [])
        broken = copy.deepcopy(self.v)
        broken["abi"]["mips32"]["sock_dgram"] = 2
        self.assertTrue(problems_against_probe(broken, text))
        broken = copy.deepcopy(self.v)
        broken["abi"]["powerpc32"]["sock_nonblock"] = 128
        self.assertTrue(problems_against_probe(broken, text))
        self.assertTrue(problems_against_probe(self.v, text.replace("events: i16", "events: i32", 1)))

    def test_the_libc_crate_agrees(self):
        found = find_libc()
        if found is None:
            self.skipTest("no cached libc crate with the files this check reads (set FFW_LIBC_SRC to one)")
        root, files = found
        self.assertEqual(problems_against_libc(self.v, files), [], root)

    def test_the_libc_check_is_sensitive(self):
        found = find_libc()
        if found is None:
            self.skipTest("no cached libc crate with the files this check reads (set FFW_LIBC_SRC to one)")
        _, files = found
        self.assertEqual(problems_against_libc(self.v, files), [])
        plants = [
            ("mips", lambda b: b["abi"]["mips32"].__setitem__("sock_dgram", 2)),
            ("sol_socket", lambda b: b["abi"]["powerpc32"].__setitem__("sol_socket", 65535)),
            ("rcvtimeo", lambda b: b["abi"]["mips32"]["so"].__setitem__("rcvtimeo", 66)),
            ("errno", lambda b: b["abi"]["mips32"]["errno"].__setitem__("EADDRINUSE", 98)),
            ("pollwrnorm", lambda b: b["abi"]["powerpc32"].__setitem__("pollwrnorm", 4)),
            ("msg_trunc", lambda b: b["common"].__setitem__("msg_trunc", 0x2000)),
        ]
        for name, plant in plants:
            broken = copy.deepcopy(self.v)
            plant(broken)
            self.assertTrue(problems_against_libc(broken, files), name)


# ----------------------------------------------------------------------------------------- the Rust text itself

def rust_code(text):
    """The code before the unit tests, with comment lines removed."""
    head = text.split("#[cfg(test)]")[0]
    return "\n".join(line for line in head.splitlines() if not line.lstrip().startswith("//"))


def rust_tables(code):
    """The per-ABI numbers as the Rust text states them, read from the `match` arms."""
    abi_name = {"PowerPc32": "powerpc32", "Mips32": "mips32"}
    out = {a: {"so": {}, "errno": {}} for a in ABIS}
    kinds = {"Stream": "sock_stream", "Dgram": "sock_dgram"}
    for abi, kind, value in re.findall(r"\(Self::(PowerPc32|Mips32), SockKind::(Stream|Dgram)\) => (\d+),", code):
        out[abi_name[abi]][kinds[kind]] = int(value)
    opts = {"ReuseAddr": "reuseaddr", "Broadcast": "broadcast", "SendBuf": "sndbuf", "RecvBuf": "rcvbuf", "RecvTimeout": "rcvtimeo",
            "SendTimeout": "sndtimeo", "PendingError": "error", "Type": "type"}
    for abi, opt, value in re.findall(r"\(Self::(PowerPc32|Mips32), SockOpt::(\w+)\) => (0x[0-9a-fA-F]+|\d+),", code):
        out[abi_name[abi]]["so"][opts[opt]] = int(value, 0)
    names = {"MsgSize": "EMSGSIZE", "AddrInUse": "EADDRINUSE", "AddrNotAvail": "EADDRNOTAVAIL", "NetUnreach": "ENETUNREACH",
             "ConnReset": "ECONNRESET", "NoBufs": "ENOBUFS", "NotConn": "ENOTCONN", "TimedOut": "ETIMEDOUT",
             "ConnRefused": "ECONNREFUSED", "InProgress": "EINPROGRESS"}
    for variant, abi, value in re.findall(r"\(Self::(\w+), Abi::(PowerPc32|Mips32)\) => (\d+),", code):
        out[abi_name[abi]]["errno"][names[variant]] = int(value)
    for fn_name, key in (("sol_socket", "sol_socket"), ("pollwrnorm", "pollwrnorm"), ("pollwrband", "pollwrband")):
        body = re.search(r"fn %s\(self\) -> \w+ \{\s*match self \{(.*?)\}\s*\}" % fn_name, code, re.S)
        if body:
            for abi, value in re.findall(r"Self::(PowerPc32|Mips32) => (0x[0-9a-fA-F]+|\d+),", body.group(1)):
                out[abi_name[abi]][key] = int(value, 0)
    return out


def problems_against_rust(v, code):
    out = []
    tables = rust_tables(code)
    for abi in ABIS:
        row, got = v["abi"][abi], tables[abi]
        for key in ("sock_stream", "sock_dgram", "sol_socket", "pollwrnorm", "pollwrband"):
            if got.get(key) != row[key]:
                out.append("%s %s: vector %r, Rust text %r" % (abi, key, row[key], got.get(key)))
        if got["so"] != row["so"]:
            out.append("%s socket options: vector %r, Rust text %r" % (abi, row["so"], got["so"]))
        if got["errno"] != row["errno"]:
            out.append("%s network errnos: vector %r, Rust text %r" % (abi, row["errno"], got["errno"]))
    return out


class RustTextAgreesWithTheVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()
        cls.text = read(NET_RS)

    def test_the_tables_in_the_rust_text_are_the_vectors(self):
        self.assertEqual(problems_against_rust(self.v, rust_code(self.text)), [])

    def test_the_rust_check_is_sensitive(self):
        code = rust_code(self.text)
        self.assertEqual(problems_against_rust(self.v, code), [])
        for old, new in (("(Self::Mips32, SockKind::Dgram) => 1,", "(Self::Mips32, SockKind::Dgram) => 2,"),
                         ("Self::Mips32 => 0xffff,", "Self::Mips32 => 1,"),
                         ("(Self::Mips32, SockOpt::RecvTimeout) => 0x1006,", "(Self::Mips32, SockOpt::RecvTimeout) => 66,"),
                         ("(Self::AddrInUse, Abi::Mips32) => 125,", "(Self::AddrInUse, Abi::Mips32) => 98,")):
            self.assertIn(old, code, old)
            self.assertTrue(problems_against_rust(self.v, code.replace(old, new, 1)), old)

    def test_the_forever_thresholds_and_the_datagram_bound_in_the_rust_text_are_the_derived_ones(self):
        code = rust_code(self.text)
        want = {"POLL_MAX_FINITE_MS": ("u32", POLL_MAX_MS), "TIMEVAL_MAX_FINITE_SEC": ("i32", TIMEVAL_MAX_SEC),
                "MAX_DATAGRAM": ("usize", MAX_DATAGRAM)}

        def stated(source):
            got = {}
            for name, kind, value in re.findall(r"pub const (\w+): (u32|i32|usize) = ([\d_]+);", source):
                got[name] = (kind, int(value.replace("_", "")))
            return got

        found = stated(code)
        for name, expected in want.items():
            self.assertEqual(found.get(name), expected, name)
        # control: the reader sees a changed value, so the equality above is not vacuous
        self.assertNotEqual(stated(code.replace("= 2_147_482;", "= 2_147_483;", 1)).get("POLL_MAX_FINITE_MS"),
                            want["POLL_MAX_FINITE_MS"])
        # and the ceilings are used where they matter, not just declared
        self.assertIn(".filter(|ms| *ms <= POLL_MAX_FINITE_MS)", code)
        self.assertIn(".filter(|sec| *sec <= TIMEVAL_MAX_FINITE_SEC)", code)
        self.assertIn("ms.min(POLL_MAX_FINITE_MS)", code)

    def test_the_retry_bound_is_the_one_abi_rs_defines(self):
        abi_rs = read(os.path.join(ROOT, "crates", "franken-platform", "src", "abi.rs"))
        match = re.search(r"pub const MAX_INTERRUPTED_ATTEMPTS: u32 = (\d+);", abi_rs)
        self.assertIsNotNone(match)
        self.assertEqual(int(match.group(1)), MAX_INTERRUPTED_ATTEMPTS)

    def test_the_code_has_no_thread_local_no_unsafe_and_nobody_elses_net_code(self):
        code = rust_code(self.text)
        for forbidden in ("thread_local", "unsafe", "std::net", "libc::", "gettimeofday", "fcntl", "extern "):
            self.assertNotIn(forbidden, code, forbidden)
        # control: the check sees these when they are there
        self.assertIn("thread_local", rust_code("fn f() {}\nthread_local! { }\n"))

    def test_the_module_is_declared_once_in_lib_rs(self):
        lib = read(os.path.join(ROOT, "crates", "franken-platform", "src", "lib.rs"))
        self.assertEqual(len(re.findall(r"^pub mod net;$", lib, re.M)), 1)


# ----------------------------------------------------------------------------------------------- the invariant map

class InvariantsMapToTestsThatExist(unittest.TestCase):
    """Each required invariant maps to Rust tests and Python tests that exist; nothing in net.rs is left unexplained."""

    @classmethod
    def setUpClass(cls):
        with open(CASES, encoding="utf-8") as fh:
            cls.cases = json.load(fh)
        cls.rust = read(NET_RS)

    def python_test_names(self):
        names = set()
        for module in ("test_net_abi", "test_ledger"):
            path = os.path.join(ROOT, "tests", "p06", module + ".py")
            for name in re.findall(r"^\s+def (test_\w+)\(", read(path), re.M):
                names.add("%s.%s" % (module, name))
        return names

    def test_every_named_test_exists(self):
        rust = set(re.findall(r"#\[test\]\s*fn (\w+)\(", self.rust))
        python = self.python_test_names()
        for inv in self.cases["invariants"]:
            self.assertTrue(inv["rust_tests"] or inv["python_tests"], inv["id"])
            for name in inv["rust_tests"]:
                self.assertIn(name, rust, "%s: no Rust test %s" % (inv["id"], name))
            for name in inv["python_tests"]:
                self.assertIn(name, python, "%s: no Python test %s" % (inv["id"], name))

    def test_every_rust_test_is_claimed_by_an_invariant(self):
        rust = set(re.findall(r"#\[test\]\s*fn (\w+)\(", self.rust))
        claimed = {n for inv in self.cases["invariants"] for n in inv["rust_tests"]}
        self.assertEqual(sorted(rust - claimed), [])

    def test_every_invariant_id_is_unique_and_stated(self):
        ids = [inv["id"] for inv in self.cases["invariants"]]
        self.assertEqual(len(ids), len(set(ids)))
        for inv in self.cases["invariants"]:
            self.assertTrue(inv["statement"].strip(), inv["id"])
            self.assertIn("inapplicable", inv)


if __name__ == "__main__":
    unittest.main()
