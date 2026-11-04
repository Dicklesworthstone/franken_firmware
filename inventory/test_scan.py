#!/usr/bin/env python3
"""Tests for inventory/scan.py (stdlib only, offline). NO live scan is ever performed: discovery and
fetching are injected, and the XML is parsed by the genuine ``xml.etree`` inside the one shared rule
(``reconcile.parse_description_xml``) that scan.py delegates to.

Run from the repository root:

    python3 -m unittest discover -s inventory -p 'test_scan.py' -v

Fixtures are synthetic UPnP device descriptions (RFC 5737 documentation addresses, invented serials).
They prove the parsing rule and the plumbing; they say nothing about any physical speaker. The real
files' shape (UDN is the only tag that differs between root and nested devices) is TealSeal's
read-only evidence, cited, not re-measured here.
"""

from __future__ import annotations

import ast
import contextlib
import datetime
import http.server
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import enrich  # noqa: E402
import scan  # noqa: E402

SCRIPT = HERE / "scan.py"
TOKEN = "SECRET-TOKEN-7731"  # planted in bad documents; must never be echoed in any error


def description_xml(n: int = 1, model: str = "S5", nested: bool = True, root_extra: str = "", **over) -> bytes:
    """A UPnP device description: a root <device> with leaf fields, plus (like real speakers) nested
    MediaServer/MediaRenderer devices that REPEAT UDN/modelName/friendlyName with different text."""
    fields = {
        "deviceType": "urn:schemas-upnp-org:device:ZonePlayer:1",
        "friendlyName": f"203.0.113.{10 + n} - Sonos Test Unit",
        "manufacturer": "Sonos, Inc.",
        "modelNumber": model,
        "modelName": "Sonos Test Unit",
        "softwareVersion": "57.23-74170",
        "hardwareVersion": "1.8.3.7-2.1",
        "seriesid": "P100",
        "serialNum": f"02-00-5E-00-00-{n:02X}:{n % 10}",
        "UDN": f"uuid:RINCON_02005E0000{n:02X}01400",
        "roomName": f"Zebra Lounge {n}",
        "memory": "32",
        "flash": "32",
    }
    fields.update(over)
    leaves = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items() if v is not None)
    sub = ""
    if nested:
        udn = fields["UDN"]
        sub = (
            "<deviceList>"
            f"<device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType><friendlyName>Media Server of {n}</friendlyName>"
            f"<modelName>Sonos Test Unit Media Server</modelName><modelNumber>{model}</modelNumber><UDN>{udn}_MS</UDN></device>"
            f"<device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>Media Renderer of {n}</friendlyName>"
            f"<modelName>Sonos Test Unit Media Renderer</modelName><modelNumber>{model}</modelNumber><UDN>{udn}_MR</UDN></device>"
            "</deviceList>"
        )
    service = "<serviceList><service><serviceType>urn:schemas-upnp-org:service:AlarmClock:1</serviceType><controlURL>/AlarmClock/Control</controlURL></service></serviceList>"
    return (
        '<?xml version="1.0"?>'
        '<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>'
        f"<device>{leaves}{root_extra}{service}{sub}</device></root>"
    ).encode()


def old_whole_tree_flatten(raw: bytes) -> dict:
    """REFERENCE ONLY: the expression scan.py used before the fix. Kept here to prove the new tests bite."""
    root = ET.fromstring(raw)
    return {el.tag.split("}")[-1]: el.text for el in root.iter() if len(el) == 0}


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        self.rc = scan._reconcile()


# ---------------------------------------------------------------------------
# import safety and "one parser"
# ---------------------------------------------------------------------------


class ImportAndStructureTests(Base):
    def test_import_does_no_network_no_file_io_and_loads_nothing(self):
        code = (
            "import builtins, importlib.util, os, socket, sys, urllib.request\n"
            "calls = []\n"
            "real_open = builtins.open\n"
            "def spy_open(*a, **k):\n    calls.append(('open', str(a[0]))); return real_open(*a, **k)\n"
            "def boom(*a, **k):\n    calls.append(('net', 'called')); raise AssertionError\n"
            "builtins.open = spy_open; socket.socket = boom; urllib.request.urlopen = boom\n"
            "spec = importlib.util.spec_from_file_location('scan_under_test', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            "builtins.open = real_open\n"
            "print(repr(calls)); print(repr(sorted(os.listdir('.')))); print('ffw_shared_reconcile' in sys.modules)\n"
        )
        proc = subprocess.run([sys.executable, "-I", "-c", code, str(SCRIPT)], cwd=self.dir, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls, listing, loaded = proc.stdout.strip().splitlines()
        self.assertEqual((calls, listing, loaded), ("[]", "[]", "False"), "import must touch nothing and load nothing")

    def test_scan_contains_no_xml_parser_of_its_own(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertFalse(imported & {"xml", "lxml", "defusedxml", "html"}, "a second parser has crept into scan.py")
        # os/signal/tempfile are reviewed: atomic publication and the SIGTERM handler (see PublicationTests). No parser.
        self.assertEqual(imported - {"__future__", "argparse", "datetime", "importlib", "json", "os", "pathlib", "signal", "socket", "sys", "tempfile", "time", "urllib"}, set())

    def test_scan_delegates_to_the_shared_rule_not_to_its_own_logic(self):
        sentinel = {"sentinel": "from-the-shared-rule"}
        with mock.patch.object(self.rc, "parse_description_xml", return_value=sentinel) as shared:
            rows = scan.build_rows({"http://203.0.113.11:1400/x"}, fetch=lambda url: b"<ignored/>")
        self.assertEqual(rows, [{"url": "http://203.0.113.11:1400/x", "fields": sentinel}])
        shared.assert_called_once()

    def test_fields_match_the_shared_rule_exactly(self):
        raw = description_xml(1)
        self.assertEqual(scan.fields_from_description(raw), self.rc.parse_description_xml(raw))

    def test_a_missing_shared_rule_stops_the_scan_before_any_network_use(self):
        lone = self.dir / "lone"
        lone.mkdir()
        (lone / "scan.py").write_bytes(SCRIPT.read_bytes())
        out = self.dir / "out"
        out.mkdir()
        code = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('scan_lone', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            "def discover():\n    print('DISCOVER-CALLED'); return set()\n"
            "print('RC', mod.main(['--out-dir', sys.argv[2], '--raw-dir', sys.argv[2]], discover=discover))\n"
        )
        run = subprocess.run([sys.executable, "-I", "-c", code, str(lone / "scan.py"), str(out)], capture_output=True, text=True, timeout=60)
        self.assertIn("RC 2", run.stdout)
        self.assertNotIn("DISCOVER-CALLED", run.stdout, "no packet may be sent without the shared rule")
        self.assertIn("shared_rule_missing", run.stderr)
        self.assertEqual(os.listdir(out), [], "no output without the shared rule")


# ---------------------------------------------------------------------------
# the producer fix: root device wins, nested repeats never become the unit's values
# ---------------------------------------------------------------------------


class NestedDeviceTests(Base):
    def test_root_device_values_win_over_nested_repeats(self):
        raw = description_xml(1)
        fields = scan.fields_from_description(raw)
        self.assertEqual(fields["UDN"], "uuid:RINCON_02005E00000101400", "the root device's UDN, with no _MS/_MR suffix")
        self.assertEqual(fields["modelName"], "Sonos Test Unit")
        self.assertEqual(fields["friendlyName"], "203.0.113.11 - Sonos Test Unit")
        for key, expected in {
            "modelNumber": "S5", "softwareVersion": "57.23-74170", "hardwareVersion": "1.8.3.7-2.1", "seriesid": "P100",
            "serialNum": "02-00-5E-00-00-01:1", "roomName": "Zebra Lounge 1", "memory": "32", "flash": "32",
        }.items():
            self.assertEqual(fields[key], expected, key)
        # only the root device's own direct leaves: containers and nested content are absent
        for absent in ("serviceType", "controlURL", "deviceList", "serviceList", "major", "minor"):
            self.assertNotIn(absent, fields)

    def test_the_old_whole_tree_flatten_would_have_failed_this(self):
        raw = description_xml(1)
        old = old_whole_tree_flatten(raw)
        # premise: on this document the old rule really did store the NESTED device's values...
        self.assertEqual(old["UDN"], "uuid:RINCON_02005E00000101400_MR")
        self.assertEqual(old["modelName"], "Sonos Test Unit Media Renderer")
        # ...so these assertions are not vacuous: the fixed path differs from the old one exactly there.
        new = scan.fields_from_description(raw)
        self.assertNotEqual(new["UDN"], old["UDN"])
        self.assertNotEqual(new["modelName"], old["modelName"])
        self.assertTrue(new["UDN"].endswith("01400") and not new["UDN"].endswith(("_MR", "_MS")))

    def test_a_document_with_no_nested_devices_is_unchanged(self):
        raw = description_xml(2, nested=False)
        self.assertEqual(scan.fields_from_description(raw)["UDN"], "uuid:RINCON_02005E00000201400")
        old = old_whole_tree_flatten(raw)
        for key in ("UDN", "modelName", "modelNumber", "serialNum", "memory"):
            self.assertEqual(scan.fields_from_description(raw)[key], old[key], key)

    def test_values_are_stripped_and_an_empty_leaf_is_an_empty_string(self):
        fields = scan.fields_from_description(description_xml(1, roomName="  Padded  ", flash=""))
        self.assertEqual((fields["roomName"], fields["flash"]), ("Padded", ""))

    def test_a_prefix_bound_upnp_namespace_is_accepted_like_a_default_binding(self):
        raw = (
            '<u:root xmlns:u="urn:schemas-upnp-org:device-1-0"><u:device><u:modelName>Prefixed</u:modelName>'
            "<u:UDN>uuid:RINCON_02005E00000901400</u:UDN></u:device></u:root>"
        ).encode()
        self.assertEqual(scan.fields_from_description(raw), {"modelName": "Prefixed", "UDN": "uuid:RINCON_02005E00000901400"})

    def test_an_identical_repeat_of_a_direct_field_is_accepted(self):
        fields = scan.fields_from_description(description_xml(1, root_extra="<seriesid>P100</seriesid>"))
        self.assertEqual(fields["seriesid"], "P100")


class HazardTests(Base):
    def codes(self, raw: bytes) -> str:
        with self.assertRaises(self.rc.InputError) as ctx:
            scan.fields_from_description(raw)
        err = ctx.exception
        self.assertNotIn(TOKEN, str(err) + getattr(err, "message", "") + getattr(err, "code", ""), "document content leaked into an error")
        return err.code

    def test_hostile_or_broken_documents_are_refused_with_a_code_and_no_content(self):
        bomb = (
            f'<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "{TOKEN}"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            "<root><device><UDN>&b;</UDN></device></root>"
        ).encode()
        cases = [
            ("entity bomb", bomb, "xml_doctype_forbidden"),
            ("lower-case doctype", b"<!doctype x><root><device/></root>", "xml_doctype_forbidden"),
            ("bare entity declaration", f'<!ENTITY a "{TOKEN}"><root/>'.encode(), "xml_doctype_forbidden"),
            ("conflicting repeated direct field", description_xml(1, root_extra=f"<seriesid>{TOKEN}</seriesid>"), "xml_duplicate_field"),
            ("no device element", f"<root><note>{TOKEN}</note></root>".encode(), "xml_shape"),
            ("device outside the UPnP namespace", f"<root><device><UDN>{TOKEN}</UDN></device></root>".encode(), "xml_namespace"),
            ("device in a foreign namespace", f'<root xmlns="urn:example:other"><device><UDN>{TOKEN}</UDN></device></root>'.encode(), "xml_namespace"),
            ("truncated", f"<root><device><UDN>{TOKEN}".encode(), "xml_parse"),
            ("not xml", f"{TOKEN} is not xml".encode(), "xml_parse"),
            ("empty", b"", "xml_parse"),
            ("oversize", b"<root>" + b"x" * (self.rc.MAX_INPUT_BYTES + 1), "input_too_large"),
        ]
        for name, raw, code in cases:
            with self.subTest(name):
                self.assertEqual(self.codes(raw), code)


# ---------------------------------------------------------------------------
# rows: one bad device never stops the rest, and nothing private leaks into errors
# ---------------------------------------------------------------------------


class RowTests(Base):
    URLS = {
        "good": "http://203.0.113.11:1400/xml/device_description.xml",
        "down": "http://203.0.113.12:1400/xml/device_description.xml",
        "bomb": "http://203.0.113.13:1400/xml/device_description.xml",
        "file": "file:///etc/hosts",
        "ftp": "ftp://203.0.113.14/xml",
        "tls": "https://203.0.113.15:1443/xml/device_description.xml",
    }

    def fake_fetch(self, calls):
        bomb = f'<!DOCTYPE x [<!ENTITY a "{TOKEN}">]><root><device/></root>'.encode()

        def fetch(url):
            calls.append(url)
            if url == self.URLS["down"]:
                raise OSError("connection refused")
            if url == self.URLS["bomb"]:
                return bomb
            return description_xml(1 if url == self.URLS["good"] else 5)

        return fetch

    def test_each_failure_is_confined_to_its_own_row(self):
        calls, saved = [], {}
        rows = scan.build_rows(set(self.URLS.values()), self.fake_fetch(calls), lambda i, raw: saved.__setitem__(i, raw))
        by_url = {r["url"]: r for r in rows}
        self.assertEqual([r["url"] for r in rows], sorted(self.URLS.values()), "rows come out in sorted-url order")
        self.assertIn("fields", by_url[self.URLS["good"]])
        self.assertIn("fields", by_url[self.URLS["tls"]], "https is allowed; one bad neighbour did not stop it")
        self.assertEqual(by_url[self.URLS["down"]], {"url": self.URLS["down"], "error": "connection refused"})
        self.assertEqual(by_url[self.URLS["bomb"]], {"url": self.URLS["bomb"], "error": "xml_doctype_forbidden"})
        self.assertNotIn(TOKEN, json.dumps(rows), "a parse failure records the rule's code, never document content")

    def test_non_http_locations_are_never_fetched(self):
        # urlopen would follow file:// or ftp:// from an unauthenticated SSDP reply and read a local file
        calls = []
        rows = scan.build_rows({self.URLS["file"], self.URLS["ftp"], self.URLS["good"]}, self.fake_fetch(calls), None)
        self.assertEqual(calls, [self.URLS["good"]], "only the http(s) location was fetched")
        errors = {r["url"]: r.get("error") for r in rows}
        self.assertEqual((errors[self.URLS["file"]], errors[self.URLS["ftp"]]), ("location_not_http", "location_not_http"))

    def test_an_error_that_holds_a_response_open_is_closed(self):
        class HoldsConnection(Exception):
            closed = False

            def close(self):
                self.closed = True

        held = HoldsConnection("HTTP Error 503")

        def fetch(url):
            raise held

        rows = scan.build_rows({self.URLS["good"]}, fetch)
        self.assertEqual(rows, [{"url": self.URLS["good"], "error": "HTTP Error 503"}])
        self.assertTrue(held.closed, "an HTTPError keeps its socket until closed")

    def test_raw_bytes_are_saved_before_parsing_under_stable_indices(self):
        saved = {}
        scan.build_rows(set(self.URLS.values()), self.fake_fetch([]), lambda i, raw: saved.__setitem__(i, raw))
        order = sorted(self.URLS.values())
        # fetched and saved: good, bomb (saved even though its parse failed), tls. Not saved: down (no bytes), file, ftp.
        self.assertEqual(sorted(saved), sorted(order.index(self.URLS[k]) for k in ("good", "bomb", "tls")))
        self.assertIn(b"<!DOCTYPE", saved[order.index(self.URLS["bomb"])])


# ---------------------------------------------------------------------------
# SSDP discovery code, aimed at an isolated 127.0.0.1 UDP responder (never multicast, never the LAN)
# ---------------------------------------------------------------------------


class _Responder:
    """A loopback UDP socket that records every datagram it receives and answers each with ``replies``."""

    def __init__(self, replies):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.replies, self.received, self._stop = replies, [], threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def addr(self):
        return self.sock.getsockname()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, sender = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.received.append(data)
            for reply in self.replies:
                self.sock.sendto(reply, sender)

    def close(self):
        self._stop.set()
        self.thread.join(5)
        self.sock.close()


def _ssdp_reply(location_line: str) -> bytes:
    return f"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age = 1800\r\n{location_line}\r\nST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n".encode()


class DiscoveryTests(Base):
    FAST = dict(rounds=2, listen_seconds=0.3, recv_timeout=0.05)

    def responder(self, replies):
        r = _Responder(replies)
        self.addCleanup(r.close)
        return r

    def test_locations_are_parsed_deduplicated_and_junk_is_survived(self):
        replies = [
            _ssdp_reply("LOCATION: http://203.0.113.11:1400/xml/device_description.xml"),
            _ssdp_reply("Location:http://203.0.113.12:1400/xml/device_description.xml"),       # mixed case, no space
            _ssdp_reply("location:    http://203.0.113.13:1400/xml/device_description.xml  "),  # lower case, padded
            b"\xff\xfe\x00 not utf-8 \x80\x81 LOCATION: http://203.0.113.14:1400/x",            # undecodable bytes
            b"HTTP/1.1 200 OK\r\nST: urn:x\r\n\r\n",                                             # no LOCATION header
            _ssdp_reply("LOCATION:"),                                                           # blank value
            b"X-NOTE: location: http://203.0.113.66:1400/evil\r\n\r\n",                         # not at the start of a line
            _ssdp_reply("LOCATION: http://203.0.113.11:1400/xml/device_description.xml"),       # repeat of the first
        ]
        found = scan.discover_locations(addr=self.responder(replies).addr, **self.FAST)
        self.assertEqual(
            found,
            {
                "http://203.0.113.11:1400/xml/device_description.xml",
                "http://203.0.113.12:1400/xml/device_description.xml",
                "http://203.0.113.13:1400/xml/device_description.xml",
            },
        )

    def test_the_search_message_and_round_count_are_what_the_protocol_needs(self):
        r = self.responder([])
        scan.discover_locations(addr=r.addr, rounds=3, listen_seconds=0.15, recv_timeout=0.05)
        self.assertEqual(len(r.received), 3, "one M-SEARCH per round")
        text = r.received[0].decode()
        self.assertTrue(text.startswith("M-SEARCH * HTTP/1.1\r\n"))
        for header in ('HOST: 239.255.255.250:1900', 'MAN: "ssdp:discover"', "ST: urn:schemas-upnp-org:device:ZonePlayer:1"):
            self.assertIn(header, text)
        self.assertTrue(text.endswith("\r\n\r\n"))
        self.assertEqual((scan.SSDP_ADDR, scan.SSDP_ROUNDS, scan.SSDP_LISTEN_SECONDS), (("239.255.255.250", 1900), 3, 3), "real defaults are unchanged")

    def test_silence_returns_an_empty_set_within_the_window(self):
        r = self.responder([])
        started = time.monotonic()
        self.assertEqual(scan.discover_locations(addr=r.addr, rounds=2, listen_seconds=0.2, recv_timeout=0.05), set())
        self.assertLess(time.monotonic() - started, 2.0, "the listen window bounds the wait")

    def test_the_socket_is_closed_on_success_and_on_failure(self):
        opened = []

        class Spy(socket.socket):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self.was_closed = False
                self.timeouts = []
                opened.append(self)

            def settimeout(self, value):
                self.timeouts.append(value)
                super().settimeout(value)

            def close(self):
                self.was_closed = True
                super().close()

        r = self.responder([_ssdp_reply("LOCATION: http://203.0.113.11:1400/x")])
        with mock.patch.object(scan.socket, "socket", Spy):
            scan.discover_locations(addr=r.addr, **self.FAST)
        self.assertEqual([s.was_closed for s in opened], [True])
        self.assertEqual(opened[0].timeouts, [0.05], "the receive timeout is the one passed in (0.5 s by default)")

        class Failing(Spy):
            def sendto(self, *a, **k):
                raise OSError("network unreachable")

        opened.clear()
        with mock.patch.object(scan.socket, "socket", Failing):
            with self.assertRaises(OSError):
                scan.discover_locations(addr=r.addr, **self.FAST)
        self.assertEqual([s.was_closed for s in opened], [True], "closed even when the send fails")

    def test_discovered_locations_feed_the_fetch_path_end_to_end(self):
        pages = {"http://203.0.113.11:1400/xml/device_description.xml": description_xml(1)}
        r = self.responder([_ssdp_reply("LOCATION: " + u) for u in pages])
        found = scan.discover_locations(addr=r.addr, **self.FAST)
        rows = scan.build_rows(found, lambda url: pages[url])
        self.assertEqual([x["fields"]["UDN"] for x in rows], ["uuid:RINCON_02005E00000101400"])


# ---------------------------------------------------------------------------
# the real fetch function, against an isolated loopback server (never the LAN)
# ---------------------------------------------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    documents: dict = {}

    def do_GET(self):  # noqa: N802 (http.server API)
        body = self.documents.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client stopped reading at its bound, which is exactly what is being tested

    def log_message(self, *args):
        pass


class LoopbackFetchTests(Base):
    def setUp(self):
        super().setUp()
        patch_env = mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"})
        patch_env.start()
        self.addCleanup(patch_env.stop)
        self.ok = description_xml(1)
        self.limit = self.rc.MAX_INPUT_BYTES
        _Handler.documents = {"/ok": self.ok, "/big": b"<root>" + b"x" * (2 * self.limit)}
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close(), thread.join(5)))
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def test_a_normal_document_is_returned_whole_and_parses_to_the_root_device(self):
        raw = scan.fetch_description(self.base + "/ok")
        self.assertEqual(raw, self.ok)
        self.assertEqual(scan.fields_from_description(raw)["modelName"], "Sonos Test Unit")

    def test_the_read_is_bounded_one_byte_past_the_shared_limit(self):
        raw = scan.fetch_description(self.base + "/big")
        self.assertEqual(len(raw), self.limit + 1, "an unbounded read would have returned all of the oversized body")
        rows = scan.build_rows({self.base + "/big", self.base + "/ok"}, scan.fetch_description)
        by_url = {r["url"]: r for r in rows}
        self.assertEqual(by_url[self.base + "/big"]["error"], "input_too_large")
        self.assertIn("fields", by_url[self.base + "/ok"], "the oversized neighbour did not stop the good one")

    def test_an_http_error_is_recorded_in_its_row_only(self):
        rows = scan.build_rows({self.base + "/missing", self.base + "/ok"}, scan.fetch_description)
        by_url = {r["url"]: r for r in rows}
        self.assertIn("404", by_url[self.base + "/missing"]["error"])
        self.assertIn("fields", by_url[self.base + "/ok"])


# ---------------------------------------------------------------------------
# main(): output placement and the full producer -> consumer chain
# ---------------------------------------------------------------------------


class MainTests(Base):
    def run_main(self, urls, fetch, *extra):
        out_dir, raw_dir = self.dir / "out", self.dir / "raw"
        out_dir.mkdir(exist_ok=True)
        out, err = io.StringIO(), io.StringIO()
        code = scan.main(["--out-dir", str(out_dir), "--raw-dir", str(raw_dir), *extra], discover=lambda: set(urls), fetch=fetch, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue(), out_dir, raw_dir

    def serve(self, models):
        pages = {f"http://203.0.113.{10 + n}:1400/xml/device_description.xml": description_xml(n, m) for n, m in enumerate(models, start=1)}
        return pages, (lambda url: pages[url])

    def test_writes_devices_json_privately_and_raw_xml_only_to_the_raw_dir(self):
        pages, fetch = self.serve(["S5", "S3", "ZB100"])
        code, out, err, out_dir, raw_dir = self.run_main(pages, fetch)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(sorted(os.listdir(out_dir)), ["devices.json"], "no raw XML beside devices.json (inventory/ is not git-ignored)")
        self.assertEqual(sorted(os.listdir(raw_dir)), ["device-0.xml", "device-1.xml", "device-2.xml"])
        for i, url in enumerate(sorted(pages)):
            self.assertEqual((raw_dir / f"device-{i}.xml").read_bytes(), pages[url], "raw capture is byte-exact")
        doc = json.loads((out_dir / "devices.json").read_text())
        self.assertEqual(sorted(doc), ["devices", "method", "observed_at"])
        self.assertIsNotNone(datetime.datetime.fromisoformat(doc["observed_at"]).utcoffset(), "observed_at must carry its UTC offset")
        self.assertEqual(doc["method"], "SSDP ZonePlayer M-SEARCH, three rounds; description GET", "shape is unchanged from the original script")
        self.assertEqual([d["fields"]["modelNumber"] for d in doc["devices"]], ["S5", "S3", "ZB100"])
        self.assertTrue(all(not d["fields"]["UDN"].endswith(("_MR", "_MS")) for d in doc["devices"]))
        # the console shows only the short identity subset, as before
        for line in out.splitlines():
            shown = json.loads(line.split(" ", 1)[1])
            self.assertLessEqual(set(shown), set(scan.SHOW_KEYS))

    def test_defaults_point_at_git_ignored_places(self):
        ignore = (REPO / ".gitignore").read_text().splitlines()
        self.assertEqual(scan.DEFAULT_RAW_DIR, ".local-real")
        self.assertIn(".local-real/", ignore)
        self.assertEqual(scan.DEFAULT_OUT_DIR, "inventory")
        self.assertIn("devices.json", ignore)

    def test_a_bad_device_is_reported_on_stderr_and_does_not_stop_the_scan(self):
        pages, fetch = self.serve(["S5", "S3"])
        bad = "http://203.0.113.99:1400/xml/device_description.xml"
        pages[bad] = b"<root/>"
        code, out, err, out_dir, _ = self.run_main(pages, lambda url: pages[url])
        self.assertEqual(code, 0)
        self.assertIn("xml_shape", err)
        doc = json.loads((out_dir / "devices.json").read_text())
        self.assertEqual(sum("fields" in d for d in doc["devices"]), 2)
        self.assertEqual(sum("error" in d for d in doc["devices"]), 1)

    def test_nothing_is_sent_when_the_output_directory_is_missing(self):
        called = []
        err = io.StringIO()
        code = scan.main(["--out-dir", str(self.dir / "absent"), "--raw-dir", str(self.dir / "raw")], discover=lambda: called.append(1) or set(), fetch=lambda u: b"", stdout=io.StringIO(), stderr=err)
        self.assertEqual((code, called), (2, []))
        self.assertIn("out_dir_missing", err.getvalue())

    def test_no_answer_still_writes_an_empty_list_and_says_so(self):
        code, _, err, out_dir, raw_dir = self.run_main(set(), lambda u: b"")
        self.assertEqual(code, 0)
        self.assertIn("no ZonePlayer answered", err)
        self.assertEqual(json.loads((out_dir / "devices.json").read_text())["devices"], [])
        self.assertFalse(raw_dir.exists(), "no raw directory is created when there is nothing to save")

    def test_usage_errors_exit_two(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scan.main(["--no-such-flag"], discover=lambda: set(), fetch=lambda u: b""), 2)

    def test_scan_output_flows_through_enrich_and_reconcile_with_the_root_device_identity(self):
        pages, fetch = self.serve(["S5", "S3", "ZB100"])
        code, _, _, out_dir, _ = self.run_main(pages, fetch)
        self.assertEqual(code, 0)
        devices = out_dir / "devices.json"
        # enrich: every record carries the ROOT device's model name, never a nested device's
        sanitized = self.dir / "sanitized.json"
        e_out, e_err = io.StringIO(), io.StringIO()
        self.assertEqual(enrich.main(["--devices", str(devices), "--nominal-unit", "MB", "--out", str(sanitized)], stdout=e_out, stderr=e_err), 0, e_err.getvalue())
        text = sanitized.read_text()
        records = json.loads(text)["devices"]
        self.assertEqual({r["device_reported"]["model_name"] for r in records}, {"Sonos Test Unit"})
        self.assertNotIn("Media Renderer", text)
        self.assertNotIn("Media Server", text)
        self.assertNotIn("_MR", text)
        self.assertEqual(len({r["device_ref"] for r in records}), 3)
        # reconcile: three distinct root identities merge with nothing, and none is ambiguous
        r_out, r_err = io.StringIO(), io.StringIO()
        rcode = self.rc.main(["--input", str(devices), "--nominal-unit", "MB", "--allow-incomplete"], stdout=r_out, stderr=r_err)
        self.assertEqual(rcode, 0, r_err.getvalue())
        manifest = json.loads(r_out.getvalue())
        self.assertEqual(manifest["summary"]["identity_components"], 3)
        self.assertEqual(manifest["conflicts"], [])
        self.assertNotIn("identity_ambiguous", r_out.getvalue())


# ---------------------------------------------------------------------------
# cancellation and restart of publication (devices.json and raw captures are written whole or not at all)
# ---------------------------------------------------------------------------


def _pages(*ns):
    return {f"http://203.0.113.{10 + n}:1400/xml/device_description.xml": description_xml(n) for n in ns}


def _minus_time(raw: bytes) -> dict:
    return {k: v for k, v in json.loads(raw).items() if k != "observed_at"}


class PublicationTests(Base):
    """Each test starts from a complete earlier scan of devices A and then cuts a scan of devices B short."""

    def setUp(self):
        super().setUp()
        self.out_dir, self.raw_dir = self.dir / "out", self.dir / "raw"
        self.out_dir.mkdir()
        self.a, self.b = _pages(1, 2), _pages(3, 4)
        self.assertEqual(self.scan(self.a)[0], 0)
        self.prev = (self.out_dir / "devices.json").read_bytes()
        ref_out, self.ref_raw = self.dir / "ref_out", self.dir / "ref_raw"
        ref_out.mkdir()
        self.assertEqual(self.scan(self.b, ref_out, self.ref_raw)[0], 0)
        self.ref_doc = _minus_time((ref_out / "devices.json").read_bytes())
        self.assertNotEqual(self.ref_doc, _minus_time(self.prev), "premise: B differs from A, or an untouched file proves nothing")

    def scan(self, pages, out_dir=None, raw_dir=None, discover=None, fetch=None):
        out, err = io.StringIO(), io.StringIO()
        code = scan.main(
            ["--out-dir", str(out_dir or self.out_dir), "--raw-dir", str(raw_dir or self.raw_dir)],
            discover=discover or (lambda: set(pages)), fetch=fetch or (lambda url: pages[url]), stdout=out, stderr=err,
        )
        return code, out.getvalue(), err.getvalue()

    def temps(self):
        return [str(p) for d in (self.out_dir, self.raw_dir) if d.is_dir() for p in d.iterdir() if p.name.startswith(".scan-")]

    @staticmethod
    def nth(n, exc, real):
        calls = []

        def wrapper(*a, **k):
            calls.append(1)
            if len(calls) == n:
                raise exc
            return real(*a, **k)

        return calls, wrapper

    def assert_previous_kept_and_clean(self):
        self.assertEqual((self.out_dir / "devices.json").read_bytes(), self.prev, "the previous devices.json must be byte-identical")
        self.assertEqual(self.temps(), [])

    def assert_rerun_converges(self):
        self.assertEqual(self.scan(self.b)[0], 0)
        self.assertEqual(_minus_time((self.out_dir / "devices.json").read_bytes()), self.ref_doc)
        for name in ("device-0.xml", "device-1.xml"):
            self.assertEqual((self.raw_dir / name).read_bytes(), (self.ref_raw / name).read_bytes())

    def test_success_leaves_no_temp_files_and_only_private_modes(self):
        self.assertEqual(sorted(p.name for p in self.out_dir.iterdir()), ["devices.json"])
        self.assertEqual(sorted(p.name for p in self.raw_dir.iterdir()), ["device-0.xml", "device-1.xml"])
        for path in (self.out_dir / "devices.json", self.raw_dir / "device-0.xml", self.raw_dir / "device-1.xml"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path.name)

    def test_interrupt_while_staging_devices_json_keeps_the_previous_file(self):
        calls, wrapper = self.nth(3, KeyboardInterrupt(), os.fsync)  # fsyncs: raw 0, raw 1, then devices.json
        with mock.patch.object(scan.os, "fsync", side_effect=wrapper):
            code, _, err = self.scan(self.b)
        self.assertEqual(len(calls), 3, "premise: the interrupt fired while devices.json was being staged")
        self.assertEqual(code, 130)
        self.assertIn("interrupted: devices.json was not written", err)
        self.assertIn("2 raw capture(s) already saved whole", err)
        self.assert_previous_kept_and_clean()
        for i, url in enumerate(sorted(self.b)):
            self.assertEqual((self.raw_dir / f"device-{i}.xml").read_bytes(), self.b[url], "a saved capture is whole, never partial")
        self.assert_rerun_converges()

    def test_a_full_disk_while_staging_devices_json_is_a_clean_failure(self):
        calls, wrapper = self.nth(3, OSError(28, "No space left on device"), os.fsync)
        with mock.patch.object(scan.os, "fsync", side_effect=wrapper):
            code, _, err = self.scan(self.b)
        self.assertEqual(len(calls), 3)
        self.assertEqual(code, 5)
        self.assertIn("output_write_failed: No space left on device", err)
        self.assert_previous_kept_and_clean()
        self.assert_rerun_converges()

    def test_interrupt_between_a_raw_files_stage_and_rename_leaves_it_whole_or_absent(self):
        calls, wrapper = self.nth(2, KeyboardInterrupt(), os.replace)  # renames: raw 0 lands, raw 1 is cut short
        with mock.patch.object(scan.os, "replace", side_effect=wrapper):
            code, _, err = self.scan(self.b)
        self.assertEqual(len(calls), 2)
        self.assertEqual(code, 130)
        self.assertIn("1 raw capture(s) already saved whole", err)
        self.assert_previous_kept_and_clean()
        urls = sorted(self.b)
        self.assertEqual((self.raw_dir / "device-0.xml").read_bytes(), self.b[urls[0]], "the rename that completed is whole")
        self.assertEqual((self.raw_dir / "device-1.xml").read_bytes(), self.a[sorted(self.a)[1]], "the cut-short capture kept its previous content")
        self.assert_rerun_converges()

    def test_interrupt_during_discovery_writes_nothing_and_creates_nothing(self):
        fresh_out, fresh_raw = self.dir / "fresh_out", self.dir / "fresh_raw"
        fresh_out.mkdir()

        def discover():
            raise KeyboardInterrupt

        code, _, err = self.scan(self.b, fresh_out, fresh_raw, discover=discover)
        self.assertEqual(code, 130)
        self.assertIn("0 raw capture(s)", err)
        self.assertEqual(list(fresh_out.iterdir()), [], "no devices.json for a scan that never finished")
        self.assertFalse(fresh_raw.exists())
        self.assertEqual(self.scan(self.a, fresh_out, fresh_raw)[0], 0, "a rerun in the same place succeeds")

    def test_interrupt_during_a_later_fetch_keeps_earlier_captures_whole_and_publishes_no_partial_scan(self):
        urls = sorted(self.b)

        def fetch(url):
            if url == urls[1]:
                raise KeyboardInterrupt
            return self.b[url]

        code, _, err = self.scan(self.b, fetch=fetch)
        self.assertEqual(code, 130)
        self.assertIn("1 raw capture(s) already saved whole", err)
        self.assert_previous_kept_and_clean()
        self.assertEqual((self.raw_dir / "device-0.xml").read_bytes(), self.b[urls[0]])
        self.assert_rerun_converges()

    def test_a_network_failure_during_discovery_is_a_clean_error_with_nothing_touched(self):
        def discover():
            raise OSError(51, "Network is unreachable")

        code, _, err = self.scan(self.b, discover=discover)
        self.assertEqual(code, 4)
        self.assertIn("discovery_failed: Network is unreachable", err)
        self.assert_previous_kept_and_clean()

    def test_an_unwritable_capture_directory_is_fatal_not_a_device_row(self):
        blocker = self.dir / "a-file"
        blocker.write_text("not a directory")
        code, _, err = self.scan(self.b, raw_dir=blocker / "raw")
        self.assertEqual(code, 5)
        self.assertIn("output_write_failed", err)
        self.assert_previous_kept_and_clean()  # in particular: no devices.json that pretends the scan succeeded

    def test_a_failed_raw_rename_is_fatal_not_a_device_row(self):
        calls, wrapper = self.nth(1, OSError(13, "Permission denied"), os.replace)
        with mock.patch.object(scan.os, "replace", side_effect=wrapper):
            code, _, err = self.scan(self.b)
        self.assertEqual(len(calls), 1)
        self.assertEqual((code, "output_write_failed: Permission denied" in err), (5, True))
        self.assert_previous_kept_and_clean()

    def test_temp_files_are_staged_beside_their_destination(self):
        # A rename across filesystems is not atomic; the temp must live in the destination's own directory.
        seen, real = [], tempfile.mkstemp

        def spy(*a, **k):
            seen.append(k.get("dir"))
            return real(*a, **k)

        with mock.patch.object(scan.tempfile, "mkstemp", side_effect=spy):
            self.assertEqual(self.scan(self.b)[0], 0)
        self.assertEqual(sorted(seen), sorted([str(self.raw_dir), str(self.raw_dir), str(self.out_dir)]))

    def test_stale_temp_files_from_a_killed_run_are_ignored_and_never_removed(self):
        stale = [self.out_dir / ".scan-killed.tmp", self.raw_dir / ".scan-killed.tmp"]
        for path in stale:
            path.write_bytes(b"half-written by a SIGKILLed scan")
        self.assertEqual(self.scan(self.b)[0], 0)
        self.assertEqual(_minus_time((self.out_dir / "devices.json").read_bytes()), self.ref_doc)
        for path in stale:
            self.assertEqual(path.read_bytes(), b"half-written by a SIGKILLed scan", "a file this run did not create is left alone")

    @unittest.skipUnless(os.name == "posix" and hasattr(signal, "SIGTERM"), "needs POSIX signals")
    def test_a_real_sigterm_in_a_real_process_takes_the_same_clean_path(self):
        urls = sorted(self.b)
        for i, url in enumerate(urls):
            (self.dir / f"page-{i}.xml").write_bytes(self.b[url])
        child = (
            "import importlib.util, os, signal, sys\n"
            "spec = importlib.util.spec_from_file_location('scan_child', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            "urls = sys.argv[4:6]; pages = {u: open(p, 'rb').read() for u, p in zip(urls, sys.argv[6:8])}\n"
            "real, n = os.fsync, [0]\n"
            "def fsync(fd):\n"
            "    n[0] += 1\n"
            "    if n[0] == 3:\n"
            "        os.kill(os.getpid(), signal.SIGTERM)\n"
            "    return real(fd)\n"
            "os.fsync = fsync\n"
            "code = mod.main(['--out-dir', sys.argv[2], '--raw-dir', sys.argv[3]], discover=lambda: set(urls), fetch=lambda u: pages[u])\n"
            "print('FSYNC_CALLS', n[0]); print('HANDLER_RESTORED', signal.getsignal(signal.SIGTERM) == signal.SIG_DFL)\n"
            "sys.exit(code)\n"
        )
        run = subprocess.run(
            [sys.executable, "-I", "-c", child, str(SCRIPT), str(self.out_dir), str(self.raw_dir), *urls, *[str(self.dir / f"page-{i}.xml") for i in range(2)]],
            capture_output=True, text=True, timeout=60,
        )
        # Literal on purpose: 130 is the interrupt status shared with enrich.py and reconcile.py.
        self.assertEqual(run.returncode, 130, (run.stdout, run.stderr))
        self.assertIn("FSYNC_CALLS 3", run.stdout, "premise: the signal arrived while devices.json was being staged")
        self.assertIn("HANDLER_RESTORED True", run.stdout)
        self.assertIn("interrupted", run.stderr)
        self.assert_previous_kept_and_clean()


if __name__ == "__main__":
    unittest.main(verbosity=2)
