"""An independent model of fsonos/ssdp.rs (G03 slice 2, bead ffw-xvv), and the loader of its hand-written vectors.

It is written from the UPnP Device Architecture shapes and from docs/contracts/g03.md, not from the Rust: it uses no code of the adapter, parses
with bytes and `split`, and builds documents with `xml.sax.saxutils`. `Options` switches on one deliberate defect at a time; the tests require
the unbroken model to pass every vector and every defect to be caught by at least one."""
from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "g03_ssdp_vectors.json"

MULTICAST = "239.255.255.250"
PORT = 1900
MAX_DATAGRAM = 1500
MAX_LINE = 512
MAX_HEADERS = 24
MAX_TARGET = 160
MAX_MX = 5
MAX_MX_ACCEPTED = 120
DEVICE_TYPE = "urn:schemas-upnp-org:device:ZonePlayer:1"
SERVER = "franken-firmware/0 UPnP/1.0"
DESCRIPTION_PATH = "/xml/device_description.xml"
# (name, urn, control path, event path): transcribed from fsonos/soap.rs; ContentDirectory is retired and is never advertised.
SERVED = [
    ("RenderingControl", "urn:schemas-upnp-org:service:RenderingControl:1", "/MediaRenderer/RenderingControl/Control", "/MediaRenderer/RenderingControl/Event"),
    ("GroupRenderingControl", "urn:schemas-upnp-org:service:GroupRenderingControl:1", "/MediaRenderer/GroupRenderingControl/Control", "/MediaRenderer/GroupRenderingControl/Event"),
    ("AVTransport", "urn:schemas-upnp-org:service:AVTransport:1", "/MediaRenderer/AVTransport/Control", "/MediaRenderer/AVTransport/Event"),
    ("ZoneGroupTopology", "urn:schemas-upnp-org:service:ZoneGroupTopology:1", "/ZoneGroupTopology/Control", "/ZoneGroupTopology/Event"),
]
RETIRED = ("ContentDirectory", "urn:schemas-upnp-org:service:ContentDirectory:1", "/MediaServer/ContentDirectory/Control", "/MediaServer/ContentDirectory/Event")


@dataclasses.dataclass(frozen=True)
class Options:
    """One deliberate defect each. All False is the model."""
    lenient_line_endings: bool = False       # accept a bare LF
    man_without_quotes: bool = False
    no_mx_clamp: bool = False
    accept_mx_zero: bool = False
    duplicates_allowed: bool = False
    advertise_content_directory: bool = False
    case_sensitive_uuid: bool = False
    answer_everything: bool = False
    unescaped_name: bool = False
    delay_unbounded: bool = False
    byebye_with_location: bool = False
    accept_non_ascii: bool = False
    accept_trailing_body: bool = False
    answer_http_1_0_search: bool = False
    no_header_cap: bool = False
    accept_bad_uuid: bool = False
    accept_port_zero: bool = False


def services(opt: Options):
    return SERVED + ([RETIRED] if opt.advertise_content_directory else [])


# ------------------------------------------------------------------------------------------------ parsing

def parse(data: bytes, opt: Options = Options()) -> Tuple[Any, ...]:
    """('search', target, mx) | ('other', kind) | ('err', code)."""
    if len(data) > MAX_DATAGRAM:
        return ("err", "too_large")
    if not opt.accept_non_ascii and any(not (0x20 <= b <= 0x7E or b in (0x0D, 0x0A)) for b in data):
        return ("err", "not_printable_ascii")
    text = data.decode("latin-1")
    if not opt.lenient_line_endings:
        for i, ch in enumerate(text):
            if ch == "\r" and text[i + 1:i + 2] != "\n":
                return ("err", "bare_line_ending")
            if ch == "\n" and text[i - 1:i] != "\r":
                return ("err", "bare_line_ending")
        terminator = "\r\n\r\n"
    else:
        text = text.replace("\r\n", "\n")
        terminator = "\n\n"
    at = text.find(terminator)
    if at < 0:
        return ("err", "unterminated")
    if at + len(terminator) != len(text) and not opt.accept_trailing_body:
        return ("err", "trailing_bytes")
    lines = text[:at].split("\r\n" if not opt.lenient_line_endings else "\n")
    first = lines[0]
    if first == "M-SEARCH * HTTP/1.1" or (opt.answer_http_1_0_search and first == "M-SEARCH * HTTP/1.0"):
        return _search(lines[1:], opt)
    if first == "NOTIFY * HTTP/1.1":
        return ("other", "notify")
    if first.startswith("HTTP/1.1 "):
        return ("other", "response")
    pieces = first.split(" ")
    if (len(pieces) == 3 and pieces[1] == "*" and pieces[2] in ("HTTP/1.1", "HTTP/1.0") and 0 < len(pieces[0]) <= 16
            and all(c.isascii() and (c.isupper() or c == "-") for c in pieces[0])):
        return ("other", "method")
    return ("err", "bad_request_line")


def _search(lines: List[str], opt: Options) -> Tuple[Any, ...]:
    seen: Dict[str, str] = {}
    for count, line in enumerate(lines):
        if count >= MAX_HEADERS and not opt.no_header_cap:
            return ("err", "too_many_headers")
        if len(line) > MAX_LINE or line.startswith(" "):
            return ("err", "bad_header")
        if ":" not in line:
            return ("err", "bad_header")
        name, value = line.split(":", 1)
        if not name or len(name) > 32 or not all(c.isascii() and (c.isalnum() or c == "-") for c in name):
            return ("err", "bad_header")
        key = name.lower()
        if key in ("host", "man", "mx", "st"):
            if key in seen and not opt.duplicates_allowed:
                return ("err", "duplicate_header")
            seen.setdefault(key, value.strip(" "))
    for key, label in (("host", "HOST"),):
        if key not in seen:
            return ("err", "missing_header")
    host = seen["host"]
    if not (0 < len(host) <= 64 and all(c.isascii() and (c.isalnum() or c in ".:[]-") for c in host)):
        return ("err", "bad_header")
    if "man" not in seen:
        return ("err", "missing_header")
    wanted = "ssdp:discover" if opt.man_without_quotes else '"ssdp:discover"'
    if seen["man"] not in (wanted, '"ssdp:discover"'):
        return ("err", "bad_man")
    if "mx" not in seen:
        return ("err", "missing_header")
    mx_text = seen["mx"]
    if not mx_text or len(mx_text) > 3 or not all(c in "0123456789" for c in mx_text):
        return ("err", "bad_mx")
    mx = int(mx_text)
    if (mx < 1 and not opt.accept_mx_zero) or mx > MAX_MX_ACCEPTED:
        return ("err", "bad_mx")
    if "st" not in seen:
        return ("err", "missing_header")
    st = seen["st"]
    if not st or len(st) > MAX_TARGET or not all(0x21 <= ord(c) <= 0x7E for c in st):
        return ("err", "bad_target")
    return ("search", st, mx if opt.no_mx_clamp else min(mx, MAX_MX))


# ------------------------------------------------------------------------------------------------ the device

def valid_uuid(uuid: str) -> bool:
    if len(uuid) != 36:
        return False
    return all((c == "-") if i in (8, 13, 18, 23) else (c in "0123456789abcdef") for i, c in enumerate(uuid))


def new_device(uuid: str, port: int, name: str, max_age: int, opt: Options = Options()) -> Optional[str]:
    """None when accepted, else the error code, checked in the order uuid, port, name, max-age."""
    if not valid_uuid(uuid) and not opt.accept_bad_uuid:
        return "bad_uuid"
    if port == 0 and not opt.accept_port_zero:
        return "bad_port"
    if not name or len(name) > 64 or any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in name):
        return "bad_name"
    if not 1800 <= max_age <= 86400:
        return "bad_max_age"
    return None


class Device:
    def __init__(self, cfg: Dict[str, Any], opt: Options = Options()) -> None:
        self.uuid, self.address, self.port = cfg["uuid"], cfg["address"], cfg["port"]
        self.name, self.max_age, self.opt = cfg["name"], cfg["max_age"], opt

    @property
    def udn(self) -> str:
        return "uuid:" + self.uuid

    @property
    def location(self) -> str:
        return "http://%s:%d%s" % (".".join(str(o) for o in self.address), self.port, DESCRIPTION_PATH)

    def advertised(self) -> List[Tuple[str, str]]:
        out = [("upnp:rootdevice", self.udn + "::upnp:rootdevice"), (self.udn, self.udn), (DEVICE_TYPE, self.udn + "::" + DEVICE_TYPE)]
        out += [(urn, self.udn + "::" + urn) for _, urn, _, _ in services(self.opt)]
        return out

    def answers(self, target: str) -> List[Tuple[str, str]]:
        everything = self.advertised()
        if target == "ssdp:all" or self.opt.answer_everything:
            return everything
        hits = []
        for nt, usn in everything:
            if nt == target:
                hits.append((nt, usn))
            elif nt.startswith("uuid:") and not self.opt.case_sensitive_uuid and nt.lower() == target.lower():
                hits.append((nt, usn))
        return hits

    def response(self, target: str) -> List[List[List[str]]]:
        return [[["CACHE-CONTROL", "max-age=%d" % self.max_age], ["EXT", ""], ["LOCATION", self.location], ["SERVER", SERVER], ["ST", nt], ["USN", usn]]
                for nt, usn in self.answers(target)]

    def alive(self) -> List[List[List[str]]]:
        return [[["HOST", "%s:%d" % (MULTICAST, PORT)], ["CACHE-CONTROL", "max-age=%d" % self.max_age], ["LOCATION", self.location], ["NT", nt],
                 ["NTS", "ssdp:alive"], ["SERVER", SERVER], ["USN", usn]] for nt, usn in self.advertised()]

    def byebye(self) -> List[List[List[str]]]:
        out = []
        for nt, usn in self.advertised():
            headers = [["HOST", "%s:%d" % (MULTICAST, PORT)], ["NT", nt], ["NTS", "ssdp:byebye"], ["USN", usn]]
            if self.opt.byebye_with_location:
                headers.insert(1, ["LOCATION", self.location])
            out.append(headers)
        return out

    def description(self) -> str:
        name = self.name if self.opt.unescaped_name else xml_escape(self.name)
        body = "".join(
            "<service><serviceType>%s</serviceType><serviceId>urn:upnp-org:serviceId:%s</serviceId><controlURL>%s</controlURL><eventSubURL>%s</eventSubURL></service>"
            % (urn, n, ctl, ev) for n, urn, ctl, ev in services(self.opt))
        return ('<?xml version="1.0"?>\n<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device>'
                "<deviceType>%s</deviceType><friendlyName>%s</friendlyName><roomName>%s</roomName><manufacturer>FrankenFirmware</manufacturer>"
                "<modelName>franken-speaker</modelName><UDN>%s</UDN><serviceList>%s</serviceList></device></root>"
                ) % (DEVICE_TYPE, name, name, self.udn, body)


def delay_ms(mx: int, entropy: int, opt: Options = Options()) -> int:
    if opt.delay_unbounded:
        return entropy
    return entropy % (max(1, min(mx, MAX_MX)) * 1000)


def wire(start: str, headers: List[List[str]]) -> str:
    return start + "\r\n" + "".join("%s:%s\r\n" % (n, (" " + v) if v else "") for n, v in headers) + "\r\n"


def load() -> Dict[str, Any]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------------ checking

def datagram_of(case: Dict[str, Any]) -> bytes:
    text = case["raw"] if "raw" in case else wire(case["start"], case["headers"])
    return text.encode("utf-8")


def check_all(opt: Options = Options()) -> List[str]:
    v = load()
    failures: List[str] = []
    for case in v["parse"]:
        got = parse(datagram_of(case), opt)
        e = case["expect"]
        want = ("search", e["search"]["target"], e["search"]["mx"]) if "search" in e else ("other", e["other"]) if "other" in e else ("err", e["err"])
        if got != want:
            failures.append("parse %s: %r != %r" % (case["id"], got, want))
    dev = Device(v["device"], opt)
    for case in v["search"]:
        got = dev.answers(case["st"])
        want = [tuple(p) for p in case["expect"]]
        if got != want:
            failures.append("search %s: %r != %r" % (case["id"], got, want))
    if dev.location != v["location"]:
        failures.append("location")
    if dev.response(v["response"]["st"]) != [v["response"]["headers"]]:
        failures.append("response")
    if dev.alive() != [c["headers"] for c in v["notify_alive"]]:
        failures.append("notify_alive")
    if dev.byebye() != [c["headers"] for c in v["notify_byebye"]]:
        failures.append("notify_byebye")
    if dev.description() != v["description"]:
        failures.append("description")
    hostile = Device(dict(v["device"], name=v["description_hostile"]["name"]), opt).description()
    if "<friendlyName>%s</friendlyName>" % v["description_hostile"]["friendly_name_xml"] not in hostile:
        failures.append("description_hostile")
    if "<roomName>%s</roomName>" % v["description_hostile"]["friendly_name_xml"] not in hostile:
        failures.append("description_hostile_room")
    for case in v["delay"]:
        if delay_ms(case["mx"], case["entropy"], opt) != case["expect"]:
            failures.append("delay %r" % case)
    for case in v["device_reject"]:
        got = new_device(case["uuid"], case["port"], case["name"], case["max_age"], opt)
        if got != case["err"]:
            failures.append("device_reject %s: %r != %r" % (case["id"], got, case["err"]))
    ok = v["device"]
    if new_device(ok["uuid"], ok["port"], ok["name"], ok["max_age"], opt) is not None:
        failures.append("the vectors' own device was refused")
    return failures
