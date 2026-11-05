#!/usr/bin/env python3
"""An independent model of the G03 fsonos compatibility adapter's pure parts (bead ffw-xvv).

    python3 -B -I tests/g03/reference.py --check      replay every golden vector against the model

The model is written from docs/contracts/g03.md, not from the Rust: it has its own tokenizer for the
restricted XML subset, its own escaping, its own argument validation, and its own GENA subscription
table. The Rust half replays the SAME vectors (crates/franken-control/src/fsonos/replay.rs). The vectors
are hand-written; neither side produced them. When the two agree on every vector, an implementation
and a model built separately reach the same answers, which is the point; a vector the Rust replay
fails while the model passes is a defect in the Rust or a hole in the contract, and neither is
hidden.

What this does NOT cover: the endpoint's routing and its ingress policy (the tailnet authorization,
the legacy bridge, the mapping onto N02 commands, N02's own refusals). Those are checked by the Rust
unit tests in fsonos/server.rs only, which run under the centralized build, and have no independent
model. docs/contracts/g03.md says so.

`Options` switches deliberately wrong behaviours on, one at a time. tests/g03/test_reference_model.py
checks that every such variant fails at least one vector after first checking that the unbroken model
passes them all.
"""

import argparse
import dataclasses
import ipaddress
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "g03_vectors.json"
USAGE = Path(__file__).resolve().parent / "usage_matrix.json"

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
U32_MAX = 2**32 - 1

# What the endpoint implements. This is the contract's list (g03.md section 4), written out here on
# purpose rather than read from the Rust table; a test compares the two.
IMPLEMENTED = {
    ("ZoneGroupTopology", "GetZoneGroupState"),
    ("AVTransport", "GetTransportInfo"),
    ("AVTransport", "Stop"),
    ("RenderingControl", "GetVolume"),
    ("RenderingControl", "SetVolume"),
    ("RenderingControl", "GetMute"),
    ("RenderingControl", "SetMute"),
    ("RenderingControl", "SetRelativeVolume"),
    ("GroupRenderingControl", "GetGroupVolume"),
    ("GroupRenderingControl", "SnapshotGroupVolume"),
    ("GroupRenderingControl", "SetGroupVolume"),
    ("GroupRenderingControl", "SetRelativeGroupVolume"),
}


@dataclasses.dataclass
class Options:
    """Deliberate defects, off by default. Each one is what a careless implementation would do."""

    allow_doctype: bool = False          # skip a DOCTYPE instead of refusing it
    decode_named_entities: bool = False  # treat an unknown &name; as empty text instead of refusing it
    size_check_after_parse: bool = False  # parse first, check the size afterwards
    unlimited_args: bool = False         # no cap on the number of arguments
    allow_repeated_args: bool = False    # later argument silently wins
    clamp_volume: bool = False           # clamp 101 to 100 instead of refusing it
    unicode_digits: bool = False         # accept any Unicode digit
    defer_as_success: bool = False       # answer a deferred action as if it worked
    seq_wraps_to_zero: bool = False      # SEQ goes 0 after 4294967295
    callback_any_host: bool = False      # accept a callback naming another host
    no_clamp_timeout: bool = False       # take the requested timeout as it is
    renewal_takes_callback: bool = False  # a renewal may change the callback
    resend_unchanged: bool = False       # publish even when nothing changed
    full_state_every_event: bool = False  # events carry every variable, not the changed ones
    forget_late_subscriber: bool = False  # a new subscriber is not told the current state
    unbounded_table: bool = False        # no cap on subscriptions
    renew_from_old_expiry: bool = False  # a renewal extends the old expiry rather than starting at now
    text_escape_only_angle: bool = False  # escape < and > but not &
    keep_control_characters: bool = False  # write a control character instead of U+FFFD


class Fault(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


# ---- escaping -------------------------------------------------------------------------------------


def allowed_char(c):
    o = ord(c)
    return c in "\t\n\r" or 0x20 <= o <= 0xD7FF or 0xE000 <= o <= 0xFFFD or 0x10000 <= o <= 0x10FFFF


def escape(opts, text, mode):
    out = []
    for c in text:
        if c == "&" and not opts.text_escape_only_angle:
            out.append("&amp;")
        elif c == "<":
            out.append("&lt;")
        elif c == ">":
            out.append("&gt;")
        elif c == '"' and mode == "attribute":
            out.append("&quot;")
        elif c == "'" and mode == "attribute":
            out.append("&apos;")
        elif allowed_char(c) or opts.keep_control_characters:
            out.append(c)
        else:
            out.append("�")
    return "".join(out)


# ---- the bounded XML subset ---------------------------------------------------------------------

PREDEFINED = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
TAG = re.compile(r"<([^\s/>=!?<][^\s/>=<]*)((?:\s+[^\s=/>]+\s*=\s*(?:\"[^\"<]*\"|'[^'<]*'))*)\s*(/?)>")
ATTR = re.compile(r"([^\s=/>]+)\s*=\s*(?:\"([^\"<]*)\"|'([^'<]*)')")
END = re.compile(r"</([^\s>/<]+)\s*>")


def decode(opts, raw, limits):
    out = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c != "&":
            out.append(c)
            i += 1
            continue
        semi = raw.find(";", i)
        if semi < 0:
            raise Fault("Malformed")
        name = raw[i + 1:semi]
        if name in PREDEFINED:
            out.append(PREDEFINED[name])
        elif name.startswith("#"):
            digits = name[1:]
            try:
                code = int(digits[1:], 16) if digits.startswith("x") else int(digits, 10)
                ch = chr(code)
            except (ValueError, OverflowError):
                raise Fault("Malformed")
            if not allowed_char(ch):
                raise Fault("Malformed")
            out.append(ch)
        elif opts.decode_named_entities:
            pass
        else:
            raise Fault("UnsupportedXml")
        i = semi + 1
    text = "".join(out)
    if len(text.encode("utf-8")) > limits["max_value_len"]:
        raise Fault("Malformed")
    if not all(allowed_char(c) for c in text):
        raise Fault("Malformed")
    return text


def tokens(opts, text, limits):
    """Yield ('start', name, attrs, empty) / ('end', name) / ('text', s), raising Fault lazily."""
    pos = 0
    if text.startswith("<?xml"):
        if not text[5:6].isspace():
            raise Fault("UnsupportedXml")
        end = text.find("?>")
        if end < 0:
            raise Fault("Malformed")
        declaration = text[5:end].lower()
        if "encoding" in declaration and not ("utf-8" in declaration or "utf8" in declaration):
            raise Fault("UnsupportedXml")
        if "standalone" in declaration:
            raise Fault("UnsupportedXml")
        pos = end + 2
    stack = []
    elements = 0
    while pos < len(text):
        if text[pos] == "<":
            if text.startswith("<!", pos):
                if not opts.allow_doctype:
                    raise Fault("UnsupportedXml")
                close = text.find(">", pos)
                pos = close + 1 if close >= 0 else len(text)
                continue
            if text.startswith("<?", pos):
                raise Fault("UnsupportedXml")
            if text.startswith("</", pos):
                m = END.match(text, pos)
                if not m or not stack or stack.pop() != m.group(1):
                    raise Fault("Malformed")
                pos = m.end()
                yield ("end", m.group(1))
                continue
            m = TAG.match(text, pos)
            if not m:
                raise Fault("Malformed")
            name, attr_text, empty = m.group(1), m.group(2), m.group(3) == "/"
            attrs = [(a, b if b is not None else c) for a, b, c in ATTR.findall(attr_text)]
            elements += 1
            if (len(stack) + 1 > limits["max_depth"] or elements > limits["max_elements"]
                    or len(attrs) > limits["max_attributes"] or len(name) > limits["max_name_len"]
                    or any(len(v) > limits["max_value_len"] for _, v in attrs)):
                raise Fault("Malformed")
            attrs = [(a, decode(opts, v, limits)) for a, v in attrs]
            if not empty:
                stack.append(name)
            pos = m.end()
            yield ("start", name, attrs, empty)
        else:
            end = text.find("<", pos)
            end = len(text) if end < 0 else end
            raw = text[pos:end]
            pos = end
            if not stack:
                if raw.strip(" \t\r\n") != "":
                    raise Fault("Malformed")
                continue
            yield ("text", decode(opts, raw, limits))
    if stack:
        raise Fault("Malformed")


def local(name):
    return name.rsplit(":", 1)[-1]


def declared_ns(name, attrs):
    wanted = "xmlns" if ":" not in name else "xmlns:" + name.split(":", 1)[0]
    return next((v for k, v in attrs if k == wanted), None)


def parse_soap(opts, vectors, soap_action, body):
    limits = vectors["limits"]
    if soap_action is None:
        raise Fault("Malformed")
    value = soap_action.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    if "#" not in value:
        raise Fault("Malformed")
    urn, header_action = value.split("#", 1)
    by_urn = {u: s for s, u in vectors["services"].items()}
    if urn not in by_urn:
        raise Fault("InvalidAction")
    service = by_urn[urn]
    if not (1 <= len(header_action) <= 64 and re.fullmatch(r"[A-Za-z0-9_]+", header_action)):
        raise Fault("Malformed")
    if not opts.size_check_after_parse and len(body) > limits["max_bytes"]:
        raise Fault("TooLarge")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise Fault("Malformed")

    events = tokens(opts, text, limits)

    def structural():
        for e in events:
            if e[0] == "text" and e[1].strip(" \t\r\n") == "":
                continue
            return e
        return None

    e = structural()
    if not e or e[0] != "start" or local(e[1]) != "Envelope" or declared_ns(e[1], e[2]) != SOAP_NS:
        raise Fault("Malformed")
    e = structural()
    if not e or e[0] != "start" or local(e[1]) != "Body" or e[3]:
        raise Fault("Malformed")
    e = structural()
    if not e or e[0] != "start":
        raise Fault("Malformed")
    action, action_empty = local(e[1]), e[3]
    if action != header_action or declared_ns(e[1], e[2]) != urn:
        raise Fault("InvalidAction")
    args = []
    if not action_empty:
        while True:
            e = structural()
            if e and e[0] == "end":
                break
            if not e or e[0] != "start":
                raise Fault("Malformed")
            if len(args) >= limits["max_args"] and not opts.unlimited_args:
                raise Fault("Malformed")
            text_parts = []
            if not e[3]:
                while True:
                    inner = next(events, None)
                    if inner and inner[0] == "text":
                        text_parts.append(inner[1])
                    elif inner and inner[0] == "end":
                        break
                    else:
                        raise Fault("Malformed")
            name = local(e[1])
            if any(k == name for k, _ in args):
                if not opts.allow_repeated_args:
                    raise Fault("InvalidArgs")
                args = [(k, v) for k, v in args if k != name]
            args.append((name, "".join(text_parts)))
    for _ in range(2):
        e = structural()
        if not e or e[0] != "end":
            raise Fault("Malformed")
    if structural() is not None:
        raise Fault("Malformed")
    if opts.size_check_after_parse and len(body) > limits["max_bytes"]:
        raise Fault("TooLarge")
    return {"service": service, "action": action, "args": [[k, v] for k, v in args]}


# ---- actions ------------------------------------------------------------------------------------


def known_actions():
    data = json.loads(USAGE.read_text(encoding="utf-8"))
    return {(a["service"], a["action"]) for a in data["actions"]}


def whole(opts, raw):
    raw = raw.strip()
    if opts.unicode_digits:
        m = re.fullmatch(r"[+-]?\d{1,10}", raw)
    else:
        m = re.fullmatch(r"[+-]?[0-9]{1,10}", raw)
    return int(raw) if m else None


def plan(opts, service, action, args):
    if service == "ContentDirectory":
        raise Fault("NotImplemented")
    if (service, action) not in known_actions():
        raise Fault("InvalidAction")
    if (service, action) not in IMPLEMENTED:
        if opts.defer_as_success:
            return {"ack": True}
        raise Fault("NotImplemented")

    required = {
        ("RenderingControl", "GetVolume"): ["InstanceID", "Channel"],
        ("RenderingControl", "GetMute"): ["InstanceID", "Channel"],
        ("RenderingControl", "SetVolume"): ["InstanceID", "Channel", "DesiredVolume"],
        ("RenderingControl", "SetMute"): ["InstanceID", "Channel", "DesiredMute"],
        ("RenderingControl", "SetRelativeVolume"): ["InstanceID", "Channel", "Adjustment"],
        ("GroupRenderingControl", "GetGroupVolume"): ["InstanceID"],
        ("GroupRenderingControl", "SnapshotGroupVolume"): ["InstanceID"],
        ("GroupRenderingControl", "SetGroupVolume"): ["InstanceID", "DesiredVolume"],
        ("GroupRenderingControl", "SetRelativeGroupVolume"): ["InstanceID", "Adjustment"],
        ("AVTransport", "GetTransportInfo"): ["InstanceID"],
        ("AVTransport", "Stop"): ["InstanceID"],
        ("ZoneGroupTopology", "GetZoneGroupState"): [],
    }[(service, action)]
    names = [k for k, _ in args]
    given = dict(args)
    if any(r not in given for r in required):
        raise Fault("InvalidArgs")
    if any(n not in required for n in names):
        raise Fault("InvalidArgs")
    if "InstanceID" in required and given["InstanceID"].strip() != "0":
        raise Fault("InvalidArgs")
    if "Channel" in required and given["Channel"].strip() != "Master":
        raise Fault("InvalidArgs")

    def volume(raw):
        n = whole(opts, raw)
        if n is None:
            raise Fault("InvalidArgs")
        if opts.clamp_volume:
            return max(0, min(100, n))
        if not 0 <= n <= 100:
            raise Fault("InvalidArgs")
        return n

    def adjustment(raw):
        n = whole(opts, raw)
        if n is None or n == 0 or not -100 <= n <= 100:
            raise Fault("InvalidArgs")
        return n

    def boolean(raw):
        v = raw.strip().lower()
        if v in ("1", "true"):
            return True
        if v in ("0", "false"):
            return False
        raise Fault("InvalidArgs")

    reads = {"GetVolume": "Volume", "GetMute": "Mute", "GetGroupVolume": "GroupVolume",
             "GetTransportInfo": "TransportInfo", "GetZoneGroupState": "ZoneGroupState"}
    if action in reads:
        return {"read": reads[action]}
    if action == "SnapshotGroupVolume":
        return {"ack": True}
    if action == "Stop":
        return {"command": "Stop"}
    if action in ("SetVolume", "SetGroupVolume"):
        return {"command": action, "value": volume(given["DesiredVolume"])}
    if action == "SetMute":
        return {"command": "SetMute", "value": boolean(given["DesiredMute"])}
    if action == "SetRelativeVolume":
        return {"command": "RelativeVolume", "value": adjustment(given["Adjustment"])}
    return {"command": "RelativeGroupVolume", "value": adjustment(given["Adjustment"])}


# ---- GENA ---------------------------------------------------------------------------------------

NS = 1_000_000_000


class Gena:
    def __init__(self, opts, config, nonce):
        self.opts, self.config, self.nonce = opts, dict(config), nonce
        self.counter = 0
        self.entries = []

    def expire(self, now):
        before = len(self.entries)
        self.entries = [e for e in self.entries if now < e["expires"]]
        return before - len(self.entries)

    def timeout(self, header):
        c = self.config
        if header is None or header.strip().lower() == "infinite":
            secs = c["default_timeout_secs"]
        else:
            m = re.fullmatch(r"Second-([0-9]+)", header.strip())
            if not m or int(m.group(1)) > U32_MAX:
                raise Fault(400)
            secs = int(m.group(1))
        if self.opts.no_clamp_timeout:
            return secs
        return max(c["min_timeout_secs"], min(c["max_timeout_secs"], secs))

    def callback(self, header, peer):
        header = header.strip()
        if len(header) > self.config["max_callback_len"]:
            raise Fault(412)
        if not (header.startswith("<") and header.endswith(">")):
            raise Fault(412)
        url = header[1:-1]
        if "<" in url or ">" in url or not url.startswith("http://"):
            raise Fault(412)
        if not all(33 <= ord(c) <= 126 for c in url):
            raise Fault(412)
        authority = url[len("http://"):].split("/", 1)[0]
        if not authority or "@" in authority:
            raise Fault(412)
        port = None
        if authority.startswith("["):
            host, _, tail = authority[1:].partition("]")
            if tail.startswith(":"):
                port = tail[1:]
            elif tail:
                raise Fault(412)
        elif ":" in authority:
            host, port = authority.rsplit(":", 1)
        else:
            host = authority
        if port is not None and not (re.fullmatch(r"[0-9]+", port) and 0 < int(port) <= 65535):
            raise Fault(412)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise Fault(412)
        if address != ipaddress.ip_address(peer) and not self.opts.callback_any_host:
            raise Fault(412)
        return url

    @staticmethod
    def full_vars(service, s):
        if service == "RenderingControl":
            v = []
            if s["volume"] is not None:
                v.append(f"Volume={s['volume']}")
            if s["mute"] is not None:
                v.append(f"Mute={int(s['mute'])}")
            return v
        if service == "GroupRenderingControl":
            return [f"GroupVolume={s['group_volume']}", f"GroupMute={int(s['group_mute'])}"]
        if service == "AVTransport":
            return [f"TransportState={s['transport']}"]
        if service == "ZoneGroupTopology":
            return [f"ZoneGroupState={s['zone_group_state']}"]
        return []

    def delta_vars(self, service, told, s):
        if self.opts.full_state_every_event:
            full = self.full_vars(service, s)
            return full if any(told[k] != s[k] for k in told) else []
        v = []
        if service == "RenderingControl":
            if told["volume"] != s["volume"] and s["volume"] is not None:
                v.append(f"Volume={s['volume']}")
            if told["mute"] != s["mute"] and s["mute"] is not None:
                v.append(f"Mute={int(s['mute'])}")
        elif service == "GroupRenderingControl":
            if told["group_volume"] != s["group_volume"]:
                v.append(f"GroupVolume={s['group_volume']}")
            if told["group_mute"] != s["group_mute"]:
                v.append(f"GroupMute={int(s['group_mute'])}")
        elif service == "AVTransport":
            if told["transport"] != s["transport"]:
                v.append(f"TransportState={s['transport']}")
        elif service == "ZoneGroupTopology":
            if told["zone_group_state"] != s["zone_group_state"]:
                v.append(f"ZoneGroupState={s['zone_group_state']}")
        return v

    @staticmethod
    def snapshot(s):
        return {k: s[k] for k in ("volume", "mute", "group_volume", "group_mute", "transport", "zone_group_state")}

    def subscribe(self, now, service, peer, callback, nt, timeout, state):
        if service == "ContentDirectory":
            raise Fault(501)
        self.expire(now)
        if nt != "upnp:event":
            raise Fault(412)
        if callback is None:
            raise Fault(412)
        url = self.callback(callback, peer)
        secs = self.timeout(timeout)
        if not self.opts.unbounded_table and len(self.entries) >= self.config["max_subscriptions"]:
            raise Fault(503)
        self.counter += 1
        sid = f"uuid:{self.nonce:08x}-0000-4000-8000-{self.counter:012x}"
        told = self.snapshot(state)
        vars_ = self.full_vars(service, state)
        if self.opts.forget_late_subscriber:
            vars_ = []
        self.entries.append({"sid": sid, "service": service, "callback": url, "expires": now + secs * NS,
                             "next_seq": 1, "told": told})
        return {"sid": sid, "timeout": secs, "initial": {"seq": 0, "vars": vars_,
                                                         "revision": state["revision"], "epoch": state["epoch"]}}

    def renew(self, now, service, sid, timeout, callback=None, nt=None):
        if (callback is not None or nt is not None) and not self.opts.renewal_takes_callback:
            raise Fault(400)
        self.expire(now)
        secs = self.timeout(timeout)
        for e in self.entries:
            if e["sid"] == sid and e["service"] == service:
                base = e["expires"] if self.opts.renew_from_old_expiry else now
                e["expires"] = base + secs * NS
                return {"sid": sid, "timeout": secs}
        raise Fault(412)

    def unsubscribe(self, now, service, sid):
        self.expire(now)
        before = len(self.entries)
        self.entries = [e for e in self.entries if not (e["sid"] == sid and e["service"] == service)]
        if len(self.entries) == before:
            raise Fault(412)
        return True

    def publish(self, now, state):
        self.expire(now)
        out = []
        now_told = self.snapshot(state)
        for e in self.entries:
            vars_ = self.delta_vars(e["service"], e["told"], state)
            if self.opts.resend_unchanged and not vars_:
                vars_ = self.full_vars(e["service"], state)
            if not vars_:
                continue
            out.append({"sid": e["sid"], "seq": e["next_seq"], "vars": vars_, "revision": state["revision"]})
            if e["next_seq"] == U32_MAX:
                e["next_seq"] = 0 if self.opts.seq_wraps_to_zero else 1
            else:
                e["next_seq"] += 1
            e["told"] = now_told
        return out

    def set_next_seq(self, seq):
        for e in self.entries:
            e["next_seq"] = seq


# ---- replay -------------------------------------------------------------------------------------


def build_body(vectors, v):
    if "wrap" in v:
        w = v["wrap"]
        body = vectors["envelope_template"].format(action=w["action"], urn=vectors["services"][w["service"]],
                                                   inner=w["inner"])
    else:
        body = v["body"]
    data = body.encode("utf-8")
    if v.get("pad_to"):
        data = data + b" " * (v["pad_to"] - len(data))
    return data


def check_escape(opts, vectors):
    failures = []
    for v in vectors["escape"]:
        got = escape(opts, v["input"], v["mode"])
        if got != v["output"]:
            failures.append((v["id"], f"escape gave {got!r}, expected {v['output']!r}"))
    return failures


def check_soap(opts, vectors):
    failures = []
    for v in vectors["soap"]:
        try:
            got = {"call": parse_soap(opts, vectors, v["soap_action"], build_body(vectors, v))}
        except Fault as f:
            got = {"fault": f.kind}
        if got != v["expect"]:
            failures.append((v["id"], f"got {got}, expected {v['expect']}"))
    return failures


def check_plan(opts, vectors):
    failures = []
    for v in vectors["plan"]:
        try:
            got = plan(opts, v["service"], v["action"], [tuple(a) for a in v["args"]])
        except Fault as f:
            got = {"fault": f.kind}
        if got != v["expect"]:
            failures.append((v["id"], f"got {got}, expected {v['expect']}"))
    return failures


def merged_state(base, overrides):
    state = dict(base)
    state.update(overrides)
    return state


def run_scenario(opts, vectors, scenario):
    g = vectors["gena"]
    config = dict(g["config"])
    config.update(scenario.get("config", {}))
    table = Gena(opts, config, g["nonce"])
    for i, step in enumerate(scenario["steps"]):
        op, want = step["op"], step.get("expect")
        at = step["at_s"] * NS if "at_s" in step else step.get("at_ns", 0)
        try:
            if op == "subscribe":
                got = {"ok": table.subscribe(at, step["service"], step["peer"], step["callback"], step["nt"],
                                             step["timeout"], merged_state(g["base_state"], step["state"]))}
            elif op == "renew":
                got = {"ok": table.renew(at, step["service"], step["sid"], step["timeout"],
                                         step.get("callback"), step.get("nt"))}
            elif op == "unsubscribe":
                got = {"ok": table.unsubscribe(at, step["service"], step["sid"])}
            elif op == "publish":
                got = {"events": table.publish(at, merged_state(g["base_state"], step["state"]))}
            elif op == "expire":
                got = {"removed": table.expire(at)}
            elif op == "len":
                got = {"len": len(table.entries)}
            elif op == "set_next_seq":
                table.set_next_seq(step["seq"])
                continue
            else:
                return (scenario["id"], f"step {i}: unknown op {op!r}")
        except Fault as f:
            got = {"err": f.kind}
        if got != want:
            return (scenario["id"], f"step {i} ({op}): got {got}, expected {want}")
    return None


def check_gena(opts, vectors):
    failures = []
    for scenario in vectors["gena"]["scenarios"]:
        failure = run_scenario(opts, vectors, scenario)
        if failure:
            failures.append(failure)
    return failures


def load():
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def check_all(opts=None, vectors=None):
    opts = opts or Options()
    vectors = vectors or load()
    return (check_escape(opts, vectors) + check_soap(opts, vectors) + check_plan(opts, vectors)
            + check_gena(opts, vectors))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="replay every vector against the model")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("nothing to do; pass --check")
    vectors = load()
    failures = check_all(Options(), vectors)
    for vector_id, detail in failures:
        print(f"FAIL {vector_id}: {detail}", file=sys.stderr)
    total = (len(vectors["escape"]) + len(vectors["soap"]) + len(vectors["plan"])
             + len(vectors["gena"]["scenarios"]))
    print(f"G03 reference model: {'FAIL' if failures else 'PASS'} ({total - len(failures)}/{total} vectors)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
