#!/usr/bin/env python3
"""Read-only observation of the owner's OWN LAN: SSDP discovery of Sonos ZonePlayers, then one
GET of each ``device_description.xml``. Humans run this, never agents (it talks to live devices).

Output is PRIVATE (serials, UDNs, room names, addresses):
  * ``<out-dir>/devices.json``  (default ``inventory/devices.json``; git-ignored)
  * ``<raw-dir>/device-N.xml``  (default ``.local-real/``; git-ignored). Raw XML used to be written
    to ``inventory/``, which is NOT git-ignored.

XML -> ``fields`` is done by exactly one rule, ``reconcile.parse_description_xml``: only the first
``<device>`` is read, and only its direct leaf children. The earlier whole-tree "last wins"
flattening stored the *nested* MediaServer/MediaRenderer ``UDN`` (the ``_MR`` suffix) as the unit's
UDN on real hardware. This file imports no XML module on purpose; do not add a second parser.

Nothing runs at import: no socket, no file, no network.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import pathlib
import signal
import socket
import sys
import tempfile
import time
import urllib.request

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_MSG = (
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n"
)
SSDP_ROUNDS = 3
SSDP_LISTEN_SECONDS = 3
GET_TIMEOUT_SECONDS = 3
METHOD = "SSDP ZonePlayer M-SEARCH, three rounds; description GET"
SHOW_KEYS = ("roomName", "modelName", "modelNumber", "hardwareVersion", "softwareVersion", "serialNum", "UDN")
DEFAULT_OUT_DIR = "inventory"
DEFAULT_RAW_DIR = ".local-real"
XML_LABEL = "device_description.xml"
EXIT_OK, EXIT_USAGE, EXIT_DISCOVERY, EXIT_OUTPUT, EXIT_INTERRUPT = 0, 2, 4, 5, 130  # 130 as in enrich.py / reconcile.py


class _OutputError(Exception):
    """A private output could not be written; fatal (never recorded as a per-device error)."""

    def __init__(self, strerror):
        super().__init__(strerror)
        self.strerror = strerror


def write_atomic(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    """Publish ``data`` at ``path`` whole or not at all.

    Staged in a temp file beside the destination, fsynced, then renamed over it. Any failure or
    interruption removes the temp file and leaves the previous file (if any) byte-identical. A hard kill
    can leave a stale ``.scan-*.tmp``; it is never read and never replaces anything. Output is private
    (serials, UDNs, room names), so the default mode is 0600.
    """
    try:
        fd, tmp = tempfile.mkstemp(prefix=".scan-", suffix=".tmp", dir=str(path.parent))
    except OSError as exc:
        raise _OutputError(exc.strerror or "cannot create a temporary file") from None
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if isinstance(exc, OSError):
            raise _OutputError(exc.strerror or "write failed") from None
        raise  # KeyboardInterrupt and friends propagate after the cleanup


def _raise_interrupt(_signum, _frame):
    raise KeyboardInterrupt


def _install_term_handler():
    """Map SIGTERM to the same cleanup path as Ctrl-C; returns the previous handler, or None if unavailable."""
    try:
        return signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError, AttributeError):  # not the main thread, or no SIGTERM on this platform
        return None


class ScanError(Exception):
    """The shared parsing rule could not be loaded; the scan must not continue without it."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _RowError(Exception):
    """A per-device problem that is recorded in the row and does not stop the scan."""


_RECONCILE = None


def _reconcile():
    """Load the sibling reconcile.py once, by path (nothing runs at import)."""
    global _RECONCILE
    if _RECONCILE is not None:
        return _RECONCILE
    path = pathlib.Path(__file__).resolve().with_name("reconcile.py")
    if not path.is_file():
        raise ScanError("shared_rule_missing")
    name = "ffw_shared_reconcile"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ScanError("shared_rule_missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise ScanError("shared_rule_unusable") from None
    _RECONCILE = module
    return module


def discover_locations(addr=SSDP_ADDR, rounds=SSDP_ROUNDS, listen_seconds=SSDP_LISTEN_SECONDS, recv_timeout=0.5) -> set:
    """SSDP M-SEARCH for ZonePlayers; returns the set of LOCATION urls that replied.

    The defaults are the real multicast search. The parameters exist so a test can aim the same code at
    an isolated 127.0.0.1 responder.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(recv_timeout)
    urls: set = set()
    try:
        for _ in range(rounds):
            sock.sendto(SSDP_MSG.encode(), addr)
            end = time.time() + listen_seconds
            while time.time() < end:
                try:
                    data, _addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                for line in data.decode(errors="replace").splitlines():
                    if line.lower().startswith("location:"):
                        value = line.split(":", 1)[1].strip()
                        if value:  # a blank header is not a device
                            urls.add(value)
    finally:
        sock.close()
    return urls


def fetch_description(url: str) -> bytes:
    """GET one description document, reading at most one byte past the shared rule's size bound."""
    limit = _reconcile().MAX_INPUT_BYTES
    with urllib.request.urlopen(url, timeout=GET_TIMEOUT_SECONDS) as response:
        return response.read(limit + 1)


def fields_from_description(raw: bytes, label: str = XML_LABEL) -> dict:
    """The one XML -> fields rule (first ``<device>``, direct leaf children). Raises the rule's InputError."""
    return _reconcile().parse_description_xml(raw, label)


def build_rows(urls, fetch, save_raw=None) -> list:
    """One row per url, sorted for stable raw-file numbering. A failure is recorded in its row only.

    ``fetch(url) -> bytes`` and ``save_raw(index, bytes)`` are injectable so this is testable offline.
    A parse failure records the rule's error code and never document content.
    """
    rc = _reconcile()  # fail fast and loudly if the shared rule is unavailable
    rows = []
    for i, url in enumerate(sorted(urls)):
        try:
            if not url.lower().startswith(("http://", "https://")):
                # urlopen would otherwise follow file:// or ftp:// from an unauthenticated SSDP reply
                raise _RowError("location_not_http")
            raw = fetch(url)
        except Exception as exc:  # network errors etc.: recorded per row, as before
            rows.append({"url": url, "error": str(exc)})
            close = getattr(exc, "close", None)  # an HTTPError holds its response open until closed
            if callable(close):
                close()
            continue
        if save_raw is not None:
            save_raw(i, raw)  # a capture that cannot be saved is fatal for the run, not a per-device error
        try:
            rows.append({"url": url, "fields": rc.parse_description_xml(raw, XML_LABEL)})
        except rc.InputError as exc:
            rows.append({"url": url, "error": exc.code})
    return rows


def document(rows: list, now: datetime.datetime | None = None) -> dict:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return {"observed_at": now.isoformat(), "method": METHOD, "devices": rows}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="scan.py", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    p.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help="directory for devices.json (private; must be git-ignored)")
    p.add_argument("--raw-dir", default=DEFAULT_RAW_DIR, help="directory for raw device-N.xml (private; default .local-real)")
    return p


def main(argv=None, discover=None, fetch=None, stdout=None, stderr=None) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    out_dir, raw_dir = pathlib.Path(args.out_dir), pathlib.Path(args.raw_dir)
    saved: list = []  # raw captures published whole so far; reported if the run is cut short

    def save_raw(index: int, raw: bytes) -> None:
        try:
            raw_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise _OutputError(exc.strerror or "cannot create the raw directory") from None
        write_atomic(raw_dir / f"device-{index}.xml", raw)
        saved.append(index)

    # Everything that can be refused is checked before the first packet is sent.
    try:
        _reconcile()
    except ScanError as exc:
        print(f"scan: error: {exc.code}: reconcile.py must sit beside scan.py", file=err)
        return EXIT_USAGE
    if not out_dir.is_dir():
        print("scan: error: out_dir_missing: --out-dir must be an existing directory", file=err)
        return EXIT_USAGE

    previous_term = _install_term_handler()
    try:
        try:
            urls = (discover or discover_locations)()
        except OSError as exc:
            print(f"scan: error: discovery_failed: {exc.strerror or type(exc).__name__}; devices.json was not touched", file=err)
            return EXIT_DISCOVERY
        rows = build_rows(urls, fetch or fetch_description, save_raw)
        if not rows:
            print("scan: no ZonePlayer answered the SSDP search; devices.json will list no devices", file=err)
        write_atomic(out_dir / "devices.json", json.dumps(document(rows), indent=2).encode("utf-8"))
    except KeyboardInterrupt:
        # A partial scan is never published as a complete devices.json; the previous one stays as it was.
        print(f"scan: error: interrupted: devices.json was not written (any previous file is untouched); {len(saved)} raw capture(s) already saved whole", file=err)
        return EXIT_INTERRUPT
    except _OutputError as exc:
        print(f"scan: error: output_write_failed: {exc.strerror}; any previous devices.json is untouched; {len(saved)} raw capture(s) saved whole", file=err)
        return EXIT_OUTPUT
    finally:
        if previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)
    for row in rows:
        if "error" in row:
            print(f"{row['url']} ERROR {row['error']}", file=err)
        else:
            print(row["url"], json.dumps({k: v for k, v in row["fields"].items() if k in SHOW_KEYS}), file=out)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
