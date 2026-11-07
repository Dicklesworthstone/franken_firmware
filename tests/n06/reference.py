"""Independent exact-integer PCM/trace oracle for actual N06 native observations."""
import hashlib
import struct

PROFILE = "n06.host-hybrid.k4-r4.v1"
SEED = 0x60601


def pcm(block):
    window, slot = divmod(block, 4)
    return bytes((SEED + window * 29 + slot * 37 + byte * 11) % 251 for byte in range(1024))


def trace_digest():
    digest = hashlib.sha256()
    for window in range(8):
        for esi in range(8):
            sent = ((window * 4 + esi) * 256 * 10**9 // 48000 if esi < 4 else
                    (window + 1) * 1024 * 10**9 // 48000 + 1000000 + (esi - 4) * 100000)
            missing = window in (1, 3) and esi < 2
            digest.update(struct.pack(">QQQB", window, esi, sent, missing))
    return digest.hexdigest()


def expected(mode):
    losses = {"baseline": {4, 5, 12, 13}, "hybrid": set(), "overload": {4, 5}}[mode]
    last = None
    run = 0
    rows = []
    for block in range(32):
        if block not in losses:
            data, outcome, run = pcm(block), "real", 0
            last = data
        else:
            run += 1
            data = attenuate(last, run)
            outcome = "concealed"
        rows.append({"block": block, "outcome": outcome, "pcm_sha256": hashlib.sha256(data).hexdigest(), "cursor": block + 1})
    return rows


def attenuate(last, run):
    gain = (22938, 16056)[run - 1]
    return b"".join(struct.pack(">h", (int.from_bytes(last[i:i+2], "big", signed=True) * gain + 16384) >> 15)
                    for i in range(0, 1024, 2))


def check_fleet(row):
    assert row["schema"] == "n06.fleet.v1" and row["profile"] == PROFILE
    assert row["group_members"] == row["checks"] == 6 and row["fleet_cap"] == 21 and row["check_limit"] == 7
    assert row["request_masks"] == [1, 1, 1, 1, 8, 8] and row["reply_esis"] == [0, 3]
    assert row["charged_work"] == 6 * 8192 + 2 * (8192 + 1024 + 1000)
    expected_rows = [{"member": member, "block": block, "outcome": "real", "pcm_sha256": hashlib.sha256(pcm(block)).hexdigest()}
                     for member in range(6) for block in range(4)]
    assert row["output"] == expected_rows, "fleet output PCM or member coverage diverged"


def check_relock(row):
    assert row["schema"] == "n06.relock.v1" and row["profile"] == PROFILE and row["epoch"] == 1
    assert row["origin_before"] == row["origin_after"] == row["healthy_origin"] and row["origin_before"] > 500_000_000
    assert row["window"] == 32 and row["anchor_frame"] == 32 * 1024
    assert row["joined_cursor"] == row["healthy_cursor"] == 130
    expected_rows = []
    for slot in range(2):
        probe = hashlib.sha256(b"FFWR-N06-v1-source" + bytes(64) + bytes([91 + slot]) * 4096).hexdigest()
        for member in ("healthy", "relocked"):
            expected_rows.append({"member": member, "block": 128 + slot, "outcome": "real", "pcm_probe_sha256": probe})
    assert row["output"] == expected_rows, "relock PCM or absolute-window coverage diverged"


def check_replays(records):
    assert len(records) == 3 and {row["mode"] for row in records} == {"baseline", "hybrid", "overload"}
    for row in records:
        assert row["schema"] == "n06.replay.v1" and row["profile"] == PROFILE
        assert row["source_epoch"] == 1 and row["seed"] == SEED and row["frames"] == 256 and row["blocks"] == 32
        assert row["evidence_class"] == "offline-host-synthetic" and row["production_fec_profile_admitted"] is False
        assert row["channel_trace_sha256"] == trace_digest()
        want = expected(row["mode"])
        assert len(row["output"]) == 32
        for actual, expected_row in zip(row["output"], want):
            assert actual == expected_row, f"first PCM divergence mode={row['mode']} block={expected_row['block']}"
        status = row["status"]
        assert status["production_fec_profile_admitted"] is False and status["chosen_strategy"] == "hybrid"
        assert status["retained_windows"] <= 8 and status["authenticated_symbols"] <= 64
        assert status["counters"]["diagnostics_dropped"] == 0
        if row["mode"] == "overload":
            assert row["injected_other_work_units"] > 0 and row["lost_feedback"] == 1
            assert status["counters"]["work_refused"] > 0 and status["counters"]["recovered"] == 2
        elif row["mode"] == "hybrid":
            assert row["injected_other_work_units"] == row["lost_feedback"] == 0
            assert status["counters"]["recovered"] == 4
        else:
            assert status["counters"]["decode_attempts"] == status["counters"]["decode_work"] == 0
