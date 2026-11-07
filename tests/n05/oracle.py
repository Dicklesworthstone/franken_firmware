"""Independent integer schedule/PCM oracle. No Rust outputs are used as expected values."""
import hashlib
import struct

BLOCKS = 64
SEED = 0x5EED05
STRATEGIES = ("concealment", "retransmit", "raptorq", "hybrid")
SCENARIOS = ("clean", "independent", "burst", "coding_window_outage", "positive_recovery",
             "late_repair", "partial_salvage", "work_exhausted", "cancelled")
MASK = (1 << 64) - 1
GAINS = (22938, 16056, 11239, 7868, 5507, 3855, 2699, 1889)


def mix(value):
    value = (value + 0x9E3779B97F4A7C15) & MASK
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK
    return value ^ (value >> 31)


def source_time(block):
    return block * 256 * 1_000_000_000 // 48_000


def payload(block):
    return b"".join(struct.pack(">h", (block * 997 + sample * 31) % 24001 - 12000)
                    for sample in range(512))


def arrival(scenario, seed, window, slot, repair, sent):
    damaged = scenario in ("positive_recovery", "late_repair", "partial_salvage", "work_exhausted", "cancelled")
    if damaged and not repair and (window == 1 or (scenario in ("work_exhausted", "cancelled") and window == 3)) and slot < 2:
        return None
    if scenario == "coding_window_outage" and window == 1:
        return None
    if scenario == "burst" and 100_000_000 <= sent < 200_000_000:
        return None
    draw = mix(seed ^ (window * 8 + slot + (4 if repair else 0)))
    if scenario == "independent" and draw % 10000 < 100:
        return None
    jitter = (draw >> 16) % 50_000_001 if scenario in ("independent", "burst") else 0
    return sent + 2_000_000 + jitter


def source_oracle(scenario, seed):
    digest = hashlib.sha256()
    audio_digest = hashlib.sha256()
    real = []
    for block in range(BLOCKS):
        sent = source_time(block)
        now = arrival(scenario, seed, block // 4, block % 4, False, sent)
        cutoff = 500_000_000 + sent - 2_500_000
        duplicate = now + 10000 if now is not None and scenario in ("independent", "burst") and mix(seed ^ block ^ 0xDECAF) % 16 == 0 else MASK
        digest.update(struct.pack(">QQQQQ", block, sent, MASK if now is None else now, cutoff, duplicate))
        audio_digest.update(payload(block))
        real.append(now is not None and now < cutoff)
    return digest.hexdigest(), audio_digest.hexdigest(), real


def expected_plain_or_retransmit(scenario, strategy, seed):
    return expected_transport(scenario, strategy, seed)["real"]


def expected_transport(scenario, strategy, seed):
    """Independent interval-gap/channel oracle, observing only each declared collection prefix."""
    assert seed == SEED, "unqualified seed"
    _, _, real = source_oracle(scenario, seed)
    jitter = 50000000 if scenario in ("independent", "burst") else 0
    cutoff = lambda block: 500000000 + source_time(block) - 2500000
    original_barriers = [[w, max(source_time(w * 4 + 4), source_time(w * 4 + 3) + 2000000 + jitter)] for w in range(16)]
    tail = {"requested": 0, "admitted": 0, "received": 0, "admitted_to_playout": 0,
            "late": 0, "duplicate": 0, "refused_work": 0,
            "refused_deadline": 0, "refused_cancelled": 0, "feedback_messages": 0,
            "max_outstanding": 0, "air_bytes": 0, "feedback_air_bytes": 0,
            "work_charged_ns": 0, "recovered_blocks": [], "decision_barriers": []}
    out = {"real": real, "admitted": 0, "late": 0, "attempts": 0, "decode_windows": [],
           "no_information": [], "insufficient": [], "repair_air": 0, "feedback_air": 0,
           "work_charged": 0, "work_refusals": 0, "deadline_refusals": 0, "cancelled": 0,
           "tail": tail, "original_barriers": original_barriers, "fec_barriers": [], "max_repair_latency": 0}
    calendar = []

    def slot(ready, cost):
        # Sorted interval-gap scan, independent of Rust's overlapping-end iteration.
        blocked = calendar + [(cutoff(b), cutoff(b) + 2000000) for b in range(64)]
        for left, right in sorted(blocked):
            if ready + cost <= left:
                break
            if ready < right:
                ready = right
        return ready

    def refusal(start, cost, missing, used, cancelled):
        if cancelled:
            return "cancelled"
        if used + cost > 20000000:
            return "work"
        if not any(start + cost < cutoff(block) for block in missing):
            return "deadline"
        return None

    def offer(block, at):
        out["max_repair_latency"] = max(out["max_repair_latency"], at - source_time(block))
        out["attempts"] += 1
        if at < cutoff(block):
            real[block] = True
            out["admitted"] += 1
        else:
            out["late"] += 1

    if strategy == "concealment":
        return out
    for window in range(16):
        first = window * 4
        originals = [(at, i) for i in range(4)
                     if (at := arrival(scenario, seed, window, i, False, source_time(first + i))) is not None]
        original_end = original_barriers[window][1]
        seen = [i for at, i in originals if at <= original_end]
        missing = [first + i for i in range(4) if i not in seen]
        used = 0
        cancelled = window == 1 and scenario == "cancelled"
        planted = window == 1 and scenario == "work_exhausted"
        floor = cutoff(first + (1 if scenario == "late_repair" else 0)) + 1 if window == 1 and scenario in ("late_repair", "partial_salvage") else 0
        if strategy == "retransmit":
            accepted = 0
            free = original_end
            for offset, block in enumerate(missing):
                cost = 600000000 if planted else 50000
                start = slot(free, cost)
                rejected = refusal(start, cost, [block], used, cancelled)
                sent = max(original_end + 20000000 + offset * 100000, start + cost)
                if rejected is None and max(sent + 2000000 + jitter, floor) >= cutoff(block):
                    rejected = "deadline"
                if rejected:
                    out[{"work": "work_refusals", "deadline": "deadline_refusals", "cancelled": "cancelled"}[rejected]] += 1
                    if rejected == "cancelled":
                        break
                    continue
                used += cost
                free = start + cost
                calendar.append((start, free))
                accepted += 1
                out["repair_air"] += 1104
                at = arrival(scenario, seed, window, offset, True, sent)
                if at is not None:
                    offer(block, max(at, floor))
            if accepted:
                out["feedback_air"] += 32
            out["work_charged"] += used
            continue
        ready = original_end
        remaining = missing[:]
        encode_start = slot(source_time(first + 4), 1000000)
        rejected = refusal(encode_start, 1000000, list(range(first, first + 4)), used, cancelled)
        if rejected:
            out[{"work": "work_refusals", "deadline": "deadline_refusals", "cancelled": "cancelled"}[rejected]] += 1
        else:
            encoded = encode_start + 1000000
            used += 1000000
            calendar.append((encode_start, encoded))
            ready = encoded + 300000 + 2000000 + jitter
            if window == 1 and scenario in ("late_repair", "partial_salvage"):
                ready = max(ready, cutoff(first + (1 if scenario == "late_repair" else 0)) + 1 - 1000000)
            out["fec_barriers"].append([window, ready])
            out["repair_air"] += 4 * 1108
            seen = [i for at, i in originals if at <= ready]
            missing = [first + i for i in range(4) if i not in seen]
            remaining = missing[:]
            mask = sum(1 << i for i in seen)
            for offset in range(4):
                at = arrival(scenario, seed, window, offset, True, encoded + offset * 100000)
                if at is not None:
                    if window == 1 and scenario in ("late_repair", "partial_salvage"):
                        at = cutoff(first + (1 if scenario == "late_repair" else 0)) + 1 - 1000000
                    if at <= ready:
                        mask |= 1 << (4 + offset)
            if missing:
                if mask == 0:
                    out["no_information"].append(window)
                elif mask.bit_count() < 4:
                    out["insufficient"].append(window)
                else:
                    cost = 600000000 if planted else 1000000
                    decode_start = slot(max(ready, encoded), cost)
                    rejected = refusal(decode_start, cost, missing, used, cancelled)
                    if rejected:
                        out[{"work": "work_refusals", "deadline": "deadline_refusals"}[rejected]] += 1
                    else:
                        assert mask in (252, 253), f"unqualified frozen FEC information set: {mask}"
                        ready = decode_start + cost
                        calendar.append((decode_start, ready))
                        used += cost
                        out["decode_windows"].append(window)
                        for block in missing:
                            offer(block, ready)
                            if ready < cutoff(block):
                                remaining.remove(block)
        if strategy == "hybrid" and remaining:
            tail["decision_barriers"].append([window, ready])
            admitted = 0
            free = ready
            for offset, block in enumerate(remaining):
                tail["requested"] += 1
                cost = 600000000 if planted else 50000
                start = slot(free, cost)
                rejected = refusal(start, cost, [block], used, cancelled)
                sent = max(ready + 20000000 + offset * 100000, start + cost)
                if rejected is None and max(sent + 2000000 + jitter, floor) >= cutoff(block):
                    rejected = "deadline"
                if rejected:
                    tail["refused_" + rejected] += 1
                    continue
                used += cost
                tail["work_charged_ns"] += cost
                free = start + cost
                calendar.append((start, free))
                admitted += 1
                tail["admitted"] += 1
                tail["air_bytes"] += 1104
                at = arrival(scenario, seed, window, offset, True, sent)
                if at is not None:
                    at = max(at, floor)
                    tail["received"] += 1
                    offer(block, at)
                    if at < cutoff(block):
                        tail["admitted_to_playout"] += 1
                        tail["recovered_blocks"].append(block)
                    else:
                        tail["late"] += 1
            if admitted:
                tail["feedback_messages"] += 1
                tail["feedback_air_bytes"] += 32
            tail["max_outstanding"] = max(tail["max_outstanding"], admitted)
        out["work_charged"] += used
    out["repair_air"] += tail["air_bytes"]
    out["feedback_air"] += tail["feedback_air_bytes"]
    tail["recovered_blocks"].sort()
    return out

def check_result(result):
    assert result["schema"] == "n05.study.v4", "wrong schema"
    assert result["profile"] == "n05.rfc6330.k4-r4.v4", "profile drift"
    assert result["build_profile"] == {"recipe": "n05.host-test-o3-d0.v1", "opt_level": "3", "debug": "false", "cargo_profile": "debug"}, "unregistered native build recipe"
    assert result["library"] == "asupersync@14032b8f2c832ee7ef1946404f5efb18162af045", "library source drift"
    assert result["evidence_class"] == "offline-host-synthetic"
    scenario, strategy, seed = (result["input"][key] for key in ("scenario", "strategy", "seed"))
    assert scenario in SCENARIOS and strategy in STRATEGIES
    assert result["blocks"] == BLOCKS and result["frames_per_packet"] == 256
    assert result["source_symbols"] == 4 and result["repair_symbols"] == 4
    trace, audio, source_real = source_oracle(scenario, seed)
    assert result["source_trace_sha256"] == trace, "first causal divergence: source trace"
    assert result["payload_sha256"] == audio, "first causal divergence: source payload"
    assert len(result["output"]) == BLOCKS, "missing output block"
    transport = expected_transport(scenario, strategy, seed)
    expected_real = transport["real"]
    last = None
    run = 0
    longest = concealed = muted = actual_real = 0
    for block, out in enumerate(result["output"]):
        assert out["block"] == block, f"cursor divergence block={block}"
        presentation = 500_000_000 + source_time(block)
        assert out["presentation_ns"] == presentation
        assert out["consume_by_ns"] == presentation - 2_500_000
        assert out["late_by_ns"] == 0, f"starved block={block}"
        assert out["render_reserved_end_ns"] == presentation - 500000
        assert out["render_served_end_ns"] == out["render_reserved_end_ns"]
        assert out["render_late_by_ns"] == 0, f"repair overlapped render work block={block}"
        is_real = out["outcome"] == "real"
        assert is_real == expected_real[block], f"first causal divergence: recovery block={block}"
        if is_real:
            expected_bytes = payload(block)
            last = expected_bytes
            run = 0
            actual_real += 1
        else:
            run += 1
            longest = max(longest, run)
            if last is None:
                assert out["outcome"] == "muted_nohistory"
                expected_bytes = b""
                muted += 1
            elif run <= 8:
                assert out["outcome"] == "concealed"
                expected_bytes = b"".join(struct.pack(">h", (sample[0] * GAINS[run - 1] + 16384) >> 15)
                                           for sample in struct.iter_unpack(">h", last))
                concealed += 1
            else:
                assert out["outcome"] == "muted_gap"
                expected_bytes = b""
                muted += 1
        assert out["payload_sha256"] == hashlib.sha256(expected_bytes).hexdigest(), f"first causal divergence: audio block={block}"
    resources, repair = result["resources"], result["repair"]
    assert resources["source_payload_bytes"] == 64 * 1024
    assert resources["source_air_bytes"] == 64 * 1104
    assert resources["work_allowance_per_window_ns"] == 20_000_000
    assert resources["real_output_payload_bytes"] == actual_real * 1024
    assert resources["concealed_blocks"] == concealed and resources["muted_blocks"] == muted
    assert resources["longest_nonreal_run_blocks"] == longest
    assert repair["attempts"] == repair["admitted"] + repair["late"] + repair["duplicate"]
    air_bytes = resources["source_air_bytes"] + resources["repair_air_bytes"] + resources["feedback_air_bytes"]
    assert resources["encoded_airtime_at_6mbps_ns"] == air_bytes * 8 * 1_000_000_000 // 6_000_000
    assert result["unrecovered_blocks"] == [i for i, real in enumerate(expected_real) if not real]
    assert resources["max_decision_late_by_ns"] == 0
    assert resources["max_render_late_by_ns"] == 0
    assert resources["max_repair_latency_ns"] == transport["max_repair_latency"]
    assert resources["original_collection_barriers"] == transport["original_barriers"]
    assert resources["fec_collection_barriers"] == transport["fec_barriers"]
    assert result["tail"] == transport["tail"], "hybrid tail accounting differs"
    tail = result["tail"]
    assert tail["requested"] == tail["admitted"] + tail["refused_work"] + tail["refused_deadline"] + tail["refused_cancelled"]
    assert tail["received"] == tail["admitted_to_playout"] + tail["late"] + tail["duplicate"]
    assert tail["admitted_to_playout"] == len(tail["recovered_blocks"])
    assert tail["max_outstanding"] <= 4 and tail["feedback_messages"] <= 16
    assert tail["feedback_air_bytes"] == tail["feedback_messages"] * 32
    assert resources["source_duplicates_seen"] == resources["source_duplicates_admitted_as_duplicate"] == (3 if scenario in ("independent", "burst") else 0)
    assert resources["repair_air_bytes"] == transport["repair_air"]
    assert resources["feedback_air_bytes"] == transport["feedback_air"]
    assert resources["work_charged_ns"] == transport["work_charged"]
    assert resources["max_window_work_ns"] <= 20000000
    assert resources["library_attempts"] == len(transport["decode_windows"])
    for field in ("admitted", "late", "attempts", "work_refusals", "deadline_refusals"):
        assert repair[field] == transport[field], f"repair accounting {field}"
    assert repair["cancelled_windows"] == transport["cancelled"]
    assert repair["decode_window_ids"] == transport["decode_windows"]
    assert repair["no_information_window_ids"] == transport["no_information"]
    assert repair["insufficient_window_ids"] == transport["insufficient"]
    assert repair["decode_failures"] == 0, "unexpected actual decoder failure; exhaustive subset test separately covers genuine rank deficits"
    assert resources["playout_resident_bytes"] >= 94 * 1028
    assert result["diagnostics_dropped"] == 0
    assert result["promotion"].startswith("none:")
    if strategy == "concealment":
        assert resources["repair_air_bytes"] == resources["feedback_air_bytes"] == resources["library_attempts"] == 0
    if scenario == "clean" and strategy == "raptorq":
        assert resources["repair_air_bytes"] == 16 * 4 * 1108
        assert resources["library_attempts"] == 0
        assert resources["sender_encode_host_elapsed_ns"] > 0
    if scenario == "positive_recovery" and strategy == "raptorq":
        assert repair["admitted"] == 2 and resources["library_attempts"] == 1
        assert resources["receiver_decode_host_elapsed_ns"] > 0
        assert resources["retained_symbol_payload_peak_bytes"] >= 4096
    if scenario == "coding_window_outage" and strategy == "raptorq":
        assert repair["no_information_windows"] == 1
    if scenario == "late_repair" and strategy == "raptorq":
        assert repair["deadline_refusals"] == 1
    if scenario == "late_repair" and strategy == "retransmit":
        assert repair["late"] == 0 and repair["deadline_refusals"] == 2
        assert resources["repair_air_bytes"] == resources["feedback_air_bytes"] == resources["work_charged_ns"] == 0
    if scenario == "work_exhausted" and strategy != "concealment":
        assert repair["work_refusals"] > 0
    if scenario == "cancelled" and strategy != "concealment":
        assert repair["cancelled_windows"] == 1
    if scenario in ("cancelled", "work_exhausted") and strategy != "concealment":
        assert repair["admitted"] == 2 and result["output"][12]["outcome"] == result["output"][13]["outcome"] == "real"
    if resources["library_attempts"]:
        assert resources["decode_work"]["peeled"] + resources["decode_work"]["gauss_ops"] > 0
    # A host reserve violation FAILS interpretation, without altering any virtual fault timing.
    assert resources["work_overruns"] == 0, "host coding-time reserve violation"
