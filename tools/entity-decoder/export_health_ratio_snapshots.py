"""Export native-ratio research from saved, owned pool acquisitions only.

The health layout supplies every application offset. A separate ratio layout
pins that layout, the build and a local native-review artifact, and supplies the
denominator offset. Its algorithm is ``occupied_pool_ratio_f32``: two sequential
binary32 sums over occupied slots, then numerator / positive denominator clamped
to [0, 1], or zero for a zero denominator. An occupied first slot initializes
each sum directly; later slots add. This is a specific reviewed native property,
not a discovery of maximum health or a universal HUD ratio.

Only complete acquisition extents are used. Their own read intervals accompany
every result; no value is carried into a later stream. No process, network, game,
or desktop access occurs. Native-review hashes identify the supplied research;
they do not convert static interpretation into runtime semantic validation.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import struct
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_health_contracts as health


def _f32(value):
    try:
        return struct.unpack("<f", struct.pack("<f", value))[0]
    except OverflowError:
        return math.copysign(math.inf, value)


def _sum(slots, key):
    total = 0.0
    for slot in slots:
        value = slot[key]
        health._need(math.isfinite(value) and value >= 0, "unsupported_pool_operand")
        total = value if slot["pool_index"] == 0 else _f32(total + value)
        health._need(math.isfinite(total), "unsupported_nonfinite_pool_sum")
    return total


def export_snapshots(acquisition_directory, health_layout_bytes, ratio_layout_bytes,
                     *, native_review_path, recipe_path=None):
    """Return acquisition-time candidates; reject missing or ambiguous bytes.

    Positive finite operands are supported, along with signed zero. Nonfinite
    operands, negative operands or overflowing sums fail rather than acquiring
    an invented health meaning. Division overflow follows the native clamp.
    Forward-owner promotion and later stream samples are deliberately outside
    this snapshot exporter. Actor prefixes identify the supplied acquisition
    route; they are not persistent participant identities.
    """
    layout, membership_offsets, scalar_offsets = health._layout(health_layout_bytes)
    health._need(isinstance(ratio_layout_bytes, bytes) and 0 < len(ratio_layout_bytes) <= 65536,
                 "ratio_layout_size_bound")
    ratio = health._object(ratio_layout_bytes, unique_keys=True)
    health._need(ratio.get("schema") == "overwatch-decoder.private.health-ratio-layout/1"
                 and ratio.get("algorithm") == "occupied_pool_ratio_f32", "unsupported_ratio_layout")
    health._need(ratio.get("health_layout_sha256") == health._sha(health_layout_bytes)
                 and ratio.get("build_sha256") == layout["executable_sha256"], "ratio_layout_pin_mismatch")
    review_raw = health._read(native_review_path, 8 * 1024 * 1024)
    health._need(health._digest(ratio.get("native_review_sha256"))
                 and health._sha(review_raw) == ratio["native_review_sha256"], "native_review_pin_mismatch")
    offset = ratio.get("denominator_offset")
    health._need(health._integer(offset) and offset >= 0, "invalid_denominator_offset")
    denominator_offsets = [offset + i * layout["slot_stride"] for i in range(layout["slot_count"])]
    health._need(all(at + 4 <= layout["extent_size"] for at in denominator_offsets),
                 "denominator_outside_extent")
    health._need(not any(a < b + 4 and b < a + 4 for a in denominator_offsets
                         for b in membership_offsets + scalar_offsets), "denominator_operand_overlap")
    bundle = health.build_contracts(acquisition_directory, health_layout_bytes, recipe_path=recipe_path)
    directory = Path(acquisition_directory)
    evidence_raw = health._read(directory / "evidence.jsonl", health.MAX_EVIDENCE_BYTES)
    profile_raw = health._read(directory / "profile.json", health.MAX_PROFILE_BYTES)
    health._need(health._sha(evidence_raw) == bundle["acquisition_evidence_sha256"]
                 and health._sha(profile_raw) == bundle["profile_sha256"], "source_changed_during_export")
    target = health._object(profile_raw)["target"]
    events = [health._object(line) for line in evidence_raw.splitlines()]
    headers = [event for event in events if event.get("kind") == "start"]
    clock = None
    if headers:
        health._need(len(headers) == 1, "ambiguous_acquisition_clock")
        header = headers[0]
        health._need(header.get("schema") == "overwatch-decoder.acquisition-evidence/1"
                     and header.get("target") == target
                     and header.get("recipe_sha256") == bundle["recipe_sha256"], "clock_source_mismatch")
        frequency, origin = header.get("monotonic_frequency"), header.get("monotonic_origin_ticks")
        health._need(health._integer(frequency) and frequency > 0
                     and health._integer(origin) and origin >= 0
                     and isinstance(header.get("utc_origin"), str) and 0 < len(header["utc_origin"]) <= 128,
                     "invalid_acquisition_clock")
        clock = dict(monotonic_frequency=frequency, monotonic_origin_ticks=origin,
                     utc_origin=header["utc_origin"])
    observations = []
    for contract in bundle["contracts"]:
        prefix, slots = contract["actor_prefix"], contract["slots"]
        base = slots[0]["membership_address"] - layout["membership_offset"]
        stage = layout.get("actor_read_stages", {}).get(prefix, layout["read_stage"])
        reads = [event for event in events if event.get("kind") == "read"
                 and event.get("purpose") == "recipe" and event.get("stage") == stage
                 and event.get("address") == base and event.get("requested_bytes") == layout["extent_size"]]
        health._need(bool(reads), "missing_ratio_extent")
        # build_contracts already checked complete, identical extents and their
        # membership/field/guard binding. Keep repeated observations separate.
        for event in reads:
            health._need(clock is None or event["read_start_ticks"] >= clock["monotonic_origin_ticks"],
                         "read_precedes_clock_origin")
            data = bytes.fromhex(event["bytes_hex"])
            operands = []
            for slot in slots:
                i = slot["index"]
                if slot["membership_u32"]:
                    operands.append(dict(pool_index=i,
                        numerator=struct.unpack_from("<f", data, scalar_offsets[i])[0],
                        denominator=struct.unpack_from("<f", data, denominator_offsets[i])[0]))
            numerator = _sum(operands, "numerator")
            denominator = _sum(operands, "denominator")
            value = max(0.0, min(1.0, _f32(numerator / denominator))) if denominator > 0 else 0.0
            observations.append(dict(actor_prefix=prefix,
                source="process_memory", status="candidate",
                validation_status="static_derived_not_runtime_validated",
                observation_scope="acquisition_extent_only",
                read_id=event.get("id") if health._integer(event.get("id")) else None,
                read_stage=stage, read_start_ticks=event["read_start_ticks"],
                read_end_ticks=event["read_end_ticks"], extent_sha256=health._sha(data),
                numerator_sum=numerator, native_denominator_sum=denominator,
                native_ratio_candidate=value, operands=operands,
                occupied_pool_count=len(operands), supplied_layout_slots=len(slots),
                maximum_health=None, pool_roles=None, hud_ratio=None,
                atomic=False, continuity_across_gaps=False, public_state_eligible=False,
                visibility="unknown"))
    return dict(schema="overwatch-decoder.private.health-ratio-snapshots/1", target=target, clock=clock,
                build_sha256=target["executable_sha256"],
                profile_sha256=bundle["profile_sha256"], recipe_sha256=bundle["recipe_sha256"],
                acquisition_manifest_sha256=bundle["acquisition_manifest_sha256"],
                acquisition_evidence_sha256=bundle["acquisition_evidence_sha256"],
                health_layout_sha256=bundle["layout_sha256"],
                ratio_layout_sha256=health._sha(ratio_layout_bytes),
                native_review_sha256=ratio["native_review_sha256"],
                algorithm=ratio["algorithm"], observation_scope="acquisition_extent_only",
                arithmetic_assumption="binary32_round_to_nearest_even",
                native_float_control_state_observed=False,
                interpretation="native_property_reconstruction_not_maximum_or_hud_health",
                observations=observations, public_state_eligible=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquisition", type=Path, required=True)
    parser.add_argument("--health-layout", type=Path, required=True)
    parser.add_argument("--ratio-layout", type=Path, required=True)
    parser.add_argument("--native-review", type=Path, required=True)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = export_snapshots(args.acquisition, health._read(args.health_layout, 65536),
            health._read(args.ratio_layout, 65536), native_review_path=args.native_review, recipe_path=args.recipe)
        with args.out.open("xb") as output:
            output.write((json.dumps(result, indent=2, allow_nan=False) + "\n").encode())
    except (health.InvalidHealthAcquisition, OSError) as error:
        parser.exit(1, f"health ratio snapshot export failed: {error}\n")
    print(json.dumps(dict(observations=len(result["observations"]),
                         profile_sha256=result["profile_sha256"],
                         observation_scope=result["observation_scope"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
