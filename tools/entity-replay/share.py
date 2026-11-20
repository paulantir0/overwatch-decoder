"""Export a bounded, allowlisted shared excerpt from a pinned replay and video."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from chunks import MAX_CHUNK, checked_index


MAX_INPUT_BYTES = 256 * 1024**2
MAX_OUTPUT_BYTES = 128 * 1024**2
MAX_FRAMES = 100_000
MAX_OBJECTS = 4096
HOLD_SECONDS = 0.05

# Exact reviewed labels in the selected capture. Unknown and unsupported labels
# have no display value. This set never admits account names from a source row.
HERO_LABELS = frozenset({
    "Genji", "Junker Queen", "Kiriko", "Lúcio", "Mei", "Ramattra", "Roadhog",
    "Sigma", "Torbjörn", "Tracer", "Zenyatta",
})
FIELD_RULES = {
    "hero": ("typed_asset_resource_match", "process_memory"),
    "health": ("current_build_native_current_health_pool_sum", "calculated_process_memory"),
    "relation": ("current_build_native_ordinary_comparison", "process_memory"),
    "position": ("current_build_native_controller_body_ownership", "process_memory"),
    "raw_quaternion_candidate": ("raw_orientation_candidate", "process_memory"),
}
RAW_ORIENTATION = "raw_owned_component_four_float_candidate"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def integer(value, low=0, high=2**53 - 1):
    return type(value) is int and low <= value <= high


def hash_value(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def tick(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value), "invalid source timestamp")
    return int(value)


def strict_json(raw):
    def unique(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs), "duplicate JSON property")
        return value

    def reject(_):
        raise ValueError("nonfinite JSON number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject)


def bounded_bytes(path, limit):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "input byte bound")
    return raw


def digest_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_identity(value, kind):
    # Use source IDs only as dictionary keys. None of their bytes are emitted.
    if isinstance(value, str) and re.fullmatch(kind + r":[0-9a-f]{64}", value):
        return value
    return None


def known_value(field, value):
    if field == "hero":
        return isinstance(value, str) and value in HERO_LABELS
    if field == "health":
        return finite(value) and 0 <= value <= 1_000_000
    if field == "relation":
        return isinstance(value, str) and value in ("self", "ally", "enemy")
    return (isinstance(value, list) and len(value) == 4 and
            all(finite(x) and abs(x) <= 1.01 for x in value) and
            0.99 <= sum(x*x for x in value) <= 1.01)


def evidence(row, field, build):
    item = row.get("field_evidence", {}).get(field)
    status, source = FIELD_RULES[field]
    if (isinstance(item, dict) and item.get("source") == source and
            item.get("validation_status") == status and item.get("observed_build_sha256") == build):
        if field != "raw_quaternion_candidate" or item.get("semantics") == RAW_ORIENTATION:
            return dict(source=source, validation_status=status, observed_build_sha256=build)
    return None


class Window:
    def __init__(self, number, count, offset):
        require(integer(number, 1, 240) and integer(count, 0, MAX_OBJECTS), "invalid window object bound")
        self.prefix = f"window-{number:04d}"
        self.offset = offset
        self.count = count
        self.identities = {"controller": {}, "body": {}}
        self.epochs = {}

    def object_index(self, value):
        require(integer(value, 0, self.count - 1), "object index outside source window")
        return self.offset + value

    def identity(self, value, kind):
        source = source_identity(value, kind)
        if source is None:
            return None
        seen = self.identities[kind]
        if source not in seen:
            require(len(seen) < MAX_OBJECTS, "identity bound")
            seen[source] = f"{self.prefix}-{kind}-{len(seen) + 1:04d}"
        return seen[source]

    def epoch(self, source):
        if source not in self.epochs:
            require(len(self.epochs) < MAX_OBJECTS, "epoch bound")
            self.epochs[source] = f"{self.prefix}-epoch-{len(self.epochs) + 1:04d}"
        return self.epochs[source]


def field_sample(row, window, frequency, frame_end):
    require(isinstance(row, dict), "invalid field sample")
    source_clock = row.get("source_timestamp", {})
    require(isinstance(source_clock, dict), "invalid field source clock")
    start, end = tick(source_clock.get("start_ticks")), tick(source_clock.get("end_ticks"))
    require(source_clock.get("clock") == "windows_qpc" and source_clock.get("frequency") == frequency and
            start <= end <= frame_end, "field source clock does not fit frame")
    build = row.get("observed_build_sha256")
    require(hash_value(build), "invalid observed build hash")
    require(isinstance(row.get("field_evidence", {}), dict), "invalid field evidence")
    field = dict(
        object=window.object_index(row.get("object")),
        controller_id=window.identity(row.get("controller_id"), "controller"),
        entity_id=window.identity(row.get("entity_id"), "body"),
        observed_build_sha256=build,
        visibility="unknown",
        source_timestamp=dict(start_ticks=str(start), end_ticks=str(end), frequency=frequency, clock="windows_qpc"),
        field_evidence={},
    )
    for name in ("hero", "health", "relation", "raw_quaternion_candidate"):
        value = row.get(name)
        proof = evidence(row, name, build)
        if (proof is not None and isinstance(value, dict) and
                value.get("validation_status") == proof["validation_status"] and
                known_value(name, value.get("value"))):
            field[name] = dict(value=value["value"], validation_status=proof["validation_status"], reason=None)
            field["field_evidence"][name] = proof
        else:
            field[name] = dict(value=None, validation_status="unknown", reason=None)
    position = evidence(row, "position", build)
    if position is not None:
        field["field_evidence"]["position"] = position
    for name in ("team", "username"):
        field[name] = dict(value=None, validation_status="unknown", reason=None)
    return field


def frame_sample(frame, source_fields, window, frequency, origin):
    require(isinstance(frame, dict) and isinstance(frame.get("objects"), list), "invalid source frame")
    start, end = tick(frame.get("start_ticks")), tick(frame.get("end_ticks"))
    source_t, source_end = frame.get("t"), frame.get("end")
    require(origin <= start <= end and finite(source_t) and finite(source_end) and
            abs(source_t - (start-origin)/frequency) <= 1/frequency and
            abs(source_end - (end-origin)/frequency) <= 1/frequency, "frame source clock mismatch")
    require(integer(frame.get("sequence")) and integer(frame.get("skipped")) and
            integer(frame.get("unknown_count")) and type(frame.get("continuity_valid")) is bool,
            "invalid frame counts")
    require(len(frame["objects"]) <= window.count, "frame object bound")
    refs = frame.get("field_refs")
    require(isinstance(refs, list) and len(refs) <= window.count and
            all(integer(ref, 0, len(source_fields)-1) for ref in refs), "invalid field references")
    fields = [field_sample(source_fields[ref], window, frequency, end) for ref in refs]
    by_object = {row["object"]: row for row in fields}
    require(len(fields) == len(by_object), "duplicate frame field object")
    points = {}
    for point in frame["objects"]:
        require(isinstance(point, list) and len(point) == 5 and all(finite(v) for v in point[1:4]) and
                (point[4] is None or type(point[4]) is bool), "invalid frame position")
        index = window.object_index(point[0])
        require(index not in points and index in by_object and
                "position" in by_object[index]["field_evidence"], "position lacks verified current source")
        points[index] = [index, *point[1:]]
    require(sum(point[4] is True for point in points.values()) <= 1, "multiple self positions")
    rotations, seen_rotations = {}, set()
    source_rotations = frame.get("rotations", [])
    require(isinstance(source_rotations, list) and len(source_rotations) <= len(points), "invalid frame orientations")
    for q in source_rotations:
        require(isinstance(q, list) and len(q) == 5, "invalid orientation row")
        index = window.object_index(q[0])
        require(index in points and index not in seen_rotations, "orientation without a unique current position")
        seen_rotations.add(index)
        candidate = by_object[index]["raw_quaternion_candidate"]["value"]
        if candidate is not None:
            require(candidate == q[1:], "orientation row differs from verified field")
            rotations[index] = [index, *candidate]
    # Only publish a candidate used by this frame. A missing point or rotation
    # stays unknown, even when a source row still carries an orientation value.
    for index, field in by_object.items():
        if index not in rotations:
            field["raw_quaternion_candidate"] = dict(value=None, validation_status="unknown", reason=None)
            field["field_evidence"].pop("raw_quaternion_candidate", None)
    return dict(
        t=(start-origin)/frequency, end=(end-origin)/frequency, epoch=window.epoch(frame["epoch"]),
        start_ticks=str(start), end_ticks=str(end), sequence=frame["sequence"], skipped=frame["skipped"],
        unknown_count=frame["unknown_count"], continuity_valid=frame["continuity_valid"],
        objects=list(points.values()), rotations=list(rotations.values()), fields=fields,
    )


def export_shared(index_path, calibration_path, video_path):
    """Return the sanitized replay and its private, source-bound trim plan."""
    index_path, calibration_path, video_path = map(Path, (index_path, calibration_path, video_path))
    require(0 < video_path.stat().st_size <= 8 * 1024**3, "video byte bound")
    raw_index = bounded_bytes(index_path, 1024**2)
    index_hash = hashlib.sha256(raw_index).hexdigest()
    index = strict_json(raw_index)
    calibration = strict_json(bounded_bytes(calibration_path, 1024**2))
    require(isinstance(index, dict) and isinstance(calibration, dict) and
            calibration.get("schema") == "overwatch-decoder.replay-alignment/1" and
            hash_value(index.get("source_sha256")) and calibration.get("source_sha256") == index["source_sha256"] and
            calibration.get("replay_index_sha256") == index_hash and
            hash_value(calibration.get("video_sha256")) and
            calibration["video_sha256"] == digest_file(video_path), "calibration does not match replay index and video")
    offset, uncertainty = calibration.get("offset_seconds"), calibration.get("uncertainty_seconds")
    require(finite(offset) and abs(offset) <= 86400 and finite(uncertainty) and
            0 <= uncertainty <= 60, "invalid calibration")
    descriptors = index.get("chunks")
    require(isinstance(descriptors, list) and 0 < len(descriptors) <= 240 and
            all(isinstance(e, dict) and integer(e.get("bytes"), 1, MAX_CHUNK) for e in descriptors) and
            sum(e["bytes"] for e in descriptors) <= MAX_INPUT_BYTES, "aggregate replay input bound")
    checked, files = checked_index(index_path)
    require(checked is not None and index.get("public_state_eligible") is False and
            raw_index == bounded_bytes(index_path, 1024**2), "replay index changed or is unsupported")
    frequency, origin = index.get("frequency"), tick(index.get("origin_ticks"))
    require(integer(frequency, 1, 10**10), "invalid replay frequency")
    frames, objects, epochs, seen_windows, data_ends = [], [], [], set(), []
    for n, (descriptor, pinned_path) in enumerate(zip(index["chunks"], files.values(), strict=True), 1):
        raw = bounded_bytes(pinned_path, MAX_CHUNK)
        require(len(raw) == descriptor["bytes"] and hashlib.sha256(raw).hexdigest() == descriptor["sha256"],
                "replay chunk changed after validation")
        chunk = strict_json(raw)
        require(isinstance(chunk, dict) and chunk.get("schema") == "overwatch-decoder.entity-replay/1" and
                chunk.get("public_state_eligible") is False and chunk.get("compact_observations") is True and
                chunk.get("frequency") == frequency and tick(chunk.get("origin_ticks")) == origin and
                chunk.get("source_sha256") == descriptor.get("source_sha256"), "replay chunk identity or clock mismatch")
        require("roster_sources" not in chunk and "multi_source_snapshot" not in chunk,
                "shared excerpts require a single roster source")
        source_objects, source_frames, source_fields = (chunk.get(k) for k in ("objects", "frames", "field_samples"))
        require(all(isinstance(value, list) for value in (source_objects, source_frames, source_fields)) and
                len(objects) + len(source_objects) <= MAX_OBJECTS and 0 < len(source_frames) <= MAX_FRAMES-len(frames) and
                len(source_fields) <= 2_000_000, "invalid replay chunk row bounds")
        number = descriptor.get("recorder_window", n)
        require(integer(number, 1, 240) and number not in seen_windows, "duplicate or invalid window")
        seen_windows.add(number)
        window = Window(number, len(source_objects), len(objects))
        for i, obj in enumerate(source_objects):
            require(isinstance(obj, dict) and obj.get("index") == i, "invalid source object index")
            display = f"{window.prefix}-object-{i+1:04d}"
            objects.append(dict(index=window.object_index(i), id=display, key=display, label=f"Object {i+1:03d}"))
        require(isinstance(chunk.get("epochs"), list) and all(isinstance(e, dict) and isinstance(e.get("id"), str)
                for e in chunk["epochs"]), "invalid source epochs")
        declared_epochs = {e["id"] for e in chunk["epochs"]}
        require(0 < len(declared_epochs) == len(chunk["epochs"]) <= MAX_OBJECTS, "invalid epoch count")
        last_data = None
        for frame in source_frames:
            require(isinstance(frame, dict) and isinstance(frame.get("epoch"), str) and
                    frame["epoch"] in declared_epochs, "frame epoch not declared")
            clean = frame_sample(frame, source_fields, window, frequency, origin)
            require(descriptor["start_seconds"] <= clean["t"] <= clean["end"] <= descriptor["end_seconds"] and
                    (not frames or clean["t"] > frames[-1]["t"]), "frame outside admitted window or order")
            if not frames or clean["epoch"] != frames[-1]["epoch"]:
                clean["continuity_valid"] = False
            if clean["objects"]:
                last_data = clean["end"]
            frames.append(clean)
        epochs.extend(dict(id=e, recorder_window=number, continuity_from_previous=False) for e in window.epochs.values())
        if last_data is not None:
            data_ends.append(min(descriptor["end_seconds"], last_data + HOLD_SECONDS))
    usable = [frame for frame in frames if frame["objects"]]
    require(usable and data_ends, "replay contains no usable positions")
    first = usable[0]["t"]
    last = data_ends[-1]
    require(last > first and first-offset >= 0, "empty replay or video clip")
    shifted_origin = tick(usable[0]["start_ticks"])
    duration = round(last-first, 9)
    def shift(value):
        return round(value-first, 9)

    included = [frame for frame in frames if first <= frame["t"] < last and frame["end"] <= last]
    require(included and len(included) <= MAX_FRAMES, "empty or oversized shared frame list")
    table = []
    for frame in included:
        frame["t"] = (tick(frame["start_ticks"])-shifted_origin)/frequency
        frame["end"] = (tick(frame["end_ticks"])-shifted_origin)/frequency
        fields = frame.pop("fields")
        frame["field_refs"] = list(range(len(table), len(table)+len(fields)))
        table.extend(fields)
    require(len(table) <= 2_000_000, "shared field row bound")
    gaps = []
    for gap in index.get("gaps", []):
        start, end = gap.get("start_seconds"), gap.get("end_seconds")
        require(finite(start) and finite(end) and 0 <= start <= end, "invalid explicit gap")
        start, end = max(first, start), min(last, end)
        if start < end:
            gaps.append(dict(start_seconds=shift(start), end_seconds=shift(end)))
    active_epochs = {frame["epoch"] for frame in included}
    summary = dict(frames=len(included), epochs=len(active_epochs), objects=len(objects),
                   positions=sum(len(f["objects"]) for f in included),
                   unknown_positions=sum(f["unknown_count"] for f in included),
                   skipped_intervals=(sum(f["skipped"] for f in included) if
                       all(integer(e.get("summary", {}).get("skipped_intervals")) for e in descriptors) else None))
    replay = dict(
        schema="overwatch-decoder.entity-replay/1", public_state_eligible=False, shared_excerpt=True,
        title="Overwatch recorded entity excerpt", frequency=frequency, origin_ticks=str(shifted_origin),
        start_seconds=0, end_seconds=duration, objects=objects, epochs=[e for e in epochs if e["id"] in active_epochs],
        frames=included, field_samples=table, events=[], untimed_events=[], gaps=gaps, summary=summary,
        interpolation=False, compact_observations=True, sample_hold_limit_seconds=HOLD_SECONDS,
        continuity_across_epochs=False, whole_match_claim=False, all_current_roster_claim=False,
        identity_scope="Display-only object and lifetime IDs scoped to each recorder window.",
        share_metadata=dict(original_source_offset_seconds=first, original_source_end_seconds=round(last, 9),
                            calibration_uncertainty_seconds=uncertainty, visibility="unknown",
                            raw_orientation_preview=True),
        note="Shared private-research excerpt. Uncovered time and visibility remain unknown.",
    )
    # Derive the reference grid from the retained coordinates, never arbitrary
    # source metadata. This is an observed extent, not a map-floor claim.
    points = [p[1:4] for frame in included for p in frame["objects"]]
    replay["bounds"] = {"min": [min(p[i] for p in points) for i in range(3)],
                        "max": [max(p[i] for p in points) for i in range(3)]}
    plan = dict(schema="overwatch-decoder.replay-share-trim/1", original_source_sha256=index["source_sha256"],
                original_replay_index_sha256=index_hash, original_video_sha256=calibration["video_sha256"],
                original_source_start_seconds=first, original_source_end_seconds=round(last, 9),
                original_video_offset_seconds=offset, video_start_seconds=round(first-offset, 9),
                video_end_seconds=round(last-offset, 9), video_duration_seconds=duration,
                calibration_uncertainty_seconds=uncertainty, frames=len(included))
    replay["source_sha256"] = hashlib.sha256(encode(replay)).hexdigest()
    replay["source_digest_kind"] = "share_export_display_content"
    encoded = encode(replay)
    require(len(encoded) <= MAX_OUTPUT_BYTES, "shared replay byte bound")
    plan["shared_replay_sha256"] = hashlib.sha256(encoded).hexdigest()
    return replay, plan


def encode(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--video", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for replay.json and private trim-plan.json")
    args = parser.parse_args()
    replay, plan = export_shared(args.index, args.calibration, args.video)
    encoded = encode(replay)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir/"replay.json").write_bytes(encoded)
    (args.output_dir/"trim-plan.json").write_bytes(encode(plan))
    print(json.dumps(dict(frames=plan["frames"], bytes=len(encoded),
                          video_start_seconds=plan["video_start_seconds"],
                          video_duration_seconds=plan["video_duration_seconds"])))


if __name__ == "__main__":
    main()
