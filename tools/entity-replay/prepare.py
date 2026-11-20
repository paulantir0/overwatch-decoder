#!/usr/bin/env python3
"""Stream private decoded entity frames into a bounded local replay artifact.

No interpolation, person identification, game access, or public-state promotion.
Usage: prepare.py INPUT.jsonl OUTPUT.json [--title TEXT]
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile


class InvalidRecording(ValueError):
    """Input cannot be represented without changing its evidence semantics."""


def require(condition, message):
    if not condition:
        raise InvalidRecording(message)


def integer(value, name, minimum=0):
    require(type(value) is int and value >= minimum, f"invalid {name}")
    return value


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def declared_pools(actor):
    """Keep the decoder's declared set; a field-name scan could miss a pool."""
    pools = actor.get("pools", [])
    require(isinstance(pools, list) and len(pools) <= 32, "invalid pool declarations")
    result, seen, physical = [], set(), set()
    for pool in pools:
        ordinal = integer(pool.get("ordinal"), "pool ordinal")
        index = integer(pool.get("pool_index"), "physical pool index")
        membership = integer(pool.get("membership_u32"), "pool membership")
        require(ordinal not in seen and index not in physical and membership <= 0xffffffff,
                "duplicate or invalid pool declaration")
        require(pool.get("field_name") == f"actor_{actor['ordinal']:04d}_pool_{ordinal:04d}_direct_candidate",
                "pool field disagrees with declaration")
        result.append((ordinal, index, membership))
        seen.add(ordinal)
        physical.add(index)
    return result


def observed_self_pools(actor, declarations, index, start, end):
    """Transport raw complete self pools, without assigning armor/max semantics."""
    if actor.get("is_self") is not True or not declarations:
        return None
    expected = {f"pool_{ordinal:04d}_direct_candidate" for ordinal, _, _ in declarations}
    actual = {key for key in actor.get("fields", {})
              if key.startswith("pool_") and key.endswith("_direct_candidate")}
    if expected != actual:
        return None
    pools = []
    for ordinal, physical, membership in declarations:
        field = actor.get("fields", {}).get(f"pool_{ordinal:04d}_direct_candidate", {})
        value = field.get("value")
        rs, re = field.get("read_start_ticks"), field.get("read_end_ticks")
        if not (field.get("status") == "observed" and field.get("type") == "f32"
                and type(value) in (int, float) and math.isfinite(value) and value >= 0
                and type(rs) is int and type(re) is int and start <= rs <= re <= end):
            return None
        pools.append([ordinal, physical, membership, value, str(rs), str(re)])
    return dict(object=index, declared_count=len(declarations), pools=pools)


def prepare(source, destination, *, title="Recorded objects — private research",
            max_frames=100_000, max_objects=4096, max_epochs=10000,
            max_positions=2_000_000,
            max_input_bytes=8 * 1024**3, max_line_bytes=2 * 1024**2,
            max_output_bytes=128 * 1024**2):
    """Atomically write JSON; retain every frame or fail, never silently truncate.

    Object keys describe declared structural bindings, not people. A repeated
    key does not assert uninterrupted lifetime across gaps or acquisition epochs.
    Memory usage is bounded by one input line and the capped object/epoch maps.
    Defaults match the browser limits. Larger limits are available only through
    this Python API for separate consumers; the browser may reject such output.
    """
    source, destination = Path(source), Path(destination)
    require(source.resolve() != destination.resolve(), "input and output must differ")
    for value in (max_frames, max_objects, max_epochs, max_positions, max_input_bytes,
                  max_line_bytes, max_output_bytes):
        require(type(value) is int and value > 0, "limits must be positive integers")
    destination.parent.mkdir(parents=True, exist_ok=True)
    objects, indices, epochs, epoch_ids = [], {}, [], set()
    active = None
    frequency = origin = None
    digest = hashlib.sha256()
    consumed = count = position_count = unknown_count = unknown_frames = skipped = 0
    rotation_count = self_pool_frames = 0
    rotation_norm_min, rotation_norm_max = math.inf, 0.0
    first_time = last_time = last_ticks = None
    low, high = [math.inf] * 3, [-math.inf] * 3
    metadata_seen = False
    temp_path = None
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as frames, source.open("rb") as stream:
        frame_bytes = 0
        while True:
            raw = stream.readline(max_line_bytes + 1)
            if not raw:
                break
            consumed += len(raw)
            require(consumed <= max_input_bytes, "input byte limit exceeded")
            require(len(raw) <= max_line_bytes, "input line limit exceeded")
            digest.update(raw)
            try:
                row = json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
            except (ValueError, UnicodeDecodeError) as error:
                raise InvalidRecording("invalid JSON input") from error
            require(isinstance(row, dict), "record must be an object")
            kind = row.get("kind")
            if kind == "metadata":
                require(not metadata_seen and count == 0 and not epochs, "duplicate/late metadata")
                require(row.get("schema") == "overwatch-decoder.private-entity-timeline/1", "unsupported source schema")
                require(row.get("public_state_eligible") is False, "source must explicitly remain private research")
                metadata_seen = True
            elif kind == "epoch_start":
                require(metadata_seen and active is None, "epoch starts before metadata or overlaps")
                eid = row.get("epoch_id")
                require(isinstance(eid, str) and eid and eid not in epoch_ids, "invalid/duplicate epoch")
                require(len(epochs) < max_epochs, "epoch limit exceeded")
                fq = integer(row.get("qpc_frequency"), "frequency", 1)
                org = integer(row.get("session_qpc_origin"), "origin")
                require(frequency is None or (fq, org) == (frequency, origin), "clock changed within recording")
                frequency, origin = fq, org
                mapping, pool_mapping, seen = {}, {}, set()
                require(isinstance(row.get("actors"), list), "missing epoch actors")
                for actor in row["actors"]:
                    ordinal = integer(actor.get("ordinal"), "ordinal")
                    key = actor.get("object_key")
                    require(isinstance(key, str) and key and len(key) <= 256, "invalid object key")
                    require(ordinal not in mapping and key not in seen, "duplicate epoch identity")
                    seen.add(key)
                    if key not in indices:
                        require(len(objects) < max_objects, "object limit exceeded")
                        index = len(objects)
                        indices[key] = index
                        objects.append(dict(id=f"object-{index + 1:04d}", index=index,
                                            key=key, label=f"Object {index + 1:03d}"))
                    mapping[ordinal] = key
                    pool_mapping[ordinal] = declared_pools(actor)
                active = dict(id=eid, mapping=mapping, pool_mapping=pool_mapping,
                              frames=0, last_sequence=None, previous_observed=False)
                declared_self = [a["ordinal"] for a in row["actors"] if a.get("is_self") is True]
                active["declared_self"] = declared_self[0] if len(declared_self) == 1 else None
                epoch_ids.add(eid)
                target = row.get("target") or {}
                require(isinstance(target, dict), "invalid target metadata")
                target = {key: target[key] for key in ("pid", "creation_file_time", "executable_sha256", "architecture") if key in target}
                epochs.append(dict(id=eid,
                                   profile_sha256=row.get("profile_sha256"),
                                   evidence_sha256=row.get("evidence_sha256"), target=target,
                                   source_timeline_sha256=row.get("source_timeline_sha256"),
                                   continuity_from_previous=False,
                                   objects=[[n, indices[k]] for n, k in mapping.items()],
                                   first_frame=count, frames=0))
            elif kind == "epoch_end":
                require(active is not None and row.get("epoch_id") == active["id"], "unmatched epoch end")
                require(integer(row.get("frames"), "epoch frame count") == active["frames"], "epoch count mismatch")
                epochs[-1].update(frames=active["frames"], end_reason=row.get("reason"))
                active = None
            elif kind == "frame":
                require(active is not None and row.get("epoch_id") == active["id"], "frame outside its epoch")
                require(row.get("profile_sha256") == epochs[-1]["profile_sha256"], "frame profile differs from epoch")
                require(count < max_frames, "frame limit exceeded")
                start = integer(row.get("start_ticks"), "frame start")
                end = integer(row.get("end_ticks"), "frame end")
                require(end >= start and start >= origin, "invalid frame time bracket")
                require(last_ticks is None or start > last_ticks, "frame timestamps must strictly increase")
                seq = integer(row.get("sequence"), "sequence")
                require(active["last_sequence"] is None or seq > active["last_sequence"], "non-increasing epoch sequence")
                missed = integer(row.get("skipped_intervals_before"), "skipped intervals")
                require(type(row.get("continuity_valid")) is bool, "missing continuity status")
                current, reads, unknown, seen_ordinals = [], [], 0, set()
                rotations, rotation_reads = [], []
                self_pools = None
                require(isinstance(row.get("actors"), list), "missing frame actors")
                unique_current_self = sum(a.get("is_self") is True for a in row["actors"]) == 1
                for actor in row["actors"]:
                    ordinal = integer(actor.get("ordinal"), "actor ordinal")
                    require(ordinal in active["mapping"] and ordinal not in seen_ordinals, "unknown/duplicate frame ordinal")
                    seen_ordinals.add(ordinal)
                    declared = active["mapping"][ordinal]
                    require(actor.get("declared_object_key") == declared, "declared identity changed within epoch")
                    key = actor.get("object_key")
                    position = actor.get("fields", {}).get("position_candidate", {})
                    valid = actor.get("identity_status") == "guarded" and key is not None and position.get("status") == "observed"
                    if not valid:
                        require(key is None or key == declared, "invalid object reference")
                        unknown += 1
                        continue
                    require(key == declared, "observed identity differs from epoch")
                    xyz = position.get("value")
                    require(position.get("type") == "f32x3" and isinstance(xyz, list) and len(xyz) == 3, "invalid position triple")
                    require(all(type(v) in (int, float) and math.isfinite(v) for v in xyz), "nonfinite/nonnumeric position")
                    own = actor.get("is_self")
                    require(own is None or type(own) is bool, "invalid self association")
                    rs = integer(position.get("read_start_ticks"), "position read start")
                    re = integer(position.get("read_end_ticks"), "position read end")
                    require(start <= rs <= re <= end, "position read outside frame")
                    index = indices[key]
                    current.append([index, *xyz, own])
                    reads.append([index, str(rs), str(re)])
                    if own is True and unique_current_self and ordinal == active["declared_self"]:
                        self_pools = observed_self_pools(actor, active["pool_mapping"][ordinal], index, start, end)
                    # Preserve raw components: neither normalization nor axis/aim
                    # interpretation is justified by the transport schema.
                    rotation = actor.get("fields", {}).get("raw_quaternion_candidate")
                    if rotation is not None and rotation.get("status") == "observed":
                        q = rotation.get("value")
                        require(rotation.get("type") == "f32x4" and isinstance(q, list) and len(q) == 4,
                                "invalid raw quaternion tuple")
                        require(all(type(v) in (int, float) and math.isfinite(v) for v in q),
                                "nonfinite/nonnumeric raw quaternion")
                        qs, qe = rotation.get("read_start_ticks"), rotation.get("read_end_ticks")
                        # Missing/stale brackets must not carry an orientation into this frame.
                        if type(qs) is int and type(qe) is int and start <= qs <= qe <= end:
                            rotations.append([index, *q])
                            rotation_reads.append([index, str(qs), str(qe)])
                            norm = math.hypot(*q)
                            require(math.isfinite(norm), "raw quaternion norm overflow")
                            rotation_norm_min = min(rotation_norm_min, norm)
                            rotation_norm_max = max(rotation_norm_max, norm)
                    for axis, value in enumerate(xyz):
                        low[axis] = min(low[axis], value)
                        high[axis] = max(high[axis], value)
                require(seen_ordinals == set(active["mapping"]), "frame omits declared actors")
                require(sum(obj[4] is True for obj in current) <= 1, "multiple self actors")
                t, stop = (start - origin) / frequency, (end - origin) / frequency
                output = dict(t=t, end=stop, epoch=active["id"], sequence=seq,
                              start_ticks=str(start), end_ticks=str(end), skipped=missed,
                              continuity_valid=bool(row["continuity_valid"] and active["previous_observed"] and not unknown and not missed),
                              objects=current, reads=reads, unknown_count=unknown,
                              rotations=rotations, rotation_reads=rotation_reads,
                              self_pools=self_pools,
                              unknown_rotation_count=len(seen_ordinals) - len(rotations))
                text = ("," if count else "") + encoded(output)
                frame_bytes += len(text.encode("utf-8"))
                require(frame_bytes <= max_output_bytes, "output byte limit exceeded")
                frames.write(text)
                first_time = t if first_time is None else first_time
                last_time, last_ticks = stop, start
                count += 1
                active["frames"] += 1
                active["last_sequence"] = seq
                active["previous_observed"] = not unknown
                require(position_count + len(current) <= max_positions, "position limit exceeded")
                position_count += len(current)
                rotation_count += len(rotations)
                self_pool_frames += self_pools is not None
                unknown_count += unknown
                unknown_frames += bool(unknown)
                skipped += missed
            else:
                raise InvalidRecording(f"unsupported record kind: {kind!r}")
        require(metadata_seen and active is None, "missing metadata or unterminated epoch")
        require(count > 0, "recording contains no frames")
        summary = dict(frames=count, epochs=len(epochs), objects=len(objects), positions=position_count,
                       unknown_positions=unknown_count, frames_with_unknown=unknown_frames,
                       skipped_intervals=skipped, frame_count=count,
                       observed_object_samples=position_count, unknown_object_samples=unknown_count,
                       distinct_objects=len(objects), observed_rotation_samples=rotation_count,
                       complete_self_pool_frames=self_pool_frames,
                       rotation_norm_range=[rotation_norm_min, rotation_norm_max] if rotation_count else None)
        document = dict(schema="overwatch-decoder.entity-replay/1", title=title, source_sha256=digest.hexdigest(),
                        frequency=frequency, origin_ticks=str(origin), start_seconds=first_time,
                        end_seconds=last_time, objects=objects, epochs=epochs,
                        bounds=dict(min=low if position_count else None, max=high if position_count else None),
                        summary=summary, public_state_eligible=False, hero_team="unknown",
                        identity_scope="structural objects, not people", interpolation=False,
                        continuity_across_epochs=False,
                        self_pool_columns=["ordinal", "physical_index", "membership_u32", "raw_value",
                                           "read_start_ticks", "read_end_ticks"],
                        self_pool_semantics="Raw declared self pools. Sum and ceiling are private HUD-health candidates, not max health, armor, or verified semantics for arbitrary recordings.",
                        orientation=dict(kind="raw_quaternion_candidate", components="q0,q1,q2,q3",
                                         component_order_validated=False, axis_convention_validated=False,
                                         rendering_assumption=dict(component_order="xyzw", up_axis="+Y", forward_axis="+Z"),
                                         values_normalized=False, missing_rotation="omit; never carry forward",
                                         camera_aim_validated=False, fov_validated=False,
                                         note="Historical controlled self yaw association only; other-object facing and camera semantics unvalidated. Display cones are orientation candidates with arbitrary aperture."))
        prefix = encoded(document)[:-1] + ',"frames":['
        require(len(prefix.encode("utf-8")) + frame_bytes + 2 <= max_output_bytes, "output byte limit exceeded")
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                             prefix=".entity-replay-", delete=False) as target:
                temp_path = Path(target.name)
                target.write(prefix)
                frames.seek(0)
                while chunk := frames.read(1024**2):
                    target.write(chunk)
                target.write("]}")
            os.replace(temp_path, destination)
            temp_path = None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--title", default="Recorded objects — private research")
    args = parser.parse_args()
    try:
        print(encoded(prepare(args.source, args.destination, title=args.title)))
    except (InvalidRecording, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"Replay conversion failed: {error}\n")


if __name__ == "__main__":
    main()
