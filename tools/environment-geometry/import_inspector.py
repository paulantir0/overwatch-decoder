"""Import timestamped Overwatch Decoder surface surveys from a closed Inspector log."""

import argparse
import json
import re
from pathlib import Path

from planar_patches import derive_patches
from surface_samples import MAX_SOURCE_BYTES, build_sidecar

VECTOR = r"\((-?\d{1,7}\.\d{2}), (-?\d{1,7}\.\d{2}), (-?\d{1,7}\.\d{2})\)"
LINE = re.compile(r"\[(\d{2}):([0-5]\d):([0-5]\d)\] (OWD[123] .+)")
INDEX = r"(\d{1,3})"
MAX_SURVEYS = 6


def _match(pattern, message):
    match = re.fullmatch(pattern, message)
    if not match:
        raise ValueError("unexpected Inspector survey record")
    return match.groups()


def _vector(parts):
    return [float(component) for component in parts]


def import_log(raw, *, rule_bytes, map_name, mode_name, build_sha256, planar_patches=False):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError("invalid Inspector log size")
    if not raw.endswith(b"\n"):
        raise ValueError("Inspector log lacks final line ending")
    records = []
    for line in raw.decode("utf-8-sig").splitlines():
        if re.search(r"\bOWD[123]\b", line):
            hours, minutes, seconds, message = _match(LINE, line)
            elapsed = int(hours) * 3600 + int(minutes) * 60 + int(seconds)
            if records and elapsed < records[-1][0]:
                raise ValueError("Inspector survey time reversed")
            records.append((elapsed, message))
    if not records:
        raise ValueError("no Inspector survey records")

    surveys = []
    cursor = 0

    def take(pattern):
        nonlocal cursor
        if cursor >= len(records):
            raise ValueError("incomplete Inspector survey")
        fields = _match(pattern, records[cursor][1])
        cursor += 1
        return fields

    escaped_map = re.escape(map_name)
    version = records[0][1][:4]
    while cursor < len(records):
        index = len(surveys)
        if index >= (MAX_SURVEYS if version == "OWD3" else 1):
            raise ValueError("unexpected number of surveys")
        started = records[cursor][0]
        ray_times = []
        if version == "OWD1":
            player = take(rf"OWD1 MAP {escaped_map} PLAYER {VECTOR}")
            ray = take(rf"OWD1 RAY {VECTOR} END {VECTOR} HIT {VECTOR}")
            origin = _vector(ray[:3])
            normal = take(rf"OWD1 NORMAL {VECTOR}")
            ray_times.append((records[cursor - 2][0], records[cursor - 1][0]))
            rays = [{"index": 0, "end": _vector(ray[3:6]), "hit": _vector(ray[6:]), "normal": _vector(normal)}]
        else:
            tag = f"OWD3 ID {index}" if version == "OWD3" else "OWD2"
            header = take(rf"{tag} MAP {escaped_map} PLAYER {VECTOR} ORIGIN {VECTOR}")
            player, origin = header[:3], _vector(header[3:])
            rays = []
            for ray_index in range(49):
                ray = take(rf"{version} RAY {INDEX} END {VECTOR} HIT {VECTOR}")
                normal = take(rf"{version} NORMAL {INDEX} {VECTOR}")
                ray_times.append((records[cursor - 2][0], records[cursor - 1][0]))
                if int(ray[0]) != ray_index or int(normal[0]) != ray_index:
                    raise ValueError("unexpected Inspector ray index")
                rays.append({"index": ray_index, "end": _vector(ray[1:4]),
                             "hit": _vector(ray[4:]), "normal": _vector(normal[1:])})
            take(rf"{tag} DONE 49")
        sidecar = build_sidecar(
            origin=origin, rays=rays, expected_count=1 if version == "OWD1" else 49,
            map_name=map_name, mode_name=mode_name, build_sha256=build_sha256,
            source_kind="inspector_log_file", source_bytes=raw, rule_bytes=rule_bytes,
            position_tolerance=0.025,
        )
        sidecar["survey"] = {
            "index": index, "player_position": _vector(player),
            "clock": "inspector_elapsed_seconds",
            "start": started, "end": records[cursor - 1][0],
        }
        for ray, (hit_time, normal_time) in zip(sidecar["rays"], ray_times):
            ray["hit_elapsed_seconds"] = hit_time
            ray["normal_elapsed_seconds"] = normal_time
        if planar_patches:
            sidecar["planar_patches"] = derive_patches(sidecar["rays"])
        surveys.append(sidecar)
    return surveys


def _read(path):
    with path.open("rb") as file:
        data = file.read(MAX_SOURCE_BYTES + 1)
    if not 0 < len(data) <= MAX_SOURCE_BYTES:
        raise ValueError("file outside source byte budget")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("rule", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--map", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--build-sha256", required=True)
    parser.add_argument("--planar-patches", action="store_true")
    args = parser.parse_args()
    try:
        surveys = import_log(
            _read(args.log), rule_bytes=_read(args.rule), map_name=args.map,
            mode_name=args.mode, build_sha256=args.build_sha256,
            planar_patches=args.planar_patches,
        )
        payload = json.dumps(surveys, indent=2, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8") as file:
            file.write(payload)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
