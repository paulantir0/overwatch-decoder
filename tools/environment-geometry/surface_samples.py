"""Validate one bounded survey in its original Workshop coordinate system."""

from __future__ import annotations

import hashlib
import math
import re

MAX_RAYS = 500
MAX_SOURCE_BYTES = 1024 * 1024
MAX_COORDINATE = 1_000_000
SOURCE_KINDS = {"inspector_log_file", "inspector_clipboard"}


def _number(value, maximum):
    if type(value) not in (int, float) or not -maximum <= value <= maximum:
        raise ValueError("coordinate or tolerance outside finite bounds")
    return float(value)


def _vector(value):
    if not isinstance(value, (list, tuple)) or len(value) != 3:
        raise ValueError("expected a three-component vector")
    return [_number(component, MAX_COORDINATE) for component in value]


def _digest(value):
    if not isinstance(value, bytes) or not 0 < len(value) <= MAX_SOURCE_BYTES:
        raise ValueError("invalid source byte length")
    return hashlib.sha256(value).hexdigest()


def _sample(index, origin, ray, tolerance):
    if not isinstance(ray, dict) or ray.keys() != {"index", "end", "hit", "normal"}:
        raise ValueError("unexpected ray fields")
    if type(ray["index"]) is not int or ray["index"] != index:
        raise ValueError("rays must be contiguous and ordered")
    end, hit, normal = (_vector(ray[key]) for key in ("end", "hit", "normal"))
    direction = [end[i] - origin[i] for i in range(3)]
    length = math.hypot(*direction)
    if length <= 2 * tolerance:
        raise ValueError("ray too short for source precision")
    offset = [hit[i] - origin[i] for i in range(3)]
    unit = [value / length for value in direction]
    along = sum(a * b for a, b in zip(unit, offset))
    deviation = math.hypot(*(value - along * axis for value, axis in zip(offset, unit)))
    if deviation > tolerance or not -tolerance <= along <= length + tolerance:
        raise ValueError("returned position outside ray tolerance")
    if abs(math.hypot(*normal) - 1) > 0.05:
        raise ValueError("returned normal is not unit length within tolerance")

    if math.dist(hit, end) <= tolerance:
        status = "miss_or_endpoint"
    elif math.dist(hit, origin) <= tolerance:
        status = "origin_ambiguous"
    elif not 0 < along < length:
        raise ValueError("returned position outside ray")
    else:
        status = "surface_hit"
    return {
        "index": index,
        "origin": origin.copy(),
        "end": end,
        "returned_hit": hit,
        "returned_normal": normal,
        "status": status,
    }


def build_sidecar(
    *, origin, rays, expected_count, map_name, mode_name, build_sha256,
    source_kind, source_bytes, rule_bytes, position_tolerance,
):
    """Build a complete single-origin sidecar from parsed, ordered records.

    The caller binds the observed map, mode, and executable to the saved source.
    Positions are never registered to a replay or used to infer coverage.
    """
    if not isinstance(build_sha256, str) or not re.fullmatch("[0-9a-f]{64}", build_sha256):
        raise ValueError("invalid executable build SHA-256")
    for name in (map_name, mode_name):
        if not isinstance(name, str) or not 0 < len(name) <= 120 or not name.isprintable():
            raise ValueError("invalid map or mode name")
    if not isinstance(source_kind, str) or source_kind not in SOURCE_KINDS:
        raise ValueError("invalid source kind")
    if type(expected_count) is not int or not 1 <= expected_count <= MAX_RAYS:
        raise ValueError("invalid expected ray count")
    if not isinstance(rays, (list, tuple)) or len(rays) != expected_count:
        raise ValueError("incomplete survey")
    tolerance = _number(position_tolerance, 0.25)
    if tolerance <= 0:
        raise ValueError("position tolerance must be positive")
    origin = _vector(origin)
    return {
        "schema": "overwatch-decoder.environment-surface-samples/1",
        "map": map_name,
        "mode": mode_name,
        "observed_build_sha256": build_sha256,
        "coordinate_space": "workshop_world",
        "replay_registration": None,
        "visibility": "unknown",
        "coverage": "sparse_first_hit_rays",
        "source": {
            "kind": source_kind,
            "sha256": _digest(source_bytes),
            "rule_sha256": _digest(rule_bytes),
            "position_tolerance": tolerance,
        },
        "rays": [_sample(index, origin, ray, tolerance) for index, ray in enumerate(rays)],
    }
