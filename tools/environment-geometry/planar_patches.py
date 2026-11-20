"""Derive conservative quads between adjacent samples of a 7×7 ray grid."""

import math

GRID_WIDTH = 7
MAX_SPAN = 5.0
MAX_PLANE_ERROR = 0.03
MIN_NORMAL_DOT = 0.999


def _subtract(a, b):
    return [x - y for x, y in zip(a, b)]


def _dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def _cross(a, b):
    x, y, z = a
    u, v, w = b
    return [y * w - z * v, z * u - x * w, x * v - y * u]


def _valid_cell(rays):
    if any(ray["status"] != "surface_hit" for ray in rays):
        return False
    vertices = [ray["returned_hit"] for ray in rays]
    normals = []
    for ray in rays:
        normal = ray["returned_normal"]
        length = math.hypot(*normal)
        normals.append([value / length for value in normal])
    for i in range(4):
        for j in range(i):
            difference = _subtract(vertices[i], vertices[j])
            if (
                math.hypot(*difference) > MAX_SPAN
                or _dot(normals[i], normals[j]) < MIN_NORMAL_DOT
                or max(abs(_dot(difference, normals[k])) for k in (i, j)) > MAX_PLANE_ERROR
            ):
                return False

    # Require a convex perimeter in ray-grid order. This also rejects degenerate cells.
    edges = [_subtract(vertices[(i + 1) % 4], vertices[i]) for i in range(4)]
    turns = [_dot(_cross(edges[i - 1], edges[i]), normals[0]) for i in range(4)]
    return all(turn > 1e-6 for turn in turns) or all(turn < -1e-6 for turn in turns)


def derive_patches(rays):
    """Return quads referencing original ray indices of a validated grid."""
    if len(rays) != GRID_WIDTH**2:
        return []
    patches = []
    for row in range(GRID_WIDTH - 1):
        for col in range(GRID_WIDTH - 1):
            start = row * GRID_WIDTH + col
            corners = [start, start + 1, start + 1 + GRID_WIDTH, start + GRID_WIDTH]
            if _valid_cell([rays[index] for index in corners]):
                patches.append({"kind": "derived_between_samples", "ray_indices": corners})
    return patches
