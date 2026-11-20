import unittest

from planar_patches import derive_patches


def make_grid(floor=False):
    rays = [{"status": "miss_or_endpoint"} for _ in range(49)]
    for index, a, b in ((0, 0, 0), (1, 1, 0), (7, 0, 1), (8, 1, 1)):
        rays[index] = {
            "status": "surface_hit",
            "returned_hit": [a, 0, b] if floor else [0, a, b],
            "returned_normal": [0, 1, 0] if floor else [1, 0, 0],
        }
    return rays


class PlanarPatchTests(unittest.TestCase):
    def test_wall_and_floor_cells_stay_inside_adjacent_samples(self):
        for floor in (False, True):
            with self.subTest(floor=floor):
                self.assertEqual(derive_patches(make_grid(floor)), [
                    {"kind": "derived_between_samples", "ray_indices": [0, 1, 8, 7]},
                ])

    def test_rejects_boundary_discontinuity_miss_and_degeneracy(self):
        for update in (
            {"returned_normal": [0, 1, 0]},
            {"returned_normal": [-1, 0, 0]},
            {"returned_hit": [0.031, 1, 1]},
            {"returned_hit": [0, 7, 1]},
            {"returned_hit": [0, 0, 0]},
            {"status": "miss_or_endpoint"},
        ):
            with self.subTest(update=update):
                rays = make_grid()
                rays[8].update(update)
                self.assertEqual(derive_patches(rays), [])

    def test_rejects_single_ray(self):
        self.assertEqual(derive_patches(make_grid()[:1]), [])
