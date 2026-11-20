"""Frame-local guard-set reuse preserves strict evidence validation."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import forward_owner_validation as validation
from test_compact_forward_owners import attach
from test_compact_live_entities import fixture
from test_forward_category_compaction import category


class GuardSetReuseTests(unittest.TestCase):
    def test_contents_not_mutable_identity_and_exact_integer_types(self):
        check = validation._guard_id_sets()
        value = [0, 1, 255]
        checked = check(value, 'fixture')
        self.assertIsInstance(checked, frozenset)
        self.assertIs(check(value.copy(), 'fixture'), checked)
        value[2] = 256
        with self.assertRaisesRegex(validation.InvalidForwardOwnerFrame, '^fixture$'):
            check(value, 'fixture')
        for bad in ([False, 1, 255], [0.0, 1, 255], [0, 1, -1], [0, 1, 1], [], [0] * 257):
            for category_path in (False, True):
                with self.subTest(bad=bad, category=category_path):
                    with self.assertRaisesRegex(validation.InvalidForwardOwnerFrame, '^fixture$'):
                        check(bad, 'fixture', category=category_path)
        self.assertEqual(check([0, 1, 255], 'fixture'), {0, 1, 255})

    def test_failed_and_over_budget_inputs_never_gain_approval(self):
        check = validation._guard_id_sets()
        for value in range(256):
            self.assertEqual(check([value], 'fixture'), {value})
        # After the finite cache budget, inputs still receive full checks.
        first = check([0, 1], 'fixture')
        self.assertIsNot(first, check([0, 1], 'fixture'))
        with self.assertRaisesRegex(validation.InvalidForwardOwnerFrame, 'invalid_later'):
            check([0, 1, 256], 'invalid_later')
        self.assertEqual(check([0, 1], 'fixture'), first)

    def test_reuse_skips_repeated_validation_but_not_between_frames(self):
        check = validation._guard_id_sets()
        original = validation.integer
        with patch.object(validation, 'integer', wraps=original) as integer:
            check([0, 1, 2], 'fixture')
            count = integer.call_count
            check([0, 1, 2], 'fixture', category=True)
            self.assertEqual(integer.call_count, count)
            validation._guard_id_sets()([0, 1, 2], 'fixture')
            self.assertEqual(integer.call_count, count + 3)

    def test_changed_guard_evidence_rejected_after_prior_frame(self):
        with tempfile.TemporaryDirectory() as directory:
            frame = category(attach(fixture(Path(directory))[0]))
            baseline = copy.deepcopy(frame)
            first = validation.validate_forward_owner_frame(frame)
            self.assertEqual(frame, baseline)
            self.assertEqual(validation.validate_forward_owner_frame(copy.deepcopy(frame)), first)
            row = frame['forward_owner_projection']['relations'][0]
            mutations = {
                'owned_bool': lambda r: r['owned_fields'][r['owned_field_prefix']+'position_candidate'].update(
                    guard_ids=[False, 1, 2, 3, 4]),
                'category_float': lambda r: r['raw_category_evidence']['fields'][2].update(
                    guard_ids=[0.0, 1, 2, 3, 4, 5, 6]),
                'category_duplicate': lambda r: r['raw_category_evidence']['fields'][2].update(
                    guard_ids=[0, 1, 2, 3, 4, 5, 5]),
                'missing_dependency': lambda r: r['raw_category_evidence']['fields'][2].update(
                    guard_ids=[0, 1, 2, 3]),
                'condition_range': lambda r: r['raw_category_evidence']['conditions'][0].update(
                    guard_ids=[256]),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    changed = copy.deepcopy(frame)
                    mutate(changed['forward_owner_projection']['relations'][0])
                    with self.assertRaises(validation.InvalidForwardOwnerFrame):
                        validation.validate_forward_owner_frame(changed)
                    self.assertEqual(validation.validate_forward_owner_frame(frame), first)
            self.assertEqual(row, baseline['forward_owner_projection']['relations'][0])


if __name__ == '__main__':
    unittest.main()
