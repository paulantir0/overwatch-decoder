"""Read-only frame scope caches never carry sampled values or guard success."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from relations import InvalidBinding
from test_relations import fixture, prepare
from test_live_relations import setup, start, live, next_frame, raw, SESSION
from live_relations import LiveRelations, InvalidLive


class GuardCheckScopeTests(unittest.TestCase):
    def setUp(self):
        profile, values = fixture()
        self.decoder, self.frame = prepare(profile, values)
        self.name = 'controller_0000_handle_candidate_i32'

    def test_scoped_and_unscoped_output_equal_and_no_result_cached(self):
        expected = self.decoder.project(self.frame)
        with self.decoder._frame_checks(self.frame):
            self.assertEqual(self.decoder.project(self.frame), expected)
            changed = self.decoder.project(self.frame)
            changed['relations'][0]['evidence'][0]['value'] = 99
            self.assertEqual(self.decoder.project(self.frame), expected)
        self.assertIsNone(self.decoder._active_checks)

    def test_guard_failure_in_next_scope_invalidates_prior_success(self):
        with self.decoder._frame_checks(self.frame):
            self.assertEqual(self.decoder.project(self.frame)['relations'][0]['relation_status'], 'observed')
        # Reusing the same dict must still create a fresh guard-check lifetime.
        self.frame['guards_after'][0].update(ok=False, error='changed')
        expected = self.decoder.project(self.frame)
        with self.decoder._frame_checks(self.frame):
            self.assertEqual(self.decoder.project(self.frame), expected)
            self.assertEqual(expected['relations'][0]['reason'], 'guard_check_failed')

    def test_guard_windows_apply_to_each_field_not_just_first_field(self):
        with self.decoder._frame_checks(self.frame):
            self.decoder.sample_scalar(self.name, self.frame, 'i32')
            # A second field's read ends after an otherwise valid after guard.
            other = 'controller_0000_manager_key_candidate_i32'
            self.frame['fields'][other]['read_end_ticks'] = 85
            with self.assertRaisesRegex(InvalidBinding, 'invalid_guard_bracket'):
                self.decoder.sample_scalar(other, self.frame, 'i32')

    def test_failure_falls_back_to_original_check_precedence(self):
        self.frame['guards_before'][0]['end_ticks'] = 35
        self.frame['guards_before'][1].update(ok=False, error='later-failure')
        with self.assertRaises(InvalidBinding) as old:
            self.decoder.sample_scalar(self.name, self.frame, 'i32')
        with self.decoder._frame_checks(self.frame):
            with self.assertRaises(InvalidBinding) as scoped:
                self.decoder.sample_scalar(self.name, self.frame, 'i32')
        self.assertEqual(str(old.exception), str(scoped.exception))
        self.assertEqual(str(scoped.exception), 'invalid_guard_bracket')

    def test_exception_and_different_frame_clear_or_bypass_scope(self):
        other = copy.deepcopy(self.frame); other['guards_before'][0].update(ok=False, error='other')
        with self.assertRaisesRegex(RuntimeError, 'stop'):
            with self.decoder._frame_checks(self.frame):
                self.decoder.sample_scalar(self.name, self.frame, 'i32')
                with self.assertRaisesRegex(InvalidBinding, 'guard_check_failed'):
                    self.decoder.sample_scalar(self.name, other, 'i32')
                raise RuntimeError('stop')
        self.assertIsNone(self.decoder._active_checks)
        with self.assertRaisesRegex(InvalidBinding, 'guard_check_failed'):
            self.decoder.sample_scalar(self.name, other, 'i32')

    def test_static_plan_invalidates_when_profile_guard_or_address_changes(self):
        with self.decoder._frame_checks(self.frame):
            self.assertEqual(self.decoder._binding(self.name)[1], 0x80000001)
        self.decoder.profile['guards'][0]['bytes_hex'] = '02000080'
        with self.decoder._frame_checks(self.frame):
            self.assertEqual(self.decoder._binding(self.name)[1], 0x80000002)
            with self.assertRaisesRegex(InvalidBinding, 'identity_word_guard_mismatch'):
                self.decoder._observed(self.name, self.frame)
        self.decoder.fields[self.name]['address'] += 1
        with self.decoder._frame_checks(self.frame):
            with self.assertRaisesRegex(InvalidBinding, 'identity_word_not_guarded'):
                self.decoder._binding(self.name)

    def test_independent_profile_instances_do_not_share_plans(self):
        profile, values = fixture(); profile['guards'][0]['bytes_hex'] = '05000080'
        other, frame = prepare(profile, values)
        with self.decoder._frame_checks(self.frame), other._frame_checks(frame):
            self.assertEqual(self.decoder._binding(self.name)[1], 0x80000001)
            self.assertEqual(other._binding(self.name)[1], 0x80000005)

    def test_adapter_projection_failure_releases_all_projector_scopes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); profile, frame, manifest, _ = setup(directory, cache=True)
            decoder = LiveRelations(directory, SESSION, 1, cached_label_recipe_sha256=manifest['recipe_sha256'])
            decoder.consume(raw(start(profile, manifest)))
            with patch.object(decoder.cache, 'project', side_effect=ValueError('projection-failed')):
                with self.assertRaisesRegex(ValueError, 'projection-failed'):
                    decoder.consume(raw(live(frame)))
            self.assertTrue(decoder.failed)
            self.assertIsNone(decoder.projector._active_checks)
            self.assertIsNone(decoder.cache.relations._active_checks)

    def test_adapter_rechecks_every_next_frame_guard_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); profile, frame, manifest, _ = setup(directory)
            decoder = LiveRelations(directory, SESSION, 1); decoder.consume(raw(start(profile, manifest)))
            decoder.consume(raw(live(frame)))
            second = next_frame(frame); second['guards_after'][0]['start_ticks'] = 135
            with self.assertRaisesRegex(InvalidLive, 'live_observed_guard_failed'):
                decoder.consume(raw(live(second, 2)))


if __name__ == '__main__':
    unittest.main()
