"""Synthetic live-epoch admission and fail-closed category behavior."""
import copy
import hashlib
import json
import unittest

from categories import InvalidCategoryEvidence
from live_categories import GuardedLiveCategories, live_frame_sha256
from test_categories import category_fixture


def raw(value):
    return json.dumps(value).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def live_category_fixture():
    profile, values, frame, finite, artifacts, native, roster = category_fixture()
    # The live path has no final recording manifest, even among its artifacts.
    artifacts.pop(finite['recording_manifest_sha256'])
    def add(value):
        data = value if isinstance(value, bytes) else raw(value)
        artifacts[sha(data)] = data
        return sha(data)
    acquisition = dict(schema='overwatch-decoder.acquisition-result/1', complete=True, target=profile['target'],
                       profile_sha256=finite['profile_sha256'], **finite['source'])
    session = dict(schema='overwatch-decoder.field-live/1', kind='session_start', session_id='fixture-live',
                   event_sequence=0, emitted_ticks=1, monotonic_frequency=1000,
                   target=profile['target'], recipe_sha256=finite['source']['recipe_sha256'],
                   revision='a' * 40, source_kind='native_process_memory', recording_frame_included=True,
                   public_state_eligible=False, atomic=False)
    segment = dict(schema='overwatch-decoder.field-live/1', kind='segment_start', session_id='fixture-live',
                   event_sequence=3, emitted_ticks=6, monotonic_frequency=1000, start_ticks=5,
                   segment=1, acquisition=1, profile_sha256=finite['profile_sha256'],
                   source_stream_schema='overwatch-decoder.field-stream/1',
                   fields=[dict(name=f['name'], type=f['type']) for f in profile['fields']])
    contract = {k: copy.deepcopy(finite[k]) for k in ('profile_sha256', 'build_sha256', 'mode_id',
        'self_controller_object_key', 'source', 'native_review_sha256', 'roster_review_sha256', 'bindings')}
    contract.update(schema='overwatch-decoder.live-category-contract/1', target=profile['target'], observer_revision=session['revision'],
                    acquisition_manifest_sha256=add(acquisition), session_start_sha256=add(session),
                    segment_start_sha256=add(segment))
    scope = dict(session_id=session['session_id'], segment=1, start_ticks=5, monotonic_frequency=1000,
                 session_start_sha256=contract['session_start_sha256'], segment_start_sha256=contract['segment_start_sha256'])
    mode = dict(schema='overwatch-decoder.live-category-mode-review/1', reviewed=True,
                review_method='manual_controlled_live_epoch', mode_id=contract['mode_id'],
                target=profile['target'], profile_sha256=contract['profile_sha256'],
                acquisition_manifest_sha256=contract['acquisition_manifest_sha256'],
                self_controller_object_key=contract['self_controller_object_key'], live_scope=scope,
                native_review_sha256=contract['native_review_sha256'], roster_review_sha256=contract['roster_review_sha256'],
                sources=[add(b'synthetic current controlled-epoch review')])
    contract['mode_review_sha256'] = add(mode)
    admission = dict(schema='overwatch-decoder.live-category-frame-admission/1', status='accepted_not_durability_verified',
                     durability_verified=False, session_id='fixture-live', segment=1,
                     profile_sha256=contract['profile_sha256'], acquisition_manifest_sha256=contract['acquisition_manifest_sha256'],
                     **contract['source'], event_sequence=4, event_sha256='12' * 32,
                     frame_sha256=live_frame_sha256(frame), frame_sequence=frame['sequence'],
                     frame_start_ticks=frame['start_ticks'], frame_end_ticks=frame['end_ticks'], monotonic_frequency=1000)
    return profile, frame, contract, artifacts, admission, mode, native, roster, acquisition, session, segment


class LiveCategoryTests(unittest.TestCase):
    def setUp(self):
        (self.profile, self.frame, self.contract, self.artifacts, self.admission, self.mode, self.native,
         self.roster, self.acquisition, self.session, self.segment) = live_category_fixture()
        self.projector = self.make()

    def add(self, value):
        data = raw(value)
        self.artifacts[sha(data)] = data
        return sha(data)

    def make(self):
        return GuardedLiveCategories(raw(self.profile), raw(self.contract), self.artifacts)

    def project(self, frame=None, admission=None, **kwargs):
        return self.projector.project(self.frame if frame is None else frame,
                                      admission=self.admission if admission is None else admission, **kwargs)

    def readmitted(self, frame):
        context = copy.deepcopy(self.admission)
        context.update(frame_sha256=live_frame_sha256(frame), frame_sequence=frame['sequence'],
                       frame_start_ticks=frame['start_ticks'], frame_end_ticks=frame['end_ticks'],
                       monotonic_frequency=frame['monotonic_frequency'])
        return context

    def assert_unknown(self, result):
        for row in result['rows']:
            self.assertEqual(row['status'], 'unknown')
            self.assertIsNone(row['raw_category_candidate'])
            self.assertIsNone(row['team_candidate'])
            self.assertIsNone(row['relative_allegiance_candidate'])

    def test_live_frame_works_without_any_recording_manifest(self):
        out = self.project()
        self.assertEqual(out['schema'], 'overwatch-decoder.guarded-live-actor-categories/1')
        self.assertEqual([r['relative_allegiance_candidate'] for r in out['rows']], ['self', 'friendly', 'enemy'])
        self.assertFalse(out['durability_verified'])
        self.assertFalse(out['public_state_eligible'])
        self.assertEqual(out['visibility'], 'unknown')
        self.assertNotIn('recording_manifest_sha256', json.dumps(out))
        self.assertFalse(hasattr(self.projector, 'recording_manifest_sha256'))
        self.assertEqual(out['live_scope']['session_id'], 'fixture-live')
        self.assertEqual(out['admission_evidence']['event_sha256'], '12' * 32)
        self.assertTrue(all(r['self_evidence'] for r in out['rows']))

    def test_finite_contract_scope_is_rejected(self):
        self.contract['recording_manifest_sha256'] = '99' * 32
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'finite_recording_scope_not_live'):
            self.make()

    def test_distinct_source_session_epoch_and_hashes_are_not_admitted(self):
        for key, value in [('session_id', 'next'), ('segment', 2), ('profile_sha256', '34' * 32),
                           ('acquisition_manifest_sha256', '34' * 32), ('recipe_sha256', '34' * 32),
                           ('evidence_sha256', '34' * 32), ('segment', True)]:
            with self.subTest(key=key, value=value):
                context = dict(self.admission, **{key: value})
                self.assert_unknown(self.project(admission=context))

    def test_nonaccepted_or_durable_claim_rejected(self):
        for context in ({}, dict(self.admission, status='recorded'), dict(self.admission, durability_verified=True)):
            self.assert_unknown(self.project(admission=context))

    def test_event_sequence_hash_and_frame_timing_must_match(self):
        for key, value in [('event_sequence', 3), ('event_sequence', True), ('event_sha256', 'broken'),
                           ('frame_sequence', 1), ('frame_sequence', False), ('frame_start_ticks', 9),
                           ('frame_end_ticks', 99), ('monotonic_frequency', 999)]:
            with self.subTest(key=key, value=value):
                self.assert_unknown(self.project(admission=dict(self.admission, **{key: value})))

    def test_mutated_frame_rejected_even_if_source_epoch_same(self):
        frame = copy.deepcopy(self.frame)
        frame['fields']['category_1']['value'] = 128
        self.assert_unknown(self.project(frame))
        out = self.project(frame, self.readmitted(frame))
        self.assertEqual(out['rows'][1]['relative_allegiance_candidate'], 'enemy')

    def test_acquisition_start_clock_and_frequency_enforced(self):
        for key, value in [('start_ticks', 4), ('monotonic_frequency', 2000)]:
            frame = copy.deepcopy(self.frame); frame[key] = value
            self.assert_unknown(self.project(frame, self.readmitted(frame)))

    def test_target_mismatch_still_fails_after_upstream_admission(self):
        frame = copy.deepcopy(self.frame); frame['target']['creation_file_time'] += 1
        self.assert_unknown(self.project(frame, self.readmitted(frame)))

    def test_guard_and_dependency_failures_survive_valid_envelope(self):
        for mutate in ('guard', 'dependency', 'bracket'):
            frame = copy.deepcopy(self.frame)
            if mutate == 'guard': frame['guards_after'][0]['ok'] = False
            elif mutate == 'dependency': frame['fields']['category_0']['guard_ids'] = []
            else: frame['guards_after'][0]['start_ticks'] = 20
            out = self.project(frame, self.readmitted(frame))
            self.assertTrue(any(r['status'] == 'unknown' for r in out['rows']))
            self.assertTrue(all(r['relative_allegiance_candidate'] is None for r in out['rows']))

    def test_missing_self_body_never_labels_spectated_actor_as_self(self):
        frame = copy.deepcopy(self.frame)
        frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        out = self.project(frame, self.readmitted(frame))
        self.assertTrue(any(r['raw_category_candidate'] is not None for r in out['rows']))
        for row in out['rows']:
            self.assertIsNone(row['team_candidate'])
            self.assertIsNone(row['relative_allegiance_candidate'])
        self.assertEqual(self.project()['rows'][1]['relative_allegiance_candidate'], 'friendly')

    def test_bad_self_category_nulls_every_relative_and_team_candidate(self):
        frame = copy.deepcopy(self.frame); frame['fields']['category_0']['value'] |= 4
        out = self.project(frame, self.readmitted(frame))
        self.assertTrue(all(r['team_candidate'] is None and r['relative_allegiance_candidate'] is None for r in out['rows']))

    def test_gap_nulls_all_candidates_without_carry(self):
        self.assert_unknown(self.project(gap=True))
        self.assertEqual(self.project()['rows'][2]['relative_allegiance_candidate'], 'enemy')

    def test_unguarded_mode_override_and_link_conditions_rejected(self):
        for case in ('missing', 'nonzero', 'partial', 'dependency'):
            self.setUp()
            binding = self.contract['bindings'][0]
            if case == 'missing': binding['conditions'][0]['address'] += 100
            elif case == 'nonzero': binding['conditions'][1]['equals'] = 1
            elif case == 'partial': binding['conditions'][1]['mask'] = 1
            else: binding['required_guard_ids'] = [0]
            with self.assertRaises(InvalidCategoryEvidence): self.make()

    def test_wrong_or_incomplete_acquisition_cannot_start_live_epoch(self):
        for key, value in [('complete', False), ('profile_sha256', '55' * 32), ('recipe_sha256', '55' * 32)]:
            self.setUp(); self.acquisition[key] = value
            self.contract['acquisition_manifest_sha256'] = self.add(self.acquisition)
            with self.assertRaises(InvalidCategoryEvidence): self.make()

    def test_frozen_review_cannot_admit_another_live_epoch(self):
        self.mode['live_scope']['segment'] = 2
        self.contract['mode_review_sha256'] = self.add(self.mode)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'live_mode_review_mismatch'): self.make()

    def test_session_must_offer_native_full_recording_evidence(self):
        self.session['recording_frame_included'] = False
        self.contract['session_start_sha256'] = self.add(self.session)
        with self.assertRaises(InvalidCategoryEvidence): self.make()

    def test_segment_field_order_and_types_must_match(self):
        self.segment['fields'].reverse()
        self.contract['segment_start_sha256'] = self.add(self.segment)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'live_segment_field_shape_mismatch'): self.make()

    def test_roster_roles_still_require_native_category_consistency(self):
        self.roster['anchors'][1].update(category=1, team='red')
        self.contract['roster_review_sha256'] = self.add(self.roster)
        self.mode['roster_review_sha256'] = self.contract['roster_review_sha256']
        self.contract['mode_review_sha256'] = self.add(self.mode)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'roster_role_category_mismatch'): self.make()

    def test_reviewed_self_must_actually_be_in_profile(self):
        missing = 'controller:' + '56' * 32
        self.contract['self_controller_object_key'] = missing
        self.roster['self_controller_object_key'] = missing
        self.roster['anchors'][0]['controller_object_key'] = missing
        self.contract['roster_review_sha256'] = self.add(self.roster)
        self.mode.update(self_controller_object_key=missing, roster_review_sha256=self.contract['roster_review_sha256'])
        self.contract['mode_review_sha256'] = self.add(self.mode)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'live_profile_self_binding_missing_or_ambiguous'): self.make()

    def test_review_artifact_corruption_rejected(self):
        self.artifacts[self.contract['native_review_sha256']] += b' '
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'artifact_hash_or_size'): self.make()

    def test_admission_extra_private_data_is_not_copied(self):
        context = dict(self.admission, private_path='/private/fixture', raw_addresses=[1234])
        out = self.project(admission=context)
        self.assertNotIn('private_path', json.dumps(out))
        self.assertNotIn('raw_addresses', json.dumps(out))
        self.assertNotIn('address', json.dumps(out))

    def test_projection_does_not_mutate_source_or_admission(self):
        snapshot = copy.deepcopy((self.frame, self.admission, self.contract, self.artifacts))
        self.project()
        self.assertEqual(snapshot, (self.frame, self.admission, self.contract, self.artifacts))


if __name__ == '__main__':
    unittest.main()
