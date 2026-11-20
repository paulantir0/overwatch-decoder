"""Synthetic source/roster binding and dynamic semantic-state tests."""
import copy
import hashlib
import json
import unittest

from categories import GuardedCategories, InvalidCategoryEvidence
from relations import GuardedRelations
from test_relations import fixture, prepare


def raw(value):
    return json.dumps(value).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def category_fixture():
    profile, values = fixture(3)
    profile['guards'] += [dict(address=0x5000, bytes_hex='00' * 8),
                          dict(address=0x5010, bytes_hex='00' * 4)]
    for n, value in enumerate((8, 8, 128)):
        name = f'category_{n}'
        profile['fields'].append(dict(name=name, type='i32', address=0x6000 + n * 4))
        values[name] = value  # Semantic values have no constant-value guards.
    decoder, frame = prepare(profile, values)
    relations = decoder.project(frame)['relations']
    artifacts = {}
    def add(value):
        data = value if isinstance(value, bytes) else raw(value)
        artifacts[sha(data)] = data
        return sha(data)
    native = dict(schema='overwatch-decoder.native-category-review/1', reviewed=True, review_method='native_consumer_trace',
                  build_sha256=profile['target']['executable_sha256'], sources=[add(b'synthetic source')],
                  required_conditions=['unlinked_owner', 'zero_override'],
                  algorithm=dict(ordered_bits=[3, 7, 11], clear_bits=[2], supported_categories=[0, 1]))
    roster = dict(schema='overwatch-decoder.category-roster-review/1', reviewed=True,
                  review_method='manual_visual_roster_with_full_native_keys',
                  build_sha256=profile['target']['executable_sha256'], mode_id='fixture-controlled-mode',
                  self_controller_object_key=relations[0]['controller_object_key'],
                  sources=[add(b'synthetic roster image'), add(b'synthetic full-key proof')],
                  category_teams=[dict(category=0, team='blue'), dict(category=1, team='red')],
                  anchors=[dict(controller_object_key=r['controller_object_key'], body_object_key=r['body_object_key'],
                                category=0 if i < 2 else 1, team='blue' if i < 2 else 'red',
                                role=('self', 'friendly', 'enemy')[i]) for i, r in enumerate(relations)])
    manifest = dict(schema='overwatch-decoder.field-recording/1', target=profile['target'], profile_sha256=decoder.hash,
                    stream_summary=dict(frames=4, monotonic_origin_ticks=0, monotonic_frequency=1000, elapsed_ms=500))
    contract = dict(schema='overwatch-decoder.category-contract/1', profile_sha256=decoder.hash,
                    build_sha256=profile['target']['executable_sha256'], mode_id='fixture-controlled-mode',
                    self_controller_object_key=relations[0]['controller_object_key'],
                    source=dict(recipe_sha256='cd' * 32, evidence_sha256='ef' * 32),
                    recording_manifest_sha256=add(manifest),
                    frame_scope=dict(first_sequence=0, last_sequence=3, start_ticks=10, end_ticks=400),
                    native_review_sha256=add(native), roster_review_sha256=add(roster),
                    bindings=[dict(body_handle_field=f'controller_{i:04}_body_0000_handle_candidate_i32',
                                   body_creation_key_field=f'controller_{i:04}_body_0000_manager_key_candidate_i32',
                                   flags_field=f'category_{i}', required_guard_ids=list(range(len(profile['guards']))),
                                   conditions=[dict(role='unlinked_owner', address=0x5000, width=8, mask=512, equals=0),
                                               dict(role='zero_override', address=0x5010, width=4, mask=2**32-1, equals=0)])
                              for i in range(3)])
    return profile, values, frame, contract, artifacts, native, roster


class CategoryTests(unittest.TestCase):
    def setUp(self):
        self.profile, self.values, self.frame, self.contract, self.artifacts, self.native, self.roster = category_fixture()
        self.projector = self.make()

    def make(self):
        return GuardedCategories(raw(self.profile), raw(self.contract), self.artifacts)

    def changed_review(self, kind, value):
        data = raw(value)
        self.artifacts[sha(data)] = data
        self.contract[kind + '_review_sha256'] = sha(data)

    def rows(self, frame=None, **kwargs):
        return self.projector.project(self.frame if frame is None else frame, **kwargs)['rows']

    def test_exact_keys_and_explicit_roster_mapping(self):
        result = self.projector.project(self.frame)
        self.assertEqual([r['raw_category_candidate'] for r in result['rows']], [0, 0, 1])
        self.assertEqual([r['relative_allegiance_candidate'] for r in result['rows']], ['self', 'friendly', 'enemy'])
        for row in result['rows']:
            self.assertFalse(row['public_state_eligible'])
            self.assertEqual(row['visibility'], 'unknown')
            self.assertEqual(len(row['evidence']), 3)
            self.assertIn('self_evidence', row)
            self.assertEqual(row['mode_scope']['recording_manifest_sha256'], self.contract['recording_manifest_sha256'])
        self.assertFalse(result['public_state_eligible'])
        self.assertEqual(result['timing']['sequence'], 0)
        self.assertEqual(result['self_controller_object_key'], self.contract['self_controller_object_key'])
        self.assertNotIn('address', json.dumps(result))

    def test_dynamic_category_and_irrelevant_flags_do_not_require_constant_guard(self):
        frame = copy.deepcopy(self.frame)
        frame['fields']['category_1']['value'] = 128 | (1 << 15)
        self.assertEqual(self.rows(frame)[1]['relative_allegiance_candidate'], 'enemy')
        self.assertEqual(self.rows()[1]['relative_allegiance_candidate'], 'friendly')

    def test_no_roster_review_yields_categories_without_allegiance(self):
        self.contract['roster_review_sha256'] = None
        self.projector = self.make()
        self.assertEqual(self.rows()[1]['raw_category_candidate'], 0)
        self.assertIsNone(self.rows()[1]['team_candidate'])
        self.assertIsNone(self.rows()[1]['relative_allegiance_candidate'])

    def test_mode_special_and_ambiguous_values_stay_null(self):
        for value, reason in ((8 | 4, 'unsupported_mode_bits'), (2048, 'unsupported_category'),
                              (0, 'absent_or_ambiguous_category'), (8 | 128, 'absent_or_ambiguous_category')):
            with self.subTest(value=value):
                frame = copy.deepcopy(self.frame)
                frame['fields']['category_1']['value'] = value
                row = self.rows(frame)[1]
                self.assertEqual(row['status'], 'unknown')
                self.assertEqual(row['reason'], reason)
                self.assertIsNone(row['raw_category_candidate'])
                self.assertIsNone(row['relative_allegiance_candidate'])

    def test_gap_never_carries_identity_semantics_or_values(self):
        for row in self.rows(gap=True):
            self.assertEqual(row['reason'], 'gap_before_frame')
            self.assertIsNone(row['raw_category_candidate'])
            self.assertIsNone(row['relative_allegiance_candidate'])
            self.assertEqual(row['evidence'], [])

    def test_recording_interval_does_not_admit_later_profile_reuse(self):
        for field, value in [('sequence', 4), ('start_ticks', 0), ('end_ticks', 401)]:
            frame = copy.deepcopy(self.frame)
            frame[field] = value
            self.assertTrue(all(r['reason'] == 'unvalidated_recording_interval' for r in self.rows(frame)))

    def test_profile_target_and_brackets_fail_closed(self):
        for case in ('profile', 'target', 'before', 'after', 'field_guard_ids', 'field_time'):
            frame = copy.deepcopy(self.frame)
            if case == 'profile': frame['profile_sha256'] = '00' * 32
            elif case == 'target': frame['target']['creation_file_time'] += 1
            elif case in ('before', 'after'): frame['guards_' + case][0]['ok'] = False
            elif case == 'field_guard_ids': frame['fields']['category_1']['guard_ids'] = []
            else: frame['fields']['category_1']['read_end_ticks'] = 101
            rows = self.rows(frame)
            self.assertIsNone(rows[1]['raw_category_candidate'], case)
            self.assertIsNone(rows[1]['relative_allegiance_candidate'], case)

    def test_unknown_self_cannot_label_others_relative_to_previous_self(self):
        frame = copy.deepcopy(self.frame)
        frame['fields']['category_0']['status'] = 'unknown'
        self.assertIsNone(self.rows(frame)[1]['relative_allegiance_candidate'])
        self.assertEqual(self.rows(frame)[1]['reason'], 'self_relation_unknown')
        self.assertEqual(self.rows()[1]['relative_allegiance_candidate'], 'friendly')

    def test_category_body_join_uses_full_key_not_prefix_order(self):
        self.contract['bindings'].reverse()
        self.projector = self.make()
        self.assertEqual([r['relative_allegiance_candidate'] for r in self.rows()], ['self', 'friendly', 'enemy'])
        self.contract['bindings'][1]['body_creation_key_field'] = 'controller_0002_body_0000_manager_key_candidate_i32'
        self.projector = self.make()
        self.assertIsNone(self.rows()[1]['raw_category_candidate'])

    def test_duplicate_category_body_is_ambiguous(self):
        self.contract['bindings'][1]['body_handle_field'] = self.contract['bindings'][0]['body_handle_field']
        self.contract['bindings'][1]['body_creation_key_field'] = self.contract['bindings'][0]['body_creation_key_field']
        self.projector = self.make()
        self.assertEqual(self.rows()[0]['reason'], 'ambiguous_category_body')
        self.assertIsNone(self.rows()[0]['raw_category_candidate'])

    def test_source_artifacts_and_explicit_build_are_required(self):
        self.artifacts[self.contract['native_review_sha256']] += b' '
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'artifact_hash'):
            self.make()
        self.setUp()
        self.contract['build_sha256'] = '00' * 32
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'contract_build'):
            self.make()

    def test_unknown_mode_and_conflicting_mapping_rejected(self):
        self.roster['mode_id'] = 'another-mode'
        self.changed_review('roster', self.roster)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'roster_review'):
            self.make()
        self.setUp()
        self.roster['category_teams'].append(dict(category=0, team='green'))
        self.changed_review('roster', self.roster)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'conflicting_team'):
            self.make()

    def test_guarded_unlinked_and_zero_override_conditions_are_not_assertions_only(self):
        for case in ('unguarded', 'positive', 'partial', 'missing', 'missing_dependency'):
            self.setUp()
            condition = self.contract['bindings'][0]['conditions'][1]
            if case == 'unguarded': condition['address'] = 0x8000
            elif case == 'positive': condition['equals'] = 1
            elif case == 'partial': condition['mask'] = 1
            elif case == 'missing': self.contract['bindings'][0]['conditions'].pop()
            else: self.contract['bindings'][0]['required_guard_ids'].pop()
            with self.assertRaises(InvalidCategoryEvidence, msg=case):
                self.make()

    def test_nonzero_override_and_present_linked_owner_in_profile_rejected(self):
        for guard_index in (-1, -2):
            self.setUp()
            self.profile['guards'][guard_index]['bytes_hex'] = ('01000000' if guard_index == -1 else '0002000000000000')
            self.contract['profile_sha256'] = sha(raw(self.profile))
            manifest = json.loads(self.artifacts[self.contract['recording_manifest_sha256']])
            manifest['profile_sha256'] = self.contract['profile_sha256']
            mb = raw(manifest); self.artifacts[sha(mb)] = mb; self.contract['recording_manifest_sha256'] = sha(mb)
            with self.assertRaisesRegex(InvalidCategoryEvidence, 'unsupported_route_condition'):
                self.make()

    def test_roster_roles_and_native_category_partition_must_agree(self):
        for case in ('friendly_opposing', 'enemy_equal', 'duplicate_self', 'self_as_enemy', 'merged_teams'):
            with self.subTest(case=case):
                self.setUp()
                anchors = self.roster['anchors']
                if case == 'friendly_opposing':
                    anchors[1].update(category=1, team='red')
                elif case == 'enemy_equal':
                    anchors[2].update(category=0, team='blue')
                elif case == 'duplicate_self':
                    duplicate = copy.deepcopy(anchors[0])
                    duplicate['body_object_key'] = 'body:' + 'de' * 32
                    anchors.append(duplicate)
                elif case == 'self_as_enemy':
                    anchors[2]['controller_object_key'] = anchors[0]['controller_object_key']
                else:
                    self.roster['category_teams'][1]['team'] = 'blue'
                    anchors[2]['team'] = 'blue'
                self.changed_review('roster', self.roster)
                with self.assertRaises(InvalidCategoryEvidence):
                    self.make()

    def test_invalid_recording_scope_and_source_pins_rejected(self):
        for case in ('hash', 'interval', 'source'):
            self.setUp()
            if case == 'hash': self.contract['recording_manifest_sha256'] = '00' * 32
            elif case == 'interval': self.contract['frame_scope']['end_ticks'] = 502
            else: self.contract['source']['evidence_sha256'] = 'not-a-hash'
            with self.assertRaises(InvalidCategoryEvidence, msg=case):
                self.make()

    def test_evidence_and_contract_are_not_mutated_by_projection(self):
        before = copy.deepcopy(self.frame)
        self.projector.project(self.frame)
        self.assertEqual(before, self.frame)


if __name__ == '__main__':
    unittest.main()
