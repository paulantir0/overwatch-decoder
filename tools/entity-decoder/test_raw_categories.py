"""Synthetic source pins, per-half guards and current-body boundaries."""
import copy
import unittest

from categories import InvalidCategoryEvidence
from raw_categories import GuardedRawCategories
from test_categories import category_fixture, raw, sha
from test_relations import prepare, change_word


def raw_fixture():
    profile, values, _, old, artifacts, native, _ = category_fixture()
    for index in range(3):
        low = next(f for f in profile['fields'] if f['name'] == f'category_{index}')
        low['address'] = 0x6000 + index * 8
        name = f'category_high_{index}'
        profile['fields'].append(dict(name=name, address=low['address'] + 4, type='i32'))
        values[name] = -1
    decoder, frame = prepare(profile, values)
    def add(value):
        data = value if isinstance(value, bytes) else raw(value)
        artifacts[sha(data)] = data
        return sha(data)
    source = dict(recipe_sha256=add(b'synthetic recipe'), evidence_sha256=add(b'synthetic acquisition evidence'))
    manifest = dict(schema='overwatch-decoder.acquisition-result/1', complete=True, error=None,
                    target=decoder.target, profile_sha256=decoder.hash, **source)
    bindings = []
    for index, binding in enumerate(old['bindings']):
        b = copy.deepcopy(binding)
        b['flags_low_field'] = b.pop('flags_field')
        b['flags_high_field'] = f'category_high_{index}'
        bindings.append(b)
    contract = dict(schema='overwatch-decoder.raw-category-contract/1', profile_sha256=decoder.hash,
                    target=decoder.target, build_sha256=decoder.target['executable_sha256'],
                    source=source, acquisition_manifest_sha256=add(manifest),
                    native_review_sha256=old['native_review_sha256'], bindings=bindings)
    return profile, values, frame, contract, artifacts, manifest, native


class RawCategoryTests(unittest.TestCase):
    def setUp(self):
        (self.profile, self.values, self.frame, self.contract, self.artifacts,
         self.manifest, self.native) = raw_fixture()
        self.projector = self.make()

    def make(self):
        return GuardedRawCategories(raw(self.profile), raw(self.contract), self.artifacts)

    def rows(self, frame=None, **kwargs):
        return self.projector.project(self.frame if frame is None else frame, **kwargs)['rows']

    def replace_artifact(self, pin, value):
        data = raw(value)
        self.artifacts[sha(data)] = data
        self.contract[pin] = sha(data)

    def test_raw_halves_exact_current_keys_no_roster_or_relative_semantics(self):
        result = self.projector.project(self.frame)
        self.assertEqual([r['raw_category_candidate'] for r in result['rows']], [0, 0, 1])
        self.assertEqual(result['source_evidence']['recipe_sha256'], self.contract['source']['recipe_sha256'])
        for row in result['rows']:
            self.assertEqual(row['raw_status'], 'observed')
            self.assertEqual(row['raw_flags_candidate']['high_u32'], 0xffffffff)
            self.assertTrue(row['raw_flags_candidate']['assembled_u64_hex'].startswith('0xffffffff'))
            self.assertEqual(len(row['evidence']), 4)
            self.assertIsNone(row['team_candidate'])
            self.assertIsNone(row['relative_allegiance_candidate'])
            self.assertFalse(row['atomic'])
            self.assertFalse(row['public_state_eligible'])
        self.assertNotIn('address', raw(result).decode())
        self.assertFalse(result['durability_verified'])

    def test_sequential_halves_keep_distinct_brackets(self):
        self.frame['fields']['category_high_0'].update(read_start_ticks=41, read_end_ticks=44)
        row = self.rows()[0]
        self.assertEqual(row['evidence'][-1]['read_end_ticks'], 44)
        self.assertEqual(row['evidence'][-2]['read_end_ticks'], 40)

    def test_dynamic_flags_and_unsupported_branches_preserve_raw_only(self):
        for value, reason in ((12, 'unsupported_mode_bits'), (2048, 'unsupported_category'),
                              (0, 'absent_or_ambiguous_category'), (136, 'absent_or_ambiguous_category')):
            with self.subTest(value=value):
                frame = copy.deepcopy(self.frame)
                frame['fields']['category_0']['value'] = value
                row = self.rows(frame)[0]
                self.assertEqual(row['raw_flags_candidate']['low_u32'], value)
                self.assertEqual(row['raw_status'], 'observed')
                self.assertEqual(row['reason'], reason)
                self.assertIsNone(row['raw_category_candidate'])
        self.frame['fields']['category_0']['value'] = 128
        self.assertEqual(self.rows()[0]['raw_category_candidate'], 1)

    def test_neither_half_can_lose_conditions_or_read_guards(self):
        for side in ('category_0', 'category_high_0'):
            for mutation in ('ids', 'read', 'unknown'):
                frame = copy.deepcopy(self.frame)
                if mutation == 'ids': frame['fields'][side]['guard_ids'] = []
                if mutation == 'read': frame['fields'][side]['read_end_ticks'] = 81
                if mutation == 'unknown': frame['fields'][side]['status'] = 'unknown'
                row = self.rows(frame)[0]
                self.assertIsNone(row['raw_flags_candidate'], (side, mutation))
        for phase in ('before', 'after'):
            frame = copy.deepcopy(self.frame)
            frame['guards_' + phase][-1]['ok'] = False
            self.assertTrue(all(r['raw_flags_candidate'] is None for r in self.rows(frame)))

    def test_gap_body_absence_and_external_stale_projection_never_carry(self):
        base = self.projector.relations.project(self.frame)
        for kwargs in (dict(gap=True), dict(relation_projection={})):
            self.assertTrue(all(r['raw_flags_candidate'] is None for r in self.rows(**kwargs)))
        self.assertEqual(self.rows(relation_projection=base)[0]['status'], 'observed')
        frame = copy.deepcopy(self.frame)
        frame['skipped_intervals_before'] = 2
        self.assertTrue(all(r['reason'] == 'gap_before_frame' for r in self.rows(frame)))
        frame = copy.deepcopy(self.frame)
        frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        row = self.rows(frame)[0]
        self.assertIsNotNone(row['controller_object_key'])
        self.assertIsNone(row['body_object_key'])
        self.assertIsNone(row['raw_flags_candidate'])
        self.assertEqual(self.rows()[0]['status'], 'observed')

    def test_fresh_body_requires_fresh_profile_and_contract(self):
        before = self.rows()[0]
        for index, value in ((2, 0x80000100), (3, 0x80000101), (4, 0x80000100)):
            change_word(self.profile, self.values, index, value)
        decoder, frame = prepare(self.profile, self.values)
        self.assertTrue(all(r['raw_flags_candidate'] is None for r in self.rows(frame)))
        self.contract['profile_sha256'] = decoder.hash
        self.manifest['profile_sha256'] = decoder.hash
        self.replace_artifact('acquisition_manifest_sha256', self.manifest)
        self.projector = self.make()
        after = self.rows(frame)[0]
        self.assertEqual(before['controller_object_key'], after['controller_object_key'])
        self.assertNotEqual(before['body_object_key'], after['body_object_key'])
        self.assertEqual(after['status'], 'observed')

    def test_source_build_recipe_evidence_and_manifest_pins(self):
        for kind in ('target', 'build', 'recipe', 'evidence', 'manifest', 'profile'):
            with self.subTest(kind=kind):
                self.setUp()
                if kind == 'target': self.contract['target'] = dict(self.contract['target'], pid=999)
                if kind == 'build': self.contract['build_sha256'] = '00' * 32
                if kind == 'profile': self.contract['profile_sha256'] = '00' * 32
                if kind in ('recipe', 'evidence'):
                    self.artifacts[self.contract['source'][kind + '_sha256']] += b'changed'
                if kind == 'manifest':
                    self.manifest['complete'] = False
                    self.replace_artifact('acquisition_manifest_sha256', self.manifest)
                with self.assertRaises(InvalidCategoryEvidence): self.make()

    def test_route_conditions_and_both_halves_dependencies_required(self):
        for case in ('positive', 'missing', 'high', 'mask'):
            with self.subTest(case=case):
                self.setUp()
                binding = self.contract['bindings'][0]
                if case == 'positive': binding['conditions'][0]['equals'] = 1
                if case == 'missing': binding['conditions'].pop()
                if case == 'mask': binding['conditions'][1]['mask'] = 1
                if case == 'high':
                    # Global dependencies cannot be removed per-field. Instead
                    # require a real local guard present only on the low half.
                    low = next(f for f in self.profile['fields'] if f['name'] == 'category_0')
                    low['guards'] = [dict(address=0x7770, bytes_hex='00')]
                    decoder, _ = prepare(self.profile, self.values)
                    binding['required_guard_ids'].append(len(decoder.guards) - 1)
                    self.contract['profile_sha256'] = decoder.hash
                    self.manifest['profile_sha256'] = decoder.hash
                    self.replace_artifact('acquisition_manifest_sha256', self.manifest)
                with self.assertRaises(InvalidCategoryEvidence): self.make()

    def test_ambiguous_bindings_and_manual_semantics_rejected(self):
        self.contract['bindings'].append(copy.deepcopy(self.contract['bindings'][0]))
        with self.assertRaises(InvalidCategoryEvidence): self.make()
        self.setUp()
        self.contract['self_controller_object_key'] = 'controller:' + '00' * 32
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'roster_semantics_not_raw'): self.make()

    def test_empty_binding_epoch_is_explicit_unknown_not_old_value(self):
        self.contract['bindings'] = []
        self.projector = self.make()
        self.assertTrue(all(r['reason'] == 'category_body_binding_missing' for r in self.rows()))

    def test_explicit_anchor_prefix_uses_own_full_guarded_relation(self):
        mapping = {}
        for field in self.profile['fields']:
            name = field['name']
            if name.startswith('controller_0002_'):
                mapping[name] = name.replace('controller_0002', 'context_anchor_0000')
                field['name'] = mapping[name]
        self.values = {mapping.get(k, k): v for k, v in self.values.items()}
        binding = self.contract['bindings'][2]
        for k in ('body_handle_field', 'body_creation_key_field'):
            binding[k] = mapping[binding[k]]
        self.contract['additional_relation_prefixes'] = ['context_anchor_0000']
        decoder, frame = prepare(self.profile, self.values)
        self.contract['profile_sha256'] = self.manifest['profile_sha256'] = decoder.hash
        self.replace_artifact('acquisition_manifest_sha256', self.manifest)
        self.projector = self.make()
        rows = self.rows(frame)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[-1]['controller_prefix'], 'context_anchor_0000')
        self.assertEqual(rows[-1]['raw_category_candidate'], 1)
        frame['fields'][mapping['controller_0002_part51_0000_body_key_candidate_i32']]['status'] = 'unknown'
        self.assertIsNone(self.rows(frame)[-1]['raw_flags_candidate'])
        self.assertIsNotNone(self.rows(frame)[-1]['controller_object_key'])

    def test_anchor_cannot_alias_an_existing_prefix_or_bypass_duplicate_handles(self):
        self.contract['additional_relation_prefixes'] = ['controller_0000']
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'additional_relation_prefixes'): self.make()
        self.setUp()
        # A separate declaration with the same controller word must invalidate
        # both relations, even though every individual word is guarded.
        change_word(self.profile, self.values, 5, 0x80000001)
        decoder, frame = prepare(self.profile, self.values)
        self.contract['profile_sha256'] = self.manifest['profile_sha256'] = decoder.hash
        self.replace_artifact('acquisition_manifest_sha256', self.manifest)
        self.projector = self.make()
        self.assertTrue(all(r['raw_flags_candidate'] is None for r in self.rows(frame)[:2]))

    def test_native_review_and_transport_mismatch_fail_closed(self):
        self.native['build_sha256'] = '00' * 32
        self.replace_artifact('native_review_sha256', self.native)
        with self.assertRaises(InvalidCategoryEvidence): self.make()
        for key, value in (('profile_sha256', '00' * 32), ('source', 'other')):
            frame = copy.deepcopy(self.frame)
            frame[key] = value
            self.assertTrue(all(r['raw_flags_candidate'] is None for r in self.rows(frame)))


if __name__ == '__main__':
    unittest.main()
