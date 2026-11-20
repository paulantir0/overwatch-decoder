"""Saved-frame composition checks for paired health-ratio observations."""
import copy
import hashlib
import json
import unittest

from overwatch_decoder.health_ratio import InvalidRatioBinding, PoolRatioContract
from export_relations import InvalidRecording, project_frame
from test_relations import fixture, prepare


def raw(value):
    return json.dumps(value).encode()


class HealthRatioExportTests(unittest.TestCase):
    def setUp(self):
        profile, values = fixture(rows=2)
        prefix = 'controller_0000_body_0000_'
        scalar, pair = prefix + 'pool_0000_direct_candidate', prefix + 'pool_0000_paired'
        profile['fields'].extend([
            dict(name=scalar, type='f32', address=0x800c),
            dict(name=pair, type='f32x3', address=0x8004),
        ])
        profile['guards'].extend([
            dict(address=0x8000, bytes_hex='01000000'),
            dict(address=0x8020, bytes_hex='00000000'),
        ])
        values.update({scalar: 100, pair: [210, 200, 100]})
        self.relations, self.frame = prepare(profile, values)
        self.frame['fields'][scalar]['type'] = 'f32'
        self.frame['fields'][pair]['type'] = 'f32x3'
        self.pair = pair
        review = raw(dict(build_sha256=profile['target']['executable_sha256']))
        self.source = dict(profile_sha256=self.relations.hash, acquisition=dict(
            manifest_sha256='c'*64, recipe_sha256='d'*64, evidence_sha256='b'*64))
        descriptor = dict(schema='overwatch-decoder.private.actor-health-ratio-contract/1',
            algorithm='occupied_pool_ratio_f32', profile_sha256=self.relations.hash,
            build_sha256=profile['target']['executable_sha256'],
            native_review_sha256=hashlib.sha256(review).hexdigest(),
            source=self.source['acquisition'], health_contract=dict(
                actor_prefix=prefix, acquisition_evidence_sha256='b'*64, slots=[
                    dict(index=0, membership_address=0x8000, membership_u32=1,
                         field_name=scalar, scalar_address=0x800c),
                    dict(index=1, membership_address=0x8020, membership_u32=0,
                         field_name=None, scalar_address=None)]),
            paired_slots=[dict(pool_index=0, field_name=pair, numerator_component=2,
                               denominator_component=1, denominator_address=0x8008)])
        self.ratio = PoolRatioContract.from_profile(raw(profile), raw(descriptor), review)

    def project(self, *, gap=0, source=None, enabled=True):
        return project_frame(self.relations, self.frame,
            self.source if source is None else source, dict(complete=True), dict(skipped_slots=gap),
            health_ratio_contracts=(self.ratio,) if enabled else ())

    def test_opt_in_joins_only_current_body_and_preserves_other_fields(self):
        baseline = self.project(enabled=False)
        result = self.project()
        row, other = result['relations']
        ratio = row['health_ratio_candidate']
        self.assertEqual(ratio['native_ratio_candidate'], .5)
        self.assertEqual(ratio['body_object_key'], row['body_object_key'])
        self.assertIsNone(other['health_ratio_candidate'])
        self.assertEqual(result.pop('health_ratio_contract_sha256'), [self.ratio.contract_sha256])
        metadata = result.pop('health_ratio_projection')
        self.assertEqual(metadata['schema'], 'overwatch-decoder.health-ratio-projection/1')
        self.assertEqual(metadata['contracts'], [dict(
            contract_sha256=self.ratio.contract_sha256,
            native_review_sha256=self.ratio.native_review_sha256,
            membership_contract_sha256=self.ratio.storage.membership_sha256,
            actor_prefix=self.ratio.storage.actor_prefix, source=self.ratio.source,
            paired_slots=list(self.ratio.paired_slots), supplied_layout_slots=2)])
        self.assertNotIn('address', json.dumps(metadata))
        for relation in result['relations']:
            relation.pop('health_ratio_candidate')
        self.assertEqual(result, baseline)

    def test_gap_or_unobserved_pair_never_reuses_previous_value(self):
        self.assertIsNotNone(self.project()['relations'][0]['health_ratio_candidate'])
        self.assertIsNone(self.project(gap=1)['relations'][0]['health_ratio_candidate'])
        self.frame['fields'][self.pair].update(status='unknown', value=None)
        self.assertIsNone(self.project()['relations'][0]['health_ratio_candidate'])

    def test_lost_reciprocal_body_clears_ratio(self):
        self.frame['fields']['controller_0000_part51_0000_body_key_candidate_i32']['value'] += 1
        row = self.project()['relations'][0]
        self.assertIsNone(row['body_object_key'])
        self.assertIsNone(row['health_ratio_candidate'])

    def test_each_acquisition_pin_is_required_even_with_unchanged_profile(self):
        for key in ('profile_sha256', 'manifest_sha256', 'recipe_sha256', 'evidence_sha256'):
            source = copy.deepcopy(self.source)
            node = source if key == 'profile_sha256' else source['acquisition']
            node[key] = 'f'*64
            with self.subTest(key=key), self.assertRaisesRegex(InvalidRatioBinding, 'ratio_source_mismatch'):
                self.project(source=source)

    def test_duplicate_actor_contract_does_not_double_count(self):
        with self.assertRaisesRegex(InvalidRecording, 'duplicate_health_ratio_actor'):
            project_frame(self.relations, self.frame, self.source, dict(complete=True),
                          dict(skipped_slots=0), health_ratio_contracts=(self.ratio, self.ratio))


if __name__ == '__main__':
    unittest.main()
