"""Ammunition adapter counterexamples: wrong epochs, joins and gap propagation."""
import copy
import unittest
from unittest.mock import patch

from ammunition_candidates import GuardedAmmunitionCandidates
from export_relations import InvalidRecording, project_frame
from test_ammunition_candidates import ammunition_fixture, raw


class AmmunitionExportTests(unittest.TestCase):
    def setUp(self):
        profile, _, self.frame, contract, artifacts, *_ = ammunition_fixture()
        self.ammo = GuardedAmmunitionCandidates(raw(profile), raw(contract), artifacts)
        self.relations = self.ammo.relations
        self.source = dict(profile_sha256=self.relations.hash, acquisition=dict(
            manifest_sha256=self.ammo.acquisition_manifest_sha256, **self.ammo.source))

    def project(self, *, source=None, gap=0, enabled=True):
        return project_frame(self.relations, self.frame,
            self.source if source is None else source, {'complete': True}, {'skipped_slots': gap},
            ammunition_projector=self.ammo if enabled else None)

    def test_opt_in_preserves_existing_fields_and_evidence_pointer(self):
        baseline = self.project(enabled=False)
        result = self.project()
        row = result['relations'][0]
        self.assertEqual(row['ammunition_candidate']['value'], 40)
        self.assertEqual(row['ammunition_evidence_ref'], '/ammunition_projection/rows/0')
        evidence = result['ammunition_projection']['rows'][0]
        self.assertEqual(evidence['controller_object_key'], row['controller_object_key'])
        self.assertEqual(evidence['body_object_key'], row['body_object_key'])
        self.assertEqual(len(evidence['evidence']), 7)
        result.pop('ammunition_projection')
        for row in result['relations']:
            for key in ('ammunition_candidate', 'ammunition_evidence_ref', 'ammunition_reason'):
                row.pop(key)
        self.assertEqual(result, baseline)

    def test_cache_qualification_survives_and_gap_clears_value(self):
        self.frame['fields']['expression_count']['value'] = 1
        row = self.project()['relations'][0]
        self.assertEqual(row['ammunition_candidate']['value'], 12)
        self.assertEqual(row['ammunition_candidate']['freshness'], 'sampled_cache_not_recomputed')
        result = self.project(gap=1)
        row = result['relations'][0]
        self.assertIsNone(row['ammunition_candidate'])
        self.assertEqual(row['ammunition_reason'], 'gap_before_frame')
        self.assertIsNone(result['ammunition_projection']['rows'][0]['is_firing'])
        self.assertIsNone(result['ammunition_projection']['rows'][0]['reloading'])

    def test_wrong_acquisition_or_profile_rejected(self):
        for key in ('profile_sha256', 'manifest_sha256', 'recipe_sha256', 'evidence_sha256'):
            source = copy.deepcopy(self.source)
            node = source if key == 'profile_sha256' else source['acquisition']
            node[key] = 'f' * 64
            with self.subTest(key=key), self.assertRaisesRegex(InvalidRecording, 'ammunition_acquisition_mismatch'):
                self.project(source=source)

    def test_foreign_controller_or_body_never_joins_by_other_key(self):
        valid = self.ammo.project(self.frame)
        for key in ('controller_object_key', 'body_object_key'):
            value = copy.deepcopy(valid)
            value['rows'][0][key] = ('controller:' if key.startswith('controller') else 'body:') + 'f' * 64
            with patch.object(self.ammo, 'project', return_value=value):
                row = self.project()['relations'][0]
                self.assertIsNone(row['ammunition_candidate'])
                self.assertIsNone(row['ammunition_evidence_ref'])

    def test_projection_timing_and_contract_must_match(self):
        valid = self.ammo.project(self.frame)
        for kind in ('timing', 'contract', 'eligibility'):
            value = copy.deepcopy(valid)
            if kind == 'timing': value['timing']['start_ticks'] += 1
            if kind == 'contract': value['contract_sha256'] = 'f' * 64
            if kind == 'eligibility': value['public_state_eligible'] = True
            with patch.object(self.ammo, 'project', return_value=value):
                with self.assertRaisesRegex(InvalidRecording, 'ammunition_projection_source_mismatch'):
                    self.project()

    def test_duplicate_actor_result_and_invented_firing_rejected(self):
        value = self.ammo.project(self.frame)
        value['rows'].append(copy.deepcopy(value['rows'][0]))
        with patch.object(self.ammo, 'project', return_value=value):
            with self.assertRaisesRegex(InvalidRecording, 'ambiguous_ammunition_join'):
                self.project()
        value = self.ammo.project(self.frame)
        value['rows'][0]['is_firing'] = True
        with patch.object(self.ammo, 'project', return_value=value):
            with self.assertRaisesRegex(InvalidRecording, 'unsupported_ammunition_semantics'):
                self.project()


if __name__ == '__main__':
    unittest.main()
