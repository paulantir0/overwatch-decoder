"""Complete synthetic acquisitions exercise identity-safe subset projection."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from controller_subset_projection import policy, prepare
from forward_owner_relations import build_forward_owner_contract, GuardedForwardOwners
from plan_live_roster import encoded, verified_census
from runtime_producer import build_present_health_contracts
from test_runtime_producer import health_acquisition


def repin(root, profile, *, remove_guard_check=False):
    profile_raw = encoded(profile)
    (root/'profile.json').write_bytes(profile_raw)
    events = [json.loads(line) for line in (root/'evidence.jsonl').read_bytes().splitlines()]
    if remove_guard_check:
        events.pop(next(i for i, e in enumerate(events) if e['kind'] == 'guard_check'))
    events[-1].update(profile_sha256=hashlib.sha256(profile_raw).hexdigest(), fields=len(profile['fields']))
    evidence = b''.join((json.dumps(e, separators=(',', ':'))+'\n').encode() for e in events)
    (root/'evidence.jsonl').write_bytes(evidence)
    manifest = json.loads((root/'manifest.json').read_bytes())
    manifest.update(profile_sha256=hashlib.sha256(profile_raw).hexdigest(), fields=len(profile['fields']),
                    evidence_sha256=hashlib.sha256(evidence).hexdigest())
    (root/'manifest.json').write_bytes(encoded(manifest))


class ControllerSubsetProjection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile, layout = health_acquisition(self.root)
        self.census = verified_census(self.root)
        self.keys = [a['controller_object_key'] for a in self.census['controllers']]
        self.config = dict(observation_mode='raw-candidates', allow_controller_subsets=True,
            controller_subset_policy=dict(expected_controller_keys=sorted(self.keys),
                expected_primary_controller_keys=sorted(self.keys), required_context_controller_key=self.keys[0]),
            target=self.profile['target'], recipe=str(self.root/'recipe.json'),
            recipe_sha256=self.census['source']['recipe_sha256'], context_composer='fixture-context.py')
        self.asset('health_layout', json.loads(layout))
        self.epoch = self.root/'epoch'; self.epoch.mkdir()

    def asset(self, name, value):
        path = self.root/(name+'.json'); data = encoded(value); path.write_bytes(data)
        self.config[name], self.config[name+'_sha256'] = str(path), hashlib.sha256(data).hexdigest()

    def retain(self, index, *, compact=False):
        profile = copy.deepcopy(self.profile)
        prefix = f'controller_{index:04d}'
        profile['fields'] = [f for f in profile['fields'] if f['name'].startswith(prefix+'_')]
        if compact:
            for field in profile['fields']:
                field['name'] = field['name'].replace(prefix, 'controller_0000', 1)
        repin(self.root, profile)
        return profile

    def test_each_survivor_keeps_its_original_full_key_after_ordinal_compaction(self):
        for index in (0, 1):
            with self.subTest(index=index):
                self.retain(index, compact=True)
                epoch = self.root/f'epoch-{index}'; epoch.mkdir()
                with self.assertRaisesRegex(ValueError, 'health_layout_exact_controller_prefixes'):
                    build_present_health_contracts(self.root, Path(self.config['health_layout']).read_bytes(),
                                                   recipe_path=self.config['recipe'])
                config = prepare(self.config, self.root, epoch)
                result = build_present_health_contracts(self.root, Path(config['health_layout']).read_bytes(),
                                                        recipe_path=config['recipe'])
                self.assertEqual(len(result['contracts']), 1)
                receipt = json.loads((epoch/'controller-subset-projection.json').read_bytes())
                self.assertEqual(receipt['profile_bindings'], [dict(prefix='controller_0000', controller_object_key=self.keys[index])])
                self.assertEqual(receipt['omitted_controller_keys'], [self.keys[1-index]])
                self.assertFalse(receipt['previous_contracts_carried'])
                self.assertTrue(receipt['context_requires_independent_admission'])
                self.assertEqual(hashlib.sha256(Path(self.config['health_layout']).read_bytes()).hexdigest(),
                                 self.config['health_layout_sha256'])

    def test_new_foreign_full_key_is_rejected_before_materialization(self):
        self.retain(1, compact=True)
        self.config['controller_subset_policy']['expected_controller_keys'] = [self.keys[0]]
        self.config['controller_subset_policy']['expected_primary_controller_keys'] = [self.keys[0]]
        with self.assertRaisesRegex(ValueError, 'controller_subset_fresh_identity_scope'):
            prepare(self.config, self.root, self.epoch)
        self.assertEqual(list(self.epoch.iterdir()), [])

    def test_missing_guard_check_is_not_subset_permission(self):
        profile = self.retain(1, compact=True)
        repin(self.root, profile, remove_guard_check=True)
        with self.assertRaisesRegex(ValueError, 'unchecked_profile_guard'):
            prepare(self.config, self.root, self.epoch)
        self.assertEqual(list(self.epoch.iterdir()), [])

    def test_partial_controller_declarations_are_not_treated_as_omitted(self):
        profile = self.retain(1, compact=True)
        # A surviving payload under a missing controller prefix is an error.
        profile['fields'].append(dict(name='controller_0001_body_0000_orphan', type='f32', address=0x6000))
        repin(self.root, profile)
        with self.assertRaisesRegex(ValueError, 'controller_subset_orphaned_fields'):
            prepare(self.config, self.root, self.epoch)

    def test_undeclared_partial_controller_prefix_is_not_silently_dropped(self):
        profile = self.retain(1, compact=True)
        original = next(f for f in profile['fields'] if f['name'].endswith('_manager_key_candidate_i32'))
        profile['fields'].append(dict(original, name='controller_0002_manager_key_candidate_i32'))
        repin(self.root, profile)
        with self.assertRaisesRegex(ValueError, 'controller_subset_profile_prefixes'):
            prepare(self.config, self.root, self.epoch)

    def test_zero_primary_subset_and_tampered_layout_reject(self):
        self.retain(1, compact=True)
        self.config['controller_subset_policy']['expected_primary_controller_keys'] = [self.keys[0]]
        with self.assertRaisesRegex(ValueError, 'controller_subset_fresh_identity_scope'):
            prepare(self.config, self.root, self.epoch)
        self.config['controller_subset_policy']['expected_primary_controller_keys'] = sorted(self.keys)
        Path(self.config['health_layout']).write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'controller_subset_asset_changed:health_layout'):
            prepare(self.config, self.root, self.epoch)

    def test_forward_contract_uses_fresh_survivor_identity_not_former_prefix_owner(self):
        bindings = []
        for index in (0, 1):
            p = f'controller_{index:04d}'
            bindings.append(dict(binding_id=f'actor{index}', owned_field_prefix=p+'_body_0000_',
                controller_handle_field=p+'_handle_candidate_i32', controller_key_field=p+'_manager_key_candidate_i32',
                reference_field=p+'_part51_0000_body_key_candidate_i32',
                owner_handle_field=p+'_body_0000_handle_candidate_i32', owner_key_field=p+'_body_0000_manager_key_candidate_i32'))
        self.asset('forward_owner_bindings', dict(schema='overwatch-decoder.forward-owner-binding-template/1',
            build_sha256=self.profile['target']['executable_sha256'], recipe_sha256=self.config['recipe_sha256'], bindings=bindings))
        self.retain(1, compact=True)
        config = prepare(self.config, self.root, self.epoch)
        contract, artifacts = build_forward_owner_contract(self.root, Path(config['forward_owner_bindings']).read_bytes())
        decoder = GuardedForwardOwners((self.root/'profile.json').read_bytes(), contract, artifacts)
        self.assertEqual(len(decoder.bindings), 1)
        words = [dict(address=w[0], value=w[1]) for w in decoder.bindings[0]['words'][:2]]
        self.assertEqual(decoder.relations._key('controller', words), self.keys[1])
        self.assertNotEqual(decoder.relations._key('controller', words), self.keys[0])

    def test_explicit_opt_in_and_strict_policy_types(self):
        untouched = {'observation_mode': 'raw-candidates'}
        self.assertIs(prepare(untouched, '/unused/acquisition', '/unused/epoch'), untouched)
        variants = [dict(allow_controller_subsets=1), dict(allow_controller_subsets=None),
                    dict(observation_mode='reviewed'), dict(include_health_candidates=False)]
        for change in variants:
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy(dict(self.config, **change))
        bad = copy.deepcopy(self.config); bad['controller_subset_policy']['expected_controller_keys'] *= 2
        with self.assertRaisesRegex(ValueError, 'controller_subset_policy_keys'): policy(bad)
        bad = copy.deepcopy(self.config); bad['allow_controller_subsets'] = False
        with self.assertRaisesRegex(ValueError, 'controller_subset_policy_without_opt_in'): policy(bad)

    def test_removed_controller_templates_do_not_disable_present_optional_owner_proofs(self):
        from test_optional_forward_owners import optional_source, config as forward_config
        from runtime_producer import forward_adapter_options
        profile, _, _, template = optional_source(self.root)
        self.config.update(forward_config(self.root, template))
        self.config['recipe_sha256'] = hashlib.sha256((self.root/'recipe.json').read_bytes()).hexdigest()
        normal = json.loads(Path(self.config['health_layout']).read_bytes())
        normal['recipe_sha256'] = self.config['recipe_sha256']
        self.asset('health_layout', normal)
        # Template storage prefixes are slots, not a claim that their former
        # controller is still present. Only controller0000 exists in this source.
        def second(value):
            if isinstance(value, str): return value.replace('controller_0000', 'controller_0001')
            if isinstance(value, list): return [second(v) for v in value]
            if isinstance(value, dict): return {k: second(v) for k, v in value.items()}
            return value
        bindings = json.loads(Path(self.config['forward_owner_bindings']).read_bytes())
        extra = second(bindings['bindings'])
        for row in extra: row['binding_id'] += '_second'
        bindings['bindings'] += extra; self.asset('forward_owner_bindings', bindings)
        layout = json.loads(Path(self.config['forward_owner_health_layout']).read_bytes())
        extra = second(layout['supported_forward_owners'])
        for row in extra: row['binding_id'] += '_second'
        layout['supported_forward_owners'] += extra
        layout['actor_prefixes'] += second(layout['actor_prefixes'])
        self.asset('forward_owner_health_layout', layout)
        category = json.loads(Path(self.config['forward_owner_category_template']).read_bytes())
        extra = second(category['bindings'])
        for row in extra: row['binding_id'] += '_second'
        category['bindings'] += extra; self.asset('forward_owner_category_template', category)
        config = prepare(self.config, self.root, self.epoch)
        options = forward_adapter_options(config, self.root, self.epoch)
        self.assertEqual(options['forward_owner_health_contracts'], [])
        result = json.loads(options['forward_owner_category_contract'].read_bytes())
        self.assertEqual(result['bindings'], [])
        self.assertEqual(result['acquisition_empty_bindings'], ['aux', 'alt'])
        contract = json.loads(options['forward_owner_contract'].read_bytes())
        self.assertEqual([b['binding_id'] for b in contract['bindings']], ['aux', 'alt'])
        # A valid optional template may cover only an omitted original actor.
        # It must not stop the independent surviving actor's projection.
        category['bindings'] = extra
        self.asset('forward_owner_category_template', category)
        second_epoch = self.root/'category-omitted'; second_epoch.mkdir()
        config = prepare(self.config, self.root, second_epoch)
        options = forward_adapter_options(config, self.root, second_epoch)
        self.assertNotIn('forward_owner_category_contract', options)
        self.assertEqual(options['forward_owner_health_contracts'], [])
        contract = json.loads(options['forward_owner_contract'].read_bytes())
        self.assertEqual([b['binding_id'] for b in contract['bindings']], ['aux', 'alt'])
        receipt = json.loads((second_epoch/'controller-subset-projection.json').read_bytes())
        self.assertEqual(receipt['unavailable_optional_projections']['forward_owner_category'],
            dict(reason='no_binding_in_acquired_controller_subset', omitted_binding_ids=['aux_second', 'alt_second']))

    def test_each_new_epoch_rechecks_assets_instead_of_reusing_previous_contracts(self):
        self.retain(1, compact=True)
        prepare(self.config, self.root, self.epoch)
        second = self.root/'second'; second.mkdir()
        Path(self.config['health_layout']).write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'controller_subset_asset_changed'):
            prepare(self.config, self.root, second)
        self.assertEqual(list(second.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
