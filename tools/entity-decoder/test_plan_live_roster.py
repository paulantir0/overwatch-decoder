import copy
import json
import tempfile
import unittest
from pathlib import Path

from plan_live_roster import InvalidPlan, digest, encoded, main, plan, verified_census

TARGET = dict(pid=42, creation_file_time=100, executable_sha256='a'*64,
              architecture='x64', image_name='fixture.exe')


def fixture(directory, count=5):
    """Synthetic native transcript; no application offsets or captured values."""
    recipe = dict(schema='overwatch-decoder.acquisition-recipe/1', target={k: TARGET[k] for k in
                  ('image_name', 'executable_sha256', 'architecture')}, stages=[dict(name='fixture', steps=[])])
    profile = dict(schema='overwatch-decoder.field-profile/1', target=TARGET.copy(), fields=[], guards=[])
    reads, checks = [], []
    for i in range(count):
        address = 4096 + i*32
        prefix = f'controller_{i:04d}'
        data = (i+10).to_bytes(4, 'little') + (i+100).to_bytes(4, 'little')
        profile['guards'].append(dict(address=address, bytes_hex=data.hex()))
        for offset, suffix in [(0, '_handle_candidate_i32'), (4, '_manager_key_candidate_i32')]:
            profile['fields'].append(dict(name=prefix+suffix, type='i32', address=address+offset))
        for offset in range(2):
            ident = len(reads)
            reads.append(dict(kind='read', id=ident, attempted=True, address=address,
                              requested_bytes=len(data), returned_bytes=len(data), error=None,
                              bytes_hex=data.hex(), read_start_ticks=1000+ident*10,
                              read_end_ticks=1001+ident*10))
        checks.append(dict(kind='guard_check', stage='final_guard_check', matches=True,
                           expected_read_id=2*i, actual_read_id=2*i+1, expected_offset=0))
    recipe_raw, profile_raw = encoded(recipe), encoded(profile)
    start = dict(schema='overwatch-decoder.acquisition-evidence/1', kind='start', target=TARGET.copy(),
                 recipe_sha256=digest(recipe_raw), revision='fixture', source_kind='native_process_memory',
                 monotonic_frequency=1000, monotonic_origin_ticks=900)
    terminal = dict(kind='profile_validated', profile_sha256=digest(profile_raw), fields=len(profile['fields']))
    evidence = b''.join(encoded(x).replace(b'\n', b'')+b'\n' for x in [start]+reads+checks+[terminal])
    manifest = dict(schema='overwatch-decoder.acquisition-result/1', complete=True, error=None, target=TARGET.copy(),
                    recipe_sha256=digest(recipe_raw), profile_sha256=digest(profile_raw),
                    evidence_sha256=digest(evidence), stages_completed=1, revision='fixture')
    for filename, raw in [('manifest.json', encoded(manifest)), ('profile.json', profile_raw),
                          ('recipe.json', recipe_raw), ('evidence.jsonl', evidence)]:
        (directory/filename).write_bytes(raw)
    base = copy.deepcopy(recipe)
    base['stages'][0]['steps'] = [dict(op='scan', name='candidates', count=64, steps=[dict(op='filter', test=['var', 'eligible'])]),
                                dict(op='require', test=['le', ['count', ['var', 'candidates']], 3])]
    base['guards'] = ['fixture_dependency']
    template = dict(schema='overwatch-decoder.roster-recipe-template/1', recipe=base,
                    selection=dict(scan_pointer='/stages/0/steps/0', maximum_controllers=3,
                                   full_handle_expression=['var', 'handle'], creation_key_expression=['var', 'key']))
    return encoded(template)


class RosterPlanningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.raw = fixture(self.root)
        self.census = verified_census(self.root, expected_target=TARGET)

    def planning(self, **kwargs):
        return plan(self.census, self.raw, template_sha256=digest(self.raw), partition_size=3, **kwargs)

    def mutate_evidence(self, edit):
        path = self.root/'evidence.jsonl'
        rows = [json.loads(l) for l in path.read_bytes().splitlines()]
        edit(rows)
        raw = b''.join(json.dumps(x).encode()+b'\n' for x in rows)
        path.write_bytes(raw)
        manifest = json.loads((self.root/'manifest.json').read_bytes())
        manifest['evidence_sha256'] = digest(raw)
        (self.root/'manifest.json').write_bytes(encoded(manifest))

    def test_deterministic_coverage_and_original_ast_preserved(self):
        result = self.planning()
        self.assertEqual(result, self.planning())
        self.assertEqual([len(p['controllers']) for p in result['partitions']], [3, 2])
        self.assertEqual(len(result['primary_controller_map']), 5)
        base = json.loads(self.raw)['recipe']
        for part in result['partitions']:
            recipe = json.loads(part['recipe_bytes'])
            steps = recipe['stages'][0]['steps']
            selected = steps[0]['steps'].pop()
            self.assertEqual(selected['op'], 'filter')
            self.assertEqual(steps.pop(1), dict(op='require', test=['eq', ['count', ['var', 'candidates']], len(part['controllers'])]))
            self.assertEqual(recipe, base)
        self.assertFalse(result['native_admission_verified'])
        self.assertFalse(result['public_state_eligible'])

    def test_anchor_repeated_without_double_primary(self):
        anchor = self.census['controllers'][-1]['controller_object_key']
        result = self.planning(anchor_controller_key=anchor)
        self.assertEqual(len(result['partitions']), 2)
        uses = [r for p in result['partitions'] for r in p['controllers'] if r['controller_object_key'] == anchor]
        self.assertEqual([x['observation_role'] for x in uses], ['primary', 'support'])
        self.assertEqual(len(result['primary_controller_map']), 5)
        with self.assertRaisesRegex(InvalidPlan, 'anchor_not_in_census'):
            self.planning(anchor_controller_key='controller:'+'b'*64)

    def test_process_epoch_and_hash_rejections(self):
        with self.assertRaisesRegex(InvalidPlan, 'expected_process_epoch'):
            verified_census(self.root, expected_target=dict(TARGET, creation_file_time=101))
        (self.root/'profile.json').write_bytes((self.root/'profile.json').read_bytes()+b' ')
        with self.assertRaisesRegex(InvalidPlan, 'source_hash'):
            verified_census(self.root)

    def test_missing_final_guard_even_with_rehashed_evidence(self):
        self.mutate_evidence(lambda rows: rows.pop(-2))
        with self.assertRaisesRegex(InvalidPlan, 'unchecked_profile_guard'):
            verified_census(self.root)

    def test_false_guard_claim_rejected(self):
        self.mutate_evidence(lambda rows: rows[2].update(bytes_hex='ff'*8))
        with self.assertRaisesRegex(InvalidPlan, 'final_guard_bytes'):
            verified_census(self.root)

    def test_failed_guard_and_fake_source_rejected(self):
        self.mutate_evidence(lambda rows: rows[-2].update(matches=False))
        with self.assertRaisesRegex(InvalidPlan, 'failed_census_guard'):
            verified_census(self.root)
        fixture(self.root)
        self.mutate_evidence(lambda rows: rows[0].update(source_kind='fixture'))
        with self.assertRaisesRegex(InvalidPlan, 'evidence_source'):
            verified_census(self.root)

    def test_duplicate_handles_rejected_with_valid_source_hashes(self):
        profile = json.loads((self.root/'profile.json').read_bytes())
        profile['guards'][1]['bytes_hex'] = profile['guards'][0]['bytes_hex']
        raw = encoded(profile)
        (self.root/'profile.json').write_bytes(raw)
        manifest = json.loads((self.root/'manifest.json').read_bytes())
        manifest['profile_sha256'] = digest(raw)
        (self.root/'manifest.json').write_bytes(encoded(manifest))
        def mutate(rows):
            rows[3]['bytes_hex'] = rows[1]['bytes_hex']
            rows[4]['bytes_hex'] = rows[1]['bytes_hex']
            rows[-1]['profile_sha256'] = digest(raw)
        self.mutate_evidence(mutate)
        with self.assertRaisesRegex(InvalidPlan, 'ambiguous_controller'):
            verified_census(self.root)

    def test_template_pin_build_pointer_and_budget(self):
        with self.assertRaisesRegex(InvalidPlan, 'template_hash'):
            plan(self.census, self.raw+b' ', template_sha256=digest(self.raw), partition_size=3)
        for mutation, reason in [(lambda t: t['recipe']['target'].update(executable_sha256='b'*64), 'template_target'),
                                 (lambda t: t['selection'].update(scan_pointer='/stages/0/steps/1'), 'selector_not_scan')]:
            template = json.loads(self.raw); mutation(template); raw = encoded(template)
            with self.assertRaisesRegex(InvalidPlan, reason):
                plan(self.census, raw, template_sha256=digest(raw), partition_size=3)
        with self.assertRaisesRegex(InvalidPlan, 'total_admission_budget'):
            self.planning(maximum_total_fields=128)
        with self.assertRaisesRegex(InvalidPlan, 'partition_bounds'):
            plan(self.census, self.raw, template_sha256=digest(self.raw), partition_size=4)

    def test_single_anchor_and_anchor_capacity(self):
        self.census['controllers'] = self.census['controllers'][:1]
        anchor = self.census['controllers'][0]['controller_object_key']
        result = plan(self.census, self.raw, template_sha256=digest(self.raw), partition_size=1, anchor_controller_key=anchor)
        self.assertEqual(len(result['partitions']), 1)
        self.census = verified_census(self.root)
        with self.assertRaisesRegex(InvalidPlan, 'anchor_consumes'):
            plan(self.census, self.raw, template_sha256=digest(self.raw), partition_size=1, anchor_controller_key=anchor)

    def test_cli_new_output_only(self):
        template = self.root/'template.json'; template.write_bytes(self.raw)
        target = self.root/'target.json'; target.write_bytes(encoded(TARGET))
        out = self.root/'planned'
        args = ['--census-acquisition', str(self.root), '--template', str(template), '--template-sha256', digest(self.raw),
                '--expected-target', str(target), '--partition-size', '3', '--output', str(out)]
        self.assertEqual(main(args), 0)
        result = json.loads((out/'plan.json').read_bytes())
        for part in result['partitions']:
            self.assertEqual(digest((out/part['recipe_file']).read_bytes()), part['recipe_sha256'])
        original = (out/'plan.json').read_bytes()
        with self.assertRaises(SystemExit):
            main(args)
        self.assertEqual((out/'plan.json').read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
