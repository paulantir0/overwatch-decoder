"""Synthetic source/identity failures; private runtime evidence stays outside Git."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from forward_owner_relations import (GuardedForwardOwners, InvalidForwardOwnerEvidence,
                                     build_forward_owner_contract)
from test_relations import fixture, prepare, change_word


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def source_fixture(count=1, mutate=None):
    profile, values = fixture(count)
    for field in profile['fields']:
        old = field['name']
        field['name'] = old.replace('_body_0000_', '_aux_0000_')
        values[field['name']] = values.pop(old)
    for i in range(count):
        profile['fields'].append(dict(name=f'controller_{i:04}_aux_0000_scalar',
                                      type='f32', address=0x8000+i*16))
    if mutate:
        mutate(profile, values)
    relations, frame = prepare(profile, values)
    for field in profile['fields']:
        if field['type'] == 'f32':
            frame['fields'][field['name']] = dict(type='f32', status='observed', value=13.5,
                read_start_ticks=35, read_end_ticks=45, guard_ids=relations.guard_ids[field['name']])
    pr = raw(profile)
    # prepare uses ordinary json.dumps; preserve its exact profile digest.
    pr = json.dumps(profile).encode()
    recipe = dict(schema='overwatch-decoder.acquisition-recipe/1', target={k: profile['target'][k]
                  for k in ('image_name', 'architecture', 'executable_sha256')}, stages=[dict(name='fixture')])
    rr = raw(recipe)
    events = [dict(schema='overwatch-decoder.acquisition-evidence/1', kind='start', source_kind='native_process_memory',
                   target=profile['target'], recipe_sha256=sha(rr), revision='fixture')]
    for i, guard in enumerate(relations.guards):
        width = len(bytes.fromhex(guard['bytes_hex']))
        for j in range(2):
            events.append(dict(kind='read', id=2*i+j, attempted=True, error=None,
                               address=guard['address'], requested_bytes=width, returned_bytes=width,
                               bytes_hex=guard['bytes_hex'], read_start_ticks=2*j, read_end_ticks=2*j+1))
        events.append(dict(kind='guard_check', stage='final_guard_check', matches=True,
                           expected_read_id=2*i, actual_read_id=2*i+1, expected_offset=0))
    events.append(dict(kind='profile_validated', profile_sha256=sha(pr), fields=len(profile['fields'])))
    er = b''.join(raw(x) for x in events)
    manifest = dict(schema='overwatch-decoder.acquisition-result/1', complete=True, error=None, revision='fixture',
                    target=profile['target'], stages_completed=1, profile_sha256=sha(pr),
                    recipe_sha256=sha(rr), evidence_sha256=sha(er))
    mr = raw(manifest)
    bindings = []
    for i in range(count):
        p = f'controller_{i:04}'
        bindings.append(dict(binding_id=f'actor{i}', owned_field_prefix=p+'_aux_0000_',
            controller_handle_field=p+'_handle_candidate_i32', controller_key_field=p+'_manager_key_candidate_i32',
            reference_field=p+'_part51_0000_body_key_candidate_i32',
            owner_handle_field=p+'_aux_0000_handle_candidate_i32', owner_key_field=p+'_aux_0000_manager_key_candidate_i32'))
    tr = raw(dict(schema='overwatch-decoder.forward-owner-binding-template/1', build_sha256=profile['target']['executable_sha256'],
                  recipe_sha256=sha(rr), bindings=bindings))
    cr = raw(dict(schema='overwatch-decoder.forward-owner-contract/1', target=profile['target'],
                  profile_sha256=sha(pr), build_sha256=profile['target']['executable_sha256'],
                  source=dict(recipe_sha256=sha(rr), evidence_sha256=sha(er)),
                  acquisition_manifest_sha256=sha(mr), binding_template_sha256=sha(tr), bindings=bindings))
    artifacts = {sha(x): x for x in (rr, er, mr, tr)}
    return pr, cr, artifacts, frame


class ForwardOwnerTests(unittest.TestCase):
    def setUp(self):
        self.pr, self.cr, self.artifacts, self.frame = source_fixture()
        self.decoder = GuardedForwardOwners(self.pr, self.cr, self.artifacts)

    def row(self, frame=None):
        return self.decoder.project(self.frame if frame is None else frame)['relations'][0]

    def test_observed_preserves_controller_and_distinct_owner(self):
        row = self.row()
        self.assertEqual(row['relation_status'], 'observed')
        self.assertTrue(row['forward_owner_object_key'].startswith('owner:'))
        ordinary = self.decoder.relations.project(self.frame)['relations'][0]
        self.assertEqual(row['controller_object_key'], ordinary['controller_object_key'])
        self.assertNotIn('body_object_key', row)
        self.assertIsNone(row['current_displayed_body'])
        self.assertEqual(row['owned_fields']['controller_0000_aux_0000_scalar']['value'], 13.5)
        self.assertNotIn('address', json.dumps(row))

    def test_full_key_mismatch_not_low_bits_match(self):
        def mutate(profile, values):
            change_word(profile, values, 4, 0x90000020)
        pr, cr, artifacts, frame = source_fixture(mutate=mutate)
        row = GuardedForwardOwners(pr, cr, artifacts).project(frame)['relations'][0]
        self.assertEqual(row['reason'], 'forward_reference_owner_mismatch')
        self.assertIsNone(row['forward_owner_object_key'])
        self.assertEqual(row['owned_fields'], {})

    def test_every_identity_and_guard_failure_clears_association(self):
        for name in self.decoder.bindings[0]['names']:
            for mutation in ('unknown', 'value', 'bracket', 'ids'):
                with self.subTest(name=name, mutation=mutation):
                    f = copy.deepcopy(self.frame)
                    if mutation == 'unknown': f['fields'][name]['status'] = 'unknown'
                    if mutation == 'value': f['fields'][name]['value'] += 1
                    if mutation == 'bracket': f['fields'][name]['read_end_ticks'] = 101
                    if mutation == 'ids': f['fields'][name]['guard_ids'] = []
                    self.assertEqual(self.row(f)['relation_status'], 'unknown')
                    self.assertEqual(self.row(f)['owned_fields'], {})
        for phase in ('before', 'after'):
            f = copy.deepcopy(self.frame); f['guards_'+phase][0]['ok'] = False
            self.assertEqual(self.row(f)['relation_status'], 'unknown')

    def test_owned_failure_does_not_destroy_valid_identity(self):
        name = 'controller_0000_aux_0000_scalar'
        for value in (None, True, float('inf'), [1, 2]):
            f = copy.deepcopy(self.frame); f['fields'][name]['value'] = value
            row = self.row(f)
            self.assertEqual(row['relation_status'], 'observed')
            self.assertIsNone(row['owned_fields'][name]['value'])
        self.assertEqual(self.row()['owned_fields'][name]['value'], 13.5)

    def test_malformed_frame_and_sample_shapes_fail_closed(self):
        for key in ('target', 'fields'):
            for value in (None, [], True):
                f = copy.deepcopy(self.frame); f[key] = value
                self.assertEqual(self.row(f)['relation_status'], 'unknown')
        for name in self.decoder.bindings[0]['names']:
            f = copy.deepcopy(self.frame); f['fields'][name] = None
            self.assertEqual(self.row(f)['relation_status'], 'unknown')
        f = copy.deepcopy(self.frame)
        f['fields']['controller_0000_aux_0000_scalar'] = []
        row = self.row(f)
        self.assertEqual(row['relation_status'], 'observed')
        self.assertIsNone(row['owned_fields']['controller_0000_aux_0000_scalar']['value'])

    def test_owned_fields_cannot_omit_identity_dependencies(self):
        def mutate(profile, values):
            # Move a core guard from global to its one identity declaration.
            guard = profile['guards'].pop(0)
            profile['fields'][0]['guards'] = [guard]
        pr, cr, artifacts, _ = source_fixture(mutate=mutate)
        with self.assertRaisesRegex(ValueError, 'owned_field_missing_identity_guards'):
            GuardedForwardOwners(pr, cr, artifacts)

    def test_duplicate_controller_invalidates_both(self):
        def mutate(profile, values):
            change_word(profile, values, 5, values[profile['fields'][0]['name']] & 0xffffffff)
        pr, cr, artifacts, frame = source_fixture(2, mutate)
        rows = GuardedForwardOwners(pr, cr, artifacts).project(frame)['relations']
        self.assertEqual([r['reason'] for r in rows], ['duplicate_controller_or_owner']*2)

    def test_gaps_profile_target_and_frame_time_fail_without_carry(self):
        self.assertEqual(self.row()['relation_status'], 'observed')
        for mutation in ('gap', 'profile', 'target', 'frequency', 'sequence'):
            f = copy.deepcopy(self.frame)
            if mutation == 'gap': f['skipped_intervals_before'] = 1
            if mutation == 'profile': f['profile_sha256'] = '00'*32
            if mutation == 'target': f['target']['creation_file_time'] += 1
            if mutation == 'frequency': f['monotonic_frequency'] = True
            if mutation == 'sequence': f['sequence'] = -1
            row = self.row(f)
            self.assertIsNone(row['controller_object_key'])
            self.assertIsNone(row['forward_owner_object_key'])
            self.assertEqual(row['owned_fields'], {})
        self.assertEqual(self.decoder.project(self.frame, gap=True)['relations'][0]['reason'], 'scheduled_gap')

    def test_duplicate_owner_invalidates_both_even_when_one_sample_fails(self):
        def mutate(profile, values):
            change_word(profile, values, 8, 0x80000030)
        pr, cr, artifacts, frame = source_fixture(2, mutate)
        decoder = GuardedForwardOwners(pr, cr, artifacts)
        frame['fields'][decoder.bindings[1]['names'][4]]['status'] = 'unknown'
        rows = decoder.project(frame)['relations']
        self.assertTrue(all(r['relation_status'] == 'unknown' for r in rows))
        self.assertTrue(all(r['owned_fields'] == {} for r in rows))

    def test_new_epoch_owner_replaces_without_changing_controller(self):
        def mutate(profile, values):
            change_word(profile, values, 2, 0x80000099)
            change_word(profile, values, 3, 0x80000098, address=0x7000)
            change_word(profile, values, 4, 0x80000099, address=0x7008)
        pr, cr, artifacts, frame = source_fixture(mutate=mutate)
        new = GuardedForwardOwners(pr, cr, artifacts).project(frame)['relations'][0]
        self.assertEqual(new['controller_object_key'], self.row()['controller_object_key'])
        self.assertNotEqual(new['forward_owner_object_key'], self.row()['forward_owner_object_key'])
        self.assertEqual(self.row(frame)['relation_status'], 'unknown')

    def test_source_hash_target_template_and_final_guard_corruption_reject(self):
        for mutation in ('hash', 'target', 'template', 'final_guard'):
            cr = json.loads(self.cr); artifacts = self.artifacts.copy()
            if mutation == 'hash': artifacts[cr['source']['evidence_sha256']] += b' '
            elif mutation == 'target': cr['target']['pid'] += 1
            elif mutation == 'template': cr['bindings'][0]['reference_field'] = cr['bindings'][0]['owner_key_field']
            else:
                ev = [json.loads(l) for l in artifacts[cr['source']['evidence_sha256']].splitlines()]
                ev[2]['bytes_hex'] = '00000000'
                er = b''.join(raw(x) for x in ev); cr['source']['evidence_sha256'] = sha(er); artifacts[sha(er)] = er
                mr = json.loads(artifacts[cr['acquisition_manifest_sha256']]); mr['evidence_sha256'] = sha(er)
                mb = raw(mr); artifacts[sha(mb)] = mb; cr['acquisition_manifest_sha256'] = sha(mb)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                GuardedForwardOwners(self.pr, raw(cr), artifacts)

    def test_epoch_builder_is_deterministic_and_pins_actual_source(self):
        c = json.loads(self.cr)
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            for name, data in [('profile.json', self.pr), ('manifest.json', self.artifacts[c['acquisition_manifest_sha256']]),
                               ('recipe.json', self.artifacts[c['source']['recipe_sha256']]),
                               ('evidence.jsonl', self.artifacts[c['source']['evidence_sha256']])]:
                (d/name).write_bytes(data)
            args = (d, self.artifacts[c['binding_template_sha256']])
            first = build_forward_owner_contract(*args)
            self.assertEqual(first, build_forward_owner_contract(*args))
            self.assertEqual(first[0], self.cr)
            (d/'evidence.jsonl').write_bytes(b'{}\n')
            with self.assertRaises(InvalidForwardOwnerEvidence): build_forward_owner_contract(*args)


if __name__ == '__main__':
    unittest.main()
