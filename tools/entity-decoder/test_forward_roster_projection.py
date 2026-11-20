"""Forward owners through source admission, finite files and live windows."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import aggregate_partitions as finite
from aggregate_live_partitions import LivePartitions
from forward_roster_projection import acquire_source_metadata, validate_source
from test_aggregate_live_partitions import live_fixture
from test_aggregate_partitions import fixture as finite_fixture, write_fixture, raw
from test_compact_forward_owners import attach, unknown
from test_forward_owner_validation import source_admission
from test_forward_owner_pipeline import write_fixture as native_fixture
from test_live_relations import SESSION, start, live
from test_live_roster_epochs import fixture as epoch_fixture, unresolved, replacement, next_frame
from live_relations import LiveRelations
from live_roster_epochs import LiveRosterEpochs
from runtime_startup import StartupSources


def configure(source, frames):
    declarations = {f['name']: f['type'] for f in source.get('fields', [])}
    for frame in frames:
        attach(frame)
        row = frame['forward_owner_projection']['relations'][0]
        declarations.update({w['field']: 'i32' for w in row['identity_evidence']})
        declarations.update({name: f['type'] for name, f in row['owned_fields'].items()})
        declarations.update({w['field']: 'i32' for w in row['controller_hero_asset_label_evidence']['fields']})
    source['fields'] = [dict(name=n, type=t) for n, t in declarations.items()]
    source['forward_owner_projection'] = source_admission(frames[0]['forward_owner_projection'])


class ForwardRosterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def setup_live(self):
        config, frames = live_fixture(self.root)
        for source in config['sources']:
            configure(source, frames[source['source_id']])
        return config, frames

    def test_live_primary_owner_is_separate_and_preserves_exact_provenance(self):
        config, frames = self.setup_live()
        adapter = LivePartitions(raw(config))
        for sid in frames:
            adapter.consume(sid, raw(frames[sid][0]))
        result = list(adapter.advance(1050))[0]
        self.assertEqual(len(result['forward_owners']), 1)
        owner = result['forward_owners'][0]
        self.assertEqual(owner['primary_source_id'], 'p1')
        self.assertEqual(owner['status'], 'observed')
        self.assertIsNone(owner['current_displayed_body'])
        self.assertNotIn('body_object_key', owner)
        entry = result['forward_owner_projections']['p1']
        self.assertEqual(entry['projection'], frames['p1'][0]['forward_owner_projection'])
        self.assertEqual(entry['source_timing'], frames['p1'][0]['timing'])
        self.assertEqual(entry['semantic_projection_sha256'], finite.sha(raw(frames['p1'][0])))
        self.assertEqual(entry['semantic_hash_scope'], 'projection_line')
        self.assertEqual(set(result['forward_owner_projections']), {'p1', 'p2'})
        self.assertTrue(all(row['body_object_key'] is not None for row in result['relations']))

    def test_missing_or_gapped_primary_never_borrows_a_support_owner(self):
        for mode in ('missing', 'gap'):
            with self.subTest(mode=mode):
                config, frames = self.setup_live()
                adapter = LivePartitions(raw(config))
                if mode == 'gap':
                    frame = unknown(frames['p1'][0])
                    frame['gap_before']['skipped_slots'] = 1
                    adapter.consume('p1', raw(frame))
                adapter.consume('p2', raw(frames['p2'][0]))
                result = list(adapter.advance(1050))[0]
                owner = result['forward_owners'][0]
                self.assertEqual(owner['status'], 'unknown')
                self.assertIsNone(owner['projection_ref'])
                self.assertIsNone(owner['relation_index'])
                self.assertEqual(set(result['forward_owner_projections']), {'p2'})
                empty = list(adapter.advance(1100))[0]
                self.assertEqual(empty['forward_owner_projections'], {})
                self.assertEqual(empty['forward_owners'][0]['reason'], 'missing_frame_in_window')

    def test_unknown_association_retains_only_audit_envelope(self):
        config, frames = self.setup_live()
        unknown(frames['p1'][0], reason='guard_failed')
        adapter = LivePartitions(raw(config))
        adapter.consume('p1', raw(frames['p1'][0]))
        result = list(adapter.advance(1050))[0]
        owner = result['forward_owners'][0]
        self.assertEqual(owner['reason'], 'guard_failed')
        self.assertIsNone(owner['projection_ref'])
        self.assertEqual(result['forward_owner_projections']['p1']['projection'],
                         frames['p1'][0]['forward_owner_projection'])

    def test_same_epoch_contract_owner_option_and_field_changes_reject(self):
        mutations = {
            'contract': lambda f: f['forward_owner_projection'].update(contract_sha256='42'*32),
            'owner': lambda f: f['forward_owner_projection']['relations'][0].update(forward_owner_object_key='owner:'+'43'*32),
            'binding': lambda f: f['forward_owner_projection']['relations'][0].update(binding_id='different'),
            'option': lambda f: f.pop('forward_owner_projection'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                config, frames = self.setup_live()
                adapter = LivePartitions(raw(config))
                adapter.consume('p1', raw(frames['p1'][0]))
                mutate(frames['p1'][1])
                with self.assertRaises(ValueError):
                    adapter.consume('p1', raw(frames['p1'][1]))
                self.assertTrue(adapter.failed)
        config, frames = self.setup_live()
        source = config['sources'][0]
        name = source['forward_owner_projection']['bindings'][0]['identity_fields'][0]
        source['fields'] = [f for f in source['fields'] if f['name'] != name]
        with self.assertRaises(ValueError):
            LivePartitions(raw(config))

    def test_raw_roster_can_retain_owner_when_reciprocal_body_is_unresolved(self):
        config, frames = epoch_fixture(self.root)
        config.update(observation_mode='raw-candidates', allow_unresolved_bodies=True)
        controller = config['roster'][0]['controller_object_key']
        for i, source in enumerate(config['sources']):
            sid = source['source_id']
            modified = [unresolved(source, f, controller) for f in frames[sid]]
            config['sources'][i] = modified[0][0]
            frames[sid] = [item[1] for item in modified]
            configure(config['sources'][i], frames[sid])
        config['roster'][0]['body_object_key'] = None
        adapter = LivePartitions(raw(config))
        for sid in frames:
            adapter.consume(sid, raw(frames[sid][0]))
        result = list(adapter.advance(1050))[0]
        self.assertIsNone(result['relations'][0]['body_object_key'])
        self.assertIsNone(result['relations'][0]['authoritative_observation'])
        self.assertEqual(result['forward_owners'][0]['status'], 'observed')

    def test_finite_file_hash_scope_and_unresolved_body_require_explicit_admission(self):
        config, frames = finite_fixture(self.root)
        config.update(observation_mode='raw-candidates', allow_unresolved_bodies=True)
        controller = config['roster'][0]['controller_object_key']
        config['roster'][0]['body_object_key'] = None
        for source in config['sources']:
            configure(source, frames[source['source_id']])
            source['objects'][0]['body_object_key'] = None
            for frame in frames[source['source_id']]:
                frame['relations'][0] = dict(controller_object_key=controller, body_object_key=None,
                    relation_status='unknown', reason='unsupported_word_binding', visibility='unknown')
        write_fixture(self.root, config, frames)
        finite.aggregate(self.root/'manifest.json', self.root/'out.jsonl')
        output = [json.loads(line) for line in (self.root/'out.jsonl').read_bytes().splitlines()]
        self.assertTrue(all(w['forward_owners'][0]['status'] == 'observed' for w in output))
        self.assertTrue(all(w['relations'][0]['authoritative_observation'] is None for w in output))
        entry = output[0]['forward_owner_projections']['p1']
        self.assertEqual(entry['semantic_hash_scope'], 'source_file')
        self.assertEqual(entry['semantic_projection_sha256'], config['sources'][0]['sha256'])
        config['sources'][0].pop('forward_owner_projection')
        write_fixture(self.root, config, frames)
        with self.assertRaisesRegex(ValueError, 'finite_unresolved_body_requires_forward_source'):
            finite.Manifest(self.root/'manifest.json')

    def test_actual_forward_artifacts_pin_runtime_source_and_detect_tampering(self):
        profile, frame, manifest, options = native_fixture(self.root)
        adapter = LiveRelations(self.root, SESSION, 1, **options)
        adapter.consume(raw(start(profile, manifest)))
        observed = adapter.consume(raw(live(frame)))
        source = dict(profile_sha256=observed['profile_sha256'],
            acquisition=observed['source_artifacts']['acquisition'], fields=profile['fields'],
            objects=[dict(controller_object_key=observed['forward_owner_projection']['relations'][0]['controller_object_key'],
                          body_object_key=None)])
        (self.root/'forward-contract.json').write_bytes((self.root/'forward.json').read_bytes())
        profile_raw = (self.root/'profile.json').read_bytes()
        metadata = acquire_source_metadata(profile_raw, self.root, observed, source)
        self.assertEqual(metadata, source_admission(observed['forward_owner_projection']))
        source['acquisition'] = dict(source['acquisition'], evidence_sha256='44'*32)
        with self.assertRaises(ValueError):
            acquire_source_metadata(profile_raw, self.root, observed, source)
        with self.assertRaisesRegex(ValueError, 'forward_roster_configured_output_missing'):
            acquire_source_metadata(profile_raw, self.root, {}, source)
        self.assertIsNone(acquire_source_metadata(b'', self.root/'unconfigured', {}, {}))

    def test_malformed_source_declarations_fail_explicitly(self):
        config, _ = self.setup_live()
        for fields in (None, [], [dict(name='x', type='f64')]):
            source = copy.deepcopy(config['sources'][0])
            source['fields'] = fields
            with self.assertRaises(ValueError):
                validate_source(source)
        source = config['sources'][0]
        source['forward_owner_projection']['bindings'][0]['identity_fields'][0] = []
        with self.assertRaises(ValueError):
            validate_source(source)

    def test_startup_adoption_requires_the_same_forward_admission(self):
        config, frames = epoch_fixture(self.root)
        warmup = StartupSources(config['target'], 1000, raw_candidates=False)
        for source in config['sources']:
            configure(source, frames[source['source_id']])
            warmup.add(source)
            warmup.consume(source['source_id'], raw(frames[source['source_id']][0]))
        altered = copy.deepcopy(config)
        altered['sources'][0]['forward_owner_projection']['contract_sha256'] = '51'*32
        with self.assertRaisesRegex(ValueError, 'startup_source_admission_mismatch'):
            LiveRosterEpochs(raw(altered))._adopt_startup(warmup, 1040)
        coordinator = LiveRosterEpochs(raw(config))
        events = coordinator._adopt_startup(warmup, 1040)
        self.assertEqual(events[0]['startup_validation']['validated_frames'], 2)
        self.assertEqual(coordinator.aggregate.pending, {})

    def test_fresh_acquisition_changes_owner_only_after_roster_transition(self):
        config, frames = epoch_fixture(self.root)
        config['sources'] = [config['sources'][0]]
        config['roster'] = [r for r in config['roster'] if r['primary_source_id'] == 'p1']
        source = config['sources'][0]
        configure(source, frames['p1'])
        coordinator = LiveRosterEpochs(raw(config))
        coordinator.consume('p1', raw(frames['p1'][0]))
        old = list(coordinator.advance(1050))[0]
        old_owner = old['forward_owners'][0]['forward_owner_object_key']
        new_owner = 'owner:'+'52'*32
        contract = source['forward_owner_projection']['contract_sha256']
        fresh, frame = replacement(source, frames['p1'][0], 1120,
            {old_owner: new_owner, contract: '53'*32})
        events = coordinator.admit('p1', raw(fresh), raw(frame))
        self.assertEqual([e['status'] for e in events], ['unknown', 'resumed_without_carried_values'])
        following = next_frame(frame, 1170)
        projection = following['forward_owner_projection']
        projection['timing']['sequence'] = following['timing']['sequence']
        projection['relations'][0]['controller_hero_asset_label_evidence']['frame_timing']['sequence'] = following['timing']['sequence']
        coordinator.consume('p1', raw(following))
        output = list(coordinator.advance(1200))[0]
        self.assertEqual(output['forward_owners'][0]['forward_owner_object_key'], new_owner)
        self.assertEqual(output['forward_owner_sources']['p1']['contract_sha256'], '53'*32)


if __name__ == '__main__':
    unittest.main()
