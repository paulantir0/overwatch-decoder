"""Fresh category artifacts admitted through the ordinary roster pipeline."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aggregate_live_partitions import LivePartitions
from compact_live_roster import CompactLiveRoster
from forward_roster_projection import acquire_source_metadata, validate_source
from live_relations import LiveRelations
from runtime_producer import forward_adapter_options, profile_body_bindings
from test_forward_category_pipeline import fixture
from test_forward_owner_relations import raw
from test_live_relations import SESSION, start, live
from export_relations import export_recording


class ForwardCategoryRosterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pr, _, _, _, self.native, _, producer = fixture(self.root)
        self.epoch = self.root/'epoch'
        self.epoch.mkdir()
        self.options = forward_adapter_options(producer, self.root, self.epoch)
        self.profile = json.loads(self.pr)

    def frame(self, native=None):
        adapter = LiveRelations(self.root, SESSION, 1, **self.options)
        adapter.consume(raw(start(self.profile, json.loads((self.root/'manifest.json').read_bytes()))))
        return adapter.consume(raw(live(self.native if native is None else native)))

    def source(self, frame):
        _, objects, unresolved = profile_body_bindings(self.pr, allow_unresolved=True)
        source = dict(source_id='p1', session_id=SESSION, segment=1,
            profile_sha256=frame['profile_sha256'], acquisition=frame['source_artifacts']['acquisition'],
            fields=[{k:f[k] for k in ('name', 'type')} for f in self.profile['fields']], objects=objects)
        if unresolved:
            source['unresolved_bodies'] = [dict(row, acquisition_evidence_sha256=source['acquisition']['evidence_sha256'])
                                           for row in unresolved]
        source['forward_owner_projection'] = acquire_source_metadata(self.pr, self.epoch, frame, source)
        return source

    def config(self, frame, source):
        frequency = frame['timing']['monotonic_frequency']
        window = frequency//10
        return dict(schema='overwatch-decoder.live-partition-config/1', epoch_id='category-fixture',
            clock_domain_id='synthetic-qpc', target=frame['target'], monotonic_frequency=frequency,
            window_origin_ticks=0, window_ticks=window, maximum_skew_ticks=frequency,
            maximum_origin_offset_ticks=0, observation_mode='raw-candidates', allow_unresolved_bodies=True,
            roster=[dict(row, primary_source_id='p1') for row in source['objects']], sources=[source])

    def test_live_admission_to_compact_preserves_exact_group_with_no_body_promotion(self):
        frame = self.frame()
        source = self.source(frame)
        config = self.config(frame, source)
        adapter = LivePartitions(raw(config))
        adapter.consume('p1', raw(frame))
        window = config['window_ticks']
        end = (frame['timing']['end_ticks']//window+1)*window
        full = list(adapter.advance(end))[-1]
        compact = CompactLiveRoster().consume(raw(full))
        owner = compact['forward_owners'][0]
        self.assertEqual(owner['category_candidate']['value']['raw_category_candidate'], 0)
        self.assertIsNone(owner['current_displayed_body'])
        self.assertEqual(owner['position_candidate']['value'], [1., 2., 3.])
        self.assertIsNone(full['relations'][0]['authoritative_observation'])
        pins = full['forward_owner_sources']['p1']
        self.assertEqual(pins['forward_category_contract_sha256'], frame['forward_owner_projection']['forward_category_contract_sha256'])

    def test_category_failure_does_not_drop_owner_position(self):
        native = copy.deepcopy(self.native)
        native['fields']['category_low'].update(status='unknown', value=None, reason='unreadable')
        frame = self.frame(native)
        source = self.source(frame)
        adapter = LivePartitions(raw(self.config(frame, source)))
        adapter.consume('p1', raw(frame))
        full = list(adapter.advance(200))[-1]
        owner = CompactLiveRoster().consume(raw(full))['forward_owners'][0]
        self.assertIsNone(owner['category_candidate']['value'])
        self.assertEqual(owner['position_candidate']['value'], [1., 2., 3.])

    def test_source_pin_mismatch_and_partial_category_admission_reject(self):
        frame = self.frame()
        source = self.source(frame)
        for key in ('forward_category_contract_sha256', 'forward_category_native_review_sha256'):
            changed = copy.deepcopy(source)
            changed['forward_owner_projection'][key] = '54'*32
            with self.subTest(key=key), self.assertRaises(ValueError):
                LivePartitions(raw(self.config(frame, changed))).consume('p1', raw(frame))
            changed['forward_owner_projection'].pop(key)
            with self.assertRaises(ValueError):
                validate_source(changed)

    def test_runtime_source_checks_actual_category_bytes_and_missing_output(self):
        frame = self.frame()
        source = self.source(frame)
        missing = copy.deepcopy(frame)
        for key in ('forward_category_output_enabled', 'forward_category_contract_sha256',
                    'forward_category_native_review_sha256'):
            missing['forward_owner_projection'].pop(key)
        with self.assertRaisesRegex(ValueError, 'configured_category_missing'):
            acquire_source_metadata(self.pr, self.epoch, missing, source)
        path = self.epoch/'forward-category-contract.json'
        contract = json.loads(path.read_bytes())
        contract['forward_contract_sha256'] = '55'*32
        path.write_bytes(raw(contract))
        with self.assertRaises(ValueError):
            acquire_source_metadata(self.pr, self.epoch, frame, source)

    def test_finite_export_publishes_category_rows_and_matching_summary(self):
        recording = self.root/'recording'
        recording.mkdir()
        pin = lambda data: hashlib.sha256(data).hexdigest()
        profile_hash = pin(self.pr)
        summary = dict(kind='summary', target=self.profile['target'], profile_sha256=profile_hash)
        payload = raw(self.native)+raw(summary)
        compressed = gzip.compress(payload, mtime=0)
        chunk = dict(schema='overwatch-decoder.field-recording-chunk/1', sequence=0, offset=0,
            compressed_bytes=len(compressed), json_bytes=len(payload), first_line=0, lines=2,
            compressed_sha256=pin(compressed), json_sha256=pin(payload))
        index = raw(chunk)
        manifest = dict(schema='overwatch-decoder.field-recording/1', target=self.profile['target'], profile_sha256=profile_hash)
        for name, data in [('profile.json', self.pr), ('manifest.json', raw(manifest)),
                           ('samples.jsonl.gz', compressed), ('chunks.jsonl', index)]:
            (recording/name).write_bytes(data)
        verified = dict(valid=True, complete=True, status='verified_complete', verified_chunks=1,
            verified_compressed_bytes=len(compressed), verified_lines=2, frames=1, profile_sha256=profile_hash,
            samples_prefix_sha256=pin(compressed), index_prefix_sha256=pin(index), json_prefix_sha256=pin(payload),
            unverified_compressed_bytes=0, unverified_index_bytes=0)
        with patch('export_relations.native_verify', return_value=verified):
            report = export_recording(recording, self.root, self.root/'export.jsonl', ['fixture-verifier'], **self.options)
            legacy = export_recording(recording, self.root, self.root/'legacy.jsonl', ['fixture-verifier'],
                **{key:val for key,val in self.options.items() if 'category' not in key})
        exported = json.loads((self.root/'export.jsonl').read_bytes())
        self.assertEqual(exported['forward_owner_projection']['relations'][0]['raw_category_candidate'], 0)
        self.assertEqual(report['frames'], 1)
        self.assertEqual(report['forward_owner_output']['observed_raw_category_candidates'], 1)
        self.assertNotIn('observed_raw_category_candidates', legacy['forward_owner_output'])


if __name__ == '__main__':
    unittest.main()
