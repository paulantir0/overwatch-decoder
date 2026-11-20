"""Synthetic historical metadata joins; no private captures or target offsets."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from controller_metadata import GuardedControllerMetadata, digest, encode
from controller_metadata_join import ControllerMetadataJoin, export_join
from test_controller_metadata import metadata_fixture


def qualified(kind):
    profile, context, frame = metadata_fixture(kind, count=2)
    result = GuardedControllerMetadata(profile, encode(context)).project(frame)
    result.update(acquisition_validation='complete_native_evidence_verified', recording_complete=True,
                  recording_manifest_sha256='ef'*32, native_verification_status='verified_complete')
    return result


def fixture(frames=None):
    frames = frames if frames is not None else [qualified('accounts'), qualified('cache')]
    artifacts = {digest(encode(frame)): encode(frame) for frame in frames}
    manifest = dict(schema='overwatch-decoder.controller-metadata-set/1', target=copy.deepcopy(frames[0]['target']),
                    clock_domain_id='synthetic-clock', monotonic_frequency=1000, exports=list(artifacts))
    keys = [row['requested_controller_object_key'] for row in qualified('accounts')['rows']]
    roster = dict(schema='overwatch-decoder.compact-live-roster/1', target=copy.deepcopy(manifest['target']),
        clock_domain_id='synthetic-clock', epoch_id='roster-session', privacy='private', atomic=False,
        public_state_eligible=False, visibility='unknown',
        participant_identity_validated=False, values_are_candidates=True, continuity_across_gaps=False,
        timing=dict(window_start_ticks=200, window_end_ticks=300, monotonic_frequency=1000),
        players=[dict(controller_object_key=key, body_object_key='body:' + str(i+1)*64,
                      status='observed', position_candidate=dict(value=[1,2,3]),
                      primary_observation=dict(source_timing=dict(start_ticks=200, end_ticks=300,
                                                                  monotonic_frequency=1000)),
                      health_candidate=dict(value=100)) for i, key in enumerate(keys)])
    return manifest, artifacts, roster


def decoder(frames=None):
    manifest, artifacts, roster = fixture(frames)
    return ControllerMetadataJoin(encode(manifest), artifacts), roster


class MetadataJoinTests(unittest.TestCase):
    def test_exact_keys_attach_only_historical_candidates_with_original_provenance(self):
        join, roster = decoder()
        result = join.project(encode(roster))
        self.assertEqual(result['schema'], 'overwatch-decoder.compact-live-roster-metadata/1')
        self.assertEqual(result['controller_metadata_join']['source_compact_sha256'], digest(encode(roster)))
        first = result['players'][0]['controller_metadata_candidates']
        self.assertEqual(first['status'], 'historical_candidates')
        self.assertEqual(first['account']['candidate']['account_status'], 'guarded_raw_candidate')
        self.assertEqual(first['cache']['candidate']['cached_label_candidate'], '人'*21)
        self.assertEqual(first['cache']['timing']['end_ticks'], 100)
        self.assertEqual(first['cache']['age_ticks'], 200)
        self.assertFalse(first['current_value_asserted'])
        self.assertIsNone(first['canonical_name'])
        self.assertIsNone(first['team'])
        self.assertFalse(first['self_identity_inferred'])
        proof = first['cache']['provenance']
        self.assertEqual(proof['guard_brackets_ref'], '/guard_brackets')
        self.assertTrue(proof['original_metadata_line_required'])
        self.assertIn(proof['export_sha256'], join.manifest['exports'])
        self.assertEqual(first['cache']['validation'], 'hash_pinned_export_candidate_not_native_reverification')

    def test_process_creation_build_and_controller_replacement_do_not_match(self):
        join, roster = decoder()
        for field, value in [('pid', 124), ('creation_file_time', 457),
                             ('executable_sha256', 'cd'*32), ('image_name', 'other.exe')]:
            changed = copy.deepcopy(roster)
            changed['target'][field] = value
            row = join.project(encode(changed))['players'][0]['controller_metadata_candidates']
            self.assertEqual(row['reason'], 'process_or_build_epoch_mismatch', field)
            self.assertIsNone(row['account'])
            self.assertIsNone(row['cache'])
        changed = copy.deepcopy(roster)
        changed['players'][0]['controller_object_key'] = 'controller:' + 'f'*64
        row = join.project(encode(changed))['players'][0]['controller_metadata_candidates']
        self.assertEqual(row['status'], 'unknown')
        self.assertIsNone(row['account'])
        self.assertIsNone(row['cache'])

    def test_unknown_roster_and_transition_never_fill_any_metadata(self):
        join, roster = decoder()
        for transition in (False, True):
            changed = copy.deepcopy(roster)
            changed['players'][0].update(status='unknown', body_object_key=None)
            if transition:
                changed['schema'] = 'overwatch-decoder.compact-live-roster-transition/1'
                changed.pop('timing')
            result = join.project(encode(changed))
            for player in result['players'] if transition else result['players'][:1]:
                attached = player['controller_metadata_candidates']
                self.assertEqual(attached['status'], 'unknown')
                self.assertIsNone(attached['account'])
                self.assertIsNone(attached['cache'])
            self.assertEqual(result['players'][0]['status'], 'unknown')

    def test_new_body_or_roster_session_preserves_only_historical_controller_binding(self):
        join, roster = decoder()
        roster['players'][0]['body_object_key'] = 'body:' + 'f'*64
        roster['epoch_id'] = 'new-roster-session'
        sample = join.project(encode(roster))['players'][0]['controller_metadata_candidates']
        self.assertEqual(sample['status'], 'historical_candidates')
        self.assertIsNone(sample['cache']['candidate']['body_object_key'])
        self.assertFalse(sample['current_value_asserted'])

    def test_future_samples_and_other_clock_domain_are_not_historical_input(self):
        join, roster = decoder()
        roster['timing'].update(window_start_ticks=0, window_end_ticks=99)
        for player in roster['players']:
            player['primary_observation']['source_timing'].update(start_ticks=0, end_ticks=99)
        attached = join.project(encode(roster))['players'][0]['controller_metadata_candidates']
        self.assertIsNone(attached['cache'])
        self.assertEqual(attached['sample_reasons']['cache'], 'metadata_after_roster_interval')
        for mode in ('domain', 'frequency'):
            changed = copy.deepcopy(roster)
            if mode == 'domain': changed['clock_domain_id'] = 'different-clock'
            else: changed['timing']['monotonic_frequency'] += 1
            attached = join.project(encode(changed))['players'][0]['controller_metadata_candidates']
            self.assertEqual(attached['reason'], 'metadata_clock_domain_mismatch')

    def test_later_unknown_sample_never_falls_back_to_prior_text(self):
        old = qualified('cache')
        newer = copy.deepcopy(old)
        newer['timing'].update(sequence=1, start_ticks=310, end_ticks=400)
        for phase in newer['guard_brackets'].values():
            for guard in phase:
                guard['start_ticks'] += 300
                guard['end_ticks'] += 300
        for row in newer['rows']:
            row.update(cached_label_candidate=None, cached_label_status='unknown',
                       cached_label_reason='label_not_declared', cached_label_evidence=[])
            for sample in row['controller_evidence']:
                sample['read_start_ticks'] += 300
                sample['read_end_ticks'] += 300
        join, roster = decoder([old, newer])
        roster['timing'].update(window_start_ticks=400, window_end_ticks=500)
        for player in roster['players']:
            player['primary_observation']['source_timing'].update(start_ticks=400, end_ticks=500)
        attached = join.project(encode(roster))['players'][0]['controller_metadata_candidates']
        self.assertEqual(attached['status'], 'unknown')
        self.assertEqual(attached['cache']['status'], 'historical_sample_unknown')
        self.assertIsNone(attached['cache']['candidate']['cached_label_candidate'])
        self.assertEqual(attached['cache']['timing']['sequence'], 1)

    def test_malformed_identity_token_guards_and_source_evidence_rejected(self):
        for mode in ('ids', 'read_time', 'guard', 'word_count', 'token_width', 'token_hash',
                     'source_hash', 'unverified', 'target', 'public', 'foreign_field'):
            frame = qualified('accounts')
            row = frame['rows'][0]
            if mode == 'ids': row['account_evidence'][0]['guard_ids'] = []
            elif mode == 'read_time': row['controller_evidence'][0]['read_end_ticks'] = 101
            elif mode == 'guard': frame['guard_brackets']['guards_after'][0]['ok'] = False
            elif mode == 'word_count': row['account_evidence'].pop()
            elif mode == 'token_width': row['account_token_candidate_hex'] = 'ab'*15
            elif mode == 'token_hash': row['account_token_sha256'] = '00'*32
            elif mode == 'source_hash': frame['source_acquisition']['recipe_sha256'] = 'bad'
            elif mode == 'unverified': frame['acquisition_validation'] = 'caller_verified_required'
            elif mode == 'target': frame['target']['pid'] += 1
            elif mode == 'public': frame['public_state_eligible'] = True
            else: row['name'] = 'unsupported'
            manifest, artifacts, _ = fixture([frame])
            if mode == 'target': manifest['target']['pid'] -= 1
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                ControllerMetadataJoin(encode(manifest), artifacts)

    def test_malformed_cache_evidence_or_unrequested_values_rejected(self):
        for mode in ('byte_count', 'byte_index', 'text', 'unrequested_token'):
            frame = qualified('cache')
            row = frame['rows'][0]
            if mode == 'byte_count': row['cached_label_evidence'].pop()
            elif mode == 'byte_index': row['cached_label_evidence'][0]['field'] = 'incorrect_field'
            elif mode == 'text': row['cached_label_candidate'] = 'bad\ntext'
            else: row['account_token_candidate_hex'] = 'ab'*16
            manifest, artifacts, _ = fixture([frame])
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                ControllerMetadataJoin(encode(manifest), artifacts)

    def test_hash_mismatch_and_duplicate_sample_times_rejected(self):
        manifest, artifacts, _ = fixture()
        artifacts[manifest['exports'][0]] += b' '
        with self.assertRaisesRegex(ValueError, 'export_hash'):
            ControllerMetadataJoin(encode(manifest), artifacts)
        first = qualified('cache')
        second = copy.deepcopy(first)
        second['partition_id'] = 'different-source'
        manifest, artifacts, _ = fixture([first, second])
        with self.assertRaisesRegex(ValueError, 'ambiguous_metadata_sample_time'):
            ControllerMetadataJoin(encode(manifest), artifacts)

    def test_results_are_detached_and_existing_roster_fields_unchanged(self):
        join, roster = decoder()
        original = copy.deepcopy(roster)
        result = join.project(encode(roster))
        sample = result['players'][0]['controller_metadata_candidates']['account']
        sample['candidate']['account_evidence'][0]['guard_ids'].clear()
        again = join.project(encode(roster))
        self.assertTrue(again['players'][0]['controller_metadata_candidates']['account']['candidate']['account_evidence'][0]['guard_ids'])
        for actual, expected in zip(again['players'], original['players']):
            self.assertEqual({key: value for key, value in actual.items() if key != 'controller_metadata_candidates'}, expected)
        self.assertEqual(roster, original)
        self.assertNotIn('address', json.dumps(again))

    def test_export_preserves_input_order_hashes_and_requires_new_output(self):
        manifest, artifacts, roster = fixture()
        later = copy.deepcopy(roster)
        later['players'][0]['status'] = 'unknown'
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory)/'input.jsonl', Path(directory)/'joined.jsonl'
            source.write_bytes(encode(roster) + encode(later))
            result = export_join(encode(manifest), artifacts, source, output)
            self.assertEqual(result['events'], 2)
            self.assertEqual(result['input_sha256'], digest(source.read_bytes()))
            self.assertEqual(result['output_sha256'], digest(output.read_bytes()))
            rows = [json.loads(line) for line in output.read_bytes().splitlines()]
            self.assertEqual(rows[1]['players'][0]['controller_metadata_candidates']['reason'], 'roster_row_unknown')
            with self.assertRaises(ValueError):
                export_join(encode(manifest), artifacts, source, output)

    def test_roster_schema_qualifiers_and_duplicate_identities_fail_closed(self):
        join, roster = decoder()
        for mode in ('schema', 'public', 'participant', 'duplicate', 'target_shape'):
            changed = copy.deepcopy(roster)
            if mode == 'schema': changed['schema'] = 'unrelated/1'
            elif mode == 'public': changed['public_state_eligible'] = True
            elif mode == 'participant': changed['participant_identity_validated'] = True
            elif mode == 'duplicate': changed['players'].append(copy.deepcopy(changed['players'][0]))
            else: changed['target'].pop('creation_file_time')
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                join.project(encode(changed))
        for raw in (b'[]\n', b'{"schema":1,"schema":2}\n', b'{}', b' '*(1024*1024+1)+b'\n'):
            with self.assertRaises(ValueError):
                join.project(raw)

    def test_missing_current_body_does_not_claim_a_successful_observed_join(self):
        join, roster = decoder()
        roster['players'][0]['body_object_key'] = None
        result = join.project(encode(roster))['players'][0]['controller_metadata_candidates']
        self.assertEqual(result['reason'], 'observed_roster_body_unknown')
        self.assertIsNone(result['account'])
        self.assertIsNone(result['cache'])

    def test_metadata_after_primary_read_is_not_attached_even_inside_same_window(self):
        join, roster = decoder()
        roster['timing'].update(window_start_ticks=0, window_end_ticks=300)
        roster['players'][0]['primary_observation']['source_timing'].update(start_ticks=50, end_ticks=99)
        result = join.project(encode(roster))['players'][0]['controller_metadata_candidates']
        self.assertIsNone(result['cache'])
        self.assertIsNone(result['account'])
        self.assertEqual(result['sample_reasons']['cache'], 'metadata_after_roster_interval')

    def test_isolated_cli_resolves_only_explicit_sibling_decoder_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root/'scripts'
            scripts.mkdir()
            for name in ('controller_metadata_join', 'controller_metadata', 'account_anchor',
                         'cached_labels', 'export_relations', 'plan_live_roster', 'relations'):
                shutil.copyfile(__import__(name).__file__, scripts/(name+'.py'))
            result = subprocess.run([sys.executable, '-I', str(scripts/'controller_metadata_join.py'), '--help'],
                                    cwd=root, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b'--metadata-set', result.stdout)


if __name__ == '__main__':
    unittest.main()
