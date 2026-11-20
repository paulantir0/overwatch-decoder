"""Synthetic metadata behavior; no application addresses or private artifacts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller_metadata import (GuardedControllerMetadata, InvalidMetadata,
                                 digest, encode, export_recording, profile_keys)
from cached_labels import GuardedCachedLabels
from test_relations import fixture, prepare


def metadata_fixture(kind='accounts', count=10, missing=()):
    profile, values = fixture(count)
    # No reciprocal body fields are needed. This fixture deliberately omits them.
    profile['fields'] = [field for field in profile['fields']
                         if field['name'].endswith(('_handle_candidate_i32', '_manager_key_candidate_i32'))
                         and '_body_' not in field['name']]
    values = {field['name']: values[field['name']] for field in profile['fields']}
    if kind == 'accounts':
        for i in range(count):
            if i in missing:
                continue
            token = (i + 1).to_bytes(4, 'little') + bytes.fromhex('010000800200000003000000')
            address = 0x10000 + i * 64
            profile['guards'].append(dict(address=address, bytes_hex=token.hex()))
            for j in range(4):
                name = f'controller_{i:04d}_part36_0000_account_word{j}_candidate_i32'
                profile['fields'].append(dict(name=name, type='i32', address=address + j * 4))
                word = int.from_bytes(token[j*4:j*4+4], 'little')
                values[name] = word if word < 2**31 else word - 2**32
    else:
        for field in list(profile['fields']):
            field['name'] = field['name'].replace('controller_', 'roster_', 1)
        values = {name.replace('controller_', 'roster_', 1): value for name, value in values.items()}
        for suffix in ('handle_candidate_i32', 'manager_key_candidate_i32'):
            original = next(field for field in profile['fields'] if field['name'] == 'roster_0000_' + suffix)
            profile['fields'].append(dict(original, name='controller_0000_' + suffix))
            values['controller_0000_' + suffix] = values[original['name']]
        label = ('人' * 21).encode() + b'\0'
        profile['guards'].append(dict(address=0x20000, bytes_hex=label.hex()))
        for i, value in enumerate(label):
            name = f'controller_0000_cached_label_0000_byte_{i:04d}_value'
            profile['fields'].append(dict(name=name, type='u8', address=0x20000 + i))
            values[name] = value
    _, frame = prepare(profile, values)
    for field in profile['fields']:
        frame['fields'][field['name']]['type'] = field['type']
    raw_profile = json.dumps(profile).encode()
    relations = GuardedCachedLabels(raw_profile).relations
    selected = profile_keys(relations, relations.prefixes)
    roster = selected if kind == 'accounts' else profile_keys(relations, [f'roster_{i:04d}' for i in range(count)])
    context = dict(schema='overwatch-decoder.controller-metadata-context/1', target=profile['target'],
                   profile_sha256=digest(raw_profile), partition_id='fixture', kind=kind,
                   controller_object_keys=list(selected), roster_controller_object_keys=list(roster),
                   source_acquisition=dict(manifest_sha256='12'*32, recipe_sha256='34'*32, evidence_sha256='56'*32))
    return raw_profile, context, frame


class ControllerMetadataTests(unittest.TestCase):
    def project(self, kind='accounts', count=10, missing=()):
        profile, context, frame = metadata_fixture(kind, count, missing)
        decoder = GuardedControllerMetadata(profile, encode(context))
        return decoder, frame, decoder.project(frame)

    def test_ten_full_tokens_without_body_names_or_roles(self):
        _, _, out = self.project()
        self.assertEqual(len(out['rows']), 10)
        self.assertTrue(all(row['account_status'] == 'guarded_raw_candidate' for row in out['rows']))
        self.assertTrue(all(len(bytes.fromhex(row['account_token_candidate_hex'])) == 16 for row in out['rows']))
        self.assertEqual(len({row['account_token_sha256'] for row in out['rows']}), 10)
        self.assertTrue(all(row['body_object_key'] is None for row in out['rows']))
        self.assertFalse(out['human_identity_validated'])
        self.assertFalse(out['mode_admitted'])
        self.assertFalse(out['public_state_eligible'])
        self.assertEqual(out['visibility'], 'unknown')
        self.assertIsNone(out['canonical_name'])
        self.assertIsNone(out['team'])

    def test_absent_component_does_not_discard_peers(self):
        _, _, out = self.project(missing=(4,))
        self.assertEqual(sum(row['account_status'] == 'guarded_raw_candidate' for row in out['rows']), 9)
        self.assertEqual(out['rows'][4]['account_reason'], 'complete_account_words_not_declared')
        self.assertIsNotNone(out['rows'][4]['controller_object_key'])

    def test_partial_zero_and_noncontiguous_tokens_never_emit(self):
        for mode in ('partial', 'zero', 'noncontiguous'):
            profile_raw, context, frame = metadata_fixture(count=1)
            profile = json.loads(profile_raw)
            name = 'controller_0000_part36_0000_account_word3_candidate_i32'
            if mode == 'partial':
                profile['fields'] = [field for field in profile['fields'] if field['name'] != name]
                frame['fields'].pop(name)
            elif mode == 'noncontiguous':
                next(field for field in profile['fields'] if field['name'] == name)['address'] += 4
            else:
                for field in profile['fields']:
                    if '_account_word' in field['name']:
                        guard = next(g for g in profile['guards'] if g['address'] <= field['address'] < g['address'] + len(bytes.fromhex(g['bytes_hex'])))
                        guard['bytes_hex'] = '00' * 16
                        frame['fields'][field['name']]['value'] = 0
            profile_raw = json.dumps(profile).encode()
            context['profile_sha256'] = digest(profile_raw)
            frame['profile_sha256'] = digest(profile_raw)
            row = GuardedControllerMetadata(profile_raw, encode(context)).project(frame)['rows'][0]
            self.assertEqual(row['account_status'], 'unknown', mode)
            self.assertIsNone(row['account_token_candidate_hex'], mode)

    def test_maximum_guarded_utf8_cache_has_no_canonical_claim(self):
        _, _, out = self.project('cache')
        row = out['rows'][0]
        self.assertEqual(row['cached_label_candidate'], '人' * 21)
        self.assertEqual(row['cached_label_status'], 'observed')
        self.assertTrue(all(sample['guard_ids'] for sample in row['cached_label_evidence']))
        self.assertFalse(out['canonical_name_validated'])

    def test_invalid_cache_bytes_unknown_preserves_current_controller(self):
        decoder, frame, _ = self.project('cache')
        frame['fields']['controller_0000_cached_label_0000_byte_0000_value']['value'] = 255
        row = decoder.project(frame)['rows'][0]
        self.assertEqual(row['cached_label_reason'], 'invalid_label_utf8')
        self.assertIsNotNone(row['controller_object_key'])
        self.assertIsNone(row['cached_label_candidate'])

    def test_global_guard_gap_target_hash_and_dependency_fail_closed(self):
        decoder, original, _ = self.project()
        for mode in ('guard', 'gap', 'target', 'profile', 'dependency', 'bracket'):
            frame = copy.deepcopy(original)
            if mode == 'guard': frame['guards_after'][0]['ok'] = False
            elif mode == 'gap': frame['skipped_intervals_before'] = 1
            elif mode == 'target': frame['target']['pid'] += 1
            elif mode == 'profile': frame['profile_sha256'] = 'ff' * 32
            else:
                sample = frame['fields']['controller_0000_handle_candidate_i32']
                if mode == 'dependency': sample['guard_ids'] = []
                else: sample['read_end_ticks'] = frame['end_ticks'] + 1
            rows = decoder.project(frame)['rows']
            self.assertTrue(all(row['controller_object_key'] is None for row in rows), mode)
            self.assertTrue(all(row['account_token_candidate_hex'] is None for row in rows), mode)
        self.assertEqual(decoder.project(original)['rows'][0]['account_status'], 'guarded_raw_candidate')

    def test_context_requires_exact_full_roster_and_source(self):
        profile, context, _ = metadata_fixture('cache')
        for mode in ('roster', 'selected', 'duplicate', 'target', 'profile', 'source', 'kind'):
            broken = copy.deepcopy(context)
            if mode == 'roster': broken['roster_controller_object_keys'][1] = 'controller:' + 'fe'*32
            elif mode == 'selected': broken['controller_object_keys'][0] = 'controller:' + 'fe'*32
            elif mode == 'duplicate': broken['roster_controller_object_keys'].append(broken['roster_controller_object_keys'][0])
            elif mode == 'target': broken['target']['creation_file_time'] += 1
            elif mode == 'profile': broken['profile_sha256'] = '00'*32
            elif mode == 'source': broken['source_acquisition']['recipe_sha256'] = 'bad'
            else: broken['kind'] = 'team'
            with self.assertRaises(InvalidMetadata, msg=mode):
                GuardedControllerMetadata(profile, encode(broken))

    def test_returned_evidence_is_detached_and_no_address_leak(self):
        decoder, frame, first = self.project('cache')
        first['guard_brackets']['guards_before'][0]['ok'] = False
        first['rows'][0]['cached_label_evidence'][0]['guard_ids'].clear()
        first['source_acquisition']['recipe_sha256'] = 'changed'
        second = decoder.project(frame)
        self.assertTrue(second['guard_brackets']['guards_before'][0]['ok'])
        self.assertTrue(second['rows'][0]['cached_label_evidence'][0]['guard_ids'])
        self.assertEqual(second['source_acquisition']['recipe_sha256'], '34'*32)
        self.assertNotIn('address', json.dumps(second))
        self.assertEqual(second['native_frame_sha256'], digest(encode(frame)))

    def test_api_does_not_claim_verification_of_supplied_source_pins(self):
        _, _, out = self.project()
        self.assertEqual(out['acquisition_validation'], 'caller_verified_required')

    def test_export_checks_source_and_native_acceptance_before_output(self):
        profile, context, frame = metadata_fixture(count=1)
        for mode in ('source_mismatch', 'native_failure', 'too_many_frames', 'accepted'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                acquisition, recording, output = root/'acquisition', root/'recording', root/'output.jsonl'
                acquisition.mkdir()
                recording.mkdir()
                (acquisition/'profile.json').write_bytes(profile)
                (recording/'profile.json').write_bytes(profile)
                (recording/'samples.jsonl.gz').write_bytes(b'fixture; iterator mocked')
                (recording/'manifest.json').write_bytes(encode(dict(schema='fixture')))
                source = dict(context['source_acquisition'])
                if mode == 'source_mismatch': source['recipe_sha256'] = '78'*32
                with patch('controller_metadata.verified_census', return_value=dict(source=source)), \
                     patch('controller_metadata.native_verify') as native, \
                     patch('controller_metadata.iter_validated_frames', return_value=iter([(frame, dict(skipped_slots=0))])):
                    native.return_value = dict(frames=1001 if mode == 'too_many_frames' else 1, status='complete')
                    if mode == 'native_failure': native.side_effect = ValueError('native rejected')
                    if mode != 'accepted':
                        with self.assertRaises(ValueError):
                            export_recording(acquisition, recording, encode(context), output, ['fixture-verifier'])
                        self.assertFalse(output.exists())
                    else:
                        summary = export_recording(acquisition, recording, encode(context), output, ['fixture-verifier'])
                        self.assertEqual(summary['frames'], 1)
                        self.assertEqual(summary['output_sha256'], digest(output.read_bytes()))
                        row = json.loads(output.read_bytes())
                        self.assertEqual(row['acquisition_validation'], 'complete_native_evidence_verified')
                        self.assertTrue(row['recording_complete'])
                        self.assertEqual(row['recording_manifest_sha256'], digest((recording/'manifest.json').read_bytes()))

    def test_duplicate_json_keys_rejected(self):
        profile, context, _ = metadata_fixture()
        with self.assertRaises(InvalidMetadata):
            GuardedControllerMetadata(profile, b'{"schema":1,"schema":2}')

    def test_duplicate_full_handle_is_rejected_even_at_different_storage(self):
        raw_profile, context, _ = metadata_fixture(count=2)
        profile = json.loads(raw_profile)
        fields = {field['name']: field for field in profile['fields']}
        first = fields['controller_0000_handle_candidate_i32']['address']
        second = fields['controller_0001_handle_candidate_i32']['address']
        first_guard = next(guard for guard in profile['guards'] if guard['address'] == first)
        next(guard for guard in profile['guards'] if guard['address'] == second)['bytes_hex'] = first_guard['bytes_hex']
        raw_profile = encode(profile)
        context['profile_sha256'] = digest(raw_profile)
        with self.assertRaisesRegex(InvalidMetadata, 'ambiguous_controller_handle'):
            GuardedControllerMetadata(raw_profile, encode(context))

    def test_cache_selection_must_belong_to_complete_guarded_roster(self):
        raw_profile, context, frame = metadata_fixture('cache', count=2)
        profile = json.loads(raw_profile)
        for i, suffix in enumerate(('handle_candidate_i32', 'manager_key_candidate_i32')):
            name = 'controller_0000_' + suffix
            address, word = 0x40000 + i * 4, 777 + i
            next(field for field in profile['fields'] if field['name'] == name)['address'] = address
            profile['guards'].append(dict(address=address, bytes_hex=word.to_bytes(4, 'little').hex()))
            frame['fields'][name]['value'] = word
        raw_profile = encode(profile)
        relations = GuardedCachedLabels(raw_profile).relations
        # All supplied pins and both independently guarded identities are valid;
        # only the cross-list census membership is false.
        context['profile_sha256'] = digest(raw_profile)
        context['controller_object_keys'] = list(profile_keys(relations, relations.prefixes))
        self.assertTrue(set(context['controller_object_keys']).isdisjoint(context['roster_controller_object_keys']))
        with self.assertRaisesRegex(InvalidMetadata, 'selected_controller_absent_from_roster'):
            GuardedControllerMetadata(raw_profile, encode(context))

    def test_legacy_missing_body_payload_does_not_gate_account_candidate(self):
        raw_profile, context, frame = metadata_fixture(count=1)
        profile = json.loads(raw_profile)
        # An unrelated declared field is absent in this frame. Its guards still
        # pass; account metadata must not sample that body's payload itself.
        profile['fields'].append(dict(name='controller_0000_part51_0000_body_key_candidate_i32',
                                      type='i32', address=0x30000))
        profile['guards'].append(dict(address=0x30000, bytes_hex='00000000'))
        raw_profile = encode(profile)
        context['profile_sha256'] = frame['profile_sha256'] = digest(raw_profile)
        frame['guards_before'].append(copy.deepcopy(frame['guards_before'][0]))
        frame['guards_after'].append(copy.deepcopy(frame['guards_after'][0]))
        decoder = GuardedControllerMetadata(raw_profile, encode(context))
        for name, sampled in frame['fields'].items():
            sampled['guard_ids'] = decoder.relations.guard_ids[name].copy()
        row = decoder.project(frame)['rows'][0]
        self.assertEqual(row['account_status'], 'guarded_raw_candidate')
        self.assertIsNone(row['body_key_reference_candidate'])


if __name__ == '__main__':
    unittest.main()
