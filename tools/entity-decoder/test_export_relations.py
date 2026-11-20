"""Offline export tests. Optional native checks use a supplied private recording."""
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import export_relations as exporter
from relations import GuardedRelations
from test_names import name_fixture
from names import GuardedNames
from test_relations import fixture, prepare


def bytes_json(value):
    return (json.dumps(value, separators=(',', ':'), allow_nan=False) + '\n').encode()


def make_fixture(root, gap=False, partial=False, unknown=False, mismatch=False, hero_resource=None, cached_label=None):
    recording, acquisition = root/'recording', root/'acquisition'
    recording.mkdir()
    acquisition.mkdir()
    profile, values = fixture()
    extra = [('_body_0000_position_candidate', 'f32x3', [1.5, 2, -3]),
             ('_part83_0000_hero_resource_low_candidate_i32', 'i32', 12),
             ('_part83_0000_hero_resource_high_candidate_i32', 'i32', 34),
             ('_body_0000_hero_resource_low_candidate_i32', 'i32', 13 if mismatch else 12),
             ('_body_0000_hero_resource_high_candidate_i32', 'i32', 34)]
    if hero_resource is not None:
        for index in range(1, len(extra)):
            suffix, kind, _ = extra[index]
            word = (hero_resource >> (32 if index % 2 == 0 else 0)) & 0xffffffff
            extra[index] = suffix, kind, word if word < 2**31 else word - 2**32
    for i, (suffix, kind, value) in enumerate(extra):
        name = 'controller_0000' + suffix
        profile['fields'].append(dict(name=name, type=kind, address=0x9000 + i * 16))
        values[name] = value
    if cached_label is not None:
        for index, value in enumerate(cached_label.encode('utf-8') + b'\0'):
            name = f'controller_0000_cached_label_0000_byte_{index:04}_value'
            profile['fields'].append(dict(name=name, type='u8', address=0xa000+index))
            values[name] = value
    raw_profile = bytes_json(profile)
    projector = GuardedRelations(raw_profile)
    frames = []
    for sequence in range(2):
        _, frame = prepare(profile, values)
        start = 1000 + sequence * 100 + (100 if gap and sequence else 0)
        slot = sequence + (1 if gap and sequence else 0)
        frame.update(profile_sha256=projector.hash, sequence=sequence, scheduled_slot=slot,
                     scheduled_ticks=start, start_ticks=start, end_ticks=start+90,
                     requested_interval_ms=100, monotonic_origin_ticks=1000,
                     skipped_intervals_before=1 if gap and sequence else 0,
                     skipped_intervals_total=1 if gap and sequence else 0)
        for check in frame['guards_before']:
            check.update(start_ticks=start+1, end_ticks=start+10)
        for check in frame['guards_after']:
            check.update(start_ticks=start+80, end_ticks=start+89)
        for name, field in frame['fields'].items():
            field.update(type=projector.fields[name]['type'], reason=None,
                         read_start_ticks=start+30, read_end_ticks=start+40)
        if unknown and sequence == 1:
            frame['fields']['controller_0000_body_0000_position_candidate'].update(status='unknown', value=None, reason='read_failed')
        frames.append(frame)
    summary = dict(kind='summary', target=profile['target'], profile_sha256=projector.hash)
    chunks = []
    compressed = bytearray()
    raw_all = bytearray()
    first = 0
    for sequence, chunk_frames in enumerate([[frames[0]], [frames[1], summary]]):
        raw = b''.join(bytes_json(frame) for frame in chunk_frames)
        member = gzip.compress(raw, mtime=0)
        entry = dict(schema='overwatch-decoder.field-recording-chunk/1', sequence=sequence, offset=len(compressed),
                     compressed_bytes=len(member), json_bytes=len(raw), first_line=first, lines=len(chunk_frames),
                     compressed_sha256=exporter.digest(member), json_sha256=exporter.digest(raw))
        chunks.append(entry)
        compressed.extend(member)
        raw_all.extend(raw)
        first += len(chunk_frames)
    index = b''.join(bytes_json(chunk) for chunk in chunks)
    manifest = dict(schema='overwatch-decoder.field-recording/1', target=profile['target'], profile_sha256=projector.hash)
    for path, content in [(recording/'profile.json', raw_profile), (recording/'manifest.json', bytes_json(manifest)),
                          (recording/'chunks.jsonl', index), (recording/'samples.jsonl.gz', compressed),
                          (acquisition/'profile.json', raw_profile)]:
        path.write_bytes(content)
    recipe = dict(target={k: profile['target'][k] for k in ['image_name', 'executable_sha256', 'architecture']}, stages=[dict(name='reciprocal_fixture')])
    (acquisition/'recipe.json').write_bytes(bytes_json(recipe))
    (acquisition/'evidence.jsonl').write_bytes(b'{"fixture":true}\n')
    acquisition_manifest = dict(schema='overwatch-decoder.acquisition-result/1', complete=True, error=None,
        target=profile['target'], profile_sha256=projector.hash, stages_completed=1,
        recipe_sha256=exporter.file_digest(acquisition/'recipe.json'), evidence_sha256=exporter.file_digest(acquisition/'evidence.jsonl'))
    (acquisition/'manifest.json').write_bytes(bytes_json(acquisition_manifest))
    verified = dict(valid=True, complete=not partial, status='verified_stopped' if partial else 'verified_complete',
                    verified_chunks=2, verified_compressed_bytes=len(compressed), verified_lines=3, frames=2,
                    profile_sha256=projector.hash, samples_prefix_sha256=exporter.digest(compressed),
                    index_prefix_sha256=exporter.digest(index), json_prefix_sha256=exporter.digest(raw_all),
                    unverified_compressed_bytes=0, unverified_index_bytes=0)
    return recording, acquisition, verified, frames, projector


class ExportTests(unittest.TestCase):
    def run_export(self, root, recording, acquisition, verified, **kwargs):
        with patch.object(exporter, 'native_verify', return_value=verified):
            return exporter.export_recording(recording, acquisition, root/'output.jsonl', ['fake-offline-verifier'], **kwargs)

    def test_real_frame_projection_with_sources_positions_resources_and_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recording, acquisition, verified, _, _ = make_fixture(root, gap=True)
            report = self.run_export(root, recording, acquisition, verified)
            rows = [json.loads(line) for line in (root/'output.jsonl').read_text().splitlines()]
            self.assertEqual(report['frames'], 2)
            self.assertEqual(report['observed_positions'], 2)
            self.assertEqual(report['matching_hero_resources'], 2)
            self.assertEqual(report['frames_after_skipped_slots'], 1)
            relation = rows[1]['relations'][0]
            self.assertEqual(relation['position_candidate']['value'], [1.5, 2, -3])
            self.assertEqual(relation['hero_resource_guid_candidate']['value'], '0x000000220000000C')
            self.assertIsNone(relation['name'])
            self.assertIsNone(relation['team'])
            self.assertIsNone(relation['hero_label'])
            self.assertEqual(relation['visibility'], 'unknown')
            self.assertIs(rows[1]['continuity_across_gaps'], False)
            self.assertEqual(rows[1]['gap_before']['skipped_slots'], 1)
            self.assertIs(rows[1]['gap_before']['previous_values_carried'], False)
            self.assertIn('acquisition', rows[1]['source_artifacts'])
            self.assertNotIn(str(root), (root/'output.jsonl').read_text())

    def test_unknown_position_is_not_carried_and_hero_mismatch_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recording, acquisition, verified, _, _ = make_fixture(root, unknown=True, mismatch=True)
            self.run_export(root, recording, acquisition, verified)
            rows = [json.loads(line) for line in (root/'output.jsonl').read_text().splitlines()]
            self.assertIsNotNone(rows[0]['relations'][0]['position_candidate'])
            self.assertIsNone(rows[1]['relations'][0]['position_candidate'])
            self.assertTrue(all(r['relations'][0]['hero_resource_guid_candidate'] is None for r in rows))

    def test_corrupt_sample_index_profile_and_acquisition_do_not_publish(self):
        for target in ['samples.jsonl.gz', 'chunks.jsonl', 'profile.json', 'acquisition-evidence']:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                recording, acquisition, verified, _, _ = make_fixture(root)
                path = acquisition/'evidence.jsonl' if target == 'acquisition-evidence' else recording/target
                value = bytearray(path.read_bytes())
                value[len(value)//2] ^= 1
                path.write_bytes(value)
                with self.assertRaises((ValueError, KeyError, OSError)):
                    self.run_export(root, recording, acquisition, verified)
                self.assertFalse((root/'output.jsonl').exists())
                self.assertFalse(list(root.glob('.entity-export-*.partial')))

    def test_reordered_chunks_and_changed_process_do_not_publish(self):
        for target in ['order', 'process']:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                recording, acquisition, verified, _, _ = make_fixture(root)
                path = recording/('chunks.jsonl' if target == 'order' else 'manifest.json')
                if target == 'order':
                    path.write_bytes(b''.join(reversed(path.read_bytes().splitlines(keepends=True))))
                else:
                    manifest = json.loads(path.read_text())
                    manifest['target']['creation_file_time'] += 1
                    path.write_bytes(bytes_json(manifest))
                with self.assertRaises(ValueError):
                    self.run_export(root, recording, acquisition, verified)
                self.assertFalse((root/'output.jsonl').exists())

    def test_partial_result_remains_explicit_and_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recording, acquisition, verified, _, _ = make_fixture(root, partial=True)
            self.run_export(root, recording, acquisition, verified, allow_partial=True)
            row = json.loads((root/'output.jsonl').read_text().splitlines()[0])
            self.assertTrue(row['recording']['partial'])
            original = (root/'output.jsonl').read_bytes()
            with self.assertRaises(ValueError):
                self.run_export(root, recording, acquisition, verified)
            self.assertEqual((root/'output.jsonl').read_bytes(), original)

    def test_health_composition_receives_native_frame_and_exact_base_projection(self):
        profile, values = fixture()
        projector, frame = prepare(profile, values)
        class Contract:
            def project(self, observed, relation_projection, gap):
                self.observed, self.gap = observed, gap
                if gap:
                    return None
                return dict(body_object_key=relation_projection['relations'][0]['body_object_key'], raw_sum=100)
        contract = Contract()
        row = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=0), [contract])
        self.assertIs(contract.observed, frame)
        self.assertEqual(row['relations'][0]['health_candidate']['raw_sum'], 100)
        row = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=1), [contract])
        self.assertIsNone(row['relations'][0]['health_candidate'])

    def test_display_name_default_omits_discriminator_and_full_name_hash(self):
        profile, _, names, frame = name_fixture()
        projector = names.relations
        default = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=0), name_projector=names)
        row = default['relations'][0]
        self.assertEqual(row['name'], 'Example')
        self.assertNotIn('private_battletag', row)
        self.assertNotIn('private_name_bytes_sha256', row)
        self.assertNotIn('Example#1234', json.dumps(default))
        self.assertNotIn(hashlib.sha256(b'Example#1234').hexdigest(), json.dumps(default))
        private = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=0),
                                         name_projector=names, include_private_battletags=True)
        self.assertEqual(private['relations'][0]['private_battletag'], 'Example#1234')
        self.assertTrue(private['private_battletag_output_enabled'])

    def test_names_never_join_by_prefix_or_cross_gaps_and_unknown_bytes(self):
        _, _, names, frame = name_fixture()
        projector = names.relations
        real_projection = names.project(frame)
        class OtherObject:
            def project(self, _):
                result = copy.deepcopy(real_projection)
                result['names'][0]['controller_object_key'] = 'controller:another'
                return result
        other = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=0), name_projector=OtherObject())
        self.assertIsNone(other['relations'][0]['name'])
        after_gap = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=1), name_projector=names)
        self.assertIsNone(after_gap['relations'][0]['name'])
        frame['fields']['controller_0000_name_0000_byte_0000_value']['status'] = 'unknown'
        unknown = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=0), name_projector=names)
        self.assertIsNone(unknown['relations'][0]['name'])

    def test_name_source_requires_separately_validated_recipe_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recording, acquisition, verified, _, _ = make_fixture(root)
            with self.assertRaisesRegex(ValueError, 'unverified_name_recipe'):
                self.run_export(root, recording, acquisition, verified, name_projector=object())
            with self.assertRaisesRegex(ValueError, 'unverified_name_recipe'):
                self.run_export(root, recording, acquisition, verified, name_projector=object(), name_recipe_sha256='00'*32)
            self.assertFalse((root/'output.jsonl').exists())

    def test_native_rejection_requires_explicit_partial_policy(self):
        result = dict(valid=True, complete=False, status='verified_stopped')
        response = type('Completed', (), dict(stdout=json.dumps(dict(command='verify-fields', ok=True, result=result))))()
        with patch.object(exporter.subprocess, 'run', return_value=response):
            with self.assertRaises(ValueError):
                exporter.native_verify(Path('.'), ['fixture'], False)
            self.assertEqual(exporter.native_verify(Path('.'), ['fixture'], True), result)


class HeroCompositionTests(unittest.TestCase):
    def setUp(self):
        from hero_labels import GuardedHeroLabels, HeroLabelCatalog
        from test_hero_labels import evidence_fixture, raw
        self.profile, self.frame, self.catalog, self.artifacts, _, _ = evidence_fixture()
        self.raw = raw
        self.decoder = GuardedHeroLabels(self.profile, HeroLabelCatalog(raw(self.catalog), self.artifacts))
        self.projector = self.decoder.relations
        for name, field in self.frame['fields'].items():
            field.update(type=self.projector.fields[name]['type'], reason=None)

    def project(self, decoder=None, gap=0):
        return exporter.project_frame(self.projector, self.frame, {}, {}, dict(skipped_slots=gap),
                                      hero_projector=self.decoder if decoder is None else decoder)

    def test_complete_export_preserves_gap_nulls_and_counts_hero_labels(self):
        from hero_labels import GuardedHeroLabels
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recording, acquisition, verified, _, _ = make_fixture(root, gap=True, hero_resource=0x02E00000000000FF)
            hero = GuardedHeroLabels((recording/'profile.json').read_bytes(), self.decoder.catalog)
            with patch.object(exporter, 'native_verify', return_value=verified):
                report = exporter.export_recording(recording, acquisition, root/'output.jsonl', ['offline'], hero_projector=hero)
            rows = [json.loads(line) for line in (root/'output.jsonl').read_text().splitlines()]
            self.assertEqual(report['matching_hero_resources'], 2)
            self.assertEqual(report['observed_hero_labels'], 1)
            self.assertEqual(rows[0]['relations'][0]['hero_label'], 'Synthetic Hero')
            self.assertIsNone(rows[1]['relations'][0]['hero_label'])
            self.assertEqual(rows[1]['relations'][0]['hero_label_reason'], 'gap_before_frame')
            self.assertNotIn(str(root), (root/'output.jsonl').read_text())

    def test_label_composes_exact_resource_with_mapping_and_read_evidence(self):
        result = self.project()
        row = result['relations'][0]
        self.assertEqual(row['hero_label'], 'Synthetic Hero')
        self.assertEqual(row['hero_label_evidence']['mapping']['resource_guid'], row['hero_resource_guid_candidate']['value'])
        self.assertEqual(len(row['hero_label_evidence']['fields']), 4)
        self.assertFalse(row['hero_label_evidence']['public_state_eligible'])
        self.assertEqual(row['visibility'], 'unknown')
        self.assertIsNone(row['name'])
        self.assertIsNone(row['team'])
        self.assertIsNone(self.project(gap=1)['relations'][0]['hero_label'])

    def test_exact_keys_resource_and_same_frame_are_required(self):
        real = self.decoder.project(self.frame)
        for case in ('controller', 'body', 'duplicate', 'resource', 'timing', 'profile', 'target'):
            with self.subTest(case=case):
                result = copy.deepcopy(real)
                if case in ('controller', 'body'):
                    result['heroes'][0][case+'_object_key'] = 'different-object'
                elif case == 'duplicate':
                    result['heroes'].append(copy.deepcopy(result['heroes'][0]))
                elif case == 'resource':
                    result['heroes'][0]['resource_guid'] = '0x02E00000000000FE'
                elif case == 'timing':
                    result['timing']['start_ticks'] += 1
                elif case == 'profile':
                    result['profile_sha256'] = 'ef'*32
                else:
                    result['target']['creation_file_time'] += 1
                class Supplied:
                    def project(self, frame, gap=False):
                        return result
                if case in ('timing', 'profile', 'target'):
                    with self.assertRaisesRegex(ValueError, 'hero_projection_source_mismatch'):
                        self.project(Supplied())
                else:
                    self.assertIsNone(self.project(Supplied())['relations'][0]['hero_label'])
        # A valid previous projection cannot carry a label into a declared gap.
        class Previous:
            def project(self, frame, gap=False):
                return real
        self.assertIsNone(self.project(Previous(), gap=1)['relations'][0]['hero_label'])

    def test_wrong_build_and_resource_mismatch_stay_unknown_without_fallback(self):
        from hero_labels import GuardedHeroLabels
        profile = json.loads(self.profile)
        profile['target']['executable_sha256'] = 'ef'*32
        self.profile = self.raw(profile)
        self.projector = GuardedRelations(self.profile)
        self.frame.update(profile_sha256=self.projector.hash, target=profile['target'])
        self.decoder = GuardedHeroLabels(self.profile, self.decoder.catalog)
        self.frame['cached_label'] = 'Synthetic Hero'
        self.assertIsNone(self.project()['relations'][0]['hero_label'])
        name = 'controller_0000_body_0000_hero_resource_low_candidate_i32'
        self.frame['fields'][name]['value'] += 1
        self.assertIsNone(self.project()['relations'][0]['hero_resource_guid_candidate'])
        self.assertIsNone(self.project()['relations'][0]['hero_label'])

    def write_evidence(self, root):
        (root/'catalog.json').write_bytes(self.raw(self.catalog))
        paths = {}
        for sha, data in self.artifacts.items():
            name = sha+'.artifact'
            (root/name).write_bytes(data)
            paths[sha] = name
        (root/'paths.json').write_bytes(self.raw(paths))
        return paths

    def test_local_manifest_loads_relative_artifacts_and_rejects_missing_corruption(self):
        for case in ('valid', 'missing_file', 'missing_reference', 'corrupt'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                paths = self.write_evidence(root)
                sha = self.catalog['entries'][0]['asset_report_sha256']
                if case == 'missing_file':
                    (root/paths[sha]).unlink()
                elif case == 'missing_reference':
                    del paths[sha]
                    (root/'paths.json').write_bytes(self.raw(paths))
                elif case == 'corrupt':
                    (root/paths[sha]).write_bytes(b'corruption')
                if case == 'valid':
                    loaded = exporter.load_hero_projector(self.profile, root/'catalog.json', root/'paths.json')
                    self.assertEqual(self.project(loaded)['relations'][0]['hero_label'], 'Synthetic Hero')
                else:
                    with self.assertRaises((ValueError, OSError)):
                        exporter.load_hero_projector(self.profile, root/'catalog.json', root/'paths.json')

    def test_local_manifest_bounds_reject_remote_paths_large_or_nonregular_files(self):
        for case in ('url', 'large', 'directory', 'duplicate'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                paths = self.write_evidence(root)
                sha = next(iter(paths))
                if case == 'url':
                    paths[sha] = 'https://invalid.example/artifact'
                elif case == 'large':
                    with (root/paths[sha]).open('wb') as file:
                        file.truncate(16*1024*1024+1)
                elif case == 'directory':
                    paths[sha] = '.'
                if case == 'duplicate':
                    (root/'paths.json').write_text('{"'+sha+'":"a","'+sha+'":"b"}')
                else:
                    (root/'paths.json').write_bytes(self.raw(paths))
                with self.assertRaises((ValueError, OSError)):
                    exporter.load_hero_projector(self.profile, root/'catalog.json', root/'paths.json')


class CachedLabelCompositionTests(unittest.TestCase):
    def setUp(self):
        from test_cached_labels import label_fixture
        _, self.decoder, self.frame = label_fixture(rows=2)
        self.projector = self.decoder.relations

    def project(self, decoder=None, gap=0):
        return exporter.project_frame(self.projector, self.frame, {}, {}, dict(skipped_slots=gap),
                     cached_label_projector=self.decoder if decoder is None else decoder)

    def test_opt_in_cache_text_is_separate_from_name_hero_and_public_state(self):
        default = exporter.project_frame(self.projector, self.frame, {}, {}, dict(skipped_slots=0))
        self.assertFalse(default['cached_label_output_enabled'])
        self.assertNotIn('cached_label_candidate', default['relations'][0])
        result = self.project()
        self.assertTrue(result['cached_label_output_enabled'])
        first, second = result['relations']
        self.assertEqual(first['cached_label_candidate'], 'Example')
        self.assertIsNone(second['cached_label_candidate'])
        for row in result['relations']:
            self.assertIsNone(row['name'])
            self.assertIsNone(row['hero_label'])
            self.assertIsNone(row['team'])
            self.assertEqual(row['visibility'], 'unknown')
        evidence = first['cached_label_evidence']
        self.assertFalse(evidence['gameplay_semantics_validated'])
        self.assertFalse(evidence['public_state_eligible'])
        self.assertEqual(evidence['privacy'], 'private')
        self.assertTrue(evidence['fields'])
        self.assertNotIn('address', json.dumps(evidence))

    def test_cache_never_joins_different_keys_duplicates_unknown_bodies_or_gaps(self):
        original = self.decoder.project(self.frame)
        for case in ('controller', 'body', 'duplicate', 'gap', 'absent_body'):
            with self.subTest(case=case):
                projection = copy.deepcopy(original)
                if case in ('controller', 'body'):
                    projection['labels'][0][case+'_object_key'] = 'other-object'
                elif case == 'duplicate':
                    projection['labels'].append(copy.deepcopy(projection['labels'][0]))
                elif case == 'absent_body':
                    projection['labels'][0]['body_object_key'] = None
                class Supplied:
                    def project(self, frame):
                        return projection
                self.assertIsNone(self.project(Supplied(), gap=case == 'gap')['relations'][0]['cached_label_candidate'])
        self.frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        self.assertEqual(self.decoder.project(self.frame)['labels'][0]['status'], 'observed')
        self.assertIsNone(self.project()['relations'][0]['cached_label_candidate'])

    def test_profile_target_timing_and_research_contract_are_checked(self):
        original = self.decoder.project(self.frame)
        for case in ('schema', 'profile', 'target', 'timing', 'privacy', 'semantics', 'public'):
            with self.subTest(case=case):
                projection = copy.deepcopy(original)
                if case == 'schema': projection['schema'] = 'other'
                elif case == 'profile': projection['profile_sha256'] = 'ab'*32
                elif case == 'target': projection['target']['executable_sha256'] = 'cd'*32
                elif case == 'timing': projection['timing']['sequence'] += 1
                elif case == 'privacy': projection['privacy'] = 'public'
                elif case == 'semantics': projection['gameplay_semantics_validated'] = True
                else: projection['public_state_eligible'] = True
                class Supplied:
                    def project(self, frame):
                        return projection
                with self.assertRaisesRegex(ValueError, 'cached_label_projection_source_mismatch'):
                    self.project(Supplied())

    def test_missing_bytes_guard_failure_and_changed_process_do_not_carry_label(self):
        for case in ('missing', 'guard', 'process'):
            with self.subTest(case=case):
                saved = copy.deepcopy(self.frame)
                if case == 'missing':
                    self.frame['fields'].pop('controller_0000_cached_label_0000_byte_0000_value')
                elif case == 'guard': self.frame['guards_after'][0]['ok'] = False
                else: self.frame['target']['creation_file_time'] += 1
                self.assertIsNone(self.project()['relations'][0]['cached_label_candidate'])
                self.frame = saved
        self.assertEqual(self.project()['relations'][0]['cached_label_candidate'], 'Example')

    def test_export_requires_recipe_pin_and_keeps_source_hashes_and_gap_nulls(self):
        from cached_labels import GuardedCachedLabels
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recording, acquisition, verified, _, _ = make_fixture(root, gap=True, cached_label='Synthetic')
            decoder = GuardedCachedLabels((recording/'profile.json').read_bytes())
            with patch.object(exporter, 'native_verify', return_value=verified):
                for pin in (None, 'ef'*32):
                    with self.assertRaisesRegex(ValueError, 'unverified_cached_label_recipe'):
                        exporter.export_recording(recording, acquisition, root/'output.jsonl', ['offline'],
                            cached_label_projector=decoder, cached_label_recipe_sha256=pin)
                    self.assertFalse((root/'output.jsonl').exists())
                pin = json.loads((acquisition/'manifest.json').read_bytes())['recipe_sha256']
                report = exporter.export_recording(recording, acquisition, root/'output.jsonl', ['offline'],
                            cached_label_projector=decoder, cached_label_recipe_sha256=pin)
            self.assertEqual(report['observed_cached_label_candidates'], 1)
            rows = [json.loads(line) for line in (root/'output.jsonl').read_text().splitlines()]
            self.assertEqual(rows[0]['relations'][0]['cached_label_candidate'], 'Synthetic')
            self.assertEqual(rows[0]['relations'][0]['cached_label_evidence']['acquisition']['recipe_sha256'], pin)
            self.assertEqual(rows[0]['source_artifacts']['profile_sha256'], verified['profile_sha256'])
            self.assertIsNone(rows[1]['relations'][0]['cached_label_candidate'])
            self.assertEqual(rows[1]['relations'][0]['cached_label_reason'], 'gap_before_frame')


class CategoryCompositionTests(unittest.TestCase):
    class SuppliedCategories:
        """Projection stub tests exporter boundaries; native semantics live elsewhere."""
        contract_sha256 = 'de'*32
        recording_manifest_sha256 = 'ef'*32
        self_controller_object_key = 'controller:fixture-self'

        def __init__(self, projector, source=None):
            self.projector, self.source = projector, source or {}
            self.mutate = lambda result: None

        def project(self, frame, gap=False):
            base = self.projector.project(frame)
            result = {key: copy.deepcopy(value) for key, value in base.items() if key != 'relations'}
            result.update(schema='overwatch-decoder.guarded-actor-categories/1', contract_sha256=self.contract_sha256,
                          source_evidence=dict(self.source), mode_id='fixture-mode',
                          recording_manifest_sha256=self.recording_manifest_sha256,
                          self_controller_object_key=self.self_controller_object_key,
                          native_review_sha256='ab'*32, roster_review_sha256='bc'*32,
                          rows=[dict(controller_object_key=row['controller_object_key'],
                                     body_object_key=row['body_object_key'], status='observed',
                                     raw_category_candidate=7, team_candidate='fixture-team',
                                     relative_allegiance_candidate='self', evidence=[dict(field='fixture_category')],
                                     self_evidence=[dict(field='fixture_self_category', read_start_ticks=30, read_end_ticks=40)],
                                     mode_scope=dict(mode_id='fixture-mode', recording_manifest_sha256=self.recording_manifest_sha256))
                                for row in base['relations']])
            self.mutate(result)
            return result

    def setUp(self):
        profile, values = fixture()
        self.projector, self.frame = prepare(profile, values)
        self.categories = self.SuppliedCategories(self.projector)

    def project(self, gap=0):
        return exporter.project_frame(self.projector, self.frame, {}, {}, dict(skipped_slots=gap),
                                      category_projector=self.categories)

    def test_validated_category_contract_loader_and_finite_scope_composition(self):
        from test_categories import category_fixture, raw
        profile, _, frame, contract, artifacts, _, _ = category_fixture()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'contract.json').write_bytes(raw(contract))
            paths = {}
            for sha, data in artifacts.items():
                paths[sha] = sha+'.artifact'
                (root/paths[sha]).write_bytes(data)
            (root/'paths.json').write_bytes(bytes_json(paths))
            categories = exporter.load_category_projector(raw(profile), root/'contract.json', root/'paths.json')
            projector = categories.relations
            result = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=0), category_projector=categories)
            self.assertEqual([r['relative_allegiance_candidate'] for r in result['relations']], ['self', 'friendly', 'enemy'])
            self.assertEqual(result['relations'][1]['category_evidence']['self_fields'][2]['field'], 'category_0')
            self.assertEqual(result['relations'][0]['category_evidence']['mode_scope']['recording_manifest_sha256'], contract['recording_manifest_sha256'])
            frame['sequence'] = 4
            outside = exporter.project_frame(projector, frame, {}, {}, dict(skipped_slots=0), category_projector=categories)
            self.assertTrue(all(r['raw_category_candidate'] is None for r in outside['relations']))
            self.assertTrue(all(r['category_reason'] == 'unvalidated_recording_interval' for r in outside['relations']))
            (root/paths[contract['native_review_sha256']]).write_bytes(b'corruption')
            with self.assertRaisesRegex(ValueError, 'category_artifact_hash'):
                exporter.load_category_projector(raw(profile), root/'contract.json', root/'paths.json')

    def test_categories_are_opt_in_separate_candidates_with_contract_provenance(self):
        default = exporter.project_frame(self.projector, self.frame, {}, {}, dict(skipped_slots=0))
        self.assertFalse(default['category_output_enabled'])
        self.assertNotIn('raw_category_candidate', default['relations'][0])
        result = self.project()
        row = result['relations'][0]
        self.assertEqual(row['raw_category_candidate'], 7)
        self.assertEqual(row['team_candidate'], 'fixture-team')
        self.assertEqual(row['relative_allegiance_candidate'], 'self')
        self.assertEqual(row['category_evidence']['contract_sha256'], self.categories.contract_sha256)
        self.assertEqual(row['category_evidence']['self_fields'][0]['read_start_ticks'], 30)
        self.assertEqual(row['category_evidence']['mode_id'], 'fixture-mode')
        self.assertEqual(row['category_evidence']['roster_review_sha256'], 'bc'*32)
        self.assertFalse(row['category_evidence']['public_state_eligible'])
        self.assertIsNone(row['team'])
        self.assertIsNone(row['name'])
        self.assertIsNone(row['hero_label'])
        self.assertEqual(row['visibility'], 'unknown')

    def test_categories_require_exact_keys_unique_rows_observed_relation_and_no_gap(self):
        for case in ('controller', 'body', 'duplicate', 'unobserved'):
            with self.subTest(case=case):
                def mutate(result):
                    if case in ('controller', 'body'):
                        result['rows'][0][case+'_object_key'] = 'different-object'
                    elif case == 'duplicate': result['rows'] *= 2
                    else: result['rows'][0]['status'] = 'unknown'
                self.categories.mutate = mutate
                self.assertIsNone(self.project()['relations'][0]['raw_category_candidate'])
        self.categories.mutate = lambda result: None
        self.assertIsNone(self.project(gap=1)['relations'][0]['raw_category_candidate'])
        self.frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        row = self.project()['relations'][0]
        self.assertIsNone(row['raw_category_candidate'])
        self.assertIsNone(row['team_candidate'])
        self.assertIsNone(row['relative_allegiance_candidate'])

    def test_category_source_profile_process_timing_and_contract_cannot_be_substituted(self):
        for case in ('schema', 'profile', 'target', 'timing', 'contract', 'source', 'recording', 'self', 'public', 'visibility'):
            with self.subTest(case=case):
                def mutate(result):
                    if case == 'schema': result['schema'] = 'other'
                    elif case == 'profile': result['profile_sha256'] = 'ef'*32
                    elif case == 'target': result['target']['creation_file_time'] += 1
                    elif case == 'timing': result['timing']['sequence'] += 1
                    elif case == 'contract': result['contract_sha256'] = 'ab'*32
                    elif case == 'source': result['source_evidence'] = {'recipe_sha256': 'ab'*32}
                    elif case == 'recording': result['recording_manifest_sha256'] = 'ab'*32
                    elif case == 'self': result['self_controller_object_key'] = 'controller:other'
                    elif case == 'public': result['public_state_eligible'] = True
                    else: result['visibility'] = 'visible'
                self.categories.mutate = mutate
                with self.assertRaisesRegex(ValueError, 'category_projection_source_mismatch'):
                    self.project()

    def test_export_checks_recipe_and_evidence_pins_before_publishing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recording, acquisition, verified, _, projector = make_fixture(root, gap=True)
            manifest = json.loads((acquisition/'manifest.json').read_bytes())
            source = {key: manifest[key] for key in ('recipe_sha256', 'evidence_sha256')}
            categories = self.SuppliedCategories(projector, source)
            categories.recording_manifest_sha256 = exporter.file_digest(recording/'manifest.json')
            with patch.object(exporter, 'native_verify', return_value=verified):
                for key in ('recipe_sha256', 'evidence_sha256'):
                    categories.source = dict(source, **{key: 'ef'*32})
                    with self.assertRaisesRegex(ValueError, 'category_acquisition_mismatch'):
                        exporter.export_recording(recording, acquisition, root/'output.jsonl', ['offline'],
                                                  category_projector=categories)
                    self.assertFalse((root/'output.jsonl').exists())
                categories.source = source
                valid_manifest_hash = categories.recording_manifest_sha256
                categories.recording_manifest_sha256 = 'ef'*32
                with self.assertRaisesRegex(ValueError, 'category_recording_mismatch'):
                    exporter.export_recording(recording, acquisition, root/'output.jsonl', ['offline'],
                                              category_projector=categories)
                self.assertFalse((root/'output.jsonl').exists())
                categories.recording_manifest_sha256 = valid_manifest_hash
                report = exporter.export_recording(recording, acquisition, root/'output.jsonl', ['offline'],
                                                  category_projector=categories)
            self.assertEqual(report['observed_category_candidates'], 1)
            rows = [json.loads(line) for line in (root/'output.jsonl').read_text().splitlines()]
            self.assertEqual(rows[0]['relations'][0]['category_evidence']['acquisition']['evidence_sha256'], source['evidence_sha256'])
            self.assertIsNone(rows[1]['relations'][0]['raw_category_candidate'])
            self.assertEqual(rows[1]['relations'][0]['category_reason'], 'gap_before_frame')


@unittest.skipUnless(os.environ.get('OVERWATCH_DECODER_ENTITY_RECORDING') and os.environ.get('OVERWATCH_DECODER_ENTITY_ACQUISITION')
                     and os.environ.get('OVERWATCH_DECODER_ENTITY_OBSERVER') and os.environ.get('OVERWATCH_DECODER_DOTNET'), 'optional real native recording')
class NativeSourceTests(unittest.TestCase):
    def command(self):
        return [os.environ['OVERWATCH_DECODER_DOTNET'], os.environ['OVERWATCH_DECODER_ENTITY_OBSERVER']]

    def test_real_recording_and_native_corruption_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, acquisition = Path(os.environ['OVERWATCH_DECODER_ENTITY_RECORDING']), Path(os.environ['OVERWATCH_DECODER_ENTITY_ACQUISITION'])
            report = exporter.export_recording(source, acquisition, root/'valid.jsonl', self.command())
            self.assertGreater(report['observed_relations'], 0)
            self.assertEqual(report['frames'], report['observed_positions'])
            copied = root/'corrupt'
            copied.mkdir()
            for name in ['profile.json', 'manifest.json', 'samples.jsonl.gz', 'chunks.jsonl']:
                shutil.copyfile(source/name, copied/name)
            path = copied/'samples.jsonl.gz'
            raw = bytearray(path.read_bytes())
            raw[len(raw)//2] ^= 1
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'native_source_rejected'):
                exporter.export_recording(copied, acquisition, root/'invalid.jsonl', self.command())
            self.assertFalse((root/'invalid.jsonl').exists())
            partial = root/'partial'
            partial.mkdir()
            for name in ['profile.json', 'manifest.json', 'samples.jsonl.gz', 'chunks.jsonl']:
                shutil.copyfile(source/name, partial/name)
            path = partial/'samples.jsonl.gz'
            path.write_bytes(path.read_bytes()[:-10])
            with self.assertRaisesRegex(ValueError, 'native_source_rejected'):
                exporter.export_recording(partial, acquisition, root/'not-opted-in.jsonl', self.command())
            recovered = exporter.export_recording(partial, acquisition, root/'recovered.jsonl', self.command(), allow_partial=True)
            self.assertFalse(recovered['source_complete'])
            self.assertEqual(recovered['source_status'], 'recoverable_prefix')
            self.assertGreater(recovered['frames'], 0)
            self.assertLess(recovered['frames'], report['frames'])
            rows = [json.loads(line) for line in (root/'recovered.jsonl').read_text().splitlines()]
            self.assertTrue(all(row['recording']['partial'] for row in rows))
            self.assertTrue(all(row['recording']['error_code'] is not None for row in rows))


@unittest.skipUnless(os.environ.get('OVERWATCH_DECODER_ENTITY_NAME_RECORDING') and os.environ.get('OVERWATCH_DECODER_ENTITY_NAME_ACQUISITION')
                     and os.environ.get('OVERWATCH_DECODER_ENTITY_OBSERVER') and os.environ.get('OVERWATCH_DECODER_DOTNET'), 'optional real native name recording')
class NativeNameSourceTests(unittest.TestCase):
    def test_display_only_export_does_not_serialize_full_tag_or_its_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(os.environ['OVERWATCH_DECODER_ENTITY_NAME_RECORDING'])
            acquisition = Path(os.environ['OVERWATCH_DECODER_ENTITY_NAME_ACQUISITION'])
            names = GuardedNames((source/'profile.json').read_bytes())
            with gzip.open(source/'samples.jsonl.gz', 'rt') as file:
                first = json.loads(next(file))
            expected = names.project(first)['names'][0]
            output = Path(temp)/'display-only.jsonl'
            recipe_hash = json.loads((acquisition/'manifest.json').read_text())['recipe_sha256']
            report = exporter.export_recording(source, acquisition, output,
                [os.environ['OVERWATCH_DECODER_DOTNET'], os.environ['OVERWATCH_DECODER_ENTITY_OBSERVER']],
                name_projector=names, name_recipe_sha256=recipe_hash)
            text = output.read_text()
            self.assertNotIn(expected['private_name'], text)
            self.assertNotIn(expected['name_bytes_sha256'], text)
            self.assertNotIn('private_battletag"', text)
            self.assertGreater(report['observed_display_names'], 0)
            rows = [json.loads(line) for line in text.splitlines()]
            self.assertEqual(rows[0]['relations'][0]['name'], expected['display_name'])
            self.assertTrue(all(row['relations'][0]['name'] is None for row in rows if row['gap_before']['skipped_slots']))


if __name__ == '__main__':
    unittest.main()
