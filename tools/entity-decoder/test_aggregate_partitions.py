"""Partition ownership, temporal gaps and corrupt-source rejection tests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import aggregate_partitions as aggregate


def raw(value):
    return json.dumps(value, separators=(',', ':')).encode() + b'\n'


def pair(index):
    return dict(controller_object_key='controller:' + f'{index:064x}',
                body_object_key='body:' + f'{index+100:064x}')


def relation(index, position=1, health=100):
    return dict(pair(index), relation_status='observed', name=None, team=None,
                cached_label_candidate='fixture-' + str(index), hero_label='Fixture Hero',
                hero_resource_guid_candidate=dict(value=f'0x{index:016X}'),
                team_candidate='fixture-team', relative_allegiance_candidate='self' if index == 1 else 'friendly',
                position_candidate=dict(value=[position, 2, 3], read_start_ticks=11, read_end_ticks=12),
                health_candidate=dict(raw_sum=health), visibility='unknown')



def bind_relation(row, frame):
    profile, build = frame['profile_sha256'], frame['target']['executable_sha256']
    start, end = frame['timing']['start_ticks'], frame['timing']['end_ticks']
    acq = frame['source_artifacts']['acquisition']
    field = lambda name, value=0: dict(field=name, value=value, read_start_ticks=start+1, read_end_ticks=start+2)
    def evidence():
        return dict(profile_sha256=profile, build_sha256=build, public_state_eligible=False,
                    fields=[field('fixture-read')])
    row['position_candidate'].update(profile_sha256=profile, build_sha256=build, source='process_memory',
        type='f32x3', read_start_ticks=start+1, read_end_ticks=start+2)
    value = row['health_candidate']['raw_sum']
    row['health_candidate'].update(schema='overwatch-decoder.actor-pool-sum/1', source='process_memory', profile_sha256=profile,
        build_sha256=build, body_object_key=row['body_object_key'], acquisition_evidence_sha256=acq['evidence_sha256'],
        public_state_eligible=False, visibility='unknown', atomic=False, complete_supplied_membership_guarding=True,
        contributions=[dict(field('fixture-pool', value), pool_index=0)], read_start_ticks=start+1, read_end_ticks=start+2)
    resource = row['hero_resource_guid_candidate']
    value = int(resource['value'], 16)
    resource.update(controller_body_match=True, evidence=[field('controller-low', value),field('controller-high'),
                                                         field('body-low', value),field('body-high')])
    row['hero_label_evidence'] = dict(evidence(), mapping=dict(label=row['hero_label'], resource_guid=resource['value'], build_sha256=build))
    row['cached_label_evidence'] = dict(evidence(), privacy='private', gameplay_semantics_validated=False, acquisition=acq)
    row['name_evidence'] = evidence()
    row['raw_category_candidate'] = 0
    row['category_evidence'] = dict(evidence(), acquisition=acq, self_controller_object_key=pair(1)['controller_object_key'],
        self_fields=[field('fixture-self')], mode_scope=dict(recording_manifest_sha256=frame['source_artifacts']['manifest_sha256'],
        frame_scope=dict(first_sequence=0,last_sequence=999,start_ticks=0,end_ticks=100000)))


def fixture(root, times1=(1020, 1070), times2=(1030, 1080)):
    target = dict(pid=123, image_name='fixture.exe', creation_file_time=456,
                  executable_sha256='ab'*32, architecture='x64')
    manifest = dict(schema='overwatch-decoder.partition-research-manifest/1', epoch_id='fixture-epoch',
                    clock_domain_id='explicit-fixture-qpc-domain', target=target,
                    monotonic_frequency=1000, window_ticks=50, maximum_skew_ticks=100,
                    maximum_origin_offset_ticks=10, roster=[dict(pair(1), primary_source_id='p1'),
                    dict(pair(2), primary_source_id='p1'), dict(pair(3), primary_source_id='p2')], sources=[])
    frames = {}
    for source_id, times, indices in [('p1', times1, (1, 2)), ('p2', times2, (1, 3))]:
        metadata = dict(source_id=source_id, path=source_id+'.jsonl', profile_sha256=('11' if source_id == 'p1' else '22')*32,
                        recording_manifest_sha256=('33' if source_id == 'p1' else '44')*32,
                        acquisition_manifest_sha256=('55' if source_id == 'p1' else '66')*32,
                        objects=[pair(i) for i in indices])
        rows, previous = [], None
        for sequence, end in enumerate(times):
            rows.append(dict(schema='overwatch-decoder.entity-relations-export/1', source='process_memory', atomic=False,
                target=target, profile_sha256=metadata['profile_sha256'], public_state_eligible=False,
                visibility='unknown', recording=dict(complete=True, partial=False, status='verified_complete'),
                timing=dict(sequence=sequence, start_ticks=end-10, end_ticks=end, monotonic_frequency=1000,
                            monotonic_origin_ticks=0, utc_origin='2020-01-01T00:00:00Z'),
                source_artifacts=dict(profile_sha256=metadata['profile_sha256'],
                    manifest_sha256=metadata['recording_manifest_sha256'], samples_prefix_sha256='77'*32,
                    index_prefix_sha256='88'*32, acquisition=dict(manifest_sha256=metadata['acquisition_manifest_sha256'],
                    recipe_sha256='99'*32, evidence_sha256='aa'*32)),
                gap_before=dict(skipped_slots=0, previous_end_ticks=previous, current_start_ticks=end-10,
                                previous_values_carried=False),
                relations=[relation(i, position=10 if source_id == 'p1' else 20,
                                    health=100 if source_id == 'p1' else 99) for i in indices]))
            for row in rows[-1]['relations']:
                bind_relation(row, rows[-1])
            previous = end
        frames[source_id] = rows
        manifest['sources'].append(metadata)
    write_fixture(root, manifest, frames)
    return manifest, frames


def write_fixture(root, manifest, frames):
    for source in manifest['sources']:
        data = b''.join(raw(frame) for frame in frames[source['source_id']])
        (root/source['path']).write_bytes(data)
        source['sha256'] = aggregate.sha(data)
    (root/'manifest.json').write_bytes(raw(manifest))


class PartitionTests(unittest.TestCase):
    def test_parse_rejects_duplicate_keys_at_any_level_and_nonfinite_values(self):
        for value in (b'{"x":1,"x":2}', b'{"outer":[{"x":1,"x":2}]}',
                      b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError): aggregate.parse(value)
        self.assertEqual(aggregate.parse(b'{"b":2,"a":1}'), {'b': 2, 'a': 1})
        self.assertEqual(list(aggregate.parse(b'{"b":2,"a":1}')), ['b', 'a'])

    def test_nested_scope_charges_all_primitive_leaves_and_exact_depth_limit(self):
        timing = dict(start_ticks=0, end_ticks=10)
        budget = [0]
        aggregate.nested_scope([None] * 99999, timing, 'profile', 'build', budget)
        self.assertEqual(budget, [100000])
        with self.assertRaisesRegex(ValueError, 'nested_evidence_bound'):
            aggregate.nested_scope([None] * 100000, timing, 'profile', 'build')
        value = None
        for _ in range(24): value = [value]
        budget = [0]
        aggregate.nested_scope(value, timing, 'profile', 'build', budget)
        self.assertEqual(budget, [25])
        with self.assertRaisesRegex(ValueError, 'nested_evidence_bound'):
            aggregate.nested_scope([value], timing, 'profile', 'build')
        aggregate.nested_scope([], timing, 'profile', 'build', depth=24)
        with self.assertRaisesRegex(ValueError, 'nested_evidence_bound'):
            aggregate.nested_scope([None], timing, 'profile', 'build', depth=24)

    def test_nested_container_after_primitive_array_still_checks_all_claims(self):
        timing = dict(start_ticks=10, end_ticks=20)
        valid = dict(profile_sha256='profile', build_sha256='build', read_start_ticks=11, read_end_ticks=12)
        value = [0] * 1000 + [valid]
        budget = [7]
        aggregate.nested_scope(value, timing, 'profile', 'build', budget)
        self.assertEqual(budget, [7 + 1 + 1001 + 4])
        for key, bad in [('profile_sha256', 'stale'), ('build_sha256', 'stale'),
                         ('read_start_ticks', 9), ('read_end_ticks', 21)]:
            with self.subTest(key=key):
                corrupt = copy.deepcopy(value); corrupt[-1][key] = bad
                with self.assertRaises(ValueError):
                    aggregate.nested_scope(corrupt, timing, 'profile', 'build')

    def run_aggregate(self, root):
        report = aggregate.aggregate(root/'manifest.json', root/'output.jsonl')
        rows = [json.loads(line) for line in (root/'output.jsonl').read_bytes().splitlines()]
        return report, rows

    def test_primary_owns_dynamic_values_supporting_motion_does_not_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root)
            report, frames = self.run_aggregate(root)
            self.assertEqual(report['windows'], 2)
            self.assertEqual(report['observed_rows'], 6)
            self.assertEqual(report['all_primary_rows_observed_windows'], 2)
            self.assertEqual(report['static_conflicts'], 0)
            self.assertEqual(report['maximum_observed_skew_ticks'], 20)
            self.assertEqual(report['clock_anchor_spread_ticks'], 0)
            for frame in frames:
                self.assertFalse(frame['atomic'])
                self.assertFalse(frame['public_state_eligible'])
                self.assertFalse(frame['values_carried_between_windows'])
                row = frame['relations'][0]
                self.assertEqual(row['status'], 'observed')
                primary, support = row['authoritative_observation'], row['supporting_observations'][0]
                self.assertEqual(primary['source_id'], 'p1')
                self.assertEqual(primary['relation']['position_candidate']['value'][0], 10)
                self.assertEqual(support['relation']['position_candidate']['value'][0], 20)
                self.assertEqual(primary['relation']['health_candidate']['raw_sum'], 100)
                self.assertEqual(support['relation']['health_candidate']['raw_sum'], 99)
                self.assertFalse(support['authoritative'])
                self.assertEqual(len(row['contributor_evidence']), 2)
                self.assertIn('acquisition', primary['source_artifacts'])
            self.assertNotIn(str(root), (root/'output.jsonl').read_text())

    def test_static_label_hero_and_team_conflicts_are_unknown(self):
        for field, value in [('cached_label_candidate', 'different'), ('hero_label', 'Different Hero'),
                             ('team_candidate', 'different-team'), ('name', 'different-name'),
                             ('hero_resource_guid_candidate', dict(value='0x00000000000000FF'))]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest, frames = fixture(root)
                frames['p2'][0]['relations'][0][field] = value
                if field == 'name':
                    frames['p1'][0]['relations'][0]['name'] = 'first-name'
                elif field == 'hero_label':
                    frames['p2'][0]['relations'][0]['hero_label_evidence']['mapping']['label'] = value
                elif field == 'hero_resource_guid_candidate':
                    support = frames['p2'][0]['relations'][0]
                    support[field].update(controller_body_match=True, evidence=[
                        dict(support['hero_label_evidence']['fields'][0], value=255),
                        dict(support['hero_label_evidence']['fields'][0], value=0),
                        dict(support['hero_label_evidence']['fields'][0], value=255),
                        dict(support['hero_label_evidence']['fields'][0], value=0)])
                    support['hero_label_evidence']['mapping']['resource_guid'] = value['value']
                write_fixture(root, manifest, frames)
                report, output = self.run_aggregate(root)
                row = output[0]['relations'][0]
                self.assertEqual(row['status'], 'unknown')
                self.assertEqual(row['reason'], 'conflicting_static_observations')
                self.assertIsNone(row['authoritative_observation'])
                self.assertEqual(report['static_conflicts'], 1)
                self.assertEqual(len(row['contributor_evidence']), 2)
                self.assertEqual(output[1]['relations'][0]['status'], 'observed')

    def test_gap_missing_and_ended_primary_never_use_supporting_self(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, frames = fixture(root, times2=(1030, 1080, 1130))
            frames['p1'][1]['gap_before']['skipped_slots'] = 1
            write_fixture(root, manifest, frames)
            _, output = self.run_aggregate(root)
            for index, reason in [(1, 'gap_in_window'), (2, 'missing_frame_in_window')]:
                row = output[index]['relations'][0]
                self.assertEqual(row['reason'], reason)
                self.assertIsNone(row['authoritative_observation'])
                self.assertEqual(len(row['supporting_observations']), 1)
                self.assertEqual(output[index]['relations'][2]['status'], 'observed')

    def test_no_frame_is_carried_to_empty_window_and_latest_in_window_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, frames = fixture(root, times1=(1020, 1040, 1170), times2=(1030, 1180))
            write_fixture(root, manifest, frames)
            report, output = self.run_aggregate(root)
            self.assertEqual(report['windows'], 4)
            self.assertEqual(report['discarded_earlier_frames_in_window'], 1)
            self.assertEqual(output[0]['relations'][0]['authoritative_observation']['source_timing']['sequence'], 1)
            for frame in output[1:3]:
                self.assertTrue(all(row['status'] == 'unknown' for row in frame['relations']))
                self.assertTrue(all(row['authoritative_observation'] is None for row in frame['relations']))
                self.assertFalse(frame['values_carried_between_windows'])

    def test_long_read_span_is_stale_without_poisoning_other_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, frames = fixture(root)
            frames['p1'][0]['timing']['start_ticks'] = 900
            frames['p1'][0]['gap_before']['current_start_ticks'] = 900
            write_fixture(root, manifest, frames)
            _, output = self.run_aggregate(root)
            self.assertEqual(output[0]['relations'][0]['reason'], 'stale_or_excessive_read_span')
            self.assertEqual(output[0]['relations'][2]['status'], 'observed')
            self.assertLessEqual(output[0]['observed_skew_ticks'], 100)

    def test_native_stopped_prefix_requires_per_source_explicit_opt_in(self):
        for allowed in (False, True):
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest, frames = fixture(root)
                for frame in frames['p1']:
                    frame['recording'].update(complete=False, partial=True, status='verified_stopped')
                if allowed:
                    manifest['sources'][0]['allow_partial'] = True
                write_fixture(root, manifest, frames)
                if allowed:
                    report, output = self.run_aggregate(root)
                    self.assertEqual(report['observed_rows'], 6)
                    selected = output[0]['relations'][0]['authoritative_observation']
                    self.assertIn('source_artifacts', selected)
                    self.assertFalse(selected['source_recording']['complete'])
                    self.assertEqual(selected['source_recording']['status'], 'verified_stopped')
                else:
                    with self.assertRaisesRegex(ValueError, 'incomplete_semantic_source'):
                        self.run_aggregate(root)
                    self.assertFalse((root/'output.jsonl').exists())

    def test_wrong_clock_target_profile_provenance_or_frame_order_never_publishes(self):
        for case in ('clock', 'frequency', 'target', 'profile', 'acquisition', 'recording', 'order', 'body'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest, frames = fixture(root)
                frame = frames['p2'][0]
                if case == 'clock': frame['timing']['utc_origin'] = '2020-01-01T00:00:01Z'
                elif case == 'frequency': frame['timing']['monotonic_frequency'] = 1001
                elif case == 'target': frame['target'] = dict(frame['target'], pid=999)
                elif case == 'profile': frame['profile_sha256'] = 'ef'*32
                elif case == 'acquisition': frame['source_artifacts']['acquisition']['manifest_sha256'] = 'ef'*32
                elif case == 'recording': frame['source_artifacts']['manifest_sha256'] = 'ef'*32
                elif case == 'order': frames['p2'].reverse()
                else: frame['relations'][0]['body_object_key'] = pair(99)['body_object_key']
                write_fixture(root, manifest, frames)
                with self.assertRaises(ValueError):
                    self.run_aggregate(root)
                self.assertFalse((root/'output.jsonl').exists())
                self.assertFalse(list(root.glob('.partition-aggregate-*.partial')))

    def test_corrupt_source_and_bad_primary_manifest_are_rejected(self):
        for case in ('corruption', 'primary', 'clock_tolerance', 'skew', 'duplicate_roster'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest, _ = fixture(root)
                if case == 'corruption': (root/'p1.jsonl').write_bytes(b'corruption\n')
                elif case == 'primary': manifest['roster'][1]['primary_source_id'] = 'p2'
                elif case == 'clock_tolerance': manifest['maximum_origin_offset_ticks'] = -1
                elif case == 'skew': manifest['maximum_skew_ticks'] = 49
                else: manifest['roster'].append(copy.deepcopy(manifest['roster'][0]))
                (root/'manifest.json').write_bytes(raw(manifest))
                with self.assertRaises(ValueError):
                    self.run_aggregate(root)
                self.assertFalse((root/'output.jsonl').exists())

    def test_reopened_source_is_rehashed_before_atomic_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root)
            original = aggregate.source_frames
            changed = False
            def mutate(manifest, source_id):
                nonlocal changed
                if not changed:
                    path = root/'p1.jsonl'
                    path.write_bytes(path.read_bytes().replace(b'"value":[10,2,3]', b'"value":[11,2,3]'))
                    changed = True
                return original(manifest, source_id)
            with patch.object(aggregate, 'source_frames', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'source_changed_or_empty'):
                    self.run_aggregate(root)
            self.assertFalse((root/'output.jsonl').exists())
            self.assertFalse(list(root.glob('.partition-aggregate-*.partial')))

    def test_output_byte_limit_covers_gap_generated_windows_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root, times1=(1020,), times2=(1030,))
            report, _ = self.run_aggregate(root)
            first_size = report['output_bytes']
            self.assertEqual(first_size, (root/'output.jsonl').stat().st_size)
            (root/'output.jsonl').unlink()
            fixture(root, times1=(1020, 1170), times2=(1030, 1180))
            with patch.object(aggregate, 'project_window', wraps=aggregate.project_window) as windows:
                with self.assertRaisesRegex(ValueError, 'output_byte_limit'):
                    aggregate.aggregate(root/'manifest.json', root/'output.jsonl', first_size + 500)
                self.assertGreaterEqual(windows.call_count, 2)
                self.assertEqual(windows.call_args_list[1].args[1], 21)
                self.assertEqual(windows.call_args_list[1].args[2], {})
            self.assertFalse((root/'output.jsonl').exists())
            self.assertFalse(list(root.glob('.partition-aggregate-*.partial')))

    def test_output_byte_limit_is_bounded_and_exact_boundary_is_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root, times1=(1020,), times2=(1030,))
            report, _ = self.run_aggregate(root)
            expected = (root/'output.jsonl').read_bytes()
            (root/'output.jsonl').unlink()
            for limit in (0, -1, aggregate.MAX_TOTAL_BYTES + 1, True):
                with self.assertRaisesRegex(ValueError, 'invalid_output_byte_limit'):
                    aggregate.aggregate(root/'manifest.json', root/'output.jsonl', limit)
            limited = aggregate.aggregate(root/'manifest.json', root/'output.jsonl', len(expected))
            self.assertEqual(limited['output_bytes'], len(expected))
            self.assertEqual((root/'output.jsonl').read_bytes(), expected)

    def test_relation_availability_and_optional_field_coverage_are_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, frames = fixture(root)
            frames['p1'][0]['relations'][0]['health_candidate'] = None
            write_fixture(root, manifest, frames)
            report, output = self.run_aggregate(root)
            self.assertEqual(report['observed_rows'], 6)
            self.assertEqual(report['authoritative_field_coverage']['health_candidate'], 5)
            self.assertEqual(report['authoritative_field_coverage']['position_candidate'], 6)
            self.assertEqual(report['observed_rows_meaning'], 'primary_relation_available_not_all_optional_fields_present')
            self.assertIsNone(output[0]['relations'][0]['authoritative_observation']['relation']['health_candidate'])

    def test_nested_identity_profile_and_read_claims_cannot_escape_parent_frame(self):
        for case in ('health_body', 'health_profile', 'health_build', 'health_epoch', 'health_sum',
                     'position_bracket', 'cache_bracket', 'hero_words', 'hero_mapping', 'category_scope', 'self_bracket'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest, frames = fixture(root)
                frame = frames['p1'][0]
                row = frame['relations'][0]
                if case == 'health_body': row['health_candidate']['body_object_key'] = pair(99)['body_object_key']
                elif case == 'health_profile': row['health_candidate']['profile_sha256'] = 'ef'*32
                elif case == 'health_build': row['health_candidate']['build_sha256'] = 'ef'*32
                elif case == 'health_epoch': row['health_candidate']['acquisition_evidence_sha256'] = 'ef'*32
                elif case == 'health_sum': row['health_candidate']['raw_sum'] += 1
                elif case == 'position_bracket': row['position_candidate']['read_end_ticks'] = frame['timing']['end_ticks']+1
                elif case == 'cache_bracket': row['cached_label_evidence']['fields'][0]['read_end_ticks'] = frame['timing']['end_ticks']+1
                elif case == 'hero_words': row['hero_resource_guid_candidate']['evidence'][0]['value'] += 1
                elif case == 'hero_mapping': row['hero_label_evidence']['mapping']['label'] = 'incorrect'
                elif case == 'category_scope': row['category_evidence']['mode_scope']['recording_manifest_sha256'] = 'ef'*32
                else: row['category_evidence']['self_fields'][0]['read_end_ticks'] = frame['timing']['end_ticks']+1
                # Rehashing the forged source cannot bypass semantic admission.
                write_fixture(root, manifest, frames)
                with self.assertRaises(ValueError):
                    self.run_aggregate(root)
                self.assertFalse((root/'output.jsonl').exists())
                self.assertFalse(list(root.glob('.partition-aggregate-*.partial')))

    def test_changed_nested_provenance_and_excessive_evidence_depth_are_rejected(self):
        for case in ('provenance', 'depth'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest, frames = fixture(root)
                if case == 'provenance':
                    frames['p1'][1]['source_artifacts']['samples_prefix_sha256'] = 'ef'*32
                else:
                    extra = {}
                    current = extra
                    for _ in range(26):
                        current['next'] = {}
                        current = current['next']
                    frames['p1'][0]['relations'][0]['extra'] = extra
                write_fixture(root, manifest, frames)
                with self.assertRaises(ValueError):
                    self.run_aggregate(root)
                self.assertFalse((root/'output.jsonl').exists())

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root)
            (root/'output.jsonl').write_bytes(b'keep me\n')
            with self.assertRaises(ValueError):
                self.run_aggregate(root)
            self.assertEqual((root/'output.jsonl').read_bytes(), b'keep me\n')


if __name__ == '__main__':
    unittest.main()
