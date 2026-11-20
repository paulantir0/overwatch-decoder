"""Synthetic live ownership, epoch admission, watermark and resource bounds."""
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import aggregate_live_partitions as live
from test_aggregate_partitions import fixture, pair, raw


def live_fixture(root):
    finite, frames = fixture(root)
    config = {k: copy.deepcopy(v) for k, v in finite.items() if k not in ('schema', 'sources')}
    config.update(schema='overwatch-decoder.live-partition-config/1', window_origin_ticks=1000, sources=[])
    for number, old in enumerate(finite['sources'], 1):
        sid = old['source_id']
        acquisition = {key: value for key, value in frames[sid][0]['source_artifacts']['acquisition'].items()}
        source = dict(source_id=sid, session_id=str(number)*32, segment=1, profile_sha256=old['profile_sha256'],
                      acquisition=acquisition, objects=old['objects'])
        declarations = {}
        for frame in frames[sid]:
            frame.update(schema='overwatch-decoder.entity-relations-live/1', session_id=source['session_id'], segment=1,
                event_sequence=frame['timing']['sequence']+1, privacy='private', durability_verified=False,
                recording_state='accepted_not_durability_verified')
            frame['recording'] = dict(complete=False, partial=True, status='accepted_not_durability_verified',
                                     durability_verified=False, continuity_across_gaps=False)
            frame['source_artifacts'] = dict(profile_sha256=source['profile_sha256'], acquisition=copy.deepcopy(acquisition),
                                            live_event_sha256='ef'*32)
            for row in frame['relations']:
                row['position_candidate']['field'] = 'fixture-position'
                declarations['fixture-pool'] = 'f32'
                row['evidence'] = [dict(field='identity-'+str(i), value=i, read_start_ticks=frame['timing']['start_ticks']+1,
                                       read_end_ticks=frame['timing']['start_ticks']+2) for i in range(5)]
                e = row['category_evidence']
                scope = dict(session_id=source['session_id'], segment=1, start_ticks=1000, monotonic_frequency=1000,
                             session_start_sha256='ab'*32, segment_start_sha256='bc'*32)
                e.update(mode_id='fixture-mode', durability_verified=False, native_review_sha256='cd'*32, roster_review_sha256='de'*32,
                         mode_review_sha256='fa'*32, contract_sha256='ed'*32,
                         mode_scope=dict(mode_id='fixture-mode', live_scope=scope, mode_review_sha256='fa'*32, roster_review_sha256='de'*32))
                source['live_category'] = {key: copy.deepcopy(e[key]) for key in ('contract_sha256', 'native_review_sha256',
                    'roster_review_sha256', 'mode_review_sha256', 'mode_id', 'self_controller_object_key')}
                source['live_category']['live_scope'] = copy.deepcopy(scope)
                frame.update(live_category_output_enabled=True, live_category_contract_sha256=e['contract_sha256'])
                e['admission'] = dict(session_id=source['session_id'], segment=1, profile_sha256=source['profile_sha256'],
                    acquisition_manifest_sha256=acquisition['manifest_sha256'], recipe_sha256=acquisition['recipe_sha256'],
                    evidence_sha256=acquisition['evidence_sha256'], event_sequence=frame['event_sequence'],
                    event_sha256=frame['source_artifacts']['live_event_sha256'], frame_sequence=frame['timing']['sequence'],
                    frame_start_ticks=frame['timing']['start_ticks'], frame_end_ticks=frame['timing']['end_ticks'],
                    monotonic_frequency=1000, frame_sha256='ac'*32)
                def collect(value):
                    if isinstance(value, dict):
                        if 'field' in value: declarations.setdefault(value['field'], value.get('type', 'i32'))
                        for child in value.values(): collect(child)
                    elif isinstance(value, list):
                        for child in value: collect(child)
                collect(row)
        source['fields'] = [dict(name=name, type=kind) for name, kind in declarations.items()]
        config['sources'].append(source)
    return config, frames


class LiveAggregateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config, self.frames = live_fixture(Path(self.temp.name))

    def make(self, **kwargs):
        return live.LivePartitions(raw(self.config), **kwargs)

    def test_common_watermark_ownership_and_no_dynamic_false_conflict(self):
        adapter = self.make()
        adapter.consume('p1', raw(self.frames['p1'][0]))
        self.assertIsNone(adapter.automatic_watermark)
        adapter.consume('p2', raw(self.frames['p2'][0]))
        self.assertEqual(adapter.automatic_watermark, 1020)
        self.assertEqual(list(adapter.advance(adapter.automatic_watermark)), [])
        adapter.consume('p1', raw(self.frames['p1'][1]))
        self.assertEqual(adapter.automatic_watermark, 1030)
        adapter.consume('p2', raw(self.frames['p2'][1]))
        windows = list(adapter.advance(adapter.automatic_watermark))
        self.assertEqual(len(windows), 1)
        result = windows[0]
        self.assertEqual(result['schema'], 'overwatch-decoder.partition-research-live/1')
        selected = result['relations'][0]['authoritative_observation']
        self.assertEqual(selected['source_id'], 'p1')
        self.assertEqual(selected['relation']['position_candidate']['value'][0], 10)
        self.assertEqual(result['relations'][0]['supporting_observations'][0]['relation']['position_candidate']['value'][0], 20)
        self.assertFalse(result['atomic']); self.assertFalse(result['durability_verified'])
        self.assertIn('semantic_projection_sha256', selected)
        summary = adapter.close()
        self.assertEqual(summary['authoritative_field_coverage']['health_candidate'], 3)
        self.assertEqual(summary['pending_windows'], 1)
        self.assertFalse(summary['all_sources_complete'])

    def test_gap_missing_source_and_empty_windows_never_carry(self):
        adapter = self.make()
        for sid in self.frames: adapter.consume(sid, raw(self.frames[sid][0]))
        first = list(adapter.advance(1050))[0]
        self.assertTrue(all(r['status'] == 'observed' for r in first['relations']))
        f = self.frames['p1'][1]
        f['gap_before']['skipped_slots'] = 1
        adapter.consume('p1', raw(f))
        windows = list(adapter.advance(1200))
        self.assertEqual(len(windows), 3)
        self.assertTrue(all(r['authoritative_observation'] is None for w in windows for r in w['relations']))
        self.assertEqual(windows[0]['unavailable_sources']['p1'], 'gap_in_window')
        self.assertEqual(windows[-1]['unavailable_sources']['p2'], 'missing_frame_in_window')
        self.assertEqual(adapter.close()['partial_windows'], 3)

    def test_late_closed_frame_rejected_and_latched(self):
        adapter = self.make()
        list(adapter.advance(1100))
        with self.assertRaisesRegex(ValueError, 'late_frame'):
            adapter.consume('p1', raw(self.frames['p1'][0]))
        with self.assertRaisesRegex(ValueError, 'closed'):
            adapter.consume('p2', raw(self.frames['p2'][0]))

    def test_old_session_future_profile_and_epoch_are_not_reconfigured(self):
        for key, value in [('session_id', 'f'*32), ('profile_sha256', 'fe'*32), ('segment', 2), ('target', {})]:
            with self.subTest(key=key):
                frame = copy.deepcopy(self.frames['p1'][0]); frame[key] = value
                with self.assertRaisesRegex(ValueError, 'reconfigure'):
                    self.make().consume('p1', raw(frame))

    def test_static_conflict_unknown_despite_primary(self):
        self.frames['p2'][0]['relations'][0]['cached_label_candidate'] = 'different'
        adapter = self.make()
        for sid in self.frames: adapter.consume(sid, raw(self.frames[sid][0]))
        result = list(adapter.advance(1050))[0]
        self.assertEqual(result['relations'][0]['reason'], 'conflicting_static_observations')
        self.assertIsNone(result['relations'][0]['authoritative_observation'])
        self.assertEqual(adapter.close()['unknown_reasons']['conflicting_static_observations'], 1)

    def test_nested_body_profile_brackets_and_declarations_reject(self):
        cases = ['body', 'profile', 'read', 'declaration', 'category_epoch', 'category_review', 'category_event']
        for case in cases:
            with self.subTest(case=case):
                frame = copy.deepcopy(self.frames['p1'][0]); row = frame['relations'][0]
                if case == 'body': row['health_candidate']['body_object_key'] = pair(9)['body_object_key']
                elif case == 'profile': row['health_candidate']['profile_sha256'] = '00'*32
                elif case == 'read': row['position_candidate']['read_end_ticks'] = 9999
                elif case == 'declaration': row['evidence'][0]['field'] = 'not-declared'
                elif case == 'category_epoch': row['category_evidence']['mode_scope']['live_scope']['segment'] = 2
                elif case == 'category_review': row['category_evidence']['mode_review_sha256'] = '00'*32
                else: row['category_evidence']['admission']['event_sequence'] = 999
                with self.assertRaises(ValueError): self.make().consume('p1', raw(frame))

    def test_order_anchor_and_source_provenance_reject(self):
        for case in ('sequence', 'end', 'clock', 'acquisition', 'durability'):
            with self.subTest(case=case):
                a = self.make(); a.consume('p1', raw(self.frames['p1'][0]))
                f = copy.deepcopy(self.frames['p1'][1])
                if case == 'sequence': f['timing']['sequence'] += 1
                elif case == 'end': f['timing']['start_ticks'] = 0
                elif case == 'clock': f['timing']['utc_origin'] = '2020-01-02T00:00:00Z'
                elif case == 'acquisition': f['source_artifacts']['acquisition']['evidence_sha256'] = '00'*32
                else: f['durability_verified'] = True
                with self.assertRaises(ValueError): a.consume('p1', raw(f))

    def test_bounds_include_empty_windows_and_pending_sparse_frames(self):
        a = self.make(maximum_output_bytes=1)
        with self.assertRaisesRegex(ValueError, 'output_byte_limit'): list(a.advance(1050))
        self.assertEqual(a.output_bytes, 0)
        with patch.object(live, 'MAX_OUTPUT_LINE_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'output_line_bound'): list(self.make().advance(1050))
        with patch.object(live, 'MAX_WINDOWS', 2):
            with self.assertRaisesRegex(ValueError, 'window_count'): list(self.make().advance(1200))
        with patch.object(live, 'MAX_OPEN_WINDOWS', 1):
            f = self.frames['p1'][1]; f['timing']['sequence'] = 0; f['gap_before']['previous_end_ticks'] = None
            with self.assertRaisesRegex(ValueError, 'pending_window'): self.make().consume('p1', raw(f))
        with patch.object(live, 'MAX_PENDING_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'pending_byte'): self.make().consume('p2', raw(self.frames['p2'][0]))

    def test_relation_availability_does_not_imply_optional_field_coverage(self):
        adapter = self.make()
        for sid in self.frames:
            frame = copy.deepcopy(self.frames[sid][0])
            frame['relations'][0]['health_candidate'] = None
            adapter.consume(sid, raw(frame))
        list(adapter.advance(1050))
        summary = adapter.close()
        self.assertEqual(summary['observed_rows'], 3)
        self.assertEqual(summary['authoritative_field_coverage']['health_candidate'], 2)

    def test_category_requires_reviewed_configuration_not_just_claimed_hashes(self):
        del self.config['sources'][0]['live_category']
        with self.assertRaisesRegex(ValueError, 'live_category_config_required'):
            self.make().consume('p1', raw(self.frames['p1'][0]))

    def test_stream_uses_minimum_accepted_watermark_and_never_flushes_eof(self):
        events = []
        for seq in (0, 1):
            for sid in self.frames: events.append(raw(dict(kind='frame', source_id=sid, projection=self.frames[sid][seq])))
        output = io.BytesIO()
        summary = live.stream(self.make(), io.BytesIO(b''.join(events)), output)
        self.assertEqual(summary['windows'], 1)
        self.assertEqual(summary['pending_windows'], 1)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertFalse(summary['durability_verified'])
        with self.assertRaises(ValueError): list(self.make().advance(-1))

    def test_discard_mode_validates_all_evidence_and_advances_only_cursors(self):
        adapter = self.make()
        adapter.consume('p1', raw(self.frames['p1'][0]), retain=False)
        self.assertEqual(adapter.sources['p1']['sequence'], 1)
        self.assertEqual(adapter.pending, {})
        self.assertEqual(adapter.pending_bytes, 0)
        broken = copy.deepcopy(self.frames['p1'][1])
        broken['relations'][0]['health_candidate']['body_object_key'] = pair(9)['body_object_key']
        with self.assertRaises(ValueError): adapter.consume('p1', raw(broken), retain=False)
        self.assertTrue(adapter.failed)

    def test_fused_walk_rejects_late_declarations_objects_and_leaf_budgets(self):
        for case in ('field', 'type', 'controller', 'body', 'profile', 'build', 'read', 'budget', 'depth'):
            with self.subTest(case=case):
                adapter = self.make()
                adapter.consume('p1', raw(self.frames['p1'][0]))
                frame = copy.deepcopy(self.frames['p1'][1])
                row = frame['relations'][0]
                tail = dict(field='identity-0', type='i32', controller_object_key=row['controller_object_key'],
                            body_object_key=row['body_object_key'], profile_sha256=frame['profile_sha256'],
                            build_sha256=frame['target']['executable_sha256'],
                            read_start_ticks=frame['timing']['start_ticks']+1,
                            read_end_ticks=frame['timing']['start_ticks']+2)
                if case == 'field': tail['field'] = 'undeclared'
                elif case == 'type': tail['type'] = 'f32'
                elif case == 'controller': tail['controller_object_key'] = pair(9)['controller_object_key']
                elif case == 'body': tail['body_object_key'] = pair(9)['body_object_key']
                elif case == 'profile': tail['profile_sha256'] = '00'*32
                elif case == 'build': tail['build_sha256'] = '00'*32
                elif case == 'read': tail['read_end_ticks'] = 999999
                row['extra_evidence'] = [0]*1000 + [tail]
                if case == 'budget': row['extra_evidence'] = [0]*100000
                if case == 'depth':
                    deep = 0
                    for _ in range(25): deep = [deep]
                    row['extra_evidence'] = deep
                with self.assertRaises(ValueError): adapter.consume('p1', raw(frame))
                self.assertTrue(adapter.failed)

    def test_returned_context_is_detached_from_validated_pending_observations(self):
        adapter = self.make()
        context = adapter.consume('p1', raw(self.frames['p1'][0]), context=True)
        self.assertNotIn('health_candidate', context['relations'][0])
        context['relations'][0]['body_object_key'] = pair(9)['body_object_key']
        context['source_artifacts']['profile_sha256'] = '00'*32
        context['timing']['start_ticks'] = -1
        adapter.consume('p2', raw(self.frames['p2'][0]))
        result = list(adapter.advance(1050))[0]
        selected = result['relations'][0]['authoritative_observation']
        self.assertEqual(selected['relation']['body_object_key'], pair(1)['body_object_key'])
        self.assertEqual(selected['source_artifacts']['profile_sha256'], self.frames['p1'][0]['profile_sha256'])

    def test_minimum_start_discards_crossing_frame_but_still_validates_it(self):
        adapter = self.make()
        context = adapter.consume('p1', raw(self.frames['p1'][0]), context=True, minimum_start_ticks=1015)
        self.assertEqual(context['timing']['sequence'], 0)
        self.assertEqual(adapter.pending, {})
        self.assertEqual(adapter.sources['p1']['sequence'], 1)
        bad = copy.deepcopy(self.frames['p1'][1])
        bad['relations'][0]['health_candidate']['profile_sha256'] = '00'*32
        with self.assertRaises(ValueError):
            adapter.consume('p1', raw(bad), minimum_start_ticks=99999)


if __name__ == '__main__': unittest.main()
