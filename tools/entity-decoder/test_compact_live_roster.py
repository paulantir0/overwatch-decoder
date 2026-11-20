"""Exact primary parity, reference integrity, unavailable rows and epoch admission."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import compact_live_roster as compact
from aggregate_live_partitions import LivePartitions
from test_aggregate_live_partitions import live_fixture
from test_compact_live_entities import pointer, raw


def fixture(root):
    config, frames = live_fixture(root)
    for rows in frames.values():
        for frame in rows:
            for row in frame['relations']:
                row['position_candidate']['validation_status'] = 'guarded_research'
                row['health_candidate'].update(status='candidate', display_ceiling_candidate=int(row['health_candidate']['raw_sum']))
                row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research', public_state_eligible=False)
                row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research', catalog_sha256='ab'*32)
                row['cached_label_evidence']['validation_status'] = 'guarded_native_cache_string_research'
                row['category_evidence']['validation_status'] = 'guarded_live_category_roster_research'
    adapter = LivePartitions(raw(config)); windows = []
    for sequence in (0, 1):
        for sid in frames:
            adapter.consume(sid, raw(frames[sid][sequence]))
            if adapter.automatic_watermark is not None: windows += adapter.advance(adapter.automatic_watermark)
    windows += adapter.advance(1200)
    return windows



def partial_fixture(root):
    from test_live_roster_epochs import fixture as epoch_fixture,unresolved,next_frame
    from test_aggregate_partitions import pair
    from live_roster_epochs import LiveRosterEpochs
    config,frames=epoch_fixture(root)
    for source_frames in frames.values():
        for frame in source_frames:
            for row in frame['relations']:
                row['position_candidate']['validation_status']='guarded_research'
                row['health_candidate'].update(status='candidate',display_ceiling_candidate=int(row['health_candidate']['raw_sum']))
                row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research',public_state_eligible=False)
                row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research',catalog_sha256='ab'*32)
                row['cached_label_evidence']['validation_status']='guarded_native_cache_string_research'
    config.update(observation_mode='raw-candidates',allow_unresolved_bodies=True)
    ck=pair(2)['controller_object_key']
    source,frame=unresolved(config['sources'][0],frames['p1'][0],ck)
    config['sources'][0]=source
    config['roster']=[dict(p,body_object_key=None)if p['controller_object_key']==ck else p for p in config['roster']]
    adapter=LiveRosterEpochs(raw(config))
    adapter.consume('p1',raw(frame));adapter.consume('p2',raw(frames['p2'][0]));first=adapter.advance(1050)[0]
    later=next_frame(frame,1070);later['relations'][0]['position_candidate']['value'][0]=71
    adapter.consume('p1',raw(later));adapter.consume('p2',raw(frames['p2'][1]));second=adapter.advance(1100)[0]
    return [first,second]

def transition(window, status='unknown', next_config='fe'*32):
    start = window['window_end_ticks']
    return dict(schema='overwatch-decoder.live-roster-transition/1', status=status, revision=1 if status == 'unknown' else 2, target=copy.deepcopy(window['target']),
        clock_domain_id=window['clock_domain_id'], monotonic_frequency=window['monotonic_frequency'], start_ticks=start,
        end_ticks=None if status == 'unknown' else start+100, previous_config_sha256=window['config_sha256'],
        trigger=dict(source_id='p1', reason='fixture_reacquisition', session_id='1'*32, segment=2, event_sequence=50,
            semantic_projection_sha256='ab'*32, live_event_sha256='bc'*32, read_start_ticks=start+1, read_end_ticks=start+2),
        previous_values_carried=False, pending_observations_discarded=True, configuration_status='reviewed_caller_input_not_native_proof',
        atomic=False, privacy='private', visibility='unknown', public_state_eligible=False, durability_verified=False,
        recording_state='accepted_not_durability_verified',
        relations=[dict(controller_object_key=r['controller_object_key'], body_object_key=None, status='unknown',
            reason='roster_epoch_transition', authoritative_observation=None, supporting_observations=[], contributor_evidence=[])for r in window['relations']],
        **({}if status == 'unknown' else dict(next_config_sha256=next_config, source_admissions={'p1':dict(profile_sha256='ef'*32)})))


class CompactRosterTests(unittest.TestCase):
    def test_internal_coordinator_values_match_canonical_public_path(self):
        from aggregate_partitions import canonical
        from test_context_projection_validation import ContextPipelineTests
        with tempfile.TemporaryDirectory()as temp:
            windows=fixture(Path(temp));normal=compact.CompactLiveRoster();fast=compact.CompactLiveRoster()
            for value in windows:
                line=canonical(value)+b'\n';expected=normal.consume(line)
                with patch('compact_live_roster.parse',side_effect=AssertionError('redundant_parse')):
                    result=fast._consume_decoded(line,value)
                self.assertEqual(compact.encode(result),compact.encode(expected))
            ending=transition(windows[-1]);ending['trigger']['reason']='finite_sources_completed'
            ending['input_end']=dict(reason='finite_sources_completed',evidence_kind='caller_verified_producer_eof_not_native_sample',
                stop_ticks=ending['trigger']['read_end_ticks'],discarded_pending_windows=0,discarded_pending_bytes=0,
                source_result_sha256={'p2':'bb'*32,'p1':'aa'*32})
            line=canonical(ending)+b'\n'
            self.assertEqual(compact.encode(fast._consume_decoded(line,ending)),compact.encode(normal.consume(line)))
            self.assertEqual(fast.summary(),normal.summary())
            # Context mapping insertion order differs from canonical JSON and
            # must not change exact compact bytes on the parse-once path.
            helper=ContextPipelineTests();helper.setUp()
            try:
                source,_,config,_,_=helper.fixture();value=helper.window(source,config)
                line=canonical(value)+b'\n'
                self.assertEqual(compact.encode(compact.CompactLiveRoster()._consume_decoded(line,value)),
                                 compact.encode(compact.CompactLiveRoster().consume(line)))
            finally:helper.tmp.cleanup()

    def test_internal_path_retains_wrong_evidence_and_limits(self):
        from aggregate_partitions import canonical
        with tempfile.TemporaryDirectory()as temp:
            original=fixture(Path(temp))[0]
            for case in ('read','body','profile'):
                with self.subTest(case=case):
                    value=copy.deepcopy(original);row=value['relations'][0]['authoritative_observation']['relation']
                    if case=='read':row['position_candidate']['read_end_ticks']=999999
                    elif case=='body':row['health_candidate']['body_object_key']='body:'+'ff'*32
                    else:row['health_candidate']['profile_sha256']='ff'*32
                    p=compact.CompactLiveRoster()
                    with self.assertRaises(ValueError):p._consume_decoded(canonical(value)+b'\n',value)
                    self.assertTrue(p.failed)
            p=compact.CompactLiveRoster()
            with self.assertRaises(ValueError):p._consume_decoded(b'{}',original)
            self.assertTrue(p.failed)
            for line in (b'{"x":1,"x":2}\n',b'{"x":NaN}\n'):
                with self.assertRaises(ValueError):compact.CompactLiveRoster().consume(line)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.windows = fixture(Path(self.temp.name))

    def test_raw_unresolved_body_keeps_nulls_exact_read_refs_and_other_actor_values(self):
        windows=partial_fixture(Path(self.temp.name));projector=compact.CompactLiveRoster()
        for source in windows:
            out=projector.consume(raw(source))
            absent=next(r for r in out['players']if r['body_object_key']is None)
            original=pointer(source,absent['source_ref'])
            self.assertEqual(absent['status'],'unknown');self.assertEqual(absent['reason'],'body_binding_unresolved')
            self.assertTrue(all(absent[k]['value']is None and absent[k]['read_span_ticks']is None for k in compact.CANDIDATES))
            self.assertIsNone(absent['primary_observation']);self.assertFalse(absent['contributor_refs'])
            refs=absent['unresolved_body']['observation_refs'];self.assertEqual(len(refs),1)
            for ref in refs:
                node=pointer(source,ref['source_ref']);declaration=pointer(source,ref['declaration_ref'])
                self.assertEqual(ref['semantic_projection_sha256'],node['semantic_projection_sha256'])
                self.assertEqual(declaration,node['declaration'])
                self.assertEqual(ref['controller_read_span_ticks'],[min(w['read_start_ticks']for w in node['relation']['evidence']),max(w['read_end_ticks']for w in node['relation']['evidence'])])
            self.assertEqual(sum(r['status']=='observed'for r in out['players']),2)
        self.assertEqual(out['players'][0]['position_candidate']['value'][0],71)

    def test_nullable_body_requires_explicit_raw_provenance_and_no_stale_values(self):
        original=partial_fixture(Path(self.temp.name))[0]
        for case in ('policy','declaration','profile','read','health','reason','word','controller','duplicate','observed'):
            with self.subTest(case=case):
                value=copy.deepcopy(original);row=next(r for r in value['relations']if r['body_object_key']is None)
                node=row['unresolved_body_observations'][0]
                if case=='policy':value.pop('observation_mode')
                elif case=='declaration':row['unresolved_body_sources']=[]
                elif case=='profile':node['source_artifacts']['profile_sha256']='ff'*32
                elif case=='read':node['relation']['evidence'][0]['read_end_ticks']=999999
                elif case=='health':node['relation']['health_candidate']={'raw_sum':175}
                elif case=='reason':node['relation']['reason']='guard_check_failed'
                elif case=='word':node['relation']['evidence'][0]['field']='unrelated'
                elif case=='controller':node['relation']['controller_object_key']='controller:'+'ff'*32
                elif case=='duplicate':row['unresolved_body_observations'].append(copy.deepcopy(node))
                else:row['status']='observed'
                with self.assertRaises(ValueError):compact.CompactLiveRoster().consume(raw(value))
        p=compact.CompactLiveRoster();p.consume(raw(original))
        later=partial_fixture(Path(self.temp.name))[1]
        row=next(r for r in later['relations']if r['body_object_key']is None)
        row['unresolved_body_sources'][0]['profile_guards_sha256']='ff'*32
        row['unresolved_body_observations'][0]['declaration']['profile_guards_sha256']='ff'*32
        with self.assertRaisesRegex(ValueError,'unresolved_declaration_changed_without_epoch'):p.consume(raw(later))

    def test_explicit_epoch_barriers_allow_full_absent_fresh_compact_bindings(self):
        from test_live_roster_epochs import change
        first=self.windows[0];partial=partial_fixture(Path(self.temp.name))[0]
        p=compact.CompactLiveRoster();p.consume(raw(first))
        opened=transition(first);closed=transition(first,'resumed_without_carried_values')
        p.consume(raw(opened));p.consume(raw(closed))
        absent=change(partial,{},150);absent.update(config_sha256=closed['next_config_sha256'],epoch_id='absent',window_index=3,observed_skew_ticks=partial['observed_skew_ticks'],maximum_skew_ticks=partial['maximum_skew_ticks'])
        out=p.consume(raw(absent));self.assertEqual(sum(r['body_object_key']is None for r in out['players']),1)
        opened=transition(absent);opened['revision']=2
        closed=transition(absent,'resumed_without_carried_values',next_config='fd'*32);closed['revision']=3
        p.consume(raw(opened));p.consume(raw(closed))
        oldbody=first['relations'][1]['body_object_key']
        fresh=change(first,{oldbody:'body:'+'ef'*32},300)
        fresh.update(config_sha256=closed['next_config_sha256'],epoch_id='fresh',window_index=6,observed_skew_ticks=first['observed_skew_ticks'],maximum_skew_ticks=first['maximum_skew_ticks'])
        out=p.consume(raw(fresh));self.assertEqual(out['players'][1]['body_object_key'],'body:'+'ef'*32)
        self.assertTrue(all(r['status']=='observed'for r in out['players']))
        self.assertNotIn('unresolved_body',out['players'][1])

    def test_primary_values_and_every_reference_resolves_without_guard_arrays(self):
        source = self.windows[0]; line = raw(source); result = compact.CompactLiveRoster().consume(line)
        self.assertEqual(result['source_frame']['sha256'], hashlib.sha256(line).hexdigest())
        self.assertEqual(result['timing'], {k: source[k] for k in compact.TIME_KEYS})
        for row, original in zip(result['players'], source['relations']):
            self.assertEqual(pointer(source, row['source_ref']), original)
            self.assertEqual(row['status'], original['status']); self.assertEqual(row['reason'], original['reason'])
            selected = original['authoritative_observation']; relation = selected['relation']
            self.assertEqual(row['primary_observation']['source_id'], original['primary_source_id'])
            self.assertEqual(row['position_candidate']['value'], relation['position_candidate']['value'])
            self.assertEqual(row['health_candidate']['value'], {k: relation['health_candidate'][k] for k in ('raw_sum', 'display_ceiling_candidate')})
            self.assertEqual(row['hero_resource_candidate']['value'], relation['hero_resource_guid_candidate']['value'])
            self.assertEqual(row['hero_label_candidate']['value'], relation['hero_label'])
            self.assertEqual(row['cached_label_candidate']['value'], relation['cached_label_candidate'])
            self.assertEqual(row['category_candidate']['value'], {k: relation[k] for k in ('raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate')})
            for key in compact.CANDIDATES:
                self.assertIsNotNone(pointer(source, row[key]['evidence_ref']))
            for ref in [row['primary_observation'], *row['supporting_observation_refs'], *row['contributor_refs']]:
                original_ref = pointer(source, ref['source_ref'])
                self.assertEqual(ref['semantic_projection_sha256'], original_ref['semantic_projection_sha256'])
                self.assertEqual(ref['source_timing'], original_ref['source_timing'])
                if 'relation_ref' in ref: self.assertEqual(pointer(source, ref['relation_ref']), original_ref['relation'])
        primary = result['players'][0]
        self.assertEqual(primary['position_candidate']['value'][0], 10)
        self.assertEqual(len(primary['supporting_observation_refs']), 1)
        self.assertNotIn('guard_ids', json.dumps(result))
        self.assertTrue(all('relation' not in ref for r in result['players'] for ref in r['supporting_observation_refs']))
        self.assertTrue(result['values_are_candidates']); self.assertFalse(result['participant_identity_validated'])

    def test_gap_unknowns_never_use_support_or_previous_primary(self):
        source = copy.deepcopy(self.windows[0]); row = source['relations'][0]
        row.update(status='unknown', reason='gap_in_window', authoritative_observation=None)
        row['contributor_evidence'] = [c for c in row['contributor_evidence'] if not c['authoritative']]
        p = compact.CompactLiveRoster(); out = p.consume(raw(source))
        row = out['players'][0]
        self.assertEqual(len(row['supporting_observation_refs']), 1)
        self.assertIsNone(row['primary_observation'])
        self.assertTrue(all(row[k]['value'] is None and row[k]['reason'] == 'gap_in_window' for k in compact.CANDIDATES))
        for value in self.windows[1:]: last = p.consume(raw(value))
        self.assertTrue(all(row['status'] == 'unknown' for row in last['players']))
        self.assertTrue(all(row[k]['value'] is None for row in last['players'] for k in compact.CANDIDATES))

    def test_static_conflict_stays_unknown_with_evidence_references(self):
        source = copy.deepcopy(self.windows[0]); row = source['relations'][0]
        row.update(status='unknown', reason='conflicting_static_observations', conflicting_static_fields=['cached_label_candidate'], authoritative_observation=None)
        out = compact.CompactLiveRoster().consume(raw(source))['players'][0]
        self.assertEqual(out['conflicting_static_fields'], ['cached_label_candidate'])
        self.assertTrue(out['contributor_refs']); self.assertIsNone(out['hero_label_candidate']['value'])

    def test_nullable_optional_fields_and_zero_unicode_keep_source_values(self):
        source = copy.deepcopy(self.windows[0]); row = source['relations'][1]['authoritative_observation']['relation']
        row['hero_label'] = None; row.pop('hero_label_evidence')
        row['cached_label_candidate'] = 'Åna Ω'; row['health_candidate'].update(raw_sum=0, display_ceiling_candidate=0)
        row['health_candidate']['contributions'][0]['value'] = 0
        row['position_candidate']['value'] = [0.0, -0.0, 0]
        out = compact.CompactLiveRoster().consume(raw(source))['players'][1]
        self.assertIsNone(out['hero_label_candidate']['value']); self.assertEqual(out['cached_label_candidate']['value'], 'Åna Ω')
        self.assertEqual(out['health_candidate']['value']['raw_sum'], 0); self.assertIn(b'-0.0', compact.encode(out))

    def test_wrong_primary_nested_body_profile_span_and_hash_reject_and_latch(self):
        for case in ('primary', 'body', 'profile', 'read', 'hash', 'qualification', 'nonfinite', 'support'):
            with self.subTest(case=case):
                source = copy.deepcopy(self.windows[0]); row = source['relations'][0]; selected = row['authoritative_observation']
                if case == 'primary': selected['source_id'] = 'p2'
                elif case == 'body': selected['relation']['health_candidate']['body_object_key'] = 'body:'+'ee'*32
                elif case == 'profile': selected['relation']['position_candidate']['profile_sha256'] = 'dd'*32
                elif case == 'read': selected['relation']['position_candidate']['read_end_ticks'] = 99999
                elif case == 'hash': selected['semantic_projection_sha256'] = 'bad'
                elif case == 'qualification': source['public_state_eligible'] = True
                elif case == 'nonfinite': selected['relation']['position_candidate']['value'][0] = float('nan')
                else: row['supporting_observations'][0]['relation']['body_object_key'] = 'body:'+'cc'*32
                p = compact.CompactLiveRoster()
                with self.assertRaises(ValueError): p.consume(raw(source))
                with self.assertRaisesRegex(ValueError, 'failed'): p.consume(raw(self.windows[0]))

    def test_same_epoch_body_primary_profile_and_order_changes_reject(self):
        for case in ('body', 'owner', 'profile', 'order', 'target', 'watermark'):
            with self.subTest(case=case):
                first, second = (copy.deepcopy(w) for w in self.windows[:2])
                if case == 'body': second['relations'][0]['body_object_key'] = 'body:'+'ee'*32
                elif case == 'owner': second['relations'][0]['primary_source_id'] = 'p2'
                elif case == 'profile':
                    second['relations'][0]['contributor_evidence'][0]['source_artifacts']['profile_sha256'] = 'ff'*32
                elif case == 'order': second['window_index'] = 0
                elif case == 'target': second['target']['pid'] += 1
                else: second['watermark_ticks'] = first['watermark_ticks']-1
                p = compact.CompactLiveRoster(); p.consume(raw(first))
                with self.assertRaises(ValueError): p.consume(raw(second))

    def test_forward_new_aggregate_epoch_with_skipped_interval_never_fills(self):
        first = copy.deepcopy(self.windows[0]); second = copy.deepcopy(self.windows[3])
        second.update(config_sha256='fe'*32, epoch_id='fixture-reacquired')
        # No observations in this late window: a new body is only a caller-pinned identity, not a candidate value.
        second['relations'][0]['body_object_key'] = 'body:'+'ee'*32
        p = compact.CompactLiveRoster(); p.consume(raw(first)); out = p.consume(raw(second))
        self.assertEqual(out['timing']['window_index'], 3); self.assertEqual(p.summary()['windows'], 2)
        self.assertEqual(out['players'][0]['body_object_key'], 'body:'+'ee'*32)
        self.assertTrue(all(row[k]['value'] is None for row in out['players'] for k in compact.CANDIDATES))

    def test_new_epoch_observed_body_rebind_preserves_only_new_primary_values(self):
        first, second = (copy.deepcopy(w) for w in self.windows[:2])
        second.update(config_sha256='fe'*32, epoch_id='fixture-body-reacquired')
        old_body = first['relations'][0]['body_object_key']; new_body = 'body:'+'ee'*32
        replacements = {old_body: new_body, '11'*32: 'ef'*32, '22'*32: 'dc'*32}
        def replace(value):
            if isinstance(value, dict): return {key: replace(item) for key, item in value.items()}
            if isinstance(value, list): return [replace(item) for item in value]
            return replacements.get(value, value) if isinstance(value, str) else value
        second = replace(second)
        second['relations'][0]['authoritative_observation']['relation']['position_candidate']['value'] = [123, 0, 0]
        p = compact.CompactLiveRoster(); before = p.consume(raw(first)); after = p.consume(raw(second))
        self.assertEqual(before['players'][0]['controller_object_key'], after['players'][0]['controller_object_key'])
        self.assertNotEqual(before['players'][0]['body_object_key'], after['players'][0]['body_object_key'])
        self.assertEqual(after['players'][0]['position_candidate']['value'], [123, 0, 0])
        self.assertEqual(after['players'][0]['primary_observation']['profile_sha256'], 'ef'*32)

    def test_explicit_transition_preserves_unknown_interval_and_requires_matching_resume(self):
        first = copy.deepcopy(self.windows[0]); second = copy.deepcopy(self.windows[3])
        second.update(config_sha256='fe'*32, epoch_id='fixture-reacquired')
        p = compact.CompactLiveRoster(); p.consume(raw(first))
        opened = transition(first); closed = transition(first, 'resumed_without_carried_values')
        a = p.consume(raw(opened)); b = p.consume(raw(closed)); c = p.consume(raw(second))
        self.assertEqual(a['schema'], 'overwatch-decoder.compact-live-roster-transition/1'); self.assertIsNone(a['end_ticks'])
        self.assertEqual(b['end_ticks'], second['window_start_ticks']); self.assertEqual(c['config_sha256'], closed['next_config_sha256'])
        self.assertTrue(all(row['body_object_key'] is None and row['position_candidate']['value'] is None for row in a['players']))
        self.assertEqual(a['source_frame']['sha256'], hashlib.sha256(raw(opened)).hexdigest())
        prefix = compact.CompactLiveRoster(); prefix.consume(raw(opened))
        wrong_target = copy.deepcopy(closed); wrong_target['target']['pid'] += 1
        with self.assertRaisesRegex(ValueError, 'clock_or_target'): prefix.consume(raw(wrong_target))
        for bad in ('open', 'closure', 'stale'):
            with self.subTest(bad=bad):
                q = compact.CompactLiveRoster(); q.consume(raw(first))
                if bad == 'closure':
                    with self.assertRaises(ValueError): q.consume(raw(closed))
                else:
                    q.consume(raw(opened))
                    if bad == 'stale': q.consume(raw(closed))
                    with self.assertRaises(ValueError): q.consume(raw(self.windows[1]))

    def test_bound_duplicate_keys_and_failure_emit_no_partial_line(self):
        for kwargs in (dict(maximum_input_bytes=1), dict(maximum_output_bytes=1)):
            output = io.BytesIO(); p = compact.CompactLiveRoster(**kwargs)
            with self.assertRaises(ValueError): compact.stream(p, io.BytesIO(raw(self.windows[0])), output)
            self.assertEqual(output.getvalue(), b''); self.assertEqual(p.summary()['windows'], 0)
        p = compact.CompactLiveRoster(maximum_events=1); p.consume(raw(self.windows[0]))
        with self.assertRaises(ValueError): p.consume(raw(self.windows[1]))
        with self.assertRaises(ValueError): compact.CompactLiveRoster().consume(b'{"schema":1,"schema":2}\n')
        with patch.object(compact, 'MAX_OUTPUT_LINE', 1):
            with self.assertRaises(ValueError): compact.CompactLiveRoster().consume(raw(self.windows[0]))
        with patch.object(compact, 'MAX_LINE', 2):
            with self.assertRaises(ValueError): compact.CompactLiveRoster().consume(raw(self.windows[0]))

    def test_unrequested_names_private_extra_metadata_not_copied(self):
        source = copy.deepcopy(self.windows[0]); row = source['relations'][1]['authoritative_observation']['relation']
        row.update(name='private-name', private_battletag='private-tag')
        source['target']['private_note'] = 'private-target'
        out = compact.encode(compact.CompactLiveRoster().consume(raw(source)))
        self.assertNotIn(b'private-name', out); self.assertNotIn(b'private-tag', out); self.assertNotIn(b'private-target', out)
        self.assertIn(b'"participant_identity_validated":false', out)

    def test_fused_walk_checks_containers_after_primitive_guard_ids(self):
        corruptions = [dict(profile_sha256='ee'*32), dict(build_sha256='ee'*32),
            dict(read_start_ticks=0, read_end_ticks=999999),
            dict(controller_object_key='controller:'+'ee'*32), dict(body_object_key='body:'+'ee'*32)]
        for node in corruptions:
            with self.subTest(node=node):
                source = copy.deepcopy(self.windows[0])
                relation = source['relations'][0]['authoritative_observation']['relation']
                relation['future_evidence'] = ['primitive-guard-id']*4096+[{'nested': node}]
                p = compact.CompactLiveRoster()
                with self.assertRaises(ValueError): p.consume(raw(source))
                with self.assertRaisesRegex(ValueError, 'failed'): p.consume(raw(self.windows[0]))

    def test_fused_walk_counts_primitive_nodes_and_leaf_depth_exactly(self):
        timing = dict(start_ticks=10, end_ticks=20)
        # Root dictionary + profile string + list +99,997 primitive leaves =100,000 nodes.
        bounded = dict(profile_sha256='ab'*32, guard_ids=['id']*99997)
        compact.validate_scope(bounded, timing, 'ab'*32, 'cd'*32)
        bounded['guard_ids'].append('one-too-many')
        with self.assertRaisesRegex(ValueError, 'bound'):
            compact.validate_scope(bounded, timing, 'ab'*32, 'cd'*32)
        nested = 'leaf'
        for _ in range(24): nested = [nested]
        compact.validate_scope(nested, timing, 'ab'*32, 'cd'*32)
        with self.assertRaisesRegex(ValueError, 'bound'):
            compact.validate_scope([nested], timing, 'ab'*32, 'cd'*32)

    def test_candidate_specific_rejections_survive_fused_scope_walk(self):
        for case in ('sum', 'duplicate_pool', 'resource_words', 'hero_mapping', 'cache_privacy', 'position_type'):
            with self.subTest(case=case):
                source = copy.deepcopy(self.windows[0]); relation = source['relations'][0]['authoritative_observation']['relation']
                if case == 'sum': relation['health_candidate']['raw_sum'] += 1
                elif case == 'duplicate_pool':
                    health = relation['health_candidate']; health['contributions'] *= 2
                    health.update(raw_sum=200, display_ceiling_candidate=200)
                elif case == 'resource_words': relation['hero_resource_guid_candidate']['evidence'][3]['value'] = 1
                elif case == 'hero_mapping': relation['hero_label_evidence']['mapping']['resource_guid'] = '0x000000000000FFFF'
                elif case == 'cache_privacy': relation['cached_label_evidence']['privacy'] = 'public'
                else: relation['position_candidate']['type'] = 'f32'
                with self.assertRaises(ValueError): compact.CompactLiveRoster().consume(raw(source))

    def test_cli_stream_hashes_and_no_eof_generated_windows(self):
        data = b''.join(raw(w) for w in self.windows)
        run = subprocess.run([sys.executable, str(Path(compact.__file__))], input=data, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stderr); self.assertEqual(report['windows'], len(self.windows))
        self.assertEqual(report['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(report['output_sha256'], hashlib.sha256(run.stdout).hexdigest())
        self.assertEqual(len(run.stdout.splitlines()), len(self.windows)); self.assertFalse(report['public_state_eligible'])


if __name__ == '__main__': unittest.main()
