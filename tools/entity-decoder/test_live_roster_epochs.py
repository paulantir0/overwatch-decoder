"""Rollover mechanics over synthetic source-bound semantic evidence."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aggregate_partitions import sha, MAX_LINE_BYTES
from live_roster_epochs import LiveRosterEpochs
from test_aggregate_live_partitions import live_fixture
from test_aggregate_partitions import pair, raw


def fixture(root):
    config, frames = live_fixture(root)
    for source in config['sources']:
        source.pop('live_category')
        source['session_epoch'] = dict(acquisition=1, session_start_sha256='ab'*32,
            acquisition_end_sha256='bc'*32, segment_start_sha256='cd'*32,
            previous_epoch_last_frame_end_ticks=None, previous_values_carried=False)
        for frame in frames[source['source_id']]:
            frame['session_epoch'] = copy.deepcopy(source['session_epoch'])
            frame.pop('live_category_contract_sha256')
            frame['live_category_output_enabled'] = False
            for row in frame['relations']:
                for key in ('raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate', 'category_evidence'):
                    row[key] = None
    return config, frames


def change(value, replacements, delta=0):
    if isinstance(value, dict):
        return {key: (child + delta if key.endswith('_ticks') and key != 'monotonic_origin_ticks'
                     and type(child) is int else change(child, replacements, delta)) for key, child in value.items()}
    if isinstance(value, list):
        return [change(child, replacements, delta) for child in value]
    return replacements.get(value, value) if isinstance(value, str) else value


def next_frame(frame, end, *, sequence=None, event_sequence=None):
    result = change(frame, {}, end - frame['timing']['end_ticks'])
    result['timing']['sequence'] = frame['timing']['sequence'] + 1 if sequence is None else sequence
    result['event_sequence'] = frame['event_sequence'] + 1 if event_sequence is None else event_sequence
    result['gap_before']['previous_end_ticks'] = frame['timing']['end_ticks']
    result['session_epoch'] = copy.deepcopy(frame['session_epoch'])
    return result


def replacement(source, previous_frame, end, bodies):
    source = copy.deepcopy(source)
    segment = source['segment'] + 1
    tag = segment * 100 + (1 if source['source_id'] == 'p1' else 2)
    replacements = {source['profile_sha256']: f'{tag:064x}',
                    source['acquisition']['manifest_sha256']: f'{tag+10:064x}',
                    source['acquisition']['evidence_sha256']: f'{tag+20:064x}', **bodies}
    source = change(source, replacements)
    source['segment'] = segment
    source['session_epoch'] = dict(acquisition=segment, session_start_sha256='ab'*32,
        acquisition_end_sha256=f'{tag+30:064x}', segment_start_sha256=f'{tag+40:064x}',
        previous_epoch_last_frame_end_ticks=previous_frame['timing']['end_ticks'], previous_values_carried=False)
    frame = change(previous_frame, replacements, end - previous_frame['timing']['end_ticks'])
    frame['segment'] = segment
    frame['timing']['sequence'] = 0
    frame['event_sequence'] += 6
    frame['gap_before']['previous_end_ticks'] = None
    frame['session_epoch'] = copy.deepcopy(source['session_epoch'])
    return source, frame


def unknown(frame):
    frame = copy.deepcopy(frame)
    frame['relations'] = [dict(controller_object_key=None, body_object_key=None,
        relation_status='unknown', reason='field_not_observed', visibility='unknown') for _ in frame['relations']]
    return frame



def unresolved(source, frame, controller):
    """An upstream-admitted profile with a guarded controller, no body fields."""
    source, frame = copy.deepcopy(source), copy.deepcopy(frame)
    source['objects'] = [dict(p,body_object_key=None) if p['controller_object_key']==controller else p for p in source['objects']]
    prefix='fixture_absent'
    names=[prefix+'_handle_candidate_i32',prefix+'_manager_key_candidate_i32']
    lookup=prefix+'_part51_0000_body_key_candidate_i32'
    source['fields'] += [dict(name=n,type='i32') for n in [*names,lookup]]
    source['unresolved_bodies']=[dict(controller_object_key=controller,reason='body_fields_not_declared',
        controller_identity_fields=names,body_lookup_key_field=lookup,body_field_prefix=prefix+'_body_',
        profile_sha256=source['profile_sha256'],profile_guards_sha256='12'*32,
        acquisition_evidence_sha256=source['acquisition']['evidence_sha256'])]
    for i,row in enumerate(frame['relations']):
        if row['controller_object_key']!=controller:continue
        evidence=copy.deepcopy(row['evidence'][:2])
        for word,name in zip(evidence,names):word['field']=name
        frame['relations'][i]=dict(controller_object_key=controller,body_object_key=None,
            relation_status='unknown',reason='unsupported_word_binding',visibility='unknown',evidence=evidence)
    return source,frame

class RosterEpochTests(unittest.TestCase):
    def test_internal_fresh_decoded_path_matches_public_without_reparse(self):
        from aggregate_partitions import parse
        with tempfile.TemporaryDirectory()as temp:
            config,frames=fixture(Path(temp));normal=LiveRosterEpochs(raw(config));fast=LiveRosterEpochs(raw(config))
            expected=[];actual=[]
            for sequence in (0,1):
                for sid in frames:
                    line=raw(frames[sid][sequence]);expected+=normal.consume(sid,line)
                    decoded=parse(line)
                    with patch('aggregate_live_partitions.parse',side_effect=AssertionError('redundant_parse')):
                        actual+=fast._consume_decoded(sid,line,decoded)
            self.assertEqual(actual,expected);self.assertEqual(fast.status(),normal.status())
            with self.assertRaises(ValueError):fast._consume_decoded('p1',b'{}',{})
            self.assertTrue(fast.failed)

    def test_decoded_path_keeps_evidence_rejection_and_public_strict_parser(self):
        from aggregate_partitions import parse
        with tempfile.TemporaryDirectory()as temp:
            config,frames=fixture(Path(temp));frame=frames['p1'][0]
            for case in ('read','profile','epoch','sequence'):
                with self.subTest(case=case):
                    bad=copy.deepcopy(frame)
                    if case=='read':bad['relations'][0]['position_candidate']['read_end_ticks']=999999
                    elif case=='profile':bad['relations'][0]['health_candidate']['profile_sha256']='ff'*32
                    elif case=='epoch':bad['session_epoch']['segment_start_sha256']='ff'*32
                    else:bad['timing']['sequence']=99
                    line=raw(bad)
                    for fast in (False,True):
                        a=LiveRosterEpochs(raw(config))
                        with self.assertRaises(ValueError):
                            a._consume_decoded('p1',line,parse(line))if fast else a.consume('p1',line)
                        self.assertTrue(a.failed)
            for bad in (b'{"x":1,"x":2}\n',b'{"x":NaN}\n'):
                a=LiveRosterEpochs(raw(config))
                with self.assertRaises(ValueError):a.consume('p1',bad)
                self.assertTrue(a.failed)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config, self.frames = fixture(Path(self.temp.name))
        self.sources = {s['source_id']: s for s in self.config['sources']}

    def make(self, **kwargs):
        return LiveRosterEpochs(raw(self.config), **kwargs)

    def started(self, **kwargs):
        co = self.make(**kwargs)
        for sid in self.frames:
            co.consume(sid, raw(self.frames[sid][0]))
        return co

    def test_explicit_runtime_end_discards_suffix_without_flushing_or_native_claim(self):
        from compact_live_roster import CompactLiveRoster
        co=self.started();before=co.status();self.assertGreater(before['pending_bytes'],0)
        stop=max(x['previous_end'] for x in before['source_cursors'].values())+1
        pins={sid:'a1'*32 for sid in self.sources}
        events=co.end_input(stop,pins)
        self.assertEqual(len(events),1);event=events[0]
        self.assertEqual(event['schema'],'overwatch-decoder.live-roster-transition/1')
        self.assertEqual(event['input_end']['discarded_pending_bytes'],before['pending_bytes'])
        self.assertEqual(event['input_end']['discarded_pending_windows'],before['pending_windows'])
        self.assertEqual(event['input_end']['stop_ticks'],stop)
        self.assertEqual(event['input_end']['evidence_kind'],'caller_verified_producer_eof_not_native_sample')
        self.assertTrue(all(x['body_object_key']is None and x['authoritative_observation']is None for x in event['relations']))
        self.assertEqual(co.status()['pending_bytes'],0);self.assertTrue(co.status()['transition_open'])
        self.assertEqual(co.status()['input_frames'],before['input_frames'])
        self.assertEqual(co.status()['next_window_index'],before['next_window_index'])
        compact=CompactLiveRoster();projected=compact.consume(raw(event))
        self.assertEqual(projected['input_end'],event['input_end'])
        self.assertTrue(all(x['health_candidate']['value']is None and x['position_candidate']['value']is None for x in projected['players']))
        for fn in (lambda:co.consume('p1',raw(self.frames['p1'][1])),lambda:co.advance(stop+1000),lambda:co.end_input(stop,pins)):
            with self.assertRaisesRegex(ValueError,'closed'):fn()
        with self.assertRaisesRegex(ValueError,'compact_roster_failed'):compact.consume(raw(event))
        self.assertEqual(co.close()['pending_windows'],0)
        for key,value in (('stop_ticks',-1),('evidence_kind','native_sample'),('discarded_pending_bytes',-1),('source_result_sha256',{})):
            changed=copy.deepcopy(event);changed['input_end'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):CompactLiveRoster().consume(raw(changed))

    def test_end_requires_all_sources_valid_clock_and_exact_result_pins(self):
        for mode in ('missing_source','early_stop','bad_pin','missing_pin'):
            with self.subTest(mode=mode):
                co=self.make() if mode=='missing_source' else self.started()
                if mode=='missing_source':co.consume('p1',raw(self.frames['p1'][0]))
                stop=max(x['read_end_ticks']for x in co.last_accepted.values())
                pins={sid:'a1'*32 for sid in self.sources}
                if mode=='early_stop':stop-=1
                if mode=='bad_pin':pins['p1']='bad'
                if mode=='missing_pin':pins.pop('p1')
                with self.assertRaises(ValueError):co.end_input(stop,pins)
                self.assertTrue(co.failed)

    def test_end_during_existing_unknown_never_emits_duplicate_open_or_resumes(self):
        co=self.started();co.consume('p1',raw(unknown(self.frames['p1'][1])))
        before=co.status();self.assertTrue(before['transition_open'])
        stop=max(x['read_end_ticks']for x in co.last_accepted.values())
        self.assertEqual(co.end_input(stop,{sid:'a1'*32 for sid in self.sources}),[])
        self.assertEqual(co.status()['transition_start_ticks'],before['transition_start_ticks'])
        self.assertEqual(co.status()['pending_bytes'],0)
        self.assertEqual(co.status()['input_end']['discarded_pending_windows'],0)

    def test_raw_present_absent_fresh_present_publishes_other_actors_without_carry(self):
        self.config.update(observation_mode='raw-candidates',allow_unresolved_bodies=True)
        co=self.started();ck=pair(2)['controller_object_key']
        changed,first=replacement(self.sources['p1'],self.frames['p1'][0],1120,{})
        absent,missing=unresolved(changed,first,ck)
        opened=co.admit('p1',raw(absent),raw(missing))
        self.assertEqual([e['status'] for e in opened],['unknown'])
        self.assertEqual(co.status()['pending_bytes'],0)
        continuing=next_frame(self.frames['p2'][0],1130)
        closed=co.consume('p2',raw(continuing))
        self.assertEqual(closed[-1]['status'],'resumed_without_carried_values')
        self.assertEqual(closed[-1]['end_ticks'],1150)
        another=next_frame(missing,1170)
        another['relations'][0]['position_candidate']['value'][0]=77
        another['relations'][0]['health_candidate']['raw_sum']=72
        another['relations'][0]['health_candidate']['contributions'][0]['value']=72
        following=next_frame(continuing,1180)
        following['relations'][1]['position_candidate']['value'][0]=88
        following['relations'][1]['health_candidate']['raw_sum']=63
        following['relations'][1]['health_candidate']['contributions'][0]['value']=63
        co.consume('p1',raw(another));co.consume('p2',raw(following))
        partial=co.advance(1200)[0]
        self.assertEqual(partial['window_start_ticks'],1150)
        rows={r['controller_object_key']:r for r in partial['relations']}
        self.assertIsNone(rows[ck]['body_object_key']);self.assertEqual(rows[ck]['reason'],'body_binding_unresolved')
        self.assertIsNone(rows[ck]['authoritative_observation'])
        proof=rows[ck]['unresolved_body_observations'][0]
        self.assertEqual(proof['semantic_projection_sha256'],sha(raw(another)))
        self.assertEqual(proof['declaration'],absent['unresolved_bodies'][0])
        self.assertEqual(proof['relation']['evidence'],another['relations'][1]['evidence'])
        for n,expected in ((1,77),(3,88)):
            self.assertEqual(rows[pair(n)['controller_object_key']]['authoritative_observation']['relation']['position_candidate']['value'][0],expected)
        for n,expected in ((1,72),(3,63)):
            self.assertEqual(rows[pair(n)['controller_object_key']]['authoritative_observation']['relation']['health_candidate']['raw_sum'],expected)
        fresh,new=replacement(absent,another,1220,{})
        fresh.pop('unresolved_bodies')
        replacements={self.sources['p1']['profile_sha256']:fresh['profile_sha256'],
            self.sources['p1']['acquisition']['manifest_sha256']:fresh['acquisition']['manifest_sha256'],
            self.sources['p1']['acquisition']['evidence_sha256']:fresh['acquisition']['evidence_sha256'],
            pair(2)['body_object_key']:pair(20)['body_object_key']}
        fresh['objects']=change(self.sources['p1']['objects'],replacements)
        new['relations']=change(self.frames['p1'][0]['relations'],replacements,1220-self.frames['p1'][0]['timing']['end_ticks'])
        co.admit('p1',raw(fresh),raw(new))
        continued=next_frame(following,1230);closed=co.consume('p2',raw(continued))
        self.assertEqual(closed[-1]['status'],'resumed_without_carried_values')
        self.assertEqual(co.status()['pending_bytes'],0)
        new=next_frame(new,1270);health=new['relations'][1]['health_candidate']
        health['raw_sum']=33;health['contributions'][0]['value']=33
        co.consume('p1',raw(new));co.consume('p2',raw(next_frame(continued,1280)))
        row=next(r for r in co.advance(1300)[0]['relations'] if r['controller_object_key']==ck)
        self.assertEqual(row['body_object_key'],pair(20)['body_object_key'])
        self.assertEqual(row['authoritative_observation']['relation']['health_candidate']['raw_sum'],33)
        self.assertNotIn('unresolved_body_observations',row)
        self.assertEqual(co.status()['source_admissions'],2)

    def test_initial_unresolved_raw_source_publishes_unknown_body_and_never_inherits_body(self):
        self.config.update(observation_mode='raw-candidates',allow_unresolved_bodies=True)
        ck=pair(2)['controller_object_key']
        source,frame=unresolved(self.sources['p1'],self.frames['p1'][0],ck)
        self.config['sources'][0]=source
        self.config['roster']=[dict(p,body_object_key=None)if p['controller_object_key']==ck else p for p in self.config['roster']]
        co=self.make();events=co.consume('p1',raw(frame));co.consume('p2',raw(self.frames['p2'][0]))
        self.assertEqual(events,[])
        window=co.advance(1050)[0]
        self.assertEqual(sum(r['status']=='observed'for r in window['relations']),2)
        missing=next(r for r in window['relations']if r['controller_object_key']==ck)
        self.assertEqual(missing['reason'],'body_binding_unresolved');self.assertIsNone(missing['body_object_key'])
        missing['unresolved_body_sources'][0]['controller_identity_fields'][0]='caller-mutation'
        missing['unresolved_body_observations'][0]['declaration']['controller_identity_fields'][0]='caller-mutation'
        co.consume('p1',raw(next_frame(frame,1070)));co.consume('p2',raw(self.frames['p2'][1]))
        self.assertFalse(co.status()['transition_open']);co.advance(1100)
        self.assertEqual(co.close()['pending_bytes'],0)
        for case in ('reviewed','evidence','guard_hash','body_declaration','missing_provenance'):
            with self.subTest(case=case):
                bad=copy.deepcopy(self.config)
                if case=='reviewed':bad.pop('observation_mode')
                elif case=='evidence':bad['sources'][0]['unresolved_bodies'][0]['acquisition_evidence_sha256']='ff'*32
                elif case=='guard_hash':bad['sources'][0]['unresolved_bodies'][0]['profile_guards_sha256']='invalid'
                elif case=='body_declaration':bad['sources'][0]['fields'].append(dict(name='fixture_absent_body_0000_handle_candidate_i32',type='i32'))
                else:bad['sources'][0].pop('unresolved_bodies')
                with self.assertRaises(ValueError):LiveRosterEpochs(raw(bad))
        for case in ('observed_old_body','carried_health','wrong_controller','identity_bracket'):
            with self.subTest(case=case):
                bad=copy.deepcopy(frame);row=bad['relations'][1]
                if case=='observed_old_body':bad['relations'][1]=copy.deepcopy(self.frames['p1'][0]['relations'][1])
                elif case=='carried_health':row['health_candidate']=copy.deepcopy(self.frames['p1'][0]['relations'][1]['health_candidate'])
                elif case=='wrong_controller':row['controller_object_key']=pair(99)['controller_object_key']
                else:row['evidence'][0]['read_end_ticks']=9999
                with self.assertRaises(ValueError):self.make().consume('p1',raw(bad))

    def test_raw_unresolved_lookup_read_failure_still_suspends(self):
        self.config.update(observation_mode='raw-candidates',allow_unresolved_bodies=True)
        source,frame=unresolved(self.sources['p1'],self.frames['p1'][0],pair(2)['controller_object_key'])
        self.config['sources'][0]=source
        self.config['roster']=[dict(p,body_object_key=None)if p['controller_object_key']==pair(2)['controller_object_key']else p for p in self.config['roster']]
        for reason in ('identity_word_unobserved','guard_check_failed','invalid_read_bracket'):
            with self.subTest(reason=reason):
                co=self.make();bad=copy.deepcopy(frame);bad['relations'][1]['reason']=reason
                events=co.consume('p1',raw(bad));co.consume('p2',raw(self.frames['p2'][0]))
                self.assertEqual(events[0]['status'],'unknown');self.assertEqual(co.advance(5000),[])
                self.assertEqual(co.status()['pending_bytes'],0)

    def test_repeated_controller_presence_disagreement_cannot_resume(self):
        self.config.update(observation_mode='raw-candidates',allow_unresolved_bodies=True)
        co=self.started();ck=pair(1)['controller_object_key']
        first,frame=replacement(self.sources['p1'],self.frames['p1'][0],1120,{})
        absent,frame=unresolved(first,frame,ck);co.admit('p1',raw(absent),raw(frame))
        continuing=next_frame(self.frames['p2'][0],1130)
        self.assertEqual(co.consume('p2',raw(continuing)),[])
        self.assertTrue(co.status()['transition_open']);self.assertEqual(co.advance(1200),[])
        other,other_frame=replacement(self.sources['p2'],continuing,1220,{})
        other,other_frame=unresolved(other,other_frame,ck)
        events=co.admit('p2',raw(other),raw(other_frame))
        self.assertEqual(events[-1]['status'],'resumed_without_carried_values')
        self.assertEqual(events[-1]['end_ticks'],1250)

    def test_normal_windows_one_pass_and_status_is_nonclosing(self):
        co = self.started()
        self.assertEqual(co.status()['pending_windows'], 1)
        outputs = []
        for sid in self.frames:
            outputs += co.consume(sid, raw(self.frames[sid][1]))
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0]['schema'], 'overwatch-decoder.partition-research-live/1')
        observation = outputs[0]['relations'][0]['authoritative_observation']
        self.assertEqual(observation['semantic_projection_sha256'], sha(raw(self.frames['p1'][0])))
        self.assertFalse(co.status()['closed'])
        co.status()['source_cursors']['p1']['sequence'] = 999
        self.assertEqual(co.status()['source_cursors']['p1']['sequence'], 2)

    def test_normal_frame_is_parsed_once_and_serialized_window_is_not_repeated(self):
        import aggregate_live_partitions as aggregate
        import live_roster_epochs as roster
        co = self.make()
        with patch.object(aggregate, 'parse', wraps=aggregate.parse) as parse_once:
            with patch.object(roster, 'parse', side_effect=AssertionError('redundant parse')):
                co.consume('p1', raw(self.frames['p1'][0]))
            self.assertEqual(parse_once.call_count, 1)
        co.consume('p2', raw(self.frames['p2'][0]))
        co.consume('p1', raw(self.frames['p1'][1]))
        with patch.object(roster, 'canonical', side_effect=AssertionError('redundant window serialization')):
            result = co.consume('p2', raw(self.frames['p2'][1]))
        self.assertEqual(len(result), 1)
        self.assertEqual(co.output_bytes, len(aggregate.canonical(result[0]))+1)

    def test_single_source_replacement_preserves_other_cursor_not_values(self):
        co = self.started()
        source, first = replacement(self.sources['p1'], self.frames['p1'][0], 1120,
                                    {pair(2)['body_object_key']: pair(20)['body_object_key']})
        events = co.admit('p1', raw(source), raw(first))
        self.assertEqual([e['status'] for e in events], ['unknown'])
        self.assertEqual(co.status()['pending_bytes'], 0)
        continuing = next_frame(self.frames['p2'][0], 1130)
        events = co.consume('p2', raw(continuing))
        self.assertEqual(events[0]['status'], 'resumed_without_carried_values')
        self.assertEqual(events[0]['end_ticks'], 1150)
        self.assertTrue(all(row['body_object_key'] is None for row in events[0]['relations']))
        self.assertEqual(co.status()['next_window_index'], 3)
        for sid, frame in [('p1', next_frame(first, 1170)), ('p2', next_frame(continuing, 1180))]:
            co.consume(sid, raw(frame))
        windows = co.advance(1200)
        self.assertEqual(windows[0]['window_index'], 3)
        selected = windows[0]['relations'][1]['authoritative_observation']
        self.assertEqual(selected['relation']['body_object_key'], pair(20)['body_object_key'])
        self.assertEqual(selected['semantic_projection_sha256'], sha(raw(next_frame(first, 1170))))

    def test_staggered_self_replacement_waits_for_all_duplicate_bindings(self):
        co = self.started()
        mapping = {pair(1)['body_object_key']: pair(21)['body_object_key']}
        source1, first1 = replacement(self.sources['p1'], self.frames['p1'][0], 1120, mapping)
        co.admit('p1', raw(source1), raw(first1))
        old2 = next_frame(self.frames['p2'][0], 1130)
        self.assertEqual(co.consume('p2', raw(old2)), [])
        self.assertTrue(co.status()['transition_open'])
        source2, first2 = replacement(self.sources['p2'], old2, 1220, mapping)
        events = co.admit('p2', raw(source2), raw(first2))
        self.assertEqual(events[-1]['end_ticks'], 1250)
        self.assertFalse(co.status()['transition_open'])
        self.assertEqual(co.status()['source_cursors']['p1']['sequence'], 1)
        self.assertEqual(co.status()['source_cursors']['p2']['sequence'], 1)

    def test_five_source_self_barrier_requires_all_five_new_bindings(self):
        config = copy.deepcopy(self.config)
        frames = {sid: copy.deepcopy(values[0]) for sid, values in self.frames.items()}
        for n in range(3, 6):
            source = copy.deepcopy(self.sources['p2'])
            source['source_id'] = 'p' + str(n)
            source['session_id'] = str(n) * 32
            config['sources'].append(source)
            frame = copy.deepcopy(frames['p2'])
            frame['session_id'] = source['session_id']
            frames[source['source_id']] = frame
        co = LiveRosterEpochs(raw(config))
        for sid, frame in frames.items(): co.consume(sid, raw(frame))
        mapping = {pair(1)['body_object_key']: pair(21)['body_object_key']}
        for n, old in enumerate(config['sources'], 1):
            sid = old['source_id']
            source, first = replacement(old, frames[sid], 1100 + n*20, mapping)
            results = co.admit(sid, raw(source), raw(first))
            if n < 5:
                self.assertTrue(co.status()['transition_open'])
                self.assertFalse(any(e.get('status') == 'resumed_without_carried_values' for e in results))
            else:
                self.assertFalse(co.status()['transition_open'])
                self.assertEqual(results[-1]['end_ticks'], 1200)
        self.assertEqual(co.status()['source_admissions'], 5)

    def test_unknown_invalidation_and_cancel_never_fill_or_resume_without_fresh_epoch(self):
        co = self.started()
        terminal = unknown(next_frame(self.frames['p1'][0], 1070))
        events = co.invalidate('p1', raw(terminal))
        self.assertEqual(events[0]['trigger']['semantic_projection_sha256'], sha(raw(terminal)))
        self.assertTrue(all(row['authoritative_observation'] is None for row in events[0]['relations']))
        co.consume('p2', raw(self.frames['p2'][1]))
        self.assertEqual(co.advance(5000), [])
        summary = co.close()
        self.assertTrue(summary['transition_open'])
        self.assertEqual(summary['pending_bytes'], 0)
        self.assertFalse(summary['durability_verified'])

    def test_invalidate_rejects_unbounded_transport_before_parsing_or_accounting(self):
        valid = raw(unknown(next_frame(self.frames['p1'][0], 1070)))
        oversized = valid[:-1] + b' ' * MAX_LINE_BYTES + b'\n'
        cases = [('p1', oversized, 'roster_frame_bound'),
                 ('p1', valid.decode(), 'roster_frame_bound'),
                 ('p1', valid.rstrip(b'\n'), 'roster_frame_bound'),
                 ('p1', b'', 'roster_frame_bound'),
                 ('missing', valid, 'roster_unknown_source')]
        for sid, data, reason in cases:
            with self.subTest(source=sid, type=type(data).__name__, length=len(data)):
                co = self.started()
                before = co.status()
                with patch('live_roster_epochs.parse') as parser:
                    with self.assertRaisesRegex(ValueError, reason): co.invalidate(sid, data)
                    parser.assert_not_called()
                self.assertTrue(co.status()['failed'])
                self.assertEqual(co.status()['input_frames'], before['input_frames'])
                self.assertEqual(co.status()['input_bytes'], before['input_bytes'])

    def test_unknown_first_new_epoch_waits_for_actual_observed_frame(self):
        co = self.started()
        source, first = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
        co.admit('p1', raw(source), raw(unknown(first)))
        co.consume('p2', raw(next_frame(self.frames['p2'][0], 1130)))
        self.assertTrue(co.status()['transition_open'])
        events = co.consume('p1', raw(next_frame(first, 1170)))
        self.assertEqual(events[-1]['end_ticks'], 1200)

    def test_wrong_admissions_controller_replacement_or_target_are_latched(self):
        for case in ('epoch_hash', 'previous_end', 'recipe', 'controller', 'target', 'old_evidence', 'sequence'):
            with self.subTest(case=case):
                co = self.started()
                source, frame = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
                if case == 'epoch_hash': frame['session_epoch']['acquisition_end_sha256'] = 'ff'*32
                elif case == 'previous_end':
                    source['session_epoch']['previous_epoch_last_frame_end_ticks'] = 999
                    frame['session_epoch'] = copy.deepcopy(source['session_epoch'])
                elif case == 'recipe': source['acquisition']['recipe_sha256'] = 'ff'*32
                elif case == 'controller': source['objects'][0]['controller_object_key'] = pair(9)['controller_object_key']
                elif case == 'target': frame['target']['pid'] += 1
                elif case == 'old_evidence': source['acquisition']['evidence_sha256'] = self.sources['p1']['acquisition']['evidence_sha256']
                else: frame['timing']['sequence'] = 1
                with self.assertRaises(ValueError): co.admit('p1', raw(source), raw(frame))
                self.assertTrue(co.status()['failed'])
                with self.assertRaisesRegex(ValueError, 'closed'): co.consume('p2', raw(self.frames['p2'][1]))

    def test_unannounced_epoch_and_replayed_old_frame_reject(self):
        co = self.started()
        source, frame = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
        with self.assertRaises(ValueError): co.consume('p1', raw(frame))
        co = self.started()
        co.admit('p1', raw(source), raw(frame))
        with self.assertRaises(ValueError): co.consume('p1', raw(self.frames['p1'][0]))

    def test_failed_acquisitions_may_skip_ordinals_not_segments(self):
        co = self.started()
        source, frame = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
        source['session_epoch']['acquisition'] = 4
        frame['session_epoch'] = copy.deepcopy(source['session_epoch'])
        self.assertEqual(co.admit('p1', raw(source), raw(frame))[0]['status'], 'unknown')

    def test_crossing_resume_boundary_frame_is_validated_then_discarded(self):
        co = self.started()
        source, first = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
        co.admit('p1', raw(source), raw(first))
        co.consume('p2', raw(next_frame(self.frames['p2'][0], 1130)))
        crossing = next_frame(first, 1155)  # starts at 1145, barrier is 1150
        self.assertEqual(co.consume('p1', raw(crossing)), [])
        self.assertEqual(co.status()['pending_bytes'], 0)
        self.assertEqual(co.status()['source_cursors']['p1']['sequence'], 2)

    def test_limits_are_cumulative_and_recovery_retains_no_samples(self):
        co = self.started(maximum_events=5)
        source, frame = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
        co.admit('p1', raw(source), raw(frame))
        for end in (1170, 1220):
            frame = next_frame(frame, end)
            co.consume('p1', raw(frame))
            self.assertEqual(co.status()['pending_bytes'], 0)
        with self.assertRaisesRegex(ValueError, 'input_bound'):
            co.consume('p1', raw(next_frame(frame, 1270)))
        co = self.started(maximum_revisions=1)
        source, frame = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
        co.admit('p1', raw(source), raw(frame))
        with self.assertRaisesRegex(ValueError, 'revision_bound'):
            co.consume('p2', raw(next_frame(self.frames['p2'][0], 1130)))

    def test_output_budget_includes_transition_records(self):
        co = self.started(maximum_output_bytes=1)
        source, frame = replacement(self.sources['p1'], self.frames['p1'][0], 1120, {})
        with self.assertRaisesRegex(ValueError, 'output_bound'): co.admit('p1', raw(source), raw(frame))

    def test_sampling_gap_uses_existing_window_unknown_without_epoch_change(self):
        co = self.started()
        skipped = copy.deepcopy(self.frames['p1'][1])
        skipped['gap_before']['skipped_slots'] = 2
        co.consume('p1', raw(skipped))
        co.consume('p2', raw(self.frames['p2'][1]))
        result = co.advance(1100)[0]
        self.assertEqual(result['unavailable_sources']['p1'], 'gap_in_window')
        self.assertFalse(co.status()['transition_open'])
        self.assertEqual(co.status()['revision'], 1)

    def test_category_artifact_and_transport_event_hashes_are_distinct(self):
        config, frames = live_fixture(Path(self.temp.name))
        for source in config['sources']:
            source['session_epoch'] = copy.deepcopy(self.sources[source['source_id']]['session_epoch'])
            self.assertNotEqual(source['live_category']['live_scope']['segment_start_sha256'],
                                source['session_epoch']['segment_start_sha256'])
            frames[source['source_id']][0]['session_epoch'] = copy.deepcopy(source['session_epoch'])
        co = LiveRosterEpochs(raw(config))
        for sid in frames:
            co.consume(sid, raw(frames[sid][0]))
        self.assertFalse(co.status()['failed'])


if __name__ == '__main__':
    unittest.main()
