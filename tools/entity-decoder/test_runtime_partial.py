"""Partial observations preserve native source admission and never carry rows."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aggregate_partitions import canonical
from runtime_partial import PartialSources, PartialOutputFailure, EncodedPartialEvent
import test_runtime_startup as startup_fixture
from test_live_roster_epochs import next_frame,unknown


class PartialTests(unittest.TestCase):
    def setUp(self):
        self.fixture=startup_fixture.StartupTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.config=self.fixture.config;self.frames=self.fixture.frames
        self.primary={r['controller_object_key']:r['primary_source_id'] for r in self.config['roster']}
        self.recipes={s['source_id']:s['acquisition']['recipe_sha256'] for s in self.config['sources']}
        self.p=PartialSources(self.config['target'],1000,self.primary,self.recipes,{'manifest_sha256':'ab'*32})

    def test_independent_observation_never_carries_other_actor_or_failed_source(self):
        for source in self.config['sources']:self.p.admit(source,{'profile_sha256':source['profile_sha256']})
        first=self.p.consume('p1',canonical(self.frames['p1'][0])+b'\n')
        second=self.p.consume('p2',canonical(self.frames['p2'][0])+b'\n')
        self.assertEqual(len(first['relations']),len(self.primary))
        for event,sid in ((first,'p1'),(second,'p2')):
            self.assertFalse(event['common_time_snapshot']);self.assertFalse(event['previous_values_carried'])
            for row in event['relations']:
                self.assertEqual(row['status'],'observed' if row['primary_source_id']==sid else 'unknown')
                if row['status']=='unknown':self.assertIsNone(row['body_object_key']);self.assertIsNone(row['observation_pointer'])
        failed=self.p.unavailable('p2','producer_failed',{'result_sha256':'ab'*32})
        self.assertTrue(all(row['status']=='unknown' for row in failed['relations']))
        following=self.p.consume('p1',canonical(next_frame(self.frames['p1'][0],1100))+b'\n')
        self.assertEqual([r['reason'] for r in following['relations'] if r['primary_source_id']=='p2'],['source_unavailable'])
        with self.assertRaises(ValueError):self.p.consume('p2',canonical(self.frames['p2'][1])+b'\n')
        terminal=self.p.end();self.assertTrue(all(row['body_object_key'] is None for row in terminal['relations']))
        with self.assertRaises(ValueError):self.p.consume('p1',b'{}\n')

    def test_guard_unknown_and_gap_do_not_repeat_last_values(self):
        self.p.admit(self.config['sources'][0],{})
        self.p.consume('p1',canonical(self.frames['p1'][0])+b'\n')
        frame=unknown(next_frame(self.frames['p1'][0],1100))
        event=self.p.consume('p1',canonical(frame)+b'\n')
        self.assertTrue(all(r['observation_pointer'] is None for r in event['relations']))
        frame=next_frame(frame,1150);frame['gap_before']['skipped_slots']=1
        event=self.p.consume('p1',canonical(frame)+b'\n')
        self.assertTrue(all(r['status']=='unknown' for r in event['relations']))
        self.assertEqual(event['source_observation']['timing'],frame['timing'])

    def test_internal_decoded_frame_preserves_output_and_validation(self):
        import runtime_partial
        source=self.config['sources'][0];frame=self.frames['p1'][0]
        raw=canonical(frame)+b'\n'
        self.p.admit(source,{})
        expected=self.p.consume('p1',raw)
        other=PartialSources(self.config['target'],1000,self.primary,self.recipes,{'manifest_sha256':'ab'*32})
        other.admit(source,{})
        with patch.object(runtime_partial,'parse',side_effect=AssertionError('second parse')):
            actual=other._consume_decoded('p1',raw,frame)
        self.assertEqual(canonical(actual),canonical(expected))
        self.assertEqual(other.summary(),self.p.summary())
        bad=next_frame(frame,1100);bad['relations'][0]['health_candidate']['body_object_key']='body:'+'ff'*32
        with self.assertRaises(ValueError):other._consume_decoded('p1',canonical(bad)+b'\n',bad)
        with self.assertRaises(ValueError):other.consume('p1',canonical(next_frame(frame,1100))+b'\n')

    def test_public_consume_still_rejects_duplicate_json_members(self):
        self.p.admit(self.config['sources'][0],{})
        raw=canonical(self.frames['p1'][0])+b'\n'
        duplicate=b'{"schema":"overwatch-decoder.entity-relations-live/1",'+raw[1:]
        with self.assertRaises(ValueError):self.p.consume('p1',duplicate)
        self.assertEqual(self.p.output_events,0)

    def test_encoded_events_preserve_samples_gaps_epochs_and_terminal_bytes(self):
        from test_live_roster_epochs import replacement
        calls=[]
        metadata={'publication_mode':'offline_saved_source_replay','publication_qpc':None}
        def encode(value):
            calls.append(value['event'])
            return canonical(dict(value,**metadata))+b'\n'
        encoded=PartialSources(self.config['target'],1000,self.primary,self.recipes,
            {'manifest_sha256':'ab'*32},event_encoder=encode)
        observers=(self.p,encoded)
        for observer in observers:
            for source in self.config['sources']:observer.admit(source,{})
        byte_count=0
        def compare(method,*args):
            nonlocal byte_count
            expected=getattr(self.p,method)(*args);actual=getattr(encoded,method)(*args)
            self.assertIsInstance(expected,dict);self.assertIsInstance(actual,EncodedPartialEvent)
            self.assertEqual(actual.kind,expected['event'])
            self.assertEqual(actual.data,canonical(dict(expected,**metadata))+b'\n')
            byte_count+=len(actual.data)
        frame=self.frames['p1'][0]
        compare('consume','p1',canonical(frame)+b'\n')
        compare('consume','p2',canonical(self.frames['p2'][0])+b'\n')
        gap=next_frame(frame,1100);gap['gap_before']['skipped_slots']=1
        compare('consume','p1',canonical(gap)+b'\n')
        bodies={r['body_object_key']:'body:'+str(i+50).zfill(64)
                for i,r in enumerate(self.config['sources'][0]['objects'])}
        source,newframe=replacement(self.config['sources'][0],gap,1200,bodies)
        for observer in observers:observer.admit(source,{'fresh_epoch':True})
        compare('consume','p1',canonical(newframe)+b'\n')
        compare('unavailable','p2','producer_failed',{'result_sha256':'ab'*32})
        compare('end')
        self.assertEqual(calls,['observation']*4+['source_unavailable','input_end'])
        self.assertEqual(encoded.output_bytes,byte_count)
        self.assertEqual(encoded.output_events,self.p.output_events)
        self.assertEqual(encoded.summary()['sources'],self.p.summary()['sources'])

    def test_bad_provenance_rejected_before_encoder(self):
        calls=[]
        def encode(value):
            calls.append(value)
            return canonical(value)+b'\n'
        p=PartialSources(self.config['target'],1000,self.primary,self.recipes,{},event_encoder=encode)
        p.admit(self.config['sources'][0],{})
        frame=copy.deepcopy(self.frames['p1'][0])
        frame['relations'][0]['health_candidate']['body_object_key']='body:'+'ff'*32
        with self.assertRaises(ValueError):p.consume('p1',canonical(frame)+b'\n')
        self.assertEqual(calls,[]);self.assertEqual(p.output_events,0)

    def test_encoder_failures_prevent_later_terminal_encoding(self):
        for case in ('exception','not_bytes','no_newline','nonfinite'):
            with self.subTest(case=case):
                calls=[]
                def encode(value):
                    calls.append(value['event'])
                    if case=='exception':raise OSError('encoding_failed')
                    if case=='not_bytes':return '{}\n'
                    if case=='no_newline':return b'{}'
                    return canonical(dict(value,invalid=float('nan')))+b'\n'
                p=PartialSources(self.config['target'],1000,self.primary,self.recipes,{},event_encoder=encode)
                with self.assertRaises(PartialOutputFailure):p.unavailable('p1','failed',{})
                with self.assertRaisesRegex(PartialOutputFailure,'partial_output_failed'):p.end()
                self.assertEqual(calls,['source_unavailable'])
                self.assertEqual(p.output_events,0);self.assertEqual(p.output_bytes,0)

    def test_bad_identity_provenance_time_and_epoch_never_emit_values(self):
        for case in ('profile','target','epoch','body','read','order'):
            with self.subTest(case=case):
                p=PartialSources(self.config['target'],1000,self.primary,self.recipes,{})
                p.admit(self.config['sources'][0],{});frame=copy.deepcopy(self.frames['p1'][0])
                if case=='profile':frame['profile_sha256']='ff'*32
                elif case=='target':frame['target']['pid']+=1
                elif case=='epoch':frame['session_epoch']['acquisition']+=1
                elif case=='body':frame['relations'][0]['health_candidate']['body_object_key']='body:'+'ff'*32
                elif case=='read':frame['relations'][0]['position_candidate']['read_end_ticks']=999999
                elif case=='order':frame['timing']['sequence']=1
                with self.assertRaises(ValueError):p.consume('p1',canonical(frame)+b'\n')
                self.assertEqual(p.output_events,0)
                with self.assertRaises(ValueError):p.consume('p1',canonical(self.frames['p1'][0])+b'\n')

    def test_fresh_epoch_replaces_body_without_reusing_prior_values(self):
        from test_live_roster_epochs import replacement
        source=self.config['sources'][0];frame=self.frames['p1'][0]
        self.p.admit(source,{});self.p.consume('p1',canonical(frame)+b'\n')
        bodies={row['body_object_key']:'body:'+str(i+50).zfill(64) for i,row in enumerate(source['objects'])}
        fresh,next_value=replacement(source,frame,1100,bodies)
        bad=copy.deepcopy(fresh);bad['session_epoch']['previous_epoch_last_frame_end_ticks']-=1
        with self.assertRaises(ValueError):self.p.admit(bad,{})
        self.p.admit(fresh,{'fresh_epoch':True});event=self.p.consume('p1',canonical(next_value)+b'\n')
        self.assertEqual(event['source_observation'],next_value)
        observed=[row for row in event['relations'] if row['status']=='observed']
        self.assertTrue(observed);self.assertTrue(all(row['body_object_key'] in bodies.values() for row in observed))
        self.assertTrue(all(not v.pending for v in self.p.validators.values()))

    def subset_observer(self):
        """Context validation is exercised by parent admission tests separately."""
        self.addCleanup(patch.stopall)
        patch('aggregate_live_partitions.validate_context_source',return_value={}).start()
        patch('aggregate_live_partitions.validate_context_frame',return_value=None).start()
        parts={s['source_id']:[r['controller_object_key']for r in s['objects']]for s in self.config['sources']}
        context=next(iter(self.primary))
        p=PartialSources(self.config['target'],1000,self.primary,self.recipes,{},
            allow_controller_subsets=True,partition_controllers=parts,required_context_controller_key=context)
        return p,parts,context

    def subset_source(self,source,parts,context):
        from runtime_partial import controller_subset_metadata
        source=copy.deepcopy(source);sid=source['source_id']
        source['context_projection']={'upstream_validated_fixture':True}
        scope=controller_subset_metadata(parts[sid],[ck for ck,s in self.primary.items()if s==sid],
            [r['controller_object_key']for r in source['objects']],context)
        source['controller_subset']=scope
        return source,{'controller_subset':copy.deepcopy(scope)}

    def test_subset_shrink_regrow_clears_missing_rows_and_keeps_exact_samples(self):
        from test_live_roster_epochs import replacement
        for removed in (0,1):
            with self.subTest(removed=removed):
                p,parts,context=self.subset_observer()
                source,pins=self.subset_source(self.config['sources'][0],parts,context)
                frame=copy.deepcopy(self.frames['p1'][0]);p.admit(source,pins);p.consume('p1',canonical(frame)+b'\n')
                fresh,value=replacement(source,frame,1100,{})
                missing=fresh['objects'].pop(removed)['controller_object_key']
                value['relations'].pop(removed)
                fresh,pins=self.subset_source(fresh,parts,context);p.admit(fresh,pins)
                event=p.consume('p1',canonical(value)+b'\n')
                row=next(r for r in event['relations']if r['controller_object_key']==missing)
                self.assertEqual(row['reason'],'not_in_acquired_subset');self.assertIsNone(row['body_object_key'])
                self.assertEqual(event['source_observation'],value)
                self.assertIn(missing,p.summary()['omitted_controller_keys'])
                self.assertFalse(p.summary()['all_census_primaries_acquired'])
                restored,newframe=replacement(source,frame,1200,{})
                # Advance from the subset epoch while restoring the original rows.
                restored['segment']=3;restored['session_epoch'].update(acquisition=3,previous_epoch_last_frame_end_ticks=value['timing']['end_ticks'])
                newframe['segment']=3;newframe['session_epoch']=copy.deepcopy(restored['session_epoch']);newframe['event_sequence']=value['event_sequence']+6
                restored,pins=self.subset_source(restored,parts,context);p.admit(restored,pins)
                event=p.consume('p1',canonical(newframe)+b'\n')
                self.assertEqual(sum(r['status']=='observed'for r in event['relations']),2)
                self.assertNotIn(missing,p.summary()['omitted_controller_keys'])
                self.assertEqual(p.summary()['coverage_scope'],'latest_admitted_profiles_only_not_continuous_coverage')
                self.assertTrue(all(not v.pending for v in p.validators.values()))
                self.assertTrue(all(r['body_object_key']is None for r in p.end()['relations']))

    def test_subset_scope_rejects_foreign_duplicates_empty_pins_and_strict_mode(self):
        for case in ('foreign','duplicate','empty','pin','context','strict'):
            with self.subTest(case=case):
                p,parts,context=self.subset_observer();source,pins=self.subset_source(self.config['sources'][0],parts,context)
                if case=='foreign':source['objects'][0]['controller_object_key']=next(ck for ck,s in self.primary.items()if s=='p2')
                elif case=='duplicate':source['objects'].append(copy.deepcopy(source['objects'][0]))
                elif case=='empty':source['objects']=[]
                elif case=='pin':pins['controller_subset']['omitted_controllers']=[{'controller_object_key':context}]
                elif case=='context':source.pop('context_projection')
                else:p=self.p
                with self.assertRaises(ValueError):p.admit(source,pins)
                self.assertEqual(p.output_events,0)

    def test_subset_fresh_epoch_and_profile_checks_remain_required(self):
        from test_live_roster_epochs import replacement
        for case in ('old_epoch','previous_end','stale_frame_profile'):
            with self.subTest(case=case):
                p,parts,context=self.subset_observer();source,pins=self.subset_source(self.config['sources'][0],parts,context)
                frame=copy.deepcopy(self.frames['p1'][0]);p.admit(source,pins);p.consume('p1',canonical(frame)+b'\n')
                fresh,value=replacement(source,frame,1100,{})
                fresh['objects']=fresh['objects'][:1];value['relations']=value['relations'][:1]
                fresh,pins=self.subset_source(fresh,parts,context)
                if case=='old_epoch':fresh['segment']=1
                elif case=='previous_end':fresh['session_epoch']['previous_epoch_last_frame_end_ticks']-=1
                if case!='stale_frame_profile':
                    with self.assertRaises(ValueError):p.admit(fresh,pins)
                else:
                    p.admit(fresh,pins);value['profile_sha256']=source['profile_sha256']
                    with self.assertRaises(ValueError):p.consume('p1',canonical(value)+b'\n')

    def test_final_serialized_limit_preserves_failure_receipt(self):
        import runtime_roster as runtime
        import runtime_partial
        class Clock:
            frequency=1000
            def tick(self):return 10000
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'out';out.mkdir();source=root/'p1';source.mkdir()
            runtime.save(source/'result.json',dict(complete=False,error='acquisition_predicate_failed'))
            ck=next(iter(self.primary));primary={ck:1};recipes={'p1':'ab'*32}
            census={'manifest_sha256':'cd'*32}
            probe=PartialSources(self.config['target'],1000,{ck:'p1'},recipes,census)
            event=probe.unavailable('p1',"ValueError('source_ended_before_admission')",
                {'result.json_sha256':runtime.digest(source/'result.json')})
            limit=len(canonical(event))+1
            plan=dict(target=self.config['target'],census_source=census,partitions=[dict(ordinal=1,recipe_sha256=recipes['p1'])])
            with patch.object(runtime,'reviewed_inputs',return_value=({},primary)),patch.object(runtime_partial,'MAX_TOTAL_BYTES',limit):
                report=runtime.observe_partial_sources(root,plan,{},[dict(source_id='p1',ordinal=1,directory=str(source))],out,Clock(),ready_timeout=1,total_timeout=10)
            self.assertFalse(report['capture_finished']);self.assertIsNotNone(report['fatal_error'])
            self.assertEqual(report['output_bytes'],0);self.assertEqual(report['output_events'],0)
            self.assertTrue((out/'partial-result.json').exists());self.assertTrue((source/'result.json').exists())

    def test_parent_keeps_good_sources_after_failed_partition(self):
        import runtime_roster as runtime
        class Clock:
            frequency=1000
            def tick(self):return 10000
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'out';out.mkdir();children=[]
            sources={s['source_id']:s for s in self.config['sources']}
            for ordinal,(sid,frames) in enumerate(self.frames.items(),1):
                path=root/sid;path.mkdir();data=b''.join(canonical(frame)+b'\n' for frame in frames) if sid=='p1' else b''
                (path/'entities.jsonl').write_bytes(data);(path/'native.jsonl').write_bytes(b'partial native evidence\n')
                result=dict(complete=sid=='p1',error=None if sid=='p1' else 'acquisition_predicate_failed',native_exit=0 if sid=='p1' else 7,
                    frames=len(frames) if sid=='p1' else 0,entities_sha256=hashlib.sha256(data).hexdigest(),
                    decoder=dict(native_session_end_seen=True,phase='ended',frames=len(frames)),
                    epochs=[dict(segment=1,profile_sha256=sources[sid]['profile_sha256'])])
                runtime.save(path/'result.json',result);children.append(dict(source_id=sid,ordinal=ordinal,directory=str(path)))
            plan=dict(target=self.config['target'],census_source={'manifest_sha256':'ab'*32},
                partitions=[dict(ordinal=i,recipe_sha256=self.recipes[f'p{i}']) for i in (1,2)])
            primary={ck:int(sid[1:]) for ck,sid in self.primary.items()}
            def admit(child,*args,**kwargs):return sources[child['source_id']],self.frames[child['source_id']][0],{}
            with patch.object(runtime,'reviewed_inputs',return_value=({},primary)),patch.object(runtime,'source_admission',side_effect=admit):
                report=runtime.observe_partial_sources(root,plan,{},children,out,Clock(),ready_timeout=1,total_timeout=10)
            self.assertFalse(report['complete']);self.assertEqual(report['frames'],len(self.frames['p1']))
            events=[json.loads(line) for line in (out/'partial-entities.jsonl').read_bytes().splitlines()]
            self.assertEqual(events[-1]['event'],'input_end')
            self.assertTrue(all(e['publication_qpc']==10000 for e in events))
            observations=[e for e in events if e['event']=='observation']
            self.assertEqual([e['source_observation'] for e in observations],self.frames['p1'])
            self.assertTrue(any(e['event']=='source_unavailable' and e['source_id']=='p2' for e in events))
            self.assertTrue(all(len(e['relations'])==len(self.primary) for e in events))
            self.assertFalse((out/'aggregate-config.json').exists())
            self.assertEqual((root/'p2/native.jsonl').read_bytes(),b'partial native evidence\n')
            performance=json.loads((out/'partial-performance.json').read_bytes())
            self.assertEqual(performance['runtime_mode'],'partial_independent_sources')
            self.assertEqual(performance['stages']['parent_parse']['calls'],len(self.frames['p1']))
            self.assertEqual(performance['stages']['coordinator']['calls'],len(self.frames['p1']))
            self.assertEqual(performance['stages']['serialize']['calls'],len(events))
            self.assertEqual(performance['stages']['write']['calls'],len(events))
            self.assertEqual(performance['stages']['write']['bytes'],report['output_bytes'])
            self.assertEqual(performance['nested_stages']['coordinator'],['serialize'])

    def test_parent_output_failure_never_appends_terminal_to_incomplete_write(self):
        import runtime_roster as runtime
        class Clock:
            frequency=1000
            def tick(self):return 10000
        for failure in ('partial_write','flush'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);out=root/'out';out.mkdir();source=root/'p1';source.mkdir()
                runtime.save(source/'result.json',dict(complete=False,error='acquisition_predicate_failed'))
                ck=next(iter(self.primary));plan=dict(target=self.config['target'],
                    census_source={'manifest_sha256':'cd'*32},
                    partitions=[dict(ordinal=1,recipe_sha256='ab'*32)])
                calls=[]
                def broken_write(file,raw,perf):
                    calls.append(raw)
                    file.write(raw[:20] if failure=='partial_write' else raw)
                    file.flush()
                    raise OSError('injected_'+failure+'_failure')
                with patch.object(runtime,'reviewed_inputs',return_value=({},{ck:1})),patch.object(runtime,'write_flushed',side_effect=broken_write):
                    report=runtime.observe_partial_sources(root,plan,{},
                        [dict(source_id='p1',ordinal=1,directory=str(source))],out,Clock(),
                        ready_timeout=1,total_timeout=10,live=False)
                self.assertEqual(len(calls),1)
                self.assertEqual(json.loads(calls[0])['event'],'source_unavailable')
                self.assertIn('injected_'+failure+'_failure',report['fatal_error'])
                self.assertFalse(report['capture_finished']);self.assertFalse(report['complete'])
                self.assertEqual(report['attempted_output_events'],1)
                self.assertEqual(report['output_events'],0);self.assertEqual(report['output_bytes'],0)
                data=(out/'partial-entities.jsonl').read_bytes()
                self.assertEqual(data,calls[0][:20] if failure=='partial_write' else calls[0])
                self.assertEqual(report['output_sha256'],hashlib.sha256(data).hexdigest())
                self.assertEqual(json.loads((out/'partial-result.json').read_bytes()),report)
                self.assertTrue((source/'result.json').exists())
                performance=json.loads((out/'partial-performance.json').read_bytes())
                self.assertEqual(performance['stages']['serialize']['calls'],1)

if __name__=='__main__':unittest.main()
