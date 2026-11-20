"""Original-event preparation and source-bound activation, synthetic fixtures only."""
import copy,json,unittest,tempfile
from pathlib import Path
from export_relations import digest
from relations import GuardedRelations
from live_relations import LiveRelations
from live_sessions import LiveSession
from test_live_sessions import fixture,consume_all
from test_live_relations import raw,live,next_frame


def sequence(events):
    for index,event in enumerate(events):event['event_sequence']=index
    return events


def background_fixture(root):
    epochs,legacy,factory,calls=fixture(root,3)
    events=copy.deepcopy(legacy[:6]);events[0]['background_preparation']=True
    session=events[0]['session_id']
    def event(kind,emitted,**kwargs):return dict(schema='overwatch-decoder.field-live/1',kind=kind,session_id=session,
        event_sequence=0,emitted_ticks=emitted,monotonic_frequency=1000,**kwargs)
    events.append(event('preparation_start',1130,acquisition=2,origin_segment=1,start_ticks=1125,observation_gap_open=False))
    old=next_frame(epochs[1][1])
    # Preserve the scheduler slot; this actual read is 50 ticks late.
    for key in ('start_ticks','end_ticks'):old[key]+=50
    old['jitter_ticks']+=50
    for phase in ('guards_before','guards_after'):
        for check in old[phase]:
            for key in ('start_ticks','end_ticks'):check[key]+=50
    for sample in old['fields'].values():
        for key in ('read_start_ticks','read_end_ticks'):sample[key]+=50
    continued=live(old,0);continued['emitted_ticks']=1270;events.append(continued)
    entry=copy.deepcopy(legacy[8]['acquisition']);entry.update(start_ticks=1125,end_ticks=1180)
    prepared_end=event('preparation_end',1280,origin_segment=1,acquisition=entry,outcome='ready');events.append(prepared_end)
    ended=copy.deepcopy(legacy[6]);ended.update(emitted_ticks=1290)
    ended['segment'].update(end_ticks=1285,frames=2,last_frame_end_ticks=1250,trigger='prepared_reacquisition');events.append(ended)
    decoder=GuardedRelations((root/'2/profile.json').read_bytes());start=1300;end=start+2*len(decoder.guards)+10
    proof=dict(schema='overwatch-decoder.profile-activation/1',target=decoder.target,profile_sha256=decoder.hash,
        start_ticks=start,end_ticks=end,passed=True,error=None,guards=[dict(guard_id=i,address_hex=f"{g['address']:016x}",
        bytes_hex=g['bytes_hex'],start_ticks=start+2*i,end_ticks=start+2*i+1) for i,g in enumerate(decoder.guards)])
    data=raw(proof);(root/'2/activation.json').write_bytes(data)
    activated=event('acquisition_end',1400,acquisition=copy.deepcopy(entry),prepared=True,origin_segment=1,
        preparation_end_sha256=None,activation=dict(start_ticks=start,end_ticks=end,guard_count=len(decoder.guards),guards_verified=True,evidence_sha256=digest(data)))
    events.append(activated)
    newsegment=copy.deepcopy(legacy[9]);newsegment['prepared']=True;events.append(newsegment)
    newgap=copy.deepcopy(legacy[10]);newgap['interval']['start_ticks']=1250;events.append(newgap)
    events.extend(copy.deepcopy(legacy[11:13]))
    terminal=copy.deepcopy(legacy[-2:]);terminal[0]['emitted_ticks']=2140;terminal[0]['interval'].update(start_ticks=2100,end_ticks=2140)
    terminal[1]['emitted_ticks']=2150;events.extend(terminal)
    sequence(events);activated['preparation_end_sha256']=digest(raw(prepared_end))
    return epochs,events,factory,calls,proof


def kinds(events,kind):return next(e for e in events if e['kind']==kind)


class BackgroundPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.epochs,self.events,self.factory,self.calls,self.proof=background_fixture(self.root)
    def test_old_reader_continues_without_gap_or_candidate_values_and_activation_uses_original_pins(self):
        coordinator=LiveSession(self.factory);results=[]
        for event in self.events:
            result=coordinator.consume(raw(event))
            if event['kind'] in ('preparation_start','preparation_end'):
                self.assertIsNone(result);self.assertEqual(coordinator.phase,'active');self.assertEqual(len(self.calls),1)
            if result is not None:results.append(result)
        self.assertEqual(len(results),3)
        self.assertEqual([r['relations'][0]['health_candidate']['raw_sum'] for r in results],[100.,100.,50.])
        self.assertEqual([r['relations'][0]['position_candidate']['value'][0] for r in results],[10.,10.,20.])
        self.assertNotIn('prepared_activation',results[0]);self.assertNotIn('prepared_activation',results[1])
        self.assertEqual(results[1]['segment'],1);self.assertEqual(results[2]['segment'],2)
        pins=results[2]['session_epoch'];ended=kinds(self.events,'preparation_end')
        self.assertEqual(pins['preparation_end_sha256'],digest(raw(ended)))
        self.assertEqual(pins['acquisition_end_sha256'],digest(raw(next(e for e in self.events if e.get('prepared') and e['kind']=='acquisition_end'))))
        self.assertEqual(results[2]['prepared_activation']['evidence_sha256'],digest(raw(self.proof)))
        self.assertFalse(pins['previous_values_carried']);self.assertTrue(coordinator.ended)
        self.assertEqual(coordinator.attempts,2);self.assertIsNone(coordinator.preparation)
        self.assertEqual(coordinator.close()['preparations_observed'][0]['outcome'],'activated')
    def test_optin_single_worker_and_false_gap_contract(self):
        for mode in ('default','duplicate','gap','ordinal','origin'):
            events=copy.deepcopy(self.events)
            if mode=='default':events[0].pop('background_preparation')
            if mode=='duplicate':events.insert(7,copy.deepcopy(events[6]))
            if mode=='gap':events[6]['gap_start_ticks']=1100
            if mode=='ordinal':events[6]['acquisition']=3
            if mode=='origin':events[6]['origin_segment']=2
            sequence(events)
            with self.subTest(mode=mode),self.assertRaises(ValueError):consume_all(LiveSession(self.factory),events)
    def test_original_preparation_hash_entry_marker_and_freshness_are_required(self):
        for mode in ('hash','entry','marker','early'):
            events=copy.deepcopy(self.events);activated=next(e for e in events if e.get('prepared') and e['kind']=='acquisition_end')
            if mode=='hash':activated['preparation_end_sha256']='00'*32
            if mode=='entry':activated['acquisition']['end_ticks']+=1
            if mode=='marker':next(e for e in events if e['kind']=='segment_start' and e['segment']==2).pop('prepared')
            if mode=='early':activated['activation']['start_ticks']=1240
            with self.subTest(mode=mode),self.assertRaises(ValueError):consume_all(LiveSession(self.factory),events)
    def test_hash_consistent_forged_activation_proofs_are_rejected_before_new_values(self):
        for mode in ('target','profile','passed','error','id','address','bytes','time','count'):
            events=copy.deepcopy(self.events);proof=copy.deepcopy(self.proof)
            if mode=='target':proof['target']['pid']+=1
            if mode=='profile':proof['profile_sha256']='00'*32
            if mode=='passed':proof['passed']=False
            if mode=='error':proof['error']='read_failed'
            if mode=='id':proof['guards'][0]['guard_id']=1
            if mode=='address':proof['guards'][0]['address_hex']='0000000000009999'
            if mode=='bytes':proof['guards'][0]['bytes_hex']='ffffffff'
            if mode=='time':proof['guards'][0]['start_ticks']=proof['start_ticks']-1
            if mode=='count':proof['guards'].pop()
            data=raw(proof);(self.root/'2/activation.json').write_bytes(data)
            next(e for e in events if e.get('prepared') and e['kind']=='acquisition_end')['activation']['evidence_sha256']=digest(data)
            coordinator=LiveSession(self.factory)
            with self.subTest(mode=mode),self.assertRaises(ValueError):consume_all(coordinator,events)
            self.assertEqual(coordinator.frames,2);self.assertTrue(coordinator.failed);self.assertIsNone(coordinator.adapter)
    def test_preparation_failure_is_explicit_and_does_not_stop_valid_old_reader(self):
        events=copy.deepcopy(self.events[:9]);ended=events[-1]
        ended['outcome']='failed';ended['acquisition'].update(complete=False,error='acquisition_predicate_failed',profile_sha256=None,manifest_sha256=None)
        # One more old-reader frame after the failed candidate; no observation gap.
        frame=next_frame(events[7]['recording_frame']);extra=live(frame,0);extra['emitted_ticks']=1370;events.append(extra)
        stop=copy.deepcopy(self.events[9]);stop['emitted_ticks']=1390
        stop['segment'].update(trigger='cancelled',end_ticks=1385,frames=3,last_frame_end_ticks=1350);events.append(stop)
        events.append(dict(self.events[-2],emitted_ticks=1400,interval=dict(start_ticks=1350,end_ticks=1400)))
        events.append(dict(self.events[-1],emitted_ticks=1410));sequence(events)
        coordinator=LiveSession(self.factory);results=consume_all(coordinator,events)
        self.assertEqual([r['relations'][0]['health_candidate']['raw_sum'] for r in results],[100.,100.,100.])
        self.assertEqual(len(self.calls),1);self.assertEqual(coordinator.failed_acquisitions,1)
        self.assertEqual(coordinator.close()['preparations_observed'][0]['outcome'],'failed')
    def test_cancelled_worker_after_segment_close_is_recorded_without_false_activation(self):
        events=copy.deepcopy(self.events[:8]);stop=copy.deepcopy(self.events[9]);stop['segment']['trigger']='cancelled';events.append(stop)
        ended=copy.deepcopy(self.events[8]);ended['emitted_ticks']=1310;ended['outcome']='cancelled'
        ended['acquisition'].update(complete=False,error='cancelled',profile_sha256=None,manifest_sha256=None);events.append(ended)
        events.append(dict(self.events[-2],emitted_ticks=1400,interval=dict(start_ticks=1250,end_ticks=1400)))
        events.append(dict(self.events[-1],emitted_ticks=1410));sequence(events)
        coordinator=LiveSession(self.factory);results=consume_all(coordinator,events)
        self.assertEqual(len(results),2);self.assertEqual(len(self.calls),1);self.assertEqual(coordinator.attempts,2)
        self.assertEqual(coordinator.close()['preparations_observed'][0]['outcome'],'cancelled')
    def test_ready_candidate_must_be_explicitly_discarded_before_terminal(self):
        events=copy.deepcopy(self.events[:10]);events[-1]['segment']['trigger']='cancelled'
        discard=dict(schema='overwatch-decoder.field-live/1',kind='preparation_discard',session_id=self.events[0]['session_id'],event_sequence=0,
            emitted_ticks=1400,monotonic_frequency=1000,acquisition=2,origin_segment=1,error='duration_elapsed',start_ticks=1390,end_ticks=1390,evidence_sha256=None)
        terminal=[dict(self.events[-2],emitted_ticks=1410,interval=dict(start_ticks=1250,end_ticks=1410)),dict(self.events[-1],emitted_ticks=1420)]
        valid=sequence([*events,discard,*terminal]);coordinator=LiveSession(self.factory);consume_all(coordinator,valid)
        self.assertEqual(coordinator.close()['preparations_observed'][0]['outcome'],'discarded')
        invalid=sequence([*events,*terminal])
        with self.assertRaisesRegex(ValueError,'unfinished_preparation'):consume_all(LiveSession(self.factory),invalid)
    def test_deployed_projector_factory_resolves_activation_file_without_artifact_injection(self):
        from unittest.mock import patch
        import run_selected_live as runner
        from test_selected_entity_view import relative_fixture
        from test_hero_asset_labels import fixture as asset_fixture
        profile,c,_,kwargs=relative_fixture();_,_,catalog,asset_artifacts,_=asset_fixture()
        package=self.root/'package';private=package/'private';(private/'artifacts').mkdir(parents=True);(private/'recipes').mkdir()
        (package/'config.json').write_bytes(raw(dict(batches=['one'])))
        artifacts=dict(kwargs['artifacts'],**asset_artifacts);calibration=b'synthetic calibration';calpin=digest(calibration);artifacts[calpin]=calibration
        for pin,data in artifacts.items():(private/'artifacts'/f'{pin}.bin').write_bytes(data)
        (private/'catalog.json').write_bytes(raw(catalog))
        proofpin=c['bindings'][0]['review_sha256'];nativepin=c['category_rule']['review_sha256']
        for name,pin in [('selected-review',proofpin),('native-review',nativepin),('practice-calibration',calpin)]:
            (private/(name+'.sha256')).write_text(pin)
        template=dict(schema='overwatch-decoder.selected-runner-template/1',local_validation_status='local',binding_validation_status='binding',
            health_validation_status='health',category_rule={k:v for k,v in c['category_rule'].items() if k not in ('review_sha256','label_review_sha256')})
        (private/'selected-template.json').write_bytes(raw(template));recipe=raw(dict(target={k:c['target'][k] for k in
            ('image_name','architecture','executable_sha256')},stages=[]));(private/'recipes/batchone.json').write_bytes(recipe)
        actor=dict(c['bindings'][0]['fields'],ordinal_within_profile_only=0,health_sum='sum')
        (private/'recipes/batchone.bindings.json').write_bytes(raw(dict(local_context=c['local_context']['fields'],actors=[actor])))
        observation=self.root/'actual-path';directory=observation/'acquisition-0002';directory.mkdir(parents=True)
        evidence=b'{"synthetic":true}\n';manifest=raw(dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,target=c['target'],
            profile_sha256=digest(profile),recipe_sha256=digest(recipe),evidence_sha256=digest(evidence),stages_completed=0))
        for name,data in [('profile.json',profile),('manifest.json',manifest),('evidence.jsonl',evidence)]:
            (directory/name).write_bytes(data)
        source=GuardedRelations(profile,allow_profile4=True);a=1300;b=a+len(source.guards)*2+10
        proof=dict(schema='overwatch-decoder.profile-activation/1',target=source.target,profile_sha256=source.hash,passed=True,error=None,
            start_ticks=a,end_ticks=b,guards=[dict(guard_id=n,address_hex=f"{g['address']:016x}",bytes_hex=g['bytes_hex'],
            start_ticks=a+2*n,end_ticks=a+2*n+1) for n,g in enumerate(source.guards)])
        proofbytes=raw(proof);(directory/'activation.json').write_bytes(proofbytes)
        session=copy.deepcopy(self.events[0]);session.update(target=c['target'],recipe_sha256=digest(recipe))
        prepstart=copy.deepcopy(self.events[6]);prepend=copy.deepcopy(self.events[8]);entry=prepend['acquisition']
        entry.update(profile_sha256=source.hash,manifest_sha256=digest(manifest));prepend['event_sequence']=8
        activated=copy.deepcopy(self.events[10]);activated.update(acquisition=copy.deepcopy(entry),preparation_end_sha256=digest(raw(prepend)))
        activated['activation']=dict(start_ticks=a,end_ticks=b,guard_count=len(source.guards),guards_verified=True,evidence_sha256=digest(proofbytes))
        activated['emitted_ticks']=b+10
        segment=copy.deepcopy(self.events[11]);segment.update(profile_sha256=source.hash,source_stream_schema='overwatch-decoder.field-stream/4',
            fields=[dict(name=f['name'],type=f['type']) for f in json.loads(profile)['fields']])
        with patch.object(runner,'BASE',package):
            projectors=runner.Projectors('one',observation,self.root/'factory-output');projectors.output.mkdir()
            adapter=projectors.factory(session,entry,segment)
            self.assertNotIn(digest(proofbytes),projectors.artifacts)
            adapter.begin_epoch(raw(session),raw(activated),raw(segment),preparation_start_raw=raw(prepstart),preparation_end_raw=raw(prepend))
            self.assertTrue(adapter.prepared_activation['actual_guard_bytes_verified'])
            # Pinning the real path is mandatory even though no injected dict contains it.
            (directory/'activation.json').write_bytes(proofbytes+b' ')
            projectors.output=self.root/'factory-output-again';projectors.output.mkdir()
            other=projectors.factory(session,entry,segment)
            with self.assertRaisesRegex(ValueError,'prepared_activation_hash'):other.begin_epoch(raw(session),raw(activated),raw(segment),
                preparation_start_raw=raw(prepstart),preparation_end_raw=raw(prepend))

    def test_activated_unstarted_terminal_is_explicit_without_candidate_values(self):
        events=copy.deepcopy(self.events[:11])
        events.append(dict(self.events[-2],emitted_ticks=1500,interval=dict(start_ticks=1250,end_ticks=1500)))
        events.append(dict(self.events[-1],emitted_ticks=1510));sequence(events)
        coordinator=LiveSession(self.factory);results=consume_all(coordinator,events)
        self.assertEqual(len(results),2);self.assertEqual(len(self.calls),1)
        summary=coordinator.close()['preparations_observed'][0]
        self.assertEqual(summary['outcome'],'activation_announced_unstarted')
        self.assertFalse(summary['observed_values_published']);self.assertFalse(summary['activation_bytes_verified'])
        self.assertTrue(coordinator.ended);self.assertIsNone(coordinator.preparation)

    def test_discarded_activation_falls_back_to_fresh_synchronous_acquisition(self):
        events=copy.deepcopy(self.events[:10]);prepared=kinds(events,'preparation_end')
        discard=dict(schema='overwatch-decoder.field-live/1',kind='preparation_discard',session_id=self.events[0]['session_id'],event_sequence=0,
            emitted_ticks=1400,monotonic_frequency=1000,acquisition=2,origin_segment=1,error='acquisition_guard_mismatch',start_ticks=1300,end_ticks=1340,evidence_sha256='ab'*32)
        events.append(discard)
        profile,frame,manifest,contracts=self.epochs[3]
        session=self.events[0]['session_id']
        def event(kind,ticks,**kwargs):return dict(schema='overwatch-decoder.field-live/1',kind=kind,session_id=session,
            event_sequence=0,emitted_ticks=ticks,monotonic_frequency=1000,**kwargs)
        events.append(event('acquisition_start',1510,acquisition=3,start_ticks=1500,observation_gap_open=True,gap_start_ticks=1250))
        entry=dict(ordinal=3,directory='acquisition-0003',start_ticks=1500,end_ticks=2800,complete=True,error=None,
            profile_sha256=manifest['profile_sha256'],manifest_sha256=digest((self.root/'3/manifest.json').read_bytes()))
        events.append(event('acquisition_end',2810,acquisition=entry))
        events.append(event('segment_start',2910,segment=2,acquisition=3,profile_sha256=manifest['profile_sha256'],
            source_stream_schema='overwatch-decoder.field-stream/1',start_ticks=2900,fields=[dict(name=f['name'],type=f['type']) for f in profile['fields']]))
        events.append(event('gap',3110,interval=dict(start_ticks=1250,end_ticks=frame['start_ticks'])))
        sampled=live(frame,0);sampled.update(segment=2,emitted_ticks=3120);events.append(sampled)
        events.append(event('segment_end',3130,terminal_summary_written=True,failure=None,segment=dict(ordinal=2,acquisition=3,
            profile_sha256=manifest['profile_sha256'],start_ticks=2900,end_ticks=3125,frames=1,first_frame_start_ticks=frame['start_ticks'],
            last_frame_end_ticks=3100,trigger='cancelled')))
        events.append(event('gap',3140,interval=dict(start_ticks=3100,end_ticks=3140)))
        events.append(dict(self.events[-1],emitted_ticks=3150));sequence(events)
        coordinator=LiveSession(self.factory);results=consume_all(coordinator,events)
        self.assertEqual(len(results),3);self.assertEqual(results[-1]['relations'][0]['health_candidate']['raw_sum'],100./3)
        self.assertNotEqual(results[-1]['relations'][0]['health_candidate']['raw_sum'],50.)
        self.assertEqual(coordinator.close()['preparations_observed'][0]['outcome'],'discarded')

if __name__=='__main__':unittest.main()
