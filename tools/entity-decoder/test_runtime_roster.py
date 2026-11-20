import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import runtime_roster as runtime
from aggregate_partitions import canonical


def fixture(count=3):
    keys=['controller:'+str(i).zfill(64) for i in range(count)]
    parts=[];primary=[]
    for i in range(max(1,count-1)):
        selected=[keys[0]]+([keys[i+1]] if count>1 else [])
        actors=[dict(controller_object_key=k,observation_role='primary' if k!=keys[0] or i==0 else 'support') for k in selected]
        parts.append(dict(ordinal=i+1,controllers=actors))
    primary=[dict(controller_object_key=k,partition=1 if n==0 else n) for n,k in enumerate(keys)]
    plan=dict(schema='overwatch-decoder.live-roster-plan/1',target={'pid':1},partitions=parts,controller_count=count,primary_controller_map=primary,anchor_controller_key=keys[0])
    roles=dict(schema='overwatch-decoder.private.current-controller-roster/1',target=plan['target'],public_state_eligible=False,self_controller_object_key=keys[0],rows=[dict(controller_object_key=k)for k in keys])
    return plan,roles


class RuntimeTests(unittest.TestCase):
    def test_context_source_admission_rejects_unconfigured_flags(self):
        for frame in ({}, {'raw_context_output_enabled':False}):
            self.assertIsNone(runtime.context_source_admission(None,None,None,None,frame))
        for frame in ({'raw_context_output_enabled':1},
                      {'context_group_projection':{}},
                      {'context_group_output_enabled':True}):
            with self.subTest(frame=frame),self.assertRaisesRegex(ValueError,'context'):
                runtime.context_source_admission(None,None,None,None,frame)

    def test_context_source_admission_uses_consumed_epoch_artifacts(self):
        from test_live_relations import context_setup,SESSION,raw,live
        from live_relations import LiveRelations
        for groups in (False,True):
            with self.subTest(groups=groups),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,admission,options=context_setup(root,groups=groups)
                adapter=LiveRelations(root,SESSION,1,**options)
                adapter.consume(raw(se));adapter.consume(raw(sg));frame=adapter.consume(raw(live(f,2)))
                names={'raw_category_contract':'category-contract','context_controller_contract':'controller-contract',
                       'context_projection_admission':'admission','context_projection_artifacts':'artifacts',
                       'context_group_contract':'group-contract'}
                for key,name in names.items():
                    if key in options:(root/f'context.{name}.json').write_bytes(options[key].read_bytes())
                runtime.save(root/'context.options.json',dict(schema='overwatch-decoder.context-projection-options/1',include_groups=groups))
                with self.assertRaisesRegex(ValueError,'context_digest'):
                    runtime.context_source_admission(root,root,se,sg,frame)
                # This unit fixture supplies the same transport hashes that
                # LiveSession adds from its consumed native metadata lines.
                frame['session_epoch']=dict(session_start_sha256=hashlib.sha256(raw(se)).hexdigest(),
                    segment_start_sha256=hashlib.sha256(raw(sg)).hexdigest())
                configured=runtime.context_source_admission(root,root,se,sg,frame)
                self.assertEqual(configured['contract_sha256'],adapter.context_contracts)
                self.assertEqual(configured['session_start_sha256'],admission['session_start_sha256'])
                self.assertEqual(configured['frame_scope'],adapter.context_groups.interval if groups else None)
                for bad_session,bad_segment in ((dict(se,extra='not_consumed'),sg),(se,dict(sg,segment=2))):
                    with self.assertRaisesRegex(ValueError,'context_native_metadata_mismatch'):
                        runtime.context_source_admission(root,root,bad_session,bad_segment,frame)
                altered=copy.deepcopy(frame);altered['context_group_projection']['admission']['configured_admission_sha256']='00'*32
                with self.assertRaises(ValueError):runtime.context_source_admission(root,root,se,sg,altered)

    def test_completion_requires_exact_consumed_bytes_and_successful_native_end(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);child=dict(source_id='p1',directory=directory)
            source=dict(segment=2,profile_sha256='a1'*32)
            good=dict(complete=True,error=None,native_exit=0,frames=3,entities_sha256='b2'*32,
                decoder=dict(native_session_end_seen=True,phase='ended',frames=3),
                epochs=[dict(segment=2,profile_sha256='a1'*32)])
            for mode in ('good','failed','missing_end','short','wrong_bytes','stale_epoch'):
                value=copy.deepcopy(good)
                if mode=='failed':value['native_exit']=1
                if mode=='missing_end':value['decoder']['native_session_end_seen']=False
                if mode=='short':value['frames']=4
                if mode=='wrong_bytes':value['entities_sha256']='c3'*32
                if mode=='stale_epoch':value['epochs'][0]['segment']=1
                runtime.save(root/'result.json',value)
                with self.subTest(mode=mode):
                    if mode=='good':self.assertEqual(runtime.completed_producer_results([child],{'p1':source},{'p1':3},{'p1':'b2'*32}),{'p1':runtime.digest(root/'result.json')})
                    else:
                        with self.assertRaisesRegex(ValueError,'producer_completion'):runtime.completed_producer_results([child],{'p1':source},{'p1':3},{'p1':'b2'*32})

    def test_terminal_event_uses_same_detailed_and_compact_writer(self):
        from test_live_roster_epochs import fixture,raw
        from live_roster_epochs import LiveRosterEpochs
        from compact_live_roster import CompactLiveRoster
        with tempfile.TemporaryDirectory() as directory:
            config,frames=fixture(Path(directory));co=LiveRosterEpochs(raw(config))
            for sid,items in frames.items():co.consume(sid,raw(items[0]))
            stop=max(x['read_end_ticks']for x in co.last_accepted.values())
            event=co.end_input(stop,{sid:'a1'*32 for sid in frames})[0]
            output=io.BytesIO();transitions=io.BytesIO();compact=io.BytesIO();order=io.StringIO()
            self.assertTrue(runtime.write_roster_event(event,output,transitions,compact,order,CompactLiveRoster(),7,runtime.ParentPerformance()))
            self.assertEqual(output.getvalue(),b'');self.assertEqual(transitions.getvalue(),canonical(event)+b'\n')
            entry=json.loads(order.getvalue());self.assertEqual(entry['output_index'],7)
            self.assertEqual(entry['compact_sha256'],hashlib.sha256(compact.getvalue()).hexdigest())
            projected=json.loads(compact.getvalue());self.assertEqual(projected['input_end']['stop_ticks'],stop)
            self.assertTrue(all(x['body_object_key']is None for x in projected['players']))

    def test_runtime_eof_appends_unknown_without_flushing_pending_windows(self):
        from test_live_roster_epochs import fixture as roster_fixture,raw,next_frame
        class Clock:
            frequency=1000
            def tick(self):return 10000
            def utc_ns(self):return 10000000000
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config,frames=roster_fixture(root);out=root/'out';out.mkdir()
            for rows in frames.values():rows.append(next_frame(rows[-1],rows[-1]['timing']['end_ticks']+100))
            for rows in frames.values():
                for frame in rows:
                    for row in frame['relations']:
                        row['position_candidate']['validation_status']='guarded_research'
                        row['health_candidate'].update(status='candidate',display_ceiling_candidate=int(row['health_candidate']['raw_sum']))
                        row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research',public_state_eligible=False)
                        row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research',catalog_sha256='ab'*32)
                        row['cached_label_evidence']['validation_status']='guarded_native_cache_string_research'
            sources={x['source_id']:x for x in config['sources']};children=[]
            for ordinal,(sid,rows) in enumerate(frames.items(),1):
                path=root/sid;path.mkdir();data=b''.join(raw(x)for x in rows)
                (path/'entities.jsonl').write_bytes(data);(path/'native.jsonl').write_bytes(b'')
                runtime.save(path/'result.json',dict(complete=True,native_exit=0,error=None,frames=len(rows),
                    entities_sha256=hashlib.sha256(data).hexdigest(),decoder=dict(native_session_end_seen=True,phase='ended',frames=len(rows)),
                    epochs=[dict(segment=1,profile_sha256=sources[sid]['profile_sha256'])]))
                children.append(dict(source_id=sid,ordinal=ordinal,directory=str(path)))
            primary={x['controller_object_key']:int(x['primary_source_id'][1:])for x in config['roster']}
            rolemap={key:{}for key in primary};plan=dict(target=config['target'],partitions=[{},{}])
            def admission(child,*args,**kwargs):return sources[child['source_id']],frames[child['source_id']][0],{}
            def route(adapter,child,data,current,*args,**kwargs):return json.loads(data),current,{},adapter.consume(child['source_id'],data),'consume'
            with patch.object(runtime,'reviewed_inputs',return_value=(rolemap,primary)),patch.object(runtime,'source_admission',side_effect=admission),patch.object(runtime,'route_projection',side_effect=route):
                result=runtime.aggregate_existing(root,plan,{},children,out,Clock(),live=False,raw_candidates=True,total_timeout=10)
            self.assertEqual(result['input_events'],sum(map(len,frames.values())))
            self.assertEqual(result['windows'],1);self.assertEqual(result['transition_records'],1)
            self.assertEqual(result['pending_windows'],0);self.assertGreater(result['input_end']['discarded_pending_windows'],0)
            self.assertTrue(result['transition_open'])
            events=[json.loads(x)for x in (out/'compact-roster.jsonl').read_bytes().splitlines()]
            self.assertEqual(len(events),2);self.assertTrue(all(x['health_candidate']['value']is None for x in events[-1]['players']))

    def test_explicit_supported_counts_and_no_ordinal_truncation(self):
        for count in (1,3,10,17):
            plan,roles=fixture(count);mapping,primary=runtime.reviewed_inputs(plan,roles)
            self.assertEqual(len(mapping),count);self.assertEqual(len(primary),count)
        for mutation in ('duplicate','missing','too_many','wrong_role'):
            plan,roles=fixture()
            if mutation=='duplicate':roles['rows'].append(roles['rows'][0])
            elif mutation=='missing':plan['partitions'][0]['controllers'].pop()
            elif mutation=='too_many':plan,roles=fixture(18)
            else:plan['partitions'][1]['controllers'][0]['observation_role']='primary'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):runtime.reviewed_inputs(plan,roles)

    def test_exactly_once_epoch_dispatch(self):
        class Adapter:
            def __init__(self):self.calls=[]
            def admit(self,*args):self.calls.append(args);return [{'transition':True}]
            def consume(self,*args):raise AssertionError('seq0 consumed twice')
        adapter=Adapter();raw=canonical(dict(segment=2,timing={'sequence':0}))+b'\n'
        fresh={'segment':2}
        with patch.object(runtime,'source_admission',return_value=(fresh,{},{})):
            result=runtime.route_projection(adapter,{'source_id':'p1'},raw,{'segment':1},{},{},{},None)
        self.assertEqual(result[-1],'admit');self.assertEqual(len(adapter.calls),1)
        with self.assertRaisesRegex(ValueError,'new_source_epoch_order'):
            runtime.route_projection(adapter,{'source_id':'p1'},raw,{'segment':0},{},{},{},None)

    def test_inventory_pin_mutation_and_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);files={}
            for name in ('runtime_roster.py','runtime_producer.py','runtime_jobs.py'):
                relative='tools/entity-decoder/'+name;path=root/relative;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(Path(runtime.__file__).with_name(name).read_bytes());files[relative]=dict(bytes=path.stat().st_size,sha256=runtime.digest(path))
            runtime.save(root/'inventory.json',files);pin=runtime.digest(root/'inventory.json')
            self.assertEqual(runtime.verify_runtime_inventory(root,pin)['files'],3)
            with self.assertRaisesRegex(ValueError,'runtime_entrypoint_not_in_inventory'):
                runtime.verify_runtime_inventory(root,pin,required_modules=('runtime_partial.py',))
            relative='tools/entity-decoder/runtime_partial.py';path=root/relative
            path.write_bytes(Path(runtime.__file__).with_name('runtime_partial.py').read_bytes())
            files[relative]=dict(bytes=path.stat().st_size,sha256=runtime.digest(path));runtime.save(root/'inventory.json',files)
            self.assertEqual(runtime.verify_runtime_inventory(root,required_modules=('runtime_partial.py',))['files'],4)
            with self.assertRaisesRegex(ValueError,'inventory_pin'):runtime.verify_runtime_inventory(root,'0'*64)
            files['../escape']={'bytes':0,'sha256':'0'*64};runtime.save(root/'inventory.json',files)
            with self.assertRaisesRegex(ValueError,'inventory_path'):runtime.verify_runtime_inventory(root)

    def test_producer_assets_are_pinned_and_resolved_before_external_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);asset=root/'asset.json';asset.write_text('{}')
            config={k:'asset.json' for k in ('recipe','composer','health_layout','native_review','roster_review','category_artifacts','hero_catalog','hero_artifacts')}
            config.update(native_exe='external-observer.exe',reviewed_mode_sources=['asset.json'])
            runtime.save(root/'p1.json',config)
            inventory={name:dict(bytes=(root/name).stat().st_size,sha256=runtime.digest(root/name))for name in ('p1.json','asset.json')}
            runtime.save(root/'inventory.json',inventory)
            checked=runtime.bundled_producer_config(root,1)
            self.assertEqual(checked['composer'],str(asset))
            self.assertEqual(checked['reviewed_mode_sources'],[str(asset)])
            asset.write_text('{"changed":true}')
            with self.assertRaisesRegex(ValueError,'producer_asset_hash'):runtime.bundled_producer_config(root,1)
            asset.write_text('{}');config['composer']='../outside.py';runtime.save(root/'p1.json',config)
            inventory['p1.json']=dict(bytes=(root/'p1.json').stat().st_size,sha256=runtime.digest(root/'p1.json'));runtime.save(root/'inventory.json',inventory)
            with self.assertRaisesRegex(ValueError,'producer_asset_not_in_inventory'):runtime.bundled_producer_config(root,1)

    def test_raw_manifest_snapshots_dynamic_counts_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            raw=[b'{"status":"running"}\n',b'{ "status": "running" }\n']
            rows=[dict(source_id='p'+str(i+1),native_manifest_sha256=hashlib.sha256(b).hexdigest())for i,b in enumerate(raw)]
            saved,total=runtime.retain_native_manifests(directory,1,rows,raw,0)
            self.assertEqual(total,sum(map(len,raw)))
            for row,b in zip(saved,raw):self.assertEqual((Path(directory)/row['native_manifest_file']).read_bytes(),b)
            rows[1]['source_id']=rows[0]['source_id']
            with self.assertRaisesRegex(ValueError,'snapshot_sources'):runtime.retain_native_manifests(directory,2,rows,raw,total)
            rows[1]['source_id']='../escape'
            with self.assertRaises(ValueError):runtime.retain_native_manifests(directory,2,rows,raw,total)

    def test_launch_startup_failure_stops_owned_jobs_without_capture_settle(self):
        from types import SimpleNamespace
        import runtime_jobs
        class Clock:
            frequency=10000000
            def __init__(self):self.now=0.;self.sleeps=[]
            def tick(self):return int(self.now*self.frequency)
            def sleep(self,seconds):self.sleeps.append(seconds);self.now+=seconds
        class Job:
            def __init__(self):self.active=True;self.closed=False
            def terminate_and_close(self,deadline):self.active=False;self.closed=True
        class Worker:
            def __init__(self,clock,n,natural=False):
                self.pid=n;self.clock=clock;self.exit=None;self.natural=natural
                self._overwatch_decoder_owned_job=Job();self.terminated_at=None
            def poll(self):
                if self.natural and self.clock.now>=1:self.exit=0
                return self.exit
            def terminate(self):self.terminated_at=self.clock.now;self.exit=-15
            def wait(self,timeout):return self.exit
        for mode in ('producer','deadline','spawn','success','admitted_error'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);bundle=root/'bundle';scripts=bundle/'tools/entity-decoder';scripts.mkdir(parents=True)
                for name in ('runtime_roster.py','runtime_producer.py'):(scripts/name).write_bytes(b'# fixture\n')
                plan,roles=fixture(3)
                for part in plan['partitions']:
                    part['recipe_sha256']='a1'*32
                    (bundle/f"p{part['ordinal']}.json").write_bytes(b'{}\n')
                runtime.save(bundle/'plan.json',plan);runtime.save(bundle/'roles.json',roles)
                args=SimpleNamespace(bundle=bundle,output=root/'out',plan=bundle/'plan.json',role_map=bundle/'roles.json',
                    census_acquisition=None,mode='reviewed',inventory_sha256='b2'*32,
                    seconds=60,interval_ms=100,ready_timeout=1,cleanup_seconds=5)
                clock=Clock();workers=[];logs=[];partial=b'{"native":"incomplete evidence"}\n';failed_result=None
                def config(*unused):return dict(target=plan['target'],recipe_sha256='a1'*32,private_controlled_fixture_reviewed=True)
                def spawn(command,**options):
                    nonlocal failed_result
                    logs.append(options['stdout'])
                    if mode=='spawn' and workers:raise OSError('fixture launch failure')
                    cfg=json.loads(Path(command[-1]).read_bytes());path=Path(cfg['output']);path.mkdir()
                    (path/'native.jsonl').write_bytes(partial)
                    if mode=='producer' and not workers:
                        runtime.save(path/'result.json',dict(complete=False,error='acquisition_predicate_failed',frames=0))
                        failed_result=(path/'result.json').read_bytes()
                    worker=Worker(clock,len(workers)+1,mode in ('success','admitted_error'));workers.append(worker);return worker
                original_aggregate=runtime.aggregate_existing
                def aggregate(*a,**kw):
                    if mode=='success':return {'fixture_success':True}
                    if mode=='admitted_error':raise ValueError('fixture post-admission failure')
                    return original_aggregate(*a,**kw)
                with patch.object(runtime,'__file__',str(scripts/'runtime_roster.py')),patch.object(runtime.sys,'platform','win32'), \
                     patch.object(runtime,'verify_runtime_inventory',return_value={'files':2}),patch.object(runtime,'WindowsClock',return_value=clock), \
                     patch.object(runtime,'shared_bytes',side_effect=lambda path,*a,**kw:Path(path).read_bytes()), \
                     patch.object(runtime,'bundled_producer_config',side_effect=config),patch.object(runtime_jobs,'spawn_producer',side_effect=spawn), \
                     patch.object(runtime.time,'monotonic',side_effect=lambda:clock.now),patch.object(runtime.time,'sleep',side_effect=clock.sleep), \
                     patch.object(runtime,'aggregate_existing',side_effect=aggregate):
                    code=runtime.launch(args)
                status=json.loads((args.output/'status.json').read_bytes())
                self.assertEqual(code,0 if mode=='success' else 2)
                self.assertEqual(status['complete'],mode=='success')
                self.assertTrue(all(w.poll()is not None and w._overwatch_decoder_owned_job.closed and not w._overwatch_decoder_owned_job.active for w in workers))
                self.assertTrue(all(c['owned_job_closed'] for c in status['children']))
                self.assertTrue(all(log.closed for log in logs))
                for child in status['children']:
                    self.assertEqual((Path(child['directory'])/'native.jsonl').read_bytes(),partial)
                    with (args.output/f"{child['source_id']}-producer.log").open('ab') as log:log.write(b'')
                if mode in ('producer','deadline','spawn'):
                    self.assertNotIn(.1,clock.sleeps)
                    self.assertLess(clock.now,2)
                    self.assertTrue(all(w.terminated_at is not None for w in workers))
                    self.assertFalse((args.output/'aggregate-config.json').exists())
                    if mode!='spawn':
                        report=json.loads((args.output/'aggregate-result.json').read_bytes())
                        self.assertEqual(report['input_events'],0);self.assertIsNotNone(report['transport_error'])
                    if failed_result is not None:self.assertEqual((args.output/'p1/result.json').read_bytes(),failed_result)
                else:
                    self.assertIn(.1,clock.sleeps)
                    self.assertTrue(all(w.terminated_at is None for w in workers))

    def test_owned_cleanup_closes_all_handles_on_timeout(self):
        class Worker:
            def __init__(self):self.calls=[]
            def poll(self):return None
            def terminate(self):self.calls.append('terminate')
            def kill(self):self.calls.append('kill')
            def wait(self,timeout):self.calls.append(timeout);raise subprocess.TimeoutExpired('owned',timeout)
        worker=Worker();log=io.BytesIO();child={}
        errors=runtime.cleanup_owned([(worker,log,child)],time.monotonic()+.01)
        self.assertTrue(errors);self.assertTrue(log.closed)
        self.assertEqual(worker.calls[0],'terminate');self.assertIn('kill',worker.calls)
        self.assertTrue(all(0<x<=2 for x in worker.calls if isinstance(x,float)))

    def test_native_metadata_uses_raw_event_hash_not_pretty_json(self):
        events=[{'kind':k,'session_id':'s'}for k in ('session_start','acquisition_end','segment_start')]
        raws=[canonical(e)+b'\n'for e in events];pins=dict(zip(('session_start_sha256','acquisition_end_sha256','segment_start_sha256'),map(lambda b:hashlib.sha256(b).hexdigest(),raws)))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'native.jsonl';path.write_bytes(b''.join(raws));metadata=runtime.NativeMetadata()
            try:self.assertEqual(metadata.actual(dict(source_id='p1',directory=directory),dict(session_epoch=pins)),events)
            finally:metadata.close()
            self.assertNotEqual(pins['session_start_sha256'],hashlib.sha256(json.dumps(events[0],indent=2).encode()).hexdigest())
            path.write_bytes(raws[0]+b'{"kind":');metadata=runtime.NativeMetadata()
            try:
                with self.assertRaisesRegex(ValueError,'not_yet_complete'):metadata.actual(dict(source_id='p1',directory=directory),dict(session_epoch=pins))
            finally:metadata.close()

    def test_readiness_deadline_and_failed_producer_persist_failure(self):
        import itertools
        class Clock:
            frequency=10000000
        for failure in ('deadline','producer'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);plan,roles=fixture(3);children=[]
                for n in (1,2):
                    child=root/f'p{n}';child.mkdir()
                    children.append(dict(source_id=f'p{n}',ordinal=n,directory=str(child)))
                    if failure=='producer':runtime.save(child/'result.json',dict(complete=False,error='fixture failure'))
                out=root/'output';out.mkdir()
                clock=itertools.chain([0],itertools.repeat(2)) if failure=='deadline' else itertools.repeat(0)
                with patch.object(runtime.time,'monotonic',side_effect=lambda:next(clock)):
                    with self.assertRaisesRegex(runtime.PreAdmissionFailure,'aggregate_failed'):
                        runtime.aggregate_existing(root,plan,roles,children,out,Clock(),live=False,ready_timeout=1,total_timeout=10)
                result=json.loads((out/'aggregate-result.json').read_bytes())
                self.assertIn('readiness_deadline' if failure=='deadline' else 'producer_failed_before_admission',result['transport_error'])
                self.assertEqual(result['input_events'],0)
                self.assertFalse((out/'combined-entities.jsonl').exists())

    def test_fresh_body_required_without_freezing_old_hero(self):
        ck='controller:'+'a'*64;old='body:'+'b'*64;new='body:'+'c'*64
        review={ck:dict(cached_label_candidate='reviewed',visual_roster_role='self',controller_resource_guid='resource-old')}
        row=dict(relation_status='observed',controller_object_key=ck,body_object_key=new,cached_label_candidate='reviewed',relative_allegiance_candidate='self',hero_resource_guid_candidate={'value':'resource-new'})
        runtime.validate_rows({'relations':[row]},{ck},review,pairs={ck:new})
        with self.assertRaisesRegex(ValueError,'fresh_epoch_body_mismatch'):
            runtime.validate_rows({'relations':[row]},{ck},review,pairs={ck:old})
        with self.assertRaisesRegex(ValueError,'initial_hero_review_mismatch'):
            runtime.validate_rows({'relations':[row]},{ck},review,initial=True,pairs={ck:new})
        row['cached_label_candidate']='unreviewed'
        with self.assertRaisesRegex(ValueError,'current_actor_review_mismatch'):
            runtime.validate_rows({'relations':[row]},{ck},review,pairs={ck:new})

    def test_proof_retry_bounded_per_revision(self):
        schedule=runtime.ProofSchedule();self.assertFalse(schedule.due(1,19,False,0));self.assertTrue(schedule.due(1,20,False,0))
        self.assertFalse(schedule.due(1,21,False,.5));self.assertTrue(schedule.due(1,22,False,1))
        self.assertFalse(schedule.due(1,23,True,2))

    def test_raw_roster_exact_verified_census_and_optional_anchor(self):
        from test_plan_live_roster import fixture as census_fixture
        from plan_live_roster import verified_census, plan as make_plan, digest
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);template=census_fixture(root);census=verified_census(root)
            for anchor in (None,census['controllers'][0]['controller_object_key']):
                plan=make_plan(census,template,template_sha256=digest(template),partition_size=3,anchor_controller_key=anchor)
                roles=runtime.raw_roster_inputs(plan,census)
                self.assertIsNone(roles['self_controller_object_key'])
                self.assertEqual(set(roles['rows'][0]),{'controller_object_key','full_handle','creation_key'})
                mapping,primary=runtime.reviewed_inputs(plan,roles,raw_candidates=True)
                self.assertEqual(len(mapping),5)
                for mutation in ('target','source','word','key','missing','duplicate','primary'):
                    bad=copy.deepcopy(plan)
                    if mutation=='target':bad['target']['pid']+=1
                    elif mutation=='source':bad['census_source']['evidence_sha256']='0'*64
                    elif mutation=='word':bad['partitions'][0]['controllers'][0]['creation_key_u32']+=1
                    elif mutation=='key':bad['partitions'][0]['controllers'][0]['controller_object_key']='controller:'+'f'*64
                    elif mutation=='missing':bad['partitions'][0]['controllers'].pop()
                    elif mutation=='duplicate':bad['partitions'][0]['controllers'].append(bad['partitions'][0]['controllers'][0])
                    else:bad['primary_controller_map'][0]['partition']=99
                    with self.subTest(anchor=anchor,mutation=mutation),self.assertRaises(ValueError):
                        runtime.raw_roster_inputs(bad,census)

    def test_raw_admission_rejects_unobserved_or_stale_pairs_not_unknown_enrichment(self):
        ck='controller:'+'a'*64;body='body:'+'b'*64
        roles={ck:dict(full_handle=12,creation_key=34)}
        row=dict(relation_status='observed',controller_object_key=ck,body_object_key=body,
                 evidence=[{'value':12},{'value':34},{'value':56}],name=None,team=None,
                 hero_label=None,cached_label_candidate=None,position_candidate={'value':[1,2,3]},health_candidate=None)
        runtime.validate_rows({'relations':[row]},{ck},roles,initial=True,pairs={ck:body},raw_candidates=True)
        for mutation in ('unobserved','body','identity','category','name','duplicate'):
            bad=copy.deepcopy(row);rows=[bad]
            if mutation=='unobserved':bad['relation_status']='unknown'
            elif mutation=='body':bad['body_object_key']='body:'+'c'*64
            elif mutation=='identity':bad['evidence'][1]['value']+=1
            elif mutation=='category':bad['relative_allegiance_candidate']='friendly'
            elif mutation=='name':bad['name']='unreviewed'
            else:rows.append(copy.deepcopy(row))
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                runtime.validate_rows({'relations':rows},{ck},roles,initial=True,pairs={ck:body},raw_candidates=True)

    def test_raw_unknown_relation_cannot_smuggle_category_or_name(self):
        for field,value in [('name','stale'),('team_candidate','stale'),('relative_allegiance_candidate','self')]:
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'raw_unreviewed'):
                runtime.validate_rows({'relations':[dict(relation_status='unknown',**{field:value})]}, {'controller'}, {}, raw_candidates=True)
        with self.assertRaisesRegex(ValueError,'raw_category_output_forbidden'):
            runtime.validate_rows({'relations':[],'category_output_enabled':True},set(),{},raw_candidates=True)

    def test_raw_source_admission_two_actual_fixture_epochs_without_category_files(self):
        from test_live_sessions import fixture as sessions_fixture, consume_all
        from test_live_relations import raw
        from live_sessions import LiveSession
        from live_roster_epochs import LiveRosterEpochs
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);epochs,events,factory,_=sessions_fixture(root)
            # This multi-source coordinator requires a consistent wall/QPC offset;
            # the generic single-session fixture leaves UTC unchanged across epochs.
            from datetime import datetime,timedelta
            for e in events:
                if e['kind']=='frame' and e['segment']==2:
                    shifted=(datetime.fromisoformat(e['utc_origin'].replace('Z','+00:00'))+timedelta(seconds=1)).isoformat()
                    e['utc_origin']=e['recording_frame']['utc_origin']=shifted
            frames=consume_all(LiveSession(factory),events)
            native=root/'native';native.mkdir()
            for n in (1,2):(native/f'acquisition-{n:04d}').symlink_to(root/str(n),target_is_directory=True)
            (root/'native.jsonl').write_bytes(b''.join(raw(e)for e in events))
            first=frames[0];row=first['relations'][0];ck=row['controller_object_key']
            roles={ck:dict(full_handle=row['evidence'][0]['value'],creation_key=row['evidence'][1]['value'])}
            plan=dict(target=first['target'],partitions=[dict(ordinal=1,controllers=[dict(controller_object_key=ck)],recipe_sha256=epochs[1][2]['recipe_sha256'])])
            child=dict(source_id='p1',ordinal=1,directory=str(root));metadata=runtime.NativeMetadata()
            try:
                source,_,pin=runtime.source_admission(child,plan,roles,{ck:1},metadata,raw(first),initial=True,raw_candidates=True)
                self.assertNotIn('live_category',source);self.assertNotIn('category_contract_sha256',pin)
                config=dict(schema='overwatch-decoder.live-partition-config/1',epoch_id='raw-fixture',clock_domain_id='fixture',target=first['target'],
                    monotonic_frequency=1000,window_origin_ticks=1000,window_ticks=100,maximum_skew_ticks=150,
                    maximum_origin_offset_ticks=10,sources=[source],roster=[dict(source['objects'][0],primary_source_id='p1')])
                coordinator=LiveRosterEpochs(canonical(config))
                runtime.route_projection(coordinator,child,raw(first),source,plan,roles,{ck:1},metadata,raw_candidates=True)
                _,replacement,_,outputs,op=runtime.route_projection(coordinator,child,raw(frames[1]),source,plan,roles,{ck:1},metadata,raw_candidates=True)
                self.assertEqual(op,'admit');self.assertNotEqual(source['objects'],replacement['objects'])
                self.assertTrue(any(x['schema']=='overwatch-decoder.live-roster-transition/1' and x['status']=='unknown' for x in outputs))
                self.assertEqual([f['relations'][0]['health_candidate']['raw_sum']for f in frames],[100.,50.])
                self.assertEqual(coordinator.status()['source_admissions'],1)
                for mutation in ('target','recipe','profile','body','category','unobserved'):
                    bad=copy.deepcopy(first)
                    if mutation=='target':bad['target']['pid']+=1
                    elif mutation=='recipe':bad['source_artifacts']['acquisition']['recipe_sha256']='0'*64
                    elif mutation=='profile':bad['profile_sha256']='0'*64
                    elif mutation=='body':bad['relations'][0]['body_object_key']='body:'+'f'*64
                    elif mutation=='category':bad['category_output_enabled']=True
                    else:bad['relations'][0]['relation_status']='unknown'
                    with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                        runtime.source_admission(child,plan,roles,{ck:1},metadata,raw(bad),initial=True,raw_candidates=True)
            finally:metadata.close()

    def test_subset_source_admission_original_keys_and_real_context_artifacts(self):
        from test_live_relations import context_setup,SESSION,raw,live,event
        from live_relations import LiveRelations
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);profile,native_frame,manifest,se,sg,_,options=context_setup(root,groups=False)
            sg['acquisition']=1
            segment_bytes=raw(sg);segment_pin=hashlib.sha256(segment_bytes).hexdigest()
            (root/(segment_pin+'.json')).write_bytes(segment_bytes)
            artifact_map=json.loads(options['context_projection_artifacts'].read_bytes());artifact_map[segment_pin]=segment_pin+'.json'
            options['context_projection_artifacts'].write_bytes(raw(artifact_map))
            admission=json.loads(options['context_projection_admission'].read_bytes());admission['segment_start_sha256']=segment_pin
            options['context_projection_admission'].write_bytes(raw(admission))
            adapter=LiveRelations(root,SESSION,1,**options)
            adapter.consume(raw(se));adapter.consume(raw(sg));frame=adapter.consume(raw(live(native_frame,2)))
            context=frame['context_group_projection']['context_projection']['controller_object_key']
            epoch=root/'epoch-0001';epoch.mkdir()
            names={'raw_category_contract':'category-contract','context_controller_contract':'controller-contract',
                   'context_projection_admission':'admission','context_projection_artifacts':'artifacts'}
            for key,name in names.items():
                data=options[key].read_bytes()
                if key=='context_projection_artifacts':
                    paths=json.loads(data);data=raw({h:str(root/path)for h,path in paths.items()})
                (epoch/f'context.{name}.json').write_bytes(data)
            runtime.save(epoch/'context.options.json',dict(schema='overwatch-decoder.context-projection-options/1',include_groups=False))
            native=root/'native';native.mkdir();(native/'acquisition-0001').symlink_to(root,target_is_directory=True)
            acq=event('acquisition_end',1,acquisition=dict(ordinal=1,directory='acquisition-0001',complete=True,error=None,
                manifest_sha256=hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest(),profile_sha256=manifest['profile_sha256']))
            # Synthetic metadata envelope fixture; original context artifacts and
            # full profile/evidence/recipe bytes are still constructor-verified.
            frame['session_epoch']=dict(acquisition=1,session_start_sha256=hashlib.sha256(raw(se)).hexdigest(),
                acquisition_end_sha256=hashlib.sha256(raw(acq)).hexdigest(),segment_start_sha256=hashlib.sha256(raw(sg)).hexdigest(),
                previous_epoch_last_frame_end_ticks=None,previous_values_carried=False)
            (root/'native.jsonl').write_bytes(raw(se)+raw(acq)+raw(sg))
            rows=frame['relations'];keys=[r['controller_object_key']for r in rows];missing='controller:'+'ef'*32
            roles={r['controller_object_key']:dict(full_handle=r['evidence'][0]['value'],creation_key=r['evidence'][1]['value'])for r in rows}
            roles[missing]=dict(full_handle=999,creation_key=888);primary={ck:1 for ck in [*keys,missing]}
            plan=dict(target=frame['target'],context_controller_object_key=context,partitions=[dict(ordinal=1,
                controllers=[dict(controller_object_key=ck)for ck in [missing,*keys]],recipe_sha256=manifest['recipe_sha256'])])
            child=dict(source_id='p1',ordinal=1,directory=str(root));metadata=runtime.NativeMetadata();self.addCleanup(metadata.close)
            for order in ([missing,*keys],[*keys,missing]):
                plan['partitions'][0]['controllers']=[dict(controller_object_key=ck)for ck in order]
                source,_,pins=runtime.source_admission(child,plan,roles,primary,metadata,raw(frame),initial=True,raw_candidates=True,allow_controller_subsets=True)
                self.assertEqual(source['controller_subset'],pins['controller_subset'])
                self.assertEqual(pins['controller_subset']['omitted_controllers'],[dict(controller_object_key=missing,reason='not_in_acquired_subset')])
                self.assertEqual(pins['controller_subset']['observed_controller_keys'],sorted(keys))
                self.assertEqual(pins['controller_subset']['required_context_controller_key'],context)
            for mutation in ('strict','foreign','missing_context','wrong_context','profile','epoch','duplicate_plan','empty_context','unconfigured_context'):
                bad=copy.deepcopy(frame);bp=copy.deepcopy(plan)
                if mutation=='foreign':bp['partitions'][0]['controllers']=bp['partitions'][0]['controllers'][1:]
                elif mutation=='missing_context':bp.pop('context_controller_object_key')
                elif mutation=='wrong_context':bp['context_controller_object_key']=missing
                elif mutation=='profile':bad['profile_sha256']='ff'*32
                elif mutation=='epoch':bad['segment']=2
                elif mutation=='duplicate_plan':bp['partitions'][0]['controllers'].append(bp['partitions'][0]['controllers'][0])
                elif mutation=='empty_context':bad['context_group_projection']['context_projection']={}
                elif mutation=='unconfigured_context':bad['raw_context_output_enabled']=False;bad['context_group_projection']=None
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                    runtime.source_admission(child,bp,roles,primary,metadata,raw(bad),initial=True,raw_candidates=True,
                        allow_controller_subsets=mutation!='strict')

    def test_controller_subset_mode_requires_partial_raw_and_pinned_module(self):
        from types import SimpleNamespace
        bundle=Path(runtime.__file__).resolve().parents[2]
        for mode,partial in (('reviewed',False),('reviewed',True),('raw-candidates',False)):
            args=SimpleNamespace(bundle=bundle,output=bundle.parent/'nonexistent-subset-test',mode=mode,
                partial_sources=partial,allow_controller_subsets=True)
            with self.subTest(mode=mode,partial=partial),patch.object(runtime.sys,'platform','win32'),self.assertRaisesRegex(ValueError,'controller_subsets_require_partial_raw_mode'):
                runtime.launch(args)
        args=SimpleNamespace(bundle=bundle,output=bundle.parent/'nonexistent-subset-test',mode='raw-candidates',
            partial_sources=True,allow_controller_subsets=True,inventory_sha256='ab'*32)
        with patch.object(runtime.sys,'platform','win32'),patch.object(runtime,'verify_runtime_inventory',side_effect=ValueError('stop_after_inventory'))as verify:
            with self.assertRaisesRegex(ValueError,'stop_after_inventory'):runtime.launch(args)
            self.assertEqual(verify.call_args.kwargs['required_modules'],('runtime_partial.py','controller_subset_projection.py'))

    def test_raw_absence_proof_requires_actual_active_epoch_and_never_inherits_prior(self):
        import types
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'native').mkdir();out=root/'out';out.mkdir()
            child=dict(source_id='p1',directory=str(root));clock=types.SimpleNamespace(tick=lambda:123)
            source=dict(segment=1,session_id='s',profile_sha256='ab'*32,acquisition={'evidence_sha256':'cd'*32},
                session_epoch={'acquisition':1},unresolved_bodies=[{'controller_object_key':'c'}])
            frame=dict(relations=[dict(controller_object_key='c',body_object_key=None,relation_status='unknown',reason='unsupported_word_binding')],timing={'sequence':0})
            target={'pid':7};manifest=dict(target=target,session_id='s',status='finished',active_operation=None,active_directory=None)
            path=root/'native/manifest.json';path.write_text(json.dumps(manifest))
            proof=runtime.RawAbsenceProofs()
            with patch.object(runtime.time,'monotonic',return_value=1):proof.observe(child,source,frame,b'exact-line\n',out,clock,target,live=True)
            self.assertFalse(proof.summary()['all_required_proved'])
            manifest.update(status='running',active_operation='recording',active_directory='segment-0001');data=json.dumps(manifest,indent=2).encode();path.write_bytes(data)
            with patch.object(runtime.time,'monotonic',return_value=2):proof.observe(child,source,frame,b'exact-line\n',out,clock,target,live=True)
            saved=proof.summary()['proofs'][0]
            self.assertEqual((out/saved['native_manifest_file']).read_bytes(),data)
            self.assertEqual(saved['native_manifest']['native_manifest_sha256'],hashlib.sha256(data).hexdigest())
            self.assertTrue(proof.summary()['all_required_proved'])
            for _ in range(18):proof.observe(child,source,frame,b'exact-line\n',out,clock,target,live=False)
            self.assertTrue(proof.ready({'p1':source}))
            replacement=dict(source,segment=2,profile_sha256='ef'*32)
            with patch.object(runtime.time,'monotonic',return_value=3):proof.observe(child,replacement,frame,b'new-line\n',out,clock,target,live=True)
            self.assertFalse(proof.summary()['all_required_proved'])
            self.assertFalse(proof.ready({'p1':replacement}))
            manifest['target']={'pid':99};path.write_text(json.dumps(manifest))
            with patch.object(runtime.time,'monotonic',return_value=4),self.assertRaisesRegex(ValueError,'native_target_or_session_changed'):
                proof.observe(child,replacement,frame,b'new-line\n',out,clock,target,live=True)

    def test_raw_full_absent_fresh_body_native_session_admission(self):
        from test_live_sessions import fixture as sessions_fixture, consume_all
        from test_live_continuity import epoch as full_epoch
        from test_live_relations import raw
        from live_sessions import LiveSession
        from live_roster_epochs import LiveRosterEpochs
        from datetime import datetime,timedelta
        def epoch(root,n,**kwargs):
            p,f,m,contracts=full_epoch(root,n,**kwargs)
            if n==2:
                p['fields']=[v for v in p['fields'] if not v['name'].startswith('controller_0000_body_')]
                f['fields']={k:v for k,v in f['fields'].items() if not k.startswith('controller_0000_body_')}
                pr=raw(p);m['profile_sha256']=f['profile_sha256']=hashlib.sha256(pr).hexdigest()
                (root/'profile.json').write_bytes(pr);(root/'manifest.json').write_bytes(raw(m))
                contracts=[]  # No descriptor from either previous or future body.
            return p,f,m,contracts
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with patch('test_live_sessions.epoch',side_effect=epoch):epochs,events,factory,_=sessions_fixture(root,count=3)
            for e in events:
                if e['kind']=='frame':
                    shifted=(datetime.fromisoformat(e['utc_origin'].replace('Z','+00:00'))+timedelta(seconds=e['segment']-1)).isoformat()
                    e['utc_origin']=e['recording_frame']['utc_origin']=shifted
            frames=consume_all(LiveSession(factory),events)
            native=root/'native';native.mkdir()
            for n in (1,2,3):(native/f'acquisition-{n:04d}').symlink_to(root/str(n),target_is_directory=True)
            (root/'native.jsonl').write_bytes(b''.join(raw(e)for e in events))
            first=frames[0];row=first['relations'][0];ck=row['controller_object_key']
            roles={ck:dict(full_handle=row['evidence'][0]['value'],creation_key=row['evidence'][1]['value'])}
            plan=dict(target=first['target'],partitions=[dict(ordinal=1,controllers=[dict(controller_object_key=ck)],recipe_sha256=epochs[1][2]['recipe_sha256'])])
            child=dict(source_id='p1',ordinal=1,directory=str(root));metadata=runtime.NativeMetadata()
            try:
                source,_,_=runtime.source_admission(child,plan,roles,{ck:1},metadata,raw(first),initial=True,raw_candidates=True)
                config=dict(schema='overwatch-decoder.live-partition-config/1',observation_mode='raw-candidates',allow_unresolved_bodies=True,
                    epoch_id='raw-fixture',clock_domain_id='fixture',target=first['target'],monotonic_frequency=1000,
                    window_origin_ticks=1000,window_ticks=100,maximum_skew_ticks=150,maximum_origin_offset_ticks=10,
                    sources=[source],roster=[dict(source['objects'][0],primary_source_id='p1')])
                co=LiveRosterEpochs(canonical(config));runtime.route_projection(co,child,raw(first),source,plan,roles,{ck:1},metadata,raw_candidates=True)
                _,absent,pin,opened,_=runtime.route_projection(co,child,raw(frames[1]),source,plan,roles,{ck:1},metadata,raw_candidates=True)
                self.assertIsNone(absent['objects'][0]['body_object_key'])
                self.assertEqual(pin['unresolved_bodies'][0]['profile_sha256'],frames[1]['profile_sha256'])
                self.assertEqual(frames[1]['relations'][0]['controller_object_key'],ck)
                self.assertIsNone(frames[1]['relations'][0]['health_candidate'])
                self.assertFalse(co.status()['transition_open']);self.assertEqual(co.status()['pending_bytes'],0)
                self.assertEqual([e['status']for e in opened],['unknown','resumed_without_carried_values'])
                _,fresh,_,closed,_=runtime.route_projection(co,child,raw(frames[2]),absent,plan,roles,{ck:1},metadata,raw_candidates=True)
                self.assertNotEqual(fresh['objects'][0]['body_object_key'],source['objects'][0]['body_object_key'])
                self.assertEqual(closed[-1]['status'],'resumed_without_carried_values')
                self.assertAlmostEqual(frames[2]['relations'][0]['health_candidate']['raw_sum'],100/3)
                self.assertEqual(co.status()['source_admissions'],2)
                bad=copy.deepcopy(frames[1]);bad['relations'][0]['evidence'][0]['value']+=1
                with self.assertRaisesRegex(ValueError,'unresolved_controller_words'):
                    runtime.source_admission(child,plan,roles,{ck:1},metadata,raw(bad),raw_candidates=True)
            finally:metadata.close()

    @unittest.skipUnless(os.environ.get('OVERWATCH_DECODER_RUNTIME_SAVED_RUN'),'optional private saved native/semantic artifacts')
    def test_saved_runtime_exact_admission_and_input_order(self):
        from live_roster_epochs import LiveRosterEpochs
        root=Path(os.environ['OVERWATCH_DECODER_RUNTIME_SAVED_RUN']);plan=runtime.shared_json(root/'plan.json');roles=runtime.shared_json(root/'current-role-map.json')
        rolemap,primary=runtime.reviewed_inputs(plan,roles);adapter=LiveRosterEpochs((root/'aggregate-config.json').read_bytes())
        current={s['source_id']:s for s in adapter.config['sources']};metadata=runtime.NativeMetadata();streams={sid:(root/sid/'entities.jsonl').open('rb')for sid in current}
        outputs={name:(root/name).open('rb')for name in ('combined-entities.jsonl','transitions.jsonl')};count=0
        order=(root/'aggregate-input-order.jsonl').open()
        try:
            for item in map(json.loads,order):
                sid=item['source_id'];raw=streams[sid].readline();self.assertEqual(hashlib.sha256(raw).hexdigest(),item['projection_sha256'])
                child=dict(source_id=sid,directory=str(root/sid),ordinal=int(sid[1:]))
                if count==0 or json.loads(raw)['timing']['sequence']==0:
                    initial=json.loads(raw)['segment']==1
                    source,frame,pin=runtime.source_admission(child,plan,rolemap,primary,metadata,raw,initial=initial)
                    if initial:self.assertEqual(source,current[sid])
                frame,fresh,pin,events,operation=runtime.route_projection(adapter,child,raw,current[sid],plan,rolemap,primary,metadata)
                self.assertEqual(operation,item['operation']);current[sid]=fresh;count+=1
                for event in events:
                    name='transitions.jsonl'if event['schema']=='overwatch-decoder.live-roster-transition/1'else'combined-entities.jsonl'
                    self.assertEqual(canonical(event)+b'\n',outputs[name].readline())
            self.assertTrue(all(not file.read(1)for file in [*streams.values(),*outputs.values()]))
            saved=runtime.shared_json(root/'aggregate-result.json');self.assertEqual(count,saved['input_events'])
            actual=adapter.close()
            for key,value in actual.items():
                if key!='schema':self.assertEqual(json.loads(json.dumps(value)),saved[key],key)
        finally:
            metadata.close();order.close()
            for file in [*streams.values(),*outputs.values()]:file.close()

if __name__=='__main__':unittest.main()
