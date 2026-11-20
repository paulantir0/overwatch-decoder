"""Empty acquisition proof admission, never a claim of current world absence."""
import copy,json,unittest
from relations import GuardedRelations
from selected_entity_view import SelectedEntityView,InvalidSelectedEntity,sha
from test_relations import prepare
from test_selected_entity_view import relative_fixture,serial_guards

def raw(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def fixture():
    original,c,old,kwargs=relative_fixture(labels=False,split_identities=True)
    profile=json.loads(original);profile['fields']=[d for d in profile['fields'] if d['name'].startswith('local_')]
    values={d['name']:old['fields'][d['name']]['value'] for d in profile['fields']}
    profile['schema']='overwatch-decoder.field-profile/1';_,frame=prepare(profile,values)
    profile['schema']='overwatch-decoder.field-profile/4';pr=raw(profile);frame['profile_sha256']=sha(pr);frame['schema']='overwatch-decoder.field-stream/4'
    serial_guards(profile,frame);r=GuardedRelations(pr,allow_profile4=True)
    recipe=raw(dict(schema='overwatch-decoder.acquisition-recipe/1',target={k:profile['target'][k] for k in
        ('image_name','architecture','executable_sha256')},stages=[dict(name='fixture')],
        field_collections=[dict(rows='actors',prefix='entity',allow_empty=True,fields=[dict(name='word',type='i32',address=1)])]))
    events=[dict(schema='overwatch-decoder.acquisition-evidence/1',kind='start',source_kind='native_process_memory',
        target=profile['target'],recipe_sha256=sha(recipe),revision='fixture')]
    for i,guard in enumerate(r.guards):
        width=len(bytes.fromhex(guard['bytes_hex']))
        for j in range(2):events.append(dict(kind='read',id=2*i+j,attempted=True,error=None,address=guard['address'],
            requested_bytes=width,returned_bytes=width,bytes_hex=guard['bytes_hex'],read_start_ticks=2*j,read_end_ticks=2*j+1))
        events.append(dict(kind='guard_check',stage='final_guard_check',matches=True,
            expected_read_id=2*i,actual_read_id=2*i+1,expected_offset=0))
    empty=dict(kind='field_collection',stage='field_collection_output',rows='actors',prefix='entity',retained_rows=0,
               depth=1,allow_empty=True,first_field=9,expanded_fields=0,identity='ordinal_within_acquisition_only')
    events.extend([empty,dict(kind='profile_validated',profile_sha256=sha(pr),fields=9)])
    evidence=b''.join(raw(e) for e in events)
    manifest=raw(dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,revision='fixture',target=profile['target'],
        profile_sha256=sha(pr),recipe_sha256=sha(recipe),evidence_sha256=sha(evidence),stages_completed=1))
    pins=dict(manifest_sha256=sha(manifest),recipe_sha256=sha(recipe),evidence_sha256=sha(evidence))
    c.update(profile_sha256=sha(pr),source=pins,bindings=[],allow_empty_bindings=True,partition_id='p0')
    review=raw(dict(schema='overwatch-decoder.selected-empty-partition-review/1',reviewed=True,partition_id='p0',target=profile['target'],
        profile_sha256=sha(pr),source=pins,collection=dict(rows='actors',prefix='entity',event_sha256=sha(raw(empty)))))
    c['empty_partition_review_sha256']=sha(review)
    kwargs['source']=dict(profile_sha256=sha(pr),acquisition=pins)
    kwargs['artifacts'].update({sha(x):x for x in (manifest,recipe,evidence,review)})
    return pr,c,frame,kwargs

class EmptyTests(unittest.TestCase):
    def test_verified_empty_acquisition_emits_no_actor_and_keeps_current_absence_unknown(self):
        pr,c,f,kw=fixture();view=SelectedEntityView(pr,raw(c),allow_profile4=True,**kw)
        result=view.project(f)
        self.assertEqual(result['entities'],[]);self.assertTrue(result['empty_partition']['acquisition_empty'])
        self.assertEqual(result['empty_partition']['current_occupancy'],'unknown')
        self.assertEqual(result['empty_partition']['status'],'context_observed')
        from run_selected_live import compact
        result.update(session_id='ab'*16,segment=1,event_sequence=0)
        compacted=compact(result,'ab'*32)
        self.assertEqual(compacted['entities'],[]);self.assertEqual(compacted['empty_partition'],result['empty_partition'])
    def test_empty_frames_recheck_local_guards_target_and_gap(self):
        pr,c,f,kw=fixture();view=SelectedEntityView(pr,raw(c),allow_profile4=True,**kw)
        for mode in ('guard','target','gap'):
            bad=copy.deepcopy(f)
            if mode=='guard':bad['guards_after'][0]['ok']=False
            if mode=='target':bad['target']['pid']+=1
            if mode=='gap':bad['skipped_intervals_before']=1
            result=view.project(bad)
            self.assertEqual(result['entities'],[]);self.assertEqual(result['empty_partition']['status'],'unknown')
            self.assertIsNotNone(result['empty_partition']['reason'])
        self.assertEqual(view.project(f)['empty_partition']['status'],'context_observed')
    def test_opt_in_and_source_artifacts_are_required(self):
        pr,c,f,kw=fixture()
        for mode in ('optout','review','partition','source'):
            contract=copy.deepcopy(c);args=copy.deepcopy(kw)
            if mode=='optout':del contract['allow_empty_bindings']
            if mode=='review':contract['empty_partition_review_sha256']='ff'*32
            if mode=='partition':contract['partition_id']='other'
            if mode=='source':args['artifacts'][c['source']['evidence_sha256']]+=b'\n'
            with self.assertRaises(ValueError):SelectedEntityView(pr,raw(contract),allow_profile4=True,**args)
    def test_empty_live_epoch_accepts_original_ordinary_v4_frame(self):
        import tempfile
        from pathlib import Path
        from live_relations import LiveRelations
        from test_live_relations import event,live,SESSION
        pr,c,frame,kw=fixture();profile=json.loads(pr);pins=c['source']
        frame.update(interpretation='profile_declared_research',visibility='research',runtime_semantics_validated=False,
            public_state_eligible=False,atomic=False,scheduled_slot=0,scheduled_ticks=0,jitter_ticks=10,
            skipped_intervals_before=0,skipped_intervals_total=0,utc_origin_before_ticks=0,
            requested_interval_ms=100,scheduler_backend='synthetic',hard_realtime=False)
        for name,sample in frame['fields'].items():
            declaration=next(d for d in profile['fields'] if d['name']==name)
            sample.update(read_address_hex=f"{declaration['address']:016x}",path_id=None,reason=None,read_attempted=True,read_error=None)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for filename,pin in [('manifest.json',pins['manifest_sha256']),('recipe.json',pins['recipe_sha256']),('evidence.jsonl',pins['evidence_sha256'])]:
                (root/filename).write_bytes(kw['artifacts'][pin])
            (root/'profile.json').write_bytes(pr);(root/'contract.json').write_bytes(raw(c))
            adapter=LiveRelations(root,SESSION,1,selected_only=True,selected_contract=root/'contract.json',selected_artifacts=kw['artifacts'])
            session=event('session_start',0,target=profile['target'],recipe_sha256=pins['recipe_sha256'],source_kind='native_process_memory',
                recording_frame_included=True,public_state_eligible=False,atomic=False);session['emitted_ticks']=0
            acquired=event('acquisition_end',2,acquisition=dict(ordinal=1,directory='acquisition-0001',complete=True,error=None,
                start_ticks=0,end_ticks=1,profile_sha256=sha(pr),manifest_sha256=pins['manifest_sha256']));acquired['emitted_ticks']=1
            segment=event('segment_start',3,segment=1,acquisition=1,profile_sha256=sha(pr),source_stream_schema='overwatch-decoder.field-stream/4',start_ticks=2,
                fields=[dict(name=f['name'],type=f['type']) for f in profile['fields']]);segment['emitted_ticks']=2
            adapter.begin_epoch(raw(session),raw(acquired),raw(segment))
            envelope=live(frame,4)
            for name,sample in frame['fields'].items():envelope['fields'][name].update(read_attempted=True,read_error=None)
            result=adapter.consume(raw(envelope))
            self.assertEqual(result['entities'],[]);self.assertEqual(result['empty_partition']['status'],'context_observed')
            self.assertFalse(result['durability_verified'])

    def test_empty_optin_does_not_hide_declared_actor_fields(self):
        pr,c,f,kw=fixture();profile=json.loads(pr)
        profile['fields'].append(dict(name='other_actor',type='i32',address=65536,
            guards=[dict(address=65536,bytes_hex='01000000')]))
        pr=raw(profile);c['profile_sha256']=sha(pr);kw['source']['profile_sha256']=sha(pr)
        review=json.loads(kw['artifacts'][c['empty_partition_review_sha256']]);review['profile_sha256']=sha(pr)
        rr=raw(review);kw['artifacts'][sha(rr)]=rr;c['empty_partition_review_sha256']=sha(rr)
        with self.assertRaisesRegex(InvalidSelectedEntity,'empty_profile_has_nonlocal_fields'):
            SelectedEntityView(pr,raw(c),allow_profile4=True,**kw)

    def test_empty_event_not_unchecked_profile_or_bad_field_collection(self):
        pr,c,f,kw=fixture()
        for mode in ('nonempty','missing_final_guard','recipe_allow_empty','provided_source'):
            contract=copy.deepcopy(c);args=copy.deepcopy(kw);pins=contract['source']
            manifest=json.loads(args['artifacts'][pins['manifest_sha256']]);recipe=json.loads(args['artifacts'][pins['recipe_sha256']])
            events=[json.loads(line) for line in args['artifacts'][pins['evidence_sha256']].splitlines()]
            if mode=='provided_source':events[0]['source_kind']='provided_memory_source'
            if mode=='nonempty':next(e for e in events if e['kind']=='field_collection')['retained_rows']=1
            if mode=='missing_final_guard':events=[e for e in events if e['kind']!='guard_check']
            if mode=='recipe_allow_empty':recipe['field_collections'][0]['allow_empty']=False
            rr=raw(recipe);events[0]['recipe_sha256']=sha(rr);er=b''.join(raw(e) for e in events)
            manifest.update(recipe_sha256=sha(rr),evidence_sha256=sha(er));mr=raw(manifest)
            newpins=dict(recipe_sha256=sha(rr),evidence_sha256=sha(er),manifest_sha256=sha(mr))
            review=json.loads(args['artifacts'][contract['empty_partition_review_sha256']]);review['source']=newpins
            event=next(e for e in events if e['kind']=='field_collection');review['collection']['event_sha256']=sha(raw(event));reviewraw=raw(review)
            args['artifacts'].update({sha(x):x for x in (rr,er,mr,reviewraw)});contract.update(source=newpins,empty_partition_review_sha256=sha(reviewraw));args['source']['acquisition']=newpins
            with self.assertRaises(ValueError):SelectedEntityView(pr,raw(contract),allow_profile4=True,**args)

if __name__=='__main__':unittest.main()
