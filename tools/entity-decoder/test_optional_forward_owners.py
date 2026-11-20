"""Optional owner absence requires native zero expansion plus current guards."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from forward_owner_relations import GuardedForwardOwners,build_forward_owner_contract
from forward_roster_projection import source_metadata,validate_source,validate_frame
from forward_owner_validation import validate_forward_owner_frame
from runtime_producer import forward_adapter_options
from live_relations import LiveRelations
from aggregate_live_partitions import LivePartitions
from compact_live_entities import CompactLiveEntities
from compact_live_roster import CompactLiveRoster
from test_forward_owner_relations import source_fixture,raw,sha
from test_live_relations import SESSION,start,live
from test_aggregate_live_partitions import live_fixture
from test_compact_live_entities import fixture as compact_fixture


def optional_source(root,present=False,mutation=None):
    def remove(profile,values):
        if not present:
            profile['fields']=[f for f in profile['fields']if '_aux_'not in f['name']]
            for name in list(values):
                if '_aux_'in name:values.pop(name)
    pr,old_contract,artifacts,frame=source_fixture(mutate=remove);old=json.loads(old_contract)
    original=artifacts[old['source']['recipe_sha256']];recipe=json.loads(original)
    children=[];bindings=[];traces=[]
    for index,label in enumerate(['aux','alt']):
        prefix='controller_0000_'+label+'_0000_';names=['controller_0000_handle_candidate_i32','controller_0000_manager_key_candidate_i32',
            'controller_0000_part51_0000_body_key_candidate_i32',prefix+'handle_candidate_i32',prefix+'manager_key_candidate_i32']
        children.append(dict(rows=label+'_owners',prefix=label,allow_empty=True,fields=[dict(name='handle_candidate_i32',type='i32'),dict(name='manager_key_candidate_i32',type='i32')]))
        bindings.append(dict(binding_id=label,owned_field_prefix=prefix,**dict(zip(['controller_handle_field','controller_key_field','reference_field','owner_handle_field','owner_key_field'],names)),
            optional_owner_collection=dict(recipe_pointer='/field_collections/0/field_collections/'+str(index),rows=label+'_owners',prefix='controller_0000_'+label,depth=2)))
        traces.append(dict(kind='field_collection',stage='field_collection_output',rows=label+'_owners',prefix='controller_0000_'+label,
            retained_rows=1 if present and label=='aux'else 0,depth=2,allow_empty=True,first_field=3,
            expanded_fields=len(json.loads(pr)['fields'])-3 if present and label=='aux'else 0,identity='ordinal_within_acquisition_only'))
    recipe['field_collections']=[dict(rows='controllers',prefix='controller',fields=[],field_collections=children)]
    rr=raw(recipe);events=[json.loads(line)for line in artifacts[old['source']['evidence_sha256']].splitlines()];events[0]['recipe_sha256']=sha(rr)
    events[-1:-1]=traces
    template=dict(schema='overwatch-decoder.forward-owner-binding-template/1',build_sha256=old['build_sha256'],recipe_sha256=sha(rr),bindings=bindings)
    if mutation:mutation(recipe,events,template)
    rr=raw(recipe);events[0]['recipe_sha256']=sha(rr);template['recipe_sha256']=sha(rr);er=b''.join(raw(e)for e in events)
    manifest=json.loads(artifacts[old['acquisition_manifest_sha256']]);manifest.update(recipe_sha256=sha(rr),evidence_sha256=sha(er),fields=len(json.loads(pr)['fields']),guard_declarations=len(json.loads(pr)['guards']))
    for name,data in [('profile.json',pr),('recipe.json',rr),('evidence.jsonl',er),('manifest.json',raw(manifest)),('bindings.json',raw(template))]:(root/name).write_bytes(data)
    frame.update(interpretation='profile_declared_research',visibility='research',runtime_semantics_validated=False,public_state_eligible=False,atomic=False,
        scheduled_slot=0,scheduled_ticks=0,jitter_ticks=10,skipped_intervals_before=0,skipped_intervals_total=0,utc_origin_before_ticks=0,
        requested_interval_ms=100,scheduler_backend='synthetic',hard_realtime=False)
    for name,field in frame['fields'].items():field.update(type=next(f['type']for f in json.loads(pr)['fields']if f['name']==name),reason=None)
    return pr,frame,manifest,template


def config(root,template):
    profile=json.loads((root/'profile.json').read_bytes());recipe=(root/'recipe.json').read_bytes()
    c=dict(forward_owner_bindings=str(root/'bindings.json'),forward_owner_bindings_sha256=sha((root/'bindings.json').read_bytes()),recipe=str(root/'recipe.json'))
    layout=dict(schema='overwatch-decoder.health-layout/1',executable_sha256=profile['target']['executable_sha256'],recipe_sha256=sha(recipe),extent_size=1152,
        read_stage='pool',slot_count=48,slot_stride=24,membership_offset=0,scalar_offset=8,scalar_field_suffix='_direct_candidate',
        actor_prefixes=[b['owned_field_prefix']for b in template['bindings']],supported_forward_owners=[dict(binding_id=b['binding_id'],owner_prefix=b['owned_field_prefix'])for b in template['bindings']])
    (root/'layout.json').write_bytes(raw(layout));c.update(forward_owner_health_layout=str(root/'layout.json'),forward_owner_health_layout_sha256=sha((root/'layout.json').read_bytes()))
    trace=b'synthetic native branch review';review=raw(dict(schema='overwatch-decoder.native-category-review/1',reviewed=True,review_method='native_consumer_trace',
        build_sha256=profile['target']['executable_sha256'],required_conditions=['unlinked_owner','zero_override'],sources=[sha(trace)],algorithm=dict(ordered_bits=[3],clear_bits=[2],supported_categories=[0])))
    paths={}
    for data in [trace,review]:
        p=root/(sha(data)+'.json');p.write_bytes(data);paths[sha(data)]=str(p)
    (root/'category-artifacts.json').write_bytes(raw(paths));category=dict(schema='overwatch-decoder.forward-owner-category-template/1',build_sha256=profile['target']['executable_sha256'],recipe_sha256=sha(recipe),native_review_sha256=sha(review),bindings=[])
    for b in template['bindings']:
        category['bindings'].append(dict(binding_id=b['binding_id'],owner_handle_field=b['owner_handle_field'],owner_key_field=b['owner_key_field'],flags_low_field=b['owned_field_prefix']+'flags_low',flags_high_field=b['owned_field_prefix']+'flags_high',conditions=[dict(role='unlinked_owner',width=8,mask=1,equals=0,field_relative=dict(field='not_present',offset=0)),dict(role='zero_override',width=4,mask=0xffffffff,equals=0,field_relative=dict(field='not_present',offset=0))]))
    (root/'category-template.json').write_bytes(raw(category));c.update(forward_owner_category_template=str(root/'category-template.json'),forward_owner_category_template_sha256=sha((root/'category-template.json').read_bytes()),forward_owner_category_artifacts=str(root/'category-artifacts.json'),forward_owner_category_artifacts_sha256=sha((root/'category-artifacts.json').read_bytes()))
    return c


class OptionalForwardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def make(self,present=False,mutation=None):
        pr,frame,manifest,template=optional_source(self.root,present,mutation)
        contract,artifacts=build_forward_owner_contract(self.root,raw(template));return GuardedForwardOwners(pr,contract,artifacts),frame

    def test_present_branch_not_poisoned_by_empty_alternative(self):
        decoder,frame=self.make(present=True);rows=decoder.project(frame)['relations']
        self.assertEqual(rows[0]['relation_status'],'observed');self.assertEqual(rows[1]['reason'],'acquisition_empty');self.assertEqual(len(rows[0]['identity_evidence']),5)
        self.assertIsNone(rows[1]['forward_owner_object_key']);self.assertEqual(len(rows[1]['identity_evidence']),3)

    def test_empty_requires_three_current_words_and_never_owner_values(self):
        d,f=self.make();out=d.project(f);self.assertTrue(all(r['reason']=='acquisition_empty'for r in out['relations']))
        for name in d.bindings[0]['names']:
            for mode in ['value','guards','span']:
                bad=copy.deepcopy(f)
                if mode=='value':bad['fields'][name]['value']+=1
                if mode=='guards':bad['fields'][name]['guard_ids']=[]
                if mode=='span':bad['fields'][name]['read_end_ticks']=9999
                self.assertNotEqual(d.project(bad)['relations'][0]['reason'],'acquisition_empty')
        self.assertEqual(d.project(f,gap=True)['relations'][0]['reason'],'scheduled_gap')
        for row in out['relations']:self.assertIsNone(row['forward_owner_object_key']);self.assertEqual(row['owned_fields'],{})

    def test_missing_malformed_or_nonempty_trace_rejected(self):
        mutations={
            'missing':lambda r,e,t:e.__setitem__(slice(None),[x for x in e if x.get('prefix')!='controller_0000_aux']),
            'nonzero':lambda r,e,t:next(x for x in e if x.get('prefix')=='controller_0000_aux').update(retained_rows=1),
            'expanded':lambda r,e,t:next(x for x in e if x.get('prefix')=='controller_0000_aux').update(expanded_fields=1),
            'not_optional':lambda r,e,t:r['field_collections'][0]['field_collections'][0].update(allow_empty=False),
            'wrong_rows':lambda r,e,t:next(x for x in e if x.get('prefix')=='controller_0000_aux').update(rows='other'),
            'wrong_pointer':lambda r,e,t:t['bindings'][0]['optional_owner_collection'].update(recipe_pointer='/field_collections/0/field_collections/1'),
        }
        for name,mutation in mutations.items():
            with self.subTest(name=name),self.assertRaises(ValueError):self.make(mutation=mutation)

    def test_partial_payload_and_malformed_current_identity_rejected(self):
        pr,frame,manifest,template=optional_source(self.root,present=True)
        profile=json.loads(pr);profile['fields']=[f for f in profile['fields']if f['name']!='controller_0000_aux_0000_manager_key_candidate_i32']
        profile_raw=raw(profile);events=[json.loads(line)for line in(self.root/'evidence.jsonl').read_bytes().splitlines()]
        events[-1].update(profile_sha256=sha(profile_raw),fields=len(profile['fields']))
        evidence=b''.join(raw(e)for e in events);manifest.update(profile_sha256=sha(profile_raw),evidence_sha256=sha(evidence),fields=len(profile['fields']))
        for name,data in [('profile.json',profile_raw),('evidence.jsonl',evidence),('manifest.json',raw(manifest))]:(self.root/name).write_bytes(data)
        with self.assertRaisesRegex(ValueError,'optional_owner_partial_or_nonempty'):build_forward_owner_contract(self.root,raw(template))
        decoder,frame=self.make();projection=decoder.project(frame)
        # The enrichment adapter supplies only null candidates for empty bindings.
        source=dict(profile_sha256=decoder.relations.hash,acquisition=dict(decoder.source,manifest_sha256=decoder.manifest_hash))
        projection.update(source_artifacts=source,controller_hero_output_enabled=False)
        for row in projection['relations']:row.update(position_candidate=None,health_candidate=None,controller_hero_asset_label_candidate=None,controller_hero_asset_label_evidence=None,controller_hero_asset_label_reason='forward_relation_unknown')
        semantic=dict(profile_sha256=decoder.relations.hash,target=decoder.relations.target,timing=projection['timing'],gap_before=dict(skipped_slots=0),source_artifacts=source,forward_owner_projection=projection)
        for malformed in [[None,{},{}],[[],{},{}],[dict(field=[],value=1),{},{}]]:
            bad=copy.deepcopy(semantic);bad['forward_owner_projection']['relations'][0]['identity_evidence']=malformed
            with self.assertRaises(ValueError):validate_forward_owner_frame(bad)
        admission=source_metadata(decoder);checked=dict(fields=[dict(name=f['name'],type=f['type'])for f in decoder.relations.profile['fields']],objects=[dict(controller_object_key=admission['bindings'][0]['controller_object_key'])],acquisition=source['acquisition'],forward_owner_projection=admission)
        validate_source(checked);checked['acquisition']=dict(checked['acquisition'],evidence_sha256='ff'*32)
        with self.assertRaises(ValueError):validate_source(checked)

    def test_materialized_health_category_and_live_projection_admit_empty(self):
        pr,frame,manifest,template=optional_source(self.root);c=config(self.root,template);epoch=self.root/'epoch';epoch.mkdir();opts=forward_adapter_options(c,self.root,epoch)
        self.assertEqual(opts['forward_owner_health_contracts'],[])
        bundle=json.loads((epoch/'forward-health-bundle.json').read_bytes());self.assertEqual(bundle['acquisition_empty_bindings'],['aux','alt'])
        category=json.loads((epoch/'forward-category-contract.json').read_bytes());self.assertEqual(category['bindings'],[]);self.assertEqual(category['acquisition_empty_bindings'],['aux','alt'])
        adapter=LiveRelations(self.root,SESSION,1,**opts);adapter.consume(raw(start(json.loads(pr),manifest)));result=adapter.consume(raw(live(frame)))
        for row in result['forward_owner_projection']['relations']:
            self.assertEqual(row['reason'],'acquisition_empty');self.assertIsNone(row['health_candidate']);self.assertIsNone(row['controller_hero_asset_label_candidate']);self.assertIsNone(row['raw_flags_candidate'])
        compact=CompactLiveEntities().consume(raw(result));self.assertEqual(len(compact['forward_owners']),2)
        projector=adapter.forward.projector;admission=source_metadata(projector,category=adapter.forward.category)
        source=dict(fields=[dict(name=f['name'],type=f['type'])for f in json.loads(pr)['fields']],objects=[dict(controller_object_key=admission['bindings'][0]['controller_object_key'],body_object_key=None)],forward_owner_projection=admission)
        validate_source(source);validate_frame(result,source)
        from runtime_producer import profile_body_bindings
        _,objects,unresolved=profile_body_bindings(pr,allow_unresolved=True)
        for declaration in unresolved:declaration['acquisition_evidence_sha256']=result['source_artifacts']['acquisition']['evidence_sha256']
        cfg,_=live_fixture(self.root)
        cfg.update(target=result['target'],observation_mode='raw-candidates',allow_unresolved_bodies=True,
            window_origin_ticks=0,window_ticks=100,maximum_skew_ticks=200,roster=[dict(objects[0],primary_source_id='p1')])
        source.update(source_id='p1',session_id=SESSION,segment=1,profile_sha256=result['profile_sha256'],
            acquisition=result['source_artifacts']['acquisition'],unresolved_bodies=unresolved,objects=objects)
        cfg['sources']=[source]
        aggregate=LivePartitions(raw(cfg));aggregate.consume('p1',raw(result));windows=list(aggregate.advance(200))
        compact_roster=CompactLiveRoster()
        for window in windows:projected=compact_roster.consume(raw(window))
        self.assertEqual(len(projected['forward_owners']),2)
        self.assertTrue(all(row['status']=='unknown'and row['forward_owner_object_key']is None
            and row['health_candidate']['value']is None for row in projected['forward_owners']))
        self.assertEqual(windows[-1]['forward_owners'][0]['reason'],'acquisition_empty')
        self.assertEqual(windows[-1]['relations'][0]['controller_object_key'],objects[0]['controller_object_key'])
