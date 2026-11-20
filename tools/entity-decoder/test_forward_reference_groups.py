"""Explicit same-controller references; synthetic acquisition bytes only."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from aggregate_live_partitions import LivePartitions
from aggregate_partitions import aggregate
from overwatch_decoder.health_projection import ForwardOwnerHealthContract
from compact_live_entities import CompactLiveEntities
from compact_live_roster import CompactLiveRoster
from forward_owner_relations import GuardedForwardOwners, build_forward_owner_contract, WORDS
from forward_owner_projection import ForwardOwnerProjection
from forward_owner_validation import validate_forward_owner_frame
from forward_roster_projection import source_metadata,validate_source,validate_frame
from live_relations import LiveRelations
from runtime_producer import profile_body_bindings
from test_forward_owner_relations import source_fixture,raw,sha
from test_live_relations import SESSION,start,live,next_frame
from test_aggregate_live_partitions import live_fixture


def paired(*, alias=False, groups=True, optional=False, swap=False, health=False, mutate=None):
    """Pin two reference routes with separate read payload names to one controller."""
    def edit(profile,values):
        # Controller and optional owner aliases share full storage and value,
        # rather than only the same low integer or field ordinal.
        for index in [0,1]+([3,4] if alias else []):
            original,other=profile['fields'][index],profile['fields'][5+index]
            g=next(g for g in profile['guards'] if g['address']==other['address'])
            source=next(g for g in profile['guards'] if g['address']==original['address'])
            g.update(address=original['address'],bytes_hex=source['bytes_hex'])
            other['address']=original['address'];values[other['name']]=values[original['name']]
        if alias:
            name=profile['fields'][7]['name'];values[name]=values[profile['fields'][2]['name']]
            next(g for g in profile['guards'] if g['address']==profile['fields'][7]['address'])['bytes_hex']=(values[name]&0xffffffff).to_bytes(4,'little').hex()
        for field in profile['fields']:
            old=field['name'];field['name']=old.replace('controller_0001','cmp_0000')
            if old in values:values[field['name']]=values.pop(old)
            if swap:
                old=field['name'];field['name']=old.replace('_aux_','_alt_')
                if old in values:values[field['name']]=values.pop(old)
        if health:
            for index in range(48):profile['guards'].append(dict(address=0xa000+16*index,bytes_hex=(1 if index==0 else 0).to_bytes(4,'little').hex()))
            for parent in ['controller_0000','cmp_0000']:
                profile['fields'].append(dict(name=parent+('_alt_'if swap else'_aux_')+'0000_pool_0000_direct_candidate',type='f32',address=0xa004))
        if mutate:mutate(profile,values)
    pr,cr,artifacts,frame=source_fixture(count=2,mutate=edit)
    c=json.loads(cr);recipe=json.loads(artifacts[c['source']['recipe_sha256']]);t=json.loads(artifacts[c['binding_template_sha256']])
    for b in t['bindings']:
        for name in ['owned_field_prefix',*WORDS]:b[name]=b[name].replace('controller_0001','cmp_0000')
    if swap:
        for b in t['bindings']:
            for name in ['owned_field_prefix',*WORDS]:b[name]=b[name].replace('_aux_','_alt_')
    traces=[]
    if optional:
        active=[];recipe['field_collections']=[]
        for i,b in enumerate(t['bindings']):
            parent='controller_0000'if i==0 else'cmp_0000';root='controller'if i==0 else'cmp'
            children=[]
            for j,label in enumerate(['aux','alt']):
                prefix=parent+'_'+label+'_0000_';present=(label=='alt')if swap else(label=='aux')
                children.append(dict(rows=parent+'_'+label,prefix=label,allow_empty=True,fields=[dict(name=n,type='i32')for n in ['handle_candidate_i32','manager_key_candidate_i32']]))
                branch=dict(b,binding_id=f'route{i}_{label}',owned_field_prefix=prefix,
                    owner_handle_field=prefix+'handle_candidate_i32',owner_key_field=prefix+'manager_key_candidate_i32',
                    optional_owner_collection=dict(recipe_pointer=f'/field_collections/{i}/field_collections/{j}',rows=parent+'_'+label,prefix=parent+'_'+label,depth=2))
                active.append(branch)
                traces.append(dict(kind='field_collection',stage='field_collection_output',rows=parent+'_'+label,prefix=parent+'_'+label,
                    retained_rows=int(present),expanded_fields=sum(f['name'].startswith(prefix)for f in json.loads(pr)['fields']),
                    depth=2,allow_empty=True,first_field=3,identity='ordinal_within_acquisition_only'))
            recipe['field_collections'].append(dict(rows=root,prefix=root,fields=[],field_collections=children))
        t['bindings']=active
    group_ids=[b['binding_id']for b in t['bindings']if not optional or ('alt'if swap else'aux')in b['binding_id']]
    if groups:t['reference_groups']=[dict(group_id='paired',binding_ids=group_ids)]
    rr=raw(recipe);t['recipe_sha256']=sha(rr)
    events=[json.loads(l)for l in artifacts[c['source']['evidence_sha256']].splitlines()];events[0]['recipe_sha256']=sha(rr);events[-1:-1]=traces
    er=b''.join(raw(e)for e in events);m=json.loads(artifacts[c['acquisition_manifest_sha256']]);m.update(recipe_sha256=sha(rr),evidence_sha256=sha(er))
    tr=raw(t);c.update(source=dict(recipe_sha256=sha(rr),evidence_sha256=sha(er)),acquisition_manifest_sha256=sha(raw(m)),binding_template_sha256=sha(tr),bindings=t['bindings'])
    if groups:c['reference_groups']=t['reference_groups']
    artifacts={sha(x):x for x in [rr,er,raw(m),tr]}
    for name,f in frame['fields'].items():f.update(type=next(f['type']for f in json.loads(pr)['fields']if f['name']==name),reason=None)
    frame.update(interpretation='profile_declared_research',visibility='research',runtime_semantics_validated=False,public_state_eligible=False,atomic=False,
        scheduled_slot=0,scheduled_ticks=0,jitter_ticks=10,skipped_intervals_before=0,skipped_intervals_total=0,utc_origin_before_ticks=0,requested_interval_ms=100,scheduler_backend='synthetic',hard_realtime=False)
    return pr,raw(c),artifacts,frame


def materialize(root,data):
    pr,cr,artifacts,frame=data;c=json.loads(cr)
    for name,pin in [('manifest.json',c['acquisition_manifest_sha256']),('recipe.json',c['source']['recipe_sha256']),('evidence.jsonl',c['source']['evidence_sha256'])]:(root/name).write_bytes(artifacts[pin])
    (root/'profile.json').write_bytes(pr);(root/'forward-contract.json').write_bytes(cr)
    paths={}
    for pin,value in artifacts.items():(root/pin).write_bytes(value);paths[pin]=pin
    (root/'forward-artifacts.json').write_bytes(raw(paths));(root/'bindings.json').write_bytes(artifacts[c['binding_template_sha256']])
    return dict(forward_owner_contract=root/'forward-contract.json',forward_owner_artifacts=root/'forward-artifacts.json')


def semantic(data):
    pr,cr,artifacts,frame=data;projector=GuardedForwardOwners(pr,cr,artifacts)
    source=dict(profile_sha256=sha(pr),acquisition=dict(projector.source,manifest_sha256=projector.manifest_hash))
    p=ForwardOwnerProjection(projector).project(frame,source)
    result=dict(profile_sha256=sha(pr),target=projector.relations.target,timing=projector.relations.project(frame)['timing'],
        gap_before=dict(skipped_slots=0),source_artifacts=source,forward_owner_projection=p)
    return result,projector


class ReferenceGroups(unittest.TestCase):
    def test_two_owners_same_owner_and_legacy_duplicate_rejection(self):
        for alias in [False,True]:
            for enabled in [False,True]:
                data=paired(alias=alias,groups=enabled);result,d=semantic(data);rows=result['forward_owner_projection']['relations']
                self.assertEqual([r['relation_status']for r in rows],['observed'if enabled else'unknown']*2)
                if enabled:
                    self.assertEqual(rows[0]['controller_object_key'],rows[1]['controller_object_key'])
                    self.assertEqual(rows[0]['forward_owner_object_key']==rows[1]['forward_owner_object_key'],alias)
                    metadata,compacted=validate_forward_owner_frame(result)
                    self.assertEqual(metadata['reference_groups'],json.loads(data[1])['reference_groups']);self.assertEqual(len(compacted),2)
                else:self.assertTrue(all(r['reason']=='duplicate_controller_or_owner'for r in rows))
                self.assertTrue(all(r['current_displayed_body']is None for r in rows))

    def test_group_constructor_rejects_wrong_controller_reference_and_partial_owner(self):
        for mode in ['controller_value','controller_storage','reference_alias']:
            def mutate(p,v):
                if mode=='controller_value':
                    # Complete profile bytes remain internally pinned, but the two controller words differ.
                    field=p['fields'][5];field['address']=0x9900;v[field['name']]=-7;p['guards'].append(dict(address=0x9900,bytes_hex='f9ffffff'))
                elif mode=='controller_storage':
                    field=p['fields'][5];field['address']=0x9900;p['guards'].append(dict(address=0x9900,bytes_hex=(v[field['name']]&0xffffffff).to_bytes(4,'little').hex()))
                else:
                    p['fields'][7]['address']=p['fields'][2]['address']
                    v[p['fields'][7]['name']]=v[p['fields'][2]['name']]
            with self.subTest(mode=mode),self.assertRaises(ValueError):semantic(paired(alias=True,mutate=mutate))
        def partial(p,v):
            field=p['fields'][8];field['address']=0x9910;v[field['name']]=v[p['fields'][3]['name']];p['guards'].append(dict(address=0x9910,bytes_hex=(v[field['name']]&0xffffffff).to_bytes(4,'little').hex()))
        result,_=semantic(paired(mutate=partial))
        self.assertTrue(all(r['reason']=='duplicate_controller_or_owner'for r in result['forward_owner_projection']['relations']))

    def test_owner_alias_collision_across_unrelated_groups_remains_unknown(self):
        def edit(p,v):
            # Two controller pairs and four exact owner aliases. Alias permission
            # stops at the declared group, even when every owner word agrees.
            for row in range(4):
                for index in (0,1,3,4):
                    source=(row//2)*10+index if index<2 else index
                    field=p['fields'][row*5+index];original=p['fields'][source]
                    guard=next(g for g in p['guards']if g['address']==field['address'])
                    guard.update(address=original['address'],bytes_hex=(v[original['name']]&0xffffffff).to_bytes(4,'little').hex())
                    field['address']=original['address'];v[field['name']]=v[original['name']]
                reference=p['fields'][row*5+2]
                v[reference['name']]=v[p['fields'][4]['name']]
                next(g for g in p['guards']if g['address']==reference['address'])['bytes_hex']=(v[reference['name']]&0xffffffff).to_bytes(4,'little').hex()
        pr,cr,artifacts,f=source_fixture(count=4,mutate=edit);c=json.loads(cr);t=json.loads(artifacts[c['binding_template_sha256']])
        groups=[dict(group_id='first',binding_ids=['actor0','actor1']),dict(group_id='second',binding_ids=['actor2','actor3'])]
        t['reference_groups']=groups;tr=raw(t);artifacts[sha(tr)]=tr;c.update(binding_template_sha256=sha(tr),reference_groups=groups)
        rows=GuardedForwardOwners(pr,raw(c),artifacts).project(f)['relations']
        self.assertTrue(all(r['reason']=='duplicate_controller_or_owner'and r['forward_owner_object_key']is None for r in rows))

    def test_template_groups_are_pinned_and_membership_is_bounded(self):
        pr,cr,arts,f=paired();c=json.loads(cr);t=json.loads(arts[c['binding_template_sha256']])
        for groups in [[],None,[dict(group_id='paired',binding_ids=['actor0'])],
            [dict(group_id='paired',binding_ids=['actor0','missing'])],
            [dict(group_id='paired',binding_ids=['actor0','actor1']),dict(group_id='overlap',binding_ids=['actor0','actor1'])]]:
            tc=copy.deepcopy(t);tc['reference_groups']=groups;data=raw(tc);ac=dict(arts);ac[sha(data)]=data;cc=dict(c,binding_template_sha256=sha(data),reference_groups=groups)
            with self.assertRaises(ValueError):GuardedForwardOwners(pr,raw(cc),ac)
        cc=copy.deepcopy(c);cc.pop('reference_groups')
        with self.assertRaisesRegex(ValueError,'binding_template_scope'):GuardedForwardOwners(pr,raw(cc),arts)
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);materialize(root,(pr,cr,arts,f));built,artifacts=build_forward_owner_contract(root,arts[c['binding_template_sha256']])
            self.assertEqual(json.loads(built)['reference_groups'],t['reference_groups'])
            self.assertEqual(GuardedForwardOwners(pr,built,artifacts).project(f)['relations'][0]['relation_status'],'observed')

    def test_guard_failure_missing_branch_and_gap_never_fill(self):
        result,d=semantic(paired());data=paired();f=data[3];name=d.bindings[1]['names'][2]
        for mode in ['missing','guard','gap']:
            changed=copy.deepcopy(f)
            if mode=='missing':changed['fields'].pop(name)
            if mode=='guard':changed['fields'][name]['guard_ids']=[]
            rows=d.project(changed,gap=mode=='gap')['relations']
            self.assertEqual(rows[1]['relation_status'],'unknown');self.assertEqual(rows[1]['owned_fields'],{})
            self.assertIsNone(rows[1]['forward_owner_object_key'])
            self.assertEqual(rows[0]['relation_status'],'unknown'if mode=='gap'else'observed')
        self.assertEqual(d.project(f)['relations'][1]['relation_status'],'observed')

    def test_health_alias_reads_remain_separate_by_binding_and_prefix(self):
        pr,cr,artifacts,f=paired(alias=True,health=True);d=GuardedForwardOwners(pr,cr,artifacts);contracts=[]
        for index,b in enumerate(d.bindings):
            prefix=b['owned_field_prefix'];f['fields'][prefix+'pool_0000_direct_candidate']['value']=175.25+index
            slots=[dict(index=i,membership_address=0xa000+16*i,membership_u32=int(i==0),field_name=prefix+'pool_0000_direct_candidate'if i==0 else None,scalar_address=0xa004 if i==0 else None)for i in range(48)]
            contracts.append(ForwardOwnerHealthContract.from_profile(pr,owner_prefix=prefix,slots=slots,binding_id=b['binding_id'],
                forward_contract_sha256=d.contract_hash,recipe_sha256=d.source['recipe_sha256'],acquisition_manifest_sha256=d.manifest_hash,acquisition_evidence_sha256=d.source['evidence_sha256']))
        source=dict(profile_sha256=sha(pr),acquisition=dict(d.source,manifest_sha256=d.manifest_hash))
        result=ForwardOwnerProjection(d,contracts).project(f,source)
        self.assertEqual([r['health_candidate']['raw_sum']for r in result['relations']],[175.25,176.25])
        frame=dict(profile_sha256=sha(pr),target=d.relations.target,timing=d.relations.project(f)['timing'],source_artifacts=source,gap_before=dict(skipped_slots=0),forward_owner_projection=result)
        validate_forward_owner_frame(frame)

    def test_optional_alternatives_group_only_present_and_new_epoch_swaps(self):
        for swap in [False,True]:
            result,d=semantic(paired(optional=True,swap=swap));rows=result['forward_owner_projection']['relations']
            observed=[r for r in rows if r['relation_status']=='observed'];empty=[r for r in rows if r['reason']=='acquisition_empty']
            self.assertEqual(len(observed),2);self.assertEqual(len(empty),2)
            self.assertTrue(all(('_alt_'if swap else'_aux_')in r['owned_field_prefix']for r in observed))
            validate_forward_owner_frame(result)
        pr,cr,arts,f=paired(optional=True);c=json.loads(cr);t=json.loads(arts[c['binding_template_sha256']])
        groups=[dict(group_id='invalid_empty_member',binding_ids=['route0_alt','route1_aux'])]
        t['reference_groups']=groups;tr=raw(t);arts[sha(tr)]=tr;c.update(reference_groups=groups,binding_template_sha256=sha(tr))
        with self.assertRaisesRegex(ValueError,'acquisition_empty_member'):GuardedForwardOwners(pr,raw(c),arts)

    def test_fresh_source_epoch_admits_changed_optional_branches(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);first_dir=root/'first';second_dir=root/'second';first_dir.mkdir();second_dir.mkdir()
            compact=CompactLiveEntities();previous=None
            for epoch,directory,swap in [(1,first_dir,False),(2,second_dir,True)]:
                data=paired(optional=True,swap=swap);opts=materialize(directory,data);pr,cr,arts,f=data
                if epoch==2:
                    # Synthetic transport only: a new native-format profile and fresh acquisition.
                    shifted=next_frame(f);shifted.update(sequence=0,scheduled_slot=0,monotonic_origin_ticks=100);f=shifted
                manifest=json.loads((directory/'manifest.json').read_bytes())
                adapter=LiveRelations(directory,SESSION,epoch,**opts)
                begin=start(json.loads(pr),manifest);begin['segment']=epoch
                if epoch==2:begin['event_sequence']=99
                adapter.consume(raw(begin))
                event=live(f,100 if epoch==2 else 1);event['segment']=epoch
                result=adapter.consume(raw(event))
                result['session_epoch']=dict(acquisition=epoch,session_start_sha256='11'*32,
                    acquisition_end_sha256=('22'if epoch==1 else'33')*32,segment_start_sha256=('44'if epoch==1 else'55')*32,
                    previous_values_carried=False,previous_epoch_last_frame_end_ticks=previous)
                out=compact.consume(raw(result));previous=result['timing']['end_ticks']
                observed=[r for r in out['forward_owners']if r['relation_status']=='observed']
                self.assertEqual(len(observed),2)
                self.assertTrue(all(('_alt_'if swap else'_aux_')in r['owned_field_prefix']for r in observed))
                self.assertEqual(out['forward_owner_projection']['reference_groups'],result['forward_owner_projection']['reference_groups'])

    def test_admission_removal_or_tampering_rejected(self):
        result,d=semantic(paired());metadata=source_metadata(d)
        source=dict(fields=[dict(name=n,type=f['type'])for n,f in d.relations.fields.items()],objects=[dict(controller_object_key=metadata['bindings'][0]['controller_object_key'])],forward_owner_projection=metadata)
        validate_source(source);validate_frame(result,source)
        for mode in ['removed','renamed','reordered']:
            bad=copy.deepcopy(result)
            if mode=='removed':bad['forward_owner_projection'].pop('reference_groups')
            elif mode=='renamed':bad['forward_owner_projection']['reference_groups'][0]['group_id']='forged'
            else:bad['forward_owner_projection']['reference_groups'][0]['binding_ids'].reverse()
            with self.subTest(mode=mode),self.assertRaises(ValueError):validate_frame(bad,source)

    def test_live_roster_and_compact_preserve_groups_unknowns_and_epoch_pins(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);data=paired(optional=True);opts=materialize(root,data);pr,cr,arts,f=data;m=json.loads((root/'manifest.json').read_bytes())
            adapter=LiveRelations(root,SESSION,1,**opts);adapter.consume(raw(start(json.loads(pr),m)));first=adapter.consume(raw(live(f)))
            compact=CompactLiveEntities();source_compact=compact.consume(raw(first))
            self.assertEqual(len(source_compact['forward_owners']),4)
            source_compact['forward_owner_projection']['reference_groups'][0]['group_id']='caller_mutation'
            source_projection=source_metadata(adapter.forward.projector)
            _,objects,unresolved=profile_body_bindings(pr,allow_unresolved=True)
            for entry in unresolved:entry['acquisition_evidence_sha256']=first['source_artifacts']['acquisition']['evidence_sha256']
            config,_=live_fixture(root);config.update(target=first['target'],observation_mode='raw-candidates',allow_unresolved_bodies=True,
                window_origin_ticks=0,window_ticks=100,maximum_skew_ticks=200,roster=[dict(objects[0],primary_source_id='p1')])
            source=dict(source_id='p1',session_id=SESSION,segment=1,profile_sha256=first['profile_sha256'],acquisition=first['source_artifacts']['acquisition'],
                fields=[dict(name=n,type=v['type'])for n,v in adapter.projector.fields.items()],objects=objects,unresolved_bodies=unresolved,forward_owner_projection=source_projection)
            config['sources']=[source];aggregator=LivePartitions(raw(config));aggregator.consume('p1',raw(first));windows=list(aggregator.advance(200))
            out=CompactLiveRoster().consume(raw(windows[-1]));self.assertEqual(len(out['forward_owners']),4)
            self.assertEqual(out['forward_owner_sources']['p1']['reference_groups'],source_projection['reference_groups'])
            self.assertEqual(sum(r['status']=='observed'for r in out['forward_owners']),2)
            second=next_frame(f);event=live(second,2);later=adapter.consume(raw(event));compact.consume(raw(later))
            third=next_frame(second);later=adapter.consume(raw(live(third,3)))
            later['forward_owner_projection']['reference_groups'][0]['group_id']='changed'
            with self.assertRaisesRegex(ValueError,'changed_within_epoch'):compact.consume(raw(later))
            bad=copy.deepcopy(windows[-1]);bad['forward_owner_sources']['p1']['reference_groups'][0]['group_id']='changed'
            with self.assertRaises(ValueError):CompactLiveRoster().consume(raw(bad))
            empty=list(aggregator.advance(300))[0];last=CompactLiveRoster().consume(raw(empty))
            self.assertTrue(all(r['health_candidate']['value']is None and r['owned_fields']=={}for r in last['forward_owners']))
            # The same finite projection fields use an explicit finite source manifest, not live retagging.
            from export_relations import project_frame
            finite_frame=project_frame(adapter.projector,f,first['source_artifacts'],dict(complete=True,partial=False,status='verified_complete'),
                first['gap_before'],forward_owner_projector=adapter.forward)
            path=root/'finite.jsonl';path.write_bytes(raw(finite_frame));source=copy.deepcopy(source)
            source.update(path=str(path),sha256=sha(path.read_bytes()),recording_manifest_sha256='55'*32,acquisition_manifest_sha256=source['acquisition']['manifest_sha256'])
            finite_frame['source_artifacts'].update(manifest_sha256='55'*32,samples_prefix_sha256='66'*32,index_prefix_sha256='77'*32)
            finite_frame['forward_owner_projection']['source_artifacts']=copy.deepcopy(finite_frame['source_artifacts']);path.write_bytes(raw(finite_frame));source['sha256']=sha(path.read_bytes())
            cfg=dict(config,schema='overwatch-decoder.partition-research-manifest/1',sources=[source]);(root/'finite-manifest.json').write_bytes(raw(cfg))
            aggregate(root/'finite-manifest.json',root/'finite-roster.jsonl')
            finite_out=[json.loads(line)for line in(root/'finite-roster.jsonl').read_bytes().splitlines()]
            self.assertEqual(sum(r['status']=='observed'for r in finite_out[-1]['forward_owners']),2)


if __name__=='__main__':unittest.main()
