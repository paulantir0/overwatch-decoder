"""Synthetic guard/contract tests; no game constants or runtime claims."""
import copy
import json
import unittest

from relations import GuardedRelations
from selected_entity_view import SelectedEntityView, InvalidSelectedEntity, WORDS, sha
from test_relations import prepare


def fixture(two=False):
    profile = dict(schema='overwatch-decoder.field-profile/1', target=dict(pid=123, creation_file_time=456,
        executable_sha256='ab'*32, architecture='x64', image_name='fixture.exe'), guards=[], fields=[])
    values = {}
    for name,value in zip(WORDS, (1,2,2,3,3,4,3)):
        address = 4096+len(values)*8
        profile['fields'].append(dict(name=name,type='i32',address=address))
        profile['guards'].append(dict(address=address,bytes_hex=value.to_bytes(4,'little').hex()))
        values[name]=value
    for name,kind,value in [('position','f32x3',[1.,2.,3.]),('hero_low','i32',11),('hero_high','i32',12)]:
        profile['fields'].append(dict(name=name,type=kind,address=8192+len(values)*16)); values[name]=value
    slots=[]
    for i in range(48):
        name=f'h{i}'; address=12288+i*8; member=0 if i==47 else 1
        profile['guards'].append(dict(address=address,bytes_hex=member.to_bytes(4,'little').hex()))
        profile['fields'].append(dict(name=name,type='f32',address=16384+i*4)); values[name]=1.0
        slots.append(dict(index=i,current=name,membership_address=address,membership_u32=member))
    raw=json.dumps(profile).encode(); review=b'synthetic explicit native layout review'
    source=dict(manifest_sha256='cd'*32,recipe_sha256='ef'*32,evidence_sha256='12'*32)
    binding=dict(binding_id='one', fields={k:k for k in (*WORDS,'position','hero_low','hero_high')},
        is_local=True,review_sha256=sha(review),validation_status='synthetic_relation',
        health=dict(slots=slots,review_sha256=sha(review),validation_status='synthetic_health'))
    c=dict(schema='overwatch-decoder.selected-entity-contract/1',target=profile['target'],profile_sha256=sha(raw),
           source=source,bindings=[binding])
    if two:
        other=copy.deepcopy(binding); other['binding_id']='two'; c['bindings'].append(other)
    _,frame=prepare(profile,values)
    for name,v in values.items():
        frame['fields'][name]['value']=v
        frame['fields'][name]['type']=next(f['type'] for f in profile['fields'] if f['name']==name)
    return raw,c,frame,dict(source=dict(profile_sha256=sha(raw),acquisition=source),artifacts={sha(review):review})


def serial_guards(profile,frame):
    r=GuardedRelations(json.dumps(profile).encode(),allow_profile4=True)
    for phase in ('before','after'):
        for i,check in enumerate(frame['guards_'+phase]):
            guard=r.guards[i]; start=check.pop('start_ticks'); end=check.pop('end_ticks')
            check.update(guard_id=i,read=dict(attempted=True,address_hex=f"{guard['address']:016x}",
                requested_bytes=len(bytes.fromhex(guard['bytes_hex'])),returned_bytes=len(bytes.fromhex(guard['bytes_hex'])),
                bytes_hex=guard['bytes_hex'],start_ticks=start,end_ticks=end,error=None))


def pool_fixture():
    import struct
    raw,c,frame,kwargs=fixture()
    profile=json.loads(raw); profile['schema']='overwatch-decoder.field-profile/4'
    layout=[dict(membership_offset=0,scalar_offset=4),dict(membership_offset=8,scalar_offset=12)]
    profile['fields'].append(dict(name='sum',type='f32',codec='pool_sum_f32',address=40960,pool_span=16,pool_slots=layout))
    raw=json.dumps(profile).encode(); c['profile_sha256']=sha(raw); kwargs['source']['profile_sha256']=sha(raw)
    h=c['bindings'][0]['health']; c['bindings'][0]['health']={k:h[k] for k in ('review_sha256','validation_status')}
    c['bindings'][0]['health']['sum_field']='sum'
    frame['profile_sha256']=sha(raw); frame['schema']='overwatch-decoder.field-stream/4'
    serial_guards(profile,frame)
    data=struct.pack('<IfIf',1,3.,2,4.).hex()
    def operand(a,b):
        return dict(attempted=True,address_hex='000000000000a000',requested_bytes=16,returned_bytes=16,
                    bytes_hex=data,start_ticks=a,end_ticks=b,error=None)
    r=GuardedRelations(raw,allow_profile4=True)
    frame['fields']['sum']=dict(type='f32',status='observed',value=7.,reason=None,read_start_ticks=30,read_end_ticks=50,
        guard_ids=r.guard_ids['sum'],path_id=None,read_address_hex='000000000000a000',read_attempted=True,read_error=None,
        codec='pool_sum_f32',pool_span=16,pool_slots=layout,read_kind='operand_envelope',
        operands=dict(snapshot_a=operand(30,40),snapshot_b=operand(45,50)))
    return raw,c,frame,kwargs


def relative_fixture(local_key=30, target_flags=1<<4, labels=True, split_identities=False):
    raw,c,frame,kwargs=pool_fixture()
    profile=json.loads(raw); profile['fields']=[]; profile['guards']=[]
    values={}; fields={}; local_fields={}
    for prefix,roles,out,initial in [('target',tuple(k for k in WORDS if k!='selector'),fields,
         dict(controller_handle=1,controller_key=2,ref_first=3,ref_third=3,body_handle=4,body_key=3)),
        ('local',WORDS,local_fields,dict(controller_handle=10,controller_key=20,selector=20,
         ref_first=local_key,ref_third=local_key,body_handle=40,body_key=local_key))]:
        guards=[]; declarations=[]
        for role in roles:
            name=prefix+'_'+role; address=4096+len(profile['fields'])*16+len(declarations)*16
            guard=dict(address=address,bytes_hex=initial[role].to_bytes(4,'little').hex()); guards.append(guard)
            declarations.append(dict(name=name,type='i32',address=address)); values[name]=initial[role]; out[role]=name
        for role,kind,value in [('flags_low','i32',target_flags if prefix=='target' else 1<<3),('flags_high','i32',0)]:
            name=prefix+'_'+role; out[role]=name; values[name]=value
            declarations.append(dict(name=name,type=kind,address=8192+len(values)*16))
        if prefix=='target':
            for role,kind,value in [('position','f32x3',[1.,2.,3.]),('hero_low','i32',11),('hero_high','i32',12)]:
                name=prefix+'_'+role; out[role]=name; values[name]=value
                declarations.append(dict(name=name,type=kind,address=8192+len(values)*16))
            codec=copy.deepcopy(next(d for d in json.loads(raw)['fields'] if d['name']=='sum'))
            declarations.append(codec); values['sum']=7.
        for d in declarations: d['guards']=copy.deepcopy(guards)
        profile['fields'].extend(declarations)
    if split_identities:
        identities={fields[k] for k in fields if k in WORDS} | {local_fields[k] for k in WORDS}
        for d in profile['fields']:
            if d['name'] in identities:
                d['guards']=[g for g in d['guards'] if g['address'] == d['address']]
    profile['fields'].append(dict(name='unrelated',type='i32',address=50000,
        guards=[dict(address=50000,bytes_hex='01000000')]))
    values['unrelated']=1
    profile['schema']='overwatch-decoder.field-profile/1'
    _,frame2=prepare(profile,values)
    profile['schema']='overwatch-decoder.field-profile/4'; raw=json.dumps(profile).encode()
    frame2['profile_sha256']=sha(raw); frame2['schema']='overwatch-decoder.field-stream/4'
    serial_guards(profile,frame2)
    for name,value in values.items():
        frame2['fields'][name]['type']=next(d['type'] for d in profile['fields'] if d['name']==name)
    sample=copy.deepcopy(frame['fields']['sum']); sample['guard_ids']=frame2['fields']['sum']['guard_ids']
    frame2['fields']['sum']=sample
    c['mode']='target_vs_local'; c['profile_sha256']=sha(raw); kwargs['source']['profile_sha256']=sha(raw)
    c['bindings'][0]['fields']=fields
    pin=c['bindings'][0]['review_sha256']
    c['local_context']=dict(fields=local_fields,review_sha256=pin,validation_status='synthetic_local')
    native=dict(reviewed=True,build_sha256=profile['target']['executable_sha256'],ordinary_branch=dict(
        ordered_category_bits=[3,4,5],supported_categories=[0,1],excluded_mode_bit=6))
    native_raw=json.dumps(native).encode(); kwargs['artifacts'][sha(native_raw)]=native_raw
    c['category_rule']=dict(ordered_bits=[3,4,5],mode_mask=1<<6,supported_categories=[0,1],
        review_sha256=sha(native_raw),validation_status='synthetic_native_with_ui',
        route_conditions=['unlinked_both_owners','null_override_argument','controlled_player_context'])
    if labels:
        evidence=b'synthetic controlled local and target UI evidence'; kwargs['artifacts'][sha(evidence)]=evidence
        review=dict(schema='overwatch-decoder.selected-relation-label-review/1',reviewed=True,target=profile['target'],
            profile_sha256=sha(raw),source=c['source'],same_group_label='ally',different_group_label='enemy',sources=[sha(evidence)])
        data=json.dumps(review).encode(); kwargs['artifacts'][sha(data)]=data
        c['category_rule'].update(same_group_label='ally',different_group_label='enemy',label_review_sha256=sha(data))
    return raw,c,frame2,kwargs


def body_absent_fixture(first=0,third=99):
    raw,c,old,kwargs=relative_fixture(split_identities=True,labels=False)
    profile=json.loads(raw)
    retained={'target_'+k for k in ('controller_handle','controller_key','ref_first','ref_third')}
    profile['fields']=[d for d in profile['fields'] if not d['name'].startswith('target_') or d['name'] in retained]
    profile['fields']=[d for d in profile['fields'] if d['name'] != 'sum']
    values={d['name']:old['fields'][d['name']]['value'] for d in profile['fields']}
    for role,value in [('ref_first',first),('ref_third',third)]:
        name='target_'+role; d=next(d for d in profile['fields'] if d['name']==name)
        d['guards'][0]['bytes_hex']=value.to_bytes(4,'little').hex();values[name]=value
    profile['schema']='overwatch-decoder.field-profile/1';_,frame=prepare(profile,values)
    profile['schema']='overwatch-decoder.field-profile/4'; raw=json.dumps(profile).encode()
    frame['schema']='overwatch-decoder.field-stream/4';frame['profile_sha256']=sha(raw);serial_guards(profile,frame)
    c['profile_sha256']=sha(raw);kwargs['source']['profile_sha256']=sha(raw)
    c['bindings'][0]['body_absent']=True;del c['bindings'][0]['health'];c['bindings'][0].pop('is_local',None)
    return raw,c,frame,kwargs


class SelectedTests(unittest.TestCase):
    def setup_view(self,two=False):
        self.raw,self.contract,self.frame,self.kwargs=fixture(two)
        return SelectedEntityView(self.raw,json.dumps(self.contract).encode(),**self.kwargs)

    def test_complete_projection_and_unknown_label(self):
        v=self.setup_view(); row=v.project(self.frame)['entities'][0]
        self.assertIsNotNone(row['entity_id']); self.assertTrue(row['is_local'])
        self.assertEqual(row['position']['value'],[1.,2.,3.]); self.assertEqual(row['health']['value'],47.)
        self.assertIsNone(row['hero']['value']); self.assertEqual(row['hero']['validation_status'],'unknown')
        self.assertIn('read_start_ticks',row['health']['reads'][0])

    def test_gap_wrong_target_profile_and_failed_guard_do_not_carry(self):
        v=self.setup_view(); self.assertIsNotNone(v.project(self.frame)['entities'][0]['entity_id'])
        frames=[]
        for key,val in [('skipped_intervals_before',1),('profile_sha256','00'*32)]:
            f=copy.deepcopy(self.frame); f[key]=val; frames.append(f)
        f=copy.deepcopy(self.frame); f['target']['pid']+=1; frames.append(f)
        f=copy.deepcopy(self.frame); f['guards_after'][0]['ok']=False; frames.append(f)
        for frame in frames:
            row=v.project(frame)['entities'][0]
            self.assertIsNone(row['entity_id']); self.assertIsNone(row['position']['value'])
        self.assertIsNotNone(v.project(self.frame)['entities'][0]['entity_id'])

    def test_association_mismatches_and_identity_word_mismatch(self):
        v=self.setup_view()
        for name in ['selector','ref_first','ref_third','body_key']:
            f=copy.deepcopy(self.frame); f['fields'][name]['value']+=1
            self.assertIsNone(v.project(f)['entities'][0]['entity_id'])

    def test_duplicate_identity_is_unknown(self):
        v=self.setup_view(two=True)
        for row in v.project(self.frame)['entities']:
            self.assertIsNone(row['entity_id']); self.assertIsNone(row['health']['value'])
            self.assertTrue(row['reason'].startswith('duplicate_'))

    def test_missing_or_nonfinite_health_no_zero_fill(self):
        v=self.setup_view()
        for value in [None,float('nan'),float('inf'),1e100]:
            f=copy.deepcopy(self.frame); f['fields']['h47']['value']=value
            row=v.project(f)['entities'][0]
            self.assertIsNone(row['health']['value']); self.assertIsNotNone(row['entity_id'])
        f=copy.deepcopy(self.frame); del f['fields']['h0']
        self.assertIsNone(v.project(f)['entities'][0]['health']['value'])

    def test_binary32_accumulation_order(self):
        v=self.setup_view(); f=self.frame
        for i in range(48): f['fields'][f'h{i}']['value']=0.
        for i,n in enumerate([16777216.,1.,-16777216.]): f['fields'][f'h{i}']['value']=n
        self.assertEqual(v.project(f)['entities'][0]['health']['value'],0.)

    def test_incomplete_layout_source_review_and_membership_rejected(self):
        self.setup_view()
        bad=[]
        c=copy.deepcopy(self.contract); c['bindings'][0]['health']['slots'].pop(); bad.append(c)
        c=copy.deepcopy(self.contract); c['bindings'][0]['health']['slots'][0]['membership_u32']=9; bad.append(c)
        c=copy.deepcopy(self.contract); c['bindings'][0]['review_sha256']='ff'*32; bad.append(c)
        c=copy.deepcopy(self.contract); c['source']['evidence_sha256']='ff'*32; bad.append(c)
        for c in bad:
            with self.assertRaises(InvalidSelectedEntity):
                SelectedEntityView(self.raw,json.dumps(c).encode(),**self.kwargs)

    def test_health_order_and_membership_address_alias_rejected(self):
        self.setup_view()
        for mutation in ('order','membership_address'):
            c=copy.deepcopy(self.contract); slots=c['bindings'][0]['health']['slots']
            if mutation == 'order': slots[0],slots[1]=slots[1],slots[0]
            else: slots[1]['membership_address']=slots[0]['membership_address']
            with self.assertRaisesRegex(InvalidSelectedEntity, 'health_slot_order|duplicate_membership_address'):
                SelectedEntityView(self.raw,json.dumps(c).encode(),**self.kwargs)

    def test_unique_names_with_duplicate_health_scalar_addresses_rejected(self):
        self.setup_view(); profile=json.loads(self.raw)
        fields={f['name']:f for f in profile['fields']}
        fields['h1']['address']=fields['h0']['address']
        raw=json.dumps(profile).encode(); c=copy.deepcopy(self.contract); c['profile_sha256']=sha(raw)
        kwargs=copy.deepcopy(self.kwargs); kwargs['source']['profile_sha256']=sha(raw)
        with self.assertRaisesRegex(InvalidSelectedEntity,'duplicate_health_scalar_address'):
            SelectedEntityView(raw,json.dumps(c).encode(),**kwargs)

    def test_position_guard_bracket_and_membership_guard_failure(self):
        v=self.setup_view(); f=copy.deepcopy(self.frame)
        f['fields']['position']['read_end_ticks']=95
        self.assertIsNone(v.project(f)['entities'][0]['position']['value'])
        f=copy.deepcopy(self.frame); f['guards_before'][-1]['ok']=False
        self.assertIsNone(v.project(f)['entities'][0]['health']['value'])

    def test_profile4_is_explicit_opt_in_and_pool_result_recomputed(self):
        raw,c,frame,kwargs=pool_fixture()
        from relations import InvalidBinding
        with self.assertRaisesRegex(InvalidBinding,'unsupported_profile_schema'):
            SelectedEntityView(raw,json.dumps(c).encode(),**kwargs)
        v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
        row=v.project(frame)['entities'][0]
        self.assertEqual(row['health']['value'],7.)
        self.assertEqual(row['health']['source'],'calculated_process_memory')
        self.assertNotIn('address',json.dumps(row))
        self.assertEqual(len(row['health']['operand_reads']),2)

    def test_stream_schema_must_match_admitted_profile_version(self):
        raw,c,f,kwargs=pool_fixture()
        view=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
        self.assertEqual(f['schema'],'overwatch-decoder.field-stream/4')
        self.assertEqual(view.project(f)['entities'][0]['health']['value'],7.)
        for schema in ('overwatch-decoder.field-stream/1','overwatch-decoder.field-stream/2','overwatch-decoder.field-stream/3'):
            bad=copy.deepcopy(f); bad['schema']=schema
            self.assertEqual(view.project(bad)['entities'][0]['reason'],'unsupported_frame')
        old=self.setup_view(); bad=copy.deepcopy(self.frame); bad['schema']='overwatch-decoder.field-stream/4'
        self.assertEqual(old.project(bad)['entities'][0]['reason'],'unsupported_frame')

    def test_current_frame_gap_optin_retains_only_fresh_guarded_values(self):
        raw,c,f,kwargs=pool_fixture();f['skipped_intervals_before']=2
        strict=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
        self.assertIsNone(strict.project(f)['entities'][0]['health']['value'])
        c['gap_policy']='current_frame_only'
        view=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
        result=view.project(f,gap=True)
        self.assertEqual(result['entities'][0]['health']['value'],7.)
        self.assertEqual(result['frame_gap']['skipped_intervals_before'],2)
        self.assertFalse(result['previous_values_carried'])
        for mode in ('guard','missing','target','invalid_gap'):
            bad=copy.deepcopy(f)
            if mode=='guard':bad['guards_after'][0]['ok']=False
            if mode=='missing':bad['fields']={}
            if mode=='target':bad['target']['pid']+=1
            if mode=='invalid_gap':bad['skipped_intervals_before']=True
            self.assertIsNone(view.project(bad)['entities'][0]['health']['value'])
        self.assertEqual(view.project(f)['entities'][0]['health']['value'],7.)
        c['gap_policy']='carry_previous'
        with self.assertRaisesRegex(InvalidSelectedEntity,'unsupported_gap_policy'):
            SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)

    def test_gap_metadata_validation_and_existing_error_precedence(self):
        raw,c,f,kwargs=pool_fixture()
        for policy in ('strict','current_frame_only'):
            c['gap_policy']=policy;view=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
            for value in (-1,True,1.5,'1',None):
                bad=copy.deepcopy(f);bad['skipped_intervals_before']=value
                self.assertEqual(view.project(bad)['entities'][0]['reason'],'invalid_gap_metadata')
            for gap in (0,1,'yes',None):
                self.assertEqual(view.project(f,gap=gap)['entities'][0]['reason'],'invalid_gap_metadata')
            bad=copy.deepcopy(f);bad['profile_sha256']='ff'*32;bad['skipped_intervals_before']=3
            self.assertEqual(view.project(bad,gap=True)['entities'][0]['reason'],'profile_mismatch')
            result=view.project(f)
            self.assertFalse(result['frame_gap']['continuity_across_gaps'])
            self.assertFalse(result['frame_gap']['previous_values_carried'])

    def test_profile4_serial_guards_validate_nested_read_evidence(self):
        raw,c,f,kwargs=pool_fixture(); v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
        self.assertNotIn('start_ticks',f['guards_before'][0])
        for key,value in [('bytes_hex','00000000'),('address_hex','0000000000009999'),('requested_bytes',1),
                          ('returned_bytes',0),('attempted',False),('end_ticks',99),('error','failed')]:
            bad=copy.deepcopy(f); bad['guards_before'][0]['read'][key]=value
            self.assertIsNone(v.project(bad)['entities'][0]['entity_id'])
        bad=copy.deepcopy(f); bad['guards_before'][0]['guard_id']=1
        self.assertIsNone(v.project(bad)['entities'][0]['entity_id'])
        bad=copy.deepcopy(f)
        for check in bad['guards_before']:
            check['start_ticks']=11;check['end_ticks']=20;del check['read']
        self.assertIsNone(v.project(bad)['entities'][0]['entity_id'])

    def test_pool_membership_value_layout_timing_and_read_tampering_unknown(self):
        import struct
        raw,c,frame,kwargs=pool_fixture()
        v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
        samples=[]
        for key,val in [('value',8.),('read_end_ticks',51),('pool_span',16.),('path_id',0),('read_attempted',False)]:
            f=copy.deepcopy(frame); f['fields']['sum'][key]=val; samples.append(f)
        for key,val in [('address_hex','000000000000b000'),('start_ticks',39),('returned_bytes',15),
                        ('bytes_hex',struct.pack('<IfIf',0,3.,2,4.).hex())]:
            f=copy.deepcopy(frame); f['fields']['sum']['operands']['snapshot_b'][key]=val; samples.append(f)
        for f in samples:
            row=v.project(f)['entities'][0]
            self.assertIsNone(row['health']['value']); self.assertIsNotNone(row['entity_id'])

    def test_pool_occupied_finiteness_and_signed_zero(self):
        import struct
        raw,c,frame,kwargs=pool_fixture()
        v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kwargs)
        sample=frame['fields']['sum']
        data=struct.pack('<IfIf',0,float('nan'),0,float('inf')).hex()
        for operand in sample['operands'].values(): operand['bytes_hex']=data
        sample['value']=0.
        self.assertEqual(v.project(frame)['entities'][0]['health']['value'],0.)
        sample['value']=-0.
        self.assertIsNone(v.project(frame)['entities'][0]['health']['value'])
        data=struct.pack('<IfIf',1,float('nan'),0,0.).hex()
        for operand in sample['operands'].values(): operand['bytes_hex']=data
        sample['value']=0.
        self.assertIsNone(v.project(frame)['entities'][0]['health']['value'])

    def test_invalid_pool_layout_rejected(self):
        raw,c,frame,kwargs=pool_fixture(); profile=json.loads(raw)
        for change in ('overlap','order','span'):
            p=copy.deepcopy(profile); d=p['fields'][-1]
            if change=='overlap': d['pool_slots'][1]['scalar_offset']=4
            if change=='order': d['pool_slots'].reverse()
            if change=='span': d['pool_span']=7
            changed=json.dumps(p).encode(); contract=copy.deepcopy(c); contract['profile_sha256']=sha(changed)
            args=copy.deepcopy(kwargs); args['source']['profile_sha256']=sha(changed)
            with self.assertRaises(InvalidSelectedEntity):
                SelectedEntityView(changed,json.dumps(contract).encode(),allow_profile4=True,**args)

    def test_nonlocal_ordinary_relation_hero_health_position(self):
        for flags,label in [(1<<3,'ally'),(1<<4,'enemy'),((1<<3)|(1<<4),'ally')]:
            raw,c,f,kw=relative_fixture(target_flags=flags)
            v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
            row=v.project(f)['entities'][0]
            self.assertEqual(row['relation']['value'],label); self.assertFalse(row['is_local'])
            self.assertEqual(row['position']['value'],[1.,2.,3.]); self.assertEqual(row['health']['value'],7.)
            self.assertIsNotNone(row['hero']['resource_guid'])
        raw,c,f,kw=relative_fixture(local_key=3,target_flags=1<<3)
        row=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw).project(f)['entities'][0]
        self.assertEqual(row['relation']['value'],'self'); self.assertTrue(row['is_local'])

    def test_nonlocal_typed_asset_label_all_requested_fields(self):
        from test_hero_asset_labels import fixture as asset_fixture
        from hero_asset_labels import HeroAssetCatalog
        _,_,catalog,artifacts,_=asset_fixture()
        raw,c,f,kw=relative_fixture()
        catalog['entries'][0]['build_sha256']=c['target']['executable_sha256']
        resource=int(catalog['entries'][0]['resource_guid'],16)
        for role,value in [('hero_low',resource&0xffffffff),('hero_high',resource>>32)]:
            f['fields']['target_'+role]['value']=value if value < 2**31 else value-2**32
        v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,
            hero_catalog=HeroAssetCatalog(json.dumps(catalog).encode(),artifacts),**kw)
        row=v.project(f)['entities'][0]
        self.assertEqual(row['hero']['value'],'Synthetic Hero')
        self.assertEqual(row['health']['value'],7.)
        self.assertEqual(row['position']['value'],[1.,2.,3.])
        self.assertEqual(row['relation']['value'],'enemy')

    def test_nonlocal_special_categories_unknown_and_group_requires_ui_review(self):
        for flags in [0,1<<5,(1<<4)|(1<<6)]:
            raw,c,f,kw=relative_fixture(target_flags=flags)
            row=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw).project(f)['entities'][0]
            self.assertIsNone(row['relation']['value']); self.assertEqual(row['health']['value'],7.)
        raw,c,f,kw=relative_fixture(labels=False)
        row=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw).project(f)['entities'][0]
        self.assertEqual(row['relation']['value'],'different_group')

    def test_nonlocal_guards_scoped_to_actor_and_current_local_context(self):
        raw,c,f,kw=relative_fixture(); v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
        r=v.relations
        other=copy.deepcopy(f); other['guards_after'][r.guard_ids['unrelated'][0]]['ok']=False
        self.assertEqual(v.project(other)['entities'][0]['relation']['value'],'enemy')
        local=copy.deepcopy(f); local['guards_after'][r.guard_ids['local_selector'][0]]['ok']=False
        row=v.project(local)['entities'][0]
        self.assertIsNone(row['relation']['value']); self.assertIsNone(row['is_local'])
        self.assertEqual(row['health']['value'],7.); self.assertIsNotNone(row['entity_id'])
        bad=copy.deepcopy(f); bad['fields']['target_ref_third']['value']+=1
        self.assertIsNone(v.project(bad)['entities'][0]['entity_id'])
        self.assertEqual(v.project(f)['entities'][0]['relation']['value'],'enemy')

    def test_explicit_body_absent_retains_only_controller_and_reference(self):
        for first,third in [(0,0),(0,99),(7,7)]:
            raw,c,f,kw=body_absent_fixture(first,third)
            view=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
            row=view.project(f)['entities'][0]
            self.assertIsNotNone(row['controller_id']);self.assertIsNone(row['entity_id']);self.assertIsNone(row['is_local'])
            self.assertEqual(row['controller_reference']['value'],dict(ref_first=first,ref_third=third))
            self.assertEqual(row['reason'],'body_not_acquired')
            for field in ('hero','health','position','relation'): self.assertIsNone(row[field]['value'])
            bad=copy.deepcopy(f);bad['skipped_intervals_before']=1
            self.assertIsNone(view.project(bad)['entities'][0]['controller_id'])
            self.assertIsNotNone(view.project(f)['entities'][0]['controller_id'])

    def test_body_absent_rejects_declared_body_and_never_falls_back_on_failure(self):
        raw,c,f,kw=relative_fixture(labels=False);c['bindings'][0]['body_absent']=True
        del c['bindings'][0]['health'];c['bindings'][0].pop('is_local',None)
        with self.assertRaisesRegex(InvalidSelectedEntity,'body_absent_but_declared'):
            SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
        raw,c,f,kw=relative_fixture(labels=False)
        view=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
        f['fields']['target_body_key']['status']='unknown'
        row=view.project(f)['entities'][0]
        self.assertNotEqual(row['reason'],'body_not_acquired');self.assertIsNone(row['controller_id'])
        self.assertNotIn('controller_reference',row)

    def test_body_absent_guard_failure_and_duplicate_controllers_unknown(self):
        raw,c,f,kw=body_absent_fixture()
        view=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
        bad=copy.deepcopy(f);gid=view.relations.guard_ids['target_controller_handle'][0]
        bad['guards_after'][gid]['ok']=False
        self.assertIsNone(view.project(bad)['entities'][0]['controller_id'])
        other=copy.deepcopy(c['bindings'][0]);other['binding_id']='duplicate';c['bindings'].append(other)
        duplicate=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
        for row in duplicate.project(f)['entities']:
            self.assertIsNone(row['controller_id']);self.assertIsNone(row['controller_reference']['value'])

    def test_individual_identity_guards_do_not_require_reverse_body_dependencies(self):
        raw,c,f,kw=relative_fixture(split_identities=True,labels=False)
        v=SelectedEntityView(raw,json.dumps(c).encode(),allow_profile4=True,**kw)
        self.assertEqual(v.project(f)['entities'][0]['relation']['value'],'different_group')
        self.assertEqual(v.project(f)['entities'][0]['health']['value'],7.)
        profile=json.loads(raw)
        position=next(d for d in profile['fields'] if d['name']=='target_position')
        position['guards'].pop()
        changed=json.dumps(profile).encode(); c['profile_sha256']=sha(changed); kw['source']['profile_sha256']=sha(changed)
        with self.assertRaisesRegex(InvalidSelectedEntity,'identity_dependencies_missing'):
            SelectedEntityView(changed,json.dumps(c).encode(),allow_profile4=True,**kw)

    def test_nonlocal_review_build_route_and_label_sources_reject(self):
        raw,c,f,kw=relative_fixture()
        for change in ('bits','route','label_source'):
            contract=copy.deepcopy(c); args=copy.deepcopy(kw)
            if change=='bits': contract['category_rule']['ordered_bits'].reverse()
            elif change=='route': contract['category_rule']['route_conditions'].pop()
            else:
                review=json.loads(args['artifacts'][contract['category_rule']['label_review_sha256']])
                review['sources']=['ff'*32]; data=json.dumps(review).encode(); args['artifacts'][sha(data)]=data
                contract['category_rule']['label_review_sha256']=sha(data)
            with self.assertRaises(InvalidSelectedEntity):
                SelectedEntityView(raw,json.dumps(contract).encode(),allow_profile4=True,**args)

    def test_export_explicit_verified_stopped_accepts_no_recovered_prefix(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from selected_entity_view import export_verified
        self.setup_view()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); recording=root/'recording'; recording.mkdir()
            (recording/'profile.json').write_bytes(self.raw)
            (recording/'manifest.json').write_text(json.dumps(dict(profile_sha256=sha(self.raw),target=self.contract['target'])))
            verified=dict(profile_sha256=sha(self.raw),valid=True,complete=False,status='verified_stopped',
                          terminal_summary_verified=True,recoverable=False,error_code=None,
                          unverified_compressed_bytes=0,unverified_index_bytes=0,
                          samples_prefix_sha256='34'*32,index_prefix_sha256='56'*32)
            def run(result,allow_stopped,output):
                with patch('export_relations.acquisition_provenance',return_value=self.kwargs['source']['acquisition']), \
                     patch('export_relations.native_verify',return_value=result) as native, \
                     patch('export_relations.iter_validated_frames',return_value=iter([(self.frame,dict(skipped_slots=0))])):
                    export_verified(recording,root/'acquisition',output,['verifier'],json.dumps(self.contract).encode(),
                                    artifacts=self.kwargs['artifacts'],allow_stopped=allow_stopped)
                    self.assertEqual(native.call_args.args[-1],allow_stopped)
            with self.assertRaises(InvalidSelectedEntity): run(verified,False,root/'rejected')
            run(verified,True,root/'accepted')
            row=json.loads((root/'accepted').read_text())
            self.assertFalse(row['recording_status']['complete']); self.assertTrue(row['recording_status']['accepted_stopped'])
            for key,value in [('valid',False),('status','recoverable_prefix'),('terminal_summary_verified',False),
                              ('recoverable',True),('unverified_compressed_bytes',1),('unverified_index_bytes',1)]:
                bad=copy.deepcopy(verified); bad[key]=value
                with self.assertRaises(InvalidSelectedEntity): run(bad,True,root/'invalid')
                self.assertFalse((root/'invalid').exists())

    def test_export_uses_chunk_index_and_never_publishes_failed_prefix(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from selected_entity_view import export_verified
        v=self.setup_view()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); recording=root/'recording'; recording.mkdir()
            (recording/'profile.json').write_bytes(self.raw)
            (recording/'manifest.json').write_text(json.dumps(dict(profile_sha256=sha(self.raw),target=v.relations.target)))
            verification=dict(valid=True,complete=True,status='verified_complete',profile_sha256=sha(self.raw),
                              samples_prefix_sha256='34'*32,index_prefix_sha256='56'*32)
            def broken(*args):
                self.assertEqual(args[1],recording/'chunks.jsonl')
                yield self.frame,dict(skipped_slots=0)
                raise ValueError('verified_prefix_changed')
            with patch('export_relations.acquisition_provenance',return_value=self.kwargs['source']['acquisition']), \
                 patch('export_relations.native_verify',return_value=verification), \
                 patch('export_relations.iter_validated_frames',side_effect=broken):
                output=root/'out.jsonl'
                with self.assertRaisesRegex(ValueError,'verified_prefix_changed'):
                    export_verified(recording,root/'acquisition',output,['verifier'],json.dumps(self.contract).encode(),
                                    artifacts=self.kwargs['artifacts'])
                self.assertFalse(output.exists())
                self.assertEqual(list(root.iterdir()),[recording])

if __name__ == '__main__': unittest.main()
