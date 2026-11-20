"""Explicit acquisition-empty local context; synthetic provenance fixtures only."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from relations import GuardedRelations
from selected_entity_view import SelectedEntityView,LOCAL_REFERENCE_WORDS,sha
from test_selected_entity_view import relative_fixture,serial_guards
from test_relations import prepare

def raw(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()

def fixture(local_key=30, reference_block=False):
    original,c,old,kw=relative_fixture(local_key=local_key,labels=False,split_identities=True)
    p=json.loads(original);local=c['local_context']['fields']
    absent={local[k] for k in ('body_handle','body_key','flags_low','flags_high')}
    p['fields']=[d for d in p['fields'] if d['name'] not in absent]
    for role in ('body_handle','body_key','flags_low','flags_high'):local[role]='local_body_0000_'+role
    if reference_block:
        first=next(d for d in p['fields'] if d['name']==local['ref_first'])
        third=next(d for d in p['fields'] if d['name']==local['ref_third'])
        third['address']=first['address']+8
        guard=dict(address=first['address'],bytes_hex=(local_key.to_bytes(4,'little')+bytes(4)+local_key.to_bytes(4,'little')).hex())
        first['guards']=[copy.deepcopy(guard)];third['guards']=[copy.deepcopy(guard)]
    values={d['name']:old['fields'][d['name']]['value'] for d in p['fields']}
    p['schema']='overwatch-decoder.field-profile/1';_,frame=prepare(p,values)
    p['schema']='overwatch-decoder.field-profile/4';pr=raw(p);frame.update(profile_sha256=sha(pr),schema='overwatch-decoder.field-stream/4')
    serial_guards(p,frame)
    for name in values:frame['fields'][name]['type']=next(d['type'] for d in p['fields'] if d['name']==name)
    sample=copy.deepcopy(old['fields']['sum']);sample['guard_ids']=frame['fields']['sum']['guard_ids'];frame['fields']['sum']=sample
    recipe=dict(schema='overwatch-decoder.acquisition-recipe/1',target={k:p['target'][k] for k in ('image_name','architecture','executable_sha256')},
      stages=[dict(name='fixture')],field_collections=[dict(rows='local_bodies',prefix='local_body',allow_empty=True,
      fields=[dict(name=role,type='i32',address=1) for role in ('body_handle','body_key','flags_low','flags_high')])])
    c.update(profile_sha256=sha(pr));c['local_context']['acquisition_empty']=True
    r=GuardedRelations(pr,allow_profile4=True)
    events=[dict(schema='overwatch-decoder.acquisition-evidence/1',kind='start',source_kind='native_process_memory',target=p['target'],recipe_sha256=sha(raw(recipe)),revision='synthetic_fixture')]
    for i,g in enumerate(r.guards):
      width=len(bytes.fromhex(g['bytes_hex']))
      for j in range(2):events.append(dict(kind='read',id=2*i+j,attempted=True,error=None,address=g['address'],requested_bytes=width,returned_bytes=width,bytes_hex=g['bytes_hex'],read_start_ticks=2*j,read_end_ticks=2*j+1))
      events.append(dict(kind='guard_check',stage='final_guard_check',matches=True,expected_read_id=2*i,actual_read_id=2*i+1,expected_offset=0))
    events += [dict(kind='field_collection',stage='field_collection_output',rows='local_bodies',prefix='local_body',depth=1,allow_empty=True,first_field=5,retained_rows=0,expanded_fields=0,identity='ordinal_within_acquisition_only'),dict(kind='profile_validated',profile_sha256=sha(pr),fields=len(p['fields']))]
    def pin(recipe,events):
      rr=raw(recipe);events[0]['recipe_sha256']=sha(rr);er=b''.join(raw(e) for e in events)
      mr=raw(dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,revision='synthetic_fixture',target=p['target'],profile_sha256=sha(pr),recipe_sha256=sha(rr),evidence_sha256=sha(er),stages_completed=1))
      pins=dict(manifest_sha256=sha(mr),recipe_sha256=sha(rr),evidence_sha256=sha(er))
      event=next(e for e in events if e['kind']=='field_collection')
      review=raw(dict(schema='overwatch-decoder.selected-empty-local-review/1',reviewed=True,target=p['target'],profile_sha256=sha(pr),source=pins,collection=dict(rows='local_bodies',prefix='local_body',event_sha256=sha(raw(event)))))
      c['source']=pins;c['local_context']['empty_review_sha256']=sha(review);kw['source']=dict(profile_sha256=sha(pr),acquisition=pins)
      kw['artifacts'].update({sha(x):x for x in (rr,er,mr,review)})
    pin(recipe,events)
    return pr,c,frame,kw,recipe,events,pin

def view(f):return SelectedEntityView(f[0],raw(f[1]),allow_profile4=True,**f[3])

class OptionalLocalTests(unittest.TestCase):
 def test_other_actor_values_survive_but_relative_identity_is_unknown(self):
    f=fixture();o=view(f).project(f[2]);row=o['entities'][0]
    self.assertIsNotNone(row['controller_id']);self.assertIsNotNone(row['entity_id']);self.assertEqual(row['position']['value'],[1.,2.,3.]);self.assertEqual(row['health']['value'],7.)
    self.assertIsNone(row['is_local']);self.assertIsNone(row['relation']['value']);self.assertEqual(row['relation']['reason'],'local_body_not_acquired')
    self.assertEqual(o['local_context_status']['current_body_presence'],'unknown');self.assertTrue(o['local_context_status']['requires_fresh_acquisition'])
    from run_selected_live import compact
    o.update(session_id='ab'*16,segment=1,event_sequence=1)
    self.assertEqual(compact(o,'ab'*32)['local_context_status'],o['local_context_status'])
 def test_equal_zero_references_only_preserve_independent_actor_values(self):
    f=fixture(local_key=0,reference_block=True);v=view(f);out=v.project(f[2]);e=out['entities'][0]
    self.assertEqual(e['health']['value'],7.);self.assertEqual(e['position']['value'],[1.,2.,3.])
    self.assertIsNotNone(e['entity_id']);self.assertIsNone(e['is_local']);self.assertIsNone(e['relation']['value'])
    self.assertEqual(out['local_context_status']['reason'],'local_body_not_acquired')
    self.assertTrue(out['local_context_status']['requires_fresh_acquisition'])
    name=f[1]['local_context']['fields']['ref_first'];gid=v.relations.guard_ids[name][0]
    self.assertEqual(len(bytes.fromhex(v.relations.guards[gid]['bytes_hex'])),12)
    for phase in ('before','after'):
      frame=copy.deepcopy(f[2]);frame['guards_'+phase][gid]['ok']=False
      changed=v.project(frame)
      self.assertNotEqual(changed['local_context_status']['reason'],'local_body_not_acquired')
      self.assertEqual(changed['entities'][0]['health']['value'],7.)
    frame=copy.deepcopy(f[2]);frame['fields'][f[1]['local_context']['fields']['ref_third']]['value']=1
    self.assertNotEqual(v.project(frame)['local_context_status']['reason'],'local_body_not_acquired')
    f[1]['local_context'].pop('acquisition_empty')
    with self.assertRaises(ValueError):view(f)

 def test_current_controller_words_and_guards_are_rechecked(self):
    f=fixture();v=view(f)
    for mode in ('selector','guard','gap','target','profile','reference'):
      frame=copy.deepcopy(f[2])
      if mode in ('selector','reference'):
        name=f[1]['local_context']['fields']['selector' if mode=='selector' else 'ref_first'];frame['fields'][name]['status']='unknown'
      if mode=='guard':
        gid=v.relations.guard_ids[f[1]['local_context']['fields']['controller_key']][0];frame['guards_after'][gid]['ok']=False
      if mode=='gap':frame['skipped_intervals_before']=1
      if mode=='target':frame['target']['pid']+=1
      if mode=='profile':frame['profile_sha256']='ff'*32
      o=v.project(frame);self.assertNotEqual(o['local_context_status']['reason'],'local_body_not_acquired')
      if mode in ('target','profile','gap'):self.assertIsNone(o['entities'][0]['health']['value'])
      else:self.assertEqual(o['entities'][0]['health']['value'],7.)
 def test_new_epoch_needed_no_cross_profile_carry(self):
    absent=fixture();present=relative_fixture(labels=False,split_identities=True)
    a=view(absent);p=SelectedEntityView(present[0],raw(present[1]),allow_profile4=True,**present[3])
    self.assertEqual(p.project(present[2])['entities'][0]['relation']['value'],'different_group')
    self.assertEqual(a.project(absent[2])['entities'][0]['relation']['reason'],'local_body_not_acquired')
    self.assertTrue(all(e['entity_id'] is None for e in a.project(present[2])['entities']))
    self.assertTrue(all(e['entity_id'] is None for e in p.project(absent[2])['entities']))
    self.assertEqual(p.project(present[2])['entities'][0]['health']['value'],7.)
 def test_no_implicit_optin_and_no_partial_payload(self):
    f=fixture();f[1]['local_context'].pop('acquisition_empty')
    with self.assertRaises(ValueError):view(f)
    f=fixture();p=json.loads(f[0]);p['fields'].append(dict(name=f[1]['local_context']['fields']['body_key'],type='i32',address=60000))
    pr=raw(p);f[1]['profile_sha256']=sha(pr);f[3]['source']['profile_sha256']=sha(pr)
    with self.assertRaisesRegex(ValueError,'empty_local_payload_declared'):SelectedEntityView(pr,raw(f[1]),allow_profile4=True,**f[3])
 def test_proof_rejects_wrong_source_collection_and_missing_guards(self):
    for mode in ('nonempty','expanded','depth','identity','wrong_collection_fields','not_optional','provided_source','missing_guards','duplicate_event'):
      with self.subTest(mode=mode):
        f=fixture();recipe,events,pin=f[4:];event=next(e for e in events if e['kind']=='field_collection')
        if mode=='nonempty':event['retained_rows']=1
        if mode=='expanded':event['expanded_fields']=1
        if mode=='depth':event['depth']=2
        if mode=='identity':event['identity']='other'
        if mode=='wrong_collection_fields':recipe['field_collections'][0]['fields'][0]['name']='unrelated'
        if mode=='not_optional':recipe['field_collections'][0]['allow_empty']=False
        if mode=='provided_source':events[0]['source_kind']='provided_memory_source'
        if mode=='missing_guards':events[:]=[e for e in events if e['kind']!='guard_check']
        if mode=='duplicate_event':events.append(copy.deepcopy(event))
        pin(recipe,events)
        with self.assertRaises(ValueError):view(f)
 def test_partial_profile_and_stale_review_rejected(self):
    for mode in ('missing_selector','stale_review','tampered_evidence'):
      f=fixture()
      if mode=='missing_selector':f[1]['local_context']['fields']['selector']='missing'
      if mode=='stale_review':f[1]['local_context']['empty_review_sha256']='ff'*32
      if mode=='tampered_evidence':f[3]['artifacts'][f[1]['source']['evidence_sha256']]+=b'\n'
      with self.assertRaises(ValueError):view(f)
 def test_runner_admission_requires_explicit_option_and_original_empty_event(self):
    import run_selected_live as runner
    from test_hero_asset_labels import fixture as asset_fixture
    f=fixture();pr,c,frame,kw=f[:4];_,_,catalog,assets,_=asset_fixture();artifacts=dict(kw['artifacts'],**assets)
    calibration=b'synthetic calibration';calpin=sha(calibration);artifacts[calpin]=calibration
    template=dict(schema='overwatch-decoder.selected-runner-template/1',local_validation_status='fixture',binding_validation_status='fixture',health_validation_status='fixture',category_rule=dict(c['category_rule'],same_group_label='ally',different_group_label='enemy'))
    template['category_rule'].pop('review_sha256')
    with tempfile.TemporaryDirectory() as d:
      root=Path(d);private=root/'private';(private/'recipes').mkdir(parents=True);(private/'artifacts').mkdir();(root/'config.json').write_bytes(raw(dict(batches=['00'])))
      for pin,data in artifacts.items():(private/'artifacts'/f'{pin}.bin').write_bytes(data)
      (private/'catalog.json').write_bytes(raw(catalog));(private/'selected-template.json').write_bytes(raw(template))
      for name,pin in [('selected-review',c['bindings'][0]['review_sha256']),('native-review',c['category_rule']['review_sha256']),('practice-calibration',calpin)]: (private/(name+'.sha256')).write_text(pin)
      (private/'recipes/batch00.json').write_bytes(artifacts[c['source']['recipe_sha256']])
      meta=dict(local_context=c['local_context']['fields'],actors=[dict(c['bindings'][0]['fields'],ordinal_within_profile_only=0,health_sum='sum')],allow_empty_local_context=True,local_empty_collection=dict(rows='local_bodies',prefix='local_body'))
      mp=private/'recipes/batch00.bindings.json';mp.write_bytes(raw(meta));acq=root/'acquisition';acq.mkdir();(acq/'profile.json').write_bytes(pr)
      for fn,k in [('manifest.json','manifest_sha256'),('evidence.jsonl','evidence_sha256')]: (acq/fn).write_bytes(artifacts[c['source'][k]])
      with patch.object(runner,'BASE',root):
        builder=runner.Projectors('00',acq,root/'out');contract,_=builder.contract(acq);cc=json.loads(contract)
        v=SelectedEntityView(pr,contract,source=dict(profile_sha256=sha(pr),acquisition=cc['source']),artifacts=builder.artifacts,allow_profile4=True)
        self.assertEqual(v.project(frame)['entities'][0]['health']['value'],7.)
        meta['allow_empty_local_context']=False;mp.write_bytes(raw(meta))
        with self.assertRaisesRegex(ValueError,'empty_local_not_configured'):runner.Projectors('00',acq,root/'out').contract(acq)
if __name__=='__main__':unittest.main()
