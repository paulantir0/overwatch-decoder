"""Owned synthetic storage tests; no game/build/offset semantics."""
import copy
import json
import unittest
from selected_entity_view import SelectedEntityView, InvalidSelectedEntity, sha
from test_selected_entity_view import relative_fixture
from run_selected_live import Projectors, compact, raw
from overwatch_decoder.session_observations import normalize


def fixture():
    pb,c,frame,kwargs=relative_fixture(labels=False)
    p=json.loads(pb);b=c['bindings'][0];name='fixture_raw_quaternion_candidate'
    position=next(f for f in p['fields'] if f['name']==b['fields']['position'])
    field=copy.deepcopy(position);field.update(name=name,type='f32x4',address=position['address']+2048)
    p['fields'].append(field);pb=json.dumps(p).encode();c['profile_sha256']=sha(pb)
    kwargs['source']['profile_sha256']=sha(pb);frame['profile_sha256']=sha(pb)
    review=dict(schema='overwatch-decoder.selected-raw-quaternion-review/1',reviewed=True,target=p['target'],
        profile_sha256=sha(pb),source=c['source'],position_declaration=position,quaternion_declaration=field,
        identity_fields={k:b['fields'][k] for k in ('controller_handle','controller_key','ref_first','ref_third','body_handle','body_key')},
        semantics='raw_owned_component_four_float_candidate')
    data=json.dumps(review).encode();kwargs['artifacts'][sha(data)]=data
    b['raw_quaternion_candidate']=dict(field=name,review_sha256=sha(data))
    frame['fields'][name]=dict(copy.deepcopy(frame['fields'][position['name']]),type='f32x4',value=[0.,0.6,0.,0.8])
    return pb,c,frame,kwargs


def project(pb,c,frame,kwargs):
    return SelectedEntityView(pb,json.dumps(c).encode(),allow_profile4=True,**kwargs).project(frame)


class QuaternionTests(unittest.TestCase):
    def test_enabled_transport_and_legacy_stripped_parity(self):
        pb,c,f,k=fixture(); result=project(pb,c,f,k);q=result['entities'][0]['raw_quaternion_candidate']
        self.assertEqual(q['validation_status'],'raw_orientation_candidate');self.assertEqual(q['reads'][0]['field'],'fixture_raw_quaternion_candidate')
        old=copy.deepcopy(c);old['bindings'][0].pop('raw_quaternion_candidate')
        expected=project(pb,old,f,k);stripped=copy.deepcopy(result);stripped['contract_sha256']=expected['contract_sha256']
        stripped['entities'][0].pop('raw_quaternion_candidate');self.assertEqual(stripped,expected)
        result.update(session_id='fixture',segment=1,event_sequence=1)
        compacted=compact(result,'ab'*32);normalized=normalize(compacted)
        self.assertEqual(normalized['entities'][0]['raw_quaternion_candidate']['value'],q['value'])
        self.assertEqual(normalized['entities'][0]['field_evidence']['raw_quaternion_candidate']['reads'][0]['read_start_ticks'],str(q['reads'][0]['read_start_ticks']))

    def test_missing_malformed_stale_and_bad_guard_do_not_poison_other_fields(self):
        pb,c,f,k=fixture();name=c['bindings'][0]['raw_quaternion_candidate']['field'];good=project(pb,c,f,k)['entities'][0]
        mutations=[lambda a:a['fields'].pop(name),lambda a:a['fields'][name].update(value=[0,0,0,0]),
            lambda a:a['fields'][name].update(value=[0,False,0,1]),lambda a:a['fields'][name].update(value=[0,0,1]),
            lambda a:a['fields'][name].update(value=[0,float('nan'),0,1]),
            lambda a:a['fields'][name].update(guard_ids=[]),lambda a:a['fields'][name].update(read_address_hex='ffffffffffffffff'),lambda a:a['fields'][name].update(read_start_ticks=a['end_ticks']+1),
            lambda a:a['fields'][name].update(status='unknown'),lambda a:a['fields'][name].update(type='f32x3')]
        for mutate in mutations:
            bad=copy.deepcopy(f);mutate(bad);row=project(pb,c,bad,k)['entities'][0]
            with self.subTest(mutation=mutate):
                self.assertIsNone(row['raw_quaternion_candidate']['value'])
                for field in ('position','health','hero','relation'):self.assertEqual(row[field],good[field])
        for mutate in (lambda a:a.update(profile_sha256='ff'*32),lambda a:a.update(skipped_intervals_before=1)):
            bad=copy.deepcopy(f);mutate(bad);self.assertIsNone(project(pb,c,bad,k)['entities'][0]['raw_quaternion_candidate']['value'])

    def test_pin_declaration_identity_and_guard_rejections(self):
        pb,c,f,k=fixture();name=c['bindings'][0]['raw_quaternion_candidate']['field']
        bad=copy.deepcopy(k);bad['artifacts']={}
        with self.assertRaises(InvalidSelectedEntity):project(pb,c,f,bad)
        for field,value in [('profile_sha256','ff'*32),('target',{}),('source',{}),('identity_fields',{}),('position_declaration',{})]:
            badc=copy.deepcopy(c);badk=copy.deepcopy(k);pin=badc['bindings'][0]['raw_quaternion_candidate']['review_sha256']
            review=json.loads(badk['artifacts'][pin]);review[field]=value;data=json.dumps(review).encode()
            badk['artifacts'][sha(data)]=data;badc['bindings'][0]['raw_quaternion_candidate']['review_sha256']=sha(data)
            with self.subTest(field=field),self.assertRaises(InvalidSelectedEntity):project(pb,badc,f,badk)
        p=json.loads(pb);next(d for d in p['fields'] if d['name']==name)['guards']=[]
        badpb=json.dumps(p).encode();c['profile_sha256']=sha(badpb);k['source']['profile_sha256']=sha(badpb)
        with self.assertRaisesRegex(InvalidSelectedEntity,'unsupported_field_declaration|quaternion_position_dependencies'):project(badpb,c,f,k)

    def test_duplicate_identity_clears_candidate(self):
        pb,c,f,k=fixture();other=copy.deepcopy(c['bindings'][0]);other['binding_id']='duplicate';c['bindings'].append(other)
        self.assertTrue(all(r['raw_quaternion_candidate']['value'] is None for r in project(pb,c,f,k)['entities']))

    def test_runner_requires_recipe_route_and_build_pin(self):
        pb,c,f,k=fixture();p=json.loads(pb);binding=c['bindings'][0];name=binding['raw_quaternion_candidate']['field']
        x=Projectors.__new__(Projectors);x.artifacts=dict(k['artifacts'])
        route=dict(schema='overwatch-decoder.selected-raw-quaternion-recipe-review/1',reviewed=True,
            build_sha256=p['target']['executable_sha256'],recipe_sha256=c['source']['recipe_sha256'],
            semantics='raw_owned_component_four_float_candidate',position_suffix=binding['fields']['position'],
            quaternion_suffix=name,relative_address_bytes=2048)
        data=raw(route);x.artifacts[sha(data)]=data;x.meta={'raw_quaternion_review_sha256':sha(data)}
        binding['raw_quaternion_candidate']=x.quaternion_binding(pb,c['source'],binding,name)
        k['artifacts']=x.artifacts;self.assertIsNotNone(project(pb,c,f,k)['entities'][0]['raw_quaternion_candidate']['value'])
        for key in ('build_sha256','recipe_sha256'):
            bad=dict(route);bad[key]='ff'*32;data=raw(bad);x.artifacts[sha(data)]=data;x.meta['raw_quaternion_review_sha256']=sha(data)
            with self.assertRaisesRegex(ValueError,'quaternion_recipe_review_scope'):x.quaternion_binding(pb,c['source'],binding,name)

    def test_normalizer_rejects_bad_candidate_only(self):
        pb,c,f,k=fixture();result=project(pb,c,f,k);result.update(session_id='fixture',segment=1,event_sequence=1)
        row=compact(result,'ab'*32)
        def evidence(a):return a['entities'][0]['field_evidence']['raw_quaternion_candidate']
        for mutate in (lambda a:evidence(a).update(profile_sha256='ff'*32),
                       lambda a:evidence(a).update(observed_build_sha256='ff'*32),
                       lambda a:evidence(a).update(review_sha256=None),
                       lambda a:evidence(a)['reads'][0].update(read_end_ticks=a['timestamp']['end_ticks']+1),
                       lambda a:a['entities'][0].update(raw_quaternion_candidate_validation='unknown')):
            bad=copy.deepcopy(row);mutate(bad);n=normalize(bad)['entities'][0]
            self.assertIsNone(n['raw_quaternion_candidate']['value']);self.assertEqual(n['position']['value'],row['entities'][0]['position'])
