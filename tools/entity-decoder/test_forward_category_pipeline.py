"""Optional native forward categories through real composition/live/epoch paths."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_forward_owner_categories import category_fixture
from test_forward_owner_relations import raw,sha
from test_live_relations import SESSION,start,live,next_frame
from forward_owner_relations import GuardedForwardOwners
from forward_owner_categories import GuardedForwardOwnerCategories
from forward_owner_projection import ForwardOwnerProjection
from live_relations import LiveRelations
from runtime_producer import forward_adapter_options,validate_config
from test_runtime_hero_assets import configuration


def fixture(root, mutate=None):
    def extra(p,v):
        name='controller_0000_aux_0000_position_candidate'
        p['fields'].append(dict(name=name,type='f32x3',address=0xA000));v[name]=[1.,2.,3.]
        if mutate:mutate(p,v)
    pr,fr,cr,artifacts,frame=category_fixture(extra)
    profile=json.loads(pr);fc=json.loads(fr);cc=json.loads(cr);paths={}
    for h,b in artifacts.items():(root/h).write_bytes(b);paths[h]=h
    for name,h in [('manifest.json',fc['acquisition_manifest_sha256']),('recipe.json',fc['source']['recipe_sha256']),
                   ('evidence.jsonl',fc['source']['evidence_sha256']),('bindings.json',fc['binding_template_sha256'])]:
        (root/name).write_bytes(artifacts[h])
    (root/'profile.json').write_bytes(pr);(root/'forward.json').write_bytes(fr);(root/'category.json').write_bytes(cr)
    (root/'artifacts.json').write_bytes(raw(paths))
    for f in profile['fields']:frame['fields'][f['name']].update(type=f['type'],reason=None)
    frame.update(interpretation='profile_declared_research',visibility='research',runtime_semantics_validated=False,
        public_state_eligible=False,atomic=False,scheduled_slot=0,scheduled_ticks=0,jitter_ticks=10,
        skipped_intervals_before=0,skipped_intervals_total=0,utc_origin_before_ticks=0,
        requested_interval_ms=100,scheduler_backend='synthetic',hard_realtime=False)
    opts=dict(forward_owner_contract=root/'forward.json',forward_owner_artifacts=root/'artifacts.json',
              forward_owner_category_contract=root/'category.json',forward_owner_category_artifacts=root/'artifacts.json')
    bindings=copy.deepcopy(cc['bindings'])
    for b in bindings:
        b.pop('required_guard_ids')
        for q in b['conditions']:q['field_relative']=dict(field='category_low',offset=q.pop('address')-0x9020)
    template=dict(schema='overwatch-decoder.forward-owner-category-template/1',build_sha256=fc['build_sha256'],
        recipe_sha256=fc['source']['recipe_sha256'],native_review_sha256=cc['native_review_sha256'],bindings=bindings)
    (root/'category-template.json').write_bytes(raw(template))
    config=dict(recipe=str(root/'recipe.json'),forward_owner_bindings=str(root/'bindings.json'),
        forward_owner_bindings_sha256=sha((root/'bindings.json').read_bytes()),
        forward_owner_category_template=str(root/'category-template.json'),
        forward_owner_category_template_sha256=sha(raw(template)),
        forward_owner_category_artifacts=str(root/'artifacts.json'),
        forward_owner_category_artifacts_sha256=sha((root/'artifacts.json').read_bytes()))
    return pr,fr,cr,artifacts,frame,opts,config


class ForwardCategoryPipeline(unittest.TestCase):
    def test_real_live_options_and_default_output_parity(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);pr,fr,cr,a,f,opts,_=fixture(root);p=json.loads(pr);m=json.loads((root/'manifest.json').read_bytes())
            enriched=LiveRelations(root,SESSION,1,**opts)
            plain=LiveRelations(root,SESSION,1,**{k:v for k,v in opts.items()if 'category'not in k})
            for adapter in [enriched,plain]:adapter.consume(raw(start(p,m)))
            x=enriched.consume(raw(live(f)));y=plain.consume(raw(live(f)));z=x['forward_owner_projection'];row=z['relations'][0]
            self.assertEqual(row['raw_category_candidate'],0);self.assertEqual(row['position_candidate']['value'],[1.,2.,3.])
            self.assertEqual(row['raw_category_evidence']['algorithm']['ordered_bits'],[3,7,11])
            self.assertTrue(z.pop('forward_category_output_enabled'))
            z.pop('forward_category_contract_sha256');z.pop('forward_category_native_review_sha256')
            for name in ['raw_category_candidate','raw_flags_candidate','raw_category_evidence','raw_category_reason']:row.pop(name)
            self.assertEqual(raw(x),raw(y))
            f=next_frame(f,missed=1);event=live(f,2);event['emitted_ticks']=400
            row=enriched.consume(raw(event))['forward_owner_projection']['relations'][0]
            self.assertIsNone(row['raw_category_candidate']);self.assertIsNone(row['raw_category_evidence'])

    def test_independent_category_failure_preserves_position(self):
        with tempfile.TemporaryDirectory()as t:
            pr,fr,cr,a,f,_,_=fixture(Path(t));fw=GuardedForwardOwners(pr,fr,a);cp=GuardedForwardOwnerCategories(pr,fr,cr,a)
            dec=ForwardOwnerProjection(fw,category_projector=cp);src=dict(profile_sha256=sha(pr),acquisition=dict(fw.source,manifest_sha256=fw.manifest_hash))
            f['fields']['category_low']['status']='unknown'
            row=dec.project(f,src)['relations'][0]
            self.assertIsNone(row['raw_category_candidate']);self.assertIsNotNone(row['position_candidate'])

    def test_spoofed_join_source_and_duplicate_rows_fail_closed(self):
        with tempfile.TemporaryDirectory()as t:
            pr,fr,cr,a,f,_,_=fixture(Path(t));fw=GuardedForwardOwners(pr,fr,a);cp=GuardedForwardOwnerCategories(pr,fr,cr,a)
            dec=ForwardOwnerProjection(fw,category_projector=cp);src=dict(profile_sha256=sha(pr),acquisition=dict(fw.source,manifest_sha256=fw.manifest_hash));original=cp.project(f)
            for mode in ['owner','controller','binding','duplicate','time','source','contract']:
                changed=copy.deepcopy(original)
                if mode in ('owner','controller'):changed['rows'][0][mode+'_object_key' if mode=='controller'else'forward_owner_object_key']='wrong'
                if mode=='binding':changed['rows'][0]['binding_id']='wrong'
                if mode=='duplicate':changed['rows']*=2
                if mode=='time':changed['timing']['start_ticks']+=1
                if mode=='source':changed['source_evidence']['evidence_sha256']='00'*32
                if mode=='contract':changed['contract_sha256']='00'*32
                with self.subTest(mode=mode),patch.object(cp,'project',return_value=changed):
                    if mode in ('time','source','contract'):
                        with self.assertRaises(ValueError):dec.project(f,src)
                    else:self.assertIsNone(dec.project(f,src)['relations'][0]['raw_category_candidate'])

    def test_runtime_fresh_materialization_and_template_tamper(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);pr,fr,cr,a,f,_,config=fixture(root);epoch=root/'epoch';epoch.mkdir()
            opts=forward_adapter_options(config,root,epoch)
            c=json.loads(Path(opts['forward_owner_category_contract']).read_bytes())
            self.assertEqual(c['profile_sha256'],sha(pr));self.assertEqual(c['forward_contract_sha256'],sha(fr))
            self.assertEqual(c['bindings'][0]['conditions'][0]['address'],0x9000)
            adapter=LiveRelations(root,SESSION,1,**opts);adapter.consume(raw(start(json.loads(pr),json.loads((root/'manifest.json').read_bytes()))))
            self.assertEqual(adapter.consume(raw(live(f)))['forward_owner_projection']['relations'][0]['raw_category_candidate'],0)
            (root/'category-template.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError,'input_changed'):forward_adapter_options(config,root,epoch)

    def test_runtime_startup_rejects_partial_stale_and_wrong_pins(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);base,_=configuration(root);pr,fr,cr,a,f,_,cfg=fixture(root)
            base = {k:v for k,v in base.items() if not k.startswith('hero_asset_')}
            base.update(cfg,target=json.loads(pr)['target'],recipe_sha256=json.loads(cr)['source']['recipe_sha256'])
            validate_config(base,root)
            for mode in ['missing','pin','old_epoch','missing_native_review']:
                c=copy.deepcopy(base)
                if mode=='missing':c.pop('forward_owner_category_artifacts')
                if mode=='pin':c['forward_owner_category_template_sha256']='00'*32
                if mode in ('old_epoch','missing_native_review'):
                    template=json.loads((root/'category-template.json').read_bytes())
                    if mode=='old_epoch':template['profile_sha256']='00'*32
                    else:template['native_review_sha256']='00'*32
                    path=root/(mode+'.json');path.write_bytes(raw(template));c['forward_owner_category_template']=str(path);c['forward_owner_category_template_sha256']=sha(raw(template))
                with self.subTest(mode=mode),self.assertRaises(ValueError):validate_config(c,root)

    def test_live_requires_complete_optional_pair_and_owner(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);_,_,_,_,_,opts,_=fixture(root)
            for missing in ['forward_owner_category_artifacts','forward_owner_contract','forward_owner_artifacts']:
                bad=opts.copy();bad.pop(missing)
                with self.subTest(missing=missing),self.assertRaises(ValueError):LiveRelations(root,SESSION,1,**bad)

    def test_new_acquisition_materializes_fresh_contract_not_old_owner(self):
        from test_relations import change_word
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);one=root/'one';two=root/'two';one.mkdir();two.mkdir()
            _,_,_,_,_,_,c1=fixture(one)
            def mutate(p,v):
                change_word(p,v,2,0x80000099);change_word(p,v,3,0x80000098);change_word(p,v,4,0x80000099)
            _,_,_,_,_,_,c2=fixture(two,mutate)
            for d in [one,two]:(d/'epoch').mkdir()
            a=forward_adapter_options(c1,one,one/'epoch');b=forward_adapter_options(c2,two,two/'epoch')
            ca=json.loads(a['forward_owner_category_contract'].read_bytes());cb=json.loads(b['forward_owner_category_contract'].read_bytes())
            self.assertNotEqual(ca['profile_sha256'],cb['profile_sha256'])
            self.assertNotEqual(ca['forward_contract_sha256'],cb['forward_contract_sha256'])
            b['forward_owner_category_contract']=a['forward_owner_category_contract']
            with self.assertRaises(ValueError):LiveRelations(two,SESSION,1,**b)

    def test_missing_condition_bytes_or_source_read_never_publish_contract(self):
        for mode in ['field','source']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as t:
                root=Path(t);_,_,_,_,_,_,c=fixture(root);epoch=root/'epoch';epoch.mkdir()
                path=root/'category-template.json';template=json.loads(path.read_bytes());q=template['bindings'][0]['conditions'][0]
                if mode=='field':q['field_relative']['offset']+=1
                else:
                    q.pop('field_relative');q['source_read']=dict(stage='not-recorded',requested_bytes=8,ordinal=0,expected_matches=1)
                path.write_bytes(raw(template));c['forward_owner_category_template_sha256']=sha(raw(template))
                with self.assertRaises(ValueError):forward_adapter_options(c,root,epoch)
                self.assertFalse((epoch/'forward-category-contract.json').exists())


if __name__=='__main__':unittest.main()
