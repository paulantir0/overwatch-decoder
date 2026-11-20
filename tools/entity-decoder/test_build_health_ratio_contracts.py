"""Synthetic local acquisition mechanics, never new runtime/game validation."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from build_health_ratio_contracts import build_contracts, validate_layout
from build_health_contracts import build_contracts as build_health
from health_ratio_validation import load_ratio_contract
from runtime_producer import build_present_health_contracts
from test_relations import fixture


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class Saved:
    def __init__(self, root, *, actors=1, bodyless=False, width=3, relocate=0, epoch=0):
        self.root=root; root.mkdir()
        self.profile,_=fixture(rows=actors)
        self.profile['target'].update(pid=7+epoch, creation_file_time=100+epoch)
        self.recipe=dict(schema='overwatch-decoder.acquisition-recipe/1',
            target={k:self.profile['target'][k]for k in ('image_name','executable_sha256','architecture')},
            stages=[dict(name='fixture_pool_extent',steps=[])])
        self.extents=[];self.prefixes=[]
        for actor in range(actors):
            prefix=f'controller_{actor:04d}_body_0000_';self.prefixes.append(prefix)
            if bodyless:
                self.profile['fields']=[f for f in self.profile['fields']if not f['name'].startswith(prefix)]
                continue
            base=0x8000+actor*0x1000;data=bytearray(72)
            for i in range(3):
                occupied=i!=1;struct.pack_into('<Ifff',data,24*i,i+1 if occupied else 0,210.,200.,100.-i)
                self.profile['guards'].append(dict(address=base+24*i,bytes_hex=data[24*i:24*i+4].hex()))
                if occupied:
                    self.profile['fields'].extend([
                        dict(name=prefix+f'pool_{i:04d}_direct_candidate',type='f32',address=base+24*i+12),
                        dict(name=prefix+f'pool_{i:04d}_scalars_candidate',type='f32x'+str(width),address=base+24*i+4)])
            self.extents.append((base,bytes(data)))
        if relocate:
            for f in self.profile['fields']:f['address']+=relocate
            for g in self.profile['guards']:g['address']+=relocate
            self.extents=[(at+relocate,b)for at,b in self.extents]
        self.health_layout=dict(schema='overwatch-decoder.health-layout/1',
            executable_sha256=self.profile['target']['executable_sha256'],recipe_sha256=sha(raw(self.recipe)),
            extent_size=72,read_stage='fixture_pool_extent',slot_count=3,slot_stride=24,
            membership_offset=0,scalar_offset=12,actor_prefixes=self.prefixes,scalar_field_suffix='_direct_candidate')
        self.layout=dict(schema='overwatch-decoder.health-ratio-layout/1',
            executable_sha256=self.profile['target']['executable_sha256'],recipe_sha256=sha(raw(self.recipe)),
            paired_field_suffix='scalars_candidate',numerator_component=2,denominator_component=1,
            denominator_offset_from_current=-4,vector_type='f32x'+str(width))
        self.review=raw(dict(build_sha256=self.profile['target']['executable_sha256'],synthetic_mechanics_only=True))
        self.extra=[];self.persist()

    def persist(self):
        recipe,profile=raw(self.recipe),raw(self.profile)
        events=[dict(schema='overwatch-decoder.acquisition-evidence/1',kind='start',target=self.profile['target'],
            recipe_sha256=sha(recipe),revision='fixture',source_kind='native_process_memory',
            monotonic_origin_ticks=0,monotonic_frequency=1000)]
        guards=[]
        for g in self.profile['guards']+sum((f.get('guards',[])for f in self.profile['fields']),[]):
            if g not in guards:guards.append(g)
        reads=[]
        def read(at,b,**extra):
            i=len(reads);reads.append(dict(kind='read',id=i,attempted=True,address=at,
                requested_bytes=len(b),returned_bytes=len(b),bytes_hex=b.hex(),error=None,
                read_start_ticks=10*i,read_end_ticks=10*i+1,**extra));return i
        original=[read(g['address'],bytes.fromhex(g['bytes_hex']))for g in guards]
        for at,b in self.extents:read(at,b,purpose='recipe',stage='fixture_pool_extent')
        checks=[]
        for i,g in zip(original,guards):
            j=read(g['address'],bytes.fromhex(g['bytes_hex']))
            checks.append(dict(kind='guard_check',stage='final_guard_check',matches=True,
                expected_read_id=i,actual_read_id=j,expected_offset=0))
        events+=reads+checks+self.extra+[dict(kind='profile_validated',profile_sha256=sha(profile),fields=len(self.profile['fields']))]
        evidence=b''.join(raw(e)for e in events)
        self.manifest=dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,target=self.profile['target'],
            profile_sha256=sha(profile),recipe_sha256=sha(recipe),evidence_sha256=sha(evidence),
            stages_completed=1,revision='fixture',fields=len(self.profile['fields']),
            guard_declarations=len(self.profile['guards'])+sum(len(f.get('guards',[]))for f in self.profile['fields']))
        for name,data in [('recipe.json',recipe),('profile.json',profile),('evidence.jsonl',evidence),('manifest.json',raw(self.manifest))]:
            (self.root/name).write_bytes(data)

    def health(self):
        return build_present_health_contracts(self.root,raw(self.health_layout),recipe_path=self.root/'recipe.json')

    def build(self, health=None):
        return build_contracts(self.root,raw(self.layout),self.review,self.health()if health is None else health)


class RatioBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def source(self,**kw):
        return Saved(self.root/('source'+str(len(list(self.root.iterdir())))),**kw)

    def test_banks_require_matching_review_and_full_membership_after_reacquisition(self):
        groups=[dict(bank_id=i,pool_indices=[i])for i in range(3)]
        for options in ({},{'relocate':0x9000,'epoch':1},{'bodyless':True}):
            s=self.source(**options);s.layout['bank_groups']=groups
            with self.assertRaises(ValueError):s.build()
            s.review=raw(dict(json.loads(s.review),bank_groups=groups))
            bundle=s.build()
            for c in bundle['contracts']:
                self.assertEqual(c['bank_groups'],groups)
                loaded=load_ratio_contract((s.root/'profile.json').read_bytes(),raw(c),s.review)
                self.assertEqual(list(loaded.bank_groups),groups)
            if options.get('bodyless'):self.assertEqual(bundle['contracts'],[])
        s=self.source();s.layout['bank_groups']=[dict(bank_id=0,pool_indices=[0,1])]
        s.review=raw(dict(json.loads(s.review),bank_groups=s.layout['bank_groups']))
        with self.assertRaises(ValueError):s.build()

    def test_fresh_complete_pairs_and_deterministic_detached_bundle(self):
        s=self.source(actors=2);health=s.health();frozen=copy.deepcopy(health);out=s.build(health)
        self.assertEqual(out,s.build(health));self.assertEqual(health,frozen)
        self.assertEqual(out['schema'],'overwatch-decoder.private.actor-health-ratio-contracts/1')
        self.assertEqual(len(out['contracts']),2);self.assertFalse(out['public_state_eligible'])
        for c in out['contracts']:
            self.assertEqual([p['pool_index']for p in c['paired_slots']],[0,2])
            loaded=load_ratio_contract((s.root/'profile.json').read_bytes(),raw(c),s.review)
            loaded.verify_source(dict(profile_sha256=out['profile_sha256'],acquisition=c['source']))
            self.assertEqual(len(loaded.storage.slots),3)
        out['contracts'][0]['health_contract']['slots'][0]['membership_u32']=9
        self.assertEqual(health,frozen)

    def test_relocation_and_new_process_use_only_new_addresses_and_pins(self):
        a=self.source();b=self.source(relocate=0x9000,epoch=1);old=a.build();new=b.build()
        self.assertNotEqual(old['profile_sha256'],new['profile_sha256'])
        self.assertEqual(new['contracts'][0]['paired_slots'][0]['denominator_address']-
            old['contracts'][0]['paired_slots'][0]['denominator_address'],0x9000)
        with self.assertRaisesRegex(ValueError,'ratio_health_bundle_source_pin'):b.build(a.health())

    def test_same_profile_new_evidence_or_recipe_requires_fresh_health(self):
        s=self.source();old=s.health();s.extra=[dict(kind='synthetic_epoch_marker')];s.persist()
        with self.assertRaisesRegex(ValueError,'ratio_health_bundle_source_pin'):s.build(old)
        self.assertNotEqual(s.build()['acquisition_evidence_sha256'],old['acquisition_evidence_sha256'])
        s.recipe['stages'][0]['name']='new';s.persist()
        with self.assertRaisesRegex(ValueError,'ratio_layout_source_pin'):s.build(old)

    def test_each_source_pin_and_review_build_is_checked(self):
        s=self.source()
        for key in ['profile_sha256','acquisition_manifest_sha256','acquisition_evidence_sha256','recipe_sha256']:
            health=s.health();health[key]='f'*64
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'ratio_health_bundle_source_pin'):s.build(health)
        s.review=raw(dict(build_sha256='f'*64))
        with self.assertRaisesRegex(ValueError,'ratio_native_review_build'):s.build()

    def test_legitimate_bodyless_bundle_clears_contracts(self):
        s=self.source(bodyless=True);h=s.health();self.assertEqual(h['contracts'],[])
        self.assertEqual(s.build(h)['contracts'],[])
        stale=self.source().health()
        with self.assertRaises(ValueError):s.build(stale)

    def test_mixed_present_and_unresolved_bodies_keeps_only_current_present_actor(self):
        s=self.source(actors=2)
        s.profile['fields']=[f for f in s.profile['fields']if not f['name'].startswith('controller_0001_body_')]
        s.extents=s.extents[:1];s.persist();h=s.health()
        self.assertEqual(h['effective_actor_prefixes'],['controller_0000_body_0000_'])
        self.assertEqual(len(s.build(h)['contracts']),1)
        h['effective_actor_prefixes'].append('controller_0001_body_0000_')
        with self.assertRaisesRegex(ValueError,'ratio_effective_actor_set_mismatch'):s.build(h)

    def test_duplicate_profile_field_or_mismatched_reciprocal_identity_rejects(self):
        for mode in ('duplicate','reciprocal'):
            s=self.source()
            if mode=='duplicate':s.profile['fields'].append(copy.deepcopy(s.profile['fields'][-1]))
            else:
                lookup=next(f for f in s.profile['fields']if f['name'].endswith('part51_0000_body_key_candidate_i32'))
                lookup['address']=next(f['address']for f in s.profile['fields']if f['name']=='controller_0000_handle_candidate_i32')
            s.persist()
            with self.subTest(mode=mode),self.assertRaises(ValueError):s.build()

    def test_omitted_present_actor_duplicate_and_partial_slots_rejected(self):
        s=self.source(actors=2)
        for mode in ('actor','duplicate','occupied','evidence','controller'):
            h=s.health()
            if mode=='actor':h['contracts'].pop()
            elif mode=='duplicate':h['contracts'][1]=copy.deepcopy(h['contracts'][0])
            elif mode=='occupied':h['contracts'][0]['slots'].pop()
            elif mode=='evidence':h['contracts'][0]['acquisition_evidence_sha256']='f'*64
            else:h['contracts'][0]['controller_prefix']='controller_0001'
            with self.subTest(mode=mode),self.assertRaises(ValueError):s.build(h)

    def test_missing_wrong_type_codec_and_address_pairs_reject(self):
        for mode in ('missing','type','codec','address'):
            s=self.source();pair=next(f for f in s.profile['fields']if f['name'].endswith('scalars_candidate'))
            if mode=='missing':s.profile['fields'].remove(pair)
            elif mode=='type':pair['type']='i32'
            elif mode=='codec':pair['codec']='invented'
            else:pair['address']+=4
            s.persist()
            with self.subTest(mode=mode),self.assertRaises(ValueError):s.build()

    def test_pair_needs_all_memberships_and_identity_dependencies(self):
        for mode in ('membership','ownership'):
            s=self.source()
            guard=s.profile['guards'].pop(-1 if mode=='membership'else 0)
            for f in s.profile['fields']:
                if not f['name'].endswith('scalars_candidate'):f.setdefault('guards',[]).append(guard)
            s.persist()
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'ratio_pair_missing_guards|ratio_pair_ownership_guards'):s.build()

    def test_f32x4_is_finite_only_supported_and_independent_forward_descriptors_ignored(self):
        s=self.source(width=4);h=s.health();h['forward_owner_contracts']=[{'independently_governed':True}]
        out=s.build(h);loaded=load_ratio_contract((s.root/'profile.json').read_bytes(),raw(out['contracts'][0]),s.review)
        self.assertEqual(loaded.paired_slots[0]['type'],'f32x4')
        self.assertNotIn('forward_owner_contracts',out)

    def test_layout_is_pure_strict_and_integer_components_only(self):
        s=self.source();self.assertEqual(validate_layout(raw(s.layout)),s.layout)
        cases=[dict(extra='unsupported'),dict(vector_type='f64'),dict(numerator_component=True),
               dict(denominator_component=2),dict(denominator_offset_from_current=4),
               dict(paired_field_suffix='../bad'),dict(recipe_sha256='wrong')]
        for edit in cases:
            with self.subTest(edit=edit),self.assertRaises(ValueError):validate_layout(raw(dict(s.layout,**edit)))
        with self.assertRaises(ValueError):validate_layout(b'{"schema":1,"schema":2}')

    def test_failed_or_missing_final_guard_not_accepted_after_rehash(self):
        for mode in ('missing','bytes'):
            s=self.source();h=s.health();p=s.root/'evidence.jsonl';events=[json.loads(x)for x in p.read_bytes().splitlines()]
            if mode=='missing':events.pop(-2)
            else:
                check=next(e for e in events if e.get('kind')=='guard_check')
                events[check['actual_read_id']+1]['bytes_hex']='ff'*8
            evidence=b''.join(raw(e)for e in events);p.write_bytes(evidence)
            s.manifest['evidence_sha256']=sha(evidence);(s.root/'manifest.json').write_bytes(raw(s.manifest))
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'unchecked_profile_guard|final_guard'):s.build(h)

    def test_explicit_recipe_path_and_cli_with_stale_cached_overwatch_decoder(self):
        s=self.source();h=s.health();recipe=s.root/'separate-recipe.json';(s.root/'recipe.json').rename(recipe)
        for name,data in [('layout.json',raw(s.layout)),('review.json',s.review),('health.json',raw(h))]:(s.root/name).write_bytes(data)
        code="""import sys,types,runpy
m=types.ModuleType('overwatch_decoder');m.__path__=['/synthetic/stale/overwatch_decoder'];sys.modules['overwatch_decoder']=m
sys.path.insert(0,sys.argv.pop(1))
runpy.run_module('build_health_ratio_contracts',run_name='__main__')
"""
        command=[sys.executable,'-I','-c',code,str(Path(__file__).parent),
            '--acquisition',str(s.root),'--recipe',str(recipe),'--layout',str(s.root/'layout.json'),
            '--native-review',str(s.root/'review.json'),'--health-bundle',str(s.root/'health.json'),
            '--out',str(s.root/'result.json')]
        result=subprocess.run(command,cwd=self.root,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        actual=json.loads((s.root/'result.json').read_bytes())
        expected=build_contracts(s.root,raw(s.layout),s.review,h,recipe_path=recipe)
        self.assertEqual(actual,expected)
        repeat=subprocess.run(command,cwd=self.root,capture_output=True,text=True,timeout=30)
        self.assertNotEqual(repeat.returncode,0)


if __name__=='__main__':unittest.main()
