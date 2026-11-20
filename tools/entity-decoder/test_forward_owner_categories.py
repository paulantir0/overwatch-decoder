"""Forward category identity/source/gap counterexamples without private layouts."""
import copy
import json
import unittest

from forward_owner_categories import GuardedForwardOwnerCategories
from test_forward_owner_relations import source_fixture, raw, sha
from test_relations import change_word


def category_fixture(mutate=None):
    def extend(profile, values):
        profile['guards'] += [dict(address=0x9000, bytes_hex='0000000000000000'),
                              dict(address=0x9010, bytes_hex='00000000')]
        for name, address, value in [('category_low', 0x9020, 8), ('category_high', 0x9024, 0)]:
            profile['fields'].append(dict(name=name, address=address, type='i32'))
            values[name] = value
        if mutate: mutate(profile, values)
    profile, forward, artifacts, frame = source_fixture(mutate=extend)
    fc = json.loads(forward)
    source = b'synthetic native category trace'
    artifacts[sha(source)] = source
    native = raw(dict(schema='overwatch-decoder.native-category-review/1', reviewed=True,
        review_method='native_consumer_trace', build_sha256=fc['build_sha256'],
        required_conditions=['unlinked_owner', 'zero_override'], sources=[sha(source)],
        algorithm=dict(ordered_bits=[3, 7, 11], clear_bits=[2], supported_categories=[0, 1])))
    artifacts[sha(native)] = native
    from relations import GuardedRelations
    g = GuardedRelations(profile)
    binding = dict(binding_id='actor0', owner_handle_field='controller_0000_aux_0000_handle_candidate_i32',
        owner_key_field='controller_0000_aux_0000_manager_key_candidate_i32',
        flags_low_field='category_low', flags_high_field='category_high',
        required_guard_ids=list(range(len(g.guards))), conditions=[
            dict(role='unlinked_owner',address=0x9000,width=8,mask=1,equals=0),
            dict(role='zero_override',address=0x9010,width=4,mask=0xffffffff,equals=0)])
    contract = raw(dict(schema='overwatch-decoder.forward-owner-category-contract/1',
        **{k:fc[k]for k in ('target','profile_sha256','build_sha256','source','acquisition_manifest_sha256')},
        forward_contract_sha256=sha(forward),native_review_sha256=sha(native),bindings=[binding]))
    return profile, forward, contract, artifacts, frame


class ForwardCategoryTests(unittest.TestCase):
    def setUp(self):
        self.p,self.f,self.c,self.a,self.frame=category_fixture()
        self.decoder=self.make()

    def make(self):
        return GuardedForwardOwnerCategories(self.p,self.f,self.c,self.a)

    def row(self,frame=None,**kw):
        return self.decoder.project(self.frame if frame is None else frame,**kw)['rows'][0]

    def test_exact_forward_owner_without_body_or_team_promotion(self):
        result=self.decoder.project(self.frame);row=result['rows'][0]
        self.assertEqual(row['raw_category_candidate'],0)
        self.assertTrue(row['forward_owner_object_key'].startswith('owner:'))
        self.assertNotIn('body_object_key',row)
        for k in ('current_displayed_body','team_candidate','relative_allegiance_candidate'):
            self.assertIsNone(row[k])
        self.assertEqual(len(row['evidence']),4)
        self.assertEqual(len(row['forward_identity_evidence']),5)
        self.assertEqual(result['source_evidence'],self.decoder.forward.project(self.frame)['source_evidence'])
        self.assertEqual(result['forward_contract_sha256'],sha(self.f))

    def test_native_flags_preserve_raw_for_unsupported_modes(self):
        for value,group in [(128,1),(0,None),(136,None),(12,None),(2048,None)]:
            f=copy.deepcopy(self.frame);f['fields']['category_low']['value']=value
            row=self.row(f);self.assertEqual(row['raw_category_candidate'],group)
            self.assertEqual(row['raw_flags_candidate']['low_u32'],value)

    def test_each_identity_half_guard_and_read_failure_nulls(self):
        for name in self.decoder.forward.bindings[0]['names']+['category_low','category_high']:
            for bad in ('unknown','ids','bracket','shape'):
                f=copy.deepcopy(self.frame)
                if bad=='unknown':f['fields'][name]['status']='unknown'
                if bad=='ids':f['fields'][name]['guard_ids']=[]
                if bad=='bracket':f['fields'][name]['read_end_ticks']=101
                if bad=='shape':f['fields'][name]=None
                with self.subTest(name=name,bad=bad):self.assertIsNone(self.row(f)['raw_category_candidate'])
        for phase in ('before','after'):
            for i in range(len(self.decoder.forward.relations.guards)):
                f=copy.deepcopy(self.frame);f['guards_'+phase][i]['ok']=False
                self.assertIsNone(self.row(f)['raw_category_candidate'])

    def test_gap_profile_target_timing_never_reuses_success(self):
        self.assertEqual(self.row()['status'],'observed')
        for key,value in [('profile_sha256','00'*32),('target',None),('start_ticks',101),
                          ('monotonic_frequency',True),('skipped_intervals_before',1)]:
            f=copy.deepcopy(self.frame);f[key]=value
            self.assertIsNone(self.row(f)['raw_category_candidate'])
        self.assertIsNone(self.row(gap=True)['raw_flags_candidate'])
        self.assertEqual(self.row()['status'],'observed')

    def test_full_reference_mismatch_is_not_a_category_binding(self):
        def mutate(p,v):change_word(p,v,2,0x90000020)
        p,f,c,a,frame=category_fixture(mutate)
        row=GuardedForwardOwnerCategories(p,f,c,a).project(frame)['rows'][0]
        self.assertEqual(row['reason'],'forward_reference_owner_mismatch')
        self.assertIsNone(row['raw_category_candidate'])

    def test_source_contract_and_owner_substitution_rejected(self):
        for mutation in ('forward','recipe','profile','build','owner','duplicate','condition'):
            c=json.loads(self.c)
            if mutation=='forward':c['forward_contract_sha256']='00'*32
            if mutation=='recipe':c['source']['recipe_sha256']='00'*32
            if mutation=='profile':c['profile_sha256']='00'*32
            if mutation=='build':c['build_sha256']='00'*32
            if mutation=='owner':c['bindings'][0]['owner_key_field']='controller_0000_manager_key_candidate_i32'
            if mutation=='duplicate':c['bindings']*=2
            if mutation=='condition':c['bindings'][0]['conditions'][0]['equals']=1
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                GuardedForwardOwnerCategories(self.p,self.f,raw(c),self.a)

    def test_changed_owner_needs_fresh_contract_and_changes_key(self):
        def mutate(p,v):
            change_word(p,v,2,0x80000099);change_word(p,v,3,0x80000098);change_word(p,v,4,0x80000099)
        p,f,c,a,frame=category_fixture(mutate)
        row=GuardedForwardOwnerCategories(p,f,c,a).project(frame)['rows'][0]
        self.assertEqual(row['controller_object_key'],self.row()['controller_object_key'])
        self.assertNotEqual(row['forward_owner_object_key'],self.row()['forward_owner_object_key'])
        self.assertEqual(row['raw_category_candidate'],0)
        self.assertIsNone(self.row(frame)['raw_category_candidate'])

    def test_sequential_flag_brackets_and_unsigned_values_preserved(self):
        f=copy.deepcopy(self.frame);f['fields']['category_high'].update(value=-1,read_start_ticks=44,read_end_ticks=46)
        row=self.row(f)
        self.assertEqual(row['raw_flags_candidate']['high_u32'],0xffffffff)
        self.assertEqual(row['evidence'][-1]['read_start_ticks'],44)
        self.assertFalse(row['atomic'])


if __name__=='__main__':unittest.main()
