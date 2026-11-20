"""Exact frame-local guard evidence memoization, including failed proofs."""
import copy,json,unittest
from unittest.mock import patch
from relations import GuardedRelations,InvalidBinding
from test_relations import prepare
from test_selected_entity_view import serial_guards


def fixture(global_prefix=False):
    shared=dict(address=4096,bytes_hex='01000000')
    own=dict(address=4104,bytes_hex='02000000')
    profile=dict(schema='overwatch-decoder.field-profile/1',target=dict(pid=1,creation_file_time=2,
        executable_sha256='ab'*32,architecture='x64',image_name='fixture.exe'),guards=[],fields=[
        dict(name='a',type='i32',address=4096,guards=[shared]),
        dict(name='b',type='i32',address=4104,guards=[shared,own])])
    if global_prefix:
        profile['guards']=[shared]
        profile['fields'].append(dict(name='c',type='i32',address=4112,
            guards=[dict(address=4112,bytes_hex='03000000')]))
    _,frame=prepare(profile,dict(a=1,b=2,c=3) if global_prefix else dict(a=1,b=2))
    profile['schema']='overwatch-decoder.field-profile/4';raw=json.dumps(profile).encode()
    decoder=GuardedRelations(raw,allow_profile4=True);frame['profile_sha256']=decoder.hash;frame['schema']='overwatch-decoder.field-stream/4'
    serial_guards(profile,frame)
    return decoder,frame


def read(decoder,frame,name='a'):
    return decoder.sample_scalar(name,frame,'i32')


def bad_read(frame,case):
    check=frame['guards_before'][0]
    if case=='status':check.update(ok=False,error='read_failed')
    elif case=='id':check['guard_id']=1
    elif case=='address':check['read']['address_hex']='0000000000009999'
    elif case=='error':check['read']['error']='read_failed'
    elif case=='timing':check['read']['start_ticks']=-1
    elif case=='bytes':check['read']['bytes_hex']='ffffffff'
    elif case=='returned':check['read']['returned_bytes']=0
    elif case=='attempted':check['read']['attempted']=False


class GuardReadCacheTests(unittest.TestCase):
    def test_shared_global_prefix_avoids_revisiting_guards_for_each_field(self):
        decoder,frame=fixture(global_prefix=True)
        expected=[read(decoder,frame,name) for name in ('a','b','c')]
        with patch.object(decoder,'_guard_check',wraps=decoder._guard_check) as check:
            with decoder._frame_checks(frame):
                active=decoder._active_checks
                self.assertEqual([read(decoder,frame,name) for name in ('b','c','a')],
                                 [expected[1],expected[2],expected[0]])
                # Each global/field guard is visited once per phase, even when
                # the first field has both global and field-local dependencies.
                self.assertEqual(check.call_count,2*len(decoder.guards))
        self.assertEqual(active[1],{});self.assertEqual(active[2],{})

    def test_shared_prefix_retains_failure_order_and_each_field_bracket(self):
        for case in ('global_after','local_before','read_before_global','read_after_local','count'):
            with self.subTest(case=case):
                decoder,frame=fixture(global_prefix=True)
                if case=='global_after':
                    frame['guards_after'][0].update(ok=False,error='global-after')
                    frame['guards_before'][1].update(ok=False,error='earlier-local-before')
                elif case=='local_before':frame['guards_before'][1].update(ok=False,error='local-before')
                elif case=='read_before_global':frame['fields']['b']['read_start_ticks']=15
                elif case=='read_after_local':frame['fields']['b']['read_end_ticks']=85
                else:frame['guards_after'].pop()
                with self.assertRaises(InvalidBinding) as expected:read(decoder,frame,'b')
                with decoder._frame_checks(frame):
                    for _ in range(2):
                        with self.assertRaises(InvalidBinding) as actual:read(decoder,frame,'b')
                        self.assertEqual(str(actual.exception),str(expected.exception))

    def test_shared_prefix_rechecks_next_scope_and_unrelated_ids(self):
        decoder,frame=fixture(global_prefix=True)
        with decoder._frame_checks(frame):read(decoder,frame,'b')
        bad_read(frame,'bytes')
        with decoder._frame_checks(frame):
            with self.assertRaisesRegex(InvalidBinding,'invalid_serial_guard_read'):read(decoder,frame,'c')
        decoder,frame=fixture(global_prefix=True)
        decoder.guard_ids['c']=[2];frame['fields']['c']['guard_ids']=[2]
        bad_read(frame,'bytes')
        expected=read(decoder,frame,'c')
        with decoder._frame_checks(frame):self.assertEqual(read(decoder,frame,'c'),expected)

    def test_overlapping_dependency_sets_validate_each_phase_record_once(self):
        decoder,frame=fixture();expected=[read(decoder,frame,name) for name in ('a','b')]
        with patch.object(decoder,'_validate_guard_check',wraps=decoder._validate_guard_check) as validate:
            with decoder._frame_checks(frame):
                active=decoder._active_checks
                self.assertEqual([read(decoder,frame,name) for name in ('a','b')],expected)
                self.assertEqual([read(decoder,frame,name) for name in ('a','b')],expected)
                self.assertEqual(validate.call_count,4)
                self.assertEqual(len(active[2]),2*len(decoder.guards))
        self.assertEqual(active[1],{});self.assertEqual(active[2],{});self.assertIsNone(decoder._active_checks)

    def test_invalid_record_is_cached_but_never_accepted(self):
        for case in ('status','id','address','error','timing','bytes','returned','attempted'):
            with self.subTest(case=case):
                decoder,frame=fixture();bad_read(frame,case)
                with self.assertRaises(InvalidBinding) as unscoped:read(decoder,frame)
                with patch.object(decoder,'_validate_guard_check',wraps=decoder._validate_guard_check) as validate:
                    with decoder._frame_checks(frame):
                        for name in ('a','b','a'):
                            with self.assertRaises(InvalidBinding) as scoped:read(decoder,frame,name)
                            self.assertEqual(str(scoped.exception),str(unscoped.exception))
                        self.assertEqual(validate.call_count,1)

    def test_reusing_same_frame_object_rechecks_fresh_bytes_every_scope(self):
        for case in ('status','id','address','error','timing','bytes','returned','attempted'):
            with self.subTest(case=case):
                decoder,frame=fixture()
                with decoder._frame_checks(frame):self.assertEqual(read(decoder,frame)['value'],1)
                bad_read(frame,case)
                with patch.object(decoder,'_validate_guard_check',wraps=decoder._validate_guard_check) as validate:
                    with decoder._frame_checks(frame):
                        with self.assertRaises(InvalidBinding):read(decoder,frame)
                        self.assertEqual(validate.call_count,1)

    def test_dependency_and_field_brackets_remain_independent(self):
        decoder,frame=fixture()
        with decoder._frame_checks(frame):
            read(decoder,frame)
            frame['fields']['b']['read_end_ticks']=85
            with self.assertRaisesRegex(InvalidBinding,'invalid_guard_bracket'):read(decoder,frame,'b')
            frame['fields']['b']['read_end_ticks']=40;frame['fields']['b']['guard_ids']=[0]
            with self.assertRaisesRegex(InvalidBinding,'guard_dependencies_mismatch'):read(decoder,frame,'b')
            frame['fields']['a']['value']=9
            self.assertEqual(read(decoder,frame)['value'],9)
            with self.assertRaisesRegex(InvalidBinding,'identity_word_guard_mismatch'):decoder._observed('a',frame)

    def test_ordered_failure_precedence_is_unchanged(self):
        decoder,frame=fixture();frame['guards_before'][0]['read']['end_ticks']=35
        frame['guards_before'][1].update(ok=False,error='later-failure')
        with self.assertRaises(InvalidBinding) as unscoped:read(decoder,frame,'b')
        with decoder._frame_checks(frame):
            with self.assertRaises(InvalidBinding) as scoped:read(decoder,frame,'b')
        self.assertEqual(str(scoped.exception),str(unscoped.exception))
        self.assertEqual(str(scoped.exception),'invalid_guard_bracket')

    def test_nested_scope_restores_parent_and_clears_success_and_failure_caches(self):
        decoder,frame=fixture();other=copy.deepcopy(frame);bad_read(other,'bytes')
        with decoder._frame_checks(frame):
            outer=decoder._active_checks;read(decoder,frame)
            with self.assertRaisesRegex(RuntimeError,'stop'):
                with decoder._frame_checks(other):
                    inner=decoder._active_checks
                    with self.assertRaises(InvalidBinding):read(decoder,other)
                    self.assertTrue(inner[2]);raise RuntimeError('stop')
            self.assertIs(decoder._active_checks,outer);self.assertEqual(inner[1],{});self.assertEqual(inner[2],{})
            self.assertEqual(read(decoder,frame)['value'],1)
        self.assertIsNone(decoder._active_checks);self.assertEqual(outer[1],{});self.assertEqual(outer[2],{})

    def test_another_frame_bypasses_active_frame_cache(self):
        decoder,frame=fixture();other=copy.deepcopy(frame);bad_read(other,'bytes')
        with decoder._frame_checks(frame):
            read(decoder,frame)
            with self.assertRaisesRegex(InvalidBinding,'invalid_serial_guard_read'):read(decoder,other)
            self.assertEqual(read(decoder,frame)['value'],1)

    def test_unscoped_word_binding_reuses_only_unchanged_typed_declarations(self):
        decoder, frame = fixture()
        with patch.object(decoder, '_uncached_binding', wraps=decoder._uncached_binding) as bind:
            self.assertEqual(decoder._binding('a'), (4096, 1))
            self.assertEqual(decoder._binding('a'), (4096, 1))
            self.assertEqual(bind.call_count, 1)
            decoder.fields['a']['guards'][0]['bytes_hex'] = '02000000'
            self.assertEqual(decoder._binding('a'), (4096, 2))
            self.assertEqual(bind.call_count, 2)
            global_guard = {'address': 1, 'bytes_hex': '00'}
            decoder.profile['guards'].append(global_guard)
            self.assertEqual(decoder._binding('a'), (4096, 2))
            global_guard['address'] = True
            with self.assertRaisesRegex(InvalidBinding, 'invalid_guard'):
                decoder._binding('a')
            global_guard['address'] = 1.0
            with self.assertRaisesRegex(InvalidBinding, 'invalid_guard'):
                decoder._binding('a')
            decoder.fields['a']['codec'] = None
            with self.assertRaisesRegex(InvalidBinding, 'unsupported_word_binding'):
                decoder._binding('a')

    def test_unscoped_word_binding_never_reuses_frame_guard_evidence(self):
        decoder, frame = fixture()
        self.assertEqual(decoder._observed('a', frame)['value'], 1)
        bad_read(frame, 'bytes')
        with self.assertRaisesRegex(InvalidBinding, 'invalid_serial_guard_read'):
            decoder._observed('a', frame)

    def test_changed_profile_guard_requires_fresh_matching_byte_proof(self):
        decoder,frame=fixture()
        with decoder._frame_checks(frame):read(decoder,frame)
        decoder.guards[0]['bytes_hex']='02000000'
        with decoder._frame_checks(frame):
            with self.assertRaisesRegex(InvalidBinding,'invalid_serial_guard_read'):read(decoder,frame)

if __name__=='__main__':unittest.main()
