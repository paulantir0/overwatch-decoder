import copy
import unittest
from event_entity_join import EventEntityJoin


class EventEntityJoinTests(unittest.TestCase):
    def setUp(self):
        self.scope = dict(target=dict(pid=7, creation_file_time=11, executable_sha256='a'*64,
            image_name='fixture.exe', architecture='x64'), world_epoch='world-lifetime', clock_id='qpc', frequency=1000)
        self.proof = dict(scope=self.scope, body_key_u32=0x80000001, body_lifetime='body-lifetime',
            entity_id='opaque-body', controller_id='opaque-controller', valid_from_ticks=90,
            valid_until_ticks=200, provenance={'profile_sha256':'b'*64})
        self.obs = dict(scope=self.scope, body_key_u32=0x80000001, body_lifetime='body-lifetime',
            entity_id='opaque-body', controller_id='opaque-controller', observed_ticks=100,
            valid_until_ticks=160, status='observed', hero='Fixture', relation='enemy',
            provenance={'frame_sha256':'c'*64})
        self.event = dict(scope=self.scope, body_key_u32=0x80000001, qpc_ticks=120,
            provenance={'event_sha256':'d'*64})
        self.joiner = EventEntityJoin(maximum_keys=2, maximum_age_ticks=50)

    def observe(self):
        self.joiner.observe(self.obs, [self.proof])

    def test_exact_full_key_source_bound_labels_without_health(self):
        self.observe(); r = self.joiner.join(self.event)
        self.assertEqual((r['entity_id'],r['hero'],r['relation'],r['age_seconds']), ('opaque-body','Fixture','enemy',.02))
        self.assertEqual(r['event_provenance'], self.event['provenance'])
        self.assertEqual(r['proof_provenance'], [self.proof['provenance']])
        self.assertFalse(r['atomic']); self.assertEqual(r['visibility'],'unknown')
        self.assertNotIn('health',r)
        e = dict(self.event, body_key_u32=1)
        self.assertIsNone(self.joiner.join(e))  # Same low index is insufficient.

    def test_independent_scope_mismatches_never_join(self):
        self.observe()
        for field,value in [('pid',8),('creation_file_time',12),('executable_sha256','e'*64),('image_name','other.exe')]:
            e=copy.deepcopy(self.event);e['scope']['target'][field]=value
            self.assertIsNone(self.joiner.join(e))
        for field,value in [('world_epoch','next-world'),('clock_id','other-clock'),('frequency',2000)]:
            e=copy.deepcopy(self.event);e['scope'][field]=value
            self.assertIsNone(self.joiner.join(e))

    def test_no_future_or_expired_observation(self):
        self.observe()
        for tick in [99,151,161]:
            self.assertIsNone(self.joiner.join(dict(self.event,qpc_ticks=tick)))
        self.assertIsNotNone(self.joiner.join(dict(self.event,qpc_ticks=150)))

    def test_proof_interval_and_identity_required(self):
        for change in [dict(valid_until_ticks=119),dict(valid_from_ticks=121),dict(entity_id='other'),dict(body_key_u32=2)]:
            j=EventEntityJoin(maximum_age_ticks=50);j.observe(self.obs,[dict(self.proof,**change)])
            self.assertIsNone(j.join(self.event))
        self.joiner.observe(self.obs,[]);self.assertIsNone(self.joiner.join(self.event))

    def test_conflicting_overlapping_proofs_fail_closed_across_updates(self):
        self.observe();o=dict(self.obs,observed_ticks=110,body_lifetime='new-life',entity_id='new-body')
        p=dict(self.proof,body_lifetime='new-life',entity_id='new-body',valid_from_ticks=110)
        self.joiner.observe(o,[p]);self.assertIsNone(self.joiner.join(self.event))

    def test_nonoverlapping_reuse_is_allowed_after_expiry(self):
        self.proof['valid_until_ticks']=109;self.observe()
        o=dict(self.obs,observed_ticks=110,body_lifetime='new-life',entity_id='new-body')
        p=dict(self.proof,body_lifetime='new-life',entity_id='new-body',valid_from_ticks=110,valid_until_ticks=200)
        self.joiner.observe(o,[p]);self.assertEqual(self.joiner.join(self.event)['entity_id'],'new-body')

    def test_invalidations_do_not_fall_back_or_accept_delayed_labels(self):
        for status in ['unknown','removed','invalid']:
            self.joiner=EventEntityJoin(maximum_keys=2,maximum_age_ticks=50)
            self.observe();self.joiner.observe(dict(self.obs,status=status,observed_ticks=110),[])
            self.assertFalse(self.joiner.observe(self.obs,[self.proof]))
            self.assertIsNone(self.joiner.join(self.event))

    def test_conflicting_same_time_is_unknown(self):
        self.observe();self.joiner.observe(dict(self.obs,hero='different'),[self.proof])
        self.assertIsNone(self.joiner.join(self.event))

    def test_eviction_and_copy_isolation(self):
        self.observe();self.obs['hero']='mutated'
        r=self.joiner.join(self.event);self.assertEqual(r['hero'],'Fixture');r['scope']['world_epoch']='mutated'
        self.assertIsNotNone(self.joiner.join(self.event))
        for key in [2,3]:self.joiner.observe(dict(self.obs,body_key_u32=key,observed_ticks=100+key),[])
        self.assertEqual(len(self.joiner._rows),2);self.assertIsNone(self.joiner.join(self.event))

    def test_oversized_or_unscoped_data_rejected(self):
        for n in [0,4097,True]:
            with self.assertRaises(ValueError):EventEntityJoin(maximum_keys=n,maximum_age_ticks=50)
        with self.assertRaises(ValueError):self.joiner.observe(dict(self.obs,health=[0]*10000),[self.proof])
        with self.assertRaises(ValueError):self.joiner.observe(self.obs,[self.proof]*33)
        with self.assertRaises(ValueError):self.joiner.observe(dict(self.obs,scope={}),[])
        with self.assertRaises(ValueError):self.joiner.join(dict(self.event,body_key_u32=True))

    def test_missing_labels_never_reuse_previous_labels(self):
        self.observe();o=dict(self.obs,hero=None,observed_ticks=110)
        self.joiner.observe(o,[self.proof]);self.assertIsNone(self.joiner.join(self.event))

    def test_repeated_same_source_proof_intervals_coalesce_without_mutation(self):
        for tick in range(100,150):
            o=dict(self.obs,observed_ticks=tick,valid_until_ticks=tick+50)
            p=dict(self.proof,valid_from_ticks=tick,valid_until_ticks=tick+50)
            original=copy.deepcopy(p)
            self.joiner.observe(o,[p]);self.assertEqual(p,original)
        self.assertEqual(len(next(iter(self.joiner._rows.values()))[1]),1)
        self.assertIsNotNone(self.joiner.join(dict(self.event,qpc_ticks=150)))

    def test_proof_overflow_remains_unknown_until_conflicting_interval_expires(self):
        proofs=[dict(self.proof,entity_id='body'+str(i))for i in range(32)]
        self.joiner.observe(self.obs,proofs)
        self.joiner.observe(dict(self.obs,observed_ticks=110),[self.proof])
        self.joiner.observe(dict(self.obs,observed_ticks=115),[self.proof])
        self.assertIsNone(self.joiner.join(self.event))
        self.joiner.observe(dict(self.obs,observed_ticks=201,valid_until_ticks=250),
            [dict(self.proof,valid_from_ticks=201,valid_until_ticks=250)])
        self.assertIsNotNone(self.joiner.join(dict(self.event,qpc_ticks=210)))

    def test_evicted_invalidation_cannot_be_undone_by_delayed_replay(self):
        j=EventEntityJoin(maximum_keys=1,maximum_age_ticks=100)
        j.observe(self.obs,[self.proof])
        j.observe(dict(self.obs,status='removed',observed_ticks=110),[])
        j.observe(dict(self.obs,body_key_u32=2,observed_ticks=111),[])
        self.assertFalse(j.observe(self.obs,[self.proof]))
        self.assertIsNone(j.join(self.event))
        self.assertEqual(len(j._rows),1)

    def test_evicted_same_time_tombstone_cannot_be_replayed(self):
        j=EventEntityJoin(maximum_keys=1,maximum_age_ticks=100)
        j.observe(self.obs,[self.proof])
        j.observe(dict(self.obs,status='removed',observed_ticks=110),[])
        # A later existing-key update and eviction share the high-water mark.
        j.observe(dict(self.obs,body_key_u32=2,observed_ticks=111),[])
        self.assertFalse(j.observe(dict(self.obs,observed_ticks=111),[self.proof]))
        self.assertIsNone(j.join(self.event))

    def test_new_keys_require_strictly_increasing_clock_and_clock_is_fixed(self):
        self.observe()
        self.assertFalse(self.joiner.observe(dict(self.obs,body_key_u32=2),[]))
        self.assertTrue(self.joiner.observe(dict(self.obs,body_key_u32=2,observed_ticks=101),[]))
        s=copy.deepcopy(self.scope);s['clock_id']='independent-clock'
        with self.assertRaises(ValueError):self.joiner.observe(dict(self.obs,scope=s,observed_ticks=102),[])

    def test_conflicting_same_time_lifetime_remains_ambiguous_on_later_update(self):
        self.observe();p=dict(self.proof,body_lifetime='other',entity_id='other-body')
        o=dict(self.obs,body_lifetime='other',entity_id='other-body')
        original=copy.deepcopy(o)
        self.joiner.observe(o,[p]);self.assertEqual(o,original)
        self.assertIsNone(self.joiner.join(self.event))
        self.joiner.observe(dict(o,observed_ticks=110),[p])
        self.assertIsNone(self.joiner.join(self.event))

    def test_batch_admits_multiple_new_keys_at_real_shared_frame_time(self):
        o2=dict(self.obs,body_key_u32=2,entity_id='body2',body_lifetime='life2')
        p2=dict(self.proof,body_key_u32=2,entity_id='body2',body_lifetime='life2')
        self.assertTrue(self.joiner.observe_many([(self.obs,[self.proof]),(o2,[p2])]))
        self.assertEqual(self.joiner.join(self.event)['observation_ticks'],100)
        self.assertEqual(self.joiner.join(dict(self.event,body_key_u32=2))['entity_id'],'body2')
        self.assertEqual(self.joiner._watermark,100)

    def test_previous_batch_replay_after_eviction_cannot_restore_invalidated_key(self):
        j=EventEntityJoin(maximum_keys=1,maximum_age_ticks=100)
        first=[(self.obs,[self.proof])]
        j.observe_many(first)
        j.observe_many([(dict(self.obs,status='invalid',observed_ticks=110),[])])
        j.observe_many([(dict(self.obs,body_key_u32=2,observed_ticks=111),[])])
        state=copy.deepcopy(j.__dict__)
        self.assertFalse(j.observe_many(first));self.assertEqual(j.__dict__,state)
        self.assertIsNone(j.join(self.event))

    def test_batch_invalid_second_row_rolls_back_first_row_clock_and_evictions(self):
        self.joiner=EventEntityJoin(maximum_keys=1,maximum_age_ticks=50)
        self.observe();state=copy.deepcopy(self.joiner.__dict__)
        first=dict(self.obs,body_key_u32=2,observed_ticks=110)
        bad=dict(self.obs,body_key_u32=3,observed_ticks=110,provenance={})
        with self.assertRaises(ValueError):self.joiner.observe_many([(first,[]),(bad,[])])
        self.assertEqual(self.joiner.__dict__,state)
        self.assertIsNotNone(self.joiner.join(self.event))

    def test_failed_batch_after_existing_row_and_proof_update_rolls_back(self):
        self.observe(); state = copy.deepcopy(self.joiner.__dict__)
        update = dict(self.obs, observed_ticks=110, hero='updated')
        extended = dict(self.proof, valid_from_ticks=110, valid_until_ticks=250)
        bad = dict(self.obs, body_key_u32=3, observed_ticks=110, provenance={})
        with self.assertRaisesRegex(ValueError, 'join_provenance'):
            self.joiner.observe_many([(update, [extended]), (bad, [])])
        self.assertEqual(self.joiner.__dict__, state)
        self.assertEqual(self.joiner.join(self.event)['hero'], 'Fixture')
        stored = next(iter(self.joiner._rows.values()))
        self.assertEqual((stored[1][0]['valid_from_ticks'], stored[1][0]['valid_until_ticks']), (90, 200))
        self.assertTrue(self.joiner.observe_many([(update, [extended])]))
        self.assertEqual(self.joiner.join(self.event)['hero'], 'updated')
        self.assertEqual(extended['valid_from_ticks'], 110)

    def test_nested_inputs_and_each_returned_label_are_isolated(self):
        observation, proof, event = copy.deepcopy(self.obs), copy.deepcopy(self.proof), copy.deepcopy(self.event)
        self.joiner.observe_many([(observation, [proof])])
        observation['scope']['world_epoch'] = 'caller-change'
        observation['provenance']['frame_sha256'] = 'caller-change'
        proof['scope']['target']['pid'] = 999
        proof['provenance']['profile_sha256'] = 'caller-change'
        proof['valid_until_ticks'] = 110
        first = self.joiner.join(event); expected = copy.deepcopy(first)
        self.assertEqual(first['observation_provenance'], self.obs['provenance'])
        self.assertEqual(first['proof_provenance'], [self.proof['provenance']])
        first['scope']['target']['pid'] = 999
        first['event_provenance']['event_sha256'] = 'result-change'
        first['observation_provenance']['frame_sha256'] = 'result-change'
        first['proof_provenance'][0]['profile_sha256'] = 'result-change'
        self.assertEqual(event, self.event)
        self.assertEqual(self.joiner.join(event), expected)

    def test_batch_duplicate_key_and_mixed_timestamps_rejected_without_mutation(self):
        for items in [[(self.obs,[self.proof]),(self.obs,[self.proof])],
            [(self.obs,[]),(dict(self.obs,body_key_u32=2,observed_ticks=101),[])]]:
            state=copy.deepcopy(self.joiner.__dict__)
            with self.assertRaises(ValueError):self.joiner.observe_many(items)
            self.assertEqual(self.joiner.__dict__,state)

    def test_batch_one_clock_bound_and_malformed_delayed_input(self):
        s=copy.deepcopy(self.scope);s['frequency']=2000
        with self.assertRaises(ValueError):self.joiner.observe_many([
            (self.obs,[]),(dict(self.obs,scope=s,body_key_u32=2),[])])
        self.assertIsNone(self.joiner._clock)
        with self.assertRaises(ValueError):self.joiner.observe_many([(self.obs,[])]*257)
        self.observe();bad=dict(self.obs,provenance={})
        with self.assertRaises(ValueError):self.joiner.observe_many([(bad,[])])
        self.assertEqual(self.joiner._watermark,100)

if __name__=='__main__':unittest.main()
