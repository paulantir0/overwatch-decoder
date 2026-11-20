import copy
import json
import unittest
from overwatch_decoder.session_observations import InvalidObservation, from_line, normalize
from incoming_observation_fixture import incoming_fixture


class ObservationTests(unittest.TestCase):
    def compact(self):
        return dict(schema='overwatch-decoder.private.selected-compact/1', source='process_memory', scope='configured_controller_window',
                    timestamp=dict(start_ticks=100, end_ticks=110, monotonic_frequency=1000), segment=1,
                    entities=[dict(entity_id='body:test', controller_id='controller:test', is_local=True,
                                   hero='Tracer', hero_validation='controlled', health=150, health_validation='candidate',
                                   position=[1,2,3], position_validation='guarded', relation='enemy', relation_validation='unknown',
                                   address=1234, path='/private', raw_words=[1,2])])

    def test_allowlist_and_unknown(self):
        r=normalize(self.compact()); e=r['entities'][0]
        self.assertEqual(e['position']['value'], [1,2,3]); self.assertIsNone(e['relation']['value'])
        self.assertIsNone(e['team']['value']); self.assertIsNone(e['username']['value'])
        self.assertEqual(e['visibility'], 'unknown'); self.assertFalse(r['public_state_eligible'])
        for field in ('address','raw_words','path'): self.assertNotIn(field,json.dumps(r))

    def test_unreviewed_or_unknown_orientation_is_null_without_losing_fields(self):
        row=self.compact();entity=row['entities'][0]
        entity.update(raw_quaternion_candidate=[0,0,0,1],raw_quaternion_candidate_validation='raw_orientation_candidate')
        for changes in ({},{'raw_quaternion_candidate_validation':'unknown'},{'raw_quaternion_candidate':[0,float('nan'),0,1]}):
            entity.update(changes);result=normalize(row)['entities'][0]
            self.assertIsNone(result['raw_quaternion_candidate']['value'])
            self.assertEqual(result['position']['value'],[1,2,3])
            self.assertNotIn('raw_quaternion_candidate',result['field_evidence'])

    def test_health_delta_is_not_damage(self):
        a=self.compact(); b=copy.deepcopy(a); b['entities'][0]['health']=70
        self.assertEqual(normalize(a)['kind'],'entities'); self.assertEqual(normalize(b)['kind'],'entities')

    def test_damage_remains_candidate_and_null_attacker(self):
        raw=dict(schema='overwatch-decoder.private.damage-feedback-candidate/1',kind='damage_feedback_candidate', amount_truncated=15,
                 confirmation=dict(frame_start_ticks=1,frame_end_ticks=2,monotonic_frequency=1000),
                 raw_vector_words=[1,2,3,4],target_label=None,validation_status='controlled_candidate',attacker='invented')
        r=normalize(raw); self.assertIsNone(r['target']); self.assertIsNone(r['attacker']); self.assertIsNone(r['exact_damage'])
        self.assertEqual(r['direction'],'outgoing_candidate'); self.assertNotIn('raw_vector_words',r)

    def test_bounds_and_timestamp(self):
        for t in ({'start_ticks':4,'end_ticks':3,'monotonic_frequency':1000}, {'start_ticks':True,'end_ticks':3,'monotonic_frequency':1000}):
            value=self.compact(); value['timestamp']=t
            with self.assertRaises(InvalidObservation): normalize(value)
        with self.assertRaises(InvalidObservation): from_line(b' '*(2*1024*1024+1))

    def test_line_hash(self):
        raw=json.dumps(self.compact()).encode(); self.assertEqual(len(from_line(raw)['source_sha256']),64)

    def test_incoming_observation_preserves_sampled_evidence_and_strips_raw_fields(self):
        value=incoming_fixture(); value['provenance']['context']['raw_words']=[9,8]
        value['source_actor']['address']=123; value['private_path']='invented-private-path'
        row=normalize(value)
        self.assertEqual(row['kind'],'incoming_source'); self.assertEqual(row['status'],'observed')
        self.assertEqual(row['timestamp']['end_ticks'],'110')
        self.assertEqual(row['source_actor']['entity_id'],'body:fixture-source')
        self.assertEqual(row['recipient_actor']['hero']['value'],'FixtureRecipient')
        self.assertIsNone(row['recipient_actor']['relation']['value'])
        self.assertEqual([p['timestamp']['start_ticks'] for p in row['source_actor']['position_observations']],['82','122'])
        self.assertEqual(row['source_sampling_clock']['utc_origin'],'2020-01-01T00:00:00+00:00')
        self.assertEqual(row['observed_build_sha256'],'f'*64)
        for key in ('raw_words','address','private_path'): self.assertNotIn(key,json.dumps(row))
        self.assertFalse(row['unique_hit']); self.assertIsNone(row['exact_damage']); self.assertIsNone(row['impact_timestamp'])
        self.assertIsNone(row['numeric_team']); self.assertEqual(row['visibility'],'unknown')

    def test_incoming_unknowns_never_gain_attribution_or_observation_time(self):
        timed=normalize(incoming_fixture('unknown'))
        self.assertIsNone(timed['source_actor']); self.assertIsNone(timed['recipient_actor'])
        self.assertEqual(timed['timestamp']['end_ticks'],'110')
        untimed=normalize(incoming_fixture('unknown',untimed=True))
        for field in ('source_actor','recipient_actor','timestamp','source_sampling_clock','observed_build_sha256'):
            self.assertIsNone(untimed[field])
        value=incoming_fixture('unknown');value['source_actor']={'entity_id':'invented'}
        with self.assertRaises(InvalidObservation):normalize(value)

    def test_incoming_contradictory_semantics_or_malformed_observed_shape_rejected(self):
        changes=[('unique_hit',True),('exact_damage',20),('impact_timestamp',100),('numeric_team',2),
                 ('visibility','visible'),('atomic',True),('public_state_eligible',True),('source_actor',None),
                 ('recipient_actor',None),('source_clock',None),('source_sampling_clock',None),('read_interval',None)]
        for field,value in changes:
            row=incoming_fixture();row[field]=value
            with self.subTest(field=field),self.assertRaises(InvalidObservation):normalize(row)
        for mutation in (lambda r:r['source_actor']['position_observations'].pop(),
                         lambda r:r['source_actor']['position_observations'][0]['position'].update(value=[float('nan'),0,0]),
                         lambda r:r['source_actor']['position_observations'][1]['position'].update(read_interval={'start_ticks':90,'end_ticks':91}),
                         lambda r:r['source_actor']['position_observations'][1]['roster'].update(read_interval={'start_ticks':120,'end_ticks':200}),
                         lambda r:r['source_actor']['relation'].update(value='unvalidated_special_mode'),
                         lambda r:r['provenance']['context']['evidence'].pop('native_event_sha256'),
                         lambda r:r['source_sampling_clock'].update(monotonic_frequency=1001),
                         lambda r:r['source_sampling_clock'].update(utc_origin='2020-01-01'),
                         lambda r:r['read_interval'].update(monotonic_frequency=1001),
                         lambda r:r.update(observed_build_sha256='a'*64)):
            row=incoming_fixture();mutation(row)
            with self.assertRaises(InvalidObservation):normalize(row)

if __name__=='__main__': unittest.main()
