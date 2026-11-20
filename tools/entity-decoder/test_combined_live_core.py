import copy,json,tempfile,unittest
from pathlib import Path
from combined_core import Epochs,LineTail,raw
S=dict(target=dict(pid=1,creation_file_time=2,executable_sha256='a'*64,image_name='fixture',architecture='x64'),world_epoch='w1',clock_id='windows_qpc',frequency=1000)
def packet(source,tick,scope=S,observations=(),events=()):return dict(source=source,tick=tick,scope=copy.deepcopy(scope),observations=list(observations),events=list(events),reason=None)
def observation(tick,end,key=7):
 o=dict(scope=S,body_key_u32=key,observed_ticks=tick,valid_until_ticks=end,status='observed',body_lifetime='lifetime',entity_id='body',controller_id='controller',hero='fixture',relation='enemy',provenance={'endpoint':'past'})
 p=dict(scope=S,body_key_u32=key,body_lifetime='lifetime',entity_id='body',controller_id='controller',valid_from_ticks=tick,valid_until_ticks=end,provenance={'endpoint':'past_and_future_observed'})
 return o,[p]
def event(tick):return dict(event=dict(scope=S,body_key_u32=7,qpc_ticks=tick,provenance={'record':'fixture'}),payload=dict(kind='damage_feedback_candidate',record_id=str(tick),first_observation={'raw_tick':999},confirmation={'frame_end_ticks':tick,'monotonic_frequency':1000}))
class CoreTests(unittest.TestCase):
 def test_damage_first_arrival_waits_for_roster_watermark_and_preserves_original_times(self):
  output=[];e=Epochs(['a','d'],'d',output.append)
  e.accept(packet('d',20,events=[event(20)]));e.accept(packet('a',10,observations=[observation(10,30)]),{'kind':'entity_updates','timestamp':{'end_ticks':10},'entities':[{'entity_id':'body'}]})
  self.assertFalse(any(r.get('record_id')for r in output));e.accept(packet('a',20,observations=[observation(20,30)]));record=next(r for r in output if r.get('record_id'))
  self.assertEqual(record['target_label']['entity_id'],'body');self.assertEqual(record['first_observation'],{'raw_tick':999});self.assertEqual(record['confirmation']['frame_end_ticks'],20)
 def test_pre_reset_endpoint_cannot_reenter_resumed_same_scope_epoch(self):
  out=[];e=Epochs(['a','d'],'d',out.append);e.accept(packet('d',10));e.accept(packet('a',10));e.accept(packet('d',20,scope=None));e.accept(packet('d',30,events=[event(30)]));e.accept(packet('a',15,observations=[observation(15,40)]));e.accept(packet('a',40));r=next(r for r in out if r.get('record_id'));self.assertIsNone(r['target_label'])
 def test_unknown_roster_invalidates_without_stale_labels(self):
  out=[];e=Epochs(['a','d'],'d',out.append);e.accept(packet('d',10));e.accept(packet('a',10,observations=[observation(10,100)]));e.accept(packet('a',20,scope=None));e.accept(packet('d',20,events=[event(20)]));r=next(r for r in out if r.get('record_id'));self.assertIsNone(r['target_label'])
 def test_only_damage_changes_scope_and_boundary_aborts_pending(self):
  out=[];e=Epochs(['a','d'],'d',out.append);e.accept(packet('d',20,events=[event(20)]));other=copy.deepcopy(S);other['world_epoch']='w2';e.accept(packet('a',10,scope=other));self.assertEqual(e.scope,S)
  e.accept(packet('d',30,scope=other));r=next(r for r in out if r.get('record_id'));self.assertIsNone(r['target_label']);self.assertEqual(e.epoch,2)
  e.accept(packet('a',40,scope=S,observations=[observation(40,60)]));self.assertEqual(e.scope,other)
 def test_unknown_damage_closes_epoch_and_terminal_uses_real_later_tick(self):
  out=[];e=Epochs(['a','d'],'d',out.append);e.accept(packet('d',20,events=[event(20)]));e.accept(packet('d',25,scope=None));self.assertIsNone(e.scope);self.assertIsNone(next(r for r in out if r.get('record_id'))['target_label'])
  with self.assertRaisesRegex(ValueError,'terminal_clock'):e.finish('d',25)
  e.finish('d',26);e.finish('a',30)
 def test_pending_bound_and_partial_tail_truncation_fail_closed(self):
  e=Epochs(['a','b','d'],'d',lambda _:None,maximum_pending_rows=2);e.accept(packet('d',20,events=[event(20)]));e.accept(packet('a',10),{'kind':'entity_updates'})
  with self.assertRaises(ValueError):e.accept(packet('a',15),{'kind':'entity_updates'})
  e.abort('pending_bound');self.assertEqual(e.pending,[])
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'source';t=LineTail(p,20);p.write_bytes(b'{"x":');self.assertIsNone(t.next());p.write_bytes(b'{"x":1}\n');self.assertEqual(t.next(),b'{"x":1}\n');t.complete();p.write_bytes(b'')
   with self.assertRaisesRegex(ValueError,'truncated'):t.next()
if __name__=='__main__':unittest.main()
