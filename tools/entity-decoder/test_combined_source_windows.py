import unittest
from combined_core import Epochs,SourceWindows
from test_combined_live_core import S,packet

def batches(source,step,actors):
 out=[]
 for tick in range(step,501,step):
  observations=[]
  for key in range(actors*8,actors*8+8)if source!='d'else[]:
   o=dict(scope=S,body_key_u32=key,observed_ticks=tick,valid_until_ticks=tick+step,status='observed',body_lifetime=str(key),entity_id='e'+str(key),controller_id='c'+str(key),hero='fixture',relation='enemy',provenance={'p':'fixture'})
   p=dict(scope=S,body_key_u32=key,body_lifetime=str(key),entity_id='e'+str(key),controller_id='c'+str(key),valid_from_ticks=tick,valid_until_ticks=tick+step,provenance={'p':'fixture'});observations.append((o,[p]))
  out.append(dict(kind='batch',packet=packet(source,tick,observations=observations)))
 return out
class SourceWindowTests(unittest.TestCase):
 def test_real_cadence_shape_old_four_rows_overflows_new_windows_remain_bounded(self):
  ids=['a'+str(i)for i in range(6)]+['d'];rows={s:batches(s,20 if s=='d'else 50,i)for i,s in enumerate(ids)}
  old=Epochs(ids,'d',lambda _:None,maximum_pending_rows=64);old.accept(packet('d',0))
  with self.assertRaisesRegex(ValueError,'stream_pending_limit'):
   for s in ids:
    for x in rows[s][:4]:old.accept(x['packet'])
  e=Epochs(ids,'d',lambda _:None,maximum_pending_rows=64);e.accept(packet('d',0));w=SourceWindows(ids);w.progress['d']=0;positions=dict.fromkeys(ids,0);peak=0;processed=0
  while True:
   for s in ids:
    if s not in w.heads and positions[s]<len(rows[s]):w.offer(s,rows[s][positions[s]]);positions[s]+=1
   choice=w.choose()
   if choice is None:break
   s,item=choice;e.accept(item['packet']);w.commit(s);processed+=1;peak=max(peak,sum(x[2]for x in e.stream._pending))
  self.assertGreater(processed,40);self.assertLessEqual(peak,64);self.assertLessEqual(len(w.heads),7)
 def test_missing_minimum_backpressures_without_inventing_progress(self):
  w=SourceWindows(['a','b'])
  for s in ['a','b']:w.offer(s,dict(kind='batch',packet={'tick':10}));w.commit(s)
  w.offer('b',dict(kind='batch',packet={'tick':20}));self.assertIsNotNone(w.choose());w.commit('b');self.assertIsNone(w.choose());self.assertEqual(w.progress['a'],10)
  w.offer('a',dict(kind='batch',packet={'tick':100}));self.assertEqual(w.choose()[0],'a');w.commit('a');self.assertEqual(w.progress['a'],100)
if __name__=='__main__':unittest.main()
