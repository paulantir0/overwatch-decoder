"""Owned transport fixtures; these do not establish native gameplay semantics."""
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
import run_combined_live as r
from test_combined_live_core import packet

class MultiRosterTests(unittest.TestCase):
 def config(self):
  return dict(roster_only=True,roster_source_limit=2,combined_storage_contract=1,
              python_sha256=r.digest(r.sys.executable),maximum_label_age_ms=500,
              roster_batches=['00','01'],source_bundles=[dict(source='roster',path='sources/roster')])
 def test_opt_in_and_two_source_bound(self):
  c=self.config()
  self.assertEqual([s['id'] for s in r.specs(c,1,20,Path('/tmp/out'),'read_only_user_gameplay')],['roster-00','roster-01'])
  for value in (None,True,0,3,'2'):
   bad=dict(c,roster_source_limit=value)
   with self.assertRaisesRegex(ValueError,'roster_source_limit'):r.specs(bad,1,20,Path('/tmp/out'),'read_only_user_gameplay')
  del c['roster_source_limit']
  with self.assertRaisesRegex(ValueError,'roster_only_topology'):r.specs(c,1,20,Path('/tmp/out'),'read_only_user_gameplay')
  c=self.config();c['roster_batches'].append('02')
  with self.assertRaisesRegex(ValueError,'roster_only_topology'):r.specs(c,1,20,Path('/tmp/out'),'read_only_user_gameplay')
 def exercise(self,mode=None):
  with tempfile.TemporaryDirectory() as tmp:
   out=Path(tmp)/'out';readers={};jobs=[];originals={}
   class Reader:
    def __init__(self,spec,c,pid):
     self.source=spec['id'];self.done=False;self.closed=False;readers[self.source]=self
     n=9 if self.source=='roster-00' else 8
     self.items=[]
     if mode not in ('both_empty',) and not(mode=='one_empty' and self.source=='roster-00'):
      for i in range(2):
       # Independent epochs and clocks: same fixture entity IDs are never
       # rewritten or joined using the other source's session/segment.
       e=dict(schema='overwatch-decoder.private.selected-compact/1',kind='entity_updates',session_id=self.source+'-session',segment=i+1,
              timestamp=dict(start_ticks=10+i*10,end_ticks=11+i*10,monotonic_frequency=1000),
              entities=[dict(entity_id=self.source+'-'+str(j),body_id=str(i)) for j in range(n)])
       if mode=='rank_shift':
        # Key K migrates from the tail of one acquisition's first chunk to
        # the head of a newer second chunk. It is not a simultaneous union.
        e['entities'][0]=dict(entity_id='K',body_id='old' if i==0 else 'replacement')
       if mode=='reserved' and self.source=='roster-01':e['roster_source_id']='roster-00'
       tick=11+i*10+(1 if self.source=='roster-01' else 0)
       if mode=='stale' and i==1 and self.source=='roster-01':tick=12
       p=packet('roster-00' if mode=='wrong_source' and self.source=='roster-01' else self.source,tick)
       self.items.append(dict(kind='batch',packet=p,entity_update=e));originals[(self.source,i+1)]=e.copy()
     self.items.append(dict(kind='finish',tick=40 if self.source=='roster-00' else 41))
    def next(self):
     if mode=='guard_abort' and self.source=='roster-01':return dict(kind='abort',tick=11,reason='fixture_identity_guard_failed')
     item=self.items.pop(0) if self.items else None
     if item and item['kind']=='finish':self.done=True
     return item
    def complete(self):assert self.done
    def close(self):self.closed=True
    def receipt(self):return dict(fixture=True)
   def spawn(cmd,**kwargs):
    source='roster-'+cmd[cmd.index('--batch')+1];dest=Path(cmd[cmd.index('--output')+1]);dest.mkdir()
    partial=mode=='both_empty' or mode=='one_empty' and source=='roster-00'
    code=7 if partial else 0;reason='acquisition_retry_limit' if partial else 'duration_elapsed'
    value=dict(status='partial' if partial else 'complete',error=None,native_exit_code=code,cli_exit_code=code,
               capture_scope='read_only_user_gameplay',owned_child_exited=True,reader_thread_stopped=True,
               native_stop_reason=reason,native_terminal=dict(status='finished',complete=not partial,stop_reason=reason))
    if mode=='bad_receipt' and source=='roster-01':value['owned_child_exited']=False
    (dest/'result.json').write_text(json.dumps(value))
    job=types.SimpleNamespace(pid=100+len(jobs),closed=False,poll=lambda:code if source in readers and readers[source].done else None);jobs.append(job);return job
   def cleanup(workers,deadline):
    for job,log,child in workers:job.closed=True;log.close();child['owned_job_closed']=True
    return []
   args=types.SimpleNamespace(pid=1,seconds=20,practice_range=False,read_only_user_gameplay=True,output=str(out),storage_cohort_bytes=1048576,maximum_total_bytes=134217728)
   with patch.object(r.sys,'platform','win32'),patch.object(r,'qpf',return_value=1000),patch.object(r,'qpc',return_value=100000):
    result=r.run(args,configuration=self.config(),input_factory=Reader,spawn=spawn,cleanup=cleanup)
   self.assertTrue(all(j.closed for j in jobs));self.assertTrue(all(x.closed for x in readers.values()))
   rows=[json.loads(line) for path in sorted(out.glob('cohort-*/game-state.jsonl')) for line in path.read_bytes().splitlines()]
   return result,rows,originals
 def test_all_seventeen_preserved_with_independent_epoch_and_timestamps(self):
  result,rows,originals=self.exercise()
  self.assertEqual(result['status'],'complete');self.assertEqual(result['source_entity_rows'],{'roster-00':2,'roster-01':2})
  self.assertTrue(result['source_epochs_independent']);self.assertFalse(result['multi_source_snapshot'])
  entities=[x for x in rows if x['kind']=='entity_updates']
  self.assertEqual(len({e['entity_id'] for x in entities for e in x['entities']}),17)
  for row in entities:
   source=row['roster_source_id'];prior=originals[(source,row['segment'])]
   for key,value in prior.items():self.assertEqual(row[key],value)
   self.assertFalse(row['join_continuity']);self.assertFalse(row['multi_source_snapshot'])
  self.assertEqual([x['roster_source_tick'] for x in entities],[11,12,21,22])
 def test_unavailable_partition_does_not_erase_independent_source(self):
  result,rows,_=self.exercise('one_empty')
  self.assertEqual(result['status'],'partial');self.assertEqual(result['cli_exit_code'],7)
  self.assertFalse(result['source_unavailable']);self.assertIsNone(result['source_stop_reason'])
  self.assertEqual(result['source_entity_rows'],{'roster-00':0,'roster-01':2})
  self.assertEqual({x['roster_source_id'] for x in rows if x['kind']=='entity_updates'},{'roster-01'})
 def test_rank_shift_never_merges_lifetimes_or_claims_census_union(self):
  result,rows,originals=self.exercise('rank_shift')
  self.assertEqual(result['status'],'complete')
  observations=[row for row in rows if row['kind']=='entity_updates']
  self.assertEqual(len(observations),4)
  for row in observations:
   self.assertEqual(row['entities'],originals[(row['roster_source_id'],row['segment'])]['entities'])
   self.assertFalse(row['all_current_roster_claim']);self.assertFalse(row['multi_source_snapshot']);self.assertFalse(row['join_continuity'])
  self.assertEqual([row['entities'][0]['body_id'] for row in observations],['old','old','replacement','replacement'])
 def test_both_explicitly_empty_preserve_retryable_unavailability(self):
  result,rows,_=self.exercise('both_empty')
  self.assertTrue(result['source_unavailable']);self.assertEqual(result['source_stop_reason'],'acquisition_retry_limit')
  self.assertEqual(result['entity_rows'],0);self.assertEqual(len(rows),4)
 def test_foreign_source_reserved_metadata_and_bad_receipt_fail_closed(self):
  for mode in ('wrong_source','reserved','bad_receipt','stale','guard_abort'):
   with self.subTest(mode=mode):
    result,_,_=self.exercise(mode);self.assertEqual(result['status'],'failed');self.assertFalse(result['source_unavailable'])

if __name__=='__main__':unittest.main()
