import copy,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import run_combined_live as r
from test_combined_live_core import S,packet,observation,event
class RuntimeTests(unittest.TestCase):
 def exercise(self,mode=None,scope='controlled_practice',batches=6,storage=False,padding=0):
  with tempfile.TemporaryDirectory()as tmp:
   output=Path(tmp)/'out';readers={};jobs=[];commands=[]
   class Reader:
    def __init__(self,spec,c,pid):
     self.source=spec['id'];self.done=False;self.closed=False;readers[self.source]=self
     obs=[observation(10,20)]if self.source=='roster-00'else[]
     obs2=[observation(20,30)]if self.source=='roster-00'else[]
     self.items=[dict(kind='batch',packet=packet(self.source,10,observations=obs),entity_update={'kind':'entity_updates','entities':[],'padding':'x'*padding}if spec['kind']=='roster'else None),None,dict(kind='batch',packet=packet(self.source,20,observations=obs2,events=[event(20)]if spec['kind']=='damage'else[]),entity_update={'kind':'entity_updates','entities':[],'padding':'x'*padding}if padding and spec['kind']=='roster'else None),None,dict(kind='finish',tick=30)]
    def next(self):
     if mode=='reader'and self.source==('roster-02'if batches>1 else'roster-00'):raise ValueError('synthetic malformed source')
     if not self.items:return None
     item=self.items.pop(0)
     if item is not None:item['diagnostic']=dict(read_ticks=99998,verified_ticks=100001 if mode=='clock'else 99999,link_sha256='0'*64)
     if item and item['kind']=='finish':self.done=True
     return item
    def close(self):
     self.closed=True
     if mode=='close'and self.source=='roster-00':raise OSError('synthetic close failure')
    def complete(self):assert self.done
    def receipt(self):return {'validated_fake_lifecycle':True}
   class Job:
    closed=False
   class Process:
    def __init__(self,source):self.source=source;self.pid=100+len(jobs);self._overwatch_decoder_owned_job=Job();jobs.append(self)
    def poll(self):return(7 if mode=='partial'and self.source=='damage'else 0)if self.source in readers and readers[self.source].done else None
   def spawn(cmd,**kwargs):
    commands.append(cmd);name='damage'if'--worker'in cmd else'roster-'+cmd[cmd.index('--batch')+1]
    if mode=='spawn'and len(commands)==min(4,batches+1):raise OSError('synthetic launch failure')
    dest=Path(cmd[cmd.index('--output')+1]);dest.mkdir();partial=mode=='partial'and name=='damage'
    result=dict(capture_scope=scope,complete=not partial,status='partial'if partial else'complete',error=None,native_exit_code=7 if partial else 0,native_terminal={'complete':not partial});(dest/'result.json').write_text(json.dumps(result))
    return Process(name)
   def cleanup(workers,deadline):
    for p,log,child in workers:p._overwatch_decoder_owned_job.closed=True;child['owned_job_closed']=True;log.close()
    return[]
   c=dict(combined_storage_contract=1,python_sha256=r.digest(r.sys.executable),maximum_label_age_ms=500,roster_batches=[f'{i:02d}'for i in range(batches)],source_bundles=[dict(source='roster',path='sources/roster'),dict(source='damage',path='sources/damage')]);args=types.SimpleNamespace(pid=1,seconds=20,practice_range=scope=='controlled_practice',read_only_user_gameplay=scope=='read_only_user_gameplay',output=str(output),storage_cohort_bytes=1048576 if storage else None,maximum_total_bytes=134217728 if storage else None)
   scans=[];original_budget=r.check_directory_budget
   def scan(path,limit,**kwargs):scans.append(limit);return original_budget(path,limit,**kwargs)
   with patch.object(r,'check_directory_budget',scan),patch.object(r.sys,'platform','win32'),patch.object(r,'qpf',return_value=1000),patch.object(r,'qpc',return_value=100000):result=r.run(args,configuration=c,input_factory=Reader,spawn=spawn,cleanup=cleanup)
   self.assertTrue(all(limit==(134217728-1048576 if storage else 3*1024*1024*1024)for limit in scans))
   self.assertTrue(all(reader.closed for reader in readers.values()));self.assertEqual(result['capture_scope'],scope);self.assertEqual(result['limits']['workers'],batches+1);self.assertTrue(all(v>=0 for v in result['scheduler']['source_poll_thread_cpu_seconds'].values()));self.assertTrue(all(v>=0 for v in result['scheduler']['source_poll_seconds'].values()));
   if mode not in('reader','spawn','clock','storage_write'):
    timings=[json.loads(x)for x in(output/'merge-timing.jsonl').read_bytes().splitlines()];self.assertEqual(len(timings),3*(batches+1));self.assertTrue(all(x['first_ticks']<=x['verified_ticks']<=x['last_ticks']for x in timings))
   self.assertTrue(all(p._overwatch_decoder_owned_job.closed for p in jobs));self.assertFalse(any('run_selected_roster.py'in str(cmd)for cmd in commands));self.assertTrue('--worker'in commands[-1]or mode in('spawn','storage_write'))
   self.assertEqual(result['status'],'failed'if mode in('reader','spawn','clock','close','storage_write')else'partial'if mode=='partial'else'complete')
   self.assertTrue(all(('--read-only-user-gameplay'in cmd)==(scope=='read_only_user_gameplay')and('--practice-range'in cmd)==(scope=='controlled_practice')for cmd in commands));self.assertLessEqual(len(jobs),7);self.assertTrue((output/('storage-index.jsonl'if storage else'game-state.jsonl')).exists())
   if storage and mode=='storage_write':
    self.assertTrue(result['provisional_tail']);self.assertEqual(result['output_rows'],0);self.assertEqual(len((output/'storage-index.jsonl').read_bytes().splitlines()),1);return result,b'',b''
   if storage:
    from combined_storage import CombinedStorageIndex
    index=CombinedStorageIndex(output,maximum_cohorts=4096,maximum_total_bytes=134217728,maximum_index_bytes=67108864,maximum_cohort_bytes=1048576)
    with(output/'storage-index.jsonl').open('rb')as catalog:
     for line in catalog:index.consume(line)
    verified=index.complete();self.assertEqual(result['schema'],'overwatch-decoder.private.combined-run/2');self.assertEqual(result['storage_policy']['result_reserve_bytes'],1048576);self.assertLessEqual((output/'result.json').stat().st_size,1048576);self.assertEqual(verified['output_sha256'],result['output_sha256']);self.assertFalse(result['provisional_tail'])
    data=b''.join((p/'game-state.jsonl').read_bytes()for p in sorted(output.glob('cohort-*')));receipts=b''.join((p/'delivery-receipts.jsonl').read_bytes()for p in sorted(output.glob('cohort-*')))
   else:data=(output/'game-state.jsonl').read_bytes();receipts=(output/'delivery-receipts.jsonl').read_bytes();self.assertEqual(result['schema'],'overwatch-decoder.private.combined-run/1')
   return result,data,receipts
 def test_storage_rolls_without_worker_or_watermark_restart_and_preserves_bytes(self):
  flat,data,receipts=self.exercise(batches=1,padding=600000)
  rolled,actual,proofs=self.exercise(batches=1,storage=True,padding=600000)
  self.assertEqual(actual,data);self.assertEqual(proofs,receipts);self.assertGreater(rolled['storage_cohorts'],1)
  self.assertEqual(rolled['scheduler']['accepted_progress'],flat['scheduler']['accepted_progress']);self.assertEqual(rolled['source_outcomes'],flat['source_outcomes']);self.assertEqual(len(rolled['children']),2)
 def test_storage_partial_or_failed_never_claims_complete(self):
  for mode in ('partial','reader','spawn','clock','close'):self.exercise(mode,batches=1,storage=True)
 def test_unpaired_storage_failure_retains_only_provisional_prefix_and_cleans(self):
  class Broken(r.CombinedStorageWriter):
   def commit_receipt(self,data):raise OSError('synthetic receipt failure')
  with patch.object(r,'CombinedStorageWriter',Broken):self.exercise('storage_write',batches=1,storage=True)
 def test_storage_flags_fail_before_any_output_or_spawn(self):
  for cohort,total in ((None,134217728),(1048576,None),(True,134217728),(1048575,134217728),(268435457,134217728),(1048576,134217727),(1048576,68719476737)):
   with self.assertRaises(ValueError):r.storage_options(types.SimpleNamespace(storage_cohort_bytes=cohort,maximum_total_bytes=total),{'combined_storage_contract':1})
  for capability in ({},{'combined_storage_contract':True}):
   with self.assertRaisesRegex(ValueError,'capability'):r.storage_options(types.SimpleNamespace(storage_cohort_bytes=1048576,maximum_total_bytes=134217728),capability)
 def test_two_sources_complete_partial_and_cleanup(self):
  for mode in (None,'partial','spawn','reader','clock','close'):self.exercise(mode,batches=1)
 def test_close_failure_does_not_skip_other_source_closes(self):self.exercise('close')
 def test_invalid_diagnostic_stage_order_cleans_all(self):self.exercise('clock')
 def test_seven_direct_owned_workers_complete_and_cleanup(self):self.exercise()
 def test_user_gameplay_flag_and_receipts(self):self.exercise(scope='read_only_user_gameplay')
 def test_partial_is_not_complete(self):self.exercise('partial')
 def test_spawn_failure_cleans_owned_prefix(self):self.exercise('spawn')
 def test_malformed_source_aborts_and_cleans_all(self):self.exercise('reader')


class RosterOnlyWindowTests(unittest.TestCase):
 def test_menu_partial_then_independent_reacquired_windows(self):
  with tempfile.TemporaryDirectory() as root:
   root = Path(root)
   windows = [
    self.exercise(root/'menu', (), 7, 'acquisition_retry_limit'),
    self.exercise(root/'active', (('first-life',1),('new-life',2)), 7, 'acquisition_attempt_limit'),
    self.exercise(root/'next', (('new-window',1),), 0, 'duration_elapsed'),
   ]
   self.assertEqual([r['status'] for r, _ in windows], ['partial','partial','complete'])
   self.assertEqual([r['source_unavailable'] for r, _ in windows], [True,False,False])
   self.assertEqual([r['entity_rows'] for r, _ in windows], [0,2,1])
   self.assertEqual([r['output_rows'] for r, _ in windows], [2,4,3])
   for result, rows in windows:
    self.assertEqual(result['schema'], 'overwatch-decoder.private.combined-run/2')
    self.assertEqual(result['capture_scope'], 'read_only_user_gameplay')
    self.assertEqual(result['limits']['workers'], 1)
    self.assertEqual([row['combined_sequence'] for row in rows], list(range(len(rows))))
    self.assertFalse(result['whole_match_claim'])
    self.assertFalse(result['storage_policy']['continuous_capture'])
   self.assertTrue(all(row['join_continuity'] is False for row in rows if row['kind']=='entity_updates'))
   actual = [(row['session_id'],row['segment']) for _, rows in windows for row in rows
             if row['kind']=='entity_updates']
   self.assertEqual(actual, [('first-life',1),('new-life',2),('new-window',1)])

 def test_budget_or_identity_failure_is_never_retryable(self):
  with tempfile.TemporaryDirectory() as root:
   for code, reason in [(7,'session_output_limit'), (7,'storage_cohort_limit'),
                        (7,'output_io_error'), (4,'permission_denied'), (2,'identity_mismatch')]:
    with self.subTest(reason=reason):
     result, _ = self.exercise(Path(root)/reason, (), code, reason)
     self.assertEqual(result['status'], 'failed')
     self.assertEqual(result['cli_exit_code'], 1)
     self.assertFalse(result['source_unavailable'])

 def test_unconfirmed_cleanup_cannot_admit_a_gap(self):
  with tempfile.TemporaryDirectory() as root:
   result, _ = self.exercise(Path(root)/'cleanup', (), 7, 'fields_never_observed', cleanup_fails=True)
   self.assertEqual(result['status'], 'failed')
   self.assertFalse(result['source_unavailable'])

 def test_duration_with_unobserved_fields_retains_only_admitted_rows(self):
  with tempfile.TemporaryDirectory() as root:
   for entities in ((), (('verified-life',1),)):
    with self.subTest(entity_rows=len(entities)):
     result, rows = self.exercise(Path(root)/str(len(entities)), entities, 7, 'fields_never_observed')
     self.assertEqual(result['status'], 'partial')
     self.assertEqual(result['cli_exit_code'], 7)
     self.assertEqual(result['source_stop_reason'], 'fields_never_observed')
     self.assertEqual(result['source_unavailable'], not entities)
     self.assertEqual(result['entity_rows'], len(entities))
     self.assertEqual(len(rows), 2+len(entities))

 def test_controlled_scope_and_noncohort_modes_reject_before_output(self):
  with tempfile.TemporaryDirectory() as root:
   for overrides in (dict(practice_range=True,read_only_user_gameplay=False),
                     dict(storage_cohort_bytes=None,maximum_total_bytes=None)):
    with self.assertRaisesRegex(ValueError, 'roster_only_requires_gameplay_cohorts'):
     self.exercise(Path(root)/'invalid', (), 0, 'duration_elapsed', **overrides)
    self.assertFalse((Path(root)/'invalid').exists())

 def exercise(self, output, entities, code, reason, cleanup_fails=False, **overrides):
  config = dict(roster_only=True, combined_storage_contract=1, python_sha256=r.digest(r.sys.executable),
                maximum_label_age_ms=500, roster_batches=['00'],
                source_bundles=[dict(source='roster',path='sources/roster')])
  scope = 'read_only_user_gameplay'
  packets = []
  for index, (session, segment) in enumerate(entities):
   entity = dict(schema='overwatch-decoder.private.selected-compact/1', kind='entity_updates',
                 session_id=session, segment=segment, entities=[dict(entity_id=session)])
   packets.append(dict(kind='batch',packet=packet('roster-00',10+index),entity_update=entity))
  packets.append(dict(kind='finish',tick=30))
  pending = iter(packets)
  finished = False
  def next_packet():
   nonlocal finished
   item = next(pending, None)
   finished = item is not None and item['kind']=='finish'
   return item
  reader = types.SimpleNamespace(next=next_packet,complete=lambda: self.assertTrue(finished),
                                 close=lambda: None,receipt=lambda: {})
  spawned = []
  def spawn(cmd, **kwargs):
   spawned.append(cmd)
   self.assertIn('--read-only-user-gameplay',cmd)
   self.assertNotIn('--worker',cmd)
   dest = Path(cmd[cmd.index('--output')+1])
   dest.mkdir()
   result = dict(capture_scope=scope,status='complete' if code==0 else 'partial',error=None,
                 native_exit_code=code,cli_exit_code=code,owned_child_exited=True,reader_thread_stopped=True,
                 native_stop_reason=reason,native_terminal=dict(status='finished',complete=code==0,stop_reason=reason))
   (dest/'result.json').write_text(json.dumps(result))
   return types.SimpleNamespace(pid=100,poll=lambda: code if finished else None)
  def cleanup(workers, deadline):
   for _, log, _ in workers: log.close()
   return ['owned job close failed'] if cleanup_fails else []
  options = dict(pid=1,seconds=45,practice_range=False,read_only_user_gameplay=True,output=str(output),
                 storage_cohort_bytes=1048576,maximum_total_bytes=134217728)
  args = types.SimpleNamespace(**(options|overrides))
  with patch.object(r.sys,'platform','win32'),patch.object(r,'qpf',return_value=1000),patch.object(r,'qpc',return_value=100000):
   result = r.run(args,configuration=config,input_factory=lambda *_: reader,spawn=spawn,cleanup=cleanup)
  self.assertEqual(len(spawned),1)
  if result['status']=='failed': return result, []
  from combined_storage import CombinedStorageIndex
  index = CombinedStorageIndex(output,maximum_cohorts=4096,maximum_total_bytes=134217728,
                               maximum_index_bytes=67108864,maximum_cohort_bytes=1048576)
  with (output/'storage-index.jsonl').open('rb') as catalog:
   for line in catalog: index.consume(line)
  self.assertEqual(index.complete()['output_sha256'],result['output_sha256'])
  rows = [json.loads(line) for path in sorted(output.glob('cohort-*/game-state.jsonl'))
          for line in path.read_bytes().splitlines()]
  return result, rows

if __name__=='__main__':unittest.main()
