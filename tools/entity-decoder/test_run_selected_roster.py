from pathlib import Path
import io,json,tempfile,types,unittest
from unittest.mock import patch
import run_selected_roster as p

def frame(seq=1,segment=1,start=10):
 return dict(schema='overwatch-decoder.private.selected-compact/1',source='process_memory',scope='configured_controller_window',
  entities=[dict(entity_id='body:x',hero=None,hero_reason='unmapped',health=200.,position=[1.,2.,3.],relation='enemy')],
  session_id='a'*32,event_sequence=seq,segment=segment,timestamp=dict(start_ticks=start,end_ticks=start+1,monotonic_frequency=1000),source_clock=dict(kind='windows_qpc'),durability_verified=False)
class Job:
 def __init__(self):self.closed=False
 def terminate_and_close(self,deadline):self.closed=True
class Process:
 def __init__(self,code):self.pid=123;self.code=code;self._overwatch_decoder_owned_job=Job()
 def poll(self):return self.code
class Tests(unittest.TestCase):
 def test_merge_unchanged_values_source_hash_and_per_batch_order(self):
  out=io.BytesIO();merge=p.Merge(out,['00','06','12'])
  a=frame();line=p.raw(a);result=merge.consume('00',line)
  for key,value in a.items():self.assertEqual(result[key],value)
  self.assertEqual(result['input_sha256'],p.sha(line));self.assertEqual(result['source_batch'],'00')
  merge.consume('06',line)
  with self.assertRaisesRegex(ValueError,'source_order'):merge.consume('00',line)
  backward=frame(2,start=5)
  with self.assertRaisesRegex(ValueError,'source_clock'):merge.consume('00',p.raw(backward))
  self.assertEqual(merge.frames,{'00':1,'06':1,'12':0})
 def test_tail_partial_write_then_complete_and_final_rejects_partial(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'selected.jsonl';line=p.raw(frame());path.write_bytes(line[:20]);merge=p.Merge(io.BytesIO(),['00']);tail=p.Tail(path,'00',merge)
   self.assertEqual(tail.poll(),0)
   with path.open('ab') as f:f.write(line[20:])
   self.assertEqual(tail.poll(final=True),1)
   with path.open('ab') as f:f.write(b'{')
   with self.assertRaisesRegex(ValueError,'partial_line'):tail.poll(final=True)
 def test_parent_outcome_never_promotes_partial_or_missing(self):
  batches=['00','06','12'];complete=[dict(batch=b,outcome='complete',exit_code=0) for b in batches]
  self.assertEqual(p.parent_outcome(complete,batches)['status'],'complete')
  partial=[*complete[:2],dict(batch='12',outcome='partial',exit_code=7)]
  self.assertEqual(p.parent_outcome(partial,batches),dict(status='partial',cli_exit_code=7))
  self.assertEqual(p.parent_outcome(complete[:2],batches)['status'],'failed')
  self.assertEqual(p.parent_outcome(complete,batches,cleanup_errors=['job failed'])['status'],'failed')
 def test_configured_fake_process_counts_close_owned_jobs_and_preserve_partial(self):
  for batches,partial_batch in [(['solo'],None),([f'p{i}' for i in range(8)],None),(['00','06','12'],None),(['00','06','12'],'06')]:
   config=dict(python_sha256='ab'*32,batches=batches)
   with self.subTest(partial=partial_batch),tempfile.TemporaryDirectory() as d:
    output=Path(d)/'out';processes=[];real_digest=p.digest_file
    def spawn(command,**kwargs):
     batch=command[command.index('--batch')+1];dest=Path(command[command.index('--output')+1]);dest.mkdir()
     (dest/'selected.jsonl').write_bytes(p.raw(frame()))
     partial=batch==partial_batch;code=7 if partial else 0
     (dest/'result.json').write_bytes(p.raw(dict(status='partial' if partial else 'complete',native_exit_code=code,
      native_terminal=dict(complete=not partial),native_stop_reason='limit' if partial else 'duration_elapsed')))
     process=Process(code);processes.append(process);self.assertEqual(kwargs['stdout'],kwargs['stderr']);return process
    package=Path(d)/'package';package.mkdir();(package/'config.json').write_bytes(p.raw(config));(package/'inventory.json').write_bytes(b'{}')
    args=types.SimpleNamespace(pid=999,seconds=20,interval_ms=50,practice_range=True,output=str(output))
    with patch.object(p,'BASE',package),patch.object(p.sys,'platform','win32'),patch.object(p,'verify_package'),patch.object(p,'spawn_producer',side_effect=spawn),\
         patch.object(p,'digest_file',side_effect=lambda path:config['python_sha256'] if str(path)==p.sys.executable else real_digest(path)):
     result=p.run(args)
    self.assertEqual(result['status'],'partial' if partial_batch else 'complete')
    self.assertTrue(all(x._overwatch_decoder_owned_job.closed for x in processes));self.assertEqual(len(processes),len(batches))
    rows=[json.loads(x) for x in (output/'entities.jsonl').read_text().splitlines()]
    self.assertEqual(sum(r.get('kind')=='entity_updates' for r in rows),len(batches))
    self.assertFalse(result['all_current_roster_claim'])
 def test_batch_ids_are_explicit_unique_and_bounded(self):
  for value in ([],[str(n) for n in range(9)],['same','same'],['../escape'],['/root'],[True],None):
   with self.assertRaisesRegex(ValueError,'configured_batch_ids'):p.configured_batches(dict(batches=value))
  self.assertEqual(p.configured_batches(dict(batches=['custom-a','z9'])),('custom-a','z9'))
  merge=p.Merge(io.BytesIO(),['custom-a'])
  with self.assertRaisesRegex(ValueError,'merge_line_bound'):merge.consume('00',p.raw(frame()))
  empty=frame();empty['entities']=[];empty['empty_partition']=dict(acquisition_empty=True,current_occupancy='unknown')
  result=merge.consume('custom-a',p.raw(empty))
  self.assertEqual(result['entities'],[]);self.assertEqual(result['empty_partition'],empty['empty_partition'])

 def test_child_job_enrollment_precedes_any_native_spawn(self):
  import run_selected_live as child
  with patch.object(child.os,'name','nt'),patch.object(child,'enroll_current_producer',side_effect=OSError('assignment denied')) as enroll, \
       patch.object(child.subprocess,'Popen') as spawn:
   with self.assertRaisesRegex(OSError,'assignment denied'):child.run(types.SimpleNamespace(job_handle=11))
   enroll.assert_called_once_with(11);spawn.assert_not_called()

 def test_spawn_failure_cleans_already_owned_jobs(self):
  config=dict(python_sha256='ab'*32,batches=['00','06','12']);process=Process(0)
  with tempfile.TemporaryDirectory() as d:
   package=Path(d)/'package';package.mkdir();(package/'config.json').write_bytes(p.raw(config));(package/'inventory.json').write_bytes(b'{}')
   args=types.SimpleNamespace(pid=999,seconds=20,interval_ms=50,practice_range=True,output=str(Path(d)/'out'))
   real_digest=p.digest_file
   with patch.object(p,'BASE',package),patch.object(p.sys,'platform','win32'),patch.object(p,'verify_package'),\
        patch.object(p,'spawn_producer',side_effect=[process,OSError('launch failed')]),\
        patch.object(p,'digest_file',side_effect=lambda path:config['python_sha256'] if str(path)==p.sys.executable else real_digest(path)):
    result=p.run(args)
   self.assertEqual(result['status'],'failed');self.assertTrue(process._overwatch_decoder_owned_job.closed)
if __name__=='__main__':unittest.main()
