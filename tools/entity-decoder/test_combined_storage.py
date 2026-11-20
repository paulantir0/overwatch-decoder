import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from combined_storage import (CombinedStorageWriter,CombinedStorageIndex,encoded,SCHEMA,CAPABILITIES)

class StorageTests(unittest.TestCase):
 def writer(self,p,**kwargs):
  opts=dict(maximum_cohort_bytes=700,maximum_total_bytes=131072,maximum_cohorts=8,maximum_index_bytes=65536,maximum_line_bytes=512,maximum_receipt_bytes=256);opts.update(kwargs);return CombinedStorageWriter(p,**opts)
 def reader(self,p,**kwargs):
  opts=dict(maximum_cohorts=8,maximum_total_bytes=131072,maximum_index_bytes=65536,maximum_cohort_bytes=700);opts.update(kwargs);return CombinedStorageIndex(p,**opts)
 def row(self,n):
  data=encoded(dict(schema='overwatch-decoder.private.selected-compact/1',combined_sequence=n,value='x'*140))
  receipt=encoded(dict(combined_sequence=n,line_sha256=hashlib.sha256(data).hexdigest()))
  return data,receipt
 def write(self,w,n):
  a,b=self.row(n);w.write_compact(a,n);w.commit_receipt(b);return a,b
 def fixture(self,p):
  w=self.writer(p);original=[]
  for n in range(4):original.append(self.write(w,n)[0])
  summary=w.close();records=(p/'storage-index.jsonl').read_bytes().splitlines(keepends=True);return summary,records,b''.join(original)
 def test_growth_during_seal_read_is_bounded_and_not_committed(self):
  from unittest.mock import patch
  for mode in ('data', 'receipt', 'after_eof'):
   with tempfile.TemporaryDirectory() as d:
    p=Path(d);_,records,_=self.fixture(p);r=self.reader(p);r.consume(records[0])
    original_open=Path.open;calls=[];grown=[False]
    class Growing:
     def __init__(self,stream,path):self.stream,self.path=stream,path
     def __enter__(self):return self
     def __exit__(self,*args):self.stream.close()
     def fileno(self):return self.stream.fileno()
     def grow(self):
      if not grown[0]:
       grown[0]=True
       target=p/'cohort-000001'/('delivery-receipts.jsonl' if mode=='receipt' else 'game-state.jsonl')
       with original_open(target,'ab') as output:output.write(b'x'*10000)
     def readline(self,size):
      calls.append(size)
      if mode!='after_eof' and self.path.name==('delivery-receipts.jsonl' if mode=='receipt' else 'game-state.jsonl'):self.grow()
      return self.stream.readline(size)
     def read(self,size):
      data=self.stream.read(size)
      if mode=='after_eof':self.grow()
      return data
    def opening(path,*args,**kwargs):
     stream=original_open(path,*args,**kwargs)
     return Growing(stream,path) if args==('rb',) else stream
    with patch.object(Path,'open',opening):
     with self.assertRaisesRegex(ValueError,'storage_file_growth|storage_file_size|storage_receipt_rows'):r.consume(records[1])
    self.assertTrue(grown[0]);self.assertEqual(r.rows,0);self.assertIsNotNone(r.active)
    self.assertLessEqual(max(calls),max(x['bytes'] for x in json.loads(records[1])['files'])+1)
 def test_three_rotations_concatenated_exact_bytes_global_sequence_and_receipts(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);summary,records,original=self.fixture(p);self.assertEqual(summary['storage_cohorts'],4);self.assertEqual(len(records),8)
   r=self.reader(p)
   for line in records:r.consume(line)
   result=r.complete();self.assertEqual(result['output_sha256'],hashlib.sha256(original).hexdigest());self.assertEqual(result['output_rows'],4)
   self.assertEqual(result,{k:v for k,v in summary.items()if k not in('provisional_tail','durability_verified')})
   self.assertFalse(CAPABILITIES['continuous_capture'])
 def test_open_prefix_is_provisional_and_returned_object_does_not_mutate_reader(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p);self.write(w,0);r=self.reader(p);opened=r.consume((p/'storage-index.jsonl').read_bytes());opened['directory']='tampered'
   self.assertEqual(r.rows,0);self.assertEqual(r.active['directory'],'cohort-000001')
   with self.assertRaisesRegex(ValueError,'provisional'):r.complete()
   w.close()
   for line in(p/'storage-index.jsonl').read_bytes().splitlines(keepends=True)[1:]:r.consume(line)
   self.assertEqual(r.complete()['output_rows'],1)
 def test_partial_pair_abort_closes_handles_without_seal_or_fabricated_row(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p);a,_=self.row(0);w.write_compact(a,0);streams=list(w.active['streams'])
   with self.assertRaisesRegex(ValueError,'unpaired'):w.close()
   self.assertTrue(all(s.closed for s in streams));self.assertTrue(w.index.closed);self.assertEqual(w.summary()['output_rows'],0);self.assertTrue(w.summary()['provisional_tail'])
   self.assertEqual(len((p/'storage-index.jsonl').read_bytes().splitlines()),1)
 def test_empty_failed_start_seal_has_null_not_invented_sequences(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p);w.close(failed_start=True);r=self.reader(p);lines=(p/'storage-index.jsonl').read_bytes().splitlines(keepends=True)
   for line in lines:r.consume(line)
   self.assertEqual(r.complete()['output_rows'],0);last=json.loads(lines[-1]);self.assertIsNone(last['first_combined_sequence']);self.assertIsNone(last['last_combined_sequence'])
 def test_wrong_seal_chain_or_order_rejected_without_commit(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);_,records,_=self.fixture(p)
   for mode in('hash','ordinal','directory','extra','first'):
    r=self.reader(p);r.consume(records[0]);bad=json.loads(records[1])
    if mode=='hash':bad['previous_seal_sha256']='a'*64
    elif mode=='ordinal':bad['ordinal']=2
    elif mode=='directory':bad['directory']='../escape'
    elif mode=='extra':bad['unexpected']=True
    else:bad['first_combined_sequence']=1
    with self.assertRaises(ValueError):r.consume(encoded(bad))
    self.assertEqual(r.rows,0);self.assertIsNotNone(r.active);r.consume(records[1]);self.assertEqual(r.rows,1)
 def test_same_size_data_tamper_and_receipt_link_mismatch_fail(self):
  for mode in('data','receipt'):
   with tempfile.TemporaryDirectory()as d:
    p=Path(d);_,records,_=self.fixture(p);r=self.reader(p);r.consume(records[0]);seal=json.loads(records[1])
    if mode=='data':f=p/'cohort-000001/game-state.jsonl';f.write_bytes(f.read_bytes().replace(b'xxxxx',b'yyyyy',1))
    else:
     f=p/'cohort-000001/delivery-receipts.jsonl';value=json.loads(f.read_bytes());value['line_sha256']='b'*64;f.write_bytes(encoded(value));seal['files'][1]['sha256']=hashlib.sha256(f.read_bytes()).hexdigest()
    with self.assertRaises(ValueError):r.consume(encoded(seal))
    self.assertEqual(r.rows,0)
 def test_truncated_files_index_and_unsafe_links_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);_,records,_=self.fixture(p)
   with self.assertRaises(ValueError):self.reader(p).consume(records[0][:-1])
   r=self.reader(p);r.consume(records[0]);f=p/'cohort-000001/game-state.jsonl';original=f.read_bytes();f.write_bytes(original[:-1])
   with self.assertRaises(ValueError):r.consume(records[1])
   f.unlink();other=p/'other';other.write_bytes(original);f.symlink_to(other)
   with self.assertRaisesRegex(ValueError,'link'):self.reader(p).consume(records[0])
 def test_duplicate_keys_and_boolean_sequence_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);_,records,_=self.fixture(p);r=self.reader(p)
   with self.assertRaises(ValueError):r.consume(records[0].replace(b'"ordinal":1',b'"ordinal":1,"ordinal":1'))
   r.consume(records[0]);seal=json.loads(records[1]);seal['first_combined_sequence']=False
   with self.assertRaises(ValueError):r.consume(encoded(seal))
 def test_cohort_and_total_budgets_do_not_expand_or_delete_prefix(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p,maximum_cohorts=1);self.write(w,0)
   with self.assertRaisesRegex(ValueError,'cohort_limit'):self.write(w,1)
   self.assertTrue((p/'cohort-000001/game-state.jsonl').exists());self.assertTrue(w.index.closed)
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p,maximum_total_bytes=8192)
   with self.assertRaisesRegex(ValueError,'total_budget'):
    for i in range(8):self.write(w,i)
   self.assertLessEqual(w.total_charged,8192)
 def test_empty_seal_is_sole_terminal_and_normal_empty_close_refused(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p);w.close(failed_start=True);r=self.reader(p)
   records=(p/'storage-index.jsonl').read_bytes().splitlines(keepends=True)
   for line in records:r.consume(line)
   next_open=encoded(dict(schema=SCHEMA,kind='open',ordinal=2,directory='cohort-000002',previous_seal_sha256=hashlib.sha256(records[-1]).hexdigest()))
   with self.assertRaisesRegex(ValueError,'open_order'):r.consume(next_open)
   r.complete()
   with self.assertRaisesRegex(ValueError,'closed'):r.consume(next_open)
  with tempfile.TemporaryDirectory()as d:
   w=self.writer(Path(d))
   with self.assertRaisesRegex(ValueError,'empty_terminal'):w.close()
   self.assertTrue(w.summary()['provisional_tail'])
 def test_cohort_budget_applies_to_both_files_combined(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);_,records,_=self.fixture(p);seal=json.loads(records[1]);cap=max(f['bytes']for f in seal['files']);r=self.reader(p,maximum_cohort_bytes=cap);r.consume(records[0])
   with self.assertRaisesRegex(ValueError,'cohort_budget'):r.consume(records[1])
   self.assertEqual(r.rows,0)
 def test_nonfinite_index_data_and_receipt_rejected_even_with_new_hashes(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);_,records,_=self.fixture(p)
   with self.assertRaisesRegex(ValueError,'nonfinite'):self.reader(p).consume(records[0].replace(b'null',b'NaN'))
  for file in('game-state.jsonl','delivery-receipts.jsonl'):
   with tempfile.TemporaryDirectory()as d:
    p=Path(d);_,records,_=self.fixture(p);seal=json.loads(records[1]);target=p/'cohort-000001'/file;value=json.loads(target.read_bytes());value['bad']=float('inf');target.write_bytes((json.dumps(value,separators=(',',':'))+'\n').encode())
    if file=='game-state.jsonl':
     receipt=p/'cohort-000001/delivery-receipts.jsonl';proof=json.loads(receipt.read_bytes());proof['line_sha256']=hashlib.sha256(target.read_bytes()).hexdigest();receipt.write_bytes(encoded(proof))
    for i,name in enumerate(('game-state.jsonl','delivery-receipts.jsonl')):
     raw=(p/'cohort-000001'/name).read_bytes();seal['files'][i].update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    r=self.reader(p);r.consume(records[0])
    with self.assertRaisesRegex(ValueError,'nonfinite'):r.consume(encoded(seal))
    self.assertEqual(r.rows,0)
 def test_seal_io_failure_retains_provisional_prefix_and_closes_handles(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p);self.write(w,0);files=list(w.active['streams']);original=w.index
   class FailedSeal:
    def write(self,data):
     if b'"kind":"seal"'in data:raise OSError('fixture seal failure')
     return original.write(data)
    def flush(self):original.flush()
    def close(self):original.close()
   w.index=FailedSeal()
   with self.assertRaisesRegex(OSError,'fixture'):w.close()
   self.assertTrue(original.closed);self.assertTrue(all(f.closed for f in files));self.assertTrue(w.summary()['provisional_tail'])
   r=self.reader(p);r.consume((p/'storage-index.jsonl').read_bytes())
   with self.assertRaisesRegex(ValueError,'provisional'):r.complete()
 def test_utf8_bom_and_non_utf8_index_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);_,records,_=self.fixture(p)
   with self.assertRaisesRegex(ValueError,'encoding'):self.reader(p).consume(b'\xef\xbb\xbf'+records[0])
   with self.assertRaises((ValueError,UnicodeError)):self.reader(p).consume(b'\xff'+records[0])
 def test_existing_paths_refused(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);w=self.writer(p);w.close(failed_start=True)
   with self.assertRaises(FileExistsError):self.writer(p)

if __name__=='__main__':unittest.main()
