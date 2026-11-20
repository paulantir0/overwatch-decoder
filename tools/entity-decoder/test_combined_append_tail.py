import os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from combined_core import LineTail
class AppendTailTests(unittest.TestCase):
 def test_append_after_empty_read_reuses_handle_and_closes(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'x';t=LineTail(p);self.assertIsNone(t.next());p.write_bytes(b'a');self.assertIsNone(t.next());handle=t.handle
   with p.open('ab')as f:f.write(b'\nb\n')
   self.assertEqual(t.next(),b'a\n');self.assertIs(t.handle,handle);self.assertEqual(t.next(),b'b\n');self.assertIsNone(t.next());t.complete();self.assertTrue(handle.closed);self.assertIsNone(t.handle)
 def test_truncate_rejects_even_with_buffered_line(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'x';p.write_bytes(b'a\nb\n');t=LineTail(p);self.assertEqual(t.next(),b'a\n');handle=t.handle;p.write_bytes(b'')
   with self.assertRaisesRegex(ValueError,'truncated'):t.next()
   self.assertTrue(handle.closed)
 def test_replace_same_size_and_delete_are_not_reopens(self):
  for mode in('replace','delete'):
   with tempfile.TemporaryDirectory()as d:
    p=Path(d)/'x';p.write_bytes(b'a\nb\n');t=LineTail(p);t.next();handle=t.handle
    if mode=='replace':q=Path(d)/'new';q.write_bytes(b'c\nd\n');os.replace(q,p)
    else:p.unlink()
    with self.assertRaisesRegex(ValueError,'replaced'if mode=='replace'else'disappeared'):t.next()
    self.assertTrue(handle.closed)
 def test_open_race_replacement_is_closed_and_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'x';p.write_bytes(b'a\n');q=Path(d)/'q';q.write_bytes(b'b\n');t=LineTail(p);original=Path.open;opened=[]
   def raced(path,*a,**k):
    os.replace(q,p);f=original(path,*a,**k);opened.append(f);return f
   with patch.object(Path,'open',raced):
    with self.assertRaisesRegex(ValueError,'replaced'):t.next()
   self.assertTrue(opened[0].closed);self.assertIsNone(t.handle)
 def test_bounds_unread_and_partial_eof_close_handles(self):
  for data,limit,reason,complete in[(b'abc',2,'partial_line_bound',False),(b'ab\n',2,'line_bound',False),(b'abc',5,'partial_line_at_eof',True)]:
   with tempfile.TemporaryDirectory()as d:
    p=Path(d)/'x';p.write_bytes(data);t=LineTail(p,limit)
    if complete:t.next()
    with self.assertRaisesRegex(ValueError,reason):t.complete()if complete else t.next()
    self.assertIsNone(t.handle)
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'x';p.write_bytes(b'a\n');t=LineTail(p);t.next()
   with p.open('ab')as f:f.write(b'b\n')
   with self.assertRaisesRegex(ValueError,'unread'):t.complete()
   self.assertIsNone(t.handle)
 def test_permission_error_closes_open_handle_and_propagates(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'x';p.write_bytes(b'a\n');t=LineTail(p);t.next();handle=t.handle
   with patch.object(Path,'stat',side_effect=PermissionError('denied')):
    with self.assertRaises(PermissionError):t.next()
   self.assertTrue(handle.closed)
 def test_one_stat_per_poll_one_open_for_append_lifetime(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'x';p.write_bytes(b'a\nb\n');t=LineTail(p);stat=Path.stat;opened=Path.open;counts=dict(stat=0,open=0)
   def s(path,*a,**k):counts['stat']+=1;return stat(path,*a,**k)
   def o(path,*a,**k):counts['open']+=1;return opened(path,*a,**k)
   with patch.object(Path,'stat',s),patch.object(Path,'open',o):
    self.assertEqual(t.next(),b'a\n');self.assertEqual(t.next(),b'b\n');self.assertIsNone(t.next());t.complete()
   self.assertEqual(counts,dict(stat=4,open=1))
if __name__=='__main__':unittest.main()
