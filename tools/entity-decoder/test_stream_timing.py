import json,tempfile,unittest
from pathlib import Path
from stream_timing import TimingJournal
class TimingTests(unittest.TestCase):
 def test_order_and_exact_link(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'timing';j=TimingJournal(p)
   for a,b in[(20,19),(-1,2),(True,2),(0,2)]:
    with self.assertRaisesRegex(ValueError,'order'):j.write('read',frequency=10,source='a',source_ticks=1,first_ticks=a,last_ticks=b,link_sha256='0'*64)
   j.write('read',frequency=10,source='a',source_ticks=1,first_ticks=2,last_ticks=3,link_sha256='a'*64);j.close();r=json.loads(p.read_bytes());self.assertEqual((r['first_ticks'],r['last_ticks'],r['link_sha256']),(2,3,'a'*64))
 def test_rows_and_bytes_saturate_without_stream_failure(self):
  for rows,bytes in[(1,4096),(20,1)]:
   with tempfile.TemporaryDirectory()as d:
    p=Path(d)/'timing';j=TimingJournal(p,maximum_rows=rows,maximum_bytes=bytes)
    for i in range(10):j.write('publish',frequency=10,source='x',source_ticks=0,first_ticks=i,last_ticks=i,link_sha256='0'*64)
    r=j.receipt();self.assertLessEqual(r['rows'],rows);self.assertLessEqual(r['bytes'],bytes);self.assertEqual(r['rows']+r['dropped_rows'],10);j.close()
 def test_line_bound_and_close(self):
  with tempfile.TemporaryDirectory()as d:
   j=TimingJournal(Path(d)/'t')
   with self.assertRaisesRegex(ValueError,'line_bound'):j.write('x',frequency=1,source='x'*5000,source_ticks=0,first_ticks=0,last_ticks=0,link_sha256='0'*64)
   j.close();j.close()
   with self.assertRaisesRegex(ValueError,'closed'):j.write('x',frequency=1,source='a',source_ticks=0,first_ticks=0,last_ticks=0,link_sha256='0'*64)
if __name__=='__main__':unittest.main()
