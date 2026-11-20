"""Bounded diagnostic sidecars; original stream bytes and source clocks stay intact."""
import ctypes,hashlib,json

class TimingJournal:
 def __init__(self,path,*,maximum_rows=32768,maximum_bytes=16777216):
  if type(maximum_rows)is not int or not 1<=maximum_rows<=32768 or type(maximum_bytes)is not int or not 1<=maximum_bytes<=16777216:raise ValueError('timing_limits')
  self.stream=path.open('xb');self.maximum_rows=maximum_rows;self.maximum_bytes=maximum_bytes;self.rows=self.bytes=self.dropped=0;self.hash=hashlib.sha256();self.closed=False
 def write(self,stage,*,frequency,source,source_ticks,first_ticks,last_ticks,link_sha256,**extra):
  if self.closed:raise ValueError('timing_closed')
  if type(frequency)is not int or frequency<=0 or any(type(v)is not int or v<0 for v in(source_ticks,first_ticks,last_ticks))or not source_ticks<=first_ticks<=last_ticks:raise ValueError('timing_stage_order')
  if not isinstance(link_sha256,str)or len(link_sha256)!=64 or any(c not in'0123456789abcdef'for c in link_sha256):raise ValueError('timing_link')
  row=dict(extra,schema='overwatch-decoder.stream-timing/1',stage=stage,source=source,source_ticks=source_ticks,first_ticks=first_ticks,last_ticks=last_ticks,frequency=frequency,clock='Windows_QueryPerformanceCounter',link_sha256=link_sha256,durability_verified=False)
  data=(json.dumps(row,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
  if len(data)>4096:raise ValueError('timing_line_bound')
  if self.rows>=self.maximum_rows or self.bytes+len(data)>self.maximum_bytes:self.dropped+=1;return False
  if self.stream.write(data)!=len(data):raise OSError('timing_short_write')
  self.stream.flush();self.hash.update(data);self.rows+=1;self.bytes+=len(data);return True
 def receipt(self):return dict(rows=self.rows,bytes=self.bytes,dropped_rows=self.dropped,maximum_rows=self.maximum_rows,maximum_bytes=self.maximum_bytes,sha256=self.hash.hexdigest(),diagnostic_only=True,durability_verified=False)
 def close(self):
  if not self.closed:self.stream.close();self.closed=True

def qpc():
 value=ctypes.c_longlong()
 if not ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(value)):raise OSError('timing_qpc_failed')
 return value.value
