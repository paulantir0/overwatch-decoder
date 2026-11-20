"""Private bounded source tails and damage-authoritative join epochs."""
import hashlib,heapq,json,sys,os
from pathlib import Path
from collections import OrderedDict
sys.path.insert(0,str(Path(__file__).resolve().parent/'private'))
from event_join_stream import EventJoinStream

def need(ok,reason):
 if not ok:raise ValueError(reason)
def raw(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
class LineTail:
 """One bounded append handle, one fresh path stat per poll; never cache liveness."""
 def __init__(self,path,maximum_line=1048576):
  self.path=Path(path);self.maximum_line=maximum_line;self.offset=0;self.pending=b'';self.lines=0;self.handle=None;self.identity=None
 def _stat(self):
  try:info=self.path.stat()
  except FileNotFoundError:
   need(self.identity is None,'source_file_disappeared');return None
  identity=(info.st_dev,info.st_ino);need(info.st_ino!=0,'source_file_identity_unavailable')
  if self.identity is not None:need(identity==self.identity,'source_file_replaced')
  need(info.st_size>=self.offset,'source_file_truncated');return info
 def next(self):
  try:
   info=self._stat()
   if info is None:return None
   while b'\n'not in self.pending:
    if self.handle is None:
     handle=self.path.open('rb',buffering=0)
     try:
      actual=os.fstat(handle.fileno());identity=(actual.st_dev,actual.st_ino)
      need(identity==(info.st_dev,info.st_ino),'source_file_replaced');need(actual.st_size>=self.offset,'source_file_truncated')
      handle.seek(self.offset)
     except BaseException:handle.close();raise
     self.handle=handle;self.identity=identity
    chunk=self.handle.read(65536)
    if not chunk:need(len(self.pending)<=self.maximum_line,'source_partial_line_bound');return None
    self.offset+=len(chunk);self.pending+=chunk;need(len(self.pending)<=self.maximum_line+65536,'source_line_bound')
   line,self.pending=self.pending.split(b'\n',1);line+=b'\n';need(len(line)<=self.maximum_line,'source_line_bound');self.lines+=1;return line
  except BaseException:self.close();raise
 def close(self):
  if self.handle is not None:self.handle.close();self.handle=None
 def complete(self):
  try:
   need(not self.pending,'source_partial_line_at_eof');info=self._stat();need(info is None or info.st_size==self.offset,'source_unread_bytes')
  finally:self.close()
class ProjectionCache:
 def __init__(self,path):self.tail=LineTail(path);self.rows=OrderedDict();self.bytes=0
 def find(self,pin):
  while pin not in self.rows:
   line=self.tail.next()
   if line is None:return None
   row=json.loads(line);key=sha(line);self.rows[key]=(line,row);self.bytes+=len(line)
   while len(self.rows)>4:
    _,(old,_)=self.rows.popitem(last=False);self.bytes-=len(old)
   need(self.bytes<=4*1048576,'projection_cache_bound')
  return self.rows[pin]
class Epochs:
 def __init__(self,sources,damage_source,emit,maximum_age_ms=500,maximum_pending_rows=1024,maximum_pending_bytes=8*1024*1024):
  self.sources=list(sources);self.damage=damage_source;self.emit=emit;self.scope=None;self.stream=None;self.epoch=0;self.floor=0;self.pending=[];self.pending_bytes=0;self.counter=0;self.last={};self.finished={};self.maximum_age_ms=maximum_age_ms;self.maximum_pending_rows=maximum_pending_rows;self.maximum_pending_bytes=maximum_pending_bytes
 def _output(self,value):self.emit(dict(value,join_epoch=self.epoch))
 def _damage(self,result):
  payload=dict(result['payload']);need('target_label'not in payload,'reserved_target_label');payload.update(target_label=result['label'],target_label_status=result['status'],target_label_reason=result['reason'],join_time_qpc_ticks=result['tick'],join_validation='owned_pinned_worker_retrospective_endpoint_bracket_nonatomic');return payload
 def _flush(self,ready=(),force=False):
  if force:
   # The stream's bounded abort result already exists. Merge it with the
   # bounded entity heap without enlarging that heap during shutdown.
   ready=sorted(ready,key=lambda r:(r['tick'],r['source'],r['event_index']));i=0
   while self.pending or i<len(ready):
    if self.pending and(i==len(ready)or self.pending[0][:2]<=(ready[i]['tick'],1)):
     _,_,_,size,value=heapq.heappop(self.pending);self.pending_bytes-=size;self._output(value)
    else:self._output(self._damage(ready[i]));i+=1
   return
  for result in ready:self._queue(result['tick'],1,self._damage(result))
  watermark=None if self.stream is None else self.stream.watermark
  while self.pending and watermark is not None and self.pending[0][0]<=watermark:
   _,_,_,size,value=heapq.heappop(self.pending);self.pending_bytes-=size;self._output(value)
 def _queue(self,tick,kind,value):
  size=len(raw(value));need(len(self.pending)<self.maximum_pending_rows and self.pending_bytes+size<=self.maximum_pending_bytes,'combined_pending_bound');heapq.heappush(self.pending,(tick,kind,self.counter,size,value));self.counter+=1;self.pending_bytes+=size
 def close_epoch(self,reason):
  if self.stream is not None:self._flush(self.stream.abort(reason),force=True)
  else:self._flush(force=True)
  if self.scope is not None:self._output(dict(schema='overwatch-decoder.private.combined-status/1',kind='join_epoch_end',reason=reason,previous_values_carried=False,scope=self.scope))
  self.scope=None;self.stream=None
 def accept(self,packet,entity_update=None):
  source,tick=packet['source'],packet['tick'];need(source in self.sources and type(tick)is int and tick>=0,'combined_source_tick');need(source not in self.finished and(source not in self.last or tick>self.last[source]),'combined_source_order');self.last[source]=tick
  scope=packet.get('scope')
  if source==self.damage:
   if scope is None:self.close_epoch(packet.get('reason')or'damage_identity_unknown')
   elif self.scope!=scope:
    self.close_epoch('damage_scope_changed');self.epoch+=1;self.floor=tick;self.scope=scope;self.stream=EventJoinStream(scope=scope,sources=self.sources,maximum_age_ticks=scope['frequency']*self.maximum_age_ms//1000,maximum_pending_rows=self.maximum_pending_rows,maximum_pending_bytes=self.maximum_pending_bytes)
    for closed,terminal in self.finished.items():self.stream.finish(closed,terminal)
    self._output(dict(schema='overwatch-decoder.private.combined-status/1',kind='join_epoch_start',scope=scope,previous_values_carried=False,watermarks_reset=True))
  if entity_update is not None:
   entity_update=dict(entity_update,join_scope_match=self.scope is not None and scope==self.scope and tick>=self.floor,join_continuity=False)
   if self.stream is None:self._output(entity_update)
   else:self._queue(tick,0,entity_update)
  if self.stream is None:
   for event in packet.get('events',[]):self._output(self._damage(dict(event,source=source,tick=tick,label=None,status='unresolved',reason='no_valid_damage_scope')))
   return
  if scope!=self.scope or tick<self.floor:ready=self.stream.invalidate(source,tick,'pre_epoch_observation'if tick<self.floor else packet.get('reason')or'join_scope_mismatch_or_unknown')
  else:ready=self.stream.submit(source,tick,observations=packet.get('observations',[]),events=packet.get('events',[]))
  self._flush(ready)
 def finish(self,source,tick):
  need(source in self.sources and source not in self.finished and type(tick)is int and(source not in self.last or tick>self.last[source]),'combined_terminal_clock');self.finished[source]=tick
  if self.stream is not None:self._flush(self.stream.finish(source,tick))
  if len(self.finished)==len(self.sources):self._flush(force=True)
 def abort(self,reason):self.close_epoch(reason)

class SourceWindows:
 """One actual head per source, service the least-advanced source first.

 Ahead sources wait when the minimum source has no next head. Backlog remains
 in the already-bounded source files, never a larger in-memory merge queue.
 """
 def __init__(self,sources):self.sources=list(sources);self.progress=dict.fromkeys(sources);self.heads={};self.closed=set();self.counts=dict.fromkeys(sources,0);self.maximum_heads=0;self.blocked_polls=0
 def offer(self,source,item):
  need(source in self.progress and source not in self.closed and source not in self.heads,'source_window_offer');need(item['kind']in('batch','finish','abort'),'source_window_kind');self.heads[source]=item;self.maximum_heads=max(self.maximum_heads,len(self.heads))
 def choose(self):
  for source,item in self.heads.items():
   if item['kind']=='abort':return source,item
  active=[s for s in self.sources if s not in self.closed]
  if not active:return None
  unstarted=[s for s in active if self.progress[s]is None]
  candidates=unstarted or[s for s in active if self.progress[s]==min(self.progress[x]for x in active)]
  available=[s for s in candidates if s in self.heads]
  if not available:self.blocked_polls+=1;return None
  def tick(source):
   item=self.heads[source];return item['packet']['tick']if item['kind']=='batch'else item['tick']
  source=min(available,key=lambda s:(tick(s),self.sources.index(s)));return source,self.heads[source]
 def commit(self,source):
  item=self.heads.pop(source);tick=item['packet']['tick']if item['kind']=='batch'else item['tick'];need(type(tick)is int and(self.progress[source]is None or tick>self.progress[source]),'source_window_time');self.progress[source]=tick;self.counts[source]+=1
  if item['kind']=='finish':self.closed.add(source)
