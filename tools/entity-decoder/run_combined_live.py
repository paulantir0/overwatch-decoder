"""Finite configured-owned-worker combined JSON with opt-in output cohorts. No target controls."""
import argparse,ctypes,hashlib,json,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
sys.path[:0]=[str(BASE),str(BASE/'private'),str(BASE/'sources/roster'),str(BASE/'sources/roster/lib'),str(BASE/'sources/roster/lib/entity_decoder'),str(BASE/'sources/damage'),str(BASE/'sources/damage/private'),str(BASE/'sources/damage/lib/entity_decoder')]
from combined_storage import CombinedStorageWriter
from stream_timing import TimingJournal
from runtime_jobs import spawn_producer
from runtime_roster import cleanup_owned
from live_file_budget import check_directory_budget
from combined_core import Epochs,SourceWindows,raw,need

ROSTER_PARTIAL_STOPS = frozenset((
 'acquisition_retry_limit', 'acquisition_attempt_limit', 'fields_never_observed',
))

def qpc():
 value=ctypes.c_longlong();need(ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(value)),'combined_qpc_failed');return value.value
def qpf():
 value=ctypes.c_longlong();need(ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(value)),'combined_qpf_failed');return value.value

def owned_spawn(command,**kwargs):
 def below_popen(*args,**options):return subprocess.Popen(*args,creationflags=getattr(subprocess,'BELOW_NORMAL_PRIORITY_CLASS',0),**options)
 return spawn_producer(command,popen=below_popen,**kwargs)

def digest(path):
 with Path(path).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def verify():
 m=json.loads((BASE/'inventory.json').read_bytes());need(len(m['files'])<=4096,'combined_inventory_bound')
 for e in m['files']:
  p=BASE/e['path'];need(p.resolve().is_relative_to(BASE)and p.is_file()and p.stat().st_size==e['size']and digest(p)==e['sha256'],'combined_pin:'+e['path'])
 c=json.loads((BASE/'config.json').read_bytes())
 for s in c['source_bundles']:
  d=BASE/s['path'];need(digest(d/'inventory.json')==s['inventory_sha256'],'source_inventory_pin')
  for e in json.loads((d/'inventory.json').read_bytes())['files']:
   p=d/e['path'];need(p.resolve().is_relative_to(d)and p.stat().st_size==e['size']and digest(p)==e['sha256'],'source_file_pin')
 return c

def specs(c,pid,seconds,output,capture_scope='controlled_practice'):
 scope_flag='--practice-range'if capture_scope=='controlled_practice'else'--read-only-user-gameplay'
 roots={s['source']:BASE/s['path']for s in c['source_bundles']};result=[];need(isinstance(c['roster_batches'],list) and 1<=len(c['roster_batches'])<=6 and len(set(c['roster_batches']))==len(c['roster_batches']),'configured_roster_sources')
 for batch in c['roster_batches']:
  name='roster-'+batch;d=output/name;b=roots['roster'];cmd=[sys.executable,'-B',str(b/'run_selected_live.py'),'--batch',batch,'--pid',str(pid),'--seconds',str(seconds),'--interval-ms','50',scope_flag,'--output',str(d)]
  result.append(dict(id=name,kind='roster',batch=batch,bundle=b,output=d,capture_scope=capture_scope,command=cmd))
 if c.get('roster_only') is True:
  limit=c.get('roster_source_limit',1)
  need(type(limit) is int and 1<=limit<=2,'roster_source_limit')
  need(capture_scope=='read_only_user_gameplay' and 1<=len(result)<=limit and set(roots)=={'roster'}
       and len(c['source_bundles'])==1,'roster_only_topology')
  return result
 b=roots['damage'];d=output/'damage';result.append(dict(id='damage',kind='damage',bundle=b,output=d,capture_scope=capture_scope,command=[sys.executable,'-B',str(b/'run_damage_auto.py'),'--worker','--pid',str(pid),'--seconds',str(seconds),scope_flag,'--output',str(d)]));return result

def outcome(spec,code,result):
 terminal=result.get('native_terminal');complete=(result.get('status')=='complete'if spec['kind']=='roster'else result.get('complete')is True)
 if code==0 and complete and result.get('native_exit_code')==0 and isinstance(terminal,dict)and terminal.get('complete')is True:return'complete'
 if code==7 and result.get('error')is None:return'partial'
 return'failed'

def roster_window_outcome(code, result):
 """Only admit verified, stopped roster windows and bounded acquisition gaps."""
 terminal = result.get('native_terminal')
 if (code not in (0, 7) or not isinstance(terminal, dict) or result.get('error') is not None
     or terminal.get('status') != 'finished' or terminal.get('complete') is not (code == 0)
     or any(type(result.get(key)) is not int or result[key] != code
            for key in ('native_exit_code','cli_exit_code'))
     or result.get('owned_child_exited') is not True or result.get('reader_thread_stopped') is not True):
  return 'failed'
 stop = terminal.get('stop_reason')
 if result.get('native_stop_reason') != stop:
  return 'failed'
 if code == 0 and stop == 'duration_elapsed' and result.get('status') == 'complete':
  return 'complete'
 if code == 7 and stop in ROSTER_PARTIAL_STOPS and result.get('status') == 'partial':
  return 'partial'
 return 'failed'

def storage_options(a,c):
 cohort=getattr(a,'storage_cohort_bytes',None);total=getattr(a,'maximum_total_bytes',None)
 need((cohort is None)==(total is None),'storage_flags_required_together')
 if cohort is None:return None
 need(type(cohort)is int and 1048576<=cohort<=268435456 and type(total)is int and 134217728<=total<=68719476736,'storage_option_bounds')
 need(type(c.get('combined_storage_contract'))is int and c['combined_storage_contract']==1,'storage_capability_not_declared')
 return dict(maximum_cohort_bytes=cohort,maximum_total_bytes=total,maximum_cohorts=4096,maximum_index_bytes=67108864)

def run(a,*,configuration=None,input_factory=None,spawn=None,cleanup=None):
 c=verify()if configuration is None else configuration;practice=bool(getattr(a,'practice_range',False));user=bool(getattr(a,'read_only_user_gameplay',False));need(practice!=user,'explicit_capture_scope');capture_scope='controlled_practice'if practice else'read_only_user_gameplay';need(sys.platform=='win32'and 20<=a.seconds<=60 and a.pid>0,'combined_scope');need(digest(sys.executable)==c['python_sha256'],'python_pin')
 storage_policy=storage_options(a,c);disk_limit=3*1024*1024*1024 if storage_policy is None else storage_policy['maximum_total_bytes']
 scan_limit=disk_limit if storage_policy is None else disk_limit-1048576
 roster_only=c.get('roster_only',False)
 need(type(roster_only) is bool,'roster_only_config')
 need(not roster_only or (user and storage_policy is not None),'roster_only_requires_gameplay_cohorts')
 output=Path(a.output).resolve();need(not output.exists()and not output.is_relative_to(BASE),'new_external_output_required')
 source_specs=specs(c,a.pid,a.seconds,output,capture_scope)
 output.mkdir(parents=True)
 if input_factory is None:
  from combined_binding import SourceInput
  input_factory=SourceInput
 spawn=owned_spawn if spawn is None else spawn;cleanup=cleanup_owned if cleanup is None else cleanup
 workers=[];children=[];inputs={};error=None;started=time.monotonic();deadline=started+a.seconds+40;last_scan=0;rows=total=0;hashstate=hashlib.sha256();engine=None;outcomes={};stream=None;receipts=None;storage=None;storage_summary=None;receipt_bytes=0;clock_frequency=qpf();timing=None;poll_cpu={};poll_calls={};poll_max={};poll_seconds={};merge_seconds=0.0;merge_peak_rows=merge_peak_bytes=0
 ids=[s['id']for s in source_specs];windows=SourceWindows(ids);poll_seconds=dict.fromkeys(ids,0.0);poll_cpu=dict.fromkeys(ids,0.0);poll_calls=dict.fromkeys(ids,0);poll_max=dict.fromkeys(ids,0.0)
 source_stop_reason=None;entity_rows=0;source_stop_reasons={};source_entity_rows=dict.fromkeys(ids,0);multiple_rosters=roster_only and len(ids)>1
 try:
  timing=TimingJournal(output/'merge-timing.jsonl')
  if storage_policy is None:stream=(output/'game-state.jsonl').open('xb');receipts=(output/'delivery-receipts.jsonl').open('xb')
  else:storage=CombinedStorageWriter(output,**dict(storage_policy,maximum_total_bytes=storage_policy['maximum_total_bytes']-1048576))
  def emit(value):
   nonlocal total,rows,receipt_bytes
   data=raw(dict(value,combined_sequence=rows,all_current_roster_claim=False,whole_match_claim=False,capture_scope=capture_scope))
   if storage is None:need(total+receipt_bytes+len(data)<=268435456,'combined_output_bound')
   before=qpc()
   if storage is None:need(stream.write(data)==len(data),'combined_short_write');stream.flush()
   else:storage.write_compact(data,rows)
   flushed=qpc();capture=value.get('timestamp',{}).get('end_ticks',value.get('confirmation',{}).get('frame_end_ticks'));frequency=value.get('timestamp',{}).get('monotonic_frequency',value.get('confirmation',{}).get('monotonic_frequency'));need(capture is None or frequency==clock_frequency and capture<=before<=flushed,'combined_delivery_clock');receipt=raw(dict(combined_sequence=rows,line_sha256=hashlib.sha256(data).hexdigest(),capture_end_qpc_ticks=capture,before_write_qpc_ticks=before,file_flushed_qpc_ticks=flushed,frequency=clock_frequency,capture_to_file_flush_ms=None if capture is None else(flushed-capture)*1000/clock_frequency,durability_verified=False,capture_scope=capture_scope))
   if storage is None:
    hashstate.update(data);total+=len(data);rows+=1;need(total+receipt_bytes+len(receipt)<=268435456,'combined_output_bound');need(receipts.write(receipt)==len(receipt),'combined_receipt_short_write');receipts.flush()
   else:
    storage.commit_receipt(receipt);hashstate.update(data);total+=len(data);rows+=1
   receipt_bytes+=len(receipt)
  engine=Epochs(ids,None if roster_only else 'damage',emit,maximum_age_ms=c['maximum_label_age_ms'],maximum_pending_rows=1024,maximum_pending_bytes=8*1024*1024)
  for spec in source_specs:
   child=dict(source=spec['id'],kind=spec['kind'],directory=spec['id']);children.append(child);log=(output/(spec['id']+'.log')).open('xb')
   try:process=spawn(spec['command'],cwd=spec['bundle'],stdout=log,stderr=log)
   except BaseException:log.close();raise
   child['owned_producer_pid']=process.pid;workers.append((process,log,child));inputs[spec['id']]=input_factory(spec,c,a.pid)
   emit(dict(schema='overwatch-decoder.private.combined-status/1',kind='source_start',source_id=spec['id'],owned_producer_pid=process.pid))
  def ingest(source,item):
   nonlocal entity_rows
   if item['kind']=='finish':engine.finish(source,item['tick'])
   elif item['kind']=='abort':raise ValueError('source_abort:'+source+':'+item['reason'])
   else:
    entity=item.get('entity_update')
    if roster_only:
     need(not item['packet'].get('events') and isinstance(entity,dict)
          and entity.get('schema')=='overwatch-decoder.private.selected-compact/1','roster_only_observation_shape')
     if multiple_rosters:
      need(item['packet']['source']==source,'roster_source_identity')
      need(not any(k in entity for k in ('roster_source_id','roster_source_tick','multi_source_snapshot')),'roster_source_reserved_metadata')
      entity=dict(entity,roster_source_id=source,roster_source_tick=item['packet']['tick'],multi_source_snapshot=False)
    engine.accept(item['packet'],entity)
    if roster_only:entity_rows+=1;source_entity_rows[source]+=1
   diagnostic=item.get('diagnostic')
   if diagnostic is not None:
    accepted=qpc();need(diagnostic['read_ticks']<=diagnostic['verified_ticks']<=accepted,'parent_diagnostic_stage_order');timing.write('parent_read_verified_accepted',frequency=clock_frequency,source=source,source_ticks=item.get('tick',item.get('packet',{}).get('tick')),first_ticks=diagnostic['read_ticks'],last_ticks=accepted,link_sha256=diagnostic['link_sha256'],verified_ticks=diagnostic['verified_ticks'],watermark=None if engine.stream is None else engine.stream.watermark)
  while len(outcomes)<len(source_specs):
   now=time.monotonic();need(now<deadline,'combined_wall_deadline')
   if now-last_scan>=.25:check_directory_budget(output,scan_limit,error_code='combined_disk_bound');last_scan=now
   progress=False
   for spec,(process,_,child)in zip(source_specs,workers):
    source=spec['id']
    if source in outcomes:continue
    code=process.poll();need(code is None or code in(0,7),'owned_source_failed:'+source)
    reader=inputs[source]
    if source not in windows.closed and source not in windows.heads:
     poll_started=time.perf_counter();cpu_started=time.thread_time()
     try:item=reader.next()
     finally:
      duration=time.perf_counter()-poll_started;poll_seconds[source]+=duration;poll_cpu[source]+=time.thread_time()-cpu_started;poll_calls[source]+=1;poll_max[source]=max(poll_max[source],duration)
     if item is not None:windows.offer(source,item);progress=True
     elif code is not None:reader.complete();raise ValueError('source_terminal_timestamp_missing:'+source)
    if source in windows.closed and code is not None:
     reader.complete();result=json.loads((spec['output']/'result.json').read_bytes());need(result.get('capture_scope', 'controlled_practice')==capture_scope,'source_receipt_capture_scope')
     state=roster_window_outcome(code,result) if roster_only else outcome(spec,code,result)
     child.update(exit_code=code,outcome=state,source_result_sha256=digest(spec['output']/'result.json'),source_receipt=reader.receipt())
     need(state!='failed','owned_source_failed:'+source);outcomes[source]=state
     if roster_only:
      source_stop_reason=result['native_terminal']['stop_reason'];source_stop_reasons[source]=source_stop_reason
     emit(dict(schema='overwatch-decoder.private.combined-status/1',kind='source_end',source_id=source,outcome=state,exit_code=code,source_result_sha256=child['source_result_sha256']))
   selected=windows.choose()
   if selected is not None:
    source,item=selected;merge_started=time.perf_counter();ingest(source,item);merge_seconds+=time.perf_counter()-merge_started;windows.commit(source);progress=True
    if engine.stream is not None:merge_peak_rows=max(merge_peak_rows,sum(p[2]for p in engine.stream._pending));merge_peak_bytes=max(merge_peak_bytes,sum(p[1]for p in engine.stream._pending))
   if not progress:time.sleep(.02)
  engine.abort('bounded_window_complete')
 except BaseException as exc:
  error=repr(exc)
  if engine is not None:
   try:engine.abort('combined_error')
   except BaseException as secondary:error+=';abort:'+repr(secondary)
 finally:
  failures=cleanup(workers,min(started+a.seconds+45,time.monotonic()+5))
  for source,reader in inputs.items():
   close=getattr(reader,'close',None)
   if close is not None:
    try:close()
    except BaseException as exc:failures.append('source_input_close:'+source+':'+repr(exc))
  for child in children:
   if child['source']in inputs:child.setdefault('source_receipt',inputs[child['source']].receipt())
  if stream is not None:stream.close()
  if receipts is not None:receipts.close()
  if timing is not None:timing.close()
  if storage is not None:
   try:
    if storage.failed or storage.pending is not None:storage.abort()
    else:storage.close(failed_start=bool(error or failures or len(outcomes)!=len(source_specs)))
    storage_summary=storage.summary()
    check_directory_budget(output,scan_limit,error_code='combined_disk_bound')
   except BaseException as exc:
    error=(error+';'if error else'')+'storage_finalize:'+repr(exc)
    storage.abort();storage_summary=storage.summary()
  status='failed'if error or failures or len(outcomes)!=len(source_specs) else'partial'if any(v!='complete'for v in outcomes.values())else'complete'
  result=dict(schema='overwatch-decoder.private.combined-run/1',status=status,capture_scope=capture_scope,cli_exit_code=1 if status=='failed'else 7 if status=='partial'else 0,error=error,cleanup_errors=failures,children=children,scheduler=dict(policy='least_advanced_actual_source_tick',accepted_progress=windows.progress,accepted_packets=windows.counts,buffered_head_ticks={k:(v['packet']['tick']if v['kind']=='batch'else v.get('tick'))for k,v in windows.heads.items()},maximum_heads=windows.maximum_heads,blocked_polls=windows.blocked_polls,source_poll_seconds=poll_seconds,source_poll_thread_cpu_seconds=poll_cpu,source_poll_calls=poll_calls,source_poll_max_wall_seconds=poll_max,timing=None if timing is None else timing.receipt(),merge_seconds=merge_seconds,peak_committed_merge_rows=merge_peak_rows,peak_committed_merge_bytes=merge_peak_bytes),source_outcomes=outcomes,output_rows=rows,output_bytes=total,delivery_receipt_bytes=receipt_bytes,output_sha256=hashstate.hexdigest(),elapsed_seconds=time.monotonic()-started,limits=dict(workers=len(source_specs),seconds=a.seconds,wall_seconds=a.seconds+45,disk_bytes=disk_limit,output_bytes=268435456 if storage_policy is None else storage_policy['maximum_total_bytes'],pending_rows_per_queue=1024,pending_bytes_per_queue=8*1024*1024,maximum_aggregate_pending_rows=2048,maximum_aggregate_pending_bytes=16*1024*1024),whole_match_claim=False,all_current_roster_claim=False,previous_values_carried=False,read_only=True,incoming_attribution='unknown')
  if storage_policy is not None:
   result['schema']='overwatch-decoder.private.combined-run/2';result['storage_policy']=dict(storage_policy,whole_output_tree_byte_limit=disk_limit,result_reserve_bytes=1048576,semantic_epoch_reset=False,continuous_capture=False)
   if storage_summary is not None:result.update(storage_summary)
  if roster_only:
   if multiple_rosters:
    # A single terminal summary is only meaningful when every source agrees.
    source_stop_reason=next(iter(source_stop_reasons.values())) if len(source_stop_reasons)==len(ids) and len(set(source_stop_reasons.values()))==1 else None
    result.update(roster_source_count=len(ids),source_stop_reasons=source_stop_reasons,source_entity_rows=source_entity_rows,multi_source_snapshot=False,source_epochs_independent=True)
   result.update(roster_only=True,entity_rows=entity_rows,source_stop_reason=source_stop_reason,
                 source_unavailable=status=='partial' and entity_rows==0 and source_stop_reason in ROSTER_PARTIAL_STOPS)
  result_bytes=raw(result)
  if storage_policy is not None:need(len(result_bytes)<=1048576,'combined_result_bound')
  (output/'result.json').write_bytes(result_bytes)
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--pid',type=int);p.add_argument('--seconds',type=int,default=45);g=p.add_mutually_exclusive_group();g.add_argument('--practice-range',action='store_true');g.add_argument('--read-only-user-gameplay',action='store_true');p.add_argument('--output');p.add_argument('--storage-cohort-bytes',type=int);p.add_argument('--maximum-total-bytes',type=int);p.add_argument('--check-package',action='store_true');a=p.parse_args()
 if a.check_package:verify();print(json.dumps(dict(package_verified=True)));sys.exit(0)
 r=run(a);print(json.dumps(r));sys.exit(r['cli_exit_code'])
