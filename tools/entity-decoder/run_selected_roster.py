"""Configured finite controlled-Practice windows; updates, never cached snapshots."""
from __future__ import annotations
import argparse,json,os,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
sys.path[:0]=[str(BASE),str(BASE/'lib'),str(BASE/'lib/entity_decoder')]
from run_selected_live import raw,sha,parse,require,digest_file,verify_package,configured_batches
from live_file_budget import check_directory_budget
from runtime_jobs import spawn_producer
from runtime_roster import cleanup_owned

MAX_LINE=512*1024
MAX_TOTAL=1536*1024*1024

class Merge:
    def __init__(self,output,batches,limit=512*1024*1024):
        self.batches=configured_batches(dict(batches=list(batches)))
        self.output=output;self.limit=limit;self.bytes=self.sequence=0;self.order={};self.frames={batch:0 for batch in self.batches}
    def write(self,event):
        data=raw(event);require(self.bytes+len(data)<=self.limit,'merged_output_bound')
        require(self.output.write(data)==len(data),'merged_short_write');self.output.flush();self.bytes+=len(data)
    def consume(self,batch,line):
        require(batch in self.batches and isinstance(line,bytes) and 0<len(line)<=MAX_LINE and line.endswith(b'\n'),'merge_line_bound')
        event=parse(line)
        require(event.get('schema')=='overwatch-decoder.private.selected-compact/1' and event.get('scope')=='configured_controller_window'
                and event.get('source')=='process_memory' and isinstance(event.get('entities'),list),'merge_input_schema')
        require(not {'source_batch','input_sha256','merge_sequence','kind'} & set(event),'merge_reserved_metadata')
        session,seq,segment=event.get('session_id'),event.get('event_sequence'),event.get('segment')
        require(isinstance(session,str) and type(seq) is int and seq>=0 and type(segment) is int and segment>=1,'merge_epoch')
        previous=self.order.get(batch)
        require(previous is None or session==previous[0] and seq>previous[1] and segment>=previous[2],'merge_source_order')
        timing=event.get('timestamp',{});start,end=timing.get('start_ticks'),timing.get('end_ticks')
        require(type(start) is int and type(end) is int and 0<=start<=end
                and (previous is None or start>=previous[3]),'merge_source_clock')
        self.order[batch]=(session,seq,segment,end)
        # The original compact object's fields and entity objects are unchanged.
        result=dict(event,kind='entity_updates',source_batch=batch,input_sha256=sha(line),merge_sequence=self.sequence)
        self.write(result);self.sequence+=1;self.frames[batch]+=1
        return result
    def status(self,batch,kind,**values):
        require(batch in self.batches and kind in ('batch_start','batch_end'),'merge_status_kind')
        self.write(dict(schema='overwatch-decoder.private.selected-roster-status/1',kind=kind,source_batch=batch,
                        merge_sequence=self.sequence,scope='configured_controller_windows',**values));self.sequence+=1

class Tail:
    def __init__(self,path,batch,merge):self.path=Path(path);self.batch=batch;self.merge=merge;self.offset=0;self.pending=b''
    def poll(self,*,final=False,deadline=None):
        if not self.path.exists():
            require(not final,'child_selected_output_missing');return 0
        require(self.path.stat().st_size>=self.offset,'child_selected_file_truncated')
        count=0
        with self.path.open('rb') as stream:
            stream.seek(self.offset)
            for _ in range(8192 if final else 16):  # <=1 MiB per poll; final drain <=512 MiB.
                require(deadline is None or time.monotonic()<deadline,'merge_drain_deadline')
                chunk=stream.read(65536)
                if not chunk:break
                self.offset+=len(chunk);self.pending+=chunk
                while b'\n' in self.pending:
                    line,self.pending=self.pending.split(b'\n',1)
                    self.merge.consume(self.batch,line+b'\n');count+=1
                require(len(self.pending)<=MAX_LINE,'child_line_bound')
        if final:
            require(self.path.stat().st_size==self.offset and not self.pending,'child_unmerged_or_partial_line')
        return count

def child_outcome(code,result):
    if not isinstance(result,dict):return 'failed'
    terminal=result.get('native_terminal',{})
    if (code==0 and result.get('status')=='complete' and result.get('native_exit_code')==0
            and isinstance(terminal,dict) and terminal.get('complete') is True):return 'complete'
    if result.get('status')=='partial' and code!=0:return 'partial'
    return 'failed'

def parent_outcome(children,batches,error=None,cleanup_errors=()):
    if (error is not None or cleanup_errors or len(children)!=len(batches)
            or {c.get('batch') for c in children}!=set(batches)
            or any(c.get('outcome')=='failed' for c in children)):
        return dict(status='failed',cli_exit_code=1)
    if all(c.get('outcome')=='complete' and c.get('exit_code')==0 for c in children):return dict(status='complete',cli_exit_code=0)
    return dict(status='partial',cli_exit_code=7)

def run(args):
    require(sys.platform=='win32','windows_roster_runner_required');verify_package()
    config=parse((BASE/'config.json').read_bytes());require(digest_file(sys.executable)==config['python_sha256'],'python_pin_failed')
    batches=configured_batches(config)
    require(args.practice_range and 20<=args.seconds<=60 and args.pid>0 and 10<=args.interval_ms<=1000,'roster_scope_or_bounds')
    output=Path(args.output).resolve();require(not output.exists() and not output.is_relative_to(BASE),'new_external_output_required')
    output.mkdir(parents=True)
    workers=[];children=[];tails={};error=None;cleanup_errors=[];started=time.monotonic();deadline=started+min(150,args.seconds+30)
    try:
        with (output/'entities.jsonl').open('xb') as stream:
            merge=Merge(stream,batches)
            for batch in batches:
                child=dict(batch=batch,directory='batch'+batch);children.append(child)
                log=(output/f'batch{batch}-runner.log').open('xb')
                try:
                    command=[sys.executable,str(BASE/'run_selected_live.py'),'--batch',batch,'--pid',str(args.pid),
                             '--seconds',str(args.seconds),'--interval-ms',str(args.interval_ms),'--practice-range',
                             '--output',str(output/child['directory'])]
                    process=spawn_producer(command,cwd=BASE,stdout=log,stderr=log)
                except BaseException:log.close();raise
                child['producer_pid']=process.pid;workers.append((process,log,child))
                tails[batch]=Tail(output/child['directory']/'selected.jsonl',batch,merge)
                merge.status(batch,'batch_start',owned_producer_pid=process.pid)
            completed=set();last_disk=0
            while len(completed)<len(batches):
                require(time.monotonic()<deadline,'roster_deadline')
                if time.monotonic()-last_disk>1:
                    check_directory_budget(output,MAX_TOTAL,error_code='roster_disk_bound')
                    last_disk=time.monotonic()
                for process,log,child in workers:
                    batch=child['batch']
                    if batch in completed:continue
                    tails[batch].poll()
                    code=process.poll()
                    if code is None:continue
                    tails[batch].poll(final=True,deadline=deadline)
                    result_path=output/child['directory']/'result.json'
                    require(result_path.is_file() and result_path.stat().st_size<=1048576,'child_result_missing_or_bound')
                    data=result_path.read_bytes();result=parse(data)
                    child.update(exit_code=code,result_sha256=sha(data),outcome=child_outcome(code,result),
                                 native_stop_reason=result.get('native_stop_reason'),frames=merge.frames[batch])
                    merge.status(batch,'batch_end',**{k:v for k,v in child.items() if k!='batch'})
                    completed.add(batch)
                    require(child['outcome']!='failed','child_failed:'+batch)
                if len(completed)<len(batches):time.sleep(.02)
            receipt_frames=dict(merge.frames);merged_bytes=merge.bytes
    except BaseException as exc:
        error=type(exc).__name__+':'+str(exc)
        receipt_frames=dict(merge.frames) if 'merge' in locals() else {};merged_bytes=merge.bytes if 'merge' in locals() else 0
    finally:
        # Always terminate and close every exact owned job, including descendants.
        cleanup_errors=cleanup_owned(workers,time.monotonic()+5)
        for process,log,child in workers:
            child.setdefault('outcome','failed');child.setdefault('exit_code',process.poll())
        outcome=parent_outcome(children,batches,error,cleanup_errors)
        files=[]
        for p in sorted(output.iterdir()):
            if p.is_file():files.append(dict(path=p.name,size=p.stat().st_size,sha256=digest_file(p)))
        receipt=dict(schema='overwatch-decoder.private.selected-roster-run/1',**outcome,error=error,cleanup_errors=cleanup_errors,
            elapsed_seconds=time.monotonic()-started,requested=dict(seconds=args.seconds,interval_ms=args.interval_ms,pid=args.pid),
            scope='configured_controller_windows_in_controlled_practice',configured_batches=list(batches),atomic=False,cached_snapshot=False,
            previous_values_carried=False,all_current_roster_claim=False,children=children,frames_by_batch=receipt_frames,
            merged_bytes=merged_bytes,package_inventory_sha256=digest_file(BASE/'inventory.json'),files=files)
        (output/'result.json').write_bytes(raw(receipt))
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--seconds',type=int,default=45);parser.add_argument('--interval-ms',type=int,default=50)
    parser.add_argument('--practice-range',action='store_true')
    args=parser.parse_args();result=run(args);print(json.dumps(result,separators=(',',':')));sys.exit(result['cli_exit_code'])
