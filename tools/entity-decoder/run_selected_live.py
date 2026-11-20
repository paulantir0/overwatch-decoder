"""Private controlled-Practice selected observation runner; one bounded owned child."""
from __future__ import annotations
import argparse,copy,ctypes,hashlib,json,os,queue,re,subprocess,sys,threading,time
from pathlib import Path

sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
sys.path[:0]=[str(BASE/'lib'),str(BASE/'lib/entity_decoder')]
from export_relations import acquisition_provenance,bounded_local_bytes,parse
from hero_asset_labels import HeroAssetCatalog
from live_relations import LiveRelations
from live_sessions import LiveSession
from live_file_budget import check_directory_budget
from event_journal import open_event_journal_writer
from runtime_jobs import enroll_current_producer

MAX_LINE=512*1024

def raw(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def proof_raw(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
def digest_file(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def journal_options(config):
    compression=config.get('native_journal_compression','none')
    require(compression in ('none','gzip'),'native_journal_compression')
    return dict(path='native-events.jsonl'+('.gz' if compression=='gzip' else ''),compression=compression)

def configured_batches(config):
    batches=config.get('batches')
    require(isinstance(batches,list) and 1<=len(batches)<=8
            and all(isinstance(b,str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,31}',b) for b in batches)
            and len(set(batches))==len(batches),'configured_batch_ids')
    return tuple(batches)

def verify_package():
    manifest=parse((BASE/'inventory.json').read_bytes())
    for entry in manifest['files']:
        path=BASE/entry['path']
        require(not Path(entry['path']).is_absolute() and path.resolve().is_relative_to(BASE),'package_path_bound')
        require(path.is_file() and path.stat().st_size==entry['size'] and digest_file(path)==entry['sha256'],
                'package_pin_failed:'+entry['path'])
    return manifest

class Projectors:
    def __init__(self,batch,observation,output):
        require(batch in configured_batches(parse((BASE/'config.json').read_bytes())),'unconfigured_batch')
        self.batch=batch;self.observation=Path(observation);self.output=Path(output)
        self.recipe=BASE/f'private/recipes/batch{batch}.json'
        self.meta=parse((BASE/f'private/recipes/batch{batch}.bindings.json').read_bytes())
        self.artifacts={p.stem:p.read_bytes() for p in (BASE/'private/artifacts').glob('*.bin')}
        self.catalog=HeroAssetCatalog((BASE/'private/catalog.json').read_bytes(),self.artifacts)
        self.proofsha=(BASE/'private/selected-review.sha256').read_text().strip()
        self.native_sha=(BASE/'private/native-review.sha256').read_text().strip()
        self.calpin=(BASE/'private/practice-calibration.sha256').read_text().strip()
        self.template=parse((BASE/'private/selected-template.json').read_bytes())
        require(self.template.get('schema')=='overwatch-decoder.selected-runner-template/1','runner_template_schema')
        self.contracts=[]
    def contract(self,acquisition):
        profile=(acquisition/'profile.json').read_bytes();p=parse(profile)
        # The full, pinned recipe is supplied explicitly; no acquisition-file edits.
        manifest=parse((acquisition/'manifest.json').read_bytes())
        require(manifest['recipe_sha256']==digest_file(self.recipe),'fresh_recipe_mismatch')
        source=dict(manifest_sha256=digest_file(acquisition/'manifest.json'),
                    recipe_sha256=manifest['recipe_sha256'],evidence_sha256=manifest['evidence_sha256'])
        names={f['name'] for f in p['fields']}
        c=dict(schema='overwatch-decoder.selected-entity-contract/1',mode='target_vs_local',profile_sha256=sha(profile),target=p['target'],
            source=source,bindings=[],local_context=dict(fields=self.meta['local_context'],review_sha256=self.proofsha,
                validation_status=self.template['local_validation_status']),
            category_rule=dict(copy.deepcopy(self.template['category_rule']),review_sha256=self.native_sha))
        if 'gap_policy' in self.template:c['gap_policy']=self.template['gap_policy']
        require(type(self.meta.get('allow_empty_local_context',False)) is bool,'empty_local_policy')
        local_body_names={self.meta['local_context'][k] for k in ('body_handle','body_key','flags_low','flags_high')}
        if not local_body_names <= names:
            require(self.meta.get('allow_empty_local_context') is True,'empty_local_not_configured')
            require(not local_body_names & names,'partial_local_payload')
            collection=self.meta.get('local_empty_collection')
            require(isinstance(collection,dict) and set(collection)=={'rows','prefix'},'empty_local_collection')
            evidence=bounded_local_bytes(acquisition/'evidence.jsonl',8*1024*1024,'empty_local_evidence_bound')
            lines=[]
            for line in evidence.splitlines(keepends=True):
                event=parse(line)
                if (event.get('kind')=='field_collection' and event.get('stage')=='field_collection_output'
                        and type(event.get('depth')) is int and event['depth']==1
                        and all(event.get(k)==v for k,v in collection.items())
                        and type(event.get('retained_rows')) is int and event['retained_rows']==0
                        and type(event.get('expanded_fields')) is int and event['expanded_fields']==0
                        and event.get('allow_empty') is True):lines.append(line)
            require(len(lines)==1,'empty_local_evidence')
            for key,path in [('manifest_sha256',acquisition/'manifest.json'),('recipe_sha256',self.recipe),
                             ('evidence_sha256',acquisition/'evidence.jsonl')]:
                data=bounded_local_bytes(path,8*1024*1024,'empty_local_source_bound')
                require(sha(data)==source[key],'empty_local_source_hash');self.artifacts[source[key]]=data
            empty=proof_raw(dict(schema='overwatch-decoder.selected-empty-local-review/1',reviewed=True,
                target=p['target'],profile_sha256=sha(profile),source=source,
                collection=dict(collection,event_sha256=sha(lines[0]))))
            pin=sha(empty);self.artifacts[pin]=empty
            c['local_context'].update(acquisition_empty=True,empty_review_sha256=pin)
        for x in self.meta['actors']:
            if x['controller_key'] not in names:continue
            fields={k:v for k,v in x.items() if k not in ('ordinal_within_profile_only','health_sum','raw_quaternion_candidate')}
            b=dict(binding_id='controller_slot_'+str(x['ordinal_within_profile_only']),fields=fields,review_sha256=self.proofsha,
                   validation_status=self.template['binding_validation_status'])
            if x['body_key'] not in names:b['body_absent']=True
            else:b['health']=dict(sum_field=x['health_sum'],review_sha256=self.proofsha,
                                 validation_status=self.template['health_validation_status'])
            if 'raw_quaternion_candidate' in x and not b.get('body_absent'):
                b['raw_quaternion_candidate'] = self.quaternion_binding(profile, source, b, x['raw_quaternion_candidate'])
            c['bindings'].append(b)
        if not c['bindings']:
            require(self.meta.get('allow_empty_partition') is True,'empty_partition_not_configured')
            collection=self.meta.get('empty_collection')
            require(isinstance(collection,dict) and set(collection)=={'rows','prefix'},'empty_partition_collection')
            evidence=bounded_local_bytes(acquisition/'evidence.jsonl',8*1024*1024,'empty_evidence_bound')
            lines=[]
            for line in evidence.splitlines(keepends=True):
                event=parse(line)
                if (event.get('kind')=='field_collection' and event.get('stage')=='field_collection_output'
                        and event.get('depth')==1 and all(event.get(k)==v for k,v in collection.items())
                        and event.get('retained_rows')==0 and event.get('expanded_fields')==0
                        and event.get('allow_empty') is True):lines.append(line)
            require(len(lines)==1,'empty_partition_evidence')
            for key,path in [('manifest_sha256',acquisition/'manifest.json'),('recipe_sha256',self.recipe),
                             ('evidence_sha256',acquisition/'evidence.jsonl')]:
                data=bounded_local_bytes(path,8*1024*1024,'empty_source_bound')
                require(sha(data)==source[key],'empty_source_hash');self.artifacts[source[key]]=data
            empty=proof_raw(dict(schema='overwatch-decoder.selected-empty-partition-review/1',reviewed=True,partition_id=self.batch,
                target=p['target'],profile_sha256=sha(profile),source=source,
                collection=dict(collection,event_sha256=sha(lines[0]))))
            empty_pin=sha(empty);self.artifacts[empty_pin]=empty
            c.update(allow_empty_bindings=True,partition_id=self.batch,empty_partition_review_sha256=empty_pin)
        review=proof_raw(dict(schema='overwatch-decoder.selected-relation-label-review/1',reviewed=True,target=p['target'],profile_sha256=sha(profile),
                       source=source,same_group_label=c['category_rule']['same_group_label'],
                       different_group_label=c['category_rule']['different_group_label'],sources=[self.calpin,self.native_sha]))
        pin=sha(review);self.artifacts[pin]=review
        c['category_rule']['label_review_sha256']=pin
        return raw(c),review
    def quaternion_binding(self, raw_profile, source, binding, name):
        """Fresh epoch review derived only from an explicit pinned recipe review."""
        profile=parse(raw_profile)
        pin=self.meta.get('raw_quaternion_review_sha256');data=self.artifacts.get(pin)
        require(isinstance(data,bytes) and sha(data)==pin,'quaternion_recipe_review_hash')
        route=parse(data)
        require(isinstance(route,dict) and route.get('schema')=='overwatch-decoder.selected-raw-quaternion-recipe-review/1'
                and route.get('reviewed') is True
                and route.get('build_sha256')==profile['target']['executable_sha256']
                and route.get('recipe_sha256')==source['recipe_sha256']
                and route.get('semantics')=='raw_owned_component_four_float_candidate','quaternion_recipe_review_scope')
        position=binding['fields']['position'];fields={f['name']:f for f in profile['fields']}
        ps,qs=route.get('position_suffix'),route.get('quaternion_suffix')
        delta=route.get('relative_address_bytes')
        require(all(isinstance(v,str) and v for v in (ps,qs,name)) and position.endswith(ps)
                and name==position[:-len(ps)]+qs and name in fields and type(delta) is int
                and 12<=delta<=4096 and fields[name].get('address')==fields[position]['address']+delta,
                'quaternion_recipe_field_route')
        # Preserve the exact original declarations, including their guard ancestry.
        # SelectedEntityView rechecks type, dependencies and all fresh frame reads.
        review=proof_raw(dict(schema='overwatch-decoder.selected-raw-quaternion-review/1',reviewed=True,
            target=profile['target'],profile_sha256=sha(raw_profile),source=source,
            position_declaration=fields[position],quaternion_declaration=fields[name],
            identity_fields={k:v for k,v in binding['fields'].items() if k in
                ('controller_handle','controller_key','ref_first','ref_third','body_handle','body_key')},
            semantics=route['semantics'],recipe_review_sha256=pin))
        review_pin=sha(review);self.artifacts[review_pin]=review
        return dict(field=name,review_sha256=review_pin)

    def resolve_acquisition(self,entry):
        ordinal=entry.get('ordinal')
        require(type(ordinal) is int and 1<=ordinal<=128 and entry.get('directory')==f"acquisition-{ordinal:04d}",
                'acquisition_directory')
        return self.observation/entry['directory']
    def factory(self,session,acquisition,segment):
        name=acquisition['directory'];require(name==f"acquisition-{acquisition['ordinal']:04d}",'acquisition_directory')
        directory=self.resolve_acquisition(acquisition);contract,review=self.contract(directory)
        dest=self.output/'contracts';dest.mkdir(exist_ok=True)
        contract_path=dest/f"segment-{segment['segment']:04d}.json"
        with contract_path.open('xb') as stream:stream.write(contract)
        with (dest/f"segment-{segment['segment']:04d}.label-review.json").open('xb') as stream:stream.write(review)
        qpins=[b['raw_quaternion_candidate']['review_sha256'] for b in parse(contract)['bindings'] if 'raw_quaternion_candidate' in b]
        if qpins:
            qpins.append(self.meta['raw_quaternion_review_sha256'])
            with (dest/f"segment-{segment['segment']:04d}.quaternion-artifacts.json").open('xb') as stream:
                stream.write(raw({pin:self.artifacts[pin].decode('utf-8') for pin in qpins}))
        self.contracts.append(dict(segment=segment['segment'],acquisition=acquisition['ordinal'],contract_sha256=sha(contract),
                                   profile_sha256=acquisition['profile_sha256'],manifest_sha256=acquisition['manifest_sha256']))
        return LiveRelations(directory,session['session_id'],segment['segment'],recipe_path=self.recipe,
            selected_only=True,selected_contract=contract_path,selected_artifacts=self.artifacts,selected_hero_catalog=self.catalog)

class Budget:
    def __init__(self,limit):self.limit=limit;self.total=0
    def write(self,file,data):
        require(self.total+len(data)<=self.limit,'runner_byte_limit')
        require(file.write(data)==len(data),'runner_short_write');self.total+=len(data);file.flush()

def qpc_frequency():
    value=ctypes.c_longlong();require(ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(value)),'qpc_frequency_failed');return value.value

def qpc():
    value=ctypes.c_longlong();require(ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(value)),'qpc_failed');return value.value

def compact(result,provenance_sha):
    rows=[]
    for row in result['entities']:
        out={k:row.get(k) for k in ('entity_id','controller_id','is_local','reason','visibility')}
        for field in ('hero','health','position','relation'):
            item=row[field];out[field]=item.get('value')
            out[field+'_validation']=item.get('validation_status')
            if item.get('reason'):out[field+'_reason']=item['reason']
        if 'raw_quaternion_candidate' in row:
            item=row['raw_quaternion_candidate']
            out['raw_quaternion_candidate']=copy.deepcopy(item.get('value'))
            out['raw_quaternion_candidate_validation']=item.get('validation_status')
            out['raw_quaternion_candidate_reason']=item.get('reason')
            out['field_evidence']={'raw_quaternion_candidate':copy.deepcopy({k:v for k,v in item.items() if k!='value'})}
        rows.append(out)
    output=dict(schema='overwatch-decoder.private.selected-compact/1',source='process_memory',scope='configured_controller_window',
                source_clock=dict(kind='windows_qpc',monotonic_frequency=result['timestamp']['monotonic_frequency'],
                                  utc_origin=result['timestamp'].get('utc_origin')),
                session_id=result['session_id'],segment=result['segment'],
                event_sequence=result['event_sequence'],timestamp=result['timestamp'],profile_sha256=result['profile_sha256'],
                provenance_sha256=provenance_sha,visibility='unknown',durability_verified=False,entities=rows)
    if any('raw_quaternion_candidate' in row for row in result['entities']):
        output['observed_build_sha256']=result['build_sha256']
    for key in ('empty_partition','local_context_status','gap_policy','frame_gap'):
        if key in result:output[key]=copy.deepcopy(result[key])
    return output

def stop_owned(child):
    """Terminate only the exact child handle created by this invocation."""
    if child is not None and child.poll() is None:
        child.terminate()
        try:child.wait(timeout=2)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=2)

def classify_outcome(error,native_exit,terminal):
    """Completion requires both the accepted native terminal and native exit."""
    fatal = native_exit if native_exit in (2,4) else None
    if error is not None:
        return dict(status='failed',cli_exit_code=fatal or 1)
    if (not isinstance(terminal,dict) or terminal.get('status') != 'finished'
            or type(terminal.get('complete')) is not bool):
        return dict(status='failed',cli_exit_code=fatal or 1)
    if terminal['complete'] and native_exit == 0:
        return dict(status='complete',cli_exit_code=0)
    if not terminal['complete']:
        return dict(status='partial',cli_exit_code=fatal or 7)
    return dict(status='failed',cli_exit_code=fatal or (native_exit if native_exit else 1))

def run(args):
    require(os.name=='nt','live_runner_requires_windows')
    if args.job_handle is not None:enroll_current_producer(args.job_handle)
    config=parse((BASE/'config.json').read_bytes());inventory=verify_package()
    require(digest_file(sys.executable)==config['python_sha256'],'python_pin_failed')
    native=BASE/'native/overwatch-decoder-observer.exe';require(digest_file(native)==config['native_sha256'],'native_pin_failed')
    require(args.practice_range,'controlled_practice_scope_required')
    require(args.batch in configured_batches(config),'unconfigured_batch')
    require(1<=args.seconds<=180 and 10<=args.interval_ms<=1000 and args.pid>0,'runner_bounds')
    journal=journal_options(config)
    output=Path(args.output).resolve();require(not output.exists() and not output.is_relative_to(BASE),'new_external_output_required')
    output.mkdir(parents=True);observation=output/'native'
    projectors=Projectors(args.batch,observation,output)
    coordinator=LiveSession(projectors.factory,maximum_bytes=config['maximum_bytes'],maximum_output_bytes=config['maximum_bytes'],
                            acquisition_resolver=projectors.resolve_acquisition)
    command=[str(native),'observe-fields','--pid',str(args.pid),'--recipe',str(projectors.recipe),'--out',str(observation),
             '--seconds',str(args.seconds),'--interval-ms',str(args.interval_ms),'--jsonl','true','--live-evidence','true',
             '--allow-field-shape-changes','true',*config['native_extra_args']]
    budget=Budget(config['maximum_bytes']);events=queue.Queue(maxsize=4*1024*1024//MAX_LINE);stop=threading.Event();child=None
    started=time.monotonic();deadline=started+min(175,args.seconds+15);error=None;native_exit=None;received=0;journal_bytes=0;thread=None;native_terminal=None
    clock_frequency=qpc_frequency()
    def reader(pipe):
        try:
            while not stop.is_set():
                line=pipe.readline(MAX_LINE+1)
                if not line:break
                require(line.endswith(b'\n') and len(line)<=MAX_LINE,'native_line_bound')
                item=(line,qpc())
                while not stop.is_set():
                    try:events.put(item,timeout=.1);break
                    except queue.Full:pass
        except Exception as exc:
            while not stop.is_set():
                try:events.put(exc,timeout=.1);break
                except queue.Full:pass
        finally:
            while not stop.is_set():
                try:events.put(None,timeout=.1);break
                except queue.Full:pass
    try:
        with (output/'native-stderr.log').open('xb') as stderr, open_event_journal_writer(output/journal['path'],compression=journal['compression']) as rawfile, \
             (output/'provenance.jsonl').open('xb') as fullfile,(output/'selected.jsonl').open('xb') as compactfile, \
             (output/'receipts.jsonl').open('xb') as receipts:
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess,'BELOW_NORMAL_PRIORITY_CLASS',0)
            child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=stderr,creationflags=creationflags)
            thread=threading.Thread(target=reader,args=(child.stdout,),daemon=True);thread.start()
            last_disk_check=0
            while True:
                require(time.monotonic()<deadline,'runner_deadline')
                if time.monotonic()-last_disk_check>1:
                    check_directory_budget(output,config['maximum_bytes'],error_code='runner_disk_limit')
                    last_disk_check=time.monotonic()
                try:item=events.get(timeout=.1)
                except queue.Empty:continue
                if item is None:break
                if isinstance(item,Exception):raise item
                line,received_ticks=item;budget.write(rawfile,line);received+=1;journal_bytes+=len(line)
                result=coordinator.consume(line)
                event=parse(line)
                if event.get('kind')=='session_end':native_terminal=event['result_before_this_write']
                if result is not None:
                    full=raw(result);budget.write(fullfile,full)
                    encoded=raw(compact(result,sha(full)));budget.write(compactfile,encoded);out_ticks=qpc()
                    frequency=event['monotonic_frequency'];frame=event['recording_frame']
                    require(frequency==clock_frequency and frame['end_ticks']<=event['emitted_ticks']<=received_ticks<=out_ticks,'qpc_clock_or_order')
                    receipt=dict(schema='overwatch-decoder.private.selected-frame-receipt/1',event_sequence=event['event_sequence'],
                        session_id=event['session_id'],segment=event['segment'],capture_start_ticks=frame['start_ticks'],
                        capture_end_ticks=frame['end_ticks'],native_emitted_ticks=event['emitted_ticks'],
                        python_received_ticks=received_ticks,output_flushed_ticks=out_ticks,monotonic_frequency=frequency,
                        capture_end_to_output_ms=(out_ticks-frame['end_ticks'])*1000/frequency,
                        python_receive_to_output_ms=(out_ticks-received_ticks)*1000/frequency,
                        raw_event_sha256=sha(line),provenance_sha256=sha(full),compact_sha256=sha(encoded),
                        atomic=False,durability_verified=False)
                    budget.write(receipts,raw(receipt))
            native_exit=child.wait(timeout=max(.1,min(3,deadline-time.monotonic())))
            require(coordinator.ended and not coordinator.failed,'native_session_not_ended')
    except BaseException as exc:
        error=type(exc).__name__+':'+str(exc)
    finally:
        stop.set()
        if child is not None:
            stop_owned(child)
            native_exit=child.returncode
            if child.stdout:child.stdout.close()
        if thread is not None:thread.join(timeout=.5)
        files=[]
        for path in sorted(output.rglob('*')):
            if path.is_file():files.append(dict(path=path.relative_to(output).as_posix(),size=path.stat().st_size,sha256=digest_file(path)))
        outcome=classify_outcome(error,native_exit,native_terminal)
        receipt=dict(schema='overwatch-decoder.private.selected-run-result/1',batch=args.batch,scope='controlled_practice_only',
                     **outcome,error=error,native_exit_code=native_exit,native_terminal=native_terminal,
                     native_stop_reason=native_terminal.get('stop_reason') if native_terminal else None,
                     requested=dict(pid=args.pid,seconds=args.seconds,interval_ms=args.interval_ms),
                     native_pid=child.pid if child else None,owned_child_exited=child is None or child.poll() is not None,
                     reader_thread_stopped=thread is None or not thread.is_alive(),
                     elapsed_seconds=time.monotonic()-started,raw_events=received,session=coordinator.close(),
                     native_event_journal=dict(journal,uncompressed_bytes=journal_bytes),
                     package_inventory_sha256=digest_file(BASE/'inventory.json'),config=config,contracts=projectors.contracts,
                     output_files=files,public_state_eligible=False,durability_verified=False)
        (output/'result.json').write_bytes(raw(receipt))
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-package',action='store_true')
    parser.add_argument('--job-handle',type=int)
    parser.add_argument('--batch');parser.add_argument('--pid',type=int)
    parser.add_argument('--output');parser.add_argument('--seconds',type=int,default=45)
    parser.add_argument('--interval-ms',type=int,default=50);parser.add_argument('--practice-range',action='store_true')
    args=parser.parse_args()
    if args.check_package:
        print(json.dumps(dict(package_verified=True,files=len(verify_package()['files']))))
    else:
        parser.error('--batch, --pid and --output required') if args.batch is None or args.pid is None or args.output is None else None
        result=run(args)
        print(json.dumps(result,separators=(',',':')))
        sys.exit(result['cli_exit_code'])
