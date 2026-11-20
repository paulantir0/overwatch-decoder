"""Synthetic recorder ledger contracts; does not assert runtime gameplay semantics."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'entity-decoder'))
from combined_storage import CombinedStorageWriter, encoded
from chunks import checked_index
from prepare_compact import prepare_repeat_session
from session_windows import read_repeat_session, recorder_video_timing
from serve import recorder_clock_metadata

ORIGIN = 9007199254741000
SCOPE = 'read_only_user_gameplay'


def source(root, number, *, offset, partial=False, status_only=False):
    window = root / 'observations' / f'window-{number:04d}'
    writer = CombinedStorageWriter(window, maximum_cohort_bytes=4096, maximum_total_bytes=65536,
                                  maximum_cohorts=8, maximum_index_bytes=32768, maximum_receipt_bytes=512)
    for i in range(2):
        if status_only:
            row = dict(schema='overwatch-decoder.private.combined-status/1', kind=('source_start', 'source_end')[i])
        else:
            t = ORIGIN + offset + i * 20
            row = dict(schema='overwatch-decoder.private.selected-compact/1', source='process_memory',
                       scope='configured_controller_window', timestamp=dict(start_ticks=t-1, end_ticks=t, monotonic_frequency=1000),
                       session_id='same_fixture_id', segment=1,
                       entities=[dict(entity_id='same_structural_key', is_local=True, position=[number, 2, 3],
                                      position_validation='guarded')])
        row['combined_sequence'] = i
        raw = encoded(row)
        writer.write_compact(raw, i)
        writer.commit_receipt(encoded(dict(combined_sequence=i, line_sha256=hashlib.sha256(raw).hexdigest())))
    summary = writer.close()
    (window / 'result.json').write_bytes(encoded(dict(summary, schema='overwatch-decoder.private.combined-run/2',
        status='partial' if partial else 'complete', cli_exit_code=7 if partial else 0,
        capture_scope=SCOPE, error=None, cleanup_errors=[])))
    return window


def record(kind, window, t, **fields):
    return dict(kind=f'observation_window_{kind}', window=window, qpc_ticks=ORIGIN+t, **fields)


def start(n, t):
    return record('start', n, t, capture_scope=SCOPE, continuity_from_previous=False)


def end(n, t, code=0):
    return record('end', n, t, accepted=True, producer_exit_code=code, continuity_to_next=False)


def gap(n, t, reason):
    return record('gap', n, t, reason=reason)


def final_session(root, events, attempted, accepted):
    root.mkdir(exist_ok=True)
    target = dict(target_pid=123, target_start_utc_ticks=504911232000000100)
    events = [dict(kind='session_start', schema='overwatch-decoder.capture-session/1', qpc_origin=ORIGIN, qpc_frequency=1000, **target), *events]
    with gzip.open(root/'events.jsonl.gz', 'wt', encoding='utf-8') as f:
        for row in [*events, dict(kind='journal_end', qpc_ticks=ORIGIN+29999, written=len(events), dropped=0)]:
            f.write(json.dumps(row)+'\n')
    m = dict(schema='overwatch-decoder.capture-session/1', status='finished_with_gaps', qpc_origin=ORIGIN, qpc_frequency=1000,
             last_update_qpc=ORIGIN+30000, journal=dict(file='events.jsonl.gz', error=None, written=len(events), dropped=0),
             observations=dict(repeat_windows=True, attempted_windows=attempted, accepted_window_numbers=accepted,
                               capture_scope=SCOPE), **target)
    (root/'session.json').write_text(json.dumps(m))
    return m


def cancelled_source(root, *, misbind_second=False, alter_second_payload=False):
    """Synthetic sealed-storage and receipt fixture, not gameplay evidence."""
    window = root/'observations/window-0001'
    writer = CombinedStorageWriter(window, maximum_cohort_bytes=4096, maximum_total_bytes=65536,
                                   maximum_cohorts=8, maximum_index_bytes=32768, maximum_receipt_bytes=512)
    worker = window/'roster-00'
    profile = worker/'native/segment-0001/profile.json'
    profile.parent.mkdir(parents=True)
    profile.write_bytes(b'{}')
    profile_hash = hashlib.sha256(profile.read_bytes()).hexdigest()
    selected, receipts = [], []
    for i in range(3):
        t = ORIGIN+1000+i*20
        stamp = dict(start_ticks=t-1, end_ticks=t, monotonic_frequency=1000)
        row = dict(schema='overwatch-decoder.private.selected-compact/1', source='process_memory',
                   scope='configured_controller_window', timestamp=stamp, session_id='worker_session',
                   profile_sha256=profile_hash, event_sequence=i, segment=1,
                   entities=[dict(entity_id='fixture_body', is_local=True, position=[i+1,2,3], position_validation='guarded')])
        raw = encoded(row)
        h = hashlib.sha256(raw).hexdigest()
        selected.append(raw)
        receipts.append(encoded(dict(compact_sha256=h, session_id='worker_session', segment=1,
                                     event_sequence=i, capture_start_ticks=t-1, capture_end_ticks=t)))
        row.update(combined_sequence=i, capture_scope=SCOPE, source_worker='roster-00',
                   observed_build_sha256='a'*64, input_sha256='f'*64 if misbind_second and i==1 else h,
                   padding='x'*2300)
        if alter_second_payload and i == 1:
            row['entities'][0]['position'] = [999,2,3]
        compact = encoded(row)
        writer.write_compact(compact,i)
        writer.commit_receipt(encoded(dict(combined_sequence=i,line_sha256=hashlib.sha256(compact).hexdigest())))
    writer.abort()  # Two sealed cohorts followed by an open-only third cohort.
    (worker/'selected.jsonl').write_bytes(b''.join(selected))
    (worker/'receipts.jsonl').write_bytes(b''.join(receipts))
    native=worker/'native/manifest.json'
    native.write_bytes(encoded(dict(schema='overwatch-decoder.field-observation/1', status='finished', monotonic_frequency=1000,
        session_id='worker_session', target=dict(pid=123,creation_file_time=100,executable_sha256='a'*64),
        segments=[dict(ordinal=1,profile_sha256=profile_hash,frames=3)])))
    files = [worker/'selected.jsonl',worker/'receipts.jsonl',native,profile]
    (worker/'result.json').write_bytes(encoded(dict(schema='overwatch-decoder.private.selected-run-result/1', status='complete',
        capture_scope=SCOPE, error=None, cli_exit_code=0, native_exit_code=0, owned_child_exited=True,
        reader_thread_stopped=True, output_files=[dict(path=f.relative_to(worker).as_posix(),size=f.stat().st_size,
            sha256=hashlib.sha256(f.read_bytes()).hexdigest())for f in files])))
    return window


def handoff_start(n, t, predecessor=None):
    return dict(start(n,t), launch_qpc_ticks=ORIGIN+t, timing_basis='recorder_launch_qpc', predecessor_window=predecessor)


def handoff_session(root, events, attempted, accepted):
    m = final_session(root, events, attempted, accepted)
    m['observations'].update(overlapping_windows=True, window_seconds=20, successor_lead_seconds=6,
        successor_timing_basis='recorder_launch_qpc', storage_format='cohorts_v1', maximum_windows=4)
    (root/'session.json').write_text(json.dumps(m))
    return m


def handoff_source(root, number, spans, *, cancelled=False, partial=False, altered=False, outside_read=False,
                   quaternion_enrichment=None, session_id='same_structural_source'):
    window = root/'observations'/f'window-{number:04d}'
    writer = CombinedStorageWriter(window, maximum_cohort_bytes=4096, maximum_total_bytes=65536,
        maximum_cohorts=16, maximum_index_bytes=32768, maximum_receipt_bytes=512)
    worker = window/'roster-00'
    profile = worker/'native/segment-0001/profile.json'
    profile.parent.mkdir(parents=True)
    profile.write_bytes(b'{}')
    profile_hash = hashlib.sha256(profile.read_bytes()).hexdigest()
    compact, receipts, originals = [], [], []

    def emit(row):
        sequence = len(compact)
        raw = encoded(dict(row, combined_sequence=sequence, capture_scope=SCOPE))
        writer.write_compact(raw,sequence)
        writer.commit_receipt(encoded(dict(combined_sequence=sequence, line_sha256=hashlib.sha256(raw).hexdigest())))
        compact.append(raw)

    emit(dict(schema='overwatch-decoder.private.combined-status/1', kind='source_start', source_id='roster-00'))
    for i,(a,b) in enumerate(spans):
        a,b = ORIGIN+a, ORIGIN+b
        stamp = dict(start_ticks=a, end_ticks=b, monotonic_frequency=1000)
        original = dict(schema='overwatch-decoder.private.selected-compact/1', source='process_memory', scope='configured_controller_window',
            timestamp=stamp, session_id=session_id, profile_sha256=profile_hash, event_sequence=i, segment=1,
            entities=[dict(entity_id='same_body', is_local=True, position=[number,i,3], position_validation='guarded')])
        actor = original['entities'][0]
        if quaternion_enrichment:
            original['observed_build_sha256'] = 'a'*64
            proof = dict(source='process_memory', validation_status='raw_orientation_candidate',
                semantics='raw_owned_component_four_float_candidate', observed_build_sha256='a'*64,
                profile_sha256=profile_hash, review_sha256='a'*64, contract_sha256='a'*64,
                source_evidence={k:'a'*64 for k in ('manifest_sha256','recipe_sha256','evidence_sha256')},
                reads=[dict(field='fixture_q',read_start_ticks=a,read_end_ticks=b)])
            if quaternion_enrichment=='invalid_original_proof':
                proof['reads'][0]['read_start_ticks'] = a-1
            actor.update(controller_id='same_controller', raw_quaternion_candidate=[0,0,0,1],
                raw_quaternion_candidate_validation='raw_orientation_candidate',
                field_evidence=dict(raw_quaternion_candidate=proof))
        raw=encoded(original)
        originals.append(raw)
        h=hashlib.sha256(raw).hexdigest()
        receipts.append(encoded(dict(compact_sha256=h, session_id=session_id, segment=1,
            event_sequence=i, capture_start_ticks=a, capture_end_ticks=b)))
        if altered and i==0:
            original['timestamp']['start_ticks'] += 1  # Original selected receipt still binds earlier read start.
        if outside_read and i==0:
            original['entities'][0]['field_evidence'] = dict(position=dict(reads=[dict(read_start_ticks=a-1,read_end_ticks=b)]))
        if quaternion_enrichment:
            actor['field_evidence'] = dict(position=dict(reads=[dict(read_start_ticks=a,read_end_ticks=b)]))
            if quaternion_enrichment=='altered_proof':
                actor['field_evidence']['raw_quaternion_candidate'] = dict(review_sha256='b'*64)
            elif quaternion_enrichment=='altered_value':
                actor['raw_quaternion_candidate'] = [1,0,0,0]
        emit(dict(original, source_worker='roster-00', observed_build_sha256='a'*64, input_sha256=h, padding='x'*2300))
    code = 7 if partial else 0
    if cancelled:
        writer.abort()
    else:
        emit(dict(schema='overwatch-decoder.private.combined-status/1', kind='source_end', source_id='roster-00'))
        summary = writer.close()
    (worker/'selected.jsonl').write_bytes(b''.join(originals))
    (worker/'receipts.jsonl').write_bytes(b''.join(receipts))
    stop = 'acquisition_retry_limit' if partial else 'duration_elapsed'
    native = worker/'native/manifest.json'
    native.write_bytes(encoded(dict(schema='overwatch-decoder.field-observation/1', status='finished', complete=not partial,
        stop_reason=stop, monotonic_frequency=1000, session_id=session_id,
        target=dict(pid=123,creation_file_time=100,executable_sha256='a'*64),
        segments=[dict(ordinal=1,profile_sha256=profile_hash,frames=len(spans))])))
    files=[worker/'selected.jsonl',worker/'receipts.jsonl',native,profile]
    (worker/'result.json').write_bytes(encoded(dict(schema='overwatch-decoder.private.selected-run-result/1',
        status='partial' if partial else 'complete', capture_scope=SCOPE, error=None, cli_exit_code=code, native_exit_code=code,
        owned_child_exited=True, reader_thread_stopped=True, native_stop_reason=stop,
        native_terminal=dict(status='finished', complete=not partial, stop_reason=stop),
        output_files=[dict(path=f.relative_to(worker).as_posix(),size=f.stat().st_size,
            sha256=hashlib.sha256(f.read_bytes()).hexdigest()) for f in files])))
    if not cancelled:
        (window/'result.json').write_bytes(encoded(dict(summary, schema='overwatch-decoder.private.combined-run/2',
            status='partial' if partial else 'complete', cli_exit_code=code, capture_scope=SCOPE, error=None, cleanup_errors=[],
            roster_only=True, entity_rows=len(spans), source_unavailable=False,
            children=[dict(source='roster-00',source_result_sha256=hashlib.sha256((worker/'result.json').read_bytes()).hexdigest())])))
    return window, hashlib.sha256(b''.join(compact[:-1] if cancelled else compact)).hexdigest()


class SessionWindowTests(unittest.TestCase):
    def test_handoff_restores_only_verified_original_v5_quaternion_evidence(self):
        for enrichment, expected in (('missing_proof',2),('invalid_original_proof',2),('altered_proof',0),('altered_value',0)):
            with self.subTest(enrichment=enrichment), tempfile.TemporaryDirectory() as d:
                base=Path(d);root=base/'session';output=base/'replay.json'
                handoff_source(root,1,[(1000,1010),(16000,16020)],quaternion_enrichment=enrichment)
                m=handoff_session(root,[handoff_start(1,500),end(1,20500)],1,[1])
                result=prepare_repeat_session(root,output,m,read_repeat_session(root,m))
                self.assertEqual(result['frames'],expected)
                _,files=checked_index(output)
                if files:
                    replay=json.loads(next(iter(files.values())).read_bytes())
                    self.assertEqual([bool(frame['rotations']) for frame in replay['frames']],
                                     [enrichment=='missing_proof']*2)
                    if enrichment=='missing_proof':
                        field=replay['field_samples'][0]['field_evidence']['raw_quaternion_candidate']
                        selected=root/'observations/window-0001/roster-00/selected.jsonl'
                        self.assertEqual(field['source_selected_sha256'],hashlib.sha256(selected.read_bytes().splitlines(keepends=True)[0]).hexdigest())
                        self.assertEqual(replay['frames'][0]['rotation_reads'][0][1:],[str(ORIGIN+1000),str(ORIGIN+1010)])

    def test_handoff_uses_full_read_brackets_and_distinct_source_pins(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d); root=base/'session'; output=base/'replay.json'
            _, first_hash=handoff_source(root,1,[(1000,1010),(16000,16020)])
            _, second_hash=handoff_source(root,2,[(15000,15030),(16020,16020),(16020,16030),(16100,16105)],partial=True)
            m=handoff_session(root,[handoff_start(1,500),handoff_start(2,14500,1),end(2,19000,7),
                gap(2,19001,'producer_partial'),end(1,20500),handoff_start(3,21500),gap(3,27000,'source_unavailable')],3,[1,2])
            result=prepare_repeat_session(root,output,m,read_repeat_session(root,m))
            self.assertEqual((result['chunks'],result['frames'],result['gaps']),(2,4,2))
            value, files=checked_index(output)
            a,b=[json.loads(f.read_bytes()) for f in files.values()]
            first,second=value['chunks']
            view=value['session_windows'][1]['overlap_selection']
            self.assertEqual((first['source_sha256'],second['source_sha256']),(first_hash,second_hash))
            self.assertEqual((view['source_frames'],view['selected_frames'],view['dropped_at_or_before_cutover'],
                view['dropped_straddling_cutover']),(4,2,2,0))
            self.assertEqual(first['end_seconds'],second['start_seconds'])
            self.assertEqual(second['start_seconds'],16.03)
            self.assertEqual(b['frames'][0]['source_read_bracket'][:2],[str(ORIGIN+16020),str(ORIGIN+16030)])
            self.assertEqual(b['frames'][0]['start_ticks'],str(ORIGIN+16030))
            self.assertEqual(b['frames'][0]['objects'][0][2],2)
            self.assertNotEqual(a['objects'][0]['key'],b['objects'][0]['key'])
            self.assertEqual(value['gaps'],[dict(start_seconds=0,end_seconds=1.01),dict(start_seconds=16.155,end_seconds=30)])
            script='''const M=require(process.argv[1]); const {value,a,b}=JSON.parse(process.argv[2]);
              const idx=M.createIndex(value); M.validateOverlapChunk(idx,idx.chunks[1],M.create(b).data);
              if (M.recorderWindowAt(idx,16.031).window!==2 || M.recorderWindowAt(idx,24).window!==3 ||
                  M.indexSample(idx,0,M.create(a),16.03).active) throw Error('window switch mismatch');
              const rejected=(fn)=>{try { fn(); } catch { return; } throw Error('tampered overlap accepted');};
              b.frames[0].source_read_bracket[0]='9007199254757019';
              rejected(()=>M.validateOverlapChunk(idx,idx.chunks[1],b));
              value.session_windows[1].overlap_selection.cutover_ticks='0'; rejected(()=>M.createIndex(value));'''
            subprocess.run(['node','-e',script,str(HERE/'model.js'),json.dumps(dict(value=value,a=a,b=b))],check=True)
            value['session_windows'][1]['overlap_selection']['cutover_ticks']='0'
            output.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'cutover source'):
                checked_index(output)

    def test_straddling_recovered_prefix_keeps_original_proof_and_late_gap(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'session'; output=base/'replay.json'
            handoff_source(root,1,[(1000,1010),(16000,16020)])
            tail, source_hash=handoff_source(root,2,[(15000,15030),(16010,16025),(16150,16160),(16200,16220)],cancelled=True)
            m=handoff_session(root,[handoff_start(1,500),handoff_start(2,14500,1),end(1,20500),gap(2,26000,'cancelled')],2,[1])
            ledger=read_repeat_session(root,m)
            self.assertEqual(prepare_repeat_session(root,output,m,ledger)['chunks'],1)
            stats=prepare_repeat_session(root,output,m,ledger,recover_sealed_prefixes=True)
            self.assertEqual((stats['chunks'],stats['recovered_chunks'],stats['frames']),(2,1,3))
            value,files=checked_index(output)
            window=value['session_windows'][1]; view=window['overlap_selection']; proof=window['recovery_evidence']
            self.assertEqual((view['source_frames'],view['selected_frames'],view['dropped_at_or_before_cutover'],
                view['dropped_straddling_cutover']),(3,1,1,1))
            self.assertEqual(proof['source_frames'],3)
            self.assertEqual(proof['source_sha256'],source_hash)
            self.assertFalse(window['recorder_accepted'])
            self.assertFalse((tail/'result.json').exists())
            self.assertEqual(value['gaps'][1],dict(start_seconds=16.07,end_seconds=16.16))
            replay=json.loads(list(files.values())[1].read_bytes())
            self.assertEqual(replay['epochs'][0]['recovery'],proof)
            self.assertEqual(replay['frames'][0]['source_read_bracket'][:2],[str(ORIGIN+16150),str(ORIGIN+16160)])
            script='''const M=require(process.argv[1]); const {value,replay}=JSON.parse(process.argv[2]);
                const idx=M.createIndex(value); M.validateOverlapChunk(idx,idx.chunks[1],M.create(replay).data);
                if (M.chunkAt(idx,16.10)!==-1) throw Error('covered real gap');
                value.session_windows[1].recovery_evidence.source_frames=1;
                try { M.createIndex(value); } catch { process.exit(0); } throw Error('mutated proof accepted');'''
            subprocess.run(['node','-e',script,str(HERE/'model.js'),json.dumps(dict(value=value,replay=replay))],check=True)

    def test_handoff_rejects_invalid_recorder_metadata(self):
        for problem in ('missing_opt_in','basis','launch_ticks','missing_predecessor','wrong_predecessor','before_lead',
                        'closed_predecessor','out_of_order_terminal','unlisted_acceptance','missing_terminal'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as d:
                root=Path(d)/'session'; start_two=handoff_start(2,14500,1)
                events=[handoff_start(1,500),start_two,end(1,18000),end(2,26000)]
                if problem=='basis': start_two['timing_basis']='native_deadline'
                if problem=='launch_ticks': start_two['launch_qpc_ticks']+=1
                if problem=='missing_predecessor': del start_two['predecessor_window']
                if problem=='wrong_predecessor': start_two['predecessor_window']=True
                if problem=='before_lead': events[1]=handoff_start(2,14499,1)
                if problem=='closed_predecessor': events[1:3]=[end(1,12000),start_two]
                if problem=='out_of_order_terminal': events[2:]=[end(2,25000),end(1,18000)]
                if problem=='missing_terminal': events.pop()
                m=handoff_session(root,events,2,[1] if problem=='unlisted_acceptance' else [1,2])
                if problem=='missing_opt_in': m['observations'].pop('overlapping_windows')
                with self.assertRaisesRegex(ValueError,'overlap'):
                    read_repeat_session(root,m)

    def test_fully_hidden_recovered_window_does_not_advance_cutover(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d); root=base/'session'; output=base/'replay.json'
            handoff_source(root,1,[(1000,1010),(16000,16020)])
            handoff_source(root,2,[(15000,15030),(15040,15050)],cancelled=True)
            handoff_source(root,3,[(23000,23010)])
            m=handoff_session(root,[handoff_start(1,500),handoff_start(2,14500,1),gap(2,18000,'cancelled'),
                end(1,20500),handoff_start(3,21500),end(3,29000)],3,[1,3])
            prepare_repeat_session(root,output,m,read_repeat_session(root,m),recover_sealed_prefixes=True)
            value,_=checked_index(output)
            _,second,third=value['session_windows']
            self.assertEqual(second['recovery_evidence']['source_frames'],1)
            self.assertEqual(second['overlap_selection']['selected_frames'],0)
            self.assertFalse(second['replayed'])
            self.assertEqual(third['overlap_selection']['cutover_from_window'],1)
            self.assertEqual([c['recorder_window'] for c in value['chunks']],[1,3])
            subprocess.run(['node','-e','require(process.argv[1]).createIndex(JSON.parse(process.argv[2]))',
                str(HERE/'model.js'),json.dumps(value)],check=True)

    def test_resealed_invalid_successor_is_omitted_even_if_bad_row_would_be_dropped(self):
        for problem in ('altered','outside_read','reversed'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as d:
                base=Path(d);root=base/'session';output=base/'out.json'
                handoff_source(root,1,[(1000,1010),(16000,16020)])
                spans=[(15000,15030),(16030,16040)] if problem!='reversed' else [(15000,15030),(15020,15040),(16030,16040)]
                handoff_source(root,2,spans,altered=problem=='altered',outside_read=problem=='outside_read')
                m=handoff_session(root,[handoff_start(1,500),handoff_start(2,14500,1),end(1,20500),end(2,26000)],2,[1,2])
                prepare_repeat_session(root,output,m,read_repeat_session(root,m))
                value,_=checked_index(output)
                self.assertEqual(len(value['chunks']),1)
                self.assertEqual(value['session_windows'][1]['reason'],'accepted_window_verification_failed')
                self.assertEqual(value['gaps'][-1],dict(start_seconds=16.07,end_seconds=30))

    def test_valid_failed_unsealed_claim_partial_and_cancelled_tail(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root = base/'session'
            source(root, 1, offset=1000)
            broken = source(root, 3, offset=11000)
            index = broken/'storage-index.jsonl'
            index.write_bytes(b''.join(index.read_bytes().splitlines(keepends=True)[:-1]))
            source(root, 4, offset=16000, partial=True)
            tail = root/'observations/window-0005'
            tail.mkdir()
            (tail/'storage-index.jsonl').write_text('not even JSON; unaccepted and never inspected')
            m = final_session(root, [start(1,500), end(1,2000), start(2,5000), gap(2,7000,'failed'),
                start(3,10000), end(3,13000), start(4,15000), end(4,18000,7), gap(4,18001,'producer_partial'),
                start(5,22000), gap(5,26000,'cancelled')], 5, [1,3,4])
            output = base/'index.json'
            result = prepare_repeat_session(root, output, m, read_repeat_session(root,m))
            self.assertEqual((result['chunks'],result['omitted_windows'],result['frames']), (2,3,4))
            value, files = checked_index(output)
            self.assertEqual([c['recorder_window'] for c in value['chunks']], [1,4])
            self.assertEqual([w['reason'] for w in value['session_windows']], ['accepted','failed',
                'accepted_window_verification_failed','accepted_partial','cancelled'])
            self.assertEqual(value['gaps'], [dict(start_seconds=0,end_seconds=1),dict(start_seconds=1.07,end_seconds=16),
                dict(start_seconds=16.07,end_seconds=30)])
            a,b = [json.loads(f.read_bytes()) for f in files.values()]
            self.assertEqual(a['origin_ticks'], b['origin_ticks'])
            self.assertEqual(a['origin_ticks'], str(ORIGIN))
            self.assertEqual(b['frames'][0]['start_ticks'], str(ORIGIN+16000))
            self.assertNotEqual(a['objects'][0]['key'], b['objects'][0]['key'])
            self.assertEqual(b['epochs'][0]['id'], 'window-0004')
            self.assertEqual(b['epochs'][0]['recorder_acceptance']['producer_exit_code'], 7)
            self.assertEqual(a['events'], b['events'])
            self.assertFalse(b['whole_match_claim'])
            script = '''const M=require(process.argv[1]); const d=JSON.parse(process.argv[2]);
              const idx=M.createIndex(d.index), model=M.create(d.first);
              if(!M.indexSample(idx,0,model,1.01).active) throw Error('missing valid sample');
              for(const t of [0,6,11,16.01,23,29]) if(M.indexSample(idx,0,model,t).objects.length) throw Error('stale window');
              if(M.recorderWindowAt(idx,6).reason!=='failed') throw Error('missing failed reason');'''
            subprocess.run(['node','-e',script,str(HERE/'model.js'),json.dumps(dict(index=value,first=a))],check=True)

    def test_status_only_and_missing_acceptance_are_video_only(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'session'
            source(root,1,offset=1000,status_only=True)
            source(root,2,offset=6000)
            m=final_session(root,[start(1,500),end(1,2000),start(2,5000)],2,[1,2])
            output=base/'out.json'
            result=prepare_repeat_session(root,output,m,read_repeat_session(root,m))
            self.assertTrue(result['video_only'])
            idx,files=checked_index(output)
            self.assertEqual(files,{})
            self.assertEqual(idx['gaps'],[dict(start_seconds=0,end_seconds=30)])
            self.assertEqual([w['reason'] for w in idx['session_windows']],
                             ['accepted_no_entity_frames','missing_journal_acceptance'])
            script = '''const M=require(process.argv[1]); const idx=M.createIndex(JSON.parse(process.argv[2]));
              const model=M.emptyIndexModel(idx); if(model.end!==30 || M.indexSample(idx,-1,model,5).active) throw Error('bad video-only model');'''
            subprocess.run(['node','-e',script,str(HERE/'model.js'),json.dumps(idx)],check=True)

    def test_journal_footer_must_match_final_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'session';m=final_session(root,[start(1,500),end(1,2000)],1,[1])
            m['journal']['written']+=1
            with self.assertRaisesRegex(ValueError,'footer/count mismatch'):
                read_repeat_session(root,m)

    def test_fresh_video_timing_recomputes_this_sessions_receipts(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m=final_session(root,[],0,[])
            m['video']=dict(state='stopped',error=None,qpc_frequency=1000,source_pts_bounds_valid=True,
                source_time_base_confirmed_microseconds=True,process_launch_before_qpc=ORIGIN+200,
                source_pts_epoch_qpc_lower_bound=ORIGIN+199,source_pts_epoch_qpc_upper_bound=ORIGIN+281,
                source_frames_logged=2,source_clock_build_verified=False)
            path=root/'video-frames.jsonl'
            rows=[dict(frame=0,source_pts_us=0,receipt_qpc=ORIGIN+300,qpc_frequency=1000),
                  dict(frame=1,source_pts_us=1000000,receipt_qpc=ORIGIN+1280,qpc_frequency=1000)]
            path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
            timing=recorder_video_timing(root,m)
            self.assertEqual(timing['source_epoch_bounds_seconds'],[.199,.281])
            self.assertAlmostEqual(timing['start_seconds'],.24)
            self.assertAlmostEqual(timing['uncertainty_seconds'],.042)
            self.assertFalse(timing['presentation_time_exact'])
            self.assertEqual(recorder_clock_metadata(dict(video_timing=timing))['alignment'],'recorder_clock_bounded')
            rows[1]['receipt_qpc']+=1
            path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
            self.assertEqual(recorder_video_timing(root,m)['status'],'unavailable')


    def test_cancelled_prefix_is_opt_in_and_does_not_admit_open_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'session';w=cancelled_source(root)
            # Neither of these bytes may be parsed during prefix recovery.
            (w/'cohort-000003/game-state.jsonl').write_text('incomplete data')
            (w/'cohort-000003/delivery-receipts.jsonl').write_text('invalid receipt')
            m=final_session(root,[start(1,500),gap(1,2000,'cancelled')],1,[])
            ledger=read_repeat_session(root,m)
            index=base/'index.json'
            strict=prepare_repeat_session(root,index,m,ledger)
            self.assertTrue(strict['video_only'])
            result=prepare_repeat_session(root,index,m,ledger,recover_sealed_prefixes=True)
            self.assertEqual((result['chunks'],result['frames'],result['recovered_chunks']),(1,2,1))
            value,files=checked_index(index)
            self.assertTrue(value['sealed_prefix_recovery'])
            window=value['session_windows'][0];chunk=value['chunks'][0]
            self.assertFalse(window['recorder_accepted']);self.assertFalse(window['manifest_accepted'])
            self.assertEqual(chunk['recovery_status'],'verified_sealed_prefix')
            self.assertEqual(window['recovery_evidence']['stop_reason'],'unsealed_or_truncated_tail')
            self.assertEqual(window['recovery_evidence']['sealed_cohorts'],2)
            self.assertEqual(chunk['end_seconds'],1.07)
            data=json.loads(next(iter(files.values())).read_bytes())
            self.assertEqual(data['origin_ticks'],str(ORIGIN))
            self.assertNotIn('recorder_acceptance',data['epochs'][0])
            self.assertEqual(data['epochs'][0]['recovery']['source_sha256'],chunk['source_sha256'])
            self.assertFalse((w/'result.json').exists())
            self.assertEqual((w/'cohort-000003/game-state.jsonl').read_text(),'incomplete data')
            value.pop('sealed_prefix_recovery')
            index.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'recovery evidence'):
                checked_index(index)

    def test_corruption_truncation_or_worker_mismatch_stops_before_bad_cohort(self):
        for problem in ('corrupt_data','truncated_index','worker_binding','resealed_altered_payload'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as d:
                base=Path(d);root=base/'session';w=cancelled_source(root,misbind_second=problem=='worker_binding',
                                                                  alter_second_payload=problem=='resealed_altered_payload')
                if problem=='corrupt_data':
                    p=w/'cohort-000002/game-state.jsonl';raw=p.read_bytes()
                    p.write_bytes(raw.replace(b'"position":[2,2,3]',b'"position":[9,2,3]',1))
                    self.assertNotEqual(raw,p.read_bytes())
                elif problem=='truncated_index':
                    p=w/'storage-index.jsonl';lines=p.read_bytes().splitlines(keepends=True)
                    p.write_bytes(b''.join(lines[:3])+lines[3][:24])
                m=final_session(root,[start(1,500),gap(1,2000,'cancelled')],1,[])
                index=base/'index.json'
                result=prepare_repeat_session(root,index,m,read_repeat_session(root,m),recover_sealed_prefixes=True)
                self.assertEqual(result['frames'],1)
                value,_=checked_index(index)
                proof=value['session_windows'][0]['recovery_evidence']
                self.assertEqual(proof['sealed_cohorts'],1)
                self.assertEqual(proof['stop_reason'],'mismatched_or_truncated_cohort')

    def test_worker_lifetime_mismatch_yields_no_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'session';w=cancelled_source(root)
            native=w/'roster-00/native/manifest.json';doc=json.loads(native.read_bytes());doc['target']['creation_file_time']=101
            native.write_bytes(encoded(doc))
            result=w/'roster-00/result.json';doc=json.loads(result.read_bytes())
            item=next(x for x in doc['output_files']if x['path']=='native/manifest.json')
            item.update(size=native.stat().st_size,sha256=hashlib.sha256(native.read_bytes()).hexdigest())
            result.write_bytes(encoded(doc))
            m=final_session(root,[start(1,500),gap(1,2000,'cancelled')],1,[])
            idx=base/'index.json'
            summary=prepare_repeat_session(root,idx,m,read_repeat_session(root,m),recover_sealed_prefixes=True)
            self.assertTrue(summary['video_only'])
            self.assertEqual(json.loads(idx.read_bytes())['session_windows'][0]['recovery_status'],'unavailable')


if __name__=='__main__':
    unittest.main()
