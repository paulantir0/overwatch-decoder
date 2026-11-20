#!/usr/bin/env python3
"""Convert private combined windows into the existing local 3D/video replay.

Position samples from independent partitions remain timed observations. Samples
can be held for at most 50 ms; unknown updates clear their partition immediately.
No attacker is inferred, including from health loss. No raw native words survive.
"""
import argparse
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from overwatch_decoder.session_observations import from_line, InvalidObservation
sys.path.insert(0, str(Path(__file__).resolve().parent))
from session_windows import (RECOVERED_PREFIX, ROSTER_SOURCES, SCOPE, check_overlap_row, confined,
                             independent_roster_bindings, independent_roster_sources, overlap_worker_bindings,
                             read_repeat_session, recorder_video_timing, recovered_source_lines, require,
                             verify_cancelled_prefix)


class NoEntityFrames(InvalidObservation):
    """A validated source contains only recorder status records."""


def source_lines(path, metadata, acceptance=None, recovery=None, overlap=None, independent=None):
    """Read one logical observation window, independent of storage boundaries."""
    if recovery is not None:
        metadata['recovery'] = recovery['evidence']
        yield from recovered_source_lines(path, recovery)
        return
    maximum_line = 2 * 1024**2
    if not path.is_dir():
        with path.open('rb') as stream:
            while raw := stream.readline(maximum_line + 1):
                if len(raw) > maximum_line: raise InvalidObservation('input line bound')
                yield raw
        return

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'entity-decoder'))
    from combined_storage import CombinedStorageIndex, contained, strict_json
    verifier = CombinedStorageIndex(path, maximum_cohorts=4096,
        maximum_total_bytes=8 * 1024**3, maximum_index_bytes=64 * 1024**2,
        maximum_cohort_bytes=256 * 1024**2)
    index = contained(path, 'storage-index.jsonl')
    if index.stat().st_size > 64 * 1024**2:
        raise InvalidObservation('storage index byte bound')
    files = []
    with index.open('rb') as stream:
        while raw := stream.readline(4097):
            record = verifier.consume(raw)
            if record['kind'] == 'seal':
                files.append((record['directory'], record['files'][0]))
    summary = verifier.complete()
    result_path = contained(path, 'result.json')
    with result_path.open('rb') as stream:
        raw_result = stream.read(1024**2 + 1)
    if len(raw_result) > 1024**2: raise InvalidObservation('storage result byte bound')
    result = strict_json(raw_result)
    if (not isinstance(result, dict) or result.get('schema') != 'overwatch-decoder.private.combined-run/2'
        or result.get('status') not in ('complete', 'partial')
        or type(result.get('cli_exit_code')) is not int
        or result['cli_exit_code'] != (0 if result['status'] == 'complete' else 7)
        or 'error' not in result or result['error'] is not None or result.get('cleanup_errors') != []
        or result.get('capture_scope') not in ('controlled_practice', 'read_only_user_gameplay')
        or summary['output_rows'] == 0
        or any(type(result.get(key)) is not type(value) or result[key] != value
               for key, value in summary.items())):
        raise InvalidObservation('storage result mismatch')
    if acceptance is not None:
        require(result['capture_scope'] == SCOPE and result['cli_exit_code'] == acceptance['producer_exit_code']
                and result.get('source_unavailable') is not True, 'sealed result disagrees with recorder acceptance')
    roster_sources = independent_roster_sources(result)
    if roster_sources:
        require(independent is not None and result.get('provisional_tail') is False,
                'independent roster result was not finalized')
        counts = result.get('source_entity_rows')
        require(isinstance(counts, dict) and set(counts) == set(roster_sources)
                and all(type(n) is int and 0 <= n <= 100000 for n in counts.values())
                and sum(counts.values()) == result.get('entity_rows')
                and result['output_rows'] == sum(counts.values())+2*len(roster_sources),
                'independent roster result counts disagree')
        independent.update(sources=roster_sources, counts=counts)
        if acceptance is not None:
            bindings, builds, proofs, children = independent_roster_bindings(path, independent['manifest'], result)
            independent.update(bindings=bindings, builds=builds, proofs=proofs, children=children)
            metadata['roster_source_evidence'] = proofs
    elif overlap is not None:
        if overlap['worker_proof'] is None:
            overlap['bindings'], overlap['build'], overlap['worker_proof'] = overlap_worker_bindings(
                path, overlap['manifest'], acceptance)
        children = result.get('children')
        require(result.get('roster_only') is True and result.get('source_unavailable') is False
                and type(result.get('entity_rows')) is int and result['entity_rows'] == len(overlap['bindings'])
                and isinstance(children, list) and len(children) == 1 and isinstance(children[0], dict)
                and children[0].get('source') == 'roster-00'
                and children[0].get('source_result_sha256') == overlap['worker_proof']['worker_result_sha256'],
                'overlapping combined result disagrees with original worker')
    metadata.update(storage_format='cohorts_v1', storage_index_sha256=summary['storage_index_sha256'],
                    storage_cohorts=summary['storage_cohorts'], producer_status=result['status'])
    # Re-read the original bytes through bounded buffers. Verify them again before
    # prepare() publishes anything, so a changed sealed source cannot be rendered.
    for directory, descriptor in files:
        source = contained(path, directory + '/' + descriptor['path'])
        hashed, size, rows = hashlib.sha256(), 0, 0
        with source.open('rb') as stream:
            while raw := stream.readline(min(maximum_line, descriptor['bytes'] - size) + 1):
                if len(raw) > maximum_line or len(raw) > descriptor['bytes'] - size:
                    raise InvalidObservation('sealed source growth')
                hashed.update(raw); size += len(raw); rows += 1
                yield raw
            if os.fstat(stream.fileno()).st_size != descriptor['bytes']:
                raise InvalidObservation('sealed source size changed')
        if (size != descriptor['bytes'] or rows != descriptor['rows']
            or hashed.hexdigest() != descriptor['sha256']):
            raise InvalidObservation('sealed source changed after verification')


def _select_overlap_frame(view, start, end, maximum_frames):
    """Apply the cutoff to a full original source bracket, before building frames."""
    previous = view['source_last_end_ticks']
    require(previous is None or int(previous) <= start and int(previous) < end, 'overlapping source clock is not ordered')
    require(view['source_frames'] < maximum_frames, 'frame bound')
    if not view['source_frames']:
        view.update(source_first_start_ticks=str(start), source_first_end_ticks=str(end))
    view['source_frames'] += 1
    view['source_last_end_ticks'] = str(end)
    cutoff = view['cutover_ticks']
    if cutoff is not None:
        cutoff = int(cutoff)
        if end <= cutoff:
            view['dropped_at_or_before_cutover'] += 1
            return False
        if start < cutoff:
            view['dropped_straddling_cutover'] += 1
            return False
    if not view['selected_frames']:
        view.update(selected_first_start_ticks=str(start), selected_first_end_ticks=str(end))
    view['selected_frames'] += 1
    return True


def prepare(sources, destination, *, session=None, maximum_frames=100000,
            maximum_positions=2000000, maximum_bytes=128*1024**2,
            window_ids=None, acceptance=None, recovery=None, overlap=None):
    sources = [Path(p) for p in sources]
    destination = Path(destination)
    if (not sources or destination.resolve() in {p.resolve() for p in sources}
        or any(p.is_dir() and destination.resolve().is_relative_to(p.resolve()) for p in sources)):
        raise InvalidObservation('input and output must differ')
    require(acceptance is None or recovery is None, 'recovery cannot imply recorder acceptance')
    admission = acceptance if acceptance is not None else recovery['window'] if recovery is not None else None
    require(admission is None or len(sources) == 1 and sources[0].is_dir(), 'admitted window requires sealed cohorts')
    require(overlap is None or admission is not None, 'overlap requires verified window admission')
    require(window_ids is None or len(window_ids) == len(sources) and len(set(window_ids)) == len(window_ids), 'invalid source windows')
    session_data = None
    if overlap is not None:
        session_data = overlap['manifest']
    elif session:
        session_data = json.loads(Path(session).read_bytes())
    origin = session_data.get('qpc_origin') if session_data else None
    frequency = session_data.get('qpc_frequency') if session_data else None
    observations, events, epochs = [], [], []
    digest = hashlib.sha256()
    read_bytes = normalized_bytes = 0
    for window, path in enumerate(sources):
        source_id = window_ids[window] if window_ids is not None else f'window-{window+1:04d}'
        epochs.append(dict(id=source_id, continuity_from_previous=False, source_sha256=None))
        window_hash = hashlib.sha256()
        if acceptance is not None:
            epochs[-1]['recorder_acceptance'] = {key: acceptance[key] for key in
                ('window', 'start_ticks', 'end_ticks', 'producer_exit_code')}
        statuses, roster_statuses = [], {}
        independent = dict(manifest=session_data)
        roster_views = {}
        for raw in source_lines(path, epochs[-1], acceptance, recovery, overlap, independent):
            read_bytes += len(raw)
            if len(raw)>2*1024**2 or read_bytes>8*1024**3:
                raise InvalidObservation('input byte bound')
            window_hash.update(raw); digest.update(raw)
            row = from_line(raw)
            normalized_bytes += len(json.dumps(row, separators=(',',':')))
            if normalized_bytes > maximum_bytes: raise InvalidObservation('normalized observation byte bound')
            roster_sources = independent.get('sources', ())
            if row['kind']=='status':
                if roster_sources:
                    _independent_status(raw, row, roster_statuses, independent)
                elif overlap is not None:
                    require(row['source_worker'] == 'roster-00' and len(statuses) < 2,
                            'invalid overlapping roster status')
                    statuses.append(row['status'])
                continue
            require(admission is None or row['kind'] == 'entities', 'read-only roster window contains a non-roster record')
            stamp=row['timestamp']
            if stamp is None:
                if row['kind'] != 'incoming_source' or row['status'] != 'unknown': raise InvalidObservation('missing observation timestamp')
                if len(events)>=100000: raise InvalidObservation('event bound')
                events.append(dict(row, window=source_id, tick=None)); continue
            start,end=int(stamp['start_ticks']),int(stamp['end_ticks'])
            if frequency is None: frequency=stamp['frequency']
            if frequency!=stamp['frequency']: raise InvalidObservation('clock frequency changed')
            if origin is None: origin=start
            if start<origin: raise InvalidObservation('source predates session origin')
            if admission is not None:
                require(int(admission['start_ticks']) <= start <= end <= int(admission['end_ticks']),
                        'source timestamp outside recorder window')
            roster_source = row.get('roster_source_id')
            require(roster_source is None or not path.is_dir() or roster_sources,
                    'independent roster packet lacks a sealed topology')
            if roster_sources:
                require(roster_source in roster_sources and roster_statuses.get(roster_source) == 'source_start',
                        'independent roster row outside its source lifecycle')
                if 'bindings' in independent:
                    check_overlap_row(raw, row, start, end, independent['bindings'][roster_source],
                                      independent['builds'][roster_source], roster_source)
                if roster_source not in roster_views:
                    prior, cutoff = (overlap['view'][k] for k in ('cutover_from_window', 'cutover_ticks')) if overlap else (None, None)
                    roster_views[roster_source] = _new_overlap_view(prior, cutoff)
                if not _select_overlap_frame(roster_views[roster_source], start, end, maximum_frames):
                    continue
            elif overlap is not None:
                require(roster_source is None and statuses == ['source_start'], 'overlapping row outside source lifecycle')
                check_overlap_row(raw, row, start, end, overlap['bindings'], overlap['build'])
                if not _select_overlap_frame(overlap['view'], start, end, maximum_frames):
                    continue
            row.update(window=source_id, tick=end)
            if row['kind']=='entities':
                if len(observations)>=maximum_frames: raise InvalidObservation('frame bound')
                observations.append(row)
            else:
                if len(events)>=100000: raise InvalidObservation('event bound')
                events.append(row)
        epochs[-1]['source_sha256']=window_hash.hexdigest()
        if recovery is not None:
            require(epochs[-1]['source_sha256'] == recovery['evidence']['source_sha256'], 'recovered source changed')
        if independent.get('sources'):
            require(roster_statuses == dict.fromkeys(independent['sources'], 'source_end')
                    and all(roster_views.get(source, {}).get('source_frames', 0) == count
                            for source, count in independent['counts'].items())
                    and not any(independent.get('bindings', {}).values()), 'incomplete independent roster source')
            if overlap is not None:
                _complete_independent_overlap(overlap, roster_views, independent)
                epochs[-1]['overlap_source_selections'] = overlap['source_views']
        if overlap is not None:
            if not independent.get('sources'):
                require(not overlap['bindings'] and (statuses == ['source_start', 'source_end']
                        or recovery is not None and statuses == ['source_start']), 'incomplete overlapping roster source')
            view = overlap['view']
            if recovery is not None:
                require(view['source_frames'] == recovery['evidence']['source_frames']
                        and view['source_first_end_ticks'] == recovery['evidence']['first_end_ticks']
                        and view['source_last_end_ticks'] == recovery['evidence']['last_end_ticks'],
                        'overlap selection differs from recovered source proof')
            overlap['source_sha256'] = epochs[-1]['source_sha256']
            epochs[-1]['overlap_selection'] = view
            if overlap['worker_proof'] is not None:
                epochs[-1]['overlap_source_evidence'] = overlap['worker_proof']
    if not observations:
        if not events: raise NoEntityFrames('no entity frames')
        raise InvalidObservation('no entity frames')
    # Independent source queues may flush out of timestamp order. Sorting changes
    # delivery order only; every original bracket and source line hash survives.
    observations.sort(key=lambda row:(row['tick'],row['window'],row['source_worker']))
    independent_rosters = any('roster_source_id' in row for row in observations)
    require(not independent_rosters or all('roster_source_id' in row for row in observations),
            'mixed independent and legacy roster input')
    indices, objects, frames, latest = {}, [], [], {}
    field_samples, field_indices = [], {}
    frame_bytes=0
    total_positions=unknown=0; low=[math.inf]*3; high=[-math.inf]*3
    for row in observations:
        tick=row['tick']; worker=row['source_worker']; window=row['window']
        # No partition history survives a new bounded acquisition window.
        if frames and frames[-1]['epoch']!=window: latest.clear()
        if independent_rosters:
            samples = (row,)
        else:
            latest[worker]=row
            latest={k:v for k,v in latest.items() if v['window']==window and 0<=tick-v['tick']<=frequency//20}
            samples = latest.values()
        xyz,reads,fields=[],[],[]
        rotations,rotation_reads=[],[]
        self_count=0
        for sample in samples:
            for entity in sample['entities']:
                position=entity['position']['value']; identity=entity['entity_id']
                if identity is None or position is None:
                    unknown+=1; continue
                # The full source lifetime, partition and acquisition segment
                # qualify structural identity; no labels transfer across windows.
                lifetime = (sample['session_id'] or 'unknown', sample['segment'] or 'unknown', identity)
                if independent_rosters:
                    key = json.dumps((window, sample['roster_source_id'], *lifetime), separators=(',', ':'))
                else:
                    key = '|'.join((window, *lifetime))
                if key not in indices:
                    if len(objects)>=4096: raise InvalidObservation('object bound')
                    index=len(objects);indices[key]=index
                    objects.append(dict(index=index,id=f'object-{index+1:04d}',key=key,label=f'Object {index+1:03d}'))
                    if independent_rosters:
                        objects[-1]['roster_source_id'] = sample['roster_source_id']
                index=indices[key]
                if any(p[0]==index for p in xyz): raise InvalidObservation('duplicate object across partitions')
                own=entity['is_local']; self_count+=own is True
                xyz.append([index,*position,own]); reads.append([index,sample['timestamp']['start_ticks'],sample['timestamp']['end_ticks']])
                position_reads=entity.get('field_evidence',{}).get('position',{}).get('reads',[])
                if position_reads:
                    reads[-1]=[index, str(min(int(r['read_start_ticks']) for r in position_reads)), str(max(int(r['read_end_ticks']) for r in position_reads))]
                candidate=entity.get('raw_quaternion_candidate',{}).get('value')
                # No rotation from another worker's held position snapshot.
                if sample is row and candidate is not None:
                    qread=entity['field_evidence']['raw_quaternion_candidate']['reads'][0]
                    rotations.append([index,*candidate])
                    rotation_reads.append([index,qread['read_start_ticks'],qread['read_end_ticks']])
                field_key=(sample["source_sha256"],index)
                if field_key not in field_indices:
                    field_indices[field_key]=len(field_samples)
                    field_samples.append(dict(object=index,entity_id=identity,controller_id=entity['controller_id'],
                    hero=entity['hero'],health=entity['health'],relation=entity['relation'],team=entity['team'],username=entity['username'],
                    field_evidence=entity.get('field_evidence',{}),source_timestamp=sample['timestamp'],
                    observed_build_sha256=sample['observed_build_sha256'],provenance_sha256=sample['provenance_sha256'],
                    source_sha256=sample['source_sha256'],visibility='unknown'))
                field_sample = field_samples[field_indices[field_key]]
                if independent_rosters:
                    field_sample.update(roster_source_id=sample['roster_source_id'], roster_source_tick=sample['roster_source_tick'],
                                        source_session_id=sample['session_id'], source_segment=sample['segment'])
                if 'raw_quaternion_candidate' in entity:
                    field_sample['raw_quaternion_candidate']=entity['raw_quaternion_candidate']
                fields.append(field_indices[field_key])
                for axis,value in enumerate(position): low[axis]=min(low[axis],value);high[axis]=max(high[axis],value)
        if self_count>1: # Conflicting self association does not create two local players.
            for point in xyz: point[4]=None
        total_positions+=len(xyz)
        if total_positions>maximum_positions: raise InvalidObservation('position bound')
        frame=dict(t=(tick-origin)/frequency,end=(tick-origin)/frequency,epoch=window,sequence=len(frames),
                   start_ticks=str(tick),end_ticks=str(tick),skipped=0,continuity_valid=False,objects=xyz,reads=reads,
                   field_refs=fields,unknown_count=sum(e['position']['value'] is None for e in row['entities']),
                   rotations=rotations,rotation_reads=rotation_reads,self_pools=None)
        if independent_rosters:
            frame.update(roster_source_id=row['roster_source_id'], roster_source_tick=row['roster_source_tick'],
                         source_session_id=row['session_id'], source_segment=row['segment'])
        if overlap is not None or independent_rosters:
            frame['source_read_bracket'] = [row['timestamp']['start_ticks'], row['timestamp']['end_ticks'], row['source_sha256']]
        frame_bytes += len(json.dumps(frame,separators=(',',':')))
        if frame_bytes > maximum_bytes: raise InvalidObservation('prepared frame byte bound')
        if not independent_rosters and frames and frames[-1]['t']==frame['t']:
            # Same-QPC partition updates form one explicitly non-atomic snapshot.
            frames[-1]=frame
        else: frames.append(frame)
    event_rows=[]; untimed_events=[]
    for row in sorted(events,key=lambda e:(e['tick'] is None, e['tick'] or 0)):
        if row['tick'] is None: untimed_events.append(dict(row, t=None))
        else: event_rows.append(dict(row, t=(row['tick']-origin)/frequency))
    total_positions=sum(len(frame["objects"]) for frame in frames)
    replay_end = max([frames[-1]['end']] + [row['t'] for row in event_rows])
    result=dict(schema='overwatch-decoder.entity-replay/1',public_state_eligible=False,title='Recorded entity and combat observations',
                source_sha256=digest.hexdigest(),frequency=frequency,origin_ticks=str(origin),
                start_seconds=frames[0]['t'],end_seconds=replay_end,objects=objects,epochs=epochs,frames=frames,field_samples=field_samples,
                bounds=dict(min=low if total_positions else None,max=high if total_positions else None),events=event_rows,untimed_events=untimed_events,
                summary=dict(frames=len(frames),epochs=len(epochs),objects=len(objects),positions=total_positions,
                             unknown_positions=unknown,skipped_intervals=None,damage_feedback_candidates=sum(e['kind']=='damage' for e in event_rows),
                             incoming_source_observations=sum(e['kind']=='incoming_source' and e['status']=='observed' for e in event_rows),
                             incoming_source_unknowns=sum(e['kind']=='incoming_source' and e['status']=='unknown' for e in event_rows+untimed_events),
                             untimed_source_observations=len(untimed_events)),
                interpolation=False,continuity_across_epochs=False,whole_match_claim=False,all_current_roster_claim=False,
                identity_scope='source-qualified structural lifetimes; usernames unknown unless supplied and validated',
                compact_observations=True,sample_hold_limit_seconds=.05,
                note='Independent partition samples held at most 50 ms with individual source times. Unknown updates clear their partition. No incoming attacker attribution or visibility inferred.')
    if independent_rosters:
        result.update(roster_sources=list(ROSTER_SOURCES), multi_source_snapshot=False)
    encoded=json.dumps(result,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()
    if len(encoded)>maximum_bytes: raise InvalidObservation('output byte bound')
    destination.parent.mkdir(parents=True,exist_ok=True)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent,prefix='.compact-replay-',delete=False) as out:
            temporary=out.name;out.write(encoded)
        os.replace(temporary,destination);temporary=None
    finally:
        if temporary: os.unlink(temporary)
    return result['summary']


def prepare_chunks(sources, destination, *, session):
    """One bounded native window per replay; publish the index only after all pass."""
    import uuid
    destination=Path(destination)
    if not 1<=len(sources)<=240:raise InvalidObservation('chunk count bound')
    directory=destination.parent/(destination.stem+'-chunks-'+uuid.uuid4().hex[:10])
    directory.mkdir(parents=True,exist_ok=False)
    chunks=[];source_hash=hashlib.sha256()
    for number,source in enumerate(sources):
        file=directory/f'{number:04d}.json'
        summary=prepare([source],file,session=session,window_ids=[f'window-{number+1:04d}'])
        # Read only one bounded chunk at a time. Browser loading stays lazy.
        data=json.loads(file.read_bytes())
        source_hash.update(bytes.fromhex(data['source_sha256']))
        with file.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
        chunks.append(dict(path=file.relative_to(destination.parent).as_posix(),start_seconds=data['start_seconds'],
                           end_seconds=data['end_seconds']+.05,sha256=sha,bytes=file.stat().st_size,summary=summary))
        del data
    value=dict(schema='overwatch-decoder.entity-replay-index/1',public_state_eligible=False,chunks=chunks,
               source_sha256=source_hash.hexdigest(),source_digest_kind='ordered_chunk_source_sha256_bytes',
               start_seconds=0,end_seconds=chunks[-1]['end_seconds'],continuity_across_chunks=False,
               whole_match_claim=False,note='Bounded observation windows loaded individually; gaps remain unknown.')
    pending=destination.with_name(destination.name+'.partial')
    pending.write_text(json.dumps(value,separators=(',',':')),encoding='utf-8');os.replace(pending,destination)
    return dict(chunks=len(chunks),frames=sum(c['summary']['frames'] for c in chunks),end_seconds=value['end_seconds'])



def _new_overlap_view(prior, cutoff):
    return dict(cutover_from_window=prior, cutover_ticks=cutoff,
                source_frames=0, source_first_start_ticks=None, source_first_end_ticks=None,
                source_last_end_ticks=None, selected_frames=0, selected_first_start_ticks=None,
                selected_first_end_ticks=None, dropped_at_or_before_cutover=0, dropped_straddling_cutover=0)


def _overlap_view(manifest, previous):
    prior, cutoff = previous if previous is not None else (None, None)
    return dict(view=_new_overlap_view(prior, cutoff), bindings=None, build=None, worker_proof=None, manifest=manifest)


def _independent_status(raw, row, statuses, independent):
    source, status = row['source_worker'], row['status']
    require(source in independent['sources'] and
            (status == 'source_start' and source not in statuses
             or status == 'source_end' and statuses.get(source) == 'source_start'),
            'invalid independent roster status')
    if 'children' in independent:
        original = json.loads(raw)
        child = independent['children'][source]
        require(original.get('capture_scope') == SCOPE and
                (status == 'source_start' and original.get('owned_producer_pid') == child.get('owned_producer_pid')
                 or status == 'source_end' and all(original.get(k) == child.get(k) for k in
                     ('source_result_sha256', 'outcome', 'exit_code'))), 'independent roster status/child mismatch')
    statuses[source] = status


def _complete_independent_overlap(overlap, roster_views, independent):
    view = overlap['view']
    views = {source: roster_views.get(source) or _new_overlap_view(view['cutover_from_window'], view['cutover_ticks'])
             for source in independent['sources']}
    originals = [v for v in views.values() if v['source_frames']]
    kept = [v for v in originals if v['selected_frames']]
    for rows, prefix in ((originals, 'source'), (kept, 'selected')):
        if rows:
            first = min(rows, key=lambda v: int(v[prefix+'_first_end_ticks']))
            view.update({prefix+'_first_'+key+'_ticks': first[prefix+'_first_'+key+'_ticks'] for key in ('start', 'end')})
    for key in ('source_frames', 'selected_frames', 'dropped_at_or_before_cutover', 'dropped_straddling_cutover'):
        view[key] = sum(v[key] for v in views.values())
    if originals:
        view['source_last_end_ticks'] = max((v['source_last_end_ticks'] for v in originals), key=int)
    view['selected_last_end_ticks'] = max((v['source_last_end_ticks'] for v in kept), key=int, default=None)
    overlap.update(source_views=views, roster_source_evidence=independent['proofs'])


def _record_overlap_view(window, overlap, digest, recovery):
    view = overlap['view']
    window.update(overlap_selection=view, source_sha256=overlap['source_sha256'])
    if overlap['worker_proof'] is not None:
        window['overlap_source_evidence'] = overlap['worker_proof']
        for pin in overlap['worker_proof'].values():
            digest.update(bytes.fromhex(pin))
    if 'source_views' in overlap:
        window.update(overlap_source_selections=overlap['source_views'], roster_source_evidence=overlap['roster_source_evidence'])
        for proof in overlap['roster_source_evidence'].values():
            for pin in proof.values():
                digest.update(bytes.fromhex(pin))
        digest.update(hashlib.sha256(json.dumps(overlap['source_views'], separators=(',', ':')).encode()).digest())
    if recovery is not None:
        window.update(recovery_status=RECOVERED_PREFIX, recovery_evidence=recovery['evidence'])
        digest.update(bytes.fromhex(recovery['evidence']['prefix_storage_index_sha256']))
    digest.update(window['window'].to_bytes(2, 'big'))
    digest.update(bytes.fromhex(overlap['source_sha256']))
    digest.update(hashlib.sha256(json.dumps(view, separators=(',', ':')).encode()).digest())


def prepare_repeat_session(root, destination, manifest, ledger, *, recover_sealed_prefixes=False):
    """Export only individually accepted, verified windows; preserve omissions as gaps."""
    import uuid
    root, destination = Path(root), Path(destination)
    require(not destination.resolve().is_relative_to(root.resolve()), 'output must be outside the original session')
    directory = destination.parent / (destination.stem + '-chunks-' + uuid.uuid4().hex[:10])
    directory.mkdir(parents=True, exist_ok=False)
    chunks, windows = [], []
    overlapping = ledger.get('overlapping_windows') is True
    previous_view = None
    digest = hashlib.sha256()
    # Bind even a zero-chunk export to the actual finalized session journal.
    digest.update(b'overwatch-decoder.accepted-window-replay/1\0')
    digest.update(bytes.fromhex(ledger['journal_sha256']))
    if recover_sealed_prefixes:
        digest.update(b'\0verified-sealed-prefixes')
    if overlapping:
        digest.update(b'\0verified-overlap-source-brackets')
        digest.update(bytes((ledger['window_seconds'], ledger['successor_lead_seconds'])))
    for admission in ledger['windows']:
        window = dict(admission, replayed=False)
        windows.append(window)
        recover = (recover_sealed_prefixes and not window['recorder_accepted']
                   and not window['manifest_accepted'] and window['reason'] == 'cancelled')
        if not window['recorder_accepted'] and not recover:
            continue  # Default path never opens an unaccepted window directory.
        n = window['window']
        identity = f'window-{n:04d}'
        out = directory / f'{n:04d}.json'
        overlap = plan = None
        try:
            source = confined(root, root / 'observations' / identity)
            plan = verify_cancelled_prefix(root, source, manifest, window, from_line) if recover else None
            require(source.is_dir() and (source/'storage-index.jsonl').is_file()
                    and not (source/'game-state.jsonl').exists(), 'window storage unavailable or ambiguous')
            if overlapping:
                overlap = _overlap_view(manifest, previous_view)
            summary = prepare([source], out, session=root/'session.json', window_ids=[identity],
                              acceptance=None if recover else window, recovery=plan, overlap=overlap)
            data = json.loads(out.read_bytes())
            start, end = data['start_seconds'], min(data['end_seconds'] + .05, window['end_seconds'])
            require(overlapping or not chunks or start >= chunks[-1]['end_seconds'], 'overlapping accepted replay windows')
            require(start <= end <= ledger['end_seconds'], 'invalid accepted replay time bounds')
            with out.open('rb') as stream:
                sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            chunk = dict(path=out.relative_to(destination.parent).as_posix(), start_seconds=start,
                         end_seconds=end, sha256=sha, bytes=out.stat().st_size, summary=summary,
                         recorder_window=n, source_sha256=data['source_sha256'])
            if data.get('multi_source_snapshot') is False:
                chunk.update(roster_sources=data['roster_sources'], multi_source_snapshot=False)
            if overlap is not None:
                _record_overlap_view(window, overlap, digest, plan)
                previous_view = (n, overlap['view']['source_last_end_ticks'])
                if chunks:
                    chunks[-1]['end_seconds'] = min(chunks[-1]['end_seconds'], start)
            else:
                digest.update(n.to_bytes(2, 'big'))
                if plan:
                    digest.update(bytes.fromhex(plan['evidence']['prefix_storage_index_sha256']))
                digest.update(bytes.fromhex(data['source_sha256']))
            chunks.append(chunk)
            window.update(replayed=True, source_sha256=data['source_sha256'])
            if plan:
                chunk['recovery_status'] = RECOVERED_PREFIX
                window.update(recovery_status=RECOVERED_PREFIX, recovery_evidence=plan['evidence'])
        except NoEntityFrames:
            if overlap is not None and overlap['view']['source_frames']:
                _record_overlap_view(window, overlap, digest, plan)
                window['overlap_view_status'] = 'all_frames_before_or_straddling_cutover'
            elif recover:
                window.update(replayed=False, recovery_status='unavailable')
            else:
                if overlap is not None:
                    _record_overlap_view(window, overlap, digest, plan)
                window.update(replayed=False, reason='accepted_no_entity_frames')
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Do not expose filesystem paths or arbitrary producer errors in a replay.
            out.unlink(missing_ok=True)
            if recover:
                window.update(replayed=False, recovery_status='unavailable')
            else:
                window.update(replayed=False, reason='accepted_window_verification_failed')
    gaps, cursor = [], 0.0
    for chunk in chunks:
        if chunk['start_seconds'] > cursor:
            gaps.append(dict(start_seconds=cursor, end_seconds=chunk['start_seconds']))
        cursor = chunk['end_seconds']
    if cursor < ledger['end_seconds']:
        gaps.append(dict(start_seconds=cursor, end_seconds=ledger['end_seconds']))
    value = dict(schema='overwatch-decoder.entity-replay-index/1', public_state_eligible=False, repeat_windows=True,
                 chunks=chunks, gaps=gaps, session_windows=windows, frequency=ledger['frequency'],
                 origin_ticks=str(ledger['origin']), source_sha256=digest.hexdigest(),
                 source_digest_kind='accepted_window_journal_and_ordered_sources',
                 journal_sha256=ledger['journal_sha256'], journal_dropped=ledger['journal_dropped'],
                 video_timing=recorder_video_timing(root, manifest), start_seconds=0, end_seconds=ledger['end_seconds'],
                 continuity_across_chunks=False, whole_match_claim=False,
                 note='Only recorder-accepted, independently verified windows contain observations. Gaps and window identities remain separate.')
    if recover_sealed_prefixes:
        value.update(sealed_prefix_recovery=True, source_digest_kind='accepted_or_recovered_window_journal_and_ordered_sources',
                     note='Recorder-accepted windows and explicitly verified cancelled prefixes are separate. Unsealed tails remain unknown.')
    if overlapping:
        value.update(overlapping_windows=True, successor_lead_seconds=ledger['successor_lead_seconds'],
                     successor_timing_basis=ledger['successor_timing_basis'], window_seconds=ledger['window_seconds'],
                     source_digest_kind='verified_overlap_journal_original_sources_and_view_selections',
                     note='Original source read brackets govern handoff. Window identities stay separate and uncovered intervals remain unknown.')
    encoded = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('utf-8')
    require(len(encoded) <= 1024**2, 'replay index byte bound')
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.replay-index-', delete=False) as stream:
        pending = Path(stream.name)
        stream.write(encoded)
    try:
        os.replace(pending, destination)
    finally:
        pending.unlink(missing_ok=True)
    if not chunks:
        directory.rmdir()
    return dict(chunks=len(chunks), frames=sum(c['summary']['frames'] for c in chunks), end_seconds=value['end_seconds'],
                attempted_windows=len(windows), omitted_windows=len(windows)-len(chunks), gaps=len(gaps),
                video_only=not chunks, video_timing=value['video_timing'],
                **({'recovered_chunks':sum(c.get('recovery_status') == RECOVERED_PREFIX for c in chunks)} if recover_sealed_prefixes else {}))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path,help='game-state.jsonl, sealed cohort window or recorder session directory')
    parser.add_argument('destination',type=Path)
    parser.add_argument('--chunks',action='store_true',help='Publish a bounded per-window replay index (requires session directory)')
    parser.add_argument('--recover-sealed-prefixes',action='store_true',
                        help='Explicitly recover verified prefixes from finalized cancelled windows')
    args=parser.parse_args()
    if args.source.is_dir() and (args.source/'session.json').is_file():
        sources=[];session=args.source/'session.json'
        if session.stat().st_size > 1024**2: raise InvalidObservation('session manifest byte bound')
        manifest = json.loads(session.read_bytes())
        ledger = read_repeat_session(args.source, manifest)
        if ledger is not None:
            print(json.dumps(prepare_repeat_session(args.source,args.destination,manifest,ledger,
                                                     recover_sealed_prefixes=args.recover_sealed_prefixes)))
            return
        for window in sorted(args.source.glob('observations/window-*')):
            if not window.is_dir():continue
            flat, cohorts = window/'game-state.jsonl', window/'storage-index.jsonl'
            if flat.is_file() == cohorts.is_file():
                raise InvalidObservation('missing or ambiguous observation window format')
            sources.append(window if cohorts.is_file() else flat)
    else: sources=[args.source];session=None
    if args.recover_sealed_prefixes:
        parser.error('--recover-sealed-prefixes requires a finalized repeat-window recorder session')
    if args.chunks:
        if session is None:parser.error('--chunks requires a recorder session directory')
        print(json.dumps(prepare_chunks(sources,args.destination,session=session)))
    else:print(json.dumps(prepare(sources,args.destination,session=session)))

if __name__=='__main__': main()
