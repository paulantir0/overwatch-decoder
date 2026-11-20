"""Bounded, finalized recorder window admission and per-session clock evidence."""
import gzip
import hashlib
import json
from pathlib import Path

from overwatch_decoder.session_observations import InvalidObservation, raw_quaternion

MAX_WINDOWS = 240
MAX_JOURNAL_BYTES = 1024**3
MAX_JOURNAL_LINE = 256 * 1024
MAX_FRAME_LOG_BYTES = 64 * 1024**2
FINAL = ('finished', 'finished_with_gaps')
SCOPE = 'read_only_user_gameplay'
WINDOW_EVENTS = ('observation_window_start', 'observation_window_end', 'observation_window_gap')
GAP_REASONS = ('source_unavailable', 'producer_partial', 'cancelled', 'failed')
HANDOFF_TIMING_BASIS = 'recorder_launch_qpc'
PARTIAL_STOPS = ('acquisition_retry_limit', 'acquisition_attempt_limit', 'fields_never_observed')
ROSTER_SOURCES = ('roster-00', 'roster-01')


def require(ok, reason):
    if not ok:
        raise InvalidObservation(reason)


def confined(root, path):
    """Never follow recorder inputs or their directories outside the selected session."""
    require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()), 'session input escapes root')
    return path


def _record(raw):
    value = json.loads(raw)
    require(isinstance(value, dict), 'invalid recorder record')
    return value


def _overlap_plan(info):
    if not any(key in info for key in ('overlapping_windows', 'successor_lead_seconds', 'successor_timing_basis')):
        return None
    lead, duration, maximum = (info.get(k) for k in ('successor_lead_seconds', 'window_seconds', 'maximum_windows'))
    require(info.get('overlapping_windows') is True and info.get('repeat_windows') is True
            and info.get('successor_timing_basis') == HANDOFF_TIMING_BASIS
            and info.get('storage_format') == 'cohorts_v1'
            and all(type(v) is int for v in (lead, duration, maximum))
            and 20 <= duration <= 60 and 0 < lead < duration and 2 <= maximum <= MAX_WINDOWS,
            'invalid overlapping recorder plan')
    return dict(overlapping_windows=True, successor_lead_seconds=lead, successor_timing_basis=HANDOFF_TIMING_BASIS,
                window_seconds=duration)


def _overlap_event(event, windows, active, launched, minimum_lead_ticks):
    kind, n, tick = (event[k] for k in ('kind', 'window', 'qpc_ticks'))
    if kind == WINDOW_EVENTS[0]:
        predecessor = event.get('predecessor_window')
        require(n == launched+1 and len(active) <= 1 and 'predecessor_window' in event
                and type(event.get('launch_qpc_ticks')) is int and event['launch_qpc_ticks'] == tick
                and event.get('timing_basis') == HANDOFF_TIMING_BASIS,
                'invalid overlapping window launch')
        if active:
            require(type(predecessor) is int and predecessor == n-1 and predecessor in active
                    and tick-windows[predecessor][WINDOW_EVENTS[0]]['qpc_ticks'] >= minimum_lead_ticks,
                    'invalid overlapping predecessor')
        else:
            require(predecessor is None, 'inactive overlapping predecessor')
        active.add(n)
        return launched+1
    if kind == WINDOW_EVENTS[2] and event.get('reason') == 'producer_partial':
        require(n not in active and windows[n].get(WINDOW_EVENTS[1], {}).get('producer_exit_code') == 7,
                'invalid overlapping partial gap')
    else:
        require(n in active, 'overlapping window terminal without an active launch')
        active.remove(n)
    return launched


def read_repeat_session(root, manifest):
    """None for legacy; otherwise final manifest AND durable journal admission."""
    info = manifest.get('observations')
    if not isinstance(info, dict):
        return None
    overlap = _overlap_plan(info)
    if 'repeat_windows' not in info:
        return None
    require(type(info['repeat_windows']) is bool, 'invalid repeat-window marker')
    if not info['repeat_windows']:
        return None
    require(manifest.get('schema') == 'overwatch-decoder.capture-session/1' and manifest.get('status') in FINAL,
            'repeat-window session must be finalized')
    require(info.get('capture_scope') == SCOPE, 'repeat-window session is not read-only gameplay')
    origin, frequency, last = (manifest.get(k) for k in ('qpc_origin', 'qpc_frequency', 'last_update_qpc'))
    require(all(type(v) is int for v in (origin, frequency, last)) and 0 <= origin < last < 2**63
            and 0 < frequency <= 2**53 - 1, 'invalid session clock')
    attempted, accepted = info.get('attempted_windows'), info.get('accepted_window_numbers')
    require(type(attempted) is int and 0 <= attempted <= MAX_WINDOWS, 'invalid attempted windows')
    if overlap:
        require(attempted <= info['maximum_windows'], 'overlapping window attempt bound')
    require(isinstance(accepted, list) and len(accepted) <= attempted
            and all(type(n) is int and 1 <= n <= attempted for n in accepted)
            and sorted(set(accepted)) == accepted, 'invalid accepted window list')
    journal = manifest.get('journal')
    require(isinstance(journal, dict) and journal.get('file') == 'events.jsonl.gz' and journal.get('error') is None,
            'final recorder journal unavailable')
    windows = {n: {} for n in range(1, attempted + 1)}
    active, launched, previous_tick = set(), 0, origin
    minimum_lead_ticks = (info['window_seconds']-info['successor_lead_seconds'])*frequency if overlap else None
    records, total_bytes, footer, session_start = 0, 0, None, None
    journal_path = confined(root, root / 'events.jsonl.gz')
    require(journal_path.is_file() and journal_path.stat().st_size <= MAX_JOURNAL_BYTES, 'journal byte bound')
    with journal_path.open('rb') as raw_journal:
        journal_hash = hashlib.file_digest(raw_journal, 'sha256').hexdigest()
        raw_journal.seek(0)
        with gzip.GzipFile(fileobj=raw_journal, mode='rb') as stream:
            while raw := stream.readline(MAX_JOURNAL_LINE + 1):
                total_bytes += len(raw)
                require(len(raw) <= MAX_JOURNAL_LINE and total_bytes <= MAX_JOURNAL_BYTES, 'journal byte bound')
                require(footer is None, 'journal records follow terminal footer')
                event = _record(raw)
                kind = event.get('kind')
                if kind == 'journal_end':
                    footer = event
                    continue
                records += 1
                if kind == 'session_start':
                    require(session_start is None, 'duplicate recorder session start')
                    session_start = event
                if kind not in WINDOW_EVENTS:
                    continue
                n, tick = event.get('window'), event.get('qpc_ticks')
                require(type(n) is int and n in windows and type(tick) is int and origin <= tick <= last,
                        'invalid recorder window event')
                require(kind not in windows[n], 'duplicate recorder window event')
                if kind == 'observation_window_start':
                    require(event.get('capture_scope') == SCOPE and event.get('continuity_from_previous') is False,
                            'invalid recorder window start')
                    require(overlap or not {'launch_qpc_ticks', 'timing_basis', 'predecessor_window'}.intersection(event),
                            'overlapping window launch lacks manifest opt-in')
                elif kind == 'observation_window_end':
                    require(event.get('continuity_to_next') is False and event.get('accepted') is True
                            and type(event.get('producer_exit_code')) is int and event['producer_exit_code'] in (0, 7),
                            'invalid recorder window acceptance')
                else:
                    require(event.get('reason') in GAP_REASONS, 'invalid recorder window gap reason')
                if overlap:
                    require(tick >= previous_tick, 'reversed overlapping journal clock')
                    launched = _overlap_event(event, windows, active, launched, minimum_lead_ticks)
                    previous_tick = tick
                windows[n][kind] = event
        raw_journal.seek(0)
        require(hashlib.file_digest(raw_journal, 'sha256').hexdigest() == journal_hash, 'recorder journal changed during import')
    require(session_start is not None and session_start.get('schema') == 'overwatch-decoder.capture-session/1'
            and session_start.get('qpc_origin') == origin and session_start.get('qpc_frequency') == frequency
            and session_start.get('target_pid') == manifest.get('target_pid')
            and session_start.get('target_start_utc_ticks') == manifest.get('target_start_utc_ticks'),
            'recorder journal session binding mismatch')
    require(footer is not None and type(footer.get('qpc_ticks')) is int and origin <= footer['qpc_ticks'] <= last
            and type(footer.get('written')) is int and footer['written'] == records == journal.get('written')
            and type(footer.get('dropped')) is int and 0 <= footer['dropped'] == journal.get('dropped'),
            'recorder journal footer/count mismatch')
    if overlap:
        require(not active and launched == attempted and previous_tick <= footer['qpc_ticks'],
                'incomplete overlapping window journal')
    out = []
    for n, events in windows.items():
        start = events.get(WINDOW_EVENTS[0], {}).get('qpc_ticks')
        end_event = events.get(WINDOW_EVENTS[1], {})
        end = end_event.get('qpc_ticks')
        gap = events.get(WINDOW_EVENTS[2], {})
        terminal = gap.get('qpc_ticks', end)
        require(start is None or terminal is None or start <= terminal, 'reversed recorder window interval')
        require(start is None or end is None or start <= end, 'reversed recorder acceptance interval')
        admitted = n in accepted and start is not None and end is not None
        if overlap:
            require((end is not None) == (n in accepted) and (end is not None or gap),
                    'overlapping journal disagrees with manifest acceptance')
        if admitted:
            require(not gap or (gap['reason'] == 'producer_partial' and end_event['producer_exit_code'] == 7
                    and gap['qpc_ticks'] >= end), 'contradictory recorder acceptance and gap')
        reason = ('accepted_partial' if end_event.get('producer_exit_code') == 7 else 'accepted') if admitted else (
            'missing_journal_acceptance' if n in accepted else gap.get('reason', 'not_accepted'))
        out.append(dict(window=n, recorder_accepted=admitted, manifest_accepted=n in accepted,
                        start_ticks=str(start) if start is not None else None,
                        end_ticks=str(end if admitted else terminal) if (end if admitted else terminal) is not None else None,
                        start_seconds=(start-origin)/frequency if start is not None else None,
                        end_seconds=((end if admitted else terminal)-origin)/frequency if (end if admitted else terminal) is not None else None,
                        producer_exit_code=end_event.get('producer_exit_code') if admitted else None,
                        reason=reason))
        if overlap:
            launch = events[WINDOW_EVENTS[0]]
            out[-1].update(launch_qpc_ticks=str(launch['launch_qpc_ticks']), timing_basis=launch['timing_basis'],
                           predecessor_window=launch['predecessor_window'])
    return dict(origin=origin, frequency=frequency, end_seconds=(last-origin)/frequency,
                windows=out, journal_sha256=journal_hash, journal_dropped=footer['dropped'], **(overlap or {}))


def recorder_video_timing(root, manifest):
    """Estimate only the conditional source epoch, verified from this session's log."""
    unavailable = dict(status='unavailable', reason='No verified recorder source-clock bracket.')
    try:
        video = manifest.get('video')
        origin, freq = manifest.get('qpc_origin'), manifest.get('qpc_frequency')
        if not isinstance(video, dict) or video.get('source_pts_bounds_valid') is not True or video.get('source_time_base_confirmed_microseconds') is not True:
            return unavailable
        if type(origin) is not int or type(freq) is not int or not 0 < freq <= 2**53 - 1:
            return unavailable
        if video.get('state') != 'stopped' or video.get('error') is not None or video.get('qpc_frequency') != freq:
            return unavailable
        launch = video.get('process_launch_before_qpc')
        if type(launch) is not int or launch < origin:
            return unavailable
        margin = max(1, (2 * freq + 999999) // 1000000)
        lower, upper, rows, previous = launch - margin, None, 0, -1
        path = confined(root, root / 'video-frames.jsonl')
        if not path.is_file() or path.stat().st_size > MAX_FRAME_LOG_BYTES:
            return unavailable
        log_hash = hashlib.sha256()
        with path.open('rb') as stream:
            while raw := stream.readline(8193):
                if len(raw) > 8192 or rows > 1080000:
                    return unavailable
                row = _record(raw)
                pts, receipt = row.get('source_pts_us'), row.get('receipt_qpc')
                if type(pts) is not int or type(receipt) is not int or pts < 0 or pts < previous or receipt < origin or row.get('frame') != rows or row.get('qpc_frequency') != freq:
                    return unavailable
                bound = receipt - (pts * freq // 1000000) + margin
                upper = bound if upper is None else min(upper, bound)
                previous = pts
                log_hash.update(raw)
                rows += 1
        if not rows or rows != video.get('source_frames_logged') or upper is None or upper < lower or lower != video.get('source_pts_epoch_qpc_lower_bound') or upper != video.get('source_pts_epoch_qpc_upper_bound'):
            return unavailable
        lo, hi = (lower-origin)/freq, (upper-origin)/freq
        # This is a timestamp-preserving remux assumption, not an input/render latency measurement.
        return dict(status='conditional_recorder_clock', start_seconds=(lo+hi)/2,
                    uncertainty_seconds=(hi-lo)/2+.001, source_epoch_bounds_seconds=[lo, hi],
                    assumed_mux_rounding_seconds=.001, source_frame_log_sha256=log_hash.hexdigest(),
                    source_frames_logged=rows, source_clock_build_verified=video.get('source_clock_build_verified') is True,
                    presentation_time_exact=False)
    except (OSError, ValueError):
        return unavailable


RECOVERED_PREFIX = 'verified_sealed_prefix'


def _bounded_object(path, maximum=1024**2):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'recovery metadata byte bound')
    return _record(raw), hashlib.sha256(raw).hexdigest()


def _sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _sealed_rows(path, descriptor):
    """Re-read only the exact admitted bytes; verify them before publication."""
    hashed, size, rows = hashlib.sha256(), 0, 0
    with path.open('rb') as stream:
        while raw := stream.readline(min(2*1024**2, descriptor['bytes'] - size) + 1):
            require(len(raw) <= 2*1024**2 and len(raw) <= descriptor['bytes'] - size and raw.endswith(b'\n'),
                    'recovery sealed file changed')
            hashed.update(raw)
            size += len(raw)
            rows += 1
            yield raw
    require(size == descriptor['bytes'] and rows == descriptor['rows'] and hashed.hexdigest() == descriptor['sha256'],
            'recovery sealed file hash mismatch')


def recovered_source_lines(path, plan):
    from combined_storage import contained
    for directory, descriptor in plan['files']:
        yield from _sealed_rows(contained(path, directory+'/'+descriptor['path']), descriptor)



def _canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode('utf-8')).hexdigest()


def _selected_payload_sha(row, keys, source_evidence):
    """Bind the exact selected fields and any original evidence retained by combined."""
    payload = {key: row[key] for key in keys}
    entities = payload['entities']
    require(isinstance(entities, list) and len(entities) == len(source_evidence)
            and all(isinstance(e, dict) for e in entities), 'recovery selected entity shape mismatch')
    for entity, pins in zip(entities, source_evidence):
        if not pins:
            continue
        evidence = entity.get('field_evidence', {})
        require(isinstance(evidence, dict), 'invalid selected field evidence')
        for name, pin in pins.items():
            # The combined v5 producer adds its own per-field evidence and omits
            # the selected quaternion proof. Its value still participates in the
            # exact payload comparison, and any restored proof comes from selected.
            if name == 'raw_quaternion_candidate' and name not in evidence:
                continue
            require(name in evidence and _canonical_sha(evidence[name]) == pin,
                    'selected field evidence changed')
    payload['entities'] = [{k:v for k,v in e.items() if k != 'field_evidence'} for e in entities]
    return _canonical_sha(payload)

def _selected_worker_bindings(path, manifest, producer_exit_code=None, source='roster-00'):
    """Bind combined rows to a completed worker on the same observed target."""
    from combined_storage import contained
    worker = contained(path, source)
    result, worker_hash = _bounded_object(contained(worker, 'result.json'))
    code = 0 if producer_exit_code is None else producer_exit_code
    complete = code == 0
    require(result.get('schema') == 'overwatch-decoder.private.selected-run-result/1'
            and result.get('status') == ('complete' if complete else 'partial')
            and result.get('capture_scope') == SCOPE and result.get('error') is None
            and type(result.get('cli_exit_code')) is int and result['cli_exit_code'] == code
            and type(result.get('native_exit_code')) is int and result['native_exit_code'] == code
            and result.get('owned_child_exited') is True and result.get('reader_thread_stopped') is True,
            'recovery worker is not complete')
    files = result.get('output_files')
    maximum_files = 128 if producer_exit_code is None else 4096
    maximum_bytes = (512 if producer_exit_code is None else 4096)*1024**2
    require(isinstance(files, list) and 3 <= len(files) <= maximum_files, 'worker inventory bound')
    inventory, total = {}, 0
    for item in files:
        require(isinstance(item, dict) and isinstance(item.get('path'), str) and item['path'] not in inventory
                and type(item.get('size')) is int and item['size'] >= 0 and _digest(item.get('sha256')),
                'invalid recovery worker inventory')
        total += item['size']
        require(total <= maximum_bytes, 'worker byte bound')
        p = contained(worker, item['path'])
        require(p.is_file() and p.stat().st_size == item['size'] and _sha(p) == item['sha256'],
                'recovery worker inventory mismatch')
        inventory[item['path']] = item
    require({'selected.jsonl', 'receipts.jsonl', 'native/manifest.json'} <= inventory.keys(), 'missing recovery worker evidence')
    native, native_hash = _bounded_object(contained(worker, 'native/manifest.json'))
    target = native.get('target')
    build = target.get('executable_sha256') if isinstance(target, dict) else None
    # Recorder uses .NET DateTime ticks; native manifest uses Windows FILETIME.
    target_start = manifest.get('target_start_utc_ticks')
    require(native.get('schema') == 'overwatch-decoder.field-observation/1' and native.get('status') == 'finished'
            and native.get('monotonic_frequency') == manifest['qpc_frequency'] and _digest(build)
            and type(manifest.get('target_pid')) is int and target.get('pid') == manifest['target_pid']
            and type(target_start) is int and target.get('creation_file_time') == target_start-504911232000000000
            and native_hash == inventory['native/manifest.json']['sha256'], 'recovery native target or clock mismatch')
    if producer_exit_code is not None:
        terminal = result.get('native_terminal')
        stop = result.get('native_stop_reason')
        require(isinstance(terminal, dict) and terminal.get('status') == 'finished'
                and terminal.get('complete') is complete and terminal.get('stop_reason') == stop
                and native.get('complete') is complete and native.get('stop_reason') == stop
                and stop in (('duration_elapsed',) if complete else PARTIAL_STOPS), 'overlapping worker terminal mismatch')
    segments = native.get('segments')
    require(isinstance(segments, list) and (1 if producer_exit_code is None else 0) <= len(segments) <= 128,
            'invalid recovery native segments')
    profiles, native_frames = {}, 0
    for seg in segments:
        ordinal, profile, frames = seg.get('ordinal'), seg.get('profile_sha256'), seg.get('frames')
        require(type(ordinal) is int and ordinal > 0 and ordinal not in profiles and _digest(profile)
                and type(frames) is int and frames >= 0, 'invalid recovery native segment')
        profile_name = f'native/segment-{ordinal:04d}/profile.json'
        require(inventory.get(profile_name, {}).get('sha256') == profile, 'recovery native profile mismatch')
        profiles[ordinal] = profile
        native_frames += frames
    require((1 if producer_exit_code is None else 0) <= native_frames <= 100000, 'recovery native frame bound')
    selected = {}
    data_sha, receipts_sha = hashlib.sha256(), hashlib.sha256()
    with contained(worker, 'selected.jsonl').open('rb') as data, contained(worker, 'receipts.jsonl').open('rb') as receipts:
        while line := data.readline(2*1024**2+1):
            proof = receipts.readline(4097)
            require(len(line) <= 2*1024**2 and 0 < len(proof) <= 4096 and line.endswith(b'\n') and proof.endswith(b'\n')
                    and len(selected) < native_frames, 'invalid recovery selected row')
            row, receipt = _record(line), _record(proof)
            key = hashlib.sha256(line).hexdigest()
            stamp = row.get('timestamp')
            require(row.get('schema') == 'overwatch-decoder.private.selected-compact/1' and isinstance(stamp, dict)
                    and key not in selected and receipt.get('compact_sha256') == key
                    and row.get('session_id') == native.get('session_id') and receipt.get('session_id') == row.get('session_id')
                    and type(row.get('segment')) is int and row['segment'] in profiles
                    and row.get('profile_sha256') == profiles[row['segment']] and receipt.get('segment') == row['segment']
                    and type(row.get('event_sequence')) is int and receipt.get('event_sequence') == row['event_sequence']
                    and stamp.get('monotonic_frequency') == manifest['qpc_frequency']
                    and receipt.get('capture_start_ticks') == stamp.get('start_ticks')
                    and receipt.get('capture_end_ticks') == stamp.get('end_ticks'), 'recovery selected receipt mismatch')
            entities = row.get('entities')
            require(isinstance(entities, list) and all(isinstance(e, dict) for e in entities),
                    'invalid recovery selected entity payload')
            keys = tuple(sorted(row))
            evidence = [e.get('field_evidence', {}) for e in entities]
            require(all(isinstance(item, dict) for item in evidence), 'invalid original selected field evidence')
            original_evidence = tuple({name:_canonical_sha(value) for name, value in item.items()} for item in evidence)
            quaternion_proofs = (tuple(item.get('raw_quaternion_candidate') for item in evidence)
                                 if producer_exit_code is not None else ())
            selected[key] = (keys, original_evidence, _selected_payload_sha(row, keys, original_evidence), quaternion_proofs)
            data_sha.update(line)
            receipts_sha.update(proof)
        require(not receipts.read(1) and len(selected) == native_frames
                and data_sha.hexdigest() == inventory['selected.jsonl']['sha256']
                and receipts_sha.hexdigest() == inventory['receipts.jsonl']['sha256'], 'recovery selected stream changed')
    return selected, build, dict(worker_result_sha256=worker_hash, native_manifest_sha256=native_hash,
        worker_selected_sha256=data_sha.hexdigest(), worker_receipts_sha256=receipts_sha.hexdigest())


def overlap_worker_bindings(path, manifest, acceptance):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'entity-decoder'))
    return _selected_worker_bindings(path, manifest, producer_exit_code=acceptance['producer_exit_code'])


def independent_roster_sources(result):
    if not any(k in result for k in ('roster_source_count', 'source_epochs_independent', 'multi_source_snapshot')):
        return ()
    require(type(result.get('roster_source_count')) is int and result['roster_source_count'] == 2
            and result.get('roster_only') is True and result.get('capture_scope') == SCOPE
            and result.get('source_epochs_independent') is True and result.get('multi_source_snapshot') is False,
            'unsupported independent roster topology')
    return ROSTER_SOURCES


def independent_roster_bindings(path, manifest, result):
    from combined_storage import contained
    sources = independent_roster_sources(result)
    counts, stops, outcomes = (result.get(k) for k in ('source_entity_rows', 'source_stop_reasons', 'source_outcomes'))
    require(all(isinstance(table, dict) and set(table) == set(sources) for table in (stops, outcomes)),
            'invalid independent roster terminal declarations')
    children = result.get('children')
    require(isinstance(children, list) and len(children) == 2
            and all(isinstance(child, dict) for child in children)
            and {child.get('source') for child in children} == set(sources),
            'invalid independent roster child list')
    bindings, builds, proofs = {}, {}, {}
    sessions, process_ids = set(), set()
    for child in children:
        source = child['source']
        code, pid = child.get('exit_code'), child.get('owned_producer_pid')
        require(type(pid) is int and pid > 0 and pid not in process_ids
                and type(code) is int and code in (0, 7) and child.get('kind') == 'roster'
                and child.get('directory') == source and child.get('owned_job_closed') is True
                and child.get('outcome') == outcomes[source] == ('complete' if code == 0 else 'partial'),
                'independent roster worker did not close cleanly')
        selected, build, proof = _selected_worker_bindings(path, manifest, code, source)
        native, native_hash = _bounded_object(contained(path, f'{source}/native/manifest.json'))
        session = native.get('session_id')
        require(isinstance(session, str) and session and session not in sessions
                and native_hash == proof['native_manifest_sha256'] and native.get('stop_reason') == stops[source]
                and child.get('source_result_sha256') == proof['worker_result_sha256']
                and len(selected) == counts[source], 'independent roster worker result mismatch')
        bindings[source], builds[source], proofs[source] = selected, build, proof
        sessions.add(session)
        process_ids.add(pid)
    require(len(set(builds.values())) == 1
            and result['cli_exit_code'] == (7 if 'partial' in outcomes.values() else 0),
            'independent roster target or terminal mismatch')
    return bindings, builds, proofs, {child['source']: child for child in children}


def check_overlap_row(raw, row, start, end, selected, build, source='roster-00'):
    """Require full source brackets and source-local evidence even for discarded rows."""
    original = _record(raw)
    require(original.get('capture_scope') == SCOPE and row['source_worker'] == source,
            'overlapping source scope or worker mismatch')
    if selected is not None:
        key = original.get('input_sha256')
        require(isinstance(key, str) and key in selected and row['observed_build_sha256'] == build,
                'overlapping source worker binding mismatch')
        keys, source_evidence, expected, quaternion_proofs = selected.pop(key)
        require(_selected_payload_sha(original, keys, source_evidence) == expected,
                'overlapping source payload mismatch')
        for entity, raw_entity, proof in zip(row['entities'], original['entities'], quaternion_proofs):
            if proof is None or 'raw_quaternion_candidate' in raw_entity.get('field_evidence', {}):
                continue
            verified_entity = dict(raw_entity, field_evidence={'raw_quaternion_candidate': proof})
            candidate, evidence = raw_quaternion(verified_entity, original)
            if evidence is not None:
                evidence['source_selected_sha256'] = key
                entity['raw_quaternion_candidate'] = candidate
                entity['field_evidence']['raw_quaternion_candidate'] = evidence
    for entity in row['entities']:
        for evidence in entity['field_evidence'].values():
            require(all(start <= int(read['read_start_ticks']) <= int(read['read_end_ticks']) <= end
                        for read in evidence['reads']), 'overlapping field reads outside source bracket')


def verify_cancelled_prefix(root, path, manifest, window, normalize):
    """Return a plan for the longest independently verified prefix, not a result.json."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'entity-decoder'))
    from combined_storage import CombinedStorageIndex, contained, parse_line
    require(manifest.get('status') in FINAL and window.get('reason') == 'cancelled'
            and window.get('recorder_accepted') is False and window.get('manifest_accepted') is False
            and window.get('start_ticks') is not None and window.get('end_ticks') is not None,
            'recovery requires a finalized cancelled window')
    path = confined(root, path)
    require(path.is_dir() and not (path/'result.json').exists() and not (path/'game-state.jsonl').exists(),
            'recovery requires an unfinalized cohort window')
    selected, build, worker_proof = _selected_worker_bindings(path, manifest)
    index = contained(path, 'storage-index.jsonl')
    with index.open('rb') as f:
        raw_index = f.read(65537)
    require(0 < len(raw_index) <= 65536, 'recovery storage index bound')
    lines = raw_index.splitlines(keepends=True)
    reader = CombinedStorageIndex(path, maximum_cohorts=64, maximum_total_bytes=512*1024**2,
                                  maximum_index_bytes=65536, maximum_cohort_bytes=64*1024**2)
    used, files = set(), []
    prefix_hash, source_hash = hashlib.sha256(), hashlib.sha256()
    first, last, frames, rows = None, None, 0, 0
    last_seal, stopped = None, 'end_of_index'
    for i in range(0, len(lines), 2):
        if i+1 >= len(lines):
            stopped = 'unsealed_or_truncated_tail'
            break
        try:
            opening, closing = parse_line(lines[i]), parse_line(lines[i+1])
            require(opening.get('kind') == 'open' and closing.get('kind') == 'seal', 'recovery pair mismatch')
            reader.consume(lines[i])
            seal = reader.consume(lines[i+1])
            descriptor = seal['files'][0]
            source = contained(path, seal['directory']+'/'+descriptor['path'])
            candidate_hash = source_hash.copy()
            candidate_used, first_tick, last_tick, frame_count = set(), first, last, frames
            for raw in _sealed_rows(source, descriptor):
                r = _record(raw)
                row = normalize(raw)
                require(r.get('capture_scope') == SCOPE, 'recovery source scope mismatch')
                candidate_hash.update(raw)
                if row['kind'] == 'status':
                    require(r.get('source_id') == 'roster-00' and row['status'] in ('source_start', 'source_end'),
                            'recovery source status mismatch')
                    continue
                require(row['kind'] == 'entities' and row['source_worker'] == 'roster-00'
                        and row['observed_build_sha256'] == build, 'recovery source worker or build mismatch')
                h = r.get('input_sha256')
                require(isinstance(h, str) and h in selected and h not in used and h not in candidate_used,
                        'recovery source row does not match worker')
                keys, original_evidence, expected, _ = selected[h]
                require(_selected_payload_sha(r, keys, original_evidence) == expected,
                        'recovery source payload does not match worker')
                stamp = row['timestamp']
                start, end = int(stamp['start_ticks']), int(stamp['end_ticks'])
                require(stamp['frequency'] == manifest['qpc_frequency']
                        and int(window['start_ticks']) <= start <= end < int(window['end_ticks'])
                        and (last_tick is None or end > last_tick), 'recovery source clock mismatch')
                candidate_used.add(h)
                first_tick = end if first_tick is None else first_tick
                last_tick, frame_count = end, frame_count+1
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            stopped = 'mismatched_or_truncated_cohort'
            break  # Commit none of this cohort's data and never inspect a later cohort.
        source_hash, first, last, frames = candidate_hash, first_tick, last_tick, frame_count
        used.update(candidate_used)
        prefix_hash.update(lines[i])
        prefix_hash.update(lines[i+1])
        last_seal = hashlib.sha256(lines[i+1]).hexdigest()
        files.append((seal['directory'], descriptor))
        rows += descriptor['rows']
    require(files and frames > 0, 'no verified recovery entity prefix')
    evidence = dict(**worker_proof, original_storage_index_sha256=hashlib.sha256(raw_index).hexdigest(),
                    prefix_storage_index_sha256=prefix_hash.hexdigest(), last_seal_sha256=last_seal,
                    source_sha256=source_hash.hexdigest(), observed_build_sha256=build,
                    sealed_cohorts=len(files), source_rows=rows, source_frames=frames,
                    first_end_ticks=str(first), last_end_ticks=str(last), stop_reason=stopped,
                    recorder_result_fabricated=False, continuation_inferred=False)
    return dict(files=files, evidence=evidence, window=window)
