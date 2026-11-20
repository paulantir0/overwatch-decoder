"""Pinned bounded replay chunks. The server serves only this explicit file set."""
import hashlib
import json
import math
import re
from pathlib import Path

MAX_CHUNK=128*1024**2
ROSTER_SOURCES = ('roster-00', 'roster-01')
WORKER_HASHES = ('worker_result_sha256', 'native_manifest_sha256', 'worker_selected_sha256', 'worker_receipts_sha256')


def _hashes(proof, keys):
    return isinstance(proof, dict) and all(isinstance(proof.get(k), str) and re.fullmatch(r'[a-f0-9]{64}', proof[k]) for k in keys)


def _ticks(*values):
    if any(not isinstance(v, str) or not re.fullmatch(r'\d{1,20}', v) for v in values):
        raise ValueError('Invalid replay source clock')
    return tuple(map(int, values))


def checked_index(path):
    path=Path(path)
    if path.stat().st_size>1024**2:return None,{}
    value=json.loads(path.read_bytes())
    if value.get('schema')!='overwatch-decoder.entity-replay-index/1':return None,{}
    repeat = value.get('repeat_windows') is True
    if (value.get('public_state_eligible') is not False or not isinstance(value.get('chunks'), list)
        or not (0 if repeat else 1) <= len(value['chunks']) <= 240):
        raise ValueError('Invalid replay chunk index')
    files={};previous=-math.inf
    for index,row in enumerate(value['chunks']):
        name=row.get('path','');start,end=row.get('start_seconds'),row.get('end_seconds')
        if not isinstance(name,str) or Path(name).is_absolute() or '\\' in name or ':' in name or any(p in ('','.','..') for p in name.split('/')):
            raise ValueError('Unsafe replay chunk path')
        file=path.parent/name
        if not file.resolve().is_relative_to(path.parent.resolve()) or file.is_symlink() or not file.is_file():raise ValueError('Replay chunk escapes index')
        if not all(type(t) in (int,float) and math.isfinite(t) and t>=0 for t in (start,end)) or end<start or start<previous:
            raise ValueError('Overlapping or invalid replay chunk time')
        previous=end
        if 'roster_sources' in row or 'multi_source_snapshot' in row:
            if row.get('roster_sources') != list(ROSTER_SOURCES) or row.get('multi_source_snapshot') is not False:
                raise ValueError('Invalid independent roster topology')
        if file.stat().st_size!=row.get('bytes') or file.stat().st_size>MAX_CHUNK:raise ValueError('Replay chunk byte bound')
        with file.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if digest!=row.get('sha256'):raise ValueError('Replay chunk digest mismatch')
        url=f'/chunks/{index:04d}.json';row['url']=url;files[url]=file.resolve()
    if repeat:
        end = value.get('end_seconds')
        if type(end) not in (int, float) or not math.isfinite(end) or end < 0 or previous > end:
            raise ValueError('Invalid repeat replay time bounds')
        windows = value.get('session_windows')
        if (not isinstance(windows, list) or len(windows) > 240 or
            any(not isinstance(w, dict) or type(w.get('window')) is not int or w['window'] != n
                or type(w.get('replayed')) is not bool for n, w in enumerate(windows, 1))):
            raise ValueError('Invalid repeat replay windows')
        for row in value['chunks']:
            n = row.get('recorder_window')
            if type(n) is not int or not 1 <= n <= len(windows):
                raise ValueError('Chunk lacks matching recorder window')
            window = windows[n-1]
            if window['replayed'] is not True or window.get('source_sha256') != row.get('source_sha256'):
                raise ValueError('Chunk source or window mismatch')
            if (window.get('recorder_accepted') is True and row.get('recovery_status') is None
                    and window.get('recovery_status') is None):
                continue
            _check_recovery(value, window, row)
        if [row['recorder_window'] for row in value['chunks']] != [w['window'] for w in windows if w['replayed']]:
            raise ValueError('Duplicate or missing replay window')
        if 'overlapping_windows' in value or any('overlap_selection' in w or 'launch_qpc_ticks' in w for w in windows):
            _check_overlap_index(value, windows)
        cursor, gaps = 0, []
        for row in value['chunks']:
            if row['start_seconds'] > cursor:
                gaps.append(dict(start_seconds=cursor, end_seconds=row['start_seconds']))
            cursor = row['end_seconds']
        if cursor < end:
            gaps.append(dict(start_seconds=cursor, end_seconds=end))
        if value.get('gaps') != gaps:
            raise ValueError('Invalid repeat replay gaps')
    return value,files


def _check_recovery(index, window, chunk):
    proof = window.get('recovery_evidence')
    expected = 'verified_sealed_prefix'
    if (index.get('sealed_prefix_recovery') is not True or window.get('recorder_accepted') is not False
        or window.get('manifest_accepted') is not False or window.get('reason') != 'cancelled'
        or window.get('recovery_status') != expected or chunk is not None and chunk.get('recovery_status') != expected
        or not isinstance(proof, dict) or proof.get('source_sha256') != window.get('source_sha256')
        or proof.get('recorder_result_fabricated') is not False or proof.get('continuation_inferred') is not False):
        raise ValueError('Chunk lacks verified recovery evidence')
    hashes = (*WORKER_HASHES, 'original_storage_index_sha256', 'prefix_storage_index_sha256', 'last_seal_sha256',
              'source_sha256', 'observed_build_sha256')
    if not _hashes(proof, hashes):
        raise ValueError('Invalid recovery evidence hashes')
    view = window.get('overlap_selection') if index.get('overlapping_windows') is True else None
    if index.get('overlapping_windows') is True and not isinstance(view, dict):
        raise ValueError('Recovered overlap lacks view selection')
    frames = view.get('source_frames') if view is not None else chunk.get('summary', {}).get('frames')
    if (type(proof.get('sealed_cohorts')) is not int or not 1 <= proof['sealed_cohorts'] <= 64
        or type(proof.get('source_frames')) is not int or not 1 <= proof['source_frames'] <= 100000
        or proof['source_frames'] != frames):
        raise ValueError('Invalid recovery evidence counts')
    stamps = [index.get('origin_ticks'), window.get('start_ticks'), proof.get('first_end_ticks'),
              proof.get('last_end_ticks'), window.get('end_ticks')]
    frequency = index.get('frequency')
    if (type(frequency) is not int or not 0 < frequency <= 2**53-1 or
        any(not isinstance(v, str) or not re.fullmatch(r'\d{1,20}', v) for v in stamps)):
        raise ValueError('Invalid recovery evidence clock')
    origin, begin, first, last, end = map(int, stamps)
    if not origin <= begin <= first <= last < end:
        raise ValueError('Recovered chunk exceeds verified prefix')
    if view is not None:
        if (view.get('source_first_end_ticks') != proof['first_end_ticks'] or
                view.get('source_last_end_ticks') != proof['last_end_ticks']):
            raise ValueError('Overlap view exceeds verified prefix')
    elif (chunk['start_seconds'] != (first-origin)/frequency or
          chunk['end_seconds'] != min((last-origin)/frequency+.05, (end-origin)/frequency)):
        raise ValueError('Recovered chunk exceeds verified prefix')


def _check_overlap_index(index, windows):
    chunks = {chunk['recorder_window']: (chunk, index['chunks'][i+1]['start_seconds'] if i+1 < len(index['chunks']) else math.inf)
              for i, chunk in enumerate(index['chunks'])}
    origin, = _ticks(index.get('origin_ticks'))
    frequency, duration, lead = (index.get(k) for k in ('frequency', 'window_seconds', 'successor_lead_seconds'))
    if (index.get('overlapping_windows') is not True or index.get('successor_timing_basis') != 'recorder_launch_qpc'
        or not all(type(v) is int for v in (frequency, duration, lead))
        or not (0 < frequency <= 2**53-1 and 20 <= duration <= 60 and 0 < lead < duration)):
        raise ValueError('Invalid overlap view clock')
    prior, cutoff = None, None
    for window in windows:
        n, predecessor = window['window'], window.get('predecessor_window')
        begin, end = _ticks(window.get('start_ticks'), window.get('end_ticks'))
        if (window.get('launch_qpc_ticks') != window['start_ticks'] or window.get('timing_basis') != 'recorder_launch_qpc'
            or 'predecessor_window' not in window or not origin <= begin <= end
            or window.get('start_seconds') != (begin-origin)/frequency or window.get('end_seconds') != (end-origin)/frequency
            or predecessor is not None and (type(predecessor) is not int or n < 2 or predecessor != n-1)):
            raise ValueError('Invalid overlap window launch')
        chunk, next_start = chunks.get(n, (None, math.inf))
        view = window.get('overlap_selection')
        if view is None and chunk is None and window.get('recovery_status') != 'verified_sealed_prefix':
            continue
        if (not isinstance(view, dict) or not _hashes(window, ('source_sha256',))
            or view.get('cutover_from_window') != prior or view.get('cutover_ticks') != cutoff):
            raise ValueError('Invalid overlap cutover source')
        multi = 'overlap_source_selections' in window or 'roster_source_evidence' in window
        if multi:
            _check_independent_overlap(window, view, chunk, begin, end)
        if window.get('recorder_accepted') is True:
            if window.get('manifest_accepted') is not True or not (multi or _hashes(window.get('overlap_source_evidence'), WORKER_HASHES)):
                raise ValueError('Missing overlap worker evidence')
        elif chunk is None:
            _check_recovery(index, window, None)
        total, kept, before, across = (view.get(k) for k in ('source_frames', 'selected_frames',
                                       'dropped_at_or_before_cutover', 'dropped_straddling_cutover'))
        if (not all(type(c) is int and 0 <= c <= 100000 for c in (total, kept, before, across))
            or total != kept+before+across or across > (2 if multi else 1) or cutoff is None and total != kept
            or bool(kept) != (chunk is not None)):
            raise ValueError('Invalid overlap selection counts')
        original = [view.get(k) for k in ('source_first_start_ticks', 'source_first_end_ticks', 'source_last_end_ticks')]
        first_selected = [view.get(k) for k in ('selected_first_start_ticks', 'selected_first_end_ticks')]
        if total:
            start, first, last = _ticks(*original)
            if not begin <= start <= first <= last <= end:
                raise ValueError('Invalid overlap original source range')
        elif original != [None, None, None]:
            raise ValueError('Empty overlap source has a time range')
        if not kept:
            if first_selected != [None, None] or (total and last > int(cutoff) and across == 0):
                raise ValueError('Unselected overlap source claims coverage')
            continue
        start_kept, first_kept = _ticks(*first_selected)
        kept_last = int(view['selected_last_end_ticks']) if multi else last
        if ((not multi and start_kept < start) or not start_kept <= first_kept <= kept_last or not first <= first_kept
            or (cutoff is not None and (start_kept < int(cutoff) or first_kept <= int(cutoff)))
            or (total == kept and (start, first) != (start_kept, first_kept))
            or kept != chunk.get('summary', {}).get('frames')
            or chunk['start_seconds'] != (first_kept-origin)/frequency
            or chunk['end_seconds'] != min((kept_last-origin)/frequency+.05, (end-origin)/frequency, next_start)):
            raise ValueError('Overlap chunk exceeds selected source range')
        prior, cutoff = n, original[-1]


def _check_independent_overlap(window, view, chunk, begin, end):
    views, proofs = window.get('overlap_source_selections'), window.get('roster_source_evidence')
    if (window.get('recorder_accepted') is not True
        or not all(isinstance(m, dict) and set(m) == set(ROSTER_SOURCES) for m in (views, proofs))
        or chunk is not None and chunk.get('multi_source_snapshot') is not False):
        raise ValueError('Missing independent overlap evidence')
    originals, selected = [], []
    counts = ('source_frames', 'selected_frames', 'dropped_at_or_before_cutover', 'dropped_straddling_cutover')
    cutoff = view['cutover_ticks']
    for source in ROSTER_SOURCES:
        v = views[source]
        if (not isinstance(v, dict) or not _hashes(proofs[source], WORKER_HASHES)
            or any(v.get(k) != view[k] for k in ('cutover_ticks', 'cutover_from_window'))):
            raise ValueError('Invalid independent overlap proof')
        total, kept, before, across = (v.get(k) for k in counts)
        if (not all(type(n) is int and 0 <= n <= 100000 for n in (total, kept, before, across))
            or total != kept+before+across or across > 1 or cutoff is None and total != kept):
            raise ValueError('Invalid independent overlap counts')
        original = [v.get(k) for k in ('source_first_start_ticks', 'source_first_end_ticks', 'source_last_end_ticks')]
        first_kept = [v.get(k) for k in ('selected_first_start_ticks', 'selected_first_end_ticks')]
        if total:
            start, first, last = _ticks(*original)
            if not begin <= start <= first <= last <= end:
                raise ValueError('Independent overlap source outside its window')
            originals.append(v)
            if kept:
                lo, hi = _ticks(*first_kept)
                if (not start <= lo <= hi <= last or first > hi or cutoff is not None and not lo >= int(cutoff) < hi
                    or total == kept and (start, first) != (lo, hi)):
                    raise ValueError('Independent overlap source crosses its cutoff')
                selected.append(v)
            elif last > int(cutoff) and across == 0:
                raise ValueError('Unselected independent source claims coverage')
        elif original != [None, None, None]:
            raise ValueError('Empty independent source has time bounds')
        if not kept and first_kept != [None, None]:
            raise ValueError('Empty independent selection has time bounds')
    expected = {k: sum(v[k] for v in views.values()) for k in counts}
    for rows, prefix in ((originals, 'source'), (selected, 'selected')):
        first_end = prefix+'_first_end_ticks'
        first = min(rows, key=lambda v: int(v[first_end]), default={})
        expected[first_end] = first.get(first_end)
        expected[prefix+'_first_start_ticks'] = first.get(prefix+'_first_start_ticks')
        expected[prefix+'_last_end_ticks'] = max((v['source_last_end_ticks'] for v in rows), key=int, default=None)
    if any(view.get(k) != value for k, value in expected.items()):
        raise ValueError('Aggregate overlap does not match independent sources')
