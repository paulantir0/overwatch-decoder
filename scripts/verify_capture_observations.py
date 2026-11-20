#!/usr/bin/env python3
"""Verify private flat/cohort recorder artifacts; no live target access."""
import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools/entity-decoder'))
sys.path.insert(0, str(ROOT / 'tools/entity-replay'))
from overwatch_decoder.session_observations import from_line
from combined_storage import (CombinedStorageIndex, contained, integer, strict_json,
                              MAX_COHORTS, MAX_COHORT_BYTES, MAX_TOTAL_BYTES,
                              MAX_INDEX_BYTES, MAX_INDEX_LINE)
from session_windows import read_repeat_session

MAX_LINE = 2 * 1024**2
MAX_ROWS = 2_000_000
MAX_JOURNAL_BYTES = 8 * 1024**3


def require(value, reason):
    if not value:
        raise ValueError(reason)


def document(path, maximum):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'JSON document byte bound')
    value = strict_json(raw)
    require(isinstance(value, dict), 'JSON document must be an object')
    return value


def bounded_lines(stream, maximum=MAX_LINE, total_limit=MAX_TOTAL_BYTES):
    total = rows = 0
    while raw := stream.readline(maximum + 1):
        total += len(raw)
        rows += 1
        require(len(raw) <= maximum and raw.endswith(b'\n'), 'JSONL line bound or partial tail')
        require(total <= total_limit and rows <= MAX_ROWS, 'JSONL total bound')
        yield raw


def pin(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def journal_receipt(value, cohorts):
    require(isinstance(value, dict), 'invalid recorder receipt')
    require(integer(value.get('source_offset')) and integer(value.get('source_bytes'), 1)
            and value['source_bytes'] <= MAX_LINE and pin(value.get('source_sha256')), 'invalid recorder receipt fields')
    if 'source_schema' in value:
        require(value['source_schema'] in ('overwatch-decoder.private.selected-compact/1', 'overwatch-decoder.private.damage-feedback-candidate/1', 'overwatch-decoder.private.incoming-source-observation/1',
                'overwatch-decoder.private.combined-status/1'), 'unsupported recorder source schema')
    if 'combined_sequence' in value:
        require(integer(value['combined_sequence']) and value['combined_sequence'] < MAX_ROWS,
                'invalid recorder global sequence')
    if cohorts:
        require(value.get('source_schema') in ('overwatch-decoder.private.selected-compact/1', 'overwatch-decoder.private.damage-feedback-candidate/1', 'overwatch-decoder.private.incoming-source-observation/1',
                'overwatch-decoder.private.combined-status/1'), 'missing/unsupported recorder source schema')
        ordinal = value.get('storage_cohort')
        require(integer(ordinal, 1) and ordinal <= MAX_COHORTS, 'invalid receipt storage cohort')
        path = f'cohort-{ordinal:06d}/game-state.jsonl'
        require(value.get('source_path') == path, 'receipt cohort/source path mismatch')
        require(integer(value.get('combined_sequence')) and value['combined_sequence'] < MAX_ROWS,
                'invalid recorder global sequence')
        require(value.get('sealed_acceptance') is False and value.get('durability_verified') is False,
                'live cohort receipt must remain provisional')
    else:
        path = 'game-state.jsonl'
        require('storage_cohort' not in value and value.get('source_path', path) == path,
                'flat receipt contains a cohort or wrong source path')
    # Do not retain arbitrary fields from an otherwise bounded journal row.
    receipt = {key: value[key] for key in ('source_offset', 'source_bytes', 'source_sha256',
               'source_schema', 'storage_cohort', 'combined_sequence') if key in value}
    return path, receipt


def sealed_sources(window, observations, result):
    total = observations.get('maximum_output_bytes', MAX_TOTAL_BYTES)
    cohort_mib = observations.get('storage_cohort_mib', 256)
    require(integer(total, 1) and total <= MAX_TOTAL_BYTES and integer(cohort_mib, 1)
            and cohort_mib <= 256, 'invalid recorded storage bounds')
    reader = CombinedStorageIndex(window, maximum_cohorts=MAX_COHORTS,
        maximum_total_bytes=total, maximum_index_bytes=MAX_INDEX_BYTES,
        maximum_cohort_bytes=min(MAX_COHORT_BYTES, cohort_mib * 1048576))
    sources = []
    index_path = contained(window, 'storage-index.jsonl')
    with index_path.open('rb') as stream:
        for raw in bounded_lines(stream, MAX_INDEX_LINE, MAX_INDEX_BYTES):
            record = reader.consume(raw)
            if record['kind'] == 'seal':
                sources.append((record['directory'] + '/game-state.jsonl', record['ordinal'], record['files']))
    summary = reader.complete()
    require({p.name for p in window.glob('cohort-*')} == {str(PurePosixPath(p).parent) for p, _, _ in sources},
            'unindexed or missing storage cohort')
    require(summary['output_rows'] > 0, 'cohort producer emitted no compact rows')
    require(result is not None and result.get('schema') == 'overwatch-decoder.private.combined-run/2', 'cohort /2 result missing')
    for key, value in summary.items():
        require(type(result.get(key)) is type(value) and result[key] == value, 'cohort result/index summary mismatch: ' + key)
    require('error' in result and 'capture_scope' in result, 'cohort result lifecycle fields missing')
    require(result.get('provisional_tail') is False, 'cohort result declares/misses a provisional tail status')
    # Detect same-size index edits between its first verification and source read.
    fresh = hashlib.sha256()
    with index_path.open('rb') as stream:
        for raw in bounded_lines(stream, MAX_INDEX_LINE, MAX_INDEX_BYTES):
            fresh.update(raw)
    require(fresh.hexdigest() == summary['storage_index_sha256'], 'storage index changed during verification')
    return sources, summary


def delivery_clock(proof, value, normalized, received, manifest, expected_scope):
    require(isinstance(proof, dict) and proof.get('line_sha256') == value['_sha256'], 'delivery/source digest mismatch')
    if 'combined_sequence' in value:
        require(type(proof.get('combined_sequence')) is int
                and proof['combined_sequence'] == value['combined_sequence'], 'delivery/source sequence mismatch')
    frequency = manifest['qpc_frequency']
    require(proof.get('frequency') == frequency and type(proof.get('frequency')) is int,
            'delivery frequency mismatch')
    before, after = proof.get('before_write_qpc_ticks'), proof.get('file_flushed_qpc_ticks')
    require(integer(before) and integer(after) and manifest['qpc_origin'] <= before <= after
            and before <= received, 'delivery/recorder causal QPC order mismatch')
    if 'capture_scope' in proof:
        require(proof['capture_scope'] == expected_scope, 'delivery capture scope mismatch')
    timestamp = normalized.get('timestamp')
    if timestamp:
        end = int(timestamp['end_ticks'])
        require(type(proof.get('capture_end_qpc_ticks')) is int and proof['capture_end_qpc_ticks'] == end and end <= before, 'capture/delivery QPC link mismatch')
        delay = proof.get('capture_to_file_flush_ms')
        require(type(delay) in (int, float) and math.isfinite(delay)
                and abs(delay - (after-end)*1000/frequency) < 1e-7, 'delivery latency declaration mismatch')
    else:
        require(proof.get('capture_end_qpc_ticks') is None, 'status delivery invented capture time')
    # The line can be visible before the writer resumes to sample its after marker.
    return received < after


def quantiles(values):
    values = sorted(values)
    if not values:
        return dict(count=0)
    return dict(count=len(values), minimum=values[0], p50=values[math.ceil(.5*(len(values)-1))],
                p95=values[math.ceil(.95*(len(values)-1))], maximum=values[-1])


def verify(directory, *, ffprobe=None, require_complete_window=False):
    root = Path(directory)
    manifest = document(contained(root, 'session.json'), 4 * 1024**2)
    require(manifest.get('schema') == 'overwatch-decoder.capture-session/1', 'unsupported session')
    require(manifest.get('status') in ('finished', 'finished_with_gaps'), 'session has not finalized')
    require(integer(manifest.get('qpc_origin')) and integer(manifest.get('qpc_frequency'), 1), 'invalid session QPC clock')
    observations = manifest.get('observations')
    require(isinstance(observations, dict), 'observation plan absent')
    expected_scope = observations.get('capture_scope', 'controlled_practice')
    require(expected_scope in ('controlled_practice', 'read_only_user_gameplay'), 'unsupported capture scope')
    storage_format = observations.get('storage_format', 'flat_v1')
    require(storage_format in ('flat_v1', 'cohorts_v1'), 'unsupported storage format')
    cohorts = storage_format == 'cohorts_v1'
    repeat = read_repeat_session(root, manifest) if cohorts else None
    accepted = {}
    if cohorts:
        maximum = observations.get('maximum_windows', 1)
        if repeat is None:
            require(type(maximum) is int and maximum == 1, 'cohort capture requires a single-window or verified repeat plan')
        else:
            require(integer(maximum, 2) and maximum <= 240 and 0 < len(repeat['windows']) <= maximum,
                    'invalid repeat cohort window bound')
            require(all(w['recorder_accepted'] for w in repeat['windows']),
                    'repeat cohort verification requires acceptance of every attempted window')
            accepted = {w['window']: w for w in repeat['windows']}
            require(observations.get('completed_windows') == len(accepted), 'manifest repeat acceptance count mismatch')
    if require_complete_window:
        require(observations.get('completed_windows', 0) >= 1 and observations.get('error') is None,
                'no successful completed observation window')
    receipts = {}; window_ends = set(); ended = False; journal_rows = performance_count = 0
    cpu_max = working_set_max = None
    with gzip.open(contained(root, 'events.jsonl.gz'), 'rb') as stream:
        for raw in bounded_lines(stream, total_limit=MAX_JOURNAL_BYTES):
            require(not ended, 'journal records after trailer')
            row = strict_json(raw)
            require(isinstance(row, dict), 'journal row must be an object')
            kind = row.get('kind')
            if kind == 'observation_receipt':
                require(integer(row.get('window'), 1) and row['window'] <= 240
                        and integer(row.get('qpc_ticks')), 'invalid receipt window/QPC')
                path, receipt = journal_receipt(row.get('receipt'), cohorts)
                key = (row['window'], path, receipt['source_offset'])
                require(key not in receipts, 'duplicate source receipt')
                receipts[key] = (receipt, row['qpc_ticks'])
            elif kind == 'recorder_performance':
                performance_count += 1
                value = row.get('cpu_percent_machine')
                if type(value) in (int, float) and math.isfinite(value):
                    cpu_max = value if cpu_max is None else max(cpu_max, value)
                value = row.get('working_set_bytes')
                if integer(value):
                    working_set_max = value if working_set_max is None else max(working_set_max, value)
            elif kind == 'observation_window_end':
                require(integer(row.get('window'), 1) and row['window'] not in window_ends, 'duplicate/invalid window end')
                window_ends.add(row['window'])
            elif kind == 'journal_end':
                ended = True
                require(row.get('written', journal_rows) == journal_rows and row.get('dropped', 0) == 0,
                        'journal trailer count/drop mismatch')
            journal_rows += 1
    require(ended, 'journal trailer missing')
    require(manifest.get('journal', {}).get('dropped') == 0, 'recorder journal dropped events')
    if 'written' in manifest.get('journal', {}):
        require(manifest['journal']['written'] == journal_rows-1, 'manifest/journal count mismatch')
    counts = dict(entities=0, damage=0, incoming_source=0, incoming_source_observations=0, incoming_source_unknowns=0, status=0, position_values=0, health_values=0,
                  hero_values=0, relation_values=0, username_values=0)
    checked = delivery_checked = visibility_marker_races = 0; delay_max = None
    windows = []; builds = set(); observed_windows = set()
    delays = dict(entities_nonempty=[], entities_empty=[], damage_candidates=[], incoming_source_observed=[], incoming_source_unknown=[])
    for window in sorted(contained(root, 'observations').glob('window-*')):
        if not window.is_dir():
            continue
        require(re.fullmatch(r'window-\d{4}', window.name), 'invalid observation window path')
        contained(root, 'observations/' + window.name)
        number = int(window.name.split('-')[-1])
        require(1 <= number <= 240 and number not in observed_windows, 'duplicate/invalid window')
        observed_windows.add(number)
        flat, index = window/'game-state.jsonl', window/'storage-index.jsonl'
        if cohorts:
            require(index.is_file() and not flat.exists(), 'cohort format missing or ambiguous')
        else:
            require(flat.is_file() and not index.exists() and not any(window.glob('cohort-*')), 'flat format missing or ambiguous')
        result_path = contained(window, 'result.json')
        result = document(result_path, 1048576) if result_path.is_file() else None
        if cohorts:
            sources, storage = sealed_sources(window, observations, result)
            if repeat is not None:
                require(number in accepted and result.get('cli_exit_code') == accepted[number]['producer_exit_code']
                        and result.get('source_unavailable') is not True,
                        'sealed repeat result disagrees with recorder acceptance')
        else:
            sources = [('game-state.jsonl', None, None)]; storage = None
            if result is not None:
                require(result.get('schema') == 'overwatch-decoder.private.combined-run/1', 'flat /1 result mismatch')
        sha = hashlib.sha256(); rows = output_bytes = 0
        for relative, ordinal, declarations in sources:
            data_path = contained(window, relative)
            proof_path = contained(window, str(PurePosixPath(relative).parent/'delivery-receipts.jsonl'))
            proof_stream = proof_path.open('rb') if proof_path.is_file() else None
            require(not cohorts or proof_stream is not None, 'cohort delivery receipts missing')
            file_sha = hashlib.sha256(); proof_sha = hashlib.sha256(); offset = proof_bytes = file_rows = 0
            try:
                with data_path.open('rb') as stream:
                    for raw in bounded_lines(stream):
                        value = strict_json(raw); row = from_line(raw); pin_value = hashlib.sha256(raw).hexdigest()
                        require(isinstance(value, dict), 'source must be an object')
                        if 'capture_scope' in value:
                            require(value['capture_scope'] == expected_scope, 'source capture scope mismatch')
                        if cohorts or 'combined_sequence' in value:
                            require(type(value.get('combined_sequence')) is int and value['combined_sequence'] == rows,
                                    'cohort global source sequence mismatch')
                        item = receipts.pop((number, relative, offset), None)
                        require(item is not None, 'source line lacks journal receipt')
                        receipt, received = item
                        if repeat is not None:
                            require(int(accepted[number]['start_ticks']) <= received <= int(accepted[number]['end_ticks']),
                                    'receipt outside accepted recorder window')
                        require(receipt['source_bytes'] == len(raw) and receipt['source_sha256'] == pin_value,
                                'source receipt byte/digest mismatch')
                        if 'source_schema' in receipt:
                            require(receipt['source_schema'] == value['schema'], 'recorder source schema mismatch')
                        if cohorts or 'combined_sequence' in receipt:
                            require(type(receipt.get('combined_sequence')) is int
                                    and receipt['combined_sequence'] == value.get('combined_sequence'), 'recorder global sequence mismatch')
                        timestamp = row.get('timestamp')
                        if timestamp:
                            require(timestamp['frequency'] == manifest['qpc_frequency'], 'source clock frequency mismatch')
                            end = int(timestamp['end_ticks'])
                            if repeat is not None:
                                require(int(accepted[number]['start_ticks']) <= int(timestamp['start_ticks']),
                                        'source predates its accepted recorder window')
                            require(int(timestamp['start_ticks']) >= manifest['qpc_origin'] and received >= end,
                                    'source/receipt QPC order mismatch')
                            delay = (received-end)/timestamp['frequency']
                            delay_max = delay if delay_max is None else max(delay_max, delay)
                            group = ('entities_nonempty' if row['entities'] else 'entities_empty') if row['kind'] == 'entities' else ('incoming_source_' + row['status'] if row['kind'] == 'incoming_source' else 'damage_candidates')
                            delays[group].append(delay)
                        if proof_stream is not None:
                            proof = proof_stream.readline(4097)
                            require(0 < len(proof) <= 4096 and proof.endswith(b'\n'), 'delivery receipt line missing/bound')
                            value['_sha256'] = pin_value
                            visibility_marker_races += delivery_clock(strict_json(proof), value, row, received, manifest, expected_scope)
                            proof_sha.update(proof); proof_bytes += len(proof); delivery_checked += 1
                        counts[row['kind']] += 1
                        if row['kind'] == 'incoming_source':
                            counts['incoming_source_observations' if row['status'] == 'observed' else 'incoming_source_unknowns'] += 1
                        for entity in row.get('entities', []):
                            for field in ('position', 'health', 'hero', 'relation', 'username'):
                                if entity[field]['value'] is not None: counts[field+'_values'] += 1
                            if entity['position']['value'] is not None and require_complete_window:
                                require(row.get('observed_build_sha256') is not None, 'position lacks observed build identity')
                        if row.get('observed_build_sha256'): builds.add(row['observed_build_sha256'])
                        sha.update(raw); file_sha.update(raw); offset += len(raw); output_bytes += len(raw)
                        rows += 1; file_rows += 1; checked += 1
                        require(rows <= MAX_ROWS and output_bytes <= MAX_TOTAL_BYTES, 'source total bound')
                if proof_stream is not None: require(proof_stream.read(1) == b'', 'delivery receipts after source EOF')
            finally:
                if proof_stream is not None: proof_stream.close()
            if declarations is not None:
                for actual, expected in zip([(offset, file_rows, file_sha.hexdigest()),
                                             (proof_bytes, file_rows, proof_sha.hexdigest())], declarations):
                    require(actual == (expected['bytes'], expected['rows'], expected['sha256']), 'sealed files changed during verification')
        state = result['status'] if result is not None else 'incomplete'
        if result is not None:
            require(result.get('output_sha256') == sha.hexdigest() and result.get('output_rows') == rows
                    and result.get('output_bytes') == output_bytes, 'combined result/source digest mismatch')
            require(result.get('capture_scope', 'controlled_practice') == expected_scope, 'combined capture scope mismatch')
            if cohorts or number in window_ends:
                require(state in ('complete', 'partial') and result.get('error') is None
                        and result.get('cleanup_errors') == [], 'completed window has failed source/cleanup')
                if cohorts or 'cli_exit_code' in result:
                    require(type(result.get('cli_exit_code')) is int
                            and result['cli_exit_code'] == (0 if state == 'complete' else 7), 'producer exit/status mismatch')
        windows.append(dict(window=number, status=state, rows=rows, bytes=output_bytes, sha256=sha.hexdigest(),
            storage_format=storage_format, sealed_storage_cohorts=storage['storage_cohorts'] if storage else 0,
            recorder_window_finalized=number in window_ends))
    require(windows and window_ends <= observed_windows, 'missing observation window')
    if repeat is not None:
        require(window_ends == observed_windows == set(accepted), 'repeat producer window or journal acceptance mismatch')
    else:
        require(not cohorts or len(windows) == 1, 'cohort capture requires one producer window')
    require(not receipts, 'receipt references absent source bytes')
    if cohorts and 'sealed_storage_cohorts' in observations:
        require(type(observations['sealed_storage_cohorts']) is int
                and observations['sealed_storage_cohorts'] == sum(w['sealed_storage_cohorts'] for w in windows),
                'recorder/producer sealed cohort count mismatch')
    if 'receipt_rows' in observations:
        require(observations['receipt_rows'] == checked, 'manifest/source receipt count mismatch')
    if require_complete_window:
        require(any(w['status'] == 'complete' and w['recorder_window_finalized'] for w in windows), 'no fully complete producer window')
        require(counts['position_values'] > 0, 'no observed entity positions for replay')
    video = manifest.get('video') or {}
    require(contained(root, 'desktop.mkv').is_file() and (root/'desktop.mkv').stat().st_size > 0, 'video file missing')
    media = None
    if ffprobe:
        command = [str(ffprobe), '-v', 'error', '-threads', '2', '-select_streams', 'v:0', '-count_frames', '-show_entries',
                   'stream=codec_name,width,height,nb_read_frames,avg_frame_rate:format=duration', '-of', 'json', str(root/'desktop.mkv')]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        require(result.returncode == 0 and not result.stderr.strip(), 'video probe/decode reported an error')
        media = json.loads(result.stdout)
        require(float(media['format']['duration']) > 0 and int(media['streams'][0]['nb_read_frames']) > 0, 'no decoded video frames')
    return dict(schema='overwatch-decoder.recorder-acceptance/1', session_status=manifest['status'], capture_scope=expected_scope,
        storage_format=storage_format, synthetic_fixture=manifest.get('synthetic_fixture') is True,
        windows=windows, observation_counts=counts, observed_builds=sorted(builds), verified_receipts=checked,
        verified_delivery_receipts=delivery_checked, reader_before_writer_after_marker_rows=visibility_marker_races,
        recorder_performance_samples=performance_count, recorder_cpu_percent_machine_max=cpu_max,
        recorder_working_set_max=working_set_max, receipt_delay_seconds_max=delay_max,
        receipt_delay_seconds_by_kind={key: quantiles(values) for key, values in delays.items()},
        receipt_delay_interpretation='delivery after source read end, includes watermark/buffering; not atomic/video alignment',
        video_qpc_bounds_valid=video.get('source_pts_bounds_valid'), video_clock_build_verified=video.get('source_clock_build_verified'),
        exact_video_alignment=False, video_probe=media, problems=manifest.get('problems', []),
        storage_rotation_establishes_continuity=False, full_match_coverage_verified=False, incoming_attacker_attribution='unknown')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session', type=Path); parser.add_argument('--ffprobe', type=Path)
    parser.add_argument('--require-complete-window', action='store_true'); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    raw = json.dumps(verify(args.session, ffprobe=args.ffprobe,
        require_complete_window=args.require_complete_window), allow_nan=False, indent=2) + '\n'
    if args.output: args.output.write_text(raw, encoding='utf-8')
    print(raw, end='')


if __name__ == '__main__':
    main()
