"""Attach historical raw metadata to exact observed compact controller keys.

This verifies export hashes and structural evidence, not native acquisition or
canonical participant semantics. Callers supply previously verified exports and
compact events. No layouts, application access, labels or team rules live here.
"""
import argparse
import bisect
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata

if __name__ == '__main__':
    # Also resolve sibling decoders under isolated/embeddable Python.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from controller_metadata import digest, encode, parse, read
from export_relations import load_local_artifacts


class InvalidMetadataJoin(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidMetadataJoin(reason)


def integer(value):
    return type(value) is int


def key(value, role='controller'):
    return isinstance(value, str) and re.fullmatch(role + r':[0-9a-f]{64}', value) is not None


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def target(value):
    need(isinstance(value, dict) and set(value) == {
        'pid', 'creation_file_time', 'executable_sha256', 'architecture', 'image_name'}, 'target_shape')
    need(integer(value['pid']) and 0 < value['pid'] < 2**31
         and integer(value['creation_file_time']) and value['creation_file_time'] > 0
         and sha(value['executable_sha256']) and value['architecture'] == 'x64'
         and isinstance(value['image_name'], str) and 0 < len(value['image_name']) <= 256, 'target_binding')


def evidence(samples, frame, *, values=False):
    need(isinstance(samples, list), 'evidence_list')
    before, after = (frame['guard_brackets'][phase] for phase in ('guards_before', 'guards_after'))
    for sample in samples:
        need(isinstance(sample, dict) and isinstance(sample.get('field'), str)
             and 0 < len(sample['field']) <= 192, 'evidence_field')
        start, end = sample.get('read_start_ticks'), sample.get('read_end_ticks')
        need(integer(start) and integer(end) and frame['timing']['start_ticks'] <= start <= end
             <= frame['timing']['end_ticks'], 'sample_timing')
        ids = sample.get('guard_ids')
        need(isinstance(ids, list) and 1 <= len(ids) <= len(before)
             and all(integer(i) and 0 <= i < len(before) for i in ids)
             and len(set(ids)) == len(ids), 'evidence_guard_ids')
        need(all(before[i]['end_ticks'] <= start <= end <= after[i]['start_ticks'] for i in ids),
             'sample_guard_brackets')
        if values:
            need(integer(sample.get('value')) and -2**31 <= sample['value'] < 2**31, 'identity_word')


def validate_frame(frame, manifest):
    need(isinstance(frame, dict) and frame.get('schema') == 'overwatch-decoder.controller-metadata-candidates/1',
         'metadata_schema')
    need(frame.get('target') == manifest['target'], 'metadata_target')
    need(frame.get('privacy') == 'private' and frame.get('public_state_eligible') is False
         and frame.get('visibility') == 'unknown' and frame.get('atomic') is False
         and frame.get('canonical_name') is None and frame.get('team') is None
         and all(frame.get(name) is False for name in ('canonical_name_validated', 'team_validated',
                  'human_identity_validated', 'participant_identity_validated', 'mode_admitted',
                  'gameplay_semantics_validated', 'continuity_across_gaps')), 'metadata_qualifiers')
    need(frame.get('acquisition_validation') == 'complete_native_evidence_verified'
         and frame.get('recording_complete') is True, 'qualified_export_required')
    need(all(sha(frame.get(name)) for name in ('profile_sha256', 'context_sha256',
                  'native_frame_sha256', 'recording_manifest_sha256'))
         and frame.get('native_frame_hash_scope') == 'canonical_parsed_frame_including_lf', 'metadata_source_hash')
    source = frame.get('source_acquisition')
    need(isinstance(source, dict) and set(source) == {
        'manifest_sha256', 'recipe_sha256', 'evidence_sha256'}
         and all(sha(value) for value in source.values()), 'acquisition_hashes')
    timing = frame.get('timing', {})
    need(isinstance(timing, dict) and all(integer(timing.get(name)) and timing[name] >= 0 for name in
                  ('sequence', 'start_ticks', 'end_ticks', 'monotonic_origin_ticks'))
         and timing['monotonic_origin_ticks'] <= timing['start_ticks'] <= timing['end_ticks']
         and timing.get('monotonic_frequency') == manifest['monotonic_frequency']
         and isinstance(timing.get('utc_origin'), str) and 0 < len(timing['utc_origin']) <= 128,
         'metadata_timing')
    guards = frame.get('guard_brackets')
    need(isinstance(guards, dict) and set(guards) == {'guards_before', 'guards_after'}, 'guard_brackets')
    before, after = guards['guards_before'], guards['guards_after']
    need(isinstance(before, list) and isinstance(after, list) and 1 <= len(before) == len(after) <= 256,
         'guard_bracket_count')
    for row in before + after:
        need(isinstance(row, dict) and integer(row.get('start_ticks')) and integer(row.get('end_ticks'))
             and timing['start_ticks'] <= row['start_ticks'] <= row['end_ticks'] <= timing['end_ticks'],
             'guard_timing')
    kind = frame.get('partition_kind')
    need(kind in ('accounts', 'cache') and isinstance(frame.get('partition_id'), str), 'metadata_kind')
    rows = frame.get('rows')
    need(isinstance(rows, list) and 1 <= len(rows) <= 64, 'metadata_row_bound')
    seen = set()
    for row in rows:
        need(isinstance(row, dict) and key(row.get('requested_controller_object_key')),
             'requested_controller_key')
        requested = row['requested_controller_object_key']
        need(requested not in seen, 'duplicate_controller_row')
        seen.add(requested)
        need(row.get('body_object_key') is None and row.get('body_key_reference_candidate') is None,
             'metadata_body_binding')
        need(set(row) <= {'requested_controller_object_key', 'controller_object_key', 'body_object_key',
             'metadata_status', 'reason', 'body_key_reference_candidate', 'body_relation_validated',
             'cached_label_candidate', 'cached_label_status', 'cached_label_reason', 'cached_label_evidence',
             'account_token_candidate_hex', 'account_token_sha256', 'account_status', 'account_reason',
             'account_evidence', 'controller_evidence', 'anchored_account_match',
             'local_native_ownership_validated', 'evidence'}, 'unsupported_metadata_row_fields')
        need(row.get('metadata_status') in ('unknown', 'guarded_candidates'), 'metadata_status')
        if row['metadata_status'] == 'unknown':
            need(row.get('controller_object_key') is None and row.get('account_token_candidate_hex') is None
                 and row.get('account_token_sha256') is None and row.get('cached_label_candidate') is None
                 and isinstance(row.get('reason'), str), 'unknown_metadata_values')
            continue
        need(row.get('controller_object_key') == requested and row.get('body_relation_validated') is False
             and row.get('local_native_ownership_validated') is False
             and row.get('anchored_account_match') is None, 'metadata_identity_qualifier')
        need(all(g.get('ok') is True and g.get('error') is None for g in before + after),
             'observed_metadata_failed_guard')
        identity = row.get('controller_evidence')
        need(isinstance(identity, list) and len(identity) == 2, 'controller_evidence')
        evidence(identity, frame, values=True)
        suffix = '_handle_candidate_i32'
        need(identity[0]['field'].endswith(suffix), 'controller_identity_fields')
        prefix = identity[0]['field'][:-len(suffix)]
        need(re.fullmatch(r'controller_\d{4}', prefix)
             and identity[1]['field'] == prefix + '_manager_key_candidate_i32', 'controller_identity_fields')
        if kind == 'accounts':
            need(row.get('cached_label_candidate') is None and row.get('cached_label_status') == 'not_requested'
                 and row.get('cached_label_evidence') == [], 'unrequested_cache_value')
            status = row.get('account_status')
            need(status in ('guarded_raw_candidate', 'unknown'), 'account_status')
            token = row.get('account_token_candidate_hex')
            samples = row.get('account_evidence')
            if status == 'unknown':
                need(token is None and row.get('account_token_sha256') is None
                     and samples == [] and isinstance(row.get('account_reason'), str), 'unknown_account_values')
            else:
                need(isinstance(token, str) and re.fullmatch('[0-9a-f]{32}', token)
                     and bytes.fromhex(token) != bytes(16) and digest(bytes.fromhex(token)) == row.get('account_token_sha256'),
                     'account_token_hash_or_width')
                evidence(samples, frame)
                need([sample['field'] for sample in samples] == [
                    prefix + f'_part36_0000_account_word{i}_candidate_i32' for i in range(4)],
                    'complete_account_evidence')
        else:
            need(row.get('account_token_candidate_hex') is None and row.get('account_token_sha256') is None
                 and row.get('account_status') == 'not_requested' and row.get('account_evidence') == [],
                 'unrequested_account_value')
            status, text, samples = (row.get(name) for name in
                                    ('cached_label_status', 'cached_label_candidate', 'cached_label_evidence'))
            need(status in ('observed', 'unknown'), 'cache_status')
            if status == 'unknown':
                need(text is None and samples == [] and isinstance(row.get('cached_label_reason'), str),
                     'unknown_cache_values')
            else:
                need(isinstance(text, str) and 1 <= len(text.encode('utf-8')) <= 63
                     and not any(unicodedata.category(char).startswith('C') for char in text), 'cache_text')
                evidence(samples, frame)
                need([sample['field'] for sample in samples] == [
                    prefix + f'_cached_label_0000_byte_{i:04d}_value' for i in range(len(text.encode('utf-8')) + 1)],
                    'complete_cache_evidence')
    return kind, rows


class ControllerMetadataJoin:
    """Stateless historical sidecar; no metadata becomes current/canonical state."""
    def __init__(self, raw_manifest, artifacts):
        need(isinstance(raw_manifest, bytes) and 0 < len(raw_manifest) <= 262144, 'set_manifest_size')
        manifest = parse(raw_manifest)
        need(isinstance(manifest, dict) and manifest.get('schema') == 'overwatch-decoder.controller-metadata-set/1', 'set_schema')
        target(manifest.get('target'))
        need(isinstance(manifest.get('clock_domain_id'), str) and 0 < len(manifest['clock_domain_id']) <= 128
             and integer(manifest.get('monotonic_frequency')) and 0 < manifest['monotonic_frequency'] <= 10**12,
             'metadata_clock_domain')
        exports = manifest.get('exports')
        need(isinstance(exports, list) and 1 <= len(exports) <= 64
             and all(sha(item) for item in exports) and len(set(exports)) == len(exports), 'export_digests')
        need(isinstance(artifacts, dict) and set(artifacts) == set(exports)
             and all(isinstance(raw, bytes) and len(raw) <= 16*1024*1024 for raw in artifacts.values())
             and sum(map(len, artifacts.values())) <= 64*1024*1024, 'artifact_bounds_or_set')
        self.hash = digest(raw_manifest)
        self.manifest = manifest
        self.index = {}
        frames = rows_total = 0
        stamps = set()
        for export_hash in exports:
            raw = artifacts[export_hash]
            need(raw and raw.endswith(b'\n') and digest(raw) == export_hash, 'export_hash_or_termination')
            for line_number, line in enumerate(raw.splitlines(keepends=True)):
                need(0 < len(line) <= 1024*1024, 'metadata_line_bound')
                frame = parse(line)
                kind, rows = validate_frame(frame, manifest)
                frames += 1
                rows_total += len(rows)
                need(frames <= 4096 and rows_total <= 8192, 'metadata_record_bound')
                for row_number, row in enumerate(rows):
                    controller = row['requested_controller_object_key']
                    timing = frame['timing']
                    stamp = (controller, kind, timing['end_ticks'], timing['start_ticks'])
                    need(stamp not in stamps, 'ambiguous_metadata_sample_time')
                    stamps.add(stamp)
                    sample = dict(row=row, frame=frame, export_sha256=export_hash,
                                  export_line_index=line_number, export_row_index=row_number,
                                  metadata_line_sha256=digest(line))
                    self.index.setdefault((controller, kind), []).append(sample)
        self.ends = {}
        for identity, samples in self.index.items():
            samples.sort(key=lambda sample: (sample['frame']['timing']['end_ticks'],
                                             sample['frame']['timing']['start_ticks']))
            self.ends[identity] = [sample['frame']['timing']['end_ticks'] for sample in samples]
        self.frames, self.rows = frames, rows_total

    def sample(self, controller, kind, cutoff):
        identity = controller, kind
        if identity not in self.index:
            return None, 'controller_metadata_not_collected'
        at = bisect.bisect_right(self.ends[identity], cutoff) - 1
        if at < 0:
            return None, 'metadata_after_roster_interval'
        sample = self.index[identity][at]
        frame = sample['frame']
        known = sample['row'].get('metadata_status') != 'unknown' and (
            sample['row'].get('account_status') == 'guarded_raw_candidate' if kind == 'accounts'
            else sample['row'].get('cached_label_status') == 'observed')
        return dict(status='historical_sample_candidate' if known else 'historical_sample_unknown', current_value_asserted=False,
            age_ticks=cutoff-frame['timing']['end_ticks'], timing=copy.deepcopy(frame['timing']),
            candidate=copy.deepcopy(sample['row']),
            provenance=dict(export_sha256=sample['export_sha256'], export_line_index=sample['export_line_index'],
                export_row_index=sample['export_row_index'], metadata_line_sha256=sample['metadata_line_sha256'],
                native_frame_sha256=frame['native_frame_sha256'], native_frame_hash_scope=frame['native_frame_hash_scope'],
                profile_sha256=frame['profile_sha256'], context_sha256=frame['context_sha256'],
                source_acquisition=copy.deepcopy(frame['source_acquisition']),
                recording_manifest_sha256=frame['recording_manifest_sha256'],
                original_acquisition_validation=frame['acquisition_validation'],
                guard_brackets_ref='/guard_brackets', original_metadata_line_required=True),
            validation='hash_pinned_export_candidate_not_native_reverification'), None

    def project(self, raw_compact):
        need(isinstance(raw_compact, bytes) and 0 < len(raw_compact) <= 1024*1024
             and raw_compact.endswith(b'\n'), 'compact_line_bound')
        event = parse(raw_compact)
        need(isinstance(event, dict), 'compact_object')
        schema = event.get('schema')
        transition = schema == 'overwatch-decoder.compact-live-roster-transition/1'
        need(transition or schema == 'overwatch-decoder.compact-live-roster/1', 'compact_schema')
        target(event.get('target'))
        need(event.get('privacy') == 'private' and event.get('public_state_eligible') is False
             and event.get('visibility') == 'unknown' and event.get('atomic') is False
             and event.get('participant_identity_validated') is False
             and event.get('values_are_candidates') is True
             and event.get('continuity_across_gaps') is False, 'compact_qualifiers')
        players = event.get('players')
        need(isinstance(players, list) and len(players) <= 128, 'compact_player_bound')
        need(all(isinstance(player, dict) and key(player.get('controller_object_key')) for player in players)
             and len({player['controller_object_key'] for player in players}) == len(players), 'compact_controller_set')
        timing = event.get('timing', {})
        if not transition:
            need(isinstance(timing, dict) and integer(timing.get('window_start_ticks')) and integer(timing.get('window_end_ticks'))
                 and 0 <= timing['window_start_ticks'] <= timing['window_end_ticks'], 'roster_interval')
        result = copy.deepcopy(event)
        result['schema'] = 'overwatch-decoder.compact-live-roster-metadata-transition/1' if transition else 'overwatch-decoder.compact-live-roster-metadata/1'
        result['controller_metadata_join'] = dict(schema='overwatch-decoder.controller-metadata-join/1',
            metadata_set_sha256=self.hash, source_compact_sha256=digest(raw_compact),
            source_compact_hash_scope='exact_compact_jsonl_line_including_lf', source_compact_schema=schema,
            validation='hash_pinned_export_candidates_and_caller_validated_roster',
            canonical_names_validated=False, team_or_self_inferred=False, current_metadata_asserted=False)
        for player in result['players']:
            reason = None
            if transition:
                reason = 'roster_transition'
            elif player.get('status') != 'observed':
                reason = 'roster_row_unknown'
            elif event['target'] != self.manifest['target']:
                reason = 'process_or_build_epoch_mismatch'
            elif event.get('clock_domain_id') != self.manifest['clock_domain_id'] or timing.get('monotonic_frequency') != self.manifest['monotonic_frequency']:
                reason = 'metadata_clock_domain_mismatch'
            elif not key(player.get('body_object_key'), 'body'):
                reason = 'observed_roster_body_unknown'
            observed = player.get('primary_observation')
            observed_time = observed.get('source_timing', {}) if isinstance(observed, dict) else {}
            if reason is None and not (isinstance(observed_time, dict)
                    and integer(observed_time.get('start_ticks')) and integer(observed_time.get('end_ticks'))
                    and 0 <= observed_time['start_ticks'] <= observed_time['end_ticks']
                    and observed_time.get('monotonic_frequency') == self.manifest['monotonic_frequency']):
                reason = 'observed_roster_timing_unknown'
            attachment = dict(status='unknown', reason=reason, account=None, cache=None,
                              historical_only=True, current_value_asserted=False,
                              canonical_name=None, team=None, self_identity_inferred=False)
            if reason is None:
                cutoff = observed_time['end_ticks']
                errors = {}
                for kind, field in (('accounts', 'account'), ('cache', 'cache')):
                    attachment[field], errors[field] = self.sample(player['controller_object_key'], kind,
                                                                   cutoff)
                attachment['roster_observation_end_ticks'] = cutoff
                attachment['comparison_reference'] = 'primary_observation.source_timing.end_ticks'
                attachment['status'] = 'historical_candidates' if any(attachment[name] is not None and
                    attachment[name]['status'] == 'historical_sample_candidate' for name in ('account', 'cache')) else 'unknown'
                attachment['sample_reasons'] = errors
            player['controller_metadata_candidates'] = attachment
        return result


def export_join(raw_manifest, artifacts, source, output):
    join = ControllerMetadataJoin(raw_manifest, artifacts)
    source, output = Path(source), Path(output)
    need(source.is_file() and source.stat().st_size <= 256*1024*1024 and not output.exists(), 'input_bound_or_new_output')
    count = total = 0
    result_hash = hashlib.sha256()
    input_hash = hashlib.sha256()
    with source.open('rb') as reader, output.open('xb') as writer:
        for line in reader:
            input_hash.update(line)
            value = join.project(line)
            encoded = encode(value)
            count += 1
            total += len(encoded)
            need(count <= 10000 and len(encoded) <= 4*1024*1024 and total <= 512*1024*1024, 'join_output_bound')
            writer.write(encoded)
            result_hash.update(encoded)
    return dict(schema='overwatch-decoder.controller-metadata-join-result/1', events=count, output_bytes=total,
                output_sha256=result_hash.hexdigest(), metadata_set_sha256=join.hash,
                input_sha256=input_hash.hexdigest(), privacy='private', public_state_eligible=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('metadata-set', 'metadata-artifacts', 'input', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(json.dumps(export_join(read(args.metadata_set, 262144),
                                load_local_artifacts(args.metadata_artifacts, 'controller_metadata'),
                                args.input, args.output)))


if __name__ == '__main__':
    main()
