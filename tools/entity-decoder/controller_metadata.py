"""Private raw controller metadata from a caller-verified acquisition.

No application addresses, layouts, names, roles or mode admission live here.
Field names follow the existing guarded controller/account/cache conventions.
The CLI verifies acquisition evidence and native recording/chunk integrity; API
callers must perform that same verification before interpreting the source pins.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

from account_anchor import account_words
from cached_labels import GuardedCachedLabels
from export_relations import iter_validated_frames, native_verify
from plan_live_roster import verified_census
from relations import InvalidBinding


class InvalidMetadata(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidMetadata(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: need(False, 'nonfinite_json'))
    except (ValueError, TypeError, RecursionError) as error:
        raise InvalidMetadata('invalid_json') from error


def read(path, maximum):
    path = Path(path)
    need(path.is_file() and path.stat().st_size <= maximum, 'input_size')
    return path.read_bytes()


def profile_keys(relations, prefixes):
    """Use both complete guarded words, including storage/process generation."""
    result = {}
    handles = set()
    for prefix in prefixes:
        names = [prefix + '_handle_candidate_i32', prefix + '_manager_key_candidate_i32']
        words = []
        for name in names:
            address, value = relations._binding(name)
            words.append(dict(address=address, value=value))
        key = relations._key('controller', words)
        need(words[0]['value'] not in handles, 'ambiguous_controller_handle')
        handles.add(words[0]['value'])
        need(key not in result, 'duplicate_controller_identity')
        result[key] = (prefix, names)
    return result


def unknown_rows(keys, reason):
    return [dict(requested_controller_object_key=key, controller_object_key=None,
                 body_object_key=None, cached_label_candidate=None,
                 account_token_candidate_hex=None, account_token_sha256=None,
                 metadata_status='unknown', reason=reason, evidence=[]) for key in keys]


class GuardedControllerMetadata:
    """Stateless candidates; complete provenance verification is the caller's job.

    A context contains only exact source pins and controller keys, automatically
    obtainable from a fresh guarded census. It is not a manual semantic review.
    Returned objects share no mutable data with the context/profile or past rows.
    """
    def __init__(self, raw_profile, raw_context):
        need(isinstance(raw_context, bytes) and len(raw_context) <= 262144, 'context_size')
        context = parse(raw_context)
        need(isinstance(context, dict) and context.get('schema') == 'overwatch-decoder.controller-metadata-context/1',
             'context_schema')
        self.labels = GuardedCachedLabels(raw_profile)
        self.relations = self.labels.relations
        self.context_sha256 = digest(raw_context)
        need(context.get('target') == self.relations.target, 'context_target')
        need(context.get('profile_sha256') == self.relations.hash, 'context_profile')
        need(context.get('kind') in ('accounts', 'cache'), 'partition_kind')
        need(isinstance(context.get('partition_id'), str)
             and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', context['partition_id']), 'partition_id')
        for field in ('controller_object_keys', 'roster_controller_object_keys'):
            keys = context.get(field)
            need(isinstance(keys, list) and 1 <= len(keys) <= 64
                 and all(isinstance(key, str) and re.fullmatch(r'controller:[0-9a-f]{64}', key)
                         for key in keys) and len(set(keys)) == len(keys), field)
        source = context.get('source_acquisition')
        need(isinstance(source, dict) and set(source) == {
            'manifest_sha256', 'recipe_sha256', 'evidence_sha256'}, 'source_acquisition')
        need(all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
                 for value in source.values()), 'source_digest')
        self.context = context
        self.selected = profile_keys(self.relations, self.relations.prefixes)
        need(set(self.selected) == set(context['controller_object_keys']), 'selected_full_keys')
        prefixes = sorted(name[:-len('_handle_candidate_i32')]
                          for name in self.relations.fields
                          if re.fullmatch(r'roster_\d{4}_handle_candidate_i32', name))
        self.roster = self.selected if context['kind'] == 'accounts' else profile_keys(self.relations, prefixes)
        need(set(self.roster) == set(context['roster_controller_object_keys']),
             'census_roster_changed_replan_required')
        need(set(self.selected) <= set(self.roster), 'selected_controller_absent_from_roster')

    def project(self, frame, *, gap=False):
        r = self.relations
        result = dict(schema='overwatch-decoder.controller-metadata-candidates/1',
                      context_sha256=self.context_sha256, profile_sha256=r.hash,
                      target=dict(r.target), source_acquisition=dict(self.context['source_acquisition']),
                      acquisition_validation='caller_verified_required',
                      timing={key: copy.deepcopy(frame.get(key)) for key in ('sequence', 'start_ticks', 'end_ticks',
                              'monotonic_frequency', 'monotonic_origin_ticks', 'utc_origin')},
                      native_frame_sha256=digest(encode(frame)),
                      native_frame_hash_scope='canonical_parsed_frame_including_lf',
                      guard_brackets={phase: [{key: copy.deepcopy(guard.get(key)) for key in
                          ('ok', 'error', 'start_ticks', 'end_ticks')}
                          for guard in frame.get(phase, []) if isinstance(guard, dict)]
                          for phase in ('guards_before', 'guards_after')},
                      partition_id=self.context['partition_id'], partition_kind=self.context['kind'],
                      rows=[], privacy='private', atomic=False, visibility='unknown',
                      public_state_eligible=False, canonical_name=None, canonical_name_validated=False,
                      human_identity_validated=False, participant_identity_validated=False,
                      gameplay_semantics_validated=False, team=None, team_validated=False,
                      mode_admitted=False, continuity_across_gaps=False)
        try:
            if gap or frame.get('skipped_intervals_before'):
                raise InvalidBinding('gap_before_frame')
            for _, names in self.roster.values():
                for name in names:
                    r._observed(name, frame)
        except InvalidBinding as error:
            result['rows'] = unknown_rows(self.selected, str(error))
            return result
        cache = {row['controller_object_key']: row for row in self.labels.project(frame)['labels']} \
            if self.context['kind'] == 'cache' else {}
        for key, (prefix, names) in self.selected.items():
            row = dict(requested_controller_object_key=key, controller_object_key=key,
                       body_object_key=None, metadata_status='guarded_candidates', reason=None,
                       body_key_reference_candidate=None, body_relation_validated=False,
                       cached_label_candidate=None, cached_label_status='not_requested',
                       cached_label_reason=None, cached_label_evidence=[],
                       account_token_candidate_hex=None, account_token_sha256=None,
                       account_status='not_requested', account_reason=None, account_evidence=[],
                       controller_evidence=[], anchored_account_match=None,
                       local_native_ownership_validated=False)
            try:
                for name in names:
                    sampled = r.sample_scalar(name, frame, 'i32')
                    row['controller_evidence'].append(dict(
                        **{field: sampled[field] for field in
                           ('field', 'value', 'read_start_ticks', 'read_end_ticks')},
                        guard_ids=r.guard_ids[name].copy()))
                if self.context['kind'] == 'accounts':
                    try:
                        sampled = account_words(r, prefix, frame)
                        if sampled is None:
                            row.update(account_status='unknown', account_reason='complete_account_words_not_declared')
                        else:
                            token, evidence = sampled
                            row.update(account_status='guarded_raw_candidate',
                                       account_token_candidate_hex=token.hex(), account_token_sha256=digest(token),
                                       account_evidence=evidence)
                    except InvalidBinding as error:
                        row.update(account_status='unknown', account_reason=str(error))
                else:
                    cached = cache.get(key)
                    need(cached is not None, 'cache_controller_join')
                    row.update(cached_label_status=cached['status'], cached_label_candidate=cached['candidate_cached_label'],
                               cached_label_reason=cached['reason'], cached_label_evidence=[dict(
                                   **sample, guard_ids=r.guard_ids[sample['field']].copy())
                                   for sample in cached['evidence']])
            except (InvalidBinding, InvalidMetadata) as error:
                row = unknown_rows([key], str(error))[0]
            result['rows'].append(row)
        return result


def export_recording(acquisition, recording, raw_context, output, verifier_command):
    """Verify complete native sources before writing bounded raw JSONL candidates."""
    acquisition, recording, output = map(Path, (acquisition, recording, output))
    need(not output.exists(), 'new_output_required')
    profile = read(acquisition / 'profile.json', 262144)
    projector = GuardedControllerMetadata(profile, raw_context)
    verified = verified_census(acquisition, expected_target=projector.relations.target)
    need(all(verified['source'][key] == value
             for key, value in projector.context['source_acquisition'].items()), 'acquisition_source_mismatch')
    need(read(recording / 'profile.json', 262144) == profile, 'recording_profile_changed')
    need((recording / 'samples.jsonl.gz').stat().st_size <= 64 * 1024 * 1024, 'recording_size')
    validation = native_verify(recording, verifier_command, False)
    need(0 < validation['frames'] <= 1000, 'recording_frame_bound')
    manifest_raw = read(recording / 'manifest.json', 262144)
    manifest, recording_hash = parse(manifest_raw), digest(manifest_raw)
    total = count = rows = unknown = 0
    output_hash = hashlib.sha256()
    with output.open('xb') as file:
        for frame, gap in iter_validated_frames(recording / 'samples.jsonl.gz', recording / 'chunks.jsonl',
                                               validation, manifest, projector.relations):
            value = projector.project(frame, gap=bool(gap['skipped_slots']))
            value.update(acquisition_validation='complete_native_evidence_verified',
                         recording_manifest_sha256=recording_hash, recording_complete=True,
                         native_verification_status=validation.get('status'))
            encoded = encode(value)
            total += len(encoded)
            need(total <= 64 * 1024 * 1024, 'candidate_output_bound')
            file.write(encoded)
            output_hash.update(encoded)
            count += 1
            rows += len(value['rows'])
            requested = 'account_status' if projector.context['kind'] == 'accounts' else 'cached_label_status'
            unknown += sum(row.get(requested) not in ('observed', 'guarded_raw_candidate') for row in value['rows'])
    return dict(schema='overwatch-decoder.controller-metadata-export/1', frames=count, rows=rows,
                unknown_rows=unknown, output_sha256=output_hash.hexdigest(), output_bytes=total,
                context_sha256=projector.context_sha256, privacy='private', public_state_eligible=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('acquisition', 'recording', 'context', 'verifier-command', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    command = parse(read(args.verifier_command, 65536))
    need(isinstance(command, list) and 1 <= len(command) <= 8
         and all(isinstance(word, str) and word for word in command), 'verifier_command')
    print(json.dumps(export_recording(args.acquisition, args.recording,
                                     read(args.context, 262144), args.output, command)))


if __name__ == '__main__':
    main()
