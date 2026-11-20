"""Match a reviewed account anchor to freshly guarded controller candidates.

This identifies an anchored account within the supplied profile, not native local
ownership, whole-process uniqueness, player visibility, or continuous lifetime.
The caller must validate acquisition/recording provenance and complete account-
census coverage. Missing declarations remain explicit; they are not proof that a
controller lacks an account. All artifacts and outputs are private research.
"""
import hashlib
import json
import re

from relations import GuardedRelations, InvalidBinding


class InvalidAccountAnchor(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidAccountAnchor(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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
        raise InvalidAccountAnchor('invalid_json') from error


def account_words(relations, prefix, frame):
    names = [prefix + f'_part36_0000_account_word{i}_candidate_i32' for i in range(4)]
    extra = [name for name in relations.fields if name.startswith(prefix + '_part36_')
             and '_account_word' in name and name not in names]
    if extra:
        raise InvalidBinding('unsupported_account_declaration')
    declared = [name in relations.fields for name in names]
    if not any(declared):
        return None
    if not all(declared):
        raise InvalidBinding('partial_account_declaration')
    # Each complete word must be frozen in profile guards, then sampled with all
    # declared before/after checks. Contiguous storage binds the full 16 bytes.
    words = [relations._observed(name, frame) for name in names]
    if any(word['address'] != words[0]['address'] + i*4 for i, word in enumerate(words)):
        raise InvalidBinding('noncontiguous_account_token')
    token = b''.join(word['value'].to_bytes(4, 'little') for word in words)
    if token == bytes(16):
        raise InvalidBinding('zero_account_token')
    evidence = [dict(field=word['field'], read_start_ticks=word['read_start_ticks'],
                     read_end_ticks=word['read_end_ticks'],
                     guard_ids=relations.guard_ids[word['field']].copy()) for word in words]
    return token, evidence


class GuardedAccountAnchor:
    """Stateless, process-scoped matching; no account bytes enter the output."""
    def __init__(self, raw_profile, raw_anchor, artifacts):
        need(isinstance(raw_anchor, bytes) and len(raw_anchor) <= 65536, 'anchor_size')
        need(isinstance(artifacts, dict) and len(artifacts) <= 64
             and all(isinstance(raw, bytes) for raw in artifacts.values())
             and sum(map(len, artifacts.values())) <= 64*1024*1024, 'artifact_bounds')
        self.hash = sha(raw_anchor)
        anchor = parse(raw_anchor)
        need(isinstance(anchor, dict) and anchor.get('schema') == 'overwatch-decoder.reviewed-account-anchor/1',
             'anchor_schema')
        self.relations = GuardedRelations(raw_profile)
        need(anchor.get('target') == self.relations.target, 'anchor_process_epoch_mismatch')
        def artifact(key, maximum):
            need(isinstance(key, str) and re.fullmatch('[0-9a-f]{64}', key), 'artifact_digest')
            raw = artifacts.get(key)
            need(isinstance(raw, bytes) and len(raw) <= maximum and sha(raw) == key,
                 'artifact_hash_or_size')
            return raw
        source_profile = artifact(anchor.get('source_profile_sha256'), 262144)
        source_frame_raw = artifact(anchor.get('source_frame_sha256'), 1048576)
        source_frame = parse(source_frame_raw)
        source = GuardedRelations(source_profile)
        need(source.target == self.relations.target, 'anchor_source_target_mismatch')
        review = parse(artifact(anchor.get('review_sha256'), 65536))
        need(isinstance(review, dict) and review.get('schema') == 'overwatch-decoder.account-anchor-review/1'
             and review.get('reviewed') is True
             and review.get('review_method') == 'explicit_local_player_account_binding', 'unreviewed_anchor')
        for key in ('target', 'source_profile_sha256', 'source_frame_sha256', 'source_controller_object_key'):
            need(review.get(key) == anchor.get(key), 'review_binding_mismatch')
        sources = review.get('sources')
        need(isinstance(sources, list) and 1 <= len(sources) <= 16
             and all(isinstance(key, str) for key in sources)
             and len(set(sources)) == len(sources), 'review_sources')
        for key in sources:
            artifact(key, 16*1024*1024)
        need(isinstance(source_frame, dict) and source_frame.get('skipped_intervals_before', 0) == 0,
             'anchor_source_gap')
        matches = [row for row in source.project(source_frame)['relations']
                   if row['controller_object_key'] == anchor.get('source_controller_object_key')]
        need(len(matches) == 1 and matches[0]['controller_object_key'] is not None, 'anchor_controller_unknown')
        try:
            sampled = account_words(source, matches[0]['controller_prefix'], source_frame)
        except InvalidBinding as error:
            raise InvalidAccountAnchor('anchor_account:' + str(error)) from error
        need(sampled is not None, 'anchor_account_missing')
        self.token = sampled[0]
        self.source = {key: anchor[key] for key in ('source_profile_sha256', 'source_frame_sha256',
                                                   'source_controller_object_key', 'review_sha256')}

    def project(self, frame, *, gap=False):
        base = self.relations.project(frame)
        result = dict(schema='overwatch-decoder.guarded-account-anchor-match/1', status='unknown', reason=None,
                      controller_object_key=None, body_object_key=None, evidence=[], controller_evidence=[],
                      profile_sha256=self.relations.hash, target=self.relations.target.copy(),
                      anchor_sha256=self.hash, anchor_source=self.source.copy(), timing=base['timing'],
                      account_candidate_count=0, matching_candidate_count=0,
                      undeclared_controller_keys=[], match_scope='profile_declared_account_candidates',
                      complete_account_census_validated=False, local_ownership_validated=False,
                      continuity_across_gaps=False, atomic=False, privacy='private',
                      visibility='unknown', public_state_eligible=False)
        try:
            if gap or frame.get('skipped_intervals_before', 0):
                raise InvalidBinding('gap_before_frame')
            matches = []
            for row in base['relations']:
                if row['controller_object_key'] is None:
                    raise InvalidBinding('controller_unknown')
                sampled = account_words(self.relations, row['controller_prefix'], frame)
                if sampled is None:
                    result['undeclared_controller_keys'].append(row['controller_object_key'])
                    continue
                result['account_candidate_count'] += 1
                token, evidence = sampled
                if token == self.token:
                    matches.append((row, evidence))
            result['matching_candidate_count'] = len(matches)
            if not matches:
                raise InvalidBinding('no_account_match')
            if len(matches) != 1:
                raise InvalidBinding('ambiguous_account_match')
            row, evidence = matches[0]
            # The body may be absent/replaced; the account belongs to controller.
            result.update(status='anchored_account_match', controller_object_key=row['controller_object_key'],
                          body_object_key=row['body_object_key'], evidence=evidence,
                          controller_evidence=row['evidence'][:2])
        except InvalidBinding as error:
            result['reason'] = str(error)
        return result
