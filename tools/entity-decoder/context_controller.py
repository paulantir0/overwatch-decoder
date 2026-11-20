"""Project a reviewed native context selector without account or roster heuristics.

Caller verification of acquisition/transport and native recipe semantics remains
required. This stateless module has no process access, application offsets, fixed
self key, team mapping, or claim that a selected body is playable rather than a
spectator camera. Every epoch needs its own source-bound contract.
"""
from __future__ import annotations

from projection_copy import detached_copy
import hashlib
import json
import re

from relations import GuardedRelations, InvalidBinding


class InvalidContextEvidence(ValueError):
    pass


def _need(value, reason):
    if not value:
        raise InvalidContextEvidence(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: _need(False, 'nonfinite_json'))
    except (ValueError, TypeError, RecursionError) as error:
        raise InvalidContextEvidence('invalid_json') from error


class GuardedContextController:
    """Return the current context-selected controller, never a cached self value."""

    def __init__(self, raw_profile, raw_contract, artifacts):
        self.relations = GuardedRelations(raw_profile)
        _need(isinstance(raw_contract, bytes) and len(raw_contract) <= 262144, 'contract_size')
        self.contract_sha256 = _sha(raw_contract)
        contract = _parse(raw_contract)
        _need(isinstance(contract, dict) and contract.get('schema') == 'overwatch-decoder.context-controller-contract/1',
              'context_contract_schema')
        _need(not any(k in contract for k in ('self_controller_object_key', 'account_token',
                                             'roster_review_sha256', 'category_teams')), 'fixed_identity_forbidden')
        _need(contract.get('target') == self.relations.target
              and contract.get('profile_sha256') == self.relations.hash, 'contract_profile_or_target_mismatch')
        build = self.relations.target['executable_sha256']
        _need(contract.get('build_sha256') == build, 'contract_build_mismatch')
        _need(isinstance(artifacts, dict) and len(artifacts) <= 128, 'artifact_count')
        seen, total = set(), 0

        def artifact(digest):
            nonlocal total
            _need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'artifact_digest')
            raw = artifacts.get(digest)
            _need(isinstance(raw, bytes) and len(raw) <= 16 * 1024 * 1024 and _sha(raw) == digest,
                  'artifact_hash_or_size')
            if digest not in seen:
                seen.add(digest)
                total += len(raw)
                _need(total <= 64 * 1024 * 1024, 'artifact_total_size')
            return raw

        source = contract.get('source')
        _need(isinstance(source, dict), 'source_pins_missing')
        self.source = {k: source.get(k) for k in ('recipe_sha256', 'evidence_sha256')}
        recipe = _parse(artifact(self.source['recipe_sha256']))
        artifact(self.source['evidence_sha256'])
        _need(isinstance(recipe, dict) and recipe.get('schema') == 'overwatch-decoder.acquisition-recipe/1'
              and all(recipe.get('target', {}).get(k) == self.relations.target[k]
                      for k in ('image_name', 'architecture', 'executable_sha256')), 'recipe_target_mismatch')
        self.acquisition_manifest_sha256 = contract.get('acquisition_manifest_sha256')
        manifest = _parse(artifact(self.acquisition_manifest_sha256))
        _need(isinstance(manifest, dict) and manifest.get('schema') == 'overwatch-decoder.acquisition-result/1'
              and manifest.get('complete') is True and manifest.get('error') is None
              and manifest.get('target') == self.relations.target
              and manifest.get('profile_sha256') == self.relations.hash
              and all(manifest.get(k) == v for k, v in self.source.items()), 'acquisition_scope_mismatch')
        self.native_review_sha256 = contract.get('native_review_sha256')
        review = _parse(artifact(self.native_review_sha256))
        required = ['guarded_controller_enumeration', 'world_context_selector', 'exact_controller_key_match']
        _need(isinstance(review, dict) and review.get('schema') == 'overwatch-decoder.native-context-controller-review/1'
              and review.get('reviewed') is True and review.get('review_method') == 'native_consumer_trace'
              and review.get('build_sha256') == build and review.get('required_conditions') == required,
              'native_review_mismatch')
        sources = review.get('sources')
        _need(isinstance(sources, list) and 1 <= len(sources) <= 32, 'native_sources_missing')
        for digest in sources:
            artifact(digest)
        self.scope = contract.get('selection_scope')
        _need(self.scope in ('complete_profile_census', 'guarded_selected_anchor'), 'selection_scope')
        self.prefixes = contract.get('candidate_prefixes')
        _need(isinstance(self.prefixes, list) and 1 <= len(self.prefixes) <= 32
              and all(isinstance(p, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}', p)
                      for p in self.prefixes) and len(set(self.prefixes)) == len(self.prefixes), 'candidate_prefixes')
        self.prefixes = self.prefixes.copy()
        if self.scope == 'complete_profile_census':
            _need(set(self.prefixes) == set(self.relations.prefixes), 'incomplete_profile_census')
        else:
            _need(len(self.prefixes) == 1, 'selected_anchor_count')
        self.selector = contract.get('selector_field')
        _need(isinstance(self.selector, str), 'selector_field')
        selector_address, _ = self.relations._binding(self.selector)
        # Field-local optional metadata guards are not selector dependencies.
        # Preserve exactly the selector's declared guards, including all globals,
        # and require it to cover every core identity/body dependency below.
        selector_ids = self.relations.guard_ids[self.selector]
        declared_ids = contract.get('required_guard_ids')
        _need(isinstance(declared_ids, list) and declared_ids
              and all(type(n) is int for n in declared_ids)
              and declared_ids == selector_ids, 'incomplete_selector_guards')
        core_fields = [self.selector]
        for prefix in self.prefixes:
            for suffix in ('_handle_candidate_i32', '_manager_key_candidate_i32'):
                address, _ = self.relations._binding(prefix + suffix)
                _need(abs(address - selector_address) >= 4, 'selector_identity_alias')
                core_fields.append(prefix + suffix)
            body = [prefix + s in self.relations.fields for s in
                    ('_body_0000_handle_candidate_i32', '_body_0000_manager_key_candidate_i32')]
            _need(body[0] == body[1], 'partial_body_identity')
            if all(body):
                for suffix in ('_body_0000_handle_candidate_i32', '_body_0000_manager_key_candidate_i32'):
                    self.relations._binding(prefix + suffix)
                    core_fields.append(prefix + suffix)
                _need(prefix + '_part51_0000_body_key_candidate_i32' in self.relations.fields,
                      'missing_body_reference')
            reference = prefix + '_part51_0000_body_key_candidate_i32'
            if reference in self.relations.fields:
                core_fields.append(reference)
        _need(all(set(self.relations.guard_ids[name]).issubset(selector_ids) for name in core_fields),
              'incomplete_selector_guards')

    @staticmethod
    def _evidence(word):
        return {k: v for k, v in word.items() if k != 'address'}

    def project(self, frame, *, gap=False):
        r = self.relations
        _need(isinstance(frame, dict), 'invalid_frame')
        result = dict(schema='overwatch-decoder.guarded-context-controller/1', profile_sha256=r.hash,
                      target=r.target.copy(), contract_sha256=self.contract_sha256,
                      native_review_sha256=self.native_review_sha256,
                      source_evidence=dict(self.source, acquisition_manifest_sha256=self.acquisition_manifest_sha256),
                      status='unknown', reason=None, controller_object_key=None, body_object_key=None,
                      body_status='unknown', body_reason=None, body_key_candidate=None,
                      selector_evidence=None, candidate_identity_evidence=[], body_evidence=[], body_reference_evidence=None,
                      selection_scope=self.scope, role='context_selected_controller',
                      local_control_semantics_validated=False, playable_body_validated=False,
                      atomic=False, public_state_eligible=False, visibility='unknown',
                      durability_verified=False, previous_values_carried=False,
                      timing={k: frame.get(k) for k in ('sequence', 'start_ticks', 'end_ticks', 'monotonic_frequency')})
        try:
            skips = frame.get('skipped_intervals_before', 0)
            if type(skips) is not int or skips < 0:
                raise InvalidBinding('invalid_gap_metadata')
            if gap or skips:
                raise InvalidBinding('scheduled_gap')
            with r._frame_checks(frame):
                selector = r._observed(self.selector, frame)
                rows, handles, keys = [], set(), set()
                for prefix in self.prefixes:
                    words = [r._observed(prefix + s, frame) for s in
                             ('_handle_candidate_i32', '_manager_key_candidate_i32')]
                    if words[0]['value'] in handles or words[1]['value'] in keys:
                        raise InvalidBinding('ambiguous_controller_identity')
                    handles.add(words[0]['value'])
                    keys.add(words[1]['value'])
                    rows.append((prefix, words, r._key('controller', words)))
                matches = [row for row in rows if row[1][1]['value'] == selector['value'] and selector['value'] != 0]
                if len(matches) != 1:
                    raise InvalidBinding('selector_match_count')
                prefix, words, key = matches[0]
                selector_proof = dict(self._evidence(selector), guard_ids=r.guard_ids[self.selector].copy(),
                                      guards_before=detached_copy(frame['guards_before']),
                                      guards_after=detached_copy(frame['guards_after']))
                result.update(status='observed', controller_object_key=key,
                              selector_evidence=selector_proof, candidate_identity_evidence=[
                                  dict(controller_object_key=ck, words=[self._evidence(w) for w in ws])
                                  for _, ws, ck in rows])
                try:
                    reference = r.sample_scalar(prefix + '_part51_0000_body_key_candidate_i32', frame, 'i32')
                    reference['value'] &= 0xffffffff
                    result['body_key_candidate'] = reference['value']
                    result['body_reference_evidence'] = self._evidence(reference)
                    body = [r._observed(prefix + s, frame) for s in
                            ('_body_0000_handle_candidate_i32', '_body_0000_manager_key_candidate_i32')]
                    if not reference['value'] or reference['value'] != body[1]['value']:
                        raise InvalidBinding('body_key_mismatch')
                    result.update(body_status='observed', body_object_key=r._key('body', body),
                                  body_evidence=[self._evidence(w) for w in [reference, *body]])
                except InvalidBinding as error:
                    result['body_reason'] = str(error)
        except InvalidBinding as error:
            result['reason'] = str(error)
        return result
