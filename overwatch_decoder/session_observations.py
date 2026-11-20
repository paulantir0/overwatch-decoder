"""Allowlisted transport for private recorded observations, never a damage decoder.

A health delta is not an event and cannot identify an attacker. Raw native words,
addresses, filesystem paths and arbitrary source fields are deliberately omitted.
"""
from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime


class InvalidObservation(ValueError):
    pass


def need(value, reason):
    if not value:
        raise InvalidObservation(reason)


def text(value, maximum=256):
    return value if isinstance(value, str) and 0 < len(value) <= maximum and not any(ord(c) < 32 for c in value) else None


def digest(value):
    return value if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) else None


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def bracket(value):
    need(isinstance(value, dict), "missing timestamp")
    start = value.get("start_ticks", value.get("frame_start_ticks"))
    end = value.get("end_ticks", value.get("frame_end_ticks"))
    frequency = value.get("monotonic_frequency")
    need(integer(start) and integer(end) and end >= start and integer(frequency, 1), "invalid QPC bracket")
    return dict(start_ticks=str(start), end_ticks=str(end), frequency=frequency, clock="windows_qpc")


def incoming_source(row, base):
    """Validate transport shape only; retain observations, never infer a hit."""
    need(row.get('kind') == 'incoming_source_observation', 'invalid incoming kind')
    status = row.get('status')
    need(status in ('observed', 'unknown'), 'invalid incoming status')
    for field, expected in (('unique_hit', False), ('exact_damage', None), ('impact_timestamp', None),
                            ('numeric_team', None), ('visibility', 'unknown'), ('atomic', False),
                            ('public_state_eligible', False), ('continuity', 'unknown')):
        need(field in row and type(row[field]) is type(expected) and row[field] == expected,
             'contradictory incoming ' + field)
    need(row.get('semantics') == 'repeated_active_source_observation', 'unsupported incoming semantics')
    need(digest(row.get('semantic_review_sha256')), 'invalid incoming review')
    if status == 'unknown' and row.get('read_interval') is None:
        need(row.get('source_actor') is None and row.get('recipient_actor') is None and row.get('source_clock') is None
             and row.get('source_sampling_clock') is None and text(row.get('reason'))
             and (row.get('observation_id') is None or digest(row['observation_id'])), 'invalid untimed incoming unknown')
        return dict(base, kind='incoming_source', status='unknown', reason=row['reason'], observation_id=row.get('observation_id'),
            timestamp=None, source_actor=None, recipient_actor=None, source_sampling_clock=None, source_observation_evidence=None,
            observed_build_sha256=None, semantic_review_sha256=row['semantic_review_sha256'], validation_status='unknown',
            semantics='repeated_active_source_observation', unique_hit=False, exact_damage=None, impact_timestamp=None,
            numeric_team=None, continuity='unknown')
    need(digest(row.get('observation_id')), 'invalid incoming identity')
    proof = row.get('provenance')
    need(isinstance(proof, dict) and proof.get('schema') == 'overwatch-decoder.source-pair-join/1', 'missing incoming evidence')
    scope = proof.get('scope'); need(isinstance(scope, dict), 'missing incoming scope')
    frequency = scope.get('frequency')
    need(scope.get('clock_id') == 'windows_qpc' and integer(frequency, 1), 'invalid incoming clock')
    target = scope.get('target'); need(isinstance(target, dict), 'missing incoming build')
    build = digest(target.get('executable_sha256')); need(build, 'invalid incoming build')
    if 'observed_build_sha256' in row:
        need(row['observed_build_sha256'] == build, 'incoming observed build mismatch')
    def interval(value):
        need(isinstance(value, dict), 'missing incoming interval')
        if 'monotonic_frequency' in value:
            need(type(value['monotonic_frequency']) is int and value['monotonic_frequency'] == frequency,
                 'incoming interval frequency mismatch')
        return bracket(dict(value, monotonic_frequency=frequency))
    stamp = interval(row.get('read_interval'))
    context = proof.get('context'); need(isinstance(context, dict), 'missing incoming context')
    need(interval(context.get('read_interval')) == stamp, 'incoming context interval mismatch')
    need(proof.get('status') == ('resolved' if status == 'observed' else 'unknown')
         and proof.get('observation_id') == row['observation_id'], 'incoming provenance mismatch')
    def hashes(value):
        need(isinstance(value, dict), 'missing incoming hash evidence')
        keys = ('native_event_sha256', 'projection_sha256',
            'recording_frame_canonical_sha256', 'profile_sha256', 'review_sha256', 'contract_sha256')
        need(all(digest(value[key]) for key in keys if key in value), 'invalid incoming hash evidence')
        result = {key: value[key] for key in keys if key in value}
        if 'source_pins' in value:
            pins = value['source_pins']; need(isinstance(pins, dict), 'invalid incoming source pins')
            result['source_pins'] = {key: pins[key] for key in ('profile_sha256', 'manifest_sha256', 'evidence_sha256', 'recipe_sha256') if key in pins}
            need(all(digest(pin) for pin in result['source_pins'].values()), 'invalid incoming source pin')
        return result
    evidence = hashes(context.get('evidence'))
    need(all(evidence.get(key) for key in ('native_event_sha256', 'projection_sha256',
        'recording_frame_canonical_sha256', 'review_sha256', 'contract_sha256')), 'incomplete incoming context evidence')
    need(digest(context.get('raw_sha256')) and text(context.get('session_id'))
         and integer(context.get('segment'), 1) and integer(context.get('sequence')), 'invalid incoming context identity')
    need(evidence.get('review_sha256') == row['semantic_review_sha256'], 'incoming review mismatch')
    sampling = row.get('source_sampling_clock'); need(isinstance(sampling, dict), 'missing incoming sampler clock')
    utc = text(sampling.get('utc_origin'), 100)
    try:
        parsed = datetime.fromisoformat(utc.replace('Z', '+00:00')) if utc else None
        need(parsed is not None and parsed.utcoffset() is not None, 'invalid incoming UTC origin')
    except (ValueError, OverflowError):
        raise InvalidObservation('invalid incoming UTC origin') from None
    before, origin = sampling.get('utc_origin_before_ticks'), sampling.get('monotonic_origin_ticks')
    need(integer(before) and integer(origin) and before <= origin <= int(stamp['start_ticks'])
         and sampling.get('monotonic_frequency') == frequency and type(sampling.get('monotonic_frequency')) is int
         and digest(sampling.get('session_start_sha256'))
         and sampling.get('meaning') == 'sampler_UTC_origin_mapping_not_impact_time', 'invalid incoming sampler mapping')
    safe_clock = dict(utc_origin=utc, utc_origin_before_ticks=str(before), monotonic_origin_ticks=str(origin),
                      frequency=frequency, clock='windows_qpc', session_start_sha256=sampling['session_start_sha256'],
                      meaning='sampler_UTC_origin_mapping_not_impact_time')
    def actor(value, source):
        need(isinstance(value, dict) and isinstance(value.get('identity'), dict), 'missing incoming actor')
        identity = value['identity']
        need(text(identity.get('entity_id')) and text(identity.get('controller_id')), 'invalid incoming actor identity')
        safe = {key: identity[key] for key in ('entity_id', 'controller_id')}
        for key in ('body_owner_id', 'controller_owner_id'):
            if key in identity:
                need(digest(identity[key]), 'invalid incoming actor lifetime'); safe[key] = identity[key]
        safe.update(hero=dict(value=None, validation_status='unknown'),
                    relation=dict(value=None, validation_status='unknown'), visibility='unknown', numeric_team=None)
        hero = value.get('hero'); need(isinstance(hero, dict), 'missing incoming hero status')
        if source:
            need(hero.get('status') in ('observed', 'unknown'), 'invalid incoming hero status')
            if hero['status'] == 'observed':
                label = hero.get('value'); need(isinstance(label, dict) and text(label.get('label'), 100), 'invalid incoming hero')
                safe['hero'] = dict(value=label['label'], validation_status='observed')
            relation = value.get('relation'); need(isinstance(relation, dict) and relation.get('status') in ('observed', 'unknown'), 'invalid incoming relation')
            if relation['status'] == 'observed':
                need(relation.get('value') in ('self', 'ally', 'enemy'), 'invalid incoming relation value')
                safe['relation'] = dict(value=relation['value'], validation_status='observed')
            positions = value.get('position_observations')
            need(isinstance(positions, list) and len(positions) == 2, 'incoming requires two sampled positions')
            safe['position_observations'] = []
            for point in positions:
                need(isinstance(point, dict), 'invalid incoming position observation')
                roster, position = point.get('roster'), point.get('position')
                need(isinstance(roster, dict) and isinstance(position, dict), 'missing incoming position brackets')
                roster_stamp, position_stamp = interval(roster.get('read_interval')), interval(position.get('read_interval'))
                need(int(roster_stamp['start_ticks']) <= int(position_stamp['start_ticks']) <= int(position_stamp['end_ticks']) <= int(roster_stamp['end_ticks']), 'incoming position outside roster bracket')
                xyz = position.get('value')
                need(position.get('status') == 'observed' and isinstance(xyz, list) and len(xyz) == 3
                     and all(type(x) in (int, float) and math.isfinite(x) for x in xyz), 'invalid incoming sampled position')
                need(digest(roster.get('raw_sha256')) and text(roster.get('session_id'))
                     and integer(roster.get('segment'), 1) and integer(roster.get('sequence')), 'invalid incoming roster identity')
                position_evidence = hashes(position.get('evidence'))
                roster_evidence = hashes(roster.get('evidence'))
                need(all(roster_evidence.get(key) for key in ('native_event_sha256', 'projection_sha256', 'profile_sha256', 'contract_sha256')), 'incomplete incoming roster evidence')
                need(position_evidence.get('projection_sha256') and position_evidence['projection_sha256'] == roster_evidence.get('projection_sha256'), 'incoming position evidence mismatch')
                safe['position_observations'].append(dict(value=list(xyz), timestamp=position_stamp,
                    roster_timestamp=roster_stamp, roster_sha256=roster['raw_sha256'], session_id=roster['session_id'],
                    segment=roster['segment'], sequence=roster['sequence'], evidence=roster_evidence,
                    validation_status=text(position['evidence'].get('validation_status')) or 'unknown'))
            first, last = safe['position_observations']
            need(int(first['roster_timestamp']['end_ticks']) <= int(stamp['start_ticks'])
                 and int(stamp['end_ticks']) <= int(last['roster_timestamp']['start_ticks']), 'incoming positions do not bracket observation')
            need((int(last['roster_timestamp']['end_ticks']) - int(first['roster_timestamp']['start_ticks'])) * 1000 <= frequency * 100,
                 'incoming position bracket exceeds source join limit')
        else:
            label, valid = text(hero.get('value'), 100), text(hero.get('validation_status'))
            if valid and valid != 'unknown':
                need(label, 'invalid incoming recipient hero'); safe['hero'] = dict(value=label, validation_status=valid)
        return safe
    if status == 'unknown':
        need(row.get('source_actor') is None and row.get('recipient_actor') is None and row.get('source_clock') is None
             and text(row.get('reason')), 'unknown incoming attribution must remain null')
        source_actor = recipient_actor = None
    else:
        need(row.get('reason') is None, 'observed incoming reason must be null')
        clock = row.get('source_clock')
        need(isinstance(clock, dict) and clock.get('clock_id') == 'windows_qpc'
             and type(clock.get('frequency')) is int and clock['frequency'] == frequency, 'incoming source clock mismatch')
        source_actor, recipient_actor = actor(row.get('source_actor'), True), actor(row.get('recipient_actor'), False)
        need(text(row.get('attribution_validation')), 'missing incoming attribution validation')
    return dict(base, kind='incoming_source', status=status, reason=text(row.get('reason')),
        observation_id=row['observation_id'], timestamp=stamp, source_actor=source_actor, recipient_actor=recipient_actor,
        source_sampling_clock=safe_clock, source_observation_evidence=dict(raw_sha256=context['raw_sha256'],
            session_id=context['session_id'], segment=context['segment'], sequence=context['sequence'], **evidence),
        observed_build_sha256=build, semantic_review_sha256=row['semantic_review_sha256'],
        validation_status=text(row.get('attribution_validation')) if status == 'observed' else 'unknown',
        semantics='repeated_active_source_observation', unique_hit=False, exact_damage=None,
        impact_timestamp=None, numeric_team=None, continuity='unknown')


def raw_quaternion(value, row):
    """Validate optional transport; never reinterpret raw storage as camera aim."""
    item=value.get('raw_quaternion_candidate')
    evidence=value.get('field_evidence',{}); evidence=evidence.get('raw_quaternion_candidate') if isinstance(evidence,dict) else None
    unknown=dict(value=None,validation_status='unknown',reason=text(value.get('raw_quaternion_candidate_reason')) or 'invalid_raw_quaternion_evidence')
    try:
        need(value.get('raw_quaternion_candidate_validation')=='raw_orientation_candidate'
             and isinstance(item,list) and len(item)==4 and all(type(x) in (int,float) and math.isfinite(x) for x in item)
             and 0.99<=sum(x*x for x in item)<=1.01,'invalid_raw_quaternion')
        need(text(value.get('entity_id')) and text(value.get('controller_id')),'missing_quaternion_identity')
        need(isinstance(evidence,dict) and evidence.get('source')=='process_memory'
             and evidence.get('validation_status')=='raw_orientation_candidate'
             and evidence.get('semantics')=='raw_owned_component_four_float_candidate','quaternion_semantics')
        for key,root in (('observed_build_sha256','observed_build_sha256'),('profile_sha256','profile_sha256')):
            need(digest(evidence.get(key)) and evidence[key]==row.get(root),'quaternion_source_mismatch')
        need(digest(evidence.get('review_sha256')) and digest(evidence.get('contract_sha256')),'quaternion_review_missing')
        source=evidence.get('source_evidence')
        need(isinstance(source,dict) and set(source)=={'manifest_sha256','recipe_sha256','evidence_sha256'}
             and all(digest(v) for v in source.values()),'quaternion_acquisition_missing')
        stamp=bracket(row.get('timestamp'));reads=evidence.get('reads')
        need(isinstance(reads,list) and len(reads)==1,'quaternion_reads')
        read=reads[0];need(isinstance(read,dict) and text(read.get('field'))
            and integer(read.get('read_start_ticks')) and integer(read.get('read_end_ticks'))
            and int(stamp['start_ticks'])<=read['read_start_ticks']<=read['read_end_ticks']<=int(stamp['end_ticks']), 'quaternion_read_bracket')
        safe={k:evidence[k] for k in ('source','validation_status','semantics','observed_build_sha256',
            'profile_sha256','contract_sha256','review_sha256')}
        safe['source_evidence']=dict(source)
        safe['reads']=[dict(field=read['field'],read_start_ticks=str(read['read_start_ticks']),read_end_ticks=str(read['read_end_ticks']))]
        return dict(value=list(item),validation_status='raw_orientation_candidate',reason=None),safe
    except InvalidObservation:
        return unknown,None


def normalize(row, *, source_sha256=None):
    """Preserve candidate validation, nullable identities and source read brackets.

    Supports the configured private compact producer, not arbitrary object JSON.
    All source schemas are kept private. Normalization does not promote semantics.
    """
    need(isinstance(row, dict), "record must be an object")
    schema = row.get("schema")
    base = dict(schema="overwatch-decoder.session-observation/1", public_state_eligible=False,
                visibility="unknown", atomic=False, source="process_memory",
                source_schema=schema, source_sha256=digest(source_sha256),
                previous_values_carried=False)
    if schema == 'overwatch-decoder.private.incoming-source-observation/1':
        return incoming_source(row, base)
    if schema == "overwatch-decoder.private.selected-compact/1":
        need(row.get("source") == "process_memory" and row.get("scope") == "configured_controller_window", "unsupported compact scope")
        rows = row.get("entities")
        need(isinstance(rows, list) and len(rows) <= 4096, "invalid entity count")
        entities = []
        for value in rows:
            need(isinstance(value, dict), "invalid entity")
            entity = dict(entity_id=text(value.get("entity_id")), controller_id=text(value.get("controller_id")),
                          is_local=value.get("is_local") if type(value.get("is_local")) is bool else None,
                          visibility="unknown")
            for field in ("hero", "health", "position", "relation", "username", "team"):
                item = value.get(field)
                valid = text(value.get(field + "_validation")) or "unknown"
                if field == "position":
                    item = item if isinstance(item, list) and len(item) == 3 and all(type(x) in (int, float) and math.isfinite(x) for x in item) else None
                elif field == "health":
                    item = item if type(item) in (int, float) and math.isfinite(item) and item >= 0 else None
                else:
                    item = text(item, 100)
                # Explicit unknown must not retain an apparently usable value.
                if valid == "unknown":
                    item = None
                entity[field] = dict(value=item, validation_status=valid,
                                     reason=text(value.get(field + "_reason")))
            evidence = value.get("field_evidence", {})
            entity["field_evidence"] = {}
            if isinstance(evidence, dict):
                for field in ("hero", "health", "position", "relation"):
                    item = evidence.get(field)
                    if not isinstance(item, dict): continue
                    reads = item.get("reads", [])
                    safe_reads = []
                    if isinstance(reads, list) and len(reads) <= 128:
                        for read in reads:
                            if isinstance(read, dict) and integer(read.get("read_start_ticks")) and integer(read.get("read_end_ticks")) and read["read_end_ticks"] >= read["read_start_ticks"]:
                                safe_reads.append(dict(read_start_ticks=str(read["read_start_ticks"]), read_end_ticks=str(read["read_end_ticks"])))
                    entity["field_evidence"][field] = dict(source=text(item.get("source")), validation_status=text(item.get("validation_status")),
                        observed_build_sha256=digest(item.get("observed_build_sha256")), reads=safe_reads)
            if 'raw_quaternion_candidate' in value:
                candidate,proof=raw_quaternion(value,row)
                entity['raw_quaternion_candidate']=candidate
                if proof is not None:entity['field_evidence']['raw_quaternion_candidate']=proof
            entities.append(entity)
        stamp = bracket(row.get("timestamp"))
        roster = {}
        if any(key in row for key in ("roster_source_id", "roster_source_tick", "multi_source_snapshot")):
            source, tick = row.get("roster_source_id"), row.get("roster_source_tick")
            need(source in ("roster-00", "roster-01") and row.get("source_worker") == source
                 and row.get("source_batch") == source[-2:] and integer(tick)
                 and tick == int(stamp["end_ticks"]) and row.get("multi_source_snapshot") is False
                 and text(row.get("session_id")) is not None and integer(row.get("segment"), 1),
                 "invalid independent roster packet")
            roster = dict(roster_source_id=source, roster_source_tick=str(tick), multi_source_snapshot=False)
        return dict(base, **roster, kind="entities", timestamp=stamp,
                    source_worker=text(row.get("source_worker")) or "selected",
                    segment=text(str(row.get("segment"))), session_id=text(row.get("session_id")),
                    profile_sha256=digest(row.get("profile_sha256")),
                    provenance_sha256=digest(row.get("provenance_sha256")),
                    frame_gap=row.get("frame_gap") is True, entities=entities,
                    all_current_roster_claim=False, observed_build_sha256=digest(row.get("observed_build_sha256")))
    if schema == "overwatch-decoder.private.damage-feedback-candidate/1" and row.get("kind") == "damage_feedback_candidate":
        amount = row.get("amount_truncated")
        need(integer(amount), "invalid truncated damage amount")
        label = row.get("target_label")
        if label is not None:
            need(isinstance(label, dict), "invalid target label")
            label = {key: text(label.get(key)) for key in ("entity_id", "controller_id", "hero", "relation", "body_lifetime")}
        # Candidate outgoing feedback never becomes an incoming/attacker event.
        return dict(base, kind="damage", direction="outgoing_candidate", attacker=None,
                    target=label, target_status=text(row.get("target_label_status")) or "unresolved",
                    target_reason=text(row.get("target_label_reason")), amount_truncated=amount,
                    exact_damage=None, complete_event_count=False,
                    record_id=text(row.get("record_id")), timestamp=bracket(row.get("confirmation")),
                    validation_status=text(row.get("validation_status")) or "unknown",
                    validation_scope=text(row.get("validation_scope"), 1024),
                    observed_build_sha256=digest(row.get("observed_build_sha256")),
                    provenance_sha256=digest(row.get("source_review_sha256")))
    if schema == "overwatch-decoder.private.combined-status/1":
        return dict(base, kind="status", source="recorder", status=text(row.get("kind")),
                    reason=text(row.get("reason")), source_worker=text(row.get("source_id")),
                    outcome=text(row.get("outcome")))
    raise InvalidObservation("unsupported observation schema")


def from_line(raw):
    import json
    need(len(raw) <= 2 * 1024 * 1024, "observation line bound")
    row = json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(InvalidObservation("nonfinite JSON")))
    return normalize(row, source_sha256=hashlib.sha256(raw).hexdigest())
