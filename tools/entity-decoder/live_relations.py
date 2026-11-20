#!/usr/bin/env python3
"""Project one configured live epoch as private, non-durable research.

Legacy projection defaults to v1. Explicit selected-only mode admits v1/v4.

stdin accepts native --jsonl true --live-evidence true events. Acquisition files
must already exist at the explicitly supplied local directory. This program does
not acquire profiles, read processes or run a durability verifier. Optional live
category evidence requires a separately reviewed contract for this exact epoch.
Neutral context/raw categories use separate source admission; group comparisons
add their own finite reviewed scope and never imply universal allegiance.
"""
from __future__ import annotations
import argparse
from projection_copy import detached_copy
from native_event_envelope import NativeEventEnvelope, borrowed_event
from native_storage import NativeStorage
from forward_owner_relations import acquisition_validation_scope
from datetime import datetime, timezone
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from relations import GuardedRelations
from export_relations import (bounded_local_bytes, digest, integer, load_hero_projector, load_hero_asset_projector,
                              parse, project_frame, load_local_artifacts, verify_ammunition_source, verify_health_ratio_sources)

MAX_LINE = 512 * 1024
MAX_METADATA = 256 * 1024
MAX_INPUT = MAX_OUTPUT = 512 * 1024 * 1024
MAX_EVENTS = 100000


class InvalidLive(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidLive(reason)


def file_hash(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)), 'rb') as file:
        metadata = os.fstat(file.fileno())
        need(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= limit, 'acquisition_evidence_bound')
        hashed, count = hashlib.sha256(), 0
        while chunk := file.read(min(1048576, limit + 1 - count)):
            count += len(chunk)
            need(count <= limit, 'acquisition_evidence_bound')
            hashed.update(chunk)
        final = os.fstat(file.fileno())
        need(count == metadata.st_size and (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) ==
             (final.st_size, final.st_mtime_ns, final.st_ctime_ns), 'acquisition_evidence_changed')
        return hashed.hexdigest()


class LiveRelations:
    @acquisition_validation_scope(reuse_current=True)
    def __init__(self, acquisition, session_id, segment, *, health_contracts=(),
                 cached_label_recipe_sha256=None, hero_catalog=None, hero_artifacts=None, hero_locale='enUS', recipe_path=None,
                 live_category_contract=None, live_category_artifacts=None,
                 raw_category_contract=None, context_controller_contract=None, context_group_contract=None,
                 context_projection_admission=None, context_projection_artifacts=None,
                 hero_asset_catalog=None, hero_asset_artifacts=None, hero_asset_locale='enUS',
                 forward_owner_contract=None, forward_owner_artifacts=None, forward_owner_health_contracts=(),
                 forward_owner_category_contract=None, forward_owner_category_artifacts=None,
                 ammunition_contract=None, ammunition_artifacts=None, ammunition_admission=None,
                 health_ratio_contracts=(), health_ratio_native_review=None,
                 selected_only=False, selected_contract=None, selected_artifacts=None, selected_hero_catalog=None):
        need(isinstance(session_id, str) and re.fullmatch('[0-9a-f]{32}', session_id), 'invalid_session_id')
        need(integer(segment) and 1 <= segment <= 128, 'invalid_segment')
        need(type(selected_only) is bool, 'selected_policy_type')
        need(selected_only == (selected_contract is not None), 'selected_mode_requires_contract')
        need(selected_only or not (selected_artifacts or selected_hero_catalog), 'selected_mode_required')
        if selected_only:
            need(not any((health_contracts, cached_label_recipe_sha256, hero_catalog, hero_artifacts,
                live_category_contract, live_category_artifacts, raw_category_contract, context_controller_contract,
                context_group_contract, context_projection_admission, context_projection_artifacts,
                hero_asset_catalog, hero_asset_artifacts, forward_owner_contract, forward_owner_artifacts,
                forward_owner_health_contracts, forward_owner_category_contract, forward_owner_category_artifacts,
                ammunition_contract, ammunition_artifacts, ammunition_admission, health_ratio_contracts,
                health_ratio_native_review)), 'selected_mode_excludes_legacy_projectors')
        self.selected = None
        self.selected_session = self.selected_acquisition = None
        self.selected_segment_start = None
        self.selected_epoch_admitted = False
        self.background_preparation = False
        self.identical_profile_refresh = False
        self.prepared_activation = None
        directory = Path(acquisition)
        self.acquisition_directory = directory.resolve()
        self.raw_profile = bounded_local_bytes(directory/'profile.json', MAX_METADATA, 'profile_size')
        # Reject duplicate keys/non-finite JSON before the existing profile parser.
        profile = parse(self.raw_profile)
        need(profile.get('schema') in ({'overwatch-decoder.field-profile/1', 'overwatch-decoder.field-profile/4'} if selected_only
             else {'overwatch-decoder.field-profile/1'}), 'unsupported_live_profile_schema')
        self.stream_schema = 'overwatch-decoder.field-stream/' + profile['schema'].rsplit('/', 1)[1]
        self.projector = (GuardedRelations(self.raw_profile, allow_profile4=True) if selected_only
                          else GuardedRelations(self.raw_profile))
        manifest_raw = bounded_local_bytes(directory/'manifest.json', MAX_METADATA, 'manifest_size')
        recipe_raw = bounded_local_bytes(recipe_path or directory/'recipe.json', 1048576, 'recipe_size')
        manifest, recipe = parse(manifest_raw), parse(recipe_raw)
        need(manifest.get('schema') == 'overwatch-decoder.acquisition-result/1' and manifest.get('complete') is True
             and manifest.get('error') is None, 'incomplete_acquisition')
        need(manifest.get('target') == self.projector.target and manifest.get('profile_sha256') == self.projector.hash,
             'acquisition_identity_mismatch')
        need(manifest.get('recipe_sha256') == digest(recipe_raw)
             and manifest.get('evidence_sha256') == file_hash(directory/'evidence.jsonl', 128*1024*1024),
             'acquisition_hash_mismatch')
        need(recipe.get('target') == {key: self.projector.target[key] for key in ('image_name', 'executable_sha256', 'architecture')}
             and isinstance(recipe.get('stages'), list) and manifest.get('stages_completed') == len(recipe['stages']),
             'acquisition_recipe_mismatch')
        self.acquisition_stage_count=len(recipe['stages'])
        self.acquisition = dict(manifest_sha256=digest(manifest_raw), recipe_sha256=manifest['recipe_sha256'],
                                evidence_sha256=manifest['evidence_sha256'], relationship_semantics='profile_declared_research')
        if selected_only:
            from selected_entity_view import SelectedEntityView
            self.selected = SelectedEntityView(self.raw_profile,
                bounded_local_bytes(selected_contract, MAX_METADATA, 'selected_contract_size'),
                source=dict(profile_sha256=self.projector.hash, acquisition=self.acquisition),
                artifacts=selected_artifacts, hero_catalog=selected_hero_catalog, allow_profile4=True)
        self.session, self.segment = session_id, segment
        self.event_sequence = self.last_emitted = None
        self.frame_sequence = self.next_slot = self.skips = 0
        self.last_end = self.anchor = None
        self.active = self.closed = self.failed = False
        self._storage = NativeStorage(InvalidLive)
        self.health = []
        need(len(health_contracts) <= 128, 'health_contract_count')
        if health_contracts:
            from overwatch_decoder.health_projection import PoolHealthContract
            for path in health_contracts:
                descriptor = parse(bounded_local_bytes(path, MAX_METADATA, 'health_descriptor_size'))
                need(descriptor.get('acquisition_evidence_sha256') == self.acquisition['evidence_sha256'], 'health_acquisition_mismatch')
                self.health.append(PoolHealthContract.from_profile(self.raw_profile, **descriptor))
            need(len({contract.actor_prefix for contract in self.health}) == len(self.health), 'duplicate_health_contract')
        self.health_ratios = []
        need(len(health_ratio_contracts) <= 128, 'health_ratio_contract_count')
        need(bool(health_ratio_contracts) == bool(health_ratio_native_review),
             'health_ratio_contracts_and_review_required_together')
        if health_ratio_contracts:
            from health_ratio_validation import load_ratio_contract
            review = bounded_local_bytes(health_ratio_native_review, 8*1024*1024, 'health_ratio_native_review_size')
            for path in health_ratio_contracts:
                contract = load_ratio_contract(self.raw_profile,
                    bounded_local_bytes(path, MAX_METADATA, 'health_ratio_contract_size'), review)
                # First live admission deliberately matches the recorded three-word vectors;
                # the generic finite ratio contract also supports f32x4.
                need(all(pair['type'] == 'f32x3' for pair in contract.paired_slots),
                     'live_ratio_requires_f32x3')
                self.health_ratios.append(contract)
            verify_health_ratio_sources(self.health_ratios,
                dict(profile_sha256=self.projector.hash, acquisition=self.acquisition))
        self.cache = None
        if cached_label_recipe_sha256 is not None:
            need(cached_label_recipe_sha256 == self.acquisition['recipe_sha256'], 'cached_label_recipe_mismatch')
            from cached_labels import GuardedCachedLabels
            self.cache = GuardedCachedLabels(self.raw_profile)
        need(bool(hero_catalog) == bool(hero_artifacts), 'hero_catalog_and_artifacts_required_together')
        self.hero = load_hero_projector(self.raw_profile, hero_catalog, hero_artifacts, hero_locale) if hero_catalog else None
        need(bool(hero_asset_catalog) == bool(hero_asset_artifacts), 'hero_asset_catalog_and_artifacts_required_together')
        self.hero_asset = load_hero_asset_projector(self.raw_profile, hero_asset_catalog,
            hero_asset_artifacts, hero_asset_locale) if hero_asset_catalog else None
        need(bool(forward_owner_contract) == bool(forward_owner_artifacts),
             'forward_contract_and_artifacts_required_together')
        need(bool(forward_owner_category_contract) == bool(forward_owner_category_artifacts),
             'forward_category_contract_and_artifacts_required_together')
        need(not forward_owner_category_contract or forward_owner_contract, 'forward_category_requires_owner')
        need(not forward_owner_health_contracts or forward_owner_contract,
             'forward_health_requires_forward_contract')
        self.forward = None
        if forward_owner_contract:
            from forward_owner_projection import load_forward_projection
            self.forward = load_forward_projection(self.raw_profile, forward_owner_contract,
                forward_owner_artifacts, forward_owner_health_contracts, self.hero_asset,
                forward_owner_category_contract, forward_owner_category_artifacts)
            self.forward.verify_source(dict(profile_sha256=self.projector.hash, acquisition=self.acquisition))
        self.category = None
        self.category_session_seen = False
        self.raw_category = self.context = self.context_groups = None
        self.context_session_seen = False
        context_options = (raw_category_contract, context_controller_contract,
                           context_projection_admission, context_projection_artifacts)
        need(not any(context_options) or all(context_options), 'context_projection_inputs_required_together')
        need(not context_group_contract or all(context_options), 'context_group_requires_context_projection')
        need(not any(context_options) or not (live_category_contract or live_category_artifacts),
             'legacy_and_context_categories_mutually_exclusive')
        need(bool(live_category_contract) == bool(live_category_artifacts), 'live_category_contract_and_artifacts_required_together')
        if live_category_contract:
            from live_categories import GuardedLiveCategories
            contract = bounded_local_bytes(live_category_contract, MAX_METADATA, 'live_category_contract_size')
            artifacts = load_local_artifacts(live_category_artifacts, 'live_category')
            self.category = GuardedLiveCategories(self.raw_profile, contract, artifacts)
            need(self.category.acquisition_manifest_sha256 == self.acquisition['manifest_sha256']
                 and self.category.source == {k: self.acquisition[k] for k in ('recipe_sha256', 'evidence_sha256')}
                 and self.category.live_scope['session_id'] == self.session
                 and self.category.live_scope['segment'] == self.segment, 'live_category_configured_epoch_mismatch')
            self.category_session = parse(artifacts[self.category.session_start_sha256])
            self.category_segment = parse(artifacts[self.category.segment_start_sha256])
        if all(context_options):
            self._configure_context(raw_category_contract, context_controller_contract, context_group_contract,
                                    context_projection_admission, context_projection_artifacts)
        self.ammunition = None
        self.ammunition_session_seen = self.ammunition_acquisition_seen = False
        ammunition_options = (ammunition_contract, ammunition_artifacts, ammunition_admission)
        need(not any(ammunition_options) or all(ammunition_options), 'ammunition_inputs_required_together')
        if all(ammunition_options):
            self._configure_ammunition(*ammunition_options)

    def _configure_ammunition(self, contract_path, artifacts_path, admission_path):
        """A reviewed scalar contract plus admission for one actual native epoch."""
        from ammunition_candidates import GuardedAmmunitionCandidates
        contract = bounded_local_bytes(contract_path, MAX_METADATA, 'ammunition_contract_size')
        artifacts = load_local_artifacts(artifacts_path, 'ammunition')
        self.ammunition = GuardedAmmunitionCandidates(self.raw_profile, contract, artifacts)
        verify_ammunition_source(self.ammunition,
                                 dict(profile_sha256=self.projector.hash, acquisition=self.acquisition))
        admission_raw = bounded_local_bytes(admission_path, MAX_METADATA, 'ammunition_admission_size')
        admission = parse(admission_raw)
        source = {k: self.acquisition[k] for k in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256')}
        expected = dict(schema='overwatch-decoder.live-ammunition-admission/1', target=self.projector.target,
                        profile_sha256=self.projector.hash, source_acquisition=source,
                        ammunition_contract_sha256=self.ammunition.contract_sha256,
                        session_id=self.session, segment=self.segment)
        metadata_keys = ('session_start_sha256', 'acquisition_end_sha256', 'segment_start_sha256')
        need(isinstance(admission, dict) and set(admission) == set(expected) | set(metadata_keys)
             and all(admission.get(k) == v for k, v in expected.items()), 'ammunition_admission_scope_mismatch')
        metadata = []
        for key in metadata_keys:
            pin = admission[key]
            need(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin), 'ammunition_metadata_digest')
            data = artifacts.get(pin)
            need(isinstance(data, bytes) and 0 < len(data) <= MAX_METADATA and digest(data) == pin,
                 'ammunition_metadata_artifact_mismatch')
            metadata.append(parse(data))
        session, acquisition, segment = metadata
        need(all(isinstance(e, dict) and e.get('schema') == 'overwatch-decoder.field-live/1'
                 and e.get('session_id') == self.session for e in metadata), 'ammunition_metadata_scope_mismatch')
        entry = acquisition.get('acquisition', {})
        need(isinstance(entry, dict), 'ammunition_metadata_scope_mismatch')
        ordinal = entry.get('ordinal')
        declarations = segment.get('fields')
        need(session.get('kind') == 'session_start' and session.get('event_sequence') == 0
             and session.get('target') == self.projector.target
             and session.get('recipe_sha256') == source['recipe_sha256']
             and session.get('source_kind') == 'native_process_memory'
             and session.get('recording_frame_included') is True
             and session.get('atomic') is False and session.get('public_state_eligible') is False
             and acquisition.get('kind') == 'acquisition_end' and isinstance(entry, dict)
             and entry.get('complete') is True and entry.get('error') is None
             and integer(ordinal) and 1 <= ordinal <= 128
             and entry.get('directory') == f'acquisition-{ordinal:04d}'
             and entry.get('manifest_sha256') == source['manifest_sha256']
             and entry.get('profile_sha256') == self.projector.hash
             and segment.get('kind') == 'segment_start' and segment.get('segment') == self.segment
             and segment.get('acquisition') == ordinal and segment.get('profile_sha256') == self.projector.hash
             and segment.get('source_stream_schema') == 'overwatch-decoder.field-stream/1'
             and isinstance(declarations, list) and all(isinstance(f, dict) for f in declarations)
             and [(f.get('name'), f.get('type')) for f in declarations] ==
                 [(n, f['type']) for n, f in self.projector.fields.items()],
             'ammunition_metadata_scope_mismatch')
        frequency = session.get('monotonic_frequency')
        need(integer(frequency) and 0 < frequency <= 10**12
             and all(e.get('monotonic_frequency') == frequency for e in metadata)
             and all(integer(e.get('event_sequence')) and integer(e.get('emitted_ticks')) for e in metadata)
             and 0 == session['event_sequence'] < acquisition['event_sequence'] < segment['event_sequence']
             and 0 <= session['emitted_ticks'] <= acquisition['emitted_ticks'] <= segment['emitted_ticks']
             and integer(entry.get('start_ticks')) and integer(entry.get('end_ticks'))
             and session['emitted_ticks'] <= entry['start_ticks'] <= entry['end_ticks'] <= acquisition['emitted_ticks']
             and integer(segment.get('start_ticks'))
             and entry['end_ticks'] <= segment['start_ticks'] <= segment['emitted_ticks'],
             'ammunition_metadata_clock_or_order')
        self.ammunition_admission = detached_copy(admission)
        self.ammunition_admission_sha256 = digest(admission_raw)
        self.ammunition_session, self.ammunition_acquisition, self.ammunition_segment = metadata

    def _admit_ammunition_acquisition(self, event, raw):
        need(self.ammunition_session_seen and not self.ammunition_acquisition_seen
             and event == self.ammunition_acquisition, 'ammunition_admitted_acquisition_mismatch')
        self.ammunition_acquisition_seen = True
        self.ammunition_acquisition_event_sha256 = digest(raw)

    def _configure_context(self, category_path, context_path, group_path, admission_path, artifacts_path):
        """Bind neutral projectors to one exact supplied live epoch, not a roster."""
        from context_controller import GuardedContextController
        from raw_categories import GuardedRawCategories
        category_raw = bounded_local_bytes(category_path, MAX_METADATA, 'raw_category_contract_size')
        context_raw = bounded_local_bytes(context_path, MAX_METADATA, 'context_controller_contract_size')
        group_raw = bounded_local_bytes(group_path, MAX_METADATA, 'context_group_contract_size') if group_path else None
        artifacts = load_local_artifacts(artifacts_path, 'context_projection')
        self.raw_category = GuardedRawCategories(self.raw_profile, category_raw, artifacts)
        self.context = GuardedContextController(self.raw_profile, context_raw, artifacts)
        if group_raw is not None:
            from context_groups import GuardedContextGroups
            self.context_groups = GuardedContextGroups(self.raw_profile, category_raw, context_raw, group_raw, artifacts)
        self.context_contracts = dict(raw_category_contract_sha256=digest(category_raw),
            context_controller_contract_sha256=digest(context_raw),
            context_group_contract_sha256=digest(group_raw) if group_raw is not None else None)
        source = {k: self.acquisition[k] for k in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256')}
        for projector in (self.raw_category, self.context):
            need(projector.acquisition_manifest_sha256 == source['manifest_sha256']
                 and projector.source == {k: source[k] for k in ('recipe_sha256', 'evidence_sha256')},
                 'context_projector_acquisition_mismatch')
        admission_raw = bounded_local_bytes(admission_path, MAX_METADATA, 'context_projection_admission_size')
        admission = parse(admission_raw)
        expected = dict(schema='overwatch-decoder.live-context-admission/1', target=self.projector.target,
                        profile_sha256=self.projector.hash, source_acquisition=source,
                        session_id=self.session, segment=self.segment, **self.context_contracts)
        need(isinstance(admission, dict) and set(admission) == set(expected) | {
            'session_start_sha256', 'segment_start_sha256'}
             and all(admission.get(k) == v for k, v in expected.items()), 'context_admission_scope_mismatch')
        metadata = []
        for key in ('session_start_sha256', 'segment_start_sha256'):
            pin = admission[key]
            need(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin), 'context_metadata_digest')
            data = artifacts.get(pin)
            need(isinstance(data, bytes) and 0 < len(data) <= MAX_METADATA and digest(data) == pin,
                 'context_metadata_artifact_mismatch')
            metadata.append(parse(data))
        session, segment = metadata
        need(isinstance(session, dict) and isinstance(segment, dict)
             and session.get('schema') == segment.get('schema') == 'overwatch-decoder.field-live/1'
             and session.get('kind') == 'session_start' and session.get('event_sequence') == 0
             and session.get('session_id') == segment.get('session_id') == self.session
             and session.get('target') == self.projector.target
             and session.get('recipe_sha256') == self.acquisition['recipe_sha256']
             and segment.get('kind') == 'segment_start' and segment.get('segment') == self.segment
             and segment.get('profile_sha256') == self.projector.hash, 'context_metadata_scope_mismatch')
        need(integer(session.get('monotonic_frequency')) and 0 < session['monotonic_frequency'] <= 10**12
             and segment.get('monotonic_frequency') == session['monotonic_frequency']
             and integer(segment.get('event_sequence')) and segment['event_sequence'] > 0
             and integer(segment.get('start_ticks')) and segment['start_ticks'] >= 0
             and integer(session.get('emitted_ticks')) and integer(segment.get('emitted_ticks'))
             and 0 <= session['emitted_ticks'] <= segment['emitted_ticks'], 'context_metadata_clock_or_order')
        self.context_admission_sha256 = digest(admission_raw)
        self.context_admission = detached_copy(admission)
        self.context_session, self.context_segment = session, segment

    def begin_epoch(self, session_start_raw, acquisition_end_raw, segment_start_raw, *,
                    preparation_start_raw=None, preparation_end_raw=None, _native_event=None):
        """Admit original metadata into a pristine epoch decoder.

        LiveSession checks every intervening native event globally. This helper
        starts the local cursor at the actual segment sequence, without making
        replacement events or pretending prior epochs were decoded here.
        """
        need(self.event_sequence is None and not self.active and not self.closed and not self.failed,
             'live_epoch_decoder_not_pristine')
        try:
            for raw in (session_start_raw, acquisition_end_raw, segment_start_raw):
                need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE and raw.endswith(b'\n'), 'live_line_bound')
            session, acquisition = map(parse, (session_start_raw, acquisition_end_raw))
            segment = parse(segment_start_raw) if _native_event is None else borrowed_event(_native_event, segment_start_raw)
            need(session.get('kind') == 'session_start' and acquisition.get('kind') == 'acquisition_end'
                 and segment.get('kind') == 'segment_start', 'live_epoch_admission_kinds')
            frequency = session.get('monotonic_frequency')
            for event in (acquisition, segment):
                need(event.get('schema') == 'overwatch-decoder.field-live/1' and event.get('session_id') == self.session
                     and event.get('monotonic_frequency') == frequency
                     and integer(event.get('event_sequence')) and integer(event.get('emitted_ticks')),
                     'live_epoch_admission_scope')
            need(0 == session.get('event_sequence') < acquisition['event_sequence'] < segment['event_sequence']
                 and session['emitted_ticks'] <= acquisition['emitted_ticks'] <= segment['emitted_ticks'],
                 'live_epoch_admission_order')
            entry = acquisition.get('acquisition', {})
            need(entry.get('complete') is True and entry.get('error') is None
                 and integer(entry.get('ordinal')) and 1 <= entry['ordinal'] <= 128
                 and entry.get('directory') == f"acquisition-{entry['ordinal']:04d}"
                 and entry.get('profile_sha256') == self.projector.hash
                 and entry.get('manifest_sha256') == self.acquisition['manifest_sha256']
                 and segment.get('acquisition') == entry['ordinal'], 'live_epoch_acquisition_mismatch')
            need(type(acquisition.get('prepared',False)) is bool
                 and type(segment.get('prepared',False)) is bool
                 and acquisition.get('prepared',False)==segment.get('prepared',False), 'prepared_epoch_marker')
            if acquisition.get('prepared'):
                self._admit_prepared_activation(session,acquisition,segment,preparation_start_raw,preparation_end_raw)
            else:
                need(preparation_start_raw is None and preparation_end_raw is None, 'unexpected_preparation_metadata')
            self.consume(session_start_raw)
            if self.selected is not None:
                need(integer(entry.get('start_ticks')) and integer(entry.get('end_ticks'))
                     and session['emitted_ticks'] <= entry['start_ticks'] <= entry['end_ticks'] <= acquisition['emitted_ticks']
                     and integer(segment.get('start_ticks'))
                     and entry['end_ticks'] <= segment['start_ticks'] <= segment['emitted_ticks'],
                     'selected_epoch_metadata_time')
                self.selected_acquisition = detached_copy(entry)
                self.selected_epoch_admitted = True
            if self.ammunition is not None:
                self._admit_ammunition_acquisition(acquisition, acquisition_end_raw)
            self.event_sequence = segment['event_sequence'] - 1
            self.last_emitted = acquisition['emitted_ticks']
            if _native_event is None or type(self).consume is not LiveRelations.consume:
                self.consume(segment_start_raw)
            else:
                self._consume_native_event(segment_start_raw, _native_event)
        except (ValueError, KeyError, TypeError, AttributeError, OSError):
            self.failed = True
            raise

    def _admit_prepared_activation(self,session,acquisition,segment,start_raw,end_raw):
        need(session.get('background_preparation') is True, 'prepared_epoch_not_enabled')
        for metadata in (start_raw,end_raw):
            need(isinstance(metadata,bytes) and 0<len(metadata)<=MAX_METADATA and metadata.endswith(b'\n'), 'prepared_metadata_bound')
        started,ended=parse(start_raw),parse(end_raw);entry=acquisition['acquisition']
        need(started.get('kind')=='preparation_start' and ended.get('kind')=='preparation_end'
             and all(e.get('schema')=='overwatch-decoder.field-live/1' and e.get('session_id')==self.session
                     and e.get('monotonic_frequency')==session['monotonic_frequency'] for e in (started,ended)), 'prepared_metadata_scope')
        origin=acquisition.get('origin_segment')
        need(integer(origin) and integer(entry.get('start_ticks')) and integer(entry.get('end_ticks')) and origin+1==self.segment
             and started.get('origin_segment')==ended.get('origin_segment')==origin
             and started.get('acquisition')==entry['ordinal'] and started.get('start_ticks')==entry['start_ticks']
             and started.get('observation_gap_open') is False and 'gap_start_ticks' not in started
             and ended.get('acquisition')==entry and ended.get('outcome')=='ready'
             and acquisition.get('preparation_end_sha256')==digest(end_raw), 'prepared_metadata_pins')
        need(all(integer(e.get('event_sequence')) and integer(e.get('emitted_ticks')) for e in (started,ended))
             and 0<started['event_sequence']<ended['event_sequence']<acquisition['event_sequence']
             and session['emitted_ticks']<=entry['start_ticks']<=started['emitted_ticks']<=ended['emitted_ticks']<=acquisition['emitted_ticks']
             and entry['start_ticks']<=entry['end_ticks']<=ended['emitted_ticks'], 'prepared_metadata_order')
        activation=acquisition.get('activation')
        need(isinstance(activation,dict), 'prepared_activation_metadata')
        a,b=activation.get('start_ticks'),activation.get('end_ticks');count=activation.get('guard_count')
        pin=activation.get('evidence_sha256')
        need(integer(a) and integer(b) and entry['end_ticks']<=a<=b<=acquisition['emitted_ticks']
             and b<=segment['start_ticks'] and integer(count) and count==len(self.projector.guards)>0
             and activation.get('guards_verified') is True and isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin),
             'prepared_activation_metadata')
        data=bounded_local_bytes(self.acquisition_directory/'activation.json',MAX_METADATA,'prepared_activation_size')
        need(digest(data)==pin,'prepared_activation_hash')
        proof=parse(data)
        need(isinstance(proof,dict) and proof.get('schema')=='overwatch-decoder.profile-activation/1'
             and proof.get('target')==self.projector.target
             and all(type(proof['target'][key]) is type(value) for key,value in self.projector.target.items())
             and proof.get('profile_sha256')==self.projector.hash
             and proof.get('passed') is True and 'error' in proof and proof['error'] is None
             and integer(proof.get('start_ticks')) and integer(proof.get('end_ticks'))
             and proof['start_ticks']==a and proof['end_ticks']==b
             and isinstance(proof.get('guards'),list) and len(proof['guards'])==count,'prepared_activation_scope')
        previous=a
        for index,(observed,guard) in enumerate(zip(proof['guards'],self.projector.guards)):
            need(isinstance(observed,dict) and integer(observed.get('guard_id')) and observed['guard_id']==index
                 and observed.get('address_hex')==f"{guard['address']:016x}", 'prepared_activation_guard_identity')
            try:actual=bytes.fromhex(observed['bytes_hex']);expected=bytes.fromhex(guard['bytes_hex'])
            except (KeyError,ValueError,TypeError) as error:raise InvalidLive('prepared_activation_guard_bytes') from error
            need(actual==expected,'prepared_activation_guard_bytes')
            start,end=observed.get('start_ticks'),observed.get('end_ticks')
            need(integer(start) and integer(end) and previous<=start<=end<=b,'prepared_activation_guard_time')
            previous=end
        self.prepared_activation=dict(evidence_sha256=pin,start_ticks=a,end_ticks=b,guard_count=count,
            origin_segment=origin,preparation_start_sha256=digest(start_raw),preparation_end_sha256=digest(end_raw),
            actual_guard_bytes_verified=True,previous_values_carried=False)

    def verify_unchanged_preparation(self,directory,entry):
        """Verify candidate files without constructing or adopting a projector."""
        try:
            need(self.identical_profile_refresh and self.active and not self.closed and not self.failed
                 and entry.get('complete') is True and entry.get('error') is None,
                 'unchanged_epoch_not_active')
            directory=Path(directory)
            profile=bounded_local_bytes(directory/'profile.json',MAX_METADATA,'unchanged_profile_size')
            need(profile==self.raw_profile and digest(profile)==self.projector.hash==entry.get('profile_sha256'),
                 'unchanged_profile_bytes')
            data=bounded_local_bytes(directory/'manifest.json',MAX_METADATA,'unchanged_manifest_size')
            need(digest(data)==entry.get('manifest_sha256'),'unchanged_manifest_hash')
            manifest=parse(data)
            need(isinstance(manifest,dict) and manifest.get('schema')=='overwatch-decoder.acquisition-result/1'
                 and manifest.get('complete') is True and manifest.get('error') is None
                 and manifest.get('target')==self.projector.target and manifest.get('profile_sha256')==self.projector.hash
                 and manifest.get('recipe_sha256')==self.acquisition['recipe_sha256']
                 and integer(manifest.get('stages_completed')) and manifest['stages_completed']==self.acquisition_stage_count,
                 'unchanged_manifest_scope')
            pin=manifest.get('evidence_sha256')
            need(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin)
                 and file_hash(directory/'evidence.jsonl',128*1024*1024)==pin,'unchanged_evidence_hash')
            return dict(candidate_profile_sha256=digest(profile),candidate_manifest_sha256=digest(data),
                        candidate_evidence_sha256=pin,profile_bytes_compared=True)
        except (ValueError,KeyError,TypeError,AttributeError,OSError):
            self.failed=True
            raise

    def consume(self, raw):
        """One bounded raw event in; return a detached mutable projection."""
        need(not self.failed, 'live_adapter_failed')
        try:
            need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE and raw.endswith(b'\n'), 'live_line_bound')
            with NativeEventEnvelope(raw).owned() as envelope:
                return detached_copy(self._consume_native_event(raw, envelope))
        except (ValueError, KeyError, TypeError, AttributeError):
            self.failed = True
            raise

    def _consume_native_event(self, raw, envelope):
        need(not self.failed, 'live_adapter_failed')
        try:
            borrowed_event(envelope, raw)
            return self._consume_event(raw, envelope)
        except (ValueError, KeyError, TypeError, AttributeError):
            self.failed = True
            raise

    def _consume(self, raw):
        # Backward-compatible private raw-byte hook; decoding remains strict.
        return self.consume(raw)

    def _consume_event(self, raw, envelope):
        need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE and raw.endswith(b'\n'), 'live_line_bound')
        event = borrowed_event(envelope, raw)
        need(isinstance(event, dict) and event.get('schema') == 'overwatch-decoder.field-live/1'
             and event.get('session_id') == self.session, 'live_session_or_schema_mismatch')
        sequence, emitted, frequency = (event.get(key) for key in ('event_sequence', 'emitted_ticks', 'monotonic_frequency'))
        need(integer(sequence) and sequence >= 0 and (self.event_sequence is None or sequence == self.event_sequence + 1)
             and integer(emitted) and emitted >= 0 and (self.last_emitted is None or emitted >= self.last_emitted)
             and integer(frequency) and 0 < frequency <= 10**12, 'live_event_order')
        self.event_sequence, self.last_emitted = sequence, emitted
        kind = event.get('kind')
        self._storage.check_event(event)
        if self.selected is not None:
            need(self.selected_session is None or frequency == self.selected_session['monotonic_frequency'],
                 'selected_session_clock_changed')
            need(not self.closed, 'selected_epoch_closed')
        if kind == 'session_start':
            self._storage.start(event)
            need(type(event.get('background_preparation',False)) is bool,'live_background_policy')
            self.background_preparation=event.get('background_preparation',False)
            need(type(event.get('identical_profile_refresh',False)) is bool,'live_identical_refresh_policy')
            self.identical_profile_refresh=event.get('identical_profile_refresh',False)
            need(not self.identical_profile_refresh or self.background_preparation,'live_identical_refresh_requires_background')
            if self.selected is not None:
                need(self.selected_session is None and event.get('source_kind') == 'native_process_memory',
                     'selected_session_metadata')
                self.selected_session = detached_copy(event)
            need(sequence == 0 and not self.active and not self.closed and event.get('target') == self.projector.target
                 and event.get('recipe_sha256') == self.acquisition['recipe_sha256']
                 and event.get('recording_frame_included') is True and event.get('public_state_eligible') is False
                 and event.get('atomic') is False, 'live_session_metadata_mismatch')
            if self.category is not None:
                need(event == self.category_session, 'live_category_reviewed_session_mismatch')
                self.category_session_seen = True
            if self.context is not None:
                need(event == self.context_session, 'context_admitted_session_mismatch')
                self.context_session_seen = True
                self.context_session_event_sha256 = digest(raw)
            if self.ammunition is not None:
                need(not self.ammunition_session_seen and event == self.ammunition_session,
                     'ammunition_admitted_session_mismatch')
                self.ammunition_session_seen = True
                self.ammunition_session_event_sha256 = digest(raw)
            return None
        if kind == 'segment_start':
            need(not self.active and not self.closed and event.get('segment') == self.segment
                 and event.get('profile_sha256') == self.projector.hash
                 and event.get('source_stream_schema') == self.stream_schema, 'live_epoch_reconfiguration_required')
            if self.selected is not None:
                need(self.selected_epoch_admitted and self.selected_session is not None and self.selected_acquisition is not None
                     and event.get('acquisition') == self.selected_acquisition['ordinal']
                     and integer(event.get('start_ticks')) and event['start_ticks'] <= emitted,
                     'selected_epoch_admission_required')
                self.selected_segment_start = event['start_ticks']
            declared = event.get('fields')
            need(isinstance(declared, list) and [(f.get('name'), f.get('type')) for f in declared] ==
                 [(name, f['type']) for name, f in self.projector.fields.items()], 'live_field_declarations_mismatch')
            if self.category is not None:
                need(self.category_session_seen and event == self.category_segment, 'live_category_reviewed_segment_mismatch')
            if self.context is not None:
                need(self.context_session_seen and event == self.context_segment, 'context_admitted_segment_mismatch')
                self.context_segment_event_sha256 = digest(raw)
            if self.ammunition is not None:
                need(self.ammunition_session_seen and self.ammunition_acquisition_seen
                     and event == self.ammunition_segment, 'ammunition_admitted_segment_mismatch')
                self.ammunition_segment_event_sha256 = digest(raw)
            self._storage.begin(event)
            self.active = True
            return None
        if kind == 'storage_cohort_sealed':
            need(self.active and not self.closed, 'live_storage_outside_epoch')
            self._storage.seal(event, raw)
            return None
        if kind in ('preparation_start','preparation_end','preparation_discard','preparation_no_change'):
            need(self.background_preparation and self.active and integer(event.get('origin_segment')) and event['origin_segment']==self.segment
                 and (kind!='preparation_no_change' or self.identical_profile_refresh), 'live_preparation_scope')
            return None
        if kind in ('segment_end', 'session_end', 'session_finalization_error'):
            if kind == 'segment_end':
                self._storage.end(event)
                need(event.get('segment', {}).get('ordinal') == self.segment, 'live_epoch_reconfiguration_required')
            if kind == 'session_end':
                self._storage.finish(event.get('result_before_this_write', {}))
            self.active, self.closed = False, True
            return None
        if kind in ('acquisition_start', 'acquisition_end', 'gap'):
            need(not self.closed or kind == 'gap', 'live_epoch_reconfiguration_required')
            if kind == 'acquisition_end' and event.get('acquisition', {}).get('complete') is True:
                acq = event['acquisition']
                if self.selected is not None:
                    need(self.selected_session is not None and not self.active
                         and self.selected_acquisition is None and acq.get('error') is None
                         and integer(acq.get('ordinal')) and 1 <= acq['ordinal'] <= 128
                         and acq.get('directory') == f"acquisition-{acq['ordinal']:04d}",
                         'selected_acquisition_lifecycle')
                    self.selected_acquisition = detached_copy(acq)
                need(acq.get('profile_sha256') == self.projector.hash and
                     acq.get('manifest_sha256') == self.acquisition['manifest_sha256'], 'live_acquisition_mismatch')
                if self.ammunition is not None:
                    self._admit_ammunition_acquisition(event, raw)
            return None
        need(kind == 'frame' and self.active and not self.closed, 'live_frame_outside_configured_epoch')
        need(event.get('segment') == self.segment and event.get('profile_sha256') == self.projector.hash
             and event.get('target') == self.projector.target, 'live_epoch_reconfiguration_required')
        need(event.get('source') == 'process_memory' and event.get('interpretation') == 'profile_declared_research'
             and event.get('data_classification') == 'private_research' and event.get('public_state_eligible') is False
             and event.get('atomic') is False and event.get('recording_state') == 'accepted_not_durability_verified',
             'live_acceptance_qualification_mismatch')
        frame = event.get('recording_frame')
        need(isinstance(frame, dict) and frame.get('schema') == self.stream_schema and frame.get('kind') == 'frame'
             and frame.get('visibility') == 'research' and frame.get('runtime_semantics_validated') is False,
             'unsupported_recording_frame')
        shared = ('target', 'profile_sha256', 'source', 'interpretation', 'public_state_eligible', 'atomic', 'sequence',
                  'scheduled_slot', 'scheduled_ticks', 'start_ticks', 'end_ticks', 'jitter_ticks', 'skipped_intervals_before',
                  'skipped_intervals_total', 'utc_origin', 'utc_origin_before_ticks', 'monotonic_origin_ticks',
                  'monotonic_frequency', 'requested_interval_ms', 'scheduler_backend', 'hard_realtime')
        need(all(key in frame and key in event and frame[key] == event[key] for key in shared), 'live_recording_envelope_mismatch')
        start, end = frame['start_ticks'], frame['end_ticks']
        missed, slot = frame['skipped_intervals_before'], frame['scheduled_slot']
        origin, interval = frame['monotonic_origin_ticks'], frame['requested_interval_ms']
        need(all(integer(v) for v in (start, end, missed, slot, origin, interval, frame['sequence'], frame['skipped_intervals_total']))
             and 0 <= start <= end <= emitted and (self.last_end is None or self.last_end <= start)
             and missed >= 0 and slot == self.next_slot + missed and frame['sequence'] == self.frame_sequence
             and frame['skipped_intervals_total'] == self.skips + missed and 10 <= interval <= 10000,
             'live_frame_order_or_gap')
        utc = datetime.fromisoformat(frame['utc_origin'])
        need(utc.tzinfo is not None and utc.utcoffset() == timezone.utc.utcoffset(None)
             and origin >= 0 and integer(frame['utc_origin_before_ticks'])
             and 0 <= frame['utc_origin_before_ticks'] <= origin
             and integer(frame['jitter_ticks']) and frame['hard_realtime'] is False, 'live_clock_anchor_invalid')
        anchor = (origin, frequency, interval, frame['utc_origin'], frame['utc_origin_before_ticks'])
        need(self.anchor is None or self.anchor == anchor, 'live_clock_changed')
        need(integer(frame['scheduled_ticks']) and frame['scheduled_ticks'] == origin + slot * max(1, interval*frequency//1000)
             and frame['jitter_ticks'] == start - frame['scheduled_ticks'], 'live_scheduled_time_mismatch')
        if self.selected is not None:
            need(start >= self.selected_segment_start, 'selected_frame_before_segment')
        cancelled = self.stream_schema == 'overwatch-decoder.field-stream/4' and frame.get('terminal_reason') == 'cancelled'
        if cancelled:
            need(event.get('terminal_reason') == 'cancelled', 'selected_cancelled_terminal_mismatch')
        checks = []
        for phase in ('before', 'after'):
            values = frame.get('guards_' + phase)
            need(isinstance(values, list) and len(values) == len(self.projector.guards), 'live_guard_count')
            if self.stream_schema == 'overwatch-decoder.field-stream/4':
                values = self._selected_guard_checks(values, start, end, cancelled)
            for value in values:
                a, b = value.get('start_ticks'), value.get('end_ticks')
                need(type(value.get('ok')) is bool and integer(a) and integer(b) and
                     ((start <= a <= b <= end) or (value['ok'] is False and a == b == 0))
                     and ((value['ok'] is True and value.get('error') is None) or
                          (value['ok'] is False and isinstance(value.get('error'), str))), 'live_guard_bracket')
            checks.append(values)
        fields, outer = frame.get('fields'), event.get('fields')
        need(isinstance(fields, dict) and isinstance(outer, dict) and set(fields) == set(outer) == set(self.projector.fields),
             'live_field_set_mismatch')
        guard_windows = {}
        for name, declaration in self.projector.fields.items():
            sample, projected = fields[name], outer[name]
            need(all(key in sample and key in projected and sample[key] == projected[key]
                     for key in ('type', 'status', 'value', 'reason', 'read_start_ticks', 'read_end_ticks')),
                 'live_field_envelope_mismatch')
            if self.stream_schema == 'overwatch-decoder.field-stream/4':
                self._selected_field_envelope(sample, projected, declaration)
            else:
                need(projected.get('source') == 'process_memory' and projected.get('read_attempted') is None,
                     'live_field_source_mismatch')
            need(sample['type'] == declaration['type'] and sample['status'] in ('observed', 'unknown')
                 and sample.get('guard_ids') == self.projector.guard_ids[name], 'live_field_dependencies_mismatch')
            a, b = sample['read_start_ticks'], sample['read_end_ticks']
            need((integer(a) and integer(b) and start <= a <= b <= end) or
                 (sample['status'] == 'unknown' and a is None and b is None), 'live_field_read_bracket')
            if cancelled:
                need(sample['status'] == 'unknown' and sample['reason'] == 'cancelled', 'selected_cancelled_field_status')
            if sample['status'] == 'observed':
                need(sample['reason'] is None and sample['value'] is not None, 'live_observed_field_invalid')
                ids = tuple(sample['guard_ids'])
                if ids not in guard_windows:
                    guard_windows[ids] = (
                        all(checks[0][idx]['ok'] and checks[1][idx]['ok'] for idx in ids),
                        max((checks[0][idx]['end_ticks'] for idx in ids), default=start),
                        min((checks[1][idx]['start_ticks'] for idx in ids), default=end))
                ok, before_end, after_start = guard_windows[ids]
                need(ok and before_end <= a and after_start >= b, 'live_observed_guard_failed')
            else:
                need(sample['value'] is None and isinstance(sample['reason'], str), 'live_unknown_field_invalid')
        self._storage.frame(event)
        gap = dict(skipped_slots=missed, previous_end_ticks=self.last_end, current_start_ticks=start, previous_values_carried=False)
        source = dict(profile_sha256=self.projector.hash, acquisition=self.acquisition.copy(), live_event_sha256=digest(raw))
        qualification = dict(complete=False, partial=True, status='accepted_not_durability_verified',
                             durability_verified=False, continuity_across_gaps=False)
        if self.selected is not None:
            result = self.selected.project(frame, gap=bool(missed))
            result.update(schema='overwatch-decoder.selected-entity-live/1', session_id=self.session, segment=self.segment,
                event_sequence=sequence, recording_state='accepted_not_durability_verified',
                durability_verified=False, privacy='private', source_artifacts=source,
                recording=qualification, gap=gap)
            if self.prepared_activation is not None:result['prepared_activation']=detached_copy(self.prepared_activation)
            self.anchor, self.last_end = anchor, end
            self.frame_sequence += 1
            self.next_slot, self.skips = slot + 1, self.skips + missed
            return result
        # This parsed frame is private to consume; all projectors below are
        # owned by this adapter and treat it read-only. Guard summaries expire
        # before returning, including on any projection failure.
        with ExitStack() as scopes:
            relations = [self.projector]
            relations += [p.relations for p in (self.cache, self.hero, self.category, self.hero_asset,
                                               self.ammunition) if p is not None]
            relations += [p.relations for p in (self.raw_category, self.context) if p is not None]
            if self.forward is not None:
                relations.append(self.forward.relations)
                if self.forward.hero is not None:
                    relations.append(self.forward.hero.relations)
                if self.forward.category is not None:
                    relations.extend((self.forward.category.forward.relations,
                                      self.forward.category.category_fields.relations))
            for projector in relations:
                scopes.enter_context(projector._frame_checks(frame))
            result = project_frame(self.projector, frame, source, qualification, gap, self.health,
                                   hero_projector=self.hero, cached_label_projector=self.cache,
                                   hero_asset_projector=self.hero_asset, forward_owner_projector=self.forward,
                                   ammunition_projector=self.ammunition, health_ratio_contracts=self.health_ratios)
            result.update(schema='overwatch-decoder.entity-relations-live/1', session_id=self.session, segment=self.segment,
                          event_sequence=sequence, recording_state='accepted_not_durability_verified',
                          durability_verified=False, privacy='private', source_artifacts=source)
            if self.category is not None:
                self._compose_live_categories(result, frame, source, gap, sequence)
            if self.context is not None:
                self._compose_context(result, frame, source, gap, sequence)
            if self.ammunition is not None:
                from live_categories import live_frame_sha256
                need(frame['monotonic_frequency'] == self.ammunition_session['monotonic_frequency']
                     and frame['start_ticks'] >= self.ammunition_segment['start_ticks'],
                     'ammunition_frame_clock_or_start_mismatch')
                result.update(live_ammunition_output_enabled=True,
                    ammunition_contract_sha256=self.ammunition.contract_sha256,
                    ammunition_admission_sha256=self.ammunition_admission_sha256,
                    ammunition_live_admission=dict(
                        schema='overwatch-decoder.live-ammunition-frame-admission/1', session_id=self.session,
                        segment=self.segment, acquisition=self.ammunition_acquisition['acquisition']['ordinal'],
                        event_sequence=sequence, profile_sha256=self.projector.hash,
                        source_acquisition={k: self.acquisition[k] for k in
                                            ('manifest_sha256', 'recipe_sha256', 'evidence_sha256')},
                        contract_sha256=self.ammunition.contract_sha256,
                        admission_sha256=self.ammunition_admission_sha256,
                        session_start_artifact_sha256=self.ammunition_admission['session_start_sha256'],
                        acquisition_end_artifact_sha256=self.ammunition_admission['acquisition_end_sha256'],
                        segment_start_artifact_sha256=self.ammunition_admission['segment_start_sha256'],
                        session_start_event_sha256=self.ammunition_session_event_sha256,
                        acquisition_end_event_sha256=self.ammunition_acquisition_event_sha256,
                        segment_start_event_sha256=self.ammunition_segment_event_sha256,
                        live_event_sha256=digest(raw), recording_frame_sha256=live_frame_sha256(frame),
                        previous_values_carried=False, durability_verified=False,
                        recording_state='accepted_not_durability_verified'))
        if self.prepared_activation is not None:result['prepared_activation']=detached_copy(self.prepared_activation)
        self.anchor, self.last_end = anchor, end
        self.frame_sequence += 1
        self.next_slot, self.skips = slot + 1, self.skips + missed
        return result

    def _selected_guard_checks(self, values, start, end, cancelled):
        """Validate native v4 read evidence; never rewrite the frame sent to the projector."""
        result = []
        for index, (value, declaration) in enumerate(zip(values, self.projector.guards)):
            need(isinstance(value, dict) and integer(value.get('guard_id')) and value.get('guard_id') == index, 'selected_guard_id')
            read = value.get('read')
            need(isinstance(read, dict) and type(read.get('attempted')) is bool, 'selected_guard_read')
            expected = bytes.fromhex(declaration['bytes_hex'])
            actual = read.get('bytes_hex')
            a, b = read.get('start_ticks'), read.get('end_ticks')
            address = declaration['address']
            need(integer(address) and integer(read.get('requested_bytes'))
                 and read['requested_bytes'] == len(expected), 'selected_guard_read_scope')
            if read['attempted']:
                returned = read.get('returned_bytes')
                # Native cancellation can interrupt the call before a byte count is available.
                interrupted = (cancelled and 'returned_bytes' in read and returned is None
                               and 'bytes_hex' in read and actual is None
                               and read.get('error') == value.get('error') == 'cancelled')
                need(read.get('address_hex') == f'{address:016x}'
                     and (integer(returned) and 0 <= returned <= len(expected) or interrupted)
                     and integer(a) and integer(b) and start <= a <= b <= end, 'selected_guard_read_time')
                success = read.get('error') is None and returned == len(expected)
                if success:
                    need(isinstance(actual, str) and re.fullmatch('[0-9a-f]+', actual) is not None
                         and len(actual) == 2 * len(expected), 'selected_guard_bytes')
                else:
                    need(actual is None and isinstance(read.get('error'), str), 'selected_guard_read_error')
            else:
                need(a is None and b is None and read.get('address_hex') is None
                     and read.get('returned_bytes') is None and actual is None
                     and isinstance(read.get('error'), str), 'selected_guard_not_attempted')
                a = b = 0
                success = False
            matches = success and actual == expected.hex()
            need(type(value.get('ok')) is bool and value['ok'] == matches,
                 'selected_guard_claim_mismatch')
            result.append(dict(ok=value['ok'], error=value.get('error'), start_ticks=a, end_ticks=b))
        return result

    def _selected_field_envelope(self, sample, projected, declaration):
        need(json.dumps(sample.get('value'), allow_nan=False) == json.dumps(projected.get('value'), allow_nan=False),
             'selected_value_envelope_mismatch')
        codec = declaration.get('codec')
        need(codec in (None, 'pool_sum_f32') and not any(k in declaration for k in ('path', 'path_id')),
             'selected_live_requires_fixed_scalar_or_pool')
        if sample.get('status') == 'observed':
            address = declaration.get('address')
            need(integer(address) and sample.get('read_address_hex') == f'{address:016x}'
                 and sample.get('path_id') is None and sample.get('read_attempted') is True
                 and sample.get('read_error') is None, 'selected_field_read_scope')
        need(projected.get('source') == ('calculated_process_memory' if codec == 'pool_sum_f32' else 'process_memory')
             and type(sample.get('read_attempted')) is bool
             and projected.get('read_attempted') == sample['read_attempted']
             and projected.get('read_error') == sample.get('read_error'), 'live_field_source_mismatch')
        if codec == 'pool_sum_f32':
            for key in ('codec', 'pool_span', 'pool_slots', 'read_kind'):
                need(projected.get(key) == sample.get(key), 'selected_codec_envelope_mismatch')
            operands = sample.get('operands')
            need(isinstance(operands, dict) and set(operands) == {'snapshot_a', 'snapshot_b'}
                 and all(isinstance(v, dict) for v in operands.values()), 'selected_codec_operands')
            sanitized = {k: {n: v for n, v in operand.items() if n != 'address_hex'}
                         for k, operand in operands.items()}
            need(projected.get('operands') == sanitized, 'selected_codec_envelope_mismatch')

    def _compose_context(self, result, frame, source, gap, sequence):
        """Keep new raw/context evidence separate from legacy allegiance fields."""
        from live_categories import live_frame_sha256
        need(frame['monotonic_frequency'] == self.context_session['monotonic_frequency']
             and frame['start_ticks'] >= self.context_segment['start_ticks'], 'context_frame_clock_or_start_mismatch')
        skipped = bool(gap['skipped_slots'])
        raw_categories = self.raw_category.project(frame, gap=skipped)
        context = self.context.project(frame, gap=skipped)
        groups = self.context_groups.project(frame, gap=skipped) if self.context_groups else None
        source_pins = dict(self.raw_category.source, acquisition_manifest_sha256=self.acquisition['manifest_sha256'])
        timing = {k: frame[k] for k in ('sequence', 'start_ticks', 'end_ticks', 'monotonic_frequency')}
        for projected, schema, contract in (
                (raw_categories, 'overwatch-decoder.guarded-raw-actor-categories/1', self.raw_category.contract_sha256),
                (context, 'overwatch-decoder.guarded-context-controller/1', self.context.contract_sha256)):
            need(isinstance(projected, dict) and projected.get('schema') == schema
                 and projected.get('profile_sha256') == self.projector.hash
                 and projected.get('target') == self.projector.target
                 and projected.get('source_evidence') == source_pins
                 and projected.get('contract_sha256') == contract
                 and all(projected.get('timing', {}).get(k) == v for k, v in timing.items())
                 and projected.get('public_state_eligible') is False and projected.get('visibility') == 'unknown'
                 and projected.get('atomic') is False and projected.get('durability_verified') is False,
                 'context_projection_source_mismatch')
        need(raw_categories.get('timing') == result['timing']
             and raw_categories.get('native_review_sha256') == self.raw_category.native_review_sha256
             and context.get('native_review_sha256') == self.context.native_review_sha256,
             'context_projection_source_mismatch')
        frame_hash = live_frame_sha256(frame)
        if groups is not None:
            need(isinstance(groups, dict) and groups.get('schema') == 'overwatch-decoder.guarded-context-groups/1'
                 and groups.get('profile_sha256') == self.projector.hash
                 and groups.get('target') == self.projector.target and groups.get('source_evidence') == source_pins
                 and groups.get('contract_sha256') == self.context_groups.contract_sha256
                 and groups.get('category_contract_sha256') == self.raw_category.contract_sha256
                 and groups.get('context_contract_sha256') == self.context.contract_sha256
                 and groups.get('two_group_review_sha256') == self.context_groups.group_review_sha256
                 and groups.get('context_scope_review_sha256') == self.context_groups.context_scope_review_sha256
                 and groups.get('mode_id') == self.context_groups.mode_id
                 and groups.get('native_frame_sha256') == frame_hash and groups.get('timing') == timing
                 and groups.get('context_controller_object_key') == context['controller_object_key']
                 and groups.get('context_body_object_key') == context['body_object_key']
                 and groups.get('public_state_eligible') is False and groups.get('visibility') == 'unknown'
                 and groups.get('atomic') is False and groups.get('durability_verified') is False,
                 'context_group_projection_source_mismatch')
        admission = dict(schema='overwatch-decoder.live-context-frame-admission/1',
            status='accepted_not_durability_verified', durability_verified=False,
            configured_admission_sha256=self.context_admission_sha256,
            session_id=self.session, segment=self.segment, event_sequence=sequence,
            event_sha256=source['live_event_sha256'], native_frame_sha256=frame_hash,
            frame_sequence=frame['sequence'], frame_start_ticks=frame['start_ticks'], frame_end_ticks=frame['end_ticks'],
            monotonic_frequency=frame['monotonic_frequency'], profile_sha256=self.projector.hash,
            source_acquisition=source['acquisition'].copy(),
            session_start_sha256=self.context_admission['session_start_sha256'],
            segment_start_sha256=self.context_admission['segment_start_sha256'],
            session_start_event_sha256=self.context_session_event_sha256,
            segment_start_event_sha256=self.context_segment_event_sha256)
        rows = raw_categories.get('rows')
        group_rows = groups.get('rows') if groups is not None else []
        need(isinstance(rows, list) and len(rows) <= 32 and all(isinstance(r, dict) for r in rows)
             and isinstance(group_rows, list) and len(group_rows) <= 32
             and all(isinstance(r, dict) for r in group_rows), 'context_projection_rows')
        context_matches = [row for row in rows
            if context['status'] == 'observed' and context['body_status'] == 'observed'
            and row.get('controller_object_key') == context['controller_object_key']
            and row.get('body_object_key') == context['body_object_key']]
        context_category = (context_matches[0]['raw_category_candidate']
            if not skipped and len(context_matches) == 1 and context_matches[0].get('status') == 'observed'
            else None)
        projection = dict(schema='overwatch-decoder.live-context-group-projection/1',
            session_id=self.session, segment=self.segment, event_sequence=sequence,
            profile_sha256=self.projector.hash, target=self.projector.target.copy(), timing=detached_copy(result['timing']),
            admission=admission, contract_sha256=self.context_contracts.copy(),
            raw_category_projection=detached_copy(raw_categories), context_projection=detached_copy(context),
            group_projection=detached_copy(groups),
            frame_scope=detached_copy(self.context_groups.interval) if self.context_groups else None,
            recording_state='accepted_not_durability_verified', durability_verified=False,
            privacy='private', public_state_eligible=False, visibility='unknown', atomic=False,
            previous_values_carried=False)
        result.update(context_group_projection=projection, raw_context_output_enabled=True,
                      context_group_output_enabled=self.context_groups is not None)
        for relation in result['relations']:
            relation.update(raw_category_candidate=None, team_candidate=None, relative_allegiance_candidate=None,
                            category_evidence=None, context_group_candidate=None,
                            context_group_evidence=None, context_group_reason=None)
            if relation['relation_status'] != 'observed' or skipped:
                relation['context_group_reason'] = 'gap_before_frame' if skipped else 'relation_unknown'
                continue
            def matches(candidates):
                return [r for r in candidates if r.get('controller_object_key') == relation['controller_object_key']
                        and r.get('body_object_key') == relation['body_object_key']]
            raw_matches, compared = matches(rows), matches(group_rows)
            if len(raw_matches) != 1 or raw_matches[0].get('raw_status') != 'observed':
                relation['context_group_reason'] = (raw_matches[0].get('reason') if len(raw_matches) == 1
                    else 'missing_or_ambiguous_category_for_exact_object_keys') or 'raw_category_unknown'
                continue
            category = raw_matches[0]
            comparison = compared[0] if len(compared) == 1 else None
            observed_group = comparison is not None and comparison.get('status') == 'observed'
            equality = (category['raw_category_candidate'] == context_category
                if category['status'] == 'observed' and context_category is not None else None)
            relation['context_group_candidate'] = dict(raw_flags=detached_copy(category['raw_flags_candidate']),
                raw_category=category['raw_category_candidate'], raw_status=category['raw_status'],
                category_status=category['status'], context_raw_category=context_category,
                category_matches_context=equality, global_group=comparison['global_group_candidate'] if observed_group else None,
                relation_to_context=comparison['group_relation_candidate'] if observed_group else None,
                group_status='observed' if observed_group else 'unknown')
            relation['context_group_reason'] = (category.get('reason') or
                ('context_group_not_configured' if groups is None else
                 comparison.get('reason') if comparison is not None else 'missing_or_ambiguous_group_for_exact_object_keys'))
            relation['context_group_evidence'] = dict(actor_fields=detached_copy(category['evidence']),
                context_reference=dict(controller_object_key=context['controller_object_key'],
                    body_object_key=context['body_object_key'], status=context['status'], reason=context['reason'],
                    body_status=context['body_status'], body_reason=context['body_reason'],
                    projection='context_group_projection.context_projection',
                    raw_category_projection='context_group_projection.raw_category_projection',
                    group_context_evidence='context_group_projection.group_projection.context_evidence' if groups else None),
                source_acquisition=source['acquisition'].copy(), profile_sha256=self.projector.hash,
                build_sha256=self.projector.target['executable_sha256'], contract_sha256=self.context_contracts.copy(),
                category_native_review_sha256=self.raw_category.native_review_sha256,
                context_native_review_sha256=self.context.native_review_sha256,
                two_group_review_sha256=self.context_groups.group_review_sha256 if self.context_groups else None,
                context_scope_review_sha256=self.context_groups.context_scope_review_sha256 if self.context_groups else None,
                frame_scope=detached_copy(projection['frame_scope']), admission=detached_copy(admission),
                public_state_eligible=False, visibility='unknown', atomic=False, durability_verified=False)


    def _compose_live_categories(self, result, frame, source, gap, sequence):
        from live_categories import live_frame_sha256
        admission = dict(schema='overwatch-decoder.live-category-frame-admission/1',
            status='accepted_not_durability_verified', durability_verified=False,
            session_id=self.session, segment=self.segment, profile_sha256=self.projector.hash,
            acquisition_manifest_sha256=self.acquisition['manifest_sha256'],
            recipe_sha256=self.acquisition['recipe_sha256'], evidence_sha256=self.acquisition['evidence_sha256'],
            event_sequence=sequence, event_sha256=source['live_event_sha256'],
            frame_sha256=live_frame_sha256(frame), frame_sequence=frame['sequence'],
            frame_start_ticks=frame['start_ticks'], frame_end_ticks=frame['end_ticks'],
            monotonic_frequency=frame['monotonic_frequency'])
        projected = self.category.project(frame, admission=admission, gap=bool(gap['skipped_slots']))
        expected_admission = {k: v for k, v in admission.items() if k not in ('schema', 'status', 'durability_verified')}
        need(projected.get('schema') == 'overwatch-decoder.guarded-live-actor-categories/1'
             and projected.get('profile_sha256') == self.projector.hash
             and projected.get('target') == self.projector.target
             and projected.get('timing') == result['timing']
             and projected.get('source_evidence') == dict(self.category.source,
                 acquisition_manifest_sha256=self.acquisition['manifest_sha256'])
             and projected.get('contract_sha256') == self.category.contract_sha256
             and projected.get('self_controller_object_key') == self.category.self_controller_object_key
             and projected.get('live_scope') == self.category.live_scope
             and projected.get('admission_evidence') == expected_admission
             and projected.get('public_state_eligible') is False and projected.get('visibility') == 'unknown'
             and projected.get('recording_state') == 'accepted_not_durability_verified'
             and projected.get('durability_verified') is False, 'live_category_projection_source_mismatch')
        rows = projected.get('rows')
        need(isinstance(rows, list), 'live_category_projection_rows')
        result.update(category_output_enabled=True, live_category_output_enabled=True,
                      live_category_contract_sha256=self.category.contract_sha256,
                      category_contract_sha256=self.category.contract_sha256)
        for relation in result['relations']:
            relation.update(raw_category_candidate=None, team_candidate=None, relative_allegiance_candidate=None)
            if relation['relation_status'] != 'observed':
                relation['category_reason'] = 'relation_unknown'
                continue
            matches = [r for r in rows if r.get('controller_object_key') == relation['controller_object_key']
                       and r.get('body_object_key') == relation['body_object_key']]
            if gap['skipped_slots']:
                relation['category_reason'] = 'gap_before_frame'
            elif len(matches) != 1:
                relation['category_reason'] = 'missing_or_ambiguous_category_for_exact_object_keys'
            elif matches[0].get('status') != 'observed':
                relation['category_reason'] = matches[0].get('reason') or 'category_projection_unknown'
            else:
                category = matches[0]
                relation.update(raw_category_candidate=category['raw_category_candidate'],
                    team_candidate=category['team_candidate'], relative_allegiance_candidate=category['relative_allegiance_candidate'])
                if category.get('reason') is not None:
                    relation['category_reason'] = category['reason']
                relation['category_evidence'] = dict(fields=category['evidence'], self_fields=category.get('self_evidence'),
                    mode_id=projected['mode_id'], mode_scope=category.get('mode_scope'),
                    self_controller_object_key=projected['self_controller_object_key'],
                    native_review_sha256=projected['native_review_sha256'], roster_review_sha256=projected['roster_review_sha256'],
                    mode_review_sha256=projected['mode_review_sha256'], contract_sha256=projected['contract_sha256'],
                    profile_sha256=self.projector.hash, build_sha256=self.projector.target['executable_sha256'],
                    acquisition=source['acquisition'].copy(), admission=projected['admission_evidence'],
                    validation_status='guarded_live_category_roster_research', public_state_eligible=False,
                    durability_verified=False)


def stream(adapter, source, output, *, maximum_input=MAX_INPUT, maximum_output=MAX_OUTPUT, maximum_events=MAX_EVENTS):
    need(all(integer(v) and v > 0 for v in (maximum_input, maximum_output, maximum_events))
         and maximum_input <= MAX_INPUT and maximum_output <= MAX_OUTPUT and maximum_events <= MAX_EVENTS, 'live_stream_bounds')
    incoming = outgoing = events = frames = 0
    while raw := source.readline(MAX_LINE + 1):
        incoming += len(raw); events += 1
        need(incoming <= maximum_input and events <= maximum_events, 'live_input_budget')
        result = adapter.consume(raw)
        if result is None:
            continue
        encoded = json.dumps(result, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        need(len(encoded) <= 1024*1024 and outgoing + len(encoded) <= maximum_output, 'live_output_budget')
        written = output.write(encoded)
        need(written == len(encoded), 'live_output_short_write')
        output.flush(); outgoing += len(encoded); frames += 1
    return dict(schema='overwatch-decoder.entity-relations-live-result/1', frames=frames, events=events, input_bytes=incoming,
                completed_write_bytes=outgoing, input_closed=True, native_epoch_closed=adapter.closed,
                durability_verified=False, public_state_eligible=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acquisition', required=True, type=Path)
    parser.add_argument('--recipe', type=Path, help='explicit observation root recipe when absent from acquisition directory')
    parser.add_argument('--session-id', required=True)
    parser.add_argument('--segment', required=True, type=int)
    parser.add_argument('--health-contract', action='append', default=[], type=Path)
    parser.add_argument('--health-ratio-contract', action='append', default=[], type=Path,
                        help='optional fresh paired f32x3 ratio contract; f32x4 live ratios are unsupported')
    parser.add_argument('--health-ratio-native-review', type=Path)
    parser.add_argument('--cached-label-recipe-sha256')
    parser.add_argument('--hero-catalog', type=Path)
    parser.add_argument('--hero-artifacts', type=Path)
    parser.add_argument('--hero-locale', default='enUS')
    parser.add_argument('--hero-asset-catalog', type=Path)
    parser.add_argument('--hero-asset-artifacts', type=Path)
    parser.add_argument('--hero-asset-locale', default='enUS')
    parser.add_argument('--forward-owner-contract', type=Path)
    parser.add_argument('--forward-owner-artifacts', type=Path)
    parser.add_argument('--forward-owner-health-contract', action='append', default=[], type=Path)
    parser.add_argument('--forward-owner-category-contract', type=Path)
    parser.add_argument('--forward-owner-category-artifacts', type=Path)
    parser.add_argument('--live-category-contract', type=Path)
    parser.add_argument('--live-category-artifacts', type=Path)
    parser.add_argument('--raw-category-contract', type=Path)
    parser.add_argument('--context-controller-contract', type=Path)
    parser.add_argument('--context-group-contract', type=Path)
    parser.add_argument('--context-projection-admission', type=Path)
    parser.add_argument('--context-projection-artifacts', type=Path)
    parser.add_argument('--ammunition-contract', type=Path)
    parser.add_argument('--ammunition-artifacts', type=Path)
    parser.add_argument('--ammunition-admission', type=Path)
    parser.add_argument('--selected-only', action='store_true')
    parser.add_argument('--selected-contract', type=Path)
    parser.add_argument('--selected-artifacts', type=Path, help='local SHA256-to-file artifact manifest')
    parser.add_argument('--selected-hero-catalog', type=Path)
    parser.add_argument('--selected-hero-artifacts', type=Path)
    args = parser.parse_args()
    try:
        if args.health_contract or args.forward_owner_contract:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        need(bool(args.selected_hero_catalog) == bool(args.selected_hero_artifacts), 'selected_catalog_inputs')
        catalog = None
        if args.selected_hero_catalog:
            from hero_asset_labels import HeroAssetCatalog
            catalog = HeroAssetCatalog(bounded_local_bytes(args.selected_hero_catalog, 65536, 'selected_catalog_size'),
                                      load_local_artifacts(args.selected_hero_artifacts, 'selected_hero'))
        adapter = LiveRelations(args.acquisition, args.session_id, args.segment, health_contracts=args.health_contract,
            cached_label_recipe_sha256=args.cached_label_recipe_sha256, hero_catalog=args.hero_catalog,
            hero_artifacts=args.hero_artifacts, hero_locale=args.hero_locale, recipe_path=args.recipe,
            live_category_contract=args.live_category_contract, live_category_artifacts=args.live_category_artifacts,
            raw_category_contract=args.raw_category_contract, context_controller_contract=args.context_controller_contract,
            context_group_contract=args.context_group_contract, context_projection_admission=args.context_projection_admission,
            context_projection_artifacts=args.context_projection_artifacts,
            hero_asset_catalog=args.hero_asset_catalog, hero_asset_artifacts=args.hero_asset_artifacts,
            hero_asset_locale=args.hero_asset_locale, forward_owner_contract=args.forward_owner_contract,
            forward_owner_artifacts=args.forward_owner_artifacts,
            forward_owner_health_contracts=args.forward_owner_health_contract,
            forward_owner_category_contract=args.forward_owner_category_contract,
            forward_owner_category_artifacts=args.forward_owner_category_artifacts,
            ammunition_contract=args.ammunition_contract, ammunition_artifacts=args.ammunition_artifacts,
            ammunition_admission=args.ammunition_admission,
            health_ratio_contracts=args.health_ratio_contract, health_ratio_native_review=args.health_ratio_native_review,
            selected_only=args.selected_only, selected_contract=args.selected_contract,
            selected_artifacts=load_local_artifacts(args.selected_artifacts, 'selected') if args.selected_artifacts else None,
            selected_hero_catalog=catalog)
        if args.selected_only:
            # The CLI binds one explicitly supplied acquisition. The coordinator
            # rejects a later epoch rather than reusing this contract/profile.
            from live_sessions import LiveSession, stream as session_stream
            coordinator = LiveSession(lambda session, acquisition, segment: adapter)
            report = session_stream(coordinator, sys.stdin.buffer, sys.stdout.buffer)
        else:
            report = stream(adapter, sys.stdin.buffer, sys.stdout.buffer)
        print(json.dumps(report), file=sys.stderr)
        return 0
    except (ValueError, KeyError, TypeError, AttributeError, OSError, ImportError) as error:
        reason = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(json.dumps(dict(schema='overwatch-decoder.entity-relations-live-result/1', error=reason,
                             durability_verified=False, public_state_eligible=False)), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
