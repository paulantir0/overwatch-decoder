"""Compose finite raw categories and a neutral controller from verified recordings.

No live transport admission or group/relative-allegiance semantics are created.
The exporter verifies the native recording and acquisition before composition.
"""
import copy

from context_controller import GuardedContextController
from raw_categories import GuardedRawCategories
from context_projection_validation import validate_context_frame
from live_categories import live_frame_sha256


class FiniteContextProjection:
    def __init__(self, profile, category_contract, context_contract, artifacts):
        self.categories = GuardedRawCategories(profile, category_contract, artifacts)
        self.context = GuardedContextController(profile, context_contract, artifacts)
        self.contracts = dict(raw_category_contract_sha256=self.categories.contract_sha256,
                              context_controller_contract_sha256=self.context.contract_sha256,
                              context_group_contract_sha256=None)

    def source_pins(self, source):
        expected = dict(recipe_sha256=source['acquisition']['recipe_sha256'],
                        evidence_sha256=source['acquisition']['evidence_sha256'])
        for projector in (self.categories, self.context):
            if (projector.source != expected or
                    projector.acquisition_manifest_sha256 != source['acquisition']['manifest_sha256'] or
                    projector.relations.hash != source['profile_sha256']):
                raise ValueError('finite_context_acquisition_mismatch')
        return dict(schema='overwatch-decoder.finite-context-source/1', contract_sha256=self.contracts.copy(),
                    category_native_review_sha256=self.categories.native_review_sha256,
                    context_native_review_sha256=self.context.native_review_sha256,
                    two_group_review_sha256=None, context_scope_review_sha256=None, frame_scope=None,
                    source_artifacts=copy.deepcopy(source))

    def compose(self, result, frame):
        source, recording = result['source_artifacts'], result['recording']
        pins = self.source_pins(source)
        skipped = bool(result['gap_before']['skipped_slots'])
        raw = self.categories.project(frame, gap=skipped)
        context = self.context.project(frame, gap=skipped)
        admission = dict(schema='overwatch-decoder.finite-context-frame-admission/1',
                         source_artifacts=copy.deepcopy(source), recording=copy.deepcopy(recording),
                         native_frame_sha256=live_frame_sha256(frame),
                         source_acquisition=copy.deepcopy(source['acquisition']),
                         profile_sha256=result['profile_sha256'],
                         timing={k: frame[k] for k in ('sequence','start_ticks','end_ticks','monotonic_frequency')})
        projection = dict(schema='overwatch-decoder.finite-context-group-projection/1',
                          profile_sha256=result['profile_sha256'], target=copy.deepcopy(result['target']),
                          timing=copy.deepcopy(result['timing']), admission=admission,
                          contract_sha256=self.contracts.copy(), raw_category_projection=raw,
                          context_projection=context, group_projection=None, frame_scope=None,
                          recording_state='native_verified_prefix', durability_verified=False,
                          privacy='private', public_state_eligible=False, visibility='unknown', atomic=False,
                          previous_values_carried=False)
        result.update(context_group_projection=projection, raw_context_output_enabled=True,
                      context_group_output_enabled=False)
        anchors = [r for r in raw['rows'] if context['status']=='observed' and context['body_status']=='observed'
                   and r['controller_object_key']==context['controller_object_key']
                   and r['body_object_key']==context['body_object_key'] and r['status']=='observed']
        context_category = anchors[0]['raw_category_candidate'] if len(anchors)==1 else None
        for row in result['relations']:
            row.update(raw_category_candidate=None, team_candidate=None, relative_allegiance_candidate=None,
                       category_evidence=None, context_group_candidate=None, context_group_evidence=None,
                       context_group_reason='gap_before_frame' if skipped else 'relation_unknown')
            if skipped or row['relation_status']!='observed':
                continue
            found = [r for r in raw['rows'] if r['controller_object_key']==row['controller_object_key']
                     and r['body_object_key']==row['body_object_key']]
            if len(found)!=1 or found[0]['raw_status']!='observed':
                row['context_group_reason'] = (found[0]['reason'] if len(found)==1 else
                    'missing_or_ambiguous_category_for_exact_object_keys') or 'raw_category_unknown'
                continue
            category = found[0]
            row['context_group_candidate'] = dict(raw_flags=copy.deepcopy(category['raw_flags_candidate']),
                raw_category=category['raw_category_candidate'], raw_status=category['raw_status'],
                category_status=category['status'], context_raw_category=context_category,
                category_matches_context=category['raw_category_candidate']==context_category
                    if category['status']=='observed' and context_category is not None else None,
                global_group=None, relation_to_context=None, group_status='unknown')
            row['context_group_reason'] = category['reason'] or 'context_group_not_configured'
            row['context_group_evidence'] = dict(actor_fields=copy.deepcopy(category['evidence']),
                context_reference={**{k:context[k] for k in ('controller_object_key','body_object_key','status','reason','body_status','body_reason')},
                    'projection':'context_group_projection.context_projection',
                    'raw_category_projection':'context_group_projection.raw_category_projection','group_context_evidence':None},
                source_acquisition=copy.deepcopy(source['acquisition']), profile_sha256=result['profile_sha256'],
                build_sha256=result['target']['executable_sha256'], contract_sha256=self.contracts.copy(),
                category_native_review_sha256=self.categories.native_review_sha256,
                context_native_review_sha256=self.context.native_review_sha256,
                two_group_review_sha256=None, context_scope_review_sha256=None, frame_scope=None,
                admission=copy.deepcopy(admission), public_state_eligible=False, visibility='unknown',
                atomic=False, durability_verified=False)
        validate_context_frame(result, dict(profile_sha256=result['profile_sha256'],
            acquisition=source['acquisition'], context_projection=pins), target=result['target'])
