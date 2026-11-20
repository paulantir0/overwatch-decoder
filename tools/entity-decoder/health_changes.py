"""Bounded net changes between accepted, consecutive reciprocal-body samples.

This consumes already validated semantic projections; it does not re-read memory
or verify native guards. Evidence remains in the two pinned original samples.
"""
import copy
import json
import math
import re

MAX_ACTORS = 128
MAX_POOLS = 128


def need(ok, reason):
    if not ok:
        raise ValueError('health_change_' + reason)


def integer(x):
    return type(x) is int


def finite(x):
    return type(x) in (int, float) and math.isfinite(x)


def digest(x):
    need(isinstance(x, str) and re.fullmatch('[0-9a-f]{64}', x), 'digest')
    return x


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def unknown(reason):
    return dict(status='unknown', value=None, reason=reason, previous_sample=None,
                current_sample=None, atomic=False, interpretation='observed_net_pool_sum_change',
                attribution=None, continuity_across_gaps=False)


def sample(row, *, target, timing, artifacts, epoch, source_sha256, evidence_ref, gap=False, evidence_container_sha256=None):
    """Normalize health from an accepted actor row, retaining bounded evidence.

    ``epoch`` is the validated source session/segment or the aggregate config
    identity that pins its upstream source admission. It must change on rollover.
    """
    ck = row.get('controller_object_key')
    need(ck is None or isinstance(ck, str) and re.fullmatch('controller:[0-9a-f]{64}', ck), 'controller')
    if gap or row.get('relation_status') != 'observed' or row.get('health_candidate') is None:
        return dict(controller_object_key=ck, sample=None)
    bk = row.get('body_object_key'); h = row['health_candidate']
    need(isinstance(bk, str) and re.fullmatch('body:[0-9a-f]{64}', bk), 'body')
    profile = digest(artifacts.get('profile_sha256')); acquisition = artifacts.get('acquisition', {})
    pins = {k:digest(acquisition.get(k)) for k in ('manifest_sha256','recipe_sha256','evidence_sha256')}
    digest(source_sha256); digest(evidence_container_sha256 or source_sha256); digest(artifacts.get('live_event_sha256')); digest(target.get('executable_sha256'))
    need(h.get('schema') == 'overwatch-decoder.actor-pool-sum/1' and h.get('status') == 'candidate'
         and h.get('body_object_key') == bk and h.get('profile_sha256') == profile
         and h.get('build_sha256') == target['executable_sha256']
         and h.get('acquisition_evidence_sha256') == pins['evidence_sha256']
         and h.get('complete_supplied_membership_guarding') is True, 'health_binding')
    need(all(integer(timing.get(k)) for k in ('sequence','start_ticks','end_ticks','monotonic_frequency','monotonic_origin_ticks'))
         and timing['sequence'] >= 0 and 0 <= timing['start_ticks'] <= timing['end_ticks']
         and timing['monotonic_frequency'] > 0 and isinstance(timing.get('utc_origin'), str), 'timing')
    values = h.get('contributions')
    need(isinstance(values, list) and 0 < len(values) <= MAX_POOLS, 'pool_count')
    reads = []
    for v in values:
        need(isinstance(v, dict) and integer(v.get('pool_index')) and v['pool_index'] >= 0
             and isinstance(v.get('field'), str) and 0 < len(v['field']) <= 256
             and finite(v.get('value')) and v['value'] >= 0
             and integer(v.get('read_start_ticks')) and integer(v.get('read_end_ticks'))
             and timing['start_ticks'] <= v['read_start_ticks'] <= v['read_end_ticks'] <= timing['end_ticks'], 'scalar')
        reads.append({k:v[k] for k in ('pool_index','field','value','read_start_ticks','read_end_ticks')})
    need(len({v['pool_index'] for v in reads}) == len(reads) and len({v['field'] for v in reads}) == len(reads), 'duplicate_pool')
    need(finite(h.get('raw_sum')) and h['raw_sum'] == sum(v['value'] for v in reads), 'sum')
    start, end = min(v['read_start_ticks'] for v in reads), max(v['read_end_ticks'] for v in reads)
    need((h.get('read_start_ticks'), h.get('read_end_ticks')) == (start, end), 'read_span')
    contract = h.get('membership_contract_sha256')
    if contract is not None: digest(contract)
    need(isinstance(epoch, dict) and 0 < len(canonical(epoch)) <= 4096, 'epoch')
    need(isinstance(evidence_ref, str) and evidence_ref.startswith('/') and len(evidence_ref) <= 1024, 'evidence_ref')
    target = {k:target[k] for k in ('pid','creation_file_time','executable_sha256','architecture','image_name')}
    need(integer(target['pid']) and target['pid'] > 0 and integer(target['creation_file_time'])
         and target['creation_file_time'] > 0 and target['architecture'] == 'x64'
         and isinstance(target['image_name'], str) and 0 < len(target['image_name']) <= 256, 'target')
    timing = {k:timing[k] for k in ('sequence','start_ticks','end_ticks','monotonic_frequency','monotonic_origin_ticks','utc_origin')}
    need(len(timing['utc_origin']) <= 128, 'clock')
    scope = dict(target=target, profile_sha256=profile, acquisition=pins, epoch=epoch,
                 clock={k:timing[k] for k in ('monotonic_frequency','monotonic_origin_ticks','utc_origin')},
                 membership_contract_sha256=contract,
                 scalar_layout=[(v['pool_index'],v['field']) for v in reads])
    s = dict(controller_object_key=ck, body_object_key=bk, raw_sum=h['raw_sum'],
             timing=timing, read_start_ticks=start, read_end_ticks=end, scalar_reads=reads,
             semantic_projection_sha256=source_sha256, native_event_sha256=artifacts['live_event_sha256'],
             evidence_ref=evidence_ref, evidence_container_sha256=evidence_container_sha256 or source_sha256,
             evidence_hash_scope='exact_jsonl_line_including_lf', scope=scope)
    return dict(controller_object_key=ck, sample=json.loads(canonical(s)))


class HealthChanges:
    """At most one previous accepted sample per controller; no historical fill."""
    def __init__(self):
        self.previous = {}
        self.failed = False

    def clear(self):
        self.previous.clear()

    def project(self, samples):
        need(not self.failed, 'failed')
        try:
            need(isinstance(samples, list) and len(samples) <= MAX_ACTORS, 'actor_bound')
            keys = [v['controller_object_key'] for v in samples if v['controller_object_key'] is not None]
            need(len(keys) == len(set(keys)), 'duplicate_controller')
            pending = {}; results = []
            for item in samples:
                ck, current = item['controller_object_key'], item['sample']
                if current is None:
                    results.append(unknown('health_unavailable_or_gap')); continue
                need(ck is not None and current['controller_object_key'] == ck, 'sample_controller')
                previous = self.previous.get(ck)
                reason = 'no_previous_observed_health'
                if previous is not None:
                    if previous['body_object_key'] != current['body_object_key']:
                        reason = 'body_changed'
                    elif previous['scope'] != current['scope']:
                        reason = 'source_epoch_or_membership_changed'
                    elif current['timing']['sequence'] != previous['timing']['sequence'] + 1:
                        reason = 'nonconsecutive_source_frames'
                    elif previous['timing']['end_ticks'] > current['timing']['start_ticks'] or previous['read_end_ticks'] > current['read_start_ticks']:
                        reason = 'overlapping_source_reads'
                    else:
                        delta = current['raw_sum'] - previous['raw_sum']
                        need(finite(delta), 'nonfinite_delta')
                        result = unknown(None)
                        result.update(status='candidate', value=delta,
                                      previous_sample=copy.deepcopy(previous), current_sample=copy.deepcopy(current))
                        results.append(result); pending[ck] = copy.deepcopy(current); continue
                results.append(unknown(reason)); pending[ck] = copy.deepcopy(current)
            # Missing and unknown actors disappear from the baseline, including
            # those not present in the current batch. Commit only after success.
            self.previous = pending
            return results
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            self.failed = True
            self.clear()
            raise
