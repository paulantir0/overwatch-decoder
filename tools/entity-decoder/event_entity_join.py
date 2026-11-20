"""Bounded private label joins over caller-validated evidence; no acquisition."""
from __future__ import annotations
from collections import OrderedDict
import copy
import re
from projection_copy import detached_copy


def _integer(x):
    return type(x) is int and 0 <= x < 2**64


def _scope(s):
    if not isinstance(s, dict) or set(s) != {'target', 'world_epoch', 'clock_id', 'frequency'}:
        raise ValueError('join_scope')
    t = s['target']
    if not isinstance(t, dict) or set(t) != {'pid', 'creation_file_time', 'executable_sha256', 'image_name', 'architecture'}:
        raise ValueError('join_target')
    if not all(_integer(t[k]) and t[k] > 0 for k in ('pid', 'creation_file_time')) or not isinstance(t['executable_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', t['executable_sha256']):
        raise ValueError('join_target')
    if t['architecture'] != 'x64' or not isinstance(t['image_name'], str) or not 1 <= len(t['image_name']) <= 128:
        raise ValueError('join_target')
    if not all(isinstance(s[k], str) and 1 <= len(s[k]) <= 128 for k in ('world_epoch', 'clock_id')) or not _integer(s['frequency']) or s['frequency'] == 0:
        raise ValueError('join_clock')
    return (tuple(sorted(t.items())), s['world_epoch'], s['clock_id'], s['frequency'])


def _provenance(p):
    if not isinstance(p, dict) or not p or len(p) > 16 or not all(isinstance(k, str) and isinstance(v, str) and 1 <= len(k) <= 64 and 1 <= len(v) <= 256 for k, v in p.items()):
        raise ValueError('join_provenance')


class EventEntityJoin:
    """Latest-only cache. Unknown and removal observations replace valid labels.

    Inputs must already have independent native/source validation. This utility
    checks their declared identity/time agreement; it does not establish it.
    """
    def __init__(self, *, maximum_keys=256, maximum_age_ticks):
        if type(maximum_keys) is not int or not 1 <= maximum_keys <= 4096 or not _integer(maximum_age_ticks):
            raise ValueError('join_bounds')
        self.maximum_keys = maximum_keys
        self.maximum_age_ticks = maximum_age_ticks
        self._rows = OrderedDict()
        self._clock = None
        self._watermark = None

    def observe(self, observation, proofs):
        """Admit one ordered observation; delayed input returns False."""
        return self._observe(observation, proofs)

    def observe_many(self, items):
        """Atomically admit up to256 distinct scope/key rows at one timestamp.

        Items are (observation, proofs) pairs. The shared timestamp must be
        strictly newer than the pre-batch watermark. Invalid or duplicate rows
        raise ValueError without changing cache, clock or watermark. A validated
        but delayed batch returns False, also without changing state.
        """
        if not isinstance(items, list) or not 1 <= len(items) <= 256:
            raise ValueError('join_batch_bound')
        seen = set(); tick = None
        for item in items:
            if not isinstance(item, (list, tuple)) or len(item) != 2 or not isinstance(item[0], dict):
                raise ValueError('join_batch_shape')
            o = item[0]
            if 'scope' not in o or 'body_key_u32' not in o or 'observed_ticks' not in o:
                raise ValueError('join_batch_shape')
            key = o['body_key_u32']; current = o['observed_ticks']
            if not _integer(key) or key >= 2**32 or not _integer(current):
                raise ValueError('join_batch_identity')
            identity = (_scope(o['scope']), key)
            if identity in seen:
                raise ValueError('join_batch_duplicate_key')
            seen.add(identity)
            if tick is None:
                tick = current
            if current != tick:
                raise ValueError('join_batch_timestamp')
        # Validate on a bounded private copy, including clock and proof checks.
        # Lower the trial watermark only for validation of delayed batches; no
        # such trial is ever published, so stale input cannot resurrect a key.
        trial = self._fork()
        delayed = self._watermark is not None and tick <= self._watermark
        if delayed:
            trial._watermark = None
            trial._rows.clear()
        for o, proofs in items:
            if not trial._observe(o, proofs, batch_tick=tick):
                raise ValueError('join_batch_order')
        if delayed:
            return False
        self._rows, self._clock, self._watermark = trial._rows, trial._clock, trial._watermark
        return True

    def _fork(self):
        """Private containers; cached rows/proofs are replaced, never mutated.

        Preserve this invariant when adding update paths: a rejected transaction
        may share old row values with the committed cache until replacement.
        """
        fork = copy.copy(self)
        fork._rows = self._rows.copy()
        return fork

    def _observe(self, observation, proofs, batch_tick=None):
        """Store one validated roster observation plus explicit body-key proofs.

        Proofs bind scope/key/lifetime to opaque body/controller IDs over an
        inclusive QPC interval. A roster observation alone cannot supply a key.
        Invalid/removed observations need no proofs and block previous labels.
        """
        required = {'scope', 'body_key_u32', 'observed_ticks', 'valid_until_ticks', 'status', 'provenance'}
        optional = {'body_lifetime', 'entity_id', 'controller_id', 'hero', 'relation'}
        if not isinstance(observation, dict) or not required <= set(observation) <= required | optional:
            raise ValueError('join_observation_shape')
        for k in optional:
            if k in observation and observation[k] is not None and (not isinstance(observation[k], str) or not 1 <= len(observation[k]) <= (128 if k in ('hero', 'relation') else 256)):
                raise ValueError('join_label_bound')
        o = dict(observation)
        scope = _scope(o['scope'])
        key = o['body_key_u32']
        if not _integer(key) or key >= 2**32 or not _integer(o['observed_ticks']) or not _integer(o['valid_until_ticks']) or o['valid_until_ticks'] < o['observed_ticks']:
            raise ValueError('join_observation')
        _provenance(o['provenance'])
        if o['status'] not in ('observed', 'unknown', 'removed', 'invalid'):
            raise ValueError('join_status')
        if not isinstance(proofs, list) or len(proofs) > 32:
            raise ValueError('join_proof_bound')
        valid = []
        for p in proofs:
            if not isinstance(p, dict) or set(p) != {'scope', 'body_key_u32', 'body_lifetime', 'entity_id', 'controller_id', 'valid_from_ticks', 'valid_until_ticks', 'provenance'} or not _integer(p['body_key_u32']) or p['body_key_u32'] >= 2**32:
                raise ValueError('join_proof_shape')
            _scope(p['scope']); _provenance(p['provenance'])
            if not _integer(p['valid_from_ticks']) or not _integer(p['valid_until_ticks']) or p['valid_from_ticks'] > p['valid_until_ticks']:
                raise ValueError('join_proof_time')
            if not all(isinstance(p[k], str) and 1 <= len(p[k]) <= 256 for k in ('body_lifetime', 'entity_id', 'controller_id')):
                raise ValueError('join_proof_identity')
            valid.append(detached_copy(p))
        cache_key = (scope, key)
        previous = self._rows.get(cache_key)
        clock = (o['scope']['clock_id'], o['scope']['frequency'])
        if self._clock is not None and clock != self._clock:
            raise ValueError('join_ingestion_clock_changed')
        # One ordered clock per instance: the constant-size watermark survives
        # key eviction. Equal-time updates are admitted only for retained keys;
        # otherwise a replay could recreate an evicted same-time tombstone.
        if self._watermark is not None and (o['observed_ticks'] < self._watermark or
                o['observed_ticks'] == self._watermark and previous is None and batch_tick != o['observed_ticks']):
            return False
        self._clock = clock
        self._watermark = o['observed_ticks']
        if previous and o['observed_ticks'] < previous[0]['observed_ticks']:
            return False  # Never let a delayed observation undo an invalidation.
        if previous and o['observed_ticks'] == previous[0]['observed_ticks'] and (o, valid) != previous:
            o['status'] = 'invalid'  # Conflicting same-time claims fail closed.
        # Coalesce overlapping intervals only for the same identity AND source
        # proof; never erase a different lifetime or provenance claim.
        if previous:
            for prior in previous[1]:
                if prior['valid_until_ticks'] < o['observed_ticks']:
                    continue
                for current in valid:
                    keys = ('scope', 'body_key_u32', 'body_lifetime', 'entity_id', 'controller_id', 'provenance')
                    if all(prior[k] == current[k] for k in keys) and prior['valid_from_ticks'] <= current['valid_until_ticks'] and current['valid_from_ticks'] <= prior['valid_until_ticks']:
                        current['valid_from_ticks'] = min(current['valid_from_ticks'], prior['valid_from_ticks'])
                        current['valid_until_ticks'] = max(current['valid_until_ticks'], prior['valid_until_ticks'])
                        break
                else:
                    valid.append(detached_copy(prior))
        blocked = previous[0].get('_blocked_until_ticks', -1) if previous else -1
        if len(valid) > 32:
            blocked = max(blocked, max(p['valid_until_ticks'] for p in valid))
        if blocked >= o['observed_ticks']:
            o = dict(o, status='invalid', _blocked_until_ticks=blocked); valid = []
        self._rows[cache_key] = (detached_copy(o), valid)  # Proofs already hold private copies.
        self._rows.move_to_end(cache_key)
        while len(self._rows) > self.maximum_keys:
            self._rows.popitem(last=False)
        return True

    def join(self, event):
        """Return timestamped labels or None; never return health/current state."""
        if not isinstance(event, dict) or set(event) != {'scope', 'body_key_u32', 'qpc_ticks', 'provenance'}:
            raise ValueError('join_event_shape')
        scope = _scope(event['scope']); _provenance(event['provenance'])
        key, tick = event['body_key_u32'], event['qpc_ticks']
        if not _integer(key) or key >= 2**32 or not _integer(tick):
            raise ValueError('join_event')
        row = self._rows.get((scope, key))
        if row is None:
            return None
        o, proofs = row
        age = tick - o['observed_ticks']
        if o['status'] != 'observed' or not 0 <= age <= self.maximum_age_ticks or tick > o['valid_until_ticks']:
            return None
        candidates = [p for p in proofs if p['scope'] == event['scope'] and p['body_key_u32'] == key and p['valid_from_ticks'] <= o['observed_ticks'] <= tick <= p['valid_until_ticks']]
        identities = {(p['body_lifetime'], p['entity_id'], p['controller_id']) for p in candidates}
        if len(identities) != 1:
            return None
        lifetime, entity, controller = next(iter(identities))
        if (o.get('body_lifetime'), o.get('entity_id'), o.get('controller_id')) != (lifetime, entity, controller):
            return None
        if not all(isinstance(o.get(k), str) and 1 <= len(o[k]) <= 128 and o[k] != 'unknown' for k in ('hero', 'relation')):
            return None
        return copy.deepcopy(dict(schema='overwatch-decoder.private.event-entity-label/1', scope=event['scope'], body_key_u32=key,
            body_lifetime=lifetime, entity_id=entity, controller_id=controller, hero=o['hero'], relation=o['relation'],
            event_ticks=tick, observation_ticks=o['observed_ticks'], age_ticks=age, age_seconds=age/event['scope']['frequency'],
            event_provenance=event['provenance'], observation_provenance=o['provenance'], proof_provenance=[p['provenance'] for p in candidates],
            atomic=False, visibility='unknown', public_state_eligible=False, interpretation='caller_validated_exact_key_temporal_label'))
