"""Bounded synchronous watermark ordering of caller-validated join evidence."""
from collections import OrderedDict
import copy
import json
from projection_copy import detached_copy

from event_entity_join import EventEntityJoin, _scope, _integer


def _json(value, depth=0):
    if depth > 32:
        raise ValueError('stream_json_depth')
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError('stream_json_key')
        for v in value.values():
            _json(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _json(v, depth + 1)
    elif value is not None and type(value) not in (str, int, float, bool):
        raise ValueError('stream_json_value')


class EventJoinStream:
    """No I/O or waiting. Inputs require independent source/guard validation.

    Source ticks strictly increase. All rows at a shared timestamp are submitted
    together per source. A stalled source requires an externally bounded abort.
    """
    def __init__(self, *, scope, sources, maximum_age_ticks, maximum_keys=256,
                 maximum_pending_rows=1024, maximum_pending_bytes=8*1024*1024):
        _scope(scope)
        if (not isinstance(sources, list) or not 1 <= len(sources) <= 16 or
                any(not isinstance(s, str) or not 1 <= len(s) <= 128 for s in sources) or
                len(set(sources)) != len(sources)):
            raise ValueError('stream_sources')
        for v, upper in ((maximum_keys, 256), (maximum_pending_rows, 4096),
                         (maximum_pending_bytes, 64*1024*1024)):
            if type(v) is not int or not 1 <= v <= upper:
                raise ValueError('stream_bounds')
        self._scope = copy.deepcopy(scope)
        self._join = EventEntityJoin(maximum_keys=maximum_keys, maximum_age_ticks=maximum_age_ticks)
        self._progress = dict.fromkeys(sources)
        self._finished = set()
        self._pending = []
        self._owners = OrderedDict()
        self._closed = False
        self.maximum_pending_rows = maximum_pending_rows
        self.maximum_pending_bytes = maximum_pending_bytes

    @property
    def watermark(self):
        active = [t for s, t in self._progress.items() if s not in self._finished]
        if any(t is None for t in active):
            return None
        return min(active) if active else max(self._progress.values())

    def submit(self, source, tick, *, observations=None, events=None):
        return self._accept(source, tick, [] if observations is None else observations, [] if events is None else events, None, False)

    def invalidate(self, source, tick, reason):
        """Invalidate current source-owned labels without closing the source."""
        return self._accept(source, tick, [], [], self._reason(reason), False)

    def finish(self, source, tick):
        return self._accept(source, tick, [], [], 'source_finished', True)

    @staticmethod
    def _reason(reason):
        if not isinstance(reason, str) or not 1 <= len(reason) <= 256:
            raise ValueError('stream_reason')
        return reason

    def _accept(self, source, tick, observations, events, invalidation, finish):
        if self._closed or source not in self._progress or source in self._finished:
            raise ValueError('stream_source_closed')
        previous = self._progress[source]
        if not _integer(tick) or previous is not None and tick <= previous:
            raise ValueError('stream_source_order')
        if not isinstance(observations, list) or not isinstance(events, list):
            raise ValueError('stream_batch_shape')
        if len(observations) + len(events) > self.maximum_pending_rows:
            raise ValueError('stream_pending_limit')
        # Validate before changing progress or releasing any buffered events.
        probe = EventEntityJoin(maximum_age_ticks=self._join.maximum_age_ticks)
        for item in observations:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError('stream_observation')
            o, proofs = item
            probe = EventEntityJoin(maximum_age_ticks=self._join.maximum_age_ticks)
            probe.observe(o, proofs)
            if o['scope'] != self._scope or o['observed_ticks'] != tick or any(p['scope'] != self._scope for p in proofs):
                raise ValueError('stream_scope_or_tick')
        for wrapper in events:
            if not isinstance(wrapper, dict) or set(wrapper) != {'event', 'payload'}:
                raise ValueError('stream_event_wrapper')
            e = wrapper['event']
            probe.join(e)
            if e['scope'] != self._scope or e['qpc_ticks'] != tick:
                raise ValueError('stream_scope_or_tick')
        # Tuples are accepted only as observation pairs, never opaque payloads.
        batch = dict(source=source, tick=tick, observations=[list(x) for x in observations],
                     events=events, invalidation=invalidation)
        _json(batch)
        try:
            size = len(json.dumps(batch, allow_nan=False, separators=(',', ':')).encode())
        except (ValueError, OverflowError) as exc:
            raise ValueError('stream_json_value') from exc
        rows = max(1, len(observations) + len(events))
        pending = self._pending + [(detached_copy(batch), size, rows)]
        if sum(p[1] for p in pending) > self.maximum_pending_bytes or sum(p[2] for p in pending) > self.maximum_pending_rows:
            raise ValueError('stream_pending_limit')
        progress = dict(self._progress, **{source: tick})
        finished = self._finished | ({source} if finish else set())
        active = [t for s, t in progress.items() if s not in finished]
        mark = None if any(t is None for t in active) else min(active) if active else max(progress.values())
        # Transactional bounded cache copy: malformed/oversized timestamp groups
        # cannot partially advance cache, ownership, progress, or output. Cached
        # rows and owner sets are replaced, never mutated, so container copies suffice.
        join, owners = self._join._fork(), self._owners.copy()
        ready = [p for p in pending if mark is not None and p[0]['tick'] <= mark]
        results = []
        for current in sorted({p[0]['tick'] for p in ready}):
            group = sorted([p[0] for p in ready if p[0]['tick'] == current], key=lambda b: b['source'])
            updates = {}
            invalid_sources = {b['source'] for b in group if b['invalidation'] is not None}
            invalid_keys = {key for key, claims in owners.items() if claims & invalid_sources}
            for b in group:
                for o, proofs in b['observations']:
                    key = o['body_key_u32']
                    if key in updates:
                        prior, prior_proofs, claims = updates[key]
                        if (prior, prior_proofs) != (o, proofs):
                            invalid_keys.add(key)
                        claims.add(b['source'])
                    else:
                        updates[key] = (o, proofs, {b['source']})
            for key in invalid_keys:
                claims = updates[key][2] if key in updates else owners[key]
                updates[key] = (dict(scope=self._scope, body_key_u32=key, observed_ticks=current,
                    valid_until_ticks=current, status='invalid', provenance={'stream': 'source_invalidation_or_conflict'}), [], claims)
            if len(updates) > 256:
                raise ValueError('stream_timestamp_group_limit')
            if updates:
                ordered = sorted(updates.items())
                if not join.observe_many([(o, proofs) for _, (o, proofs, _) in ordered]):
                    raise ValueError('stream_internal_order')
                for key, (_, _, claims) in ordered:
                    owners[key] = set(claims)
                    owners.move_to_end(key)
                while len(owners) > join.maximum_keys:
                    owners.popitem(last=False)
            for b in group:
                for index, wrapper in enumerate(b['events']):
                    label = join.join(wrapper['event'])
                    results.append(self._result(b, index, wrapper, label, None if label else 'no_valid_label'))
        self._join, self._owners = join, owners
        self._progress, self._finished = progress, finished
        self._pending = [p for p in pending if mark is None or p[0]['tick'] > mark]
        return results

    @staticmethod
    def _result(batch, index, wrapper, label, reason):
        result = copy.deepcopy(dict(schema='overwatch-decoder.event-join-stream-result/1', source=batch['source'],
            tick=batch['tick'], event_index=index, event=wrapper['event'], payload=wrapper['payload'],
            status='resolved' if label is not None else 'unresolved', label=None, reason=reason))
        result['label'] = label  # join() already returned a private deep copy.
        return result

    def abort(self, reason):
        reason = self._reason(reason)
        if self._closed:
            raise ValueError('stream_closed')
        results = []
        for b, _, _ in sorted(self._pending, key=lambda p: (p[0]['tick'], p[0]['source'])):
            for index, wrapper in enumerate(b['events']):
                results.append(self._result(b, index, wrapper, None, 'aborted:' + reason))
        self._pending.clear()
        self._owners.clear()
        self._join = EventEntityJoin(maximum_keys=self._join.maximum_keys, maximum_age_ticks=self._join.maximum_age_ticks)
        self._closed = True
        return results
