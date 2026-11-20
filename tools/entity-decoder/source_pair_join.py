"""Bounded join of independently admitted, neutral full-pair observations.

This module does no acquisition, direction classification, hit counting, or waiting.
Callers validate their original evidence first. Inputs are strict UTF-8 JSON bytes;
SHA256 references cover those exact bytes. Context and roster epochs are independent.
A resolved identity requires the latest left and first right roster endpoints plus
all intervening frames, within a whole <=100 ms bracket. Equal identities at these
observations do not establish continuous lifetime or exclude an unobserved ABA.

advance/finish require caller-observed clock ticks; advance explicitly abandons
pending contexts as unknown (e.g. a caller's bounded source-stall watchdog). History
and pending contexts share hard row/byte budgets. Overflow abandons pending work
and history explicitly, rather than silently substituting older endpoints. Evidence
objects are compact JSON references (<=4096 canonical UTF-8 bytes each), limiting
result amplification when many pending contexts share endpoints. Buffered byte
counts cover original JSON bytes; decoded Python objects have additional overhead.
"""
from collections import deque
import hashlib
import json
import math

from projection_copy import detached_copy

_ID = {'entity_id', 'controller_id', 'body_key_u32', 'controller_key_u32',
       'body_owner_id', 'controller_owner_id', 'body_handle_u32', 'controller_handle_u32'}
_BASE = {'schema', 'scope', 'session_id', 'segment', 'sequence', 'read_interval', 'gap_before', 'evidence'}
_MAX_RAW = 8 * 1024 * 1024


def _integer(v, low=0, high=2**63-1):
    return type(v) is int and low <= v <= high


def _finite(v):
    try:
        return type(v) in (int, float) and math.isfinite(v)
    except OverflowError:
        return False


def _text(v):
    return type(v) is str and 1 <= len(v) <= 256 and not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in v)


def _keys(v, keys):
    if type(v) is not dict or set(v) != keys:
        raise ValueError('pair_shape')


def _identity(v):
    _keys(v, _ID)
    if any(not _integer(v[k], 1, 2**32-1) if k.endswith('_u32') else not _text(v[k]) for k in _ID):
        raise ValueError('pair_identity')


def _interval(v):
    _keys(v, {'start_ticks', 'end_ticks'})
    if not _integer(v['start_ticks']) or not _integer(v['end_ticks'], v['start_ticks']):
        raise ValueError('pair_interval')


def _scope(v):
    _keys(v, {'target', 'world_id', 'clock_id', 'frequency', 'recipient'})
    t = v['target']
    _keys(t, {'pid', 'creation_file_time', 'executable_sha256', 'image_name', 'architecture'})
    h = t['executable_sha256']
    if (not _integer(t['pid'], 1) or not _integer(t['creation_file_time'], 1) or
            type(h) is not str or len(h) != 64 or any(c not in '0123456789abcdef' for c in h) or
            not all(_text(t[k]) for k in ('image_name', 'architecture')) or
            not all(_text(v[k]) for k in ('world_id', 'clock_id')) or
            not _integer(v['frequency'], 1, 10**12)):
        raise ValueError('pair_scope')
    _identity(v['recipient'])


def _json(v, depth=0):
    if depth > 32:
        raise ValueError('pair_json_depth')
    if type(v) is dict:
        if any(not _text(k) for k in v):
            raise ValueError('pair_json_key')
        for x in v.values():
            _json(x, depth+1)
    elif type(v) is list:
        for x in v:
            _json(x, depth+1)
    elif type(v) is str:
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise ValueError('pair_unicode')
    elif type(v) is float:
        if not math.isfinite(v):
            raise ValueError('pair_nonfinite')
    elif v is not None and type(v) not in (str, int, bool):
        raise ValueError('pair_json_value')


def _pairs(items):
    result = {}
    for k, v in items:
        if k in result:
            raise ValueError('pair_duplicate_key')
        result[k] = v
    return result


def _reject_constant(value):
    raise ValueError('pair_nonfinite')


def _evidence(v):
    if type(v) is not dict or len(json.dumps(v, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')) > 4096:
        raise ValueError('pair_evidence_size')


def _parse(raw, kind):
    if type(raw) is not bytes:
        raise ValueError('pair_input_bytes')
    if not raw or len(raw) > _MAX_RAW:
        raise ValueError('pair_input_size')
    try:
        v = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_reject_constant)
        _json(v)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('pair_json') from exc
    extra = {'observation_id', 'status', 'source_body_key_u32', 'source_controller_key_u32'} if kind == 'context' else {'actors'}
    _keys(v, _BASE | extra)
    if v['schema'] != 'overwatch-decoder.source-' + kind + '/1':
        raise ValueError('pair_schema')
    _scope(v['scope'])
    _interval(v['read_interval'])
    if (not _text(v['session_id']) or not _integer(v['segment'], 1) or
            not _integer(v['sequence']) or type(v['gap_before']) is not bool or type(v['evidence']) is not dict):
        raise ValueError('pair_envelope')
    _evidence(v['evidence'])
    if kind == 'context':
        if not _text(v['observation_id']) or v['status'] not in ('observed', 'unknown', 'inactive'):
            raise ValueError('pair_context')
        for k in ('source_body_key_u32', 'source_controller_key_u32'):
            if not _integer(v[k], 0, 2**32-1):
                raise ValueError('pair_source_key')
    else:
        if type(v['actors']) is not list or len(v['actors']) > 1024:
            raise ValueError('pair_actors')
        for actor in v['actors']:
            _keys(actor, {'identity', 'status', 'hero', 'relation', 'position'})
            _identity(actor['identity'])
            if actor['status'] not in ('observed', 'unknown'):
                raise ValueError('pair_actor_status')
            for name in ('hero', 'relation', 'position'):
                f = actor[name]
                _keys(f, {'status', 'value', 'read_interval', 'evidence'})
                _interval(f['read_interval'])
                if (f['read_interval']['start_ticks'] < v['read_interval']['start_ticks'] or
                        f['read_interval']['end_ticks'] > v['read_interval']['end_ticks'] or
                        type(f['evidence']) is not dict or f['status'] not in ('observed', 'unknown')):
                    raise ValueError('pair_field')
                _evidence(f['evidence'])
                if f['status'] == 'unknown':
                    if f['value'] is not None:
                        raise ValueError('pair_unknown_value')
                elif name == 'hero':
                    _keys(f['value'], {'resource_id', 'label'})
                    if not all(_text(x) for x in f['value'].values()):
                        raise ValueError('pair_hero')
                elif name == 'relation':
                    if not _text(f['value']):
                        raise ValueError('pair_relation')
                elif (type(f['value']) is not list or len(f['value']) != 3 or
                      any(not _finite(x) for x in f['value'])):
                    raise ValueError('pair_position')
    return dict(value=v, raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw),
                rows=1 if kind == 'context' else max(1, len(v['actors'])))


class SourcePairJoin:
    """Raw JSON contract: overwatch-decoder.source-context/1 and overwatch-decoder.source-roster/1.

    Both carry scope, session_id, segment, sequence, read_interval, gap_before,
    and compact evidence. Scope pins target, world_id, clock_id, frequency, and
    the recipient's full identity. Context adds observation_id, status, and both
    source_*_key_u32 values. Roster adds actors (identity/status/hero/relation/
    position); each field has status/value/read_interval/evidence. Exact required
    keys and value validation are enforced below, with no coercion or defaults.

    submit_context/observe_roster return detached neutral results, including
    exact-byte hashes and selected endpoints. Inputs require prior independent
    admission; these hashes identify bytes, not evidence authenticity. There is
    no background timer: callers must invoke advance/finish on observed clocks.
    """
    def __init__(self, *, maximum_pending_rows=1024, maximum_pending_bytes=8*1024*1024,
                 maximum_bracket_ms=100):
        if (not _integer(maximum_pending_rows, 1, 1024) or
                not _integer(maximum_pending_bytes, 1, 8*1024*1024) or
                not _integer(maximum_bracket_ms, 1, 100)):
            raise ValueError('pair_bounds')
        self.maximum_pending_rows = maximum_pending_rows
        self.maximum_pending_bytes = maximum_pending_bytes
        self.maximum_bracket_ms = maximum_bracket_ms
        self._history = deque()
        self._pending = []
        self._previous = {}
        self._closed = False
        self._last_control_tick = 0

    @property
    def buffered_rows(self):
        return sum(x['rows'] for x in [*self._history, *self._pending])

    @property
    def buffered_bytes(self):
        return sum(x['size'] for x in [*self._history, *self._pending])

    def submit_context(self, raw_jsonl):
        return self._accept(raw_jsonl, 'context')

    def observe_roster(self, raw_jsonl):
        return self._accept(raw_jsonl, 'roster')

    @staticmethod
    def _ref(item):
        v = item['value']
        return dict(raw_sha256=item['raw_sha256'], session_id=v['session_id'], segment=v['segment'],
                    sequence=v['sequence'], read_interval=detached_copy(v['read_interval']),
                    evidence=detached_copy(v['evidence']))

    def _unknown(self, item, reason):
        return dict(schema='overwatch-decoder.source-pair-join/1', status='unknown', reason=reason,
                    observation_id=item['value']['observation_id'], scope=detached_copy(item['value']['scope']),
                    context=self._ref(item), identity=None, endpoints=None)

    def _flush(self, reason):
        results = [self._unknown(x, reason) for x in self._pending]
        self._pending.clear()
        return results

    def _accept(self, raw, kind):
        if self._closed:
            raise ValueError('pair_closed')
        item = _parse(raw, kind)  # Validate everything before mutating any stream state.
        v = item['value']
        previous = self._previous.get(kind)
        epoch = (v['session_id'], v['segment'], v['scope'])
        changed = previous is not None and previous['epoch'] != epoch
        start = v['read_interval']['start_ticks']
        end = v['read_interval']['end_ticks']
        if previous is not None and not changed:
            if (v['sequence'] <= previous['sequence'] or start < previous['start'] or
                    kind == 'roster' and start < previous['end'] or
                    v['sequence'] != previous['sequence']+1 and not v['gap_before']):
                raise ValueError('pair_source_order')
        if start < self._last_control_tick:
            raise ValueError('pair_before_control_tick')
        results = []
        if changed or v['gap_before']:
            results += self._flush('source_epoch_changed' if changed else 'source_gap')
            if changed or kind == 'roster':
                self._history.clear()
        self._previous[kind] = dict(epoch=epoch, sequence=v['sequence'], start=start, end=end)
        if kind == 'context' and v['status'] != 'observed':
            # Clear unresolved earlier contexts, without inventing a roster gap.
            results += self._flush('context_' + v['status'])
            results.append(self._unknown(item, 'context_' + v['status']))
            return results
        self._prune()
        if (self.buffered_rows + item['rows'] > self.maximum_pending_rows or
                self.buffered_bytes + item['size'] > self.maximum_pending_bytes):
            results += self._flush('buffer_overflow')
            self._history.clear()
            if kind == 'context':
                results.append(self._unknown(item, 'buffer_overflow'))
                return results
            results.append(dict(schema='overwatch-decoder.source-pair-join/1', status='unknown', reason='buffer_overflow',
                                observation_id=None, roster=self._ref(item)))
        if item['rows'] > self.maximum_pending_rows or item['size'] > self.maximum_pending_bytes:
            return results
        (self._pending if kind == 'context' else self._history).append(item)
        pending = []
        for context in self._pending:
            result = self._join(context)
            if result is None:
                pending.append(context)
            else:
                results.append(result)
        self._pending = pending
        self._prune()
        return results

    def _prune(self):
        # Context starts never regress within an epoch. Keep the latest possible
        # left endpoint and every later frame needed by the oldest pending row.
        if 'context' not in self._previous or not self._history:
            return
        threshold = min((x['value']['read_interval']['start_ticks'] for x in self._pending),
                        default=self._previous['context']['start'])
        left = [i for i, x in enumerate(self._history)
                if x['value']['read_interval']['end_ticks'] <= threshold]
        if left:
            for _ in range(left[-1]):
                self._history.popleft()

    @staticmethod
    def _actor(frame, body, controller):
        # A duplicate or partial-key alias is not a unique full-pair observation.
        claims = [a for a in frame['value']['actors']
                  if a['identity']['body_key_u32'] == body or a['identity']['controller_key_u32'] == controller]
        if len(claims) != 1 or claims[0]['status'] != 'observed':
            return None
        a = claims[0]
        unique = ('entity_id', 'controller_id', 'body_owner_id', 'controller_owner_id',
                  'body_handle_u32', 'controller_handle_u32')
        if any(other is not a and any(other['identity'][k] == a['identity'][k] for k in unique)
               for other in frame['value']['actors']):
            return None
        return a if a['identity']['body_key_u32'] == body and a['identity']['controller_key_u32'] == controller else None

    def _join(self, item):
        c = item['value']
        body, controller = c['source_body_key_u32'], c['source_controller_key_u32']
        if not body or not controller:
            return self._unknown(item, 'source_pair_zero')
        frames = list(self._history)
        if not frames:
            return None
        if any(f['value']['scope'] != c['scope'] for f in frames):
            return self._unknown(item, 'scope_mismatch')
        left = [i for i, f in enumerate(frames) if f['value']['read_interval']['end_ticks'] <= c['read_interval']['start_ticks']]
        right = [i for i, f in enumerate(frames) if f['value']['read_interval']['start_ticks'] >= c['read_interval']['end_ticks']]
        if not left:
            if right:
                return self._unknown(item, 'missing_left_endpoint')
            return None
        if not right:
            # A future right endpoint cannot improve an already excessive bracket.
            elapsed = frames[-1]['value']['read_interval']['end_ticks'] - frames[left[-1]]['value']['read_interval']['start_ticks']
            if elapsed * 1000 > self.maximum_bracket_ms * c['scope']['frequency']:
                return self._unknown(item, 'bracket_too_old')
            return None
        lo, hi = left[-1], right[0]
        if hi <= lo:
            return self._unknown(item, 'endpoint_order')
        bracket = frames[hi]['value']['read_interval']['end_ticks'] - frames[lo]['value']['read_interval']['start_ticks']
        if bracket * 1000 > self.maximum_bracket_ms * c['scope']['frequency']:
            return self._unknown(item, 'bracket_too_old')
        actors = [self._actor(f, body, controller) for f in frames[lo:hi+1]]
        if any(a is None for a in actors):
            return self._unknown(item, 'pair_missing_unknown_or_aliased')
        if any(a['identity'] != actors[0]['identity'] for a in actors[1:]):
            return self._unknown(item, 'pair_identity_changed')
        # Labels qualify independently. Positions deliberately retain both values.
        fields = {}
        for name in ('hero', 'relation'):
            values = [a[name] for a in actors]
            good = all(f['status'] == 'observed' and f['value'] == values[0]['value'] for f in values)
            fields[name] = dict(status='observed' if good else 'unknown',
                                value=detached_copy(values[0]['value']) if good else None)
        endpoints = [dict(roster=self._ref(frames[i]), actor=detached_copy(a))
                     for i, a in ((lo, actors[0]), (hi, actors[-1]))]
        return dict(schema='overwatch-decoder.source-pair-join/1', status='resolved', reason=None,
                    observation_id=c['observation_id'], scope=detached_copy(c['scope']), context=self._ref(item),
                    identity=detached_copy(actors[0]['identity']), fields=fields, endpoints=endpoints,
                    bracket_ticks=bracket)

    def advance(self, tick, reason='source_stall'):
        """Abandon pending contexts using an actual externally observed clock tick."""
        if (self._closed or not _integer(tick) or not _text(reason) or tick < self._last_control_tick or
                any(tick < p['end'] for p in self._previous.values())):
            raise ValueError('pair_control')
        self._last_control_tick = tick
        results = self._flush(reason)
        self._history.clear()
        return results

    def finish(self, tick):
        results = self.advance(tick, 'source_finished')
        self._closed = True
        return results
