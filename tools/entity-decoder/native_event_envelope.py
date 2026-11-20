"""Strict, single-call native JSON ownership; no process or transport access.

Borrowed containers are read-only. Public snapshots are detached built-ins; an
expired envelope cannot be reused. No API accepts a caller-supplied decoded dict.
"""
from contextlib import contextmanager
import copy
import json

from export_relations import InvalidRecording, need

_ATOMIC = frozenset((type(None), bool, int, float, str))
_MISSING = object()


def _detach(value, memo):
    kind = type(value)
    if kind in _ATOMIC:
        return value
    identity = id(value)
    if identity in memo:
        return memo[identity]
    if isinstance(value, dict):
        result = {}; memo[identity] = result
        for key, item in value.items():
            result[key] = item if type(item) in _ATOMIC else _detach(item, memo)
        return result
    if isinstance(value, list):
        result = []; memo[identity] = result
        result.extend(item if type(item) in _ATOMIC else _detach(item, memo) for item in value)
        return result
    return copy.deepcopy(value, memo)


def _readonly(*args, **kwargs):
    raise TypeError('native_event_read_only')


class _ReadOnlyDict(dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _readonly

    def __deepcopy__(self, memo):
        return _detach(self, memo)


class _ReadOnlyList(list):
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = __iadd__ = __imul__ = _readonly

    def __deepcopy__(self, memo):
        return _detach(self, memo)


def _array(value):
    if type(value) is list:
        # Object hooks have already frozen dictionaries. Recurse only for
        # nested arrays; scalar entries need no Python function call.
        return _ReadOnlyList([_array(item) if type(item) is list else item for item in value])
    return value


def _unique(pairs):
    # JSON object keys are strings. The native dict constructor performs the
    # insertion loop without one Python call per property; a shorter result
    # proves a duplicate, including differently escaped copies of one key.
    result = _ReadOnlyDict(pairs)
    need(len(result) == len(pairs), 'duplicate_json_key')
    for key, value in pairs:
        if type(value) is list:
            dict.__setitem__(result, key, _array(value))
    return result


class NativeEventEnvelope:
    """Decode original bytes once; internal borrows require active ownership."""
    __slots__ = ('__raw', '__event', '__active', '__used')

    def __init__(self, raw):
        need(isinstance(raw, bytes) and 0 < len(raw) <= 512 * 1024 and raw.endswith(b'\n'), 'native_event_line_bound')
        self.__raw = raw
        self.__event = _array(json.loads(raw, object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(InvalidRecording('nonfinite_json'))))
        self.__active = self.__used = False

    @property
    def raw(self):
        return self.__raw

    def __copy__(self):
        raise TypeError('native_event_envelope_not_copyable')

    def __deepcopy__(self, memo):
        raise TypeError('native_event_envelope_not_copyable')

    @contextmanager
    def owned(self):
        need(not self.__used, 'native_event_already_used')
        self.__used = self.__active = True
        try:
            yield self
        finally:
            self.__active = False
            self.__event = _MISSING

    def _borrow(self, raw):
        need(self.__active and self.__event is not _MISSING, 'native_event_not_active')
        need(isinstance(raw, bytes) and raw == self.__raw, 'native_event_raw_mismatch')
        return self.__event

    def snapshot(self):
        """A caller may mutate this copy without changing any borrowed graph."""
        return _detach(self._borrow(self.__raw), {})


def borrowed_event(envelope, raw):
    need(type(envelope) is NativeEventEnvelope, 'native_event_envelope_required')
    return envelope._borrow(raw)
