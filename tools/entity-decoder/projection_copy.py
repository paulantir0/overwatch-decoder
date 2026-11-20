"""Detach JSON projection trees without generic deepcopy's scalar dispatch.

Only exact built-in containers and immutable scalar types take the fast path.
Memoization preserves aliases/cycles; custom objects retain deepcopy behavior.
Pinned runtime/composer bundles importing consumers must include this module.
"""
import copy

_ATOMIC = frozenset((type(None), bool, int, float, str, bytes, complex))


def detached_copy(value, memo=None):
    kind = type(value)
    if kind in _ATOMIC:
        return value
    if memo is None:
        memo = {}
    identity = id(value)
    if identity in memo:
        return memo[identity]
    if kind is list:
        result = []
        memo[identity] = result
        result.extend(item if type(item) in _ATOMIC else detached_copy(item, memo) for item in value)
        return result
    if kind is dict:
        result = {}
        memo[identity] = result
        for key, item in value.items():
            result[key if type(key) in _ATOMIC else detached_copy(key, memo)] = (
                item if type(item) in _ATOMIC else detached_copy(item, memo))
        return result
    return copy.deepcopy(value, memo)
