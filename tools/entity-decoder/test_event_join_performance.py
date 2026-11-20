"""Synthetic deterministic workload; --benchmark measures CPU without a native target."""
import argparse
import hashlib
import json
import platform
import time
import unittest

from event_join_stream import EventJoinStream


def workload(frames, interleaved=False, keys=32):
    scope = dict(target=dict(pid=1, creation_file_time=2, executable_sha256='a'*64,
        image_name='fixture', architecture='x64'), world_epoch='w', clock_id='qpc', frequency=1000)
    sources = ['s%d' % i for i in range(7)]
    stream = EventJoinStream(scope=scope, sources=sources, maximum_age_ticks=100)
    digest = hashlib.sha256(); resolved = 0; emitted = 0

    def pair(tick, key):
        observation = dict(scope=scope, body_key_u32=key, observed_ticks=tick, valid_until_ticks=tick + 10,
            status='observed', body_lifetime='life', entity_id='e%d' % key, controller_id='c',
            hero='h', relation='r', provenance={'frame':str(tick)})
        proof = dict(scope=scope, body_key_u32=key, body_lifetime='life', entity_id='e%d' % key,
            controller_id='c', valid_from_ticks=0, valid_until_ticks=10**9, provenance={'proof':'p'})
        return observation, [proof]

    def consume(results):
        nonlocal resolved, emitted
        for result in results:
            emitted += 1; resolved += result['status'] == 'resolved'
            digest.update(json.dumps(result, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n')

    for frame in range(1, frames + 1):
        base = 7 * frame if interleaved else frame
        for i, source in enumerate(sources):
            tick = base + i if interleaved else base
            rows = {}
            if i == 0:
                rows['observations'] = [pair(tick, key) for key in range(keys)]
            elif i == 1:
                rows['events'] = [dict(event=dict(scope=scope, body_key_u32=key, qpc_ticks=tick,
                    provenance={'event':str(tick)}), payload={'n':tick}) for key in range(keys)]
            consume(stream.submit(source, tick, **rows))
    last = 7 * frames + 16 if interleaved else frames + 10
    for source in sources:
        consume(stream.finish(source, last))
    return dict(resolved=resolved, emitted=emitted, expected=frames * keys, sha256=digest.hexdigest(),
                pending_rows=len(stream._pending), owners=len(stream._owners))


class PerformanceWorkloadTests(unittest.TestCase):
    def test_bounded_synthetic_outputs_resolve_in_both_arrival_patterns(self):
        for staggered in (False, True):
            first = workload(3, staggered); second = workload(3, staggered)
            self.assertEqual(first, second)
            self.assertEqual((first['resolved'], first['emitted'], first['expected']), (96, 96, 96))
            self.assertEqual((first['pending_rows'], first['owners']), (0, 32))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--benchmark', action='store_true')
    parser.add_argument('--frames', type=int, default=900)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--interleaved', action='store_true')
    args = parser.parse_args()
    if args.benchmark:
        if not 1 <= args.frames <= 10000 or not 1 <= args.repeat <= 10:
            parser.error('bounded frames/repeat required')
        for repeat in range(args.repeat):
            wall = time.perf_counter(); cpu = time.process_time()
            result = workload(args.frames, args.interleaved)
            cpu = time.process_time() - cpu; wall = time.perf_counter() - wall
            if result['resolved'] != result['expected'] or result['emitted'] != result['expected']:
                raise RuntimeError('Synthetic output count mismatch')
            print(json.dumps(dict(result, repeat=repeat + 1, frames=args.frames, interleaved=args.interleaved,
                cpu_seconds=cpu, wall_seconds=wall, cpu_seconds_per_modeled_second_at_180fps=cpu * 180 / args.frames,
                python=platform.python_version(), machine=platform.machine())), flush=True)
    else:
        unittest.main(argv=[__file__])
