"""Independent finite synthetic producer for the recorder's portable integration tests.

No target reads, input or external packages. Emits original bytes, their receipts
and chained seals directly, without importing the production storage writer.
"""
import argparse
import hashlib
import json
import pathlib
import sys
import time


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


p = argparse.ArgumentParser()
p.add_argument('--pid', type=int, required=True)
p.add_argument('--seconds', type=int, required=True)
scope = p.add_mutually_exclusive_group(required=True)
scope.add_argument('--practice-range', action='store_true')
scope.add_argument('--read-only-user-gameplay', action='store_true')
p.add_argument('--output', required=True)
p.add_argument('--storage-cohort-bytes', type=int, required=True)
p.add_argument('--maximum-total-bytes', type=int, required=True)
p.add_argument('--fixture-mode', required=True)
a = p.parse_args()
assert 20 <= a.seconds <= 1800 and a.pid > 0
assert 1048576 <= a.storage_cohort_bytes <= 256 * 1048576
assert 128 * 1048576 <= a.maximum_total_bytes <= 64 * 1024 * 1048576
out = pathlib.Path(a.output)
out.mkdir()
all_data = bytearray()
receipt_bytes = rows = 0
previous = None
index = bytearray()
empty = a.fixture_mode == 'empty'
counts = [0] if empty else [1, 1100, 1100, 1100]
for ordinal, count in enumerate(counts, 1):
    folder = out / f'cohort-{ordinal:06d}'
    folder.mkdir()
    data_path, receipt_path = folder / 'game-state.jsonl', folder / 'delivery-receipts.jsonl'
    data_path.touch()
    receipt_path.touch()
    identity = dict(schema='overwatch-decoder.private.combined-storage/1', ordinal=ordinal,
                    directory=folder.name, previous_seal_sha256=previous)
    opening = encoded(dict(identity, kind='open'))
    with (out / 'storage-index.jsonl').open('ab') as stream:
        stream.write(opening)
        stream.flush()
    index.extend(opening)
    data, receipts = bytearray(), bytearray()
    first = rows if count else None
    for number in range(count):
        line = encoded(dict(schema='overwatch-decoder.private.selected-compact/1',
                            combined_sequence=rows, fixture_private_value='synthetic'))
        receipt = encoded(dict(combined_sequence=rows, line_sha256=sha(line)))
        with data_path.open('ab') as stream:
            stream.write(line)
            stream.flush()
        with receipt_path.open('ab') as stream:
            stream.write(receipt)
            stream.flush()
        data.extend(line)
        receipts.extend(receipt)
        all_data.extend(line)
        rows += 1
        receipt_bytes += len(receipt)
        if ordinal == 1 and number == 0:
            deadline = time.monotonic() + 10
            while not (out / 'receipt-seen').exists():
                if time.monotonic() > deadline:
                    raise RuntimeError('fixture receipt handshake timed out')
                time.sleep(.01)
            if a.fixture_mode == 'cancel':
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    time.sleep(.01)
                raise RuntimeError('fixture cancellation was not applied')
    if a.fixture_mode == 'missing-seal' and ordinal == len(counts):
        break
    files = [dict(path=path.name, bytes=len(raw), rows=count, sha256=sha(raw))
             for path, raw in [(data_path, data), (receipt_path, receipts)]]
    if a.fixture_mode == 'corrupt-seal' and ordinal == len(counts):
        files[0]['sha256'] = '0' * 64
    seal = encoded(dict(identity, kind='seal', files=files,
                        first_combined_sequence=first, last_combined_sequence=rows-1 if count else None))
    with (out / 'storage-index.jsonl').open('ab') as stream:
        stream.write(seal)
        stream.flush()
    index.extend(seal)
    previous = sha(seal)
if a.fixture_mode == 'directory-bound':
    with (out / 'other-evidence.bin').open('wb') as stream:
        stream.truncate(a.maximum_total_bytes)
code = 7 if a.fixture_mode == 'partial' else 3 if a.fixture_mode == 'exit-code' else 0
result = dict(schema='overwatch-decoder.private.combined-run/2', cli_exit_code=code,
              status='partial' if code == 7 else 'complete', error=None, cleanup_errors=[],
              capture_scope='controlled_practice' if a.practice_range else 'read_only_user_gameplay',
              output_rows=rows, output_bytes=len(all_data), output_sha256=sha(all_data),
              delivery_receipt_bytes=receipt_bytes, storage_index_bytes=len(index),
              storage_index_records=2*len(counts), storage_cohorts=len(counts), storage_index_sha256=sha(index))
if a.fixture_mode == 'wrong-scope':
    result['capture_scope'] = 'read_only_user_gameplay' if a.practice_range else 'controlled_practice'
if a.fixture_mode == 'wrong-result':
    result['output_sha256'] = '0' * 64
if a.fixture_mode == 'wrong-schema':
    result['schema'] = 'overwatch-decoder.private.combined-run/1'
if a.fixture_mode != 'missing-result':
    (out / 'result.json').write_bytes(encoded(result))
sys.exit(code)
