"""Opt-in combined-output storage foundation; not a continuous-capture capability.

One active immutable-path cohort, exact seal-line hash chain, bounded streaming
verification. Storage boundaries contain no source values or clock transitions.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path

SCHEMA = 'overwatch-decoder.private.combined-storage/1'
MAX_COHORTS = 4096
MAX_COHORT_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_INDEX_LINE = 4096
CAPABILITIES = {'combined_storage': 1, 'continuous_capture': False}
FILES = ('game-state.jsonl', 'delivery-receipts.jsonl')
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 2**63 - 1


def digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def strict_json(data):
    def reject_constant(value):
        raise ValueError('storage_nonfinite_json')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'storage_duplicate_key')
            result[key] = value
        return result
    text = data.decode('utf-8') if isinstance(data, bytes) else data
    need(not text.startswith('\ufeff'), 'storage_json_encoding')
    return json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)


def parse_line(data):
    need(isinstance(data, bytes) and 0 < len(data) <= MAX_INDEX_LINE and data.endswith(b'\n'), 'storage_index_line')
    result = strict_json(data)
    need(isinstance(result, dict), 'storage_index_object')
    return result


def contained(root, relative):
    need(isinstance(relative, str) and relative and '\\' not in relative and ':' not in relative,
         'storage_path')
    need(all(p not in ('', '.', '..') for p in relative.split('/')) and not relative.startswith('/'), 'storage_path')
    target = root / relative
    need(target.resolve().is_relative_to(root.resolve()), 'storage_path_escape')
    cursor = target
    while cursor != root:
        need(not cursor.is_symlink(), 'storage_link')
        cursor = cursor.parent
    need(not root.is_symlink(), 'storage_link')
    return target


class CombinedStorageWriter:
    """Write original compact bytes then their receipt; seal only complete pairs.

    Caller samples QPC around write_compact(), then constructs the original
    receipt and calls commit_receipt(). No timings/values are fabricated here.
    abort() preserves an unsealed provisional prefix, never a complete seal.
    """
    def __init__(self, root, *, maximum_cohort_bytes, maximum_total_bytes,
                 maximum_cohorts, maximum_index_bytes, maximum_line_bytes=2*1024*1024,
                 maximum_receipt_bytes=4096):
        for value, upper in ((maximum_cohort_bytes, MAX_COHORT_BYTES),
                             (maximum_total_bytes, MAX_TOTAL_BYTES),
                             (maximum_cohorts, MAX_COHORTS), (maximum_index_bytes, MAX_INDEX_BYTES)):
            need(integer(value, 1) and value <= upper, 'storage_limits')
        need(integer(maximum_line_bytes, 1) and maximum_line_bytes <= 2*1024*1024
             and integer(maximum_receipt_bytes, 1) and maximum_receipt_bytes <= 4096, 'storage_line_limits')
        need(maximum_total_bytes >= 2*MAX_INDEX_LINE and maximum_index_bytes >= 2*MAX_INDEX_LINE,
             'storage_seal_reserve')
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.cohort_limit, self.total_limit = maximum_cohort_bytes, maximum_total_bytes
        self.cohort_count_limit, self.index_limit = maximum_cohorts, maximum_index_bytes
        self.line_limit, self.receipt_limit = maximum_line_bytes, maximum_receipt_bytes
        self.index = contained(self.root, 'storage-index.jsonl').open('xb')
        self.index_hash = hashlib.sha256()
        self.index_bytes = self.index_records = self.total_charged = 0
        self.output_hash = hashlib.sha256()
        self.output_rows = self.output_bytes = self.receipt_bytes = 0
        self.ordinal = 0
        self.previous = None
        self.active = None
        self.pending = None
        self.closed = self.failed = False
        try:
            self._open()
        except BaseException:
            self.abort()
            raise

    def _index(self, value):
        data = encoded(value)
        need(len(data) <= MAX_INDEX_LINE and self.index_bytes + len(data) <= self.index_limit
             and self.total_charged + len(data) <= self.total_limit, 'storage_index_budget')
        need(self.index.write(data) == len(data), 'storage_index_short_write')
        self.index.flush()
        self.index_hash.update(data)
        self.index_bytes += len(data)
        self.index_records += 1
        self.total_charged += len(data)
        return hashlib.sha256(data).hexdigest()

    def _open(self):
        need(self.ordinal < self.cohort_count_limit, 'storage_cohort_limit')
        self.ordinal += 1
        directory = f'cohort-{self.ordinal:06d}'
        contained(self.root, directory).mkdir()
        streams = []
        try:
            for name in FILES:
                streams.append(contained(self.root, directory + '/' + name).open('xb'))
            self.active = dict(directory=directory, streams=streams, bytes=[0, 0], rows=0,
                               hashes=[hashlib.sha256(), hashlib.sha256()], first=None, last=None)
            self._index(dict(schema=SCHEMA, kind='open', ordinal=self.ordinal,
                             directory=directory, previous_seal_sha256=self.previous))
        except BaseException:
            for stream in streams:
                stream.close()
            raise

    def _seal(self):
        need(self.pending is None and self.active is not None, 'storage_unpaired_row')
        a = self.active
        for stream in a['streams']:
            stream.close()
        files = [dict(path=name, bytes=a['bytes'][i], rows=a['rows'], sha256=a['hashes'][i].hexdigest())
                 for i, name in enumerate(FILES)]
        pin = self._index(dict(schema=SCHEMA, kind='seal', ordinal=self.ordinal, directory=a['directory'],
                               previous_seal_sha256=self.previous, files=files,
                               first_combined_sequence=a['first'], last_combined_sequence=a['last']))
        self.previous = pin
        self.active = None

    def write_compact(self, data, sequence):
        try:
            need(not self.closed and not self.failed and self.pending is None, 'storage_writer_state')
            need(isinstance(data, bytes) and 0 < len(data) <= self.line_limit
                 and data.endswith(b'\n') and data.count(b'\n') == 1, 'storage_compact_line')
            need(integer(sequence) and sequence == self.output_rows, 'storage_sequence')
            reserve = len(data) + self.receipt_limit
            need(reserve <= self.cohort_limit, 'storage_row_cohort_bound')
            if sum(self.active['bytes']) + reserve > self.cohort_limit:
                self._seal()
                self._open()
            need(self.total_charged + reserve + MAX_INDEX_LINE <= self.total_limit
                 and self.index_bytes + MAX_INDEX_LINE <= self.index_limit, 'storage_total_budget')
            need(self.active['streams'][0].write(data) == len(data), 'storage_compact_short_write')
            self.active['streams'][0].flush()
            self.pending = (data, sequence)
        except BaseException:
            self.failed = True
            self.abort()
            raise

    def commit_receipt(self, data):
        try:
            need(not self.closed and not self.failed and self.pending is not None, 'storage_writer_state')
            need(isinstance(data, bytes) and 0 < len(data) <= self.receipt_limit
                 and data.endswith(b'\n') and data.count(b'\n') == 1, 'storage_receipt_line')
            compact, sequence = self.pending
            a = self.active
            need(a['streams'][1].write(data) == len(data), 'storage_receipt_short_write')
            a['streams'][1].flush()
            for i, value in enumerate((compact, data)):
                a['hashes'][i].update(value)
                a['bytes'][i] += len(value)
            a['rows'] += 1
            a['first'] = sequence if a['first'] is None else a['first']
            a['last'] = sequence
            self.output_hash.update(compact)
            self.output_rows += 1
            self.output_bytes += len(compact)
            self.receipt_bytes += len(data)
            self.total_charged += len(compact) + len(data)
            self.pending = None
        except BaseException:
            self.failed = True
            self.abort()
            raise

    def close(self, *, failed_start=False):
        need(not self.closed and not self.failed, 'storage_writer_closed')
        try:
            need(self.pending is None, 'storage_unpaired_row')
            need(self.active['rows'] > 0 or failed_start is True and self.ordinal == 1, 'storage_empty_terminal')
            self._seal()
        except BaseException:
            self.failed = True
            self.abort()
            raise
        self.index.close()
        self.closed = True
        return self.summary()

    def abort(self):
        if self.active is not None:
            for stream in self.active['streams']:
                stream.close()
        self.index.close()
        self.closed = True

    def summary(self):
        return dict(storage_index_sha256=self.index_hash.hexdigest(), storage_index_bytes=self.index_bytes,
                    storage_index_records=self.index_records, storage_cohorts=self.ordinal,
                    output_rows=self.output_rows, output_bytes=self.output_bytes,
                    output_sha256=self.output_hash.hexdigest(), delivery_receipt_bytes=self.receipt_bytes,
                    provisional_tail=self.active is not None, durability_verified=False)


class CombinedStorageIndex:
    """Strict bounded open/seal validator. Only a seal establishes file acceptance."""
    def __init__(self, root, *, maximum_cohorts, maximum_total_bytes, maximum_index_bytes, maximum_cohort_bytes):
        need(integer(maximum_cohorts, 1) and maximum_cohorts <= MAX_COHORTS
             and integer(maximum_total_bytes, 1) and maximum_total_bytes <= MAX_TOTAL_BYTES
             and integer(maximum_index_bytes, 1) and maximum_index_bytes <= MAX_INDEX_BYTES
             and integer(maximum_cohort_bytes, 1) and maximum_cohort_bytes <= MAX_COHORT_BYTES, 'storage_reader_limits')
        self.root = Path(root)
        self.maximum_cohorts, self.maximum_total, self.maximum_index = maximum_cohorts, maximum_total_bytes, maximum_index_bytes
        self.active = None
        self.closed = False
        self.empty_terminal = False
        self.cohort_limit = maximum_cohort_bytes
        self.ordinal = self.rows = self.output_bytes = self.receipt_bytes = self.index_bytes = self.records = 0
        self.previous = None
        self.index_hash, self.output_hash = hashlib.sha256(), hashlib.sha256()

    def consume(self, raw):
        need(not self.closed, 'storage_reader_closed')
        r = parse_line(raw)
        need(r.get('schema') == SCHEMA and r.get('kind') in ('open', 'seal'), 'storage_schema')
        base = {'schema', 'kind', 'ordinal', 'directory', 'previous_seal_sha256'}
        keys = base if r['kind'] == 'open' else base | {'files', 'first_combined_sequence', 'last_combined_sequence'}
        need(set(r) == keys and integer(r['ordinal'], 1) and r['ordinal'] <= self.maximum_cohorts
             and r['directory'] == f"cohort-{r['ordinal']:06d}" and r['previous_seal_sha256'] == self.previous,
             'storage_identity_chain')
        need(self.index_bytes + len(raw) <= self.maximum_index, 'storage_reader_index_budget')
        need(self.output_bytes + self.receipt_bytes + self.index_bytes + len(raw) <= self.maximum_total, 'storage_reader_total_budget')
        contained(self.root, r['directory'])
        if r['kind'] == 'open':
            need(not self.empty_terminal and self.active is None and r['ordinal'] == self.ordinal + 1, 'storage_open_order')
            for name in FILES:
                need(contained(self.root, r['directory'] + '/' + name).is_file(), 'storage_open_file_missing')
            self.active = dict(r)
            self.ordinal = r['ordinal']
        else:
            need(self.active is not None and r['ordinal'] == self.ordinal
                 and r['directory'] == self.active['directory'], 'storage_seal_order')
            need(isinstance(r['files'], list) and len(r['files']) == 2, 'storage_files')
            # Verify pairwise original line links without buffering the cohort.
            from contextlib import ExitStack
            paths = []
            for i, item in enumerate(r['files']):
                need(isinstance(item, dict) and set(item) == {'path', 'bytes', 'rows', 'sha256'}
                     and item['path'] == FILES[i] and integer(item['bytes']) and integer(item['rows'])
                     and digest(item['sha256']), 'storage_file_descriptor')
                path = contained(self.root, r['directory'] + '/' + item['path'])
                need(path.stat().st_size == item['bytes'], 'storage_file_size')
                paths.append(path)
            need(sum(x['bytes'] for x in r['files']) <= self.cohort_limit, 'storage_reader_cohort_budget')
            need(sum(x['bytes'] for x in r['files']) + self.output_bytes + self.receipt_bytes
                 + self.index_bytes + len(raw) <= self.maximum_total, 'storage_reader_total_budget')
            output_hash = self.output_hash.copy()
            hashes, sizes, counts = [hashlib.sha256(), hashlib.sha256()], [0, 0], [0, 0]
            with ExitStack() as stack:
                streams = [stack.enter_context(path.open('rb')) for path in paths]
                # Bound work even if a producer grows a supposedly sealed file.
                while line := streams[0].readline(min(2*1024*1024, r['files'][0]['bytes'] - sizes[0]) + 1):
                    need(len(line) <= r['files'][0]['bytes'] - sizes[0], 'storage_file_growth')
                    receipt = streams[1].readline(min(4096, r['files'][1]['bytes'] - sizes[1]) + 1)
                    need(len(receipt) <= r['files'][1]['bytes'] - sizes[1], 'storage_file_growth')
                    need(len(line) <= 2*1024*1024 and line.endswith(b'\n')
                         and 0 < len(receipt) <= 4096 and receipt.endswith(b'\n'), 'storage_file_line')
                    value, proof = strict_json(line), strict_json(receipt)
                    need(isinstance(value, dict) and type(value.get('combined_sequence')) is int
                         and value['combined_sequence'] == self.rows + counts[0], 'storage_data_sequence')
                    need(isinstance(proof, dict) and type(proof.get('combined_sequence')) is int
                         and proof['combined_sequence'] == value['combined_sequence']
                         and proof.get('line_sha256') == hashlib.sha256(line).hexdigest(), 'storage_receipt_link')
                    for i, data in enumerate((line, receipt)):
                        hashes[i].update(data)
                        sizes[i] += len(data)
                        counts[i] += 1
                    output_hash.update(line)
                need(streams[1].read(1) == b'', 'storage_receipt_rows')
                for i, stream in enumerate(streams):
                    need(os.fstat(stream.fileno()).st_size == r['files'][i]['bytes']
                         and paths[i].stat().st_size == r['files'][i]['bytes'], 'storage_file_size')
            for i, item in enumerate(r['files']):
                need(sizes[i] == item['bytes'] and counts[i] == item['rows']
                     and hashes[i].hexdigest() == item['sha256'], 'storage_file_hash_rows')
            first, last = r['first_combined_sequence'], r['last_combined_sequence']
            need((counts[0] == 0 and self.ordinal == 1 and self.rows == 0 and sizes == [0, 0] and first is None and last is None)
                 or (counts[0] > 0 and type(first) is int and type(last) is int
                     and first == self.rows and last == first + counts[0] - 1), 'storage_seal_sequence')
            need(self.output_bytes + self.receipt_bytes + sum(sizes) + self.index_bytes + len(raw)
                 <= self.maximum_total, 'storage_reader_total_budget')
            self.output_hash = output_hash
            self.output_bytes += sizes[0]
            self.receipt_bytes += sizes[1]
            self.rows += counts[0]
            self.empty_terminal = counts[0] == 0
            self.previous = hashlib.sha256(raw).hexdigest()
            self.active = None
        self.index_hash.update(raw)
        self.index_bytes += len(raw)
        self.records += 1
        return r

    def complete(self):
        need(self.active is None and self.records > 0, 'storage_provisional_tail')
        self.closed = True
        return dict(storage_index_sha256=self.index_hash.hexdigest(), storage_index_bytes=self.index_bytes,
                    storage_index_records=self.records, storage_cohorts=self.ordinal,
                    output_rows=self.rows, output_bytes=self.output_bytes,
                    output_sha256=self.output_hash.hexdigest(), delivery_receipt_bytes=self.receipt_bytes)
