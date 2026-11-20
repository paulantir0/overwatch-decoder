"""Lossless native-event journals; compression does not change JSONL evidence.

Writers are new-file-only. Readers are for stopped, immutable artifacts and must
be exhausted to verify the gzip trailer and final file identity. Callers retain
their existing native-stream validation and uncompressed output budgets.
"""
from contextlib import contextmanager
import gzip
import os
from pathlib import Path


@contextmanager
def open_event_journal_writer(path, *, compression='gzip'):
    if compression not in ('none', 'gzip'):
        raise ValueError('journal_compression')
    with Path(path).open('xb') as raw:
        if compression == 'none':
            yield raw
        else:
            # Never place a private filename or a varying wall timestamp in the
            # gzip header. Flush remains buffered publication, not fsync proof.
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw,
                               compresslevel=1, mtime=0) as stream:
                yield stream


def iter_event_journal(path, *, maximum_line=512*1024,
                       maximum_bytes=512*1024*1024,
                       maximum_stored_bytes=512*1024*1024):
    """Yield original line bytes from plain or gzip journals, with strict limits.

    Partial final lines, changed files, truncated gzip members and CRC failures
    raise. Already yielded lines are a prefix, not proof of complete recording.
    No event decoding, recovery, acquisition or gameplay interpretation occurs.
    """
    for value in (maximum_line, maximum_bytes, maximum_stored_bytes):
        if type(value) is not int or value <= 0:
            raise ValueError('journal_bounds')
    if maximum_line > 1024*1024 or maximum_bytes > 4*1024**3 or maximum_stored_bytes > 4*1024**3:
        raise ValueError('journal_bounds')
    with Path(path).open('rb') as raw:
        before = os.fstat(raw.fileno())
        if before.st_size > maximum_stored_bytes:
            raise ValueError('journal_stored_limit')
        compressed = raw.read(2) == b'\x1f\x8b'
        raw.seek(0)
        stream = gzip.GzipFile(fileobj=raw, mode='rb') if compressed else raw
        total = 0
        try:
            while True:
                # Stop decompression at the smaller line/remaining budget. This
                # bounds a compressed oversized line before allocating it whole.
                bound = min(maximum_line, maximum_bytes-total)
                line = stream.readline(bound+1)
                if not line:
                    break
                if len(line) > maximum_line:
                    raise ValueError('journal_line_limit')
                total += len(line)
                if total > maximum_bytes:
                    raise ValueError('journal_byte_limit')
                if not line.endswith(b'\n'):
                    raise ValueError('journal_partial_line')
                yield line
            after = os.fstat(raw.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev) != (
                    after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev):
                raise ValueError('journal_changed')
        finally:
            if compressed:
                stream.close()
