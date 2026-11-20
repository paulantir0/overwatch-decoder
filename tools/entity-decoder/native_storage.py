"""Bounded validation of native storage notifications, never file verification.

The native sink seals BEFORE the next accepted-frame callback, and its sole
terminal seal precedes segment_end. This state contains no gameplay values.
"""
import copy
import hashlib
import re

from export_relations import integer

_OPTIONS = frozenset(('schema', 'cohort_bytes', 'maximum_cohorts', 'sealed_cohorts',
                      'recording_schema', 'semantic_epoch_reset'))
_RECORD = frozenset(('schema', 'ordinal', 'directory', 'profile_sha256',
    'previous_record_sha256', 'first_chunk', 'chunks', 'first_line', 'lines',
    'compressed_bytes', 'json_bytes', 'index_bytes', 'samples_sha256', 'index_sha256',
    'terminal_summary_included'))
_EVENT = frozenset(('schema', 'kind', 'session_id', 'event_sequence', 'emitted_ticks',
    'monotonic_frequency', 'segment', 'acquisition', 'profile_sha256',
    'storage_cohort_ordinal', 'index_record', 'index_record_sha256'))


class NativeStorage:
    """One consumer's metadata cursor; clone only from an admitted coordinator.

    Session and adapter each advance once. A fresh direct epoch cannot claim a
    global prefix it did not receive; the coordinator supplies that prefix when
    handing a newly admitted adapter its active state.
    """
    def __init__(self, error=ValueError):
        self.error = error
        self.enabled = self.active = self.terminal = False
        self.policy = None
        self.session = self.frequency = None
        self.global_ordinal = self.segments = 0
        self.total_json = self.total_compressed = self.total_index = 0
        self.segment = self.acquisition = self.profile = None
        self.ordinal = self.chunks = self.lines = self.frames = 0
        self.previous = None
        self.pending_frame_seal_ticks = None
        self.history_known = True

    def need(self, ok, reason):
        if not ok:
            raise self.error('storage_' + reason)

    def clone(self):
        # State is only immutable scalar metadata and a privately constructed
        # options dict. No raw envelope, projection, open file or hash list.
        result = copy.copy(self)
        result.policy = None if self.policy is None else dict(self.policy)
        return result

    def start(self, event):
        if 'storage_rotation' not in event:
            return
        p = event['storage_rotation']
        self.need(isinstance(p, dict) and set(p) == _OPTIONS, 'policy_fields')
        self.need(p['schema'] == 'overwatch-decoder.field-storage-options/1'
            and integer(p['cohort_bytes']) and 65536 <= p['cohort_bytes'] <= 1024**3
            and integer(p['maximum_cohorts']) and 1 <= p['maximum_cohorts'] <= 4096
            and integer(p['sealed_cohorts']) and p['sealed_cohorts'] == 0
            and p['recording_schema'] == 'overwatch-decoder.field-recording/2'
            and p['semantic_epoch_reset'] is False, 'policy')
        self.need(not self.enabled and not self.active and self.global_ordinal == 0, 'policy_repeated')
        self.enabled = True
        self.policy = dict(p)
        self.session, self.frequency = event.get('session_id'), event.get('monotonic_frequency')

    def check_event(self, event):
        if self.enabled and self.active and self.terminal:
            self.need(event.get('kind') == 'segment_end', 'event_after_terminal_seal')
        elif self.enabled and self.active and self.pending_frame_seal_ticks is not None:
            self.need(event.get('kind') in ('frame', 'storage_cohort_sealed', 'segment_end'), 'rotation_callback_order')

    def begin(self, event):
        if not self.enabled:
            return
        segment, acquisition, profile = (event.get(k) for k in ('segment', 'acquisition', 'profile_sha256'))
        self.need(not self.active and integer(segment) and 1 <= segment <= 128
            and integer(acquisition) and 1 <= acquisition <= 128 and self._hash(profile)
            and event.get('monotonic_frequency') == self.frequency, 'segment_scope')
        self.need(self.global_ordinal < self.policy['maximum_cohorts'], 'cohort_limit')
        self.history_known = self.history_known and segment == self.segments + 1
        self.segments = segment
        self.segment, self.acquisition, self.profile = segment, acquisition, profile
        self.ordinal = self.chunks = self.lines = self.frames = 0
        self.previous = None
        self.pending_frame_seal_ticks = None
        self.active, self.terminal = True, False

    def frame(self, event):
        if not self.enabled:
            return
        self.need(self.active and not self.terminal, 'frame_after_seal_or_epoch')
        self.need(event.get('monotonic_frequency') == self.frequency, 'clock_changed')
        self.need(integer(event.get('sequence')) and event['sequence'] == self.frames, 'frame_sequence')
        if self.pending_frame_seal_ticks is not None:
            # Rotation occurs inside WriteFrame, after that frame was read but
            # before its accepted callback. This is a check, not a watermark.
            self.need(integer(event.get('end_ticks')) and event['end_ticks'] <= self.pending_frame_seal_ticks,
                'rotation_before_frame_read')
            self.pending_frame_seal_ticks = None
        self.frames += 1

    @staticmethod
    def _hash(value):
        return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None

    def seal(self, event, raw):
        self.need(self.enabled, 'not_enabled')
        self.need(self.active and not self.terminal and self.history_known, 'active_prefix_required')
        self.need(set(event) == _EVENT, 'event_fields')
        self.need(integer(event['segment']) and event['segment'] == self.segment
            and integer(event['acquisition']) and event['acquisition'] == self.acquisition
            and event['profile_sha256'] == self.profile
            and event['monotonic_frequency'] == self.frequency, 'active_pins')
        number = event['storage_cohort_ordinal']
        self.need(integer(number) and number == self.global_ordinal + 1
            and number <= self.policy['maximum_cohorts'], 'global_ordinal')
        r = event['index_record']
        self.need(isinstance(r, dict) and set(r) == _RECORD, 'record_fields')
        self.need(r['schema'] == 'overwatch-decoder.field-storage-cohort/1'
            and integer(r['ordinal']) and r['ordinal'] == self.ordinal + 1
            and r['directory'] == f"storage-{r['ordinal']:06d}"
            and r['profile_sha256'] == self.profile
            and r['previous_record_sha256'] == self.previous, 'record_scope_or_chain')
        self.need(all(self._hash(r[k]) for k in ('samples_sha256', 'index_sha256'))
            and self._hash(event['index_record_sha256']), 'record_hash')
        self.need(all(integer(r[k]) and r[k] >= 0 for k in ('first_chunk', 'chunks', 'first_line',
            'lines', 'compressed_bytes', 'json_bytes', 'index_bytes'))
            and type(r['terminal_summary_included']) is bool, 'record_numbers')
        self.need(r['terminal_summary_included'] or number < self.policy['maximum_cohorts'], 'nonterminal_at_cohort_limit')
        self.need(r['first_chunk'] == self.chunks and r['first_line'] == self.lines
            and 0 < r['chunks'] <= r['lines'] and self.chunks + r['chunks'] <= 200000
            and self.lines + r['lines'] == self.frames + int(r['terminal_summary_included']), 'chunk_or_line_order')
        self.need(18 * r['chunks'] <= r['compressed_bytes'] <= self.policy['cohort_bytes']
            and r['compressed_bytes'] <= r['chunks'] * (1024**2 + 8192)
            and r['lines'] <= r['json_bytes'] <= r['chunks'] * 1024**2
            and 0 < r['index_bytes'] <= r['chunks'] * 4096, 'record_bounds')
        # Every record value is now a bounded primitive with restricted string
        # domains. No nested braces or literal closing brace can occur inside
        # these values. Decode no second JSON graph: hash the original embedded
        # object bytes, then the catalog's LF (not the live envelope's suffix).
        match = re.search(rb'"index_record"\s*:\s*', raw)
        self.need(match is not None and raw[match.end():match.end()+1] == b'{', 'record_raw_object')
        begin = match.end(); end = raw.find(b'}', begin)
        self.need(end >= begin, 'record_raw_object')
        line = raw[begin:end+1] + b'\n'
        self.need(len(line) <= 4096 and hashlib.sha256(line).hexdigest() == event['index_record_sha256'], 'record_raw_hash')
        self.need(self.total_json + r['json_bytes'] <= 32 * 1024**3
            and self.total_compressed + r['compressed_bytes'] <= 2 * 1024**3
            and self.total_index + r['index_bytes'] + len(line) <= 64 * 1024**2, 'cumulative_bounds')
        self.global_ordinal = number
        self.ordinal += 1; self.chunks += r['chunks']; self.lines += r['lines']
        self.total_json += r['json_bytes']; self.total_compressed += r['compressed_bytes']
        self.total_index += r['index_bytes'] + len(line)
        self.previous = event['index_record_sha256']
        self.terminal = r['terminal_summary_included']
        self.pending_frame_seal_ticks = None if self.terminal else event['emitted_ticks']

    def end(self, event):
        if not self.enabled:
            return
        entry = event.get('segment', {})
        self.need(self.active and isinstance(entry, dict)
            and integer(entry.get('ordinal')) and entry['ordinal'] == self.segment
            and integer(entry.get('acquisition')) and entry['acquisition'] == self.acquisition
            and entry.get('profile_sha256') == self.profile
            and integer(entry.get('frames')) and entry['frames'] == self.frames, 'end_scope')
        written = event.get('terminal_summary_written')
        self.need(type(written) is bool, 'terminal_flag')
        if written:
            self.need(self.terminal and self.lines == self.frames + 1, 'missing_terminal_seal')
        else:
            self.need(isinstance(event.get('failure'), str) and bool(event['failure']), 'unsealed_end_without_failure')
        self.active = False

    def finish(self, final):
        if not self.enabled:
            self.need('storage_rotation' not in final, 'undeclared_terminal_policy')
            return
        self.need(not self.active and self.history_known, 'unfinished_epoch')
        self.need(final.get('schema') == 'overwatch-decoder.field-observation/1'
            and final.get('session_id') == self.session, 'terminal_scope')
        p = final.get('storage_rotation')
        expected = dict(self.policy, sealed_cohorts=self.global_ordinal)
        self.need(isinstance(p, dict) and set(p) == _OPTIONS
            and all(type(p[k]) is type(v) and p[k] == v for k, v in expected.items()), 'terminal_policy')

    def receipt(self):
        return dict(enabled=True, sealed_cohorts=self.global_ordinal,
            metadata_only=True, independent_file_verification=False, durability_verified=False)
