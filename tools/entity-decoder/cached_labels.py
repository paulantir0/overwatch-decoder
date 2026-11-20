"""Private string candidates from an independently verified keyed native cache.

The caller must verify acquisition/recording provenance and the exact cache-to-
controller lookup. A matching string does not establish participant semantics.

The byte provider is unchanged. The explicit packed provider uses a guarded
``_cached_label_0000_packed_length_i32`` and contiguous
``_cached_label_0000_word_NNNN_i32`` fields: complete UTF-8 plus NUL, rounded to
four bytes. Its native recipe must independently validate allocation capacity.
Optional local guard failures never supply a cached or truncated string.
"""
import re
import unicodedata

from relations import GuardedRelations, InvalidBinding


class GuardedCachedLabels:
    def __init__(self, raw_profile: bytes):
        self.relations = GuardedRelations(raw_profile)

    def _packed(self, prefix, frame):
        """Complete length+NUL, with at most three allocation-safe padding bytes.

        The caller's verified native recipe must prove the rounded read extent
        fits the string allocation. This decoder proves current guarded length,
        complete contiguous words and matching dependencies, not allocation size.
        """
        length_name = prefix + '_cached_label_0000_packed_length_i32'
        pattern = re.compile(re.escape(prefix) + r'_cached_label_(\d{4})_word_(\d{4})_i32\Z')
        lengths = [name for name in self.relations.fields
                   if re.fullmatch(re.escape(prefix) + r'_cached_label_\d{4}_packed_length_i32', name)]
        declared = sorted((int(m[1]), int(m[2]), name) for name in self.relations.fields
                          if (m := pattern.fullmatch(name)))
        if lengths != [length_name]:
            raise InvalidBinding('invalid_packed_label_length_declaration')
        skipped = frame.get('skipped_intervals_before', 0)
        if type(skipped) is not int or skipped < 0:
            raise InvalidBinding('invalid_gap_metadata')
        if skipped:
            raise InvalidBinding('scheduled_gap')
        length = self.relations._observed(length_name, frame)
        size = length['value']
        if not 1 <= size <= 63:
            raise InvalidBinding('invalid_packed_label_length')
        count = (size + 4) // 4
        if [(row, index) for row, index, _ in declared] != [(0, i) for i in range(count)]:
            raise InvalidBinding('invalid_packed_label_word_declaration')
        ids = self.relations.guard_ids[length_name]
        if any(self.relations.guard_ids[name] != ids for _, _, name in declared):
            raise InvalidBinding('packed_label_dependencies_mismatch')
        samples = [self.relations.sample_scalar(name, frame, 'i32') for _, _, name in declared]
        if any(sample['address'] != samples[0]['address'] + 4 * i for i, sample in enumerate(samples)):
            raise InvalidBinding('noncontiguous_packed_label_words')
        raw = b''.join((sample['value'] & 0xffffffff).to_bytes(4, 'little') for sample in samples)
        if raw[size] != 0 or 0 in raw[:size]:
            raise InvalidBinding('label_length_or_terminator_mismatch')
        evidence = [dict(field=length_name, value=size, read_start_ticks=length['read_start_ticks'],
                         read_end_ticks=length['read_end_ticks'])]
        evidence.extend({key: sample[key] for key in ('field', 'value', 'read_start_ticks', 'read_end_ticks')}
                        for sample in samples)
        return raw[:size], evidence

    def project(self, frame):
        relations = self.relations.project(frame)
        result = {key: value for key, value in relations.items() if key != 'relations'}
        result.update(schema='overwatch-decoder.guarded-cached-labels/1', privacy='private',
                      gameplay_semantics_validated=False, labels=[])
        for relation in relations['relations']:
            row = dict(controller_object_key=relation['controller_object_key'],
                       body_object_key=relation['body_object_key'], status='unknown',
                       reason=None, candidate_cached_label=None, evidence=[])
            try:
                if row['controller_object_key'] is None:
                    raise InvalidBinding(relation['reason'] or 'controller_unknown')
                pattern = re.compile(re.escape(relation['controller_prefix'])
                                     + r'_cached_label_(\d{4})_byte_(\d{4})_value\Z')
                declared = sorted((int(match[1]), int(match[2]), name)
                                  for name in self.relations.fields
                                  if (match := pattern.fullmatch(name)))
                packed = any(re.fullmatch(re.escape(relation['controller_prefix'])
                                         + r'_cached_label_\d{4}_(?:word_\d{4}_i32|packed_length_i32)', name)
                             for name in self.relations.fields)
                if packed and declared:
                    raise InvalidBinding('mixed_label_provider_declarations')
                if packed:
                    raw_text, evidence = self._packed(relation['controller_prefix'], frame)
                elif not declared:
                    raise InvalidBinding('label_not_declared')
                elif (not 2 <= len(declared) <= 64
                        or [(row_index, byte_index) for row_index, byte_index, _ in declared]
                        != [(0, i) for i in range(len(declared))]):
                    raise InvalidBinding('invalid_label_byte_declaration')
                if not packed:
                    samples = [self.relations.sample_scalar(name, frame, 'u8')
                               for _, _, name in declared]
                    if any(sample['address'] != samples[0]['address'] + i
                           for i, sample in enumerate(samples)):
                        raise InvalidBinding('noncontiguous_label_bytes')
                    raw = bytes(sample['value'] for sample in samples)
                    if raw[-1] != 0 or 0 in raw[:-1]:
                        raise InvalidBinding('label_length_or_terminator_mismatch')
                    raw_text = raw[:-1]
                    evidence = [{key: sample[key] for key in ('field', 'read_start_ticks', 'read_end_ticks')}
                                for sample in samples]
                try:
                    text = raw_text.decode('utf-8', errors='strict')
                except UnicodeDecodeError as error:
                    raise InvalidBinding('invalid_label_utf8') from error
                if not text or any(unicodedata.category(char).startswith('C') for char in text):
                    raise InvalidBinding('empty_or_control_label')
                row.update(status='observed', candidate_cached_label=text,
                           evidence=evidence)
            except InvalidBinding as error:
                row['reason'] = str(error)
            result['labels'].append(row)
        return result
