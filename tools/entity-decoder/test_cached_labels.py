"""Synthetic cache candidates; no application data or offsets."""
import copy
import json
import unittest

from cached_labels import GuardedCachedLabels
from test_relations import fixture, prepare


def label_fixture(raw=b'Example\0', rows=1):
    profile, values = fixture(rows)
    for index, value in enumerate(raw):
        name = f'controller_0000_cached_label_0000_byte_{index:04}_value'
        profile['fields'].append(dict(name=name, address=0x4000 + index, type='u8'))
        values[name] = value
    _, frame = prepare(profile, values)
    for name, sample in frame['fields'].items():
        if '_cached_label_' in name:
            sample['type'] = 'u8'
    return profile, GuardedCachedLabels(json.dumps(profile).encode()), frame


def packed_fixture(text=b'Example', padding=b'\xa5'):
    profile, values = fixture()
    base = 'controller_0000_cached_label_0000_'
    length = len(text)
    guard = dict(address=0x3000, bytes_hex=length.to_bytes(4, 'little').hex())
    name = base + 'packed_length_i32'
    profile['fields'].append(dict(name=name, type='i32', address=0x3000, guards=[guard.copy()]))
    values[name] = length
    raw = text + b'\0'
    raw += padding * (-len(raw) % 4)
    for index in range(len(raw) // 4):
        name = base + f'word_{index:04}_i32'
        profile['fields'].append(dict(name=name, type='i32', address=0x4000 + index * 4,
                                      guards=[guard.copy()]))
        values[name] = int.from_bytes(raw[index*4:index*4+4], 'little', signed=True)
    _, frame = prepare(profile, values)
    return profile, GuardedCachedLabels(json.dumps(profile).encode()), frame


class CachedLabelsTests(unittest.TestCase):
    def test_packed_complete_little_endian_text_at_all_word_boundaries(self):
        for size in range(1, 64):
            text = b'x' * size
            _, decoder, frame = packed_fixture(text)
            row = decoder.project(frame)['labels'][0]
            self.assertEqual(row['candidate_cached_label'], text.decode(), size)
            self.assertEqual(len(row['evidence']), 1 + (size + 4) // 4)
            self.assertEqual(row['evidence'][0]['value'], size)
            self.assertTrue(all('value' in sample for sample in row['evidence']))
        _, decoder, frame = packed_fixture('Éxample'.encode())
        self.assertEqual(decoder.project(frame)['labels'][0]['candidate_cached_label'], 'Éxample')

    def test_packed_local_guard_failure_preserves_raw_relation(self):
        _, decoder, frame = packed_fixture()
        baseline = decoder.relations.project(frame)
        frame['guards_after'][-1]['ok'] = False
        self.assertEqual(decoder.relations.project(frame), baseline)
        self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])
        self.assertEqual(decoder.project(frame)['labels'][0]['body_object_key'],
                         baseline['relations'][0]['body_object_key'])

    def test_packed_missing_extra_mixed_and_wrongly_bound_words_fail(self):
        for mode in ('missing', 'extra', 'mixed', 'address', 'dependencies', 'second_row', 'length'):
            profile, _, frame = packed_fixture(b'complete')
            base = 'controller_0000_cached_label_0000_'
            if mode == 'missing': profile['fields'].pop()
            elif mode == 'extra':
                extra = copy.deepcopy(profile['fields'][-1]); extra['name'] = base + 'word_0003_i32'
                extra['address'] += 4; profile['fields'].append(extra)
            elif mode == 'mixed':
                profile['fields'].append(dict(name=base+'byte_0000_value', type='u8', address=0x5000))
            elif mode == 'address': profile['fields'][-1]['address'] += 4
            elif mode == 'dependencies': profile['fields'][-1].pop('guards')
            elif mode == 'second_row': profile['fields'][-1]['name'] = profile['fields'][-1]['name'].replace('label_0000', 'label_0001')
            else: frame['fields'][base+'packed_length_i32']['value'] -= 1
            decoder = GuardedCachedLabels(json.dumps(profile).encode()); frame['profile_sha256'] = decoder.relations.hash
            with self.subTest(mode=mode):
                self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])

    def test_packed_invalid_text_terminator_and_gap_never_truncate_or_carry(self):
        for text in (b'', b'a\0hidden', b'\xff', b'a\nb', b'x'*64):
            _, decoder, frame = packed_fixture(text)
            self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])
        _, decoder, frame = packed_fixture(b'abc')
        baseline = copy.deepcopy(frame)
        name = 'controller_0000_cached_label_0000_word_0000_i32'
        frame['fields'][name]['value'] = int.from_bytes(b'abcX', 'little')
        self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])
        for skip in (1, -1, True):
            frame = copy.deepcopy(baseline); frame['skipped_intervals_before'] = skip
            self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])
        self.assertEqual(decoder.project(baseline)['labels'][0]['candidate_cached_label'], 'abc')

    def test_packed_word_checks_are_complete(self):
        _, decoder, original = packed_fixture(b'x'*63)
        name = 'controller_0000_cached_label_0000_word_0015_i32'
        for patch in ({'value': 2**31}, {'value': True}, {'status': 'unknown'},
                      {'type': 'u8'}, {'guard_ids': []}, {'read_end_ticks': 101}):
            frame = copy.deepcopy(original); frame['fields'][name].update(patch)
            self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'], patch)

    def test_packed_length_is_guard_bound_and_body_is_independent(self):
        _, decoder, original = packed_fixture()
        name = 'controller_0000_cached_label_0000_packed_length_i32'
        for patch in ({'value': True}, {'value': 7.0}, {'value': -1}, {'status': 'unknown'},
                      {'type': 'u8'}, {'guard_ids': []}, {'read_start_ticks': 9}):
            frame = copy.deepcopy(original); frame['fields'][name].update(patch)
            self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'], patch)
        frame = copy.deepcopy(original)
        frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        row = decoder.project(frame)['labels'][0]
        self.assertEqual(row['candidate_cached_label'], 'Example')
        self.assertIsNone(row['body_object_key'])
        frame['fields'].pop('controller_0000_manager_key_candidate_i32')
        self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])

    def test_packed_length_name_does_not_override_declared_native_type(self):
        for declared_type in ('f32', 'f32x3', 'u8'):
            profile, _, frame = packed_fixture()
            name = 'controller_0000_cached_label_0000_packed_length_i32'
            field = next(item for item in profile['fields'] if item['name'] == name)
            field['type'] = declared_type
            decoder = GuardedCachedLabels(json.dumps(profile).encode())
            frame['profile_sha256'] = decoder.relations.hash
            frame['fields'][name].update(type=declared_type, value=7.0)
            row = decoder.project(frame)['labels'][0]
            self.assertIsNone(row['candidate_cached_label'])
            self.assertEqual(row['reason'], 'unsupported_word_binding')

    def test_candidate_preserves_text_without_account_or_gameplay_claims(self):
        _, decoder, frame = label_fixture('Éxample#42\0'.encode())
        result = decoder.project(frame)
        self.assertEqual(result['labels'][0]['candidate_cached_label'], 'Éxample#42')
        self.assertFalse(result['gameplay_semantics_validated'])
        self.assertFalse(result['participant_identity_validated'])
        self.assertFalse(result['public_state_eligible'])
        self.assertEqual(result['privacy'], 'private')
        self.assertEqual(result['visibility'], 'unknown')
        self.assertNotIn('address', json.dumps(result))

    def test_missing_cache_entry_does_not_fill_from_another_controller(self):
        _, decoder, frame = label_fixture(rows=2)
        rows = decoder.project(frame)['labels']
        self.assertEqual(rows[0]['status'], 'observed')
        self.assertEqual(rows[1]['reason'], 'label_not_declared')
        self.assertIsNone(rows[1]['candidate_cached_label'])
        self.assertIsNotNone(rows[1]['controller_object_key'])

    def test_invalid_text_and_length_unknown(self):
        for raw in (b'', b'\0', b'Example', b'a\0b\0', b'\xff\0', b'a\nb\0', b'x' * 64 + b'\0'):
            _, decoder, frame = label_fixture(raw)
            self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'], raw)

    def test_guard_scalar_and_target_failures_unknown(self):
        _, decoder, original = label_fixture()
        for mode in ('guard', 'target', 'scalar', 'dependency', 'bracket'):
            frame = copy.deepcopy(original)
            sample = frame['fields']['controller_0000_cached_label_0000_byte_0000_value']
            if mode == 'guard': frame['guards_after'][0]['ok'] = False
            elif mode == 'target': frame['target']['pid'] += 1
            elif mode == 'scalar': sample['value'] = 256
            elif mode == 'dependency': sample['guard_ids'] = []
            else: sample['read_end_ticks'] = 101
            self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'], mode)

    def test_noncontiguous_storage_and_duplicate_rows_rejected(self):
        for mode in ('address', 'row'):
            profile, _, frame = label_fixture()
            if mode == 'address': profile['fields'][-1]['address'] += 1
            else: profile['fields'][-1]['name'] = profile['fields'][-1]['name'].replace('label_0000', 'label_0001')
            decoder = GuardedCachedLabels(json.dumps(profile).encode())
            frame['profile_sha256'] = decoder.relations.hash
            self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])

    def test_unknown_body_preserves_independent_controller_label(self):
        _, decoder, frame = label_fixture()
        frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        row = decoder.project(frame)['labels'][0]
        self.assertEqual(row['status'], 'observed')
        self.assertIsNone(row['body_object_key'])

    def test_no_value_carried_through_gap(self):
        _, decoder, frame = label_fixture()
        self.assertEqual(decoder.project(frame)['labels'][0]['status'], 'observed')
        frame['fields'] = {}
        self.assertIsNone(decoder.project(frame)['labels'][0]['candidate_cached_label'])


if __name__ == '__main__':
    unittest.main()
