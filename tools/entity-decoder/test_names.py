import copy
import json
import unittest

from names import GuardedNames
from test_relations import fixture, prepare


def name_fixture(raw=b'Example#1234', *, terminated=True):
    profile, values = fixture()
    for index in range(4):
        address = 0x3000 + index * 4
        name = f'controller_0000_part36_0000_account_word{index}_candidate_i32'
        profile['fields'].append(dict(name=name, address=address, type='i32'))
        profile['guards'].append(dict(address=address, bytes_hex=(index + 1).to_bytes(4, 'little').hex()))
        values[name] = index + 1
    data = (raw + b'\0' * 64)[:64] if terminated else raw.ljust(64, b'x')[:64]
    for index, byte in enumerate(data):
        name = f'controller_0000_name_0000_byte_{index:04}_value'
        profile['fields'].append(dict(name=name, address=0x4000 + index, type='u8'))
        values[name] = byte
    decoder, frame = prepare(profile, values)
    for name, sample in frame['fields'].items():
        if '_name_' in name:
            sample['type'] = 'u8'
    return profile, values, GuardedNames(json.dumps(profile).encode()), frame


class NamesTests(unittest.TestCase):
    def test_private_name_and_display_transformation(self):
        _, _, decoder, frame = name_fixture()
        result = decoder.project(frame)
        row = result['names'][0]
        self.assertEqual(row['private_name'], 'Example#1234')
        self.assertEqual(row['display_name'], 'Example')
        self.assertEqual(result['privacy'], 'private')
        self.assertFalse(result['public_state_eligible'])
        self.assertFalse(result['participant_identity_validated'])
        self.assertEqual(result['visibility'], 'unknown')
        self.assertNotIn('address', json.dumps(result))

    def test_utf8_preserved_and_only_numeric_suffix_removed(self):
        for name in ('Éxample#42', 'Example#abc', '名'):
            _, _, decoder, frame = name_fixture(name.encode())
            row = decoder.project(frame)['names'][0]
            self.assertEqual(row['private_name'], name)
            self.assertEqual(row['display_name'], 'Éxample' if name.endswith('#42') else name)

    def test_invalid_or_unterminated_text_unknown(self):
        for raw, terminated, reason in ((b'\xff', True, 'invalid_name_utf8'),
                                       (b'', True, 'empty_or_control_name'),
                                       (b'a\nb', True, 'empty_or_control_name'),
                                       (b'x', False, 'unterminated_name')):
            _, _, decoder, frame = name_fixture(raw, terminated=terminated)
            row = decoder.project(frame)['names'][0]
            self.assertEqual(row['reason'], reason)
            self.assertIsNone(row['private_name'])

    def test_missing_byte_or_guard_or_account_rejects_name(self):
        for mutation in ('byte', 'guard', 'account', 'target'):
            _, _, decoder, frame = name_fixture()
            if mutation == 'byte':
                frame['fields']['controller_0000_name_0000_byte_0002_value']['status'] = 'unknown'
            elif mutation == 'guard':
                frame['guards_after'][0]['ok'] = False
            elif mutation == 'account':
                frame['fields']['controller_0000_part36_0000_account_word0_candidate_i32']['value'] += 1
            else:
                frame['target']['pid'] += 1
            self.assertIsNone(decoder.project(frame)['names'][0]['private_name'], mutation)

    def test_name_does_not_require_observed_body(self):
        _, _, decoder, frame = name_fixture()
        frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        row = decoder.project(frame)['names'][0]
        self.assertEqual(row['status'], 'observed')
        self.assertIsNone(row['body_object_key'])

    def test_noncontiguous_bytes_rejected(self):
        profile, _, _, frame = name_fixture()
        profile['fields'][-1]['address'] += 1
        decoder = GuardedNames(json.dumps(profile).encode())
        frame['profile_sha256'] = decoder.relations.hash
        self.assertEqual(decoder.project(frame)['names'][0]['reason'], 'noncontiguous_name_bytes')

    def test_no_name_carried_across_gap(self):
        _, _, decoder, frame = name_fixture()
        self.assertEqual(decoder.project(frame)['names'][0]['status'], 'observed')
        frame['fields'] = {}
        self.assertIsNone(decoder.project(frame)['names'][0]['private_name'])

    def test_byte_value_range_and_bracket_checked(self):
        _, _, decoder, original = name_fixture()
        for patch in ({'value': -1}, {'value': 256}, {'value': True}, {'read_end_ticks': 101}):
            frame = copy.deepcopy(original)
            frame['fields']['controller_0000_name_0000_byte_0001_value'].update(patch)
            self.assertIsNone(decoder.project(frame)['names'][0]['private_name'])


if __name__ == '__main__':
    unittest.main()
