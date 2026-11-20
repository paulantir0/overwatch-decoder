"""Synthetic behavioral tests; no game capture or application offsets."""
import copy
import json
import unittest

from relations import GuardedRelations, InvalidBinding

SUFFIXES = ("_handle_candidate_i32", "_manager_key_candidate_i32",
            "_part51_0000_body_key_candidate_i32", "_body_0000_handle_candidate_i32",
            "_body_0000_manager_key_candidate_i32")


def fixture(rows=1):
    profile = dict(schema="overwatch-decoder.field-profile/1", target=dict(
        pid=123, creation_file_time=456, executable_sha256="ab" * 32,
        architecture="x64", image_name="fixture.exe"), guards=[], fields=[])
    values = {}
    for row in range(rows):
        for index, (suffix, value) in enumerate(zip(SUFFIXES, (0x80000001 + row,
                0x80000010 + row, 0x80000020 + row, 0x80000030 + row, 0x80000020 + row))):
            address = 0x1000 + row * 0x100 + index * 8
            name = f"controller_{row:04}" + suffix
            profile['fields'].append(dict(name=name, type="i32", address=address))
            profile['guards'].append(dict(address=address, bytes_hex=value.to_bytes(4, "little").hex()))
            values[name] = value - 2**32
    return profile, values


def prepare(profile, values):
    decoder = GuardedRelations(json.dumps(profile).encode())
    frame = dict(schema="overwatch-decoder.field-stream/1", kind="frame", source="process_memory",
                 profile_sha256=decoder.hash, target=profile['target'].copy(),
                 start_ticks=10, end_ticks=100, sequence=0, monotonic_frequency=1000,
                 utc_origin="2026-01-01T00:00:00Z", monotonic_origin_ticks=0,
                 guards_before=[dict(ok=True, error=None, start_ticks=11, end_ticks=20)
                                for _ in decoder.guards],
                 guards_after=[dict(ok=True, error=None, start_ticks=80, end_ticks=90)
                               for _ in decoder.guards], fields={})
    for name, value in values.items():
        frame['fields'][name] = dict(type="i32", status="observed", value=value,
                                    read_start_ticks=30, read_end_ticks=40,
                                    guard_ids=decoder.guard_ids[name])
    return decoder, frame


def change_word(profile, values, index, value, address=None):
    field = profile['fields'][index]
    guard = next(g for g in profile['guards'] if g['address'] == field['address'])
    guard['bytes_hex'] = value.to_bytes(4, 'little').hex()
    if address is not None:
        guard['address'] = field['address'] = address
    values[field['name']] = value if value < 2**31 else value - 2**32


class RelationsTests(unittest.TestCase):
    def setUp(self):
        self.profile, self.values = fixture()
        self.decoder, self.frame = prepare(self.profile, self.values)

    def row(self, frame=None):
        return self.decoder.project(frame or self.frame)['relations'][0]

    def test_observes_signed_words_without_gameplay_claims(self):
        result = self.decoder.project(self.frame)
        self.assertEqual(result['relations'][0]['relation_status'], 'observed')
        self.assertEqual(result['relations'][0]['evidence'][0]['value'], 0x80000001)
        for flag in ('atomic', 'public_state_eligible', 'participant_identity_validated', 'continuity_across_gaps'):
            self.assertIs(result[flag], False)
        self.assertEqual(result['visibility'], 'unknown')
        self.assertEqual(result['timing']['start_ticks'], 10)
        self.assertNotIn('address', json.dumps(result))

    def test_replacement_body_changes_only_body_key(self):
        first = self.row()
        change_word(self.profile, self.values, 2, 0x80000090)
        change_word(self.profile, self.values, 3, 0x80000091, 0x9000)
        change_word(self.profile, self.values, 4, 0x80000090, 0x9008)
        decoder, frame = prepare(self.profile, self.values)
        second = decoder.project(frame)['relations'][0]
        self.assertEqual(first['controller_object_key'], second['controller_object_key'])
        self.assertNotEqual(first['body_object_key'], second['body_object_key'])

    def test_controller_generation_storage_and_target_scope_keys(self):
        initial = self.row()['controller_object_key']
        for mode in ('generation', 'storage', 'pid', 'creation_file_time', 'executable_sha256'):
            profile, values = fixture()
            if mode == 'generation':
                change_word(profile, values, 0, 0x81000001)
            elif mode == 'storage':
                change_word(profile, values, 0, 0x80000001, 0x7000)
            elif mode == 'executable_sha256':
                profile['target'][mode] = 'cd' * 32
            else:
                profile['target'][mode] += 1
            decoder, frame = prepare(profile, values)
            self.assertNotEqual(initial, decoder.project(frame)['relations'][0]['controller_object_key'], mode)

    def test_no_identity_carried_across_gap(self):
        self.assertEqual(self.row()['relation_status'], 'observed')
        self.frame['fields'] = {}
        self.assertIsNone(self.row()['controller_object_key'])
        self.assertIsNone(self.row()['body_object_key'])

    def test_unknown_body_preserves_controller(self):
        self.frame['fields'].pop('controller_0000' + SUFFIXES[4])
        self.assertIsNotNone(self.row()['controller_object_key'])
        self.assertIsNone(self.row()['body_object_key'])
        self.assertEqual(self.row()['relation_status'], 'unknown')

    def test_mismatched_relation_rejected_even_when_each_word_guarded(self):
        change_word(self.profile, self.values, 4, 0x80000099)
        decoder, frame = prepare(self.profile, self.values)
        self.assertEqual(decoder.project(frame)['relations'][0]['reason'], 'body_key_mismatch')

    def test_wrong_value_or_unknown_word_fails_closed(self):
        name = 'controller_0000' + SUFFIXES[0]
        for patch in ({'value': 1}, {'value': True}, {'value': 2**31}, {'status': 'unknown'}, {'type': 'f32'}):
            frame = copy.deepcopy(self.frame)
            frame['fields'][name].update(patch)
            self.assertIsNone(self.row(frame)['controller_object_key'])

    def test_exact_profile_target_schema_required(self):
        for mutation in ('hash', 'target', 'schema', 'source'):
            frame = copy.deepcopy(self.frame)
            if mutation == 'hash': frame['profile_sha256'] = '00' * 32
            elif mutation == 'target': frame['target']['pid'] += 1
            else: frame[mutation] = 'wrong'
            self.assertIsNone(self.row(frame)['controller_object_key'])

    def test_before_and_after_dependencies_must_pass_and_bracket_read(self):
        for phase in ('before', 'after'):
            for patch in ({'ok': False}, {'error': 'denied'}, {'start_ticks': 200}, {'end_ticks': 0}):
                frame = copy.deepcopy(self.frame)
                frame['guards_' + phase][-1].update(patch)
                self.assertIsNone(self.row(frame)['controller_object_key'])
        self.frame['fields']['controller_0000' + SUFFIXES[0]]['guard_ids'] = []
        self.assertEqual(self.row()['reason'], 'guard_dependencies_mismatch')

    def test_guard_checks_cannot_be_missing(self):
        del self.frame['guards_after']
        self.assertEqual(self.row()['reason'], 'missing_guard_checks')

    def test_read_and_frame_brackets_are_ordered(self):
        for a, b in ((41, 40), (0, 40), (30, 101), (True, 40)):
            frame = copy.deepcopy(self.frame)
            frame['fields']['controller_0000' + SUFFIXES[0]].update(read_start_ticks=a, read_end_ticks=b)
            self.assertEqual(self.row(frame)['reason'], 'invalid_read_bracket')
        self.frame['end_ticks'] = 9
        self.assertEqual(self.row()['reason'], 'invalid_frame_bracket')

    def test_full_identity_guard_required_and_conflicts_fail(self):
        self.profile['guards'][0]['bytes_hex'] = '0100'
        decoder, frame = prepare(self.profile, self.values)
        self.assertEqual(decoder.project(frame)['relations'][0]['reason'], 'identity_word_not_guarded')
        self.profile['guards'][0]['bytes_hex'] = '01000080'
        self.profile['guards'].append(dict(address=0x1001, bytes_hex='ff'))
        decoder, frame = prepare(self.profile, self.values)
        self.assertEqual(decoder.project(frame)['relations'][0]['reason'], 'conflicting_identity_guards')

    def test_field_local_guards_deduplicate_like_native_recorder(self):
        guards = self.profile.pop('guards')
        for field, guard in zip(self.profile['fields'], guards):
            field['guards'] = [guard, guard.copy()]
        decoder, frame = prepare(self.profile, self.values)
        self.assertEqual(len(decoder.guards), 5)
        self.assertEqual(decoder.project(frame)['relations'][0]['relation_status'], 'observed')

    def test_duplicate_handles_are_ambiguous(self):
        for duplicate_index, reason in ((0, 'ambiguous_controller_handle'), (3, 'ambiguous_body_handle')):
            profile, values = fixture(rows=2)
            change_word(profile, values, 5 + duplicate_index, (0x80000001, 0, 0, 0x80000030)[duplicate_index])
            decoder, frame = prepare(profile, values)
            rows = decoder.project(frame)['relations']
            self.assertEqual([row['reason'] for row in rows], [reason, reason])
            self.assertTrue(all(row['body_object_key'] is None for row in rows))

    def test_duplicate_json_or_field_labels_rejected(self):
        with self.assertRaises(InvalidBinding):
            GuardedRelations(b'{"schema":1,"schema":2}')
        self.profile['fields'].append(self.profile['fields'][0].copy())
        with self.assertRaises(InvalidBinding):
            prepare(self.profile, self.values)

    def test_dynamic_bindings_cannot_substitute_for_guarded_address(self):
        self.profile['fields'][0]['path_id'] = 0
        decoder, frame = prepare(self.profile, self.values)
        self.assertEqual(decoder.project(frame)['relations'][0]['reason'], 'unsupported_word_binding')


if __name__ == '__main__':
    unittest.main()
