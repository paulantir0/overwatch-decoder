"""Synthetic account matching; no game data or local account values."""
import copy
import json
import unittest

from account_anchor import GuardedAccountAnchor, InvalidAccountAnchor, sha
from test_relations import fixture, prepare, change_word

TOKEN = bytes(range(1, 17))
OTHER = bytes(range(17, 33))


def account_fixture(tokens=(TOKEN,)):
    profile, values = fixture(len(tokens))
    for row, token in enumerate(tokens):
        if token is None:
            continue
        address = 0x5000 + row*32
        profile['guards'].append(dict(address=address, bytes_hex=token.hex()))
        for index in range(4):
            name = f'controller_{row:04d}_part36_0000_account_word{index}_candidate_i32'
            profile['fields'].append(dict(name=name, type='i32', address=address+4*index))
            value = int.from_bytes(token[4*index:4*index+4], 'little', signed=True)
            values[name] = value
    _, frame = prepare(profile, values)
    return profile, values, frame


def anchor_fixture():
    profile, _, frame = account_fixture()
    source_profile, source_frame = json.dumps(profile).encode(), json.dumps(frame).encode()
    source_key = prepare(profile, {k: v['value'] for k, v in frame['fields'].items()})[0].project(frame)['relations'][0]['controller_object_key']
    review_source = b'Synthetic explicit account review evidence.'
    common = dict(target=profile['target'], source_profile_sha256=sha(source_profile),
                  source_frame_sha256=sha(source_frame), source_controller_object_key=source_key)
    review = dict(common, schema='overwatch-decoder.account-anchor-review/1', reviewed=True,
                  review_method='explicit_local_player_account_binding', sources=[sha(review_source)])
    review_raw = json.dumps(review).encode()
    anchor = dict(common, schema='overwatch-decoder.reviewed-account-anchor/1', review_sha256=sha(review_raw))
    artifacts = {sha(raw): raw for raw in (source_profile, source_frame, review_raw, review_source)}
    return json.dumps(anchor).encode(), artifacts


class AccountAnchorTests(unittest.TestCase):
    def setUp(self):
        self.anchor, self.artifacts = anchor_fixture()

    def decoder(self, profile):
        return GuardedAccountAnchor(json.dumps(profile).encode(), self.anchor, self.artifacts)

    def test_new_controller_same_account_matches_without_name_or_hero(self):
        profile, values, _ = account_fixture((OTHER, TOKEN, None))
        change_word(profile, values, 5, 0x80000202)
        _, frame = prepare(profile, values)
        result = self.decoder(profile).project(frame)
        self.assertEqual(result['status'], 'anchored_account_match')
        self.assertEqual(result['account_candidate_count'], 2)
        self.assertEqual(result['matching_candidate_count'], 1)
        self.assertEqual(len(result['undeclared_controller_keys']), 1)
        self.assertNotEqual(result['controller_object_key'], json.loads(self.anchor)['source_controller_object_key'])
        for flag in ('public_state_eligible', 'local_ownership_validated', 'complete_account_census_validated', 'continuity_across_gaps'):
            self.assertFalse(result[flag])
        output = json.dumps(result)
        self.assertNotIn(TOKEN.hex(), output)
        self.assertNotIn(sha(TOKEN), output)
        self.assertNotIn('account_token', output)
        self.assertNotIn('address', output)
        self.assertEqual(len(result['evidence']), 4)
        self.assertEqual(len(result['controller_evidence']), 2)

    def test_zero_and_duplicate_matches_are_unknown(self):
        for tokens, reason in [((OTHER,), 'no_account_match'), ((TOKEN, TOKEN), 'ambiguous_account_match'),
                               ((None,), 'no_account_match')]:
            profile, _, frame = account_fixture(tokens)
            result = self.decoder(profile).project(frame)
            self.assertEqual(result['reason'], reason)
            self.assertIsNone(result['controller_object_key'])

    def test_missing_or_partial_candidate_prevents_unique_claim(self):
        profile, values, frame = account_fixture((TOKEN, OTHER))
        frame['fields']['controller_0001_part36_0000_account_word2_candidate_i32']['status'] = 'unknown'
        result = self.decoder(profile).project(frame)
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['controller_object_key'])
        profile['fields'] = [x for x in profile['fields'] if x['name'] != 'controller_0001_part36_0000_account_word2_candidate_i32']
        values.pop('controller_0001_part36_0000_account_word2_candidate_i32')
        _, frame = prepare(profile, values)
        self.assertEqual(self.decoder(profile).project(frame)['reason'], 'partial_account_declaration')

    def test_full_token_guard_and_contiguous_storage_required(self):
        for mode in ('guard', 'address', 'extra'):
            profile, values, _ = account_fixture()
            if mode == 'guard':
                profile['guards'][-1]['bytes_hex'] = TOKEN[:12].hex()
            elif mode == 'address':
                profile['fields'][-1]['address'] += 32
                profile['guards'].append(dict(address=profile['fields'][-1]['address'], bytes_hex=TOKEN[12:].hex()))
            else:
                extra = copy.deepcopy(profile['fields'][-1]); extra['name'] = extra['name'].replace('part36_0000', 'part36_0001')
                profile['fields'].append(extra); values[extra['name']] = values[profile['fields'][-2]['name']]
            _, frame = prepare(profile, values)
            self.assertEqual(self.decoder(profile).project(frame)['status'], 'unknown', mode)

    def test_bad_guard_value_dependency_and_bracket_unknown(self):
        profile, _, original = account_fixture()
        decoder = self.decoder(profile)
        for mode in ('guard', 'value', 'ids', 'bracket', 'target'):
            frame = copy.deepcopy(original)
            sample = frame['fields']['controller_0000_part36_0000_account_word0_candidate_i32']
            if mode == 'guard': frame['guards_after'][0]['ok'] = False
            elif mode == 'value': sample['value'] += 1
            elif mode == 'ids': sample['guard_ids'] = []
            elif mode == 'bracket': sample['read_start_ticks'] = 0
            else: frame['target']['creation_file_time'] += 1
            result = decoder.project(frame)
            self.assertEqual(result['status'], 'unknown', mode)
            self.assertIsNone(result['controller_object_key'])

    def test_gap_and_cancellation_no_carry(self):
        profile, _, frame = account_fixture()
        decoder = self.decoder(profile)
        self.assertEqual(decoder.project(frame)['status'], 'anchored_account_match')
        self.assertEqual(decoder.project(frame, gap=True)['reason'], 'gap_before_frame')
        frame['skipped_intervals_before'] = 1
        self.assertEqual(decoder.project(frame)['reason'], 'gap_before_frame')
        frame['skipped_intervals_before'] = 0
        frame['fields'] = {}
        self.assertIsNone(decoder.project(frame)['controller_object_key'])

    def test_missing_body_does_not_erase_independent_account(self):
        profile, _, frame = account_fixture()
        frame['fields'].pop('controller_0000_body_0000_manager_key_candidate_i32')
        result = self.decoder(profile).project(frame)
        self.assertEqual(result['status'], 'anchored_account_match')
        self.assertIsNone(result['body_object_key'])

    def test_review_process_and_artifact_pins_required(self):
        profile, _, _ = account_fixture()
        profile['target']['pid'] += 1
        with self.assertRaisesRegex(InvalidAccountAnchor, 'process_epoch'):
            self.decoder(profile)
        profile, _, _ = account_fixture()
        artifacts = dict(self.artifacts)
        review_key = json.loads(self.anchor)['review_sha256']
        artifacts[review_key] += b' '
        with self.assertRaisesRegex(InvalidAccountAnchor, 'artifact_hash'):
            GuardedAccountAnchor(json.dumps(profile).encode(), self.anchor, artifacts)
        review = json.loads(self.artifacts[review_key]); review['reviewed'] = False
        raw = json.dumps(review).encode(); artifacts[sha(raw)] = raw
        anchor = json.loads(self.anchor); anchor['review_sha256'] = sha(raw)
        with self.assertRaisesRegex(InvalidAccountAnchor, 'unreviewed_anchor'):
            GuardedAccountAnchor(json.dumps(profile).encode(), json.dumps(anchor).encode(), artifacts)

    def test_unobserved_anchor_cannot_seed_future_match(self):
        profile, _, _ = account_fixture()
        anchor = json.loads(self.anchor); artifacts = dict(self.artifacts)
        source = json.loads(artifacts[anchor['source_frame_sha256']]); source['guards_before'][0]['ok'] = False
        raw = json.dumps(source).encode(); artifacts[sha(raw)] = raw
        review = json.loads(artifacts[anchor['review_sha256']]); review['source_frame_sha256'] = sha(raw)
        reviewed = json.dumps(review).encode(); artifacts[sha(reviewed)] = reviewed
        anchor.update(source_frame_sha256=sha(raw), review_sha256=sha(reviewed))
        with self.assertRaisesRegex(InvalidAccountAnchor, 'controller_unknown'):
            GuardedAccountAnchor(json.dumps(profile).encode(), json.dumps(anchor).encode(), artifacts)

    def test_zero_account_is_not_an_anchor(self):
        profile, _, frame = account_fixture((bytes(16),))
        self.assertEqual(self.decoder(profile).project(frame)['reason'], 'zero_account_token')


if __name__ == '__main__':
    unittest.main()
