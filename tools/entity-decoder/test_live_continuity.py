"""Synthetic epoch transitions; these do not establish game respawn behavior."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from live_relations import InvalidLive, LiveRelations
from test_live_relations import SESSION, event, live, raw, setup, start
from test_relations import change_word, prepare


def epoch(root, ordinal, *, replacement_body=False, replacement_controller=False):
    """Publish a fresh acquisition and distinctly sampled values for each epoch."""
    root.mkdir()
    profile, template, manifest, contracts = setup(root, health=True)
    values = {name: sample['value'] for name, sample in template['fields'].items()}
    if replacement_body:
        change_word(profile, values, 2, 0x80000090)
        change_word(profile, values, 3, 0x80000091, 0x9000)
        change_word(profile, values, 4, 0x80000090, 0x9008)
    if replacement_controller:
        change_word(profile, values, 1, 0x80000099)
    values['controller_0000_body_0000_position_candidate'] = [ordinal * 10., 0., 0.]
    values['controller_0000_body_0000_pool_0000_direct_candidate'] = 100. / ordinal
    decoder, frame = prepare(profile, values)
    frame.update({key: copy.deepcopy(value) for key, value in template.items()
                  if key not in ('profile_sha256', 'fields', 'guards_before', 'guards_after')})
    # The new native epoch resets its frame sequence and owns its clock anchor.
    delta = ordinal * 1000
    for key in ('start_ticks', 'end_ticks', 'scheduled_ticks', 'monotonic_origin_ticks', 'utc_origin_before_ticks'):
        frame[key] += delta
    for phase in ('guards_before', 'guards_after'):
        for check in frame[phase]:
            check['start_ticks'] += delta
            check['end_ticks'] += delta
    for name, sample in frame['fields'].items():
        sample.update(type=decoder.fields[name]['type'], reason=None)
        sample['read_start_ticks'] += delta
        sample['read_end_ticks'] += delta
    profile_raw = json.dumps(profile).encode()
    evidence = raw(dict(kind='synthetic_epoch', ordinal=ordinal))
    manifest.update(profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
                    evidence_sha256=hashlib.sha256(evidence).hexdigest())
    for filename, data in [('profile.json', profile_raw), ('evidence.jsonl', evidence),
                           ('manifest.json', raw(manifest))]:
        (root / filename).write_bytes(data)
    descriptor = json.loads(contracts[0].read_bytes())
    descriptor['acquisition_evidence_sha256'] = manifest['evidence_sha256']
    contracts[0].write_bytes(raw(descriptor))
    return profile, frame, manifest, contracts


def begin(profile, manifest, ordinal, index):
    result = start(profile, manifest)
    result.update(segment=ordinal, event_sequence=index, emitted_ticks=ordinal * 1000 + 200)
    return result


def sample(frame, ordinal, index):
    result = live(frame, index)
    result.update(segment=ordinal, emitted_ticks=ordinal * 1000 + 300)
    return result


class LiveContinuityTests(unittest.TestCase):
    def test_fresh_epoch_rebinds_same_controller_without_carrying_body_values(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            p1, f1, m1, c1 = epoch(base / 'first', 1)
            first = LiveRelations(base / 'first', SESSION, 1, health_contracts=c1)
            first.consume(raw(begin(p1, m1, 1, 0)))
            row1 = first.consume(raw(sample(f1, 1, 1)))['relations'][0]
            end = event('segment_end', 2, segment=dict(ordinal=1))
            end['emitted_ticks'] = 1400
            first.consume(raw(end))
            p2, f2, m2, c2 = epoch(base / 'second', 2, replacement_body=True)
            with self.assertRaisesRegex(InvalidLive, 'reconfiguration'):
                first.consume(raw(begin(p2, m2, 2, 3)))
            with self.assertRaisesRegex(InvalidLive, 'health_acquisition_mismatch'):
                LiveRelations(base / 'second', SESSION, 2, health_contracts=c1)
            second = LiveRelations(base / 'second', SESSION, 2, health_contracts=c2)
            second.consume(raw(begin(p2, m2, 2, 3)))
            output = second.consume(raw(sample(f2, 2, 4)))
            row2 = output['relations'][0]
            self.assertEqual(row1['controller_object_key'], row2['controller_object_key'])
            self.assertNotEqual(row1['body_object_key'], row2['body_object_key'])
            self.assertEqual(row2['position_candidate']['value'], [20., 0., 0.])
            self.assertEqual(row2['health_candidate']['raw_sum'], 50.)
            self.assertEqual(row2['health_candidate']['body_object_key'], row2['body_object_key'])
            self.assertEqual(output['source_artifacts']['acquisition']['evidence_sha256'], m2['evidence_sha256'])
            self.assertEqual(output['segment'], 2)
            self.assertFalse(output['continuity_across_gaps'])
            self.assertFalse(output['durability_verified'])
            self.assertFalse(output['public_state_eligible'])

    def test_missing_new_body_does_not_reuse_previous_body_or_values(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            p1, f1, m1, c1 = epoch(base / 'first', 1)
            first = LiveRelations(base / 'first', SESSION, 1, health_contracts=c1)
            first.consume(raw(begin(p1, m1, 1, 0)))
            row1 = first.consume(raw(sample(f1, 1, 1)))['relations'][0]
            p2, f2, m2, c2 = epoch(base / 'second', 2, replacement_body=True)
            f2['fields']['controller_0000_body_0000_manager_key_candidate_i32'].update(
                status='unknown', value=None, reason='synthetic_read_failed',
                read_start_ticks=None, read_end_ticks=None)
            second = LiveRelations(base / 'second', SESSION, 2, health_contracts=c2)
            second.consume(raw(begin(p2, m2, 2, 3)))
            row2 = second.consume(raw(sample(f2, 2, 4)))['relations'][0]
            self.assertEqual(row1['controller_object_key'], row2['controller_object_key'])
            self.assertEqual(row2['relation_status'], 'unknown')
            for name in ('body_object_key', 'position_candidate', 'health_candidate'):
                self.assertIsNone(row2[name], name)

    def test_replaced_controller_is_not_same_identity_despite_same_ordinal(self):
        with tempfile.TemporaryDirectory() as temp:
            rows = []
            for ordinal in (1, 2):
                root = Path(temp) / str(ordinal)
                p, f, m, c = epoch(root, ordinal, replacement_controller=ordinal == 2)
                adapter = LiveRelations(root, SESSION, ordinal, health_contracts=c)
                adapter.consume(raw(begin(p, m, ordinal, 0)))
                rows.append(adapter.consume(raw(sample(f, ordinal, 1)))['relations'][0])
            self.assertEqual(rows[0]['controller_prefix'], rows[1]['controller_prefix'])
            self.assertNotEqual(rows[0]['controller_object_key'], rows[1]['controller_object_key'])


if __name__ == '__main__':
    unittest.main()
