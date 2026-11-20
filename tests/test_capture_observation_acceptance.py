import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from incoming_observation_fixture import incoming_fixture

spec=importlib.util.spec_from_file_location('acceptance',Path(__file__).resolve().parents[1]/'scripts/verify_capture_observations.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class AcceptanceTests(unittest.TestCase):
    def fixture(self,root):
        window=root/'observations/window-0001';window.mkdir(parents=True)
        raw=(json.dumps(dict(schema='overwatch-decoder.private.selected-compact/1',source='process_memory',scope='configured_controller_window',timestamp=dict(start_ticks=100,end_ticks=101,monotonic_frequency=1000),observed_build_sha256='a'*64,entities=[dict(entity_id='owned-fixture',position=[1,2,3],position_validation='fixture_only')]))+'\n').encode()
        (window/'game-state.jsonl').write_bytes(raw)
        result=dict(schema='overwatch-decoder.private.combined-run/1',status='complete',output_sha256=hashlib.sha256(raw).hexdigest(),output_rows=1,output_bytes=len(raw),capture_scope='read_only_user_gameplay',error=None,cleanup_errors=[])
        (window/'result.json').write_text(json.dumps(result))
        rows=[dict(kind='observation_receipt',window=1,qpc_ticks=110,receipt=dict(source_offset=0,source_bytes=len(raw),source_sha256=hashlib.sha256(raw).hexdigest())),dict(kind='observation_window_end',window=1),dict(kind='journal_end')]
        with gzip.open(root/'events.jsonl.gz','wt') as stream:
            for row in rows:stream.write(json.dumps(row)+'\n')
        manifest=dict(schema='overwatch-decoder.capture-session/1',status='finished',synthetic_fixture=True,qpc_origin=0,qpc_frequency=1000,observations=dict(capture_scope='read_only_user_gameplay',completed_windows=1,error=None),journal=dict(dropped=0),video=dict(source_pts_bounds_valid=True,source_clock_build_verified=False))
        (root/'session.json').write_text(json.dumps(manifest));(root/'desktop.mkv').write_bytes(b'explicit fixture, not verified media')
        return window,result
    def test_exact_receipts_and_scope(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);report=M.verify(root,require_complete_window=True)
            self.assertEqual(report['verified_receipts'],1);self.assertEqual(report['observation_counts']['entities'],1)
            self.assertAlmostEqual(report['receipt_delay_seconds_max'],.009);self.assertFalse(report['exact_video_alignment']);self.assertIsNone(report['video_probe'])
    def test_source_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);window,_=self.fixture(root);source=window/'game-state.jsonl';source.write_bytes(source.read_bytes().replace(b'100',b'200'))
            with self.assertRaises(ValueError):M.verify(root)
    def test_wrong_mode_and_partial_never_count_as_complete(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);window,result=self.fixture(root);result['capture_scope']='controlled_practice';(window/'result.json').write_text(json.dumps(result))
            with self.assertRaises(ValueError):M.verify(root)
            result['capture_scope']='read_only_user_gameplay';result['status']='partial';(window/'result.json').write_text(json.dumps(result))
            with self.assertRaises(ValueError):M.verify(root,require_complete_window=True)

    def test_flat_incoming_receipt_schema_allowlist(self):
        receipt=dict(source_schema='overwatch-decoder.private.incoming-source-observation/1', source_offset=0,
                     source_bytes=10, source_sha256='a'*64)
        self.assertEqual(M.journal_receipt(receipt,False)[0],'game-state.jsonl')
        receipt['source_schema']='invented.unsupported/1'
        with self.assertRaises(ValueError):M.journal_receipt(receipt,False)


class CohortAcceptanceTests(unittest.TestCase):
    def fixture(self, root, count=6, code=0, records=None, *, first_tick=100):
        from combined_storage import CombinedStorageWriter, encoded
        window = root/'observations/window-0001'
        window.mkdir(parents=True)
        if records is not None: count=len(records)
        writer = CombinedStorageWriter(window, maximum_cohort_bytes=8192 if records else 1400, maximum_total_bytes=131072,
            maximum_cohorts=32, maximum_index_bytes=16384, maximum_receipt_bytes=512)
        for sequence in range(count):
            start = first_tick + sequence*10
            raw = encoded(dict(schema='overwatch-decoder.private.selected-compact/1', kind='entity_updates',
                combined_sequence=sequence, source='process_memory', scope='configured_controller_window',
                capture_scope='read_only_user_gameplay', timestamp=dict(start_ticks=start, end_ticks=start+1,
                monotonic_frequency=1000), observed_build_sha256='a'*64,
                entities=[dict(entity_id='synthetic-only', position=[1, 2, 3], position_validation='fixture_only')]))
            end = start+1
            if records is not None:
                value=dict(records[sequence], combined_sequence=sequence, capture_scope='read_only_user_gameplay')
                raw=encoded(value);interval=value.get('read_interval') or value.get('timestamp');end=interval['end_ticks'] if interval else None
            writer.write_compact(raw, sequence)
            writer.commit_receipt(encoded(dict(combined_sequence=sequence, line_sha256=hashlib.sha256(raw).hexdigest(),
                frequency=1000, capture_end_qpc_ticks=end, before_write_qpc_ticks=(end if end is not None else start)+3,
                file_flushed_qpc_ticks=(end if end is not None else start)+4, capture_to_file_flush_ms=4 if end is not None else None,
                capture_scope='read_only_user_gameplay', durability_verified=False)))
        summary = writer.close(failed_start=count == 0)
        result = dict(summary, schema='overwatch-decoder.private.combined-run/2', status='complete' if code == 0 else 'partial',
            cli_exit_code=code, error=None, cleanup_errors=[], capture_scope='read_only_user_gameplay')
        self.save_result(window, result)
        manifest = dict(schema='overwatch-decoder.capture-session/1', status='finished' if code == 0 else 'finished_with_gaps',
            synthetic_fixture=True, fixture_note='Synthetic verifier fixture; no runtime/media evidence.',
            qpc_origin=0, qpc_frequency=1000, observations=dict(capture_scope='read_only_user_gameplay',
            storage_format='cohorts_v1', storage_cohort_mib=1, maximum_windows=1, sealed_storage_cohorts=summary['storage_cohorts'], maximum_output_bytes=128*1048576,
            receipt_rows=count, completed_windows=1, error=None), journal=dict(dropped=0),
            video=dict(source_pts_bounds_valid=True, source_clock_build_verified=False))
        (root/'session.json').write_text(json.dumps(manifest))
        (root/'desktop.mkv').write_bytes(b'SYNTHETIC PLACEHOLDER; NOT VERIFIED MEDIA')
        journal = []
        for ordinal in range(1, summary['storage_cohorts']+1):
            relative = f'cohort-{ordinal:06d}/game-state.jsonl'
            offset = 0
            for raw in (window/relative).read_bytes().splitlines(keepends=True):
                value = json.loads(raw)
                journal.append(dict(kind='observation_receipt', window=1,
                    qpc_ticks=((value.get('timestamp') or value.get('read_interval') or {}).get('end_ticks', 200))+9,
                    receipt=dict(source_schema=value['schema'], source_path=relative, storage_cohort=ordinal,
                    source_offset=offset, source_bytes=len(raw), source_sha256=hashlib.sha256(raw).hexdigest(),
                    combined_sequence=value['combined_sequence'], sealed_acceptance=False, durability_verified=False)))
                offset += len(raw)
        journal.append(dict(kind='observation_window_end', window=1))
        self.write_journal(root, journal)
        return window, result

    def test_incoming_observed_timed_unknown_and_untimed_unknown_receipts(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); self.fixture(root,records=[incoming_fixture(),incoming_fixture('unknown'),incoming_fixture('unknown',untimed=True),
                dict(schema='overwatch-decoder.private.selected-compact/1',source='process_memory',scope='configured_controller_window',
                    timestamp=dict(start_ticks=150,end_ticks=151,monotonic_frequency=1000),observed_build_sha256='a'*64,
                    entities=[dict(entity_id='synthetic-only',position=[1,2,3],position_validation='synthetic_only')])])
            report=M.verify(root,require_complete_window=True)
            self.assertEqual(report['verified_receipts'],4); self.assertEqual(report['verified_delivery_receipts'],4)
            counts=report['observation_counts']
            self.assertEqual(counts['incoming_source_observations'],1);self.assertEqual(counts['incoming_source_unknowns'],2)
            self.assertEqual(counts['damage'],0)
            self.assertEqual(report['receipt_delay_seconds_by_kind']['incoming_source_observed']['count'],1)

    def test_incoming_malformed_observed_source_is_not_transport_acceptance(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);row=incoming_fixture();row['unique_hit']=True
            self.fixture(root,records=[row])
            with self.assertRaisesRegex(ValueError,'unique_hit'):M.verify(root,require_complete_window=True)

    @staticmethod
    def save_result(window, result):
        (window/'result.json').write_text(json.dumps(result))

    @staticmethod
    def read_journal(root):
        with gzip.open(root/'events.jsonl.gz', 'rt') as stream:
            return [json.loads(raw) for raw in stream if json.loads(raw)['kind'] != 'journal_end']

    @staticmethod
    def write_journal(root, rows):
        with gzip.open(root/'events.jsonl.gz', 'wt') as stream:
            for row in rows:
                stream.write(json.dumps(row)+'\n')
            stream.write(json.dumps(dict(kind='journal_end', written=len(rows), dropped=0, qpc_ticks=500))+'\n')
        manifest = json.loads((root/'session.json').read_bytes())
        manifest['journal']['written'] = len(rows)
        (root/'session.json').write_text(json.dumps(manifest))

    def reseal(self, window, result):
        from combined_storage import encoded
        previous = None; index = bytearray()
        for raw in (window/'storage-index.jsonl').read_bytes().splitlines():
            row = json.loads(raw); row['previous_seal_sha256'] = previous
            if row['kind'] == 'seal':
                for file in row['files']:
                    data = (window/row['directory']/file['path']).read_bytes()
                    file.update(bytes=len(data), rows=data.count(b'\n'), sha256=hashlib.sha256(data).hexdigest())
            line = encoded(row); index.extend(line)
            if row['kind'] == 'seal': previous = hashlib.sha256(line).hexdigest()
        (window/'storage-index.jsonl').write_bytes(index)
        reader = M.CombinedStorageIndex(window, maximum_cohorts=32, maximum_total_bytes=131072,
            maximum_index_bytes=16384, maximum_cohort_bytes=1048576)
        for raw in bytes(index).splitlines(keepends=True): reader.consume(raw)
        result.update(reader.complete()); self.save_result(window, result)

    def repeat_fixture(self, root):
        first, _ = self.fixture(root, count=1)
        staging = root/'other'
        second, _ = self.fixture(staging, count=1, first_tick=300)
        second.rename(first.parent/'window-0002')
        receipt1, _ = self.read_journal(root)
        receipt2, _ = self.read_journal(staging)
        receipt2['window'] = 2
        manifest = json.loads((root/'session.json').read_bytes())
        manifest.update(last_update_qpc=500, target_pid=42, target_start_utc_ticks=10)
        manifest['journal'].update(file='events.jsonl.gz', error=None)
        manifest['observations'].update(repeat_windows=True, maximum_windows=2, attempted_windows=2,
            completed_windows=2, accepted_window_numbers=[1, 2], sealed_storage_cohorts=2, receipt_rows=2)
        (root/'session.json').write_text(json.dumps(manifest))
        rows = [dict(kind='session_start', schema='overwatch-decoder.capture-session/1', qpc_origin=0,
                     qpc_frequency=1000, target_pid=42, target_start_utc_ticks=10)]
        for n, tick, receipt in [(1, 50, receipt1), (2, 250, receipt2)]:
            rows.extend([dict(kind='observation_window_start', window=n, qpc_ticks=tick,
                capture_scope='read_only_user_gameplay', continuity_from_previous=False), receipt,
                dict(kind='observation_window_end', window=n, qpc_ticks=tick+100, accepted=True,
                     producer_exit_code=0, continuity_to_next=False)])
        self.write_journal(root, rows)
        return rows

    def test_verified_repeat_cohorts_allow_per_window_sequence_restart(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.repeat_fixture(root)
            report = M.verify(root, require_complete_window=True)
            self.assertEqual(report['verified_receipts'], 2)
            self.assertEqual(report['verified_delivery_receipts'], 2)
            self.assertEqual([w['window'] for w in report['windows']], [1, 2])
            self.assertFalse(report['full_match_coverage_verified'])

    def test_repeat_cohorts_reject_unadmitted_or_misclocked_receipts(self):
        for mode in ('unadmitted', 'misclocked', 'wrong-terminal'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d); rows = self.repeat_fixture(root)
                if mode == 'unadmitted':
                    rows.pop()
                elif mode == 'misclocked':
                    rows[-2]['qpc_ticks'] = 400
                else:
                    rows[-1]['producer_exit_code'] = 7
                self.write_journal(root, rows)
                with self.assertRaises(ValueError):
                    M.verify(root)

    def test_multiple_cohorts_reset_offsets_but_keep_global_sequence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); window, _ = self.fixture(root)
            report = M.verify(root, require_complete_window=True)
            self.assertEqual(report['verified_receipts'], 6)
            self.assertEqual(report['verified_delivery_receipts'], 6)
            self.assertEqual(report['receipt_delay_seconds_by_kind']['entities_nonempty']['count'], 6)
            self.assertAlmostEqual(report['receipt_delay_seconds_by_kind']['entities_nonempty']['p95'], .009)
            self.assertGreater(report['windows'][0]['sealed_storage_cohorts'], 1)
            self.assertEqual(report['storage_format'], 'cohorts_v1')
            self.assertTrue(report['synthetic_fixture'])
            self.assertFalse(report['storage_rotation_establishes_continuity'])
            self.assertFalse(report['full_match_coverage_verified'])
            self.assertIsNone(report['video_probe'])

    def test_recorder_sibling_log_is_not_a_window(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.fixture(root)
            (root/'observations/window-0001.log').write_text('Synthetic producer diagnostics')
            self.assertEqual(M.verify(root)['verified_receipts'], 6)

    def test_partial_result_is_preserved_but_never_complete(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.fixture(root, code=7)
            self.assertEqual(M.verify(root)['windows'][0]['status'], 'partial')
            with self.assertRaisesRegex(ValueError, 'no fully complete'):
                M.verify(root, require_complete_window=True)

    def test_recorder_receipt_identity_faults_rejected(self):
        for mode in ['duplicate', 'missing', 'path', 'cohort', 'sequence', 'offset', 'bytes', 'hash', 'schema',
                     'sealed', 'durability', 'missing-schema', 'missing-path', 'missing-cohort', 'missing-sequence', 'wrong-window']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d); self.fixture(root); rows = self.read_journal(root); receipt = rows[0]['receipt']
                if mode == 'duplicate': rows.insert(1, dict(rows[0]))
                elif mode == 'missing': rows.pop(0)
                elif mode == 'path': receipt['source_path'] = '../game-state.jsonl'
                elif mode == 'cohort': receipt['storage_cohort'] += 1
                elif mode == 'sequence': receipt['combined_sequence'] += 1
                elif mode == 'offset': receipt['source_offset'] += 1
                elif mode == 'bytes': receipt['source_bytes'] += 1
                elif mode == 'hash': receipt['source_sha256'] = '0'*64
                elif mode == 'schema': receipt['source_schema'] = 'unsupported'
                elif mode == 'sealed': receipt['sealed_acceptance'] = True
                elif mode == 'durability': receipt['durability_verified'] = True
                elif mode.startswith('missing-'): receipt.pop({'missing-schema':'source_schema', 'missing-path':'source_path', 'missing-cohort':'storage_cohort', 'missing-sequence':'combined_sequence'}[mode])
                elif mode == 'wrong-window': rows[0]['window'] = 2
                self.write_journal(root, rows)
                with self.assertRaises(ValueError): M.verify(root)

    def test_format_faults_rejected(self):
        for mode in ['missing-declaration', 'unknown', 'flat-and-index', 'missing-index', 'missing-both', 'flat-declared', 'orphan-cohort', 'two-window-plan', 'manifest-cohort-count']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d); window, _ = self.fixture(root)
                manifest = json.loads((root/'session.json').read_bytes())
                if mode == 'missing-declaration': manifest['observations'].pop('storage_format')
                if mode == 'two-window-plan': manifest['observations']['maximum_windows'] = 2
                if mode == 'manifest-cohort-count': manifest['observations']['sealed_storage_cohorts'] = 99
                if mode == 'unknown': manifest['observations']['storage_format'] = 'future'
                if mode == 'flat-declared': manifest['observations']['storage_format'] = 'flat_v1'
                if mode == 'flat-and-index': (window/'game-state.jsonl').write_bytes(b'\n')
                if mode in ('missing-index', 'missing-both'): (window/'storage-index.jsonl').unlink()
                if mode == 'orphan-cohort': (window/'cohort-000999').mkdir()
                (root/'session.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError): M.verify(root)

    def test_result_and_seal_faults_rejected(self):
        for mode in ['scope', 'rows', 'bytes', 'sha', 'index-sha', 'index-count', 'cohort-count', 'receipt-bytes',
                     'code', 'schema', 'provisional', 'missing-provisional', 'missing-scope', 'missing-error', 'cleanup', 'error', 'missing', 'unsealed', 'seal-hash', 'data-hash']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d); window, result = self.fixture(root)
                if mode == 'scope': result['capture_scope'] = 'controlled_practice'
                if mode == 'rows': result['output_rows'] += 1
                if mode == 'bytes': result['output_bytes'] += 1
                if mode == 'sha': result['output_sha256'] = '0'*64
                if mode == 'index-sha': result['storage_index_sha256'] = '0'*64
                if mode == 'index-count': result['storage_index_records'] += 1
                if mode == 'cohort-count': result['storage_cohorts'] += 1
                if mode == 'receipt-bytes': result['delivery_receipt_bytes'] += 1
                if mode == 'code': result['cli_exit_code'] = 7
                if mode == 'schema': result['schema'] = 'overwatch-decoder.private.combined-run/1'
                if mode == 'provisional': result['provisional_tail'] = True
                if mode == 'missing-provisional': result.pop('provisional_tail')
                if mode == 'missing-scope': result.pop('capture_scope')
                if mode == 'missing-error': result.pop('error')
                if mode == 'cleanup': result['cleanup_errors'] = ['fixture']
                if mode == 'error': result['error'] = 'fixture'
                self.save_result(window, result)
                if mode == 'missing': (window/'result.json').unlink()
                if mode == 'unsealed':
                    p = window/'storage-index.jsonl'; p.write_bytes(b''.join(p.read_bytes().splitlines(keepends=True)[:-1]))
                if mode == 'seal-hash':
                    p = window/'storage-index.jsonl'; p.write_bytes(p.read_bytes().replace(b'"previous_seal_sha256":null', b'"previous_seal_sha256":"bad"', 1))
                if mode == 'data-hash':
                    p = window/'cohort-000001/game-state.jsonl'; p.write_bytes(p.read_bytes().replace(b'synthetic-only', b'SYNTHETIC-only'))
                with self.assertRaises((ValueError, FileNotFoundError)): M.verify(root)

    def test_delivery_clock_faults_after_valid_resealing(self):
        for mode in ['frequency', 'before', 'after', 'capture', 'delay', 'scope']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d); window, result = self.fixture(root)
                p = window/'cohort-000001/delivery-receipts.jsonl'; receipt = json.loads(p.read_bytes())
                if mode == 'frequency': receipt['frequency'] = 2000
                if mode == 'before': receipt['before_write_qpc_ticks'] = 999
                if mode == 'after': receipt['file_flushed_qpc_ticks'] = 1
                if mode == 'capture': receipt['capture_end_qpc_ticks'] = 0
                if mode == 'delay': receipt['capture_to_file_flush_ms'] = 0
                if mode == 'scope': receipt['capture_scope'] = 'controlled_practice'
                from combined_storage import encoded
                p.write_bytes(encoded(receipt)); self.reseal(window, result)
                with self.assertRaises(ValueError): M.verify(root)

    def test_writer_after_marker_is_not_recorder_causal_floor(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.fixture(root); rows = self.read_journal(root)
            for row in rows:
                if row['kind'] == 'observation_receipt': row['qpc_ticks'] -= 6
            self.write_journal(root, rows)
            self.assertEqual(M.verify(root)['reader_before_writer_after_marker_rows'], 6)

    def test_empty_cohort_cannot_claim_success(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.fixture(root, count=0)
            with self.assertRaisesRegex(ValueError, 'no compact rows'): M.verify(root)

    def test_journal_and_flat_source_reads_are_bounded_before_parsing(self):
        for mode in ['journal', 'flat']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                if mode == 'flat':
                    window, _ = AcceptanceTests().fixture(root)
                    (window/'game-state.jsonl').write_bytes(b' '*(M.MAX_LINE+1)+b'\n')
                else:
                    self.fixture(root)
                    with gzip.open(root/'events.jsonl.gz', 'wb') as stream: stream.write(b' '*(M.MAX_LINE+1)+b'\n')
                with self.assertRaisesRegex(ValueError, 'line bound'): M.verify(root)

    def test_optional_saved_repack_has_explicitly_synthetic_journal(self):
        import os, shutil
        source = os.environ.get('OVERWATCH_DECODER_VERIFIER_STORAGE_FIXTURE')
        if not source: self.skipTest('Set OVERWATCH_DECODER_VERIFIER_STORAGE_FIXTURE to an offline /2 repack')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.fixture(root, count=0)
            target = root/'observations/window-0001'; shutil.rmtree(target); shutil.copytree(source, target)
            result = json.loads((target/'result.json').read_bytes()); journal = []; origin = frequency = None
            for cohort in sorted(target.glob('cohort-*')):
                offset = 0
                with (cohort/'game-state.jsonl').open('rb') as data, (cohort/'delivery-receipts.jsonl').open('rb') as proofs:
                    for raw, proof in zip(data, proofs):
                        value, proof = json.loads(raw), json.loads(proof); frequency = proof['frequency']
                        origin = min(origin if origin is not None else proof['before_write_qpc_ticks'], proof['before_write_qpc_ticks'])
                        journal.append(dict(kind='observation_receipt', window=1, qpc_ticks=proof['file_flushed_qpc_ticks']+1,
                            receipt=dict(source_schema=value['schema'], source_path=cohort.name+'/game-state.jsonl',
                            storage_cohort=int(cohort.name.split('-')[-1]), source_offset=offset, source_bytes=len(raw),
                            source_sha256=hashlib.sha256(raw).hexdigest(), combined_sequence=value['combined_sequence'],
                            sealed_acceptance=False, durability_verified=False)))
                        offset += len(raw)
            manifest = json.loads((root/'session.json').read_bytes()); manifest.update(qpc_origin=max(0,origin-frequency*60), qpc_frequency=frequency)
            manifest['observations'].update(receipt_rows=result['output_rows'], capture_scope=result['capture_scope'], storage_cohort_mib=16, sealed_storage_cohorts=result['storage_cohorts'])
            manifest['fixture_note'] = 'Original saved compact/delivery bytes; SYNTHETIC recorder receipts and placeholder media, NOT runtime acceptance.'
            (root/'session.json').write_text(json.dumps(manifest)); journal.append(dict(kind='observation_window_end',window=1)); self.write_journal(root,journal)
            report = M.verify(root, require_complete_window=True)
            self.assertTrue(report['synthetic_fixture']); self.assertIsNone(report['video_probe'])
            self.assertEqual(report['verified_receipts'], result['output_rows'])
            self.assertEqual(report['windows'][0]['sealed_storage_cohorts'], result['storage_cohorts'])

    def test_source_clock_and_declared_scope_faults(self):
        for mode in ['frequency', 'origin', 'reader', 'scope']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d); window, result = self.fixture(root)
                manifest = json.loads((root/'session.json').read_bytes())
                if mode == 'frequency': manifest['qpc_frequency'] = 2000
                if mode == 'origin': manifest['qpc_origin'] = 101
                (root/'session.json').write_text(json.dumps(manifest))
                if mode == 'reader':
                    rows = self.read_journal(root); rows[0]['qpc_ticks'] = 100; self.write_journal(root, rows)
                if mode == 'scope':
                    from combined_storage import encoded
                    p = window/'cohort-000001/game-state.jsonl'; value = json.loads(p.read_bytes())
                    value['capture_scope'] = 'controlled_practice'; raw = encoded(value); p.write_bytes(raw)
                    proof = window/'cohort-000001/delivery-receipts.jsonl'; value = json.loads(proof.read_bytes())
                    value['line_sha256'] = hashlib.sha256(raw).hexdigest(); proof.write_bytes(encoded(value))
                    self.reseal(window, result); rows = self.read_journal(root)
                    rows[0]['receipt'].update(source_bytes=len(raw), source_sha256=hashlib.sha256(raw).hexdigest())
                    self.write_journal(root, rows)
                with self.assertRaises(ValueError): M.verify(root)

    def test_journal_trailer_and_duplicate_properties(self):
        for mode in ['missing', 'after', 'duplicate', 'duplicate-property']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d); self.fixture(root)
                if mode == 'missing':
                    rows = self.read_journal(root)
                    with gzip.open(root/'events.jsonl.gz', 'wt') as stream:
                        for row in rows: stream.write(json.dumps(row)+'\n')
                else:
                    with gzip.open(root/'events.jsonl.gz', 'ab') as stream:
                        stream.write(b'{"kind":"journal_end","kind":"journal_end"}\n' if mode == 'duplicate-property'
                            else b'{"kind":"journal_end"}\n' if mode == 'duplicate' else b'{"kind":"recorder_performance"}\n')
                with self.assertRaises(ValueError): M.verify(root)


if __name__ == '__main__':
    unittest.main()
