"""Synthetic independent source admission and cutover fixtures."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_session_windows import (
    HERE, ORIGIN, SCOPE, CombinedStorageWriter, checked_index, encoded, end, gap,
    handoff_session, handoff_source, handoff_start, prepare_repeat_session, read_repeat_session,
)


def independent_handoff_source(root, number, spans, *, misroute=False, second_partial=False):
    window = root/'observations'/f'window-{number:04d}'
    writer = CombinedStorageWriter(window, maximum_cohort_bytes=4096, maximum_total_bytes=65536,
        maximum_cohorts=16, maximum_index_bytes=32768, maximum_receipt_bytes=512)
    children, sources, counts, stops, outcomes = [], [], {}, {}, {}
    for i, brackets in enumerate(spans):
        source_id = f'roster-{i:02d}'
        with tempfile.TemporaryDirectory() as stage:
            source_path, _ = handoff_source(Path(stage), 1, brackets, session_id=f'fixture-source-{i}',
                                           partial=i == 1 and second_partial)
            worker = source_path/'roster-00'
            worker.rename(window/source_id)
        selected = (window/source_id/'selected.jsonl').read_bytes().splitlines(keepends=True)
        counts[source_id] = len(selected)
        worker_bytes = (window/source_id/'result.json').read_bytes()
        result = json.loads(worker_bytes)
        stops[source_id] = result['native_stop_reason']
        outcomes[source_id] = result['status']
        children.append(dict(source=source_id, directory=source_id, kind='roster',
            owned_producer_pid=900+i, owned_job_closed=True, outcome=result['status'],
            exit_code=result['cli_exit_code'], source_result_sha256=hashlib.sha256(worker_bytes).hexdigest()))
        for raw in selected:
            row = json.loads(raw)
            tick = row['timestamp']['end_ticks']
            claimed = 'roster-00' if misroute and i == 1 else source_id
            row.update(source_worker=claimed, source_batch=claimed[-2:], roster_source_id=claimed,
                roster_source_tick=tick, multi_source_snapshot=False, observed_build_sha256='a'*64,
                input_sha256=hashlib.sha256(raw).hexdigest())
            sources.append(row)
    rows = [dict(schema='overwatch-decoder.private.combined-status/1', kind='source_start', source_id=c['source'],
                 owned_producer_pid=c['owned_producer_pid']) for c in children]
    rows.extend(sorted(sources, key=lambda row: (row['roster_source_tick'], row['roster_source_id'])))
    rows.extend(dict(schema='overwatch-decoder.private.combined-status/1', kind='source_end', source_id=c['source'],
        exit_code=c['exit_code'], outcome=c['outcome'], source_result_sha256=c['source_result_sha256']) for c in children)
    for seq, row in enumerate(rows):
        raw = encoded(dict(row, capture_scope=SCOPE, combined_sequence=seq))
        writer.write_compact(raw, seq)
        writer.commit_receipt(encoded(dict(combined_sequence=seq, line_sha256=hashlib.sha256(raw).hexdigest())))
    summary = writer.close()
    (window/'result.json').write_bytes(encoded(dict(summary, schema='overwatch-decoder.private.combined-run/2',
        capture_scope=SCOPE, status='partial' if second_partial else 'complete',
        cli_exit_code=7 if second_partial else 0, error=None, cleanup_errors=[],
        source_unavailable=False, roster_only=True, roster_source_count=2, source_epochs_independent=True,
        multi_source_snapshot=False, source_entity_rows=counts, source_stop_reasons=stops,
        source_outcomes=outcomes, entity_rows=len(sources), children=children)))


class IndependentRosterTests(unittest.TestCase):
    def test_tied_samples_and_full_read_cutover(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d); root = base/'session'; index = base/'index.json'
            independent_handoff_source(root, 1, [[(1000,1010),(16000,16010)],[(1005,1010),(16005,16012)]])
            independent_handoff_source(root, 2, [[(15999,16003),(16010,16015),(16015,16018)],[(16001,16005),(16012,16018)]])
            manifest = handoff_session(root, [handoff_start(1,0), handoff_start(2,15000,1),
                end(1,18000), end(2,28000)], 2, [1,2])
            report = prepare_repeat_session(root,index,manifest,read_repeat_session(root,manifest))
            self.assertEqual((report['chunks'],report['frames']), (2,6))
            data,_ = checked_index(index)
            first, second = [json.loads((base/c['path']).read_bytes()) for c in data['chunks']]
            self.assertEqual(first['frames'][0]['t'],first['frames'][1]['t'])
            self.assertEqual([f['roster_source_id'] for f in second['frames']],['roster-00','roster-01'])
            self.assertEqual(second['frames'][0]['t'],second['frames'][1]['t'])
            self.assertEqual(len({o['key'] for o in second['objects']}),2)
            self.assertTrue(all(len(f['objects'])==1 for f in first['frames']+second['frames']))
            view = data['session_windows'][1]['overlap_selection']
            self.assertEqual((view['dropped_at_or_before_cutover'],view['dropped_straddling_cutover']),(2,1))
            self.assertEqual(view['cutover_ticks'],str(ORIGIN+16012))
            self.assertFalse(data['continuity_across_chunks'])
            validation = """
const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const m=require(process.argv[1]),idx=m.createIndex(JSON.parse(process.argv[2]));
for(const chunk of idx.chunks){
  const loaded=m.create(JSON.parse(fs.readFileSync(path.join(process.argv[3],chunk.path))));
  m.validateOverlapChunk(idx,chunk,loaded.data);
  const t=loaded.data.frames[0].t;
  assert.deepEqual(m.sampleAt(loaded,t).objects,[]);
  for(const id of ['roster-00','roster-01']){
    const scoped=m.selectRoster(loaded,id), sample=m.sampleAt(scoped,t);
    assert.equal(sample.objects.length,1);
    assert.equal(sample.recordedFields[0].roster_source_id,id);
    assert.equal(sample.frame.source_session_id,'fixture-source-'+id.at(-1));
    assert.equal(m.sampleAt(scoped,t+.1).active,false);
  }
}
"""
            subprocess.run(['node','-e',validation,str(HERE/'model.js'),json.dumps(data),str(base)],check=True)

    def test_resealed_wrong_slot_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'session';index=base/'index.json'
            independent_handoff_source(root, 1, [[(1000,1010)],[(1005,1015)]],misroute=True)
            manifest=handoff_session(root,[handoff_start(1,0),end(1,20000)],1,[1])
            report=prepare_repeat_session(root,index,manifest,read_repeat_session(root,manifest))
            self.assertEqual(report['chunks'],0)
            data,_=checked_index(index)
            self.assertEqual(data['session_windows'][0]['reason'],'accepted_window_verification_failed')

    def test_unavailable_source_does_not_erase_other_slot(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'session';index=base/'index.json'
            independent_handoff_source(root,1,[[(1000,1010)],[]],second_partial=True)
            manifest=handoff_session(root,[handoff_start(1,0),end(1,20000,7),gap(1,20001,'producer_partial')],1,[1])
            report=prepare_repeat_session(root,index,manifest,read_repeat_session(root,manifest))
            self.assertEqual((report['chunks'],report['frames']),(1,1))
            data,_=checked_index(index)
            self.assertEqual(data['session_windows'][0]['overlap_source_selections']['roster-01']['source_frames'],0)
