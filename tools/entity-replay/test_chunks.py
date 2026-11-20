import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('chunks',Path(__file__).with_name('chunks.py'));C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
spec=importlib.util.spec_from_file_location('compact',Path(__file__).with_name('prepare_compact.py'));P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

class ChunkTests(unittest.TestCase):
    def test_index_pins_and_confinement(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);chunk=root/'chunk.json';chunk.write_text('{}');index=root/'index.json'
            row=dict(path='chunk.json',start_seconds=0,end_seconds=1,bytes=2,sha256=hashlib.sha256(b'{}').hexdigest())
            value=dict(schema='overwatch-decoder.entity-replay-index/1',public_state_eligible=False,chunks=[row]);index.write_text(json.dumps(value))
            data,files=C.checked_index(index);self.assertEqual(list(files),['/chunks/0000.json'])
            chunk.write_text('[]')
            with self.assertRaises(ValueError):C.checked_index(index)
            row['path']='../escape';index.write_text(json.dumps(value))
            with self.assertRaises(ValueError):C.checked_index(index)
    def test_two_windows_share_session_clock_and_are_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);session=root/'session.json';session.write_text(json.dumps(dict(qpc_origin=0,qpc_frequency=1000)))
            sources=[]
            for t in (100,1000):
                file=root/f'source{t}'
                file.write_text(json.dumps(dict(schema='overwatch-decoder.private.selected-compact/1',source='process_memory',scope='configured_controller_window',timestamp=dict(start_ticks=t,end_ticks=t+1,monotonic_frequency=1000),entities=[]))+'\n');sources.append(file)
            index=root/'index.json';summary=P.prepare_chunks(sources,index,session=session)
            self.assertEqual(summary['chunks'],2);data,files=C.checked_index(index)
            self.assertEqual([c['start_seconds'] for c in data['chunks']],[.101,1.001]);self.assertEqual(len(files),2)

if __name__=='__main__':unittest.main()
