"""Runtime keeps explicit stage pins aligned with fresh present-prefix subsets."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from runtime_producer import build_present_health_contracts,forward_adapter_options
from test_runtime_producer import health_acquisition
from test_optional_forward_owners import optional_source,config
from test_forward_reference_groups import paired,materialize
from test_forward_owner_relations import raw,sha


class StageFiltering(unittest.TestCase):
    def test_reciprocal_missing_prefixes_filter_stages_from_same_acquisition(self):
        for absent in [(),(0,),(0,1)]:
            with self.subTest(absent=absent),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);profile,layout_raw=health_acquisition(root,absent)
                layout=json.loads(layout_raw);layout['actor_read_stages']={p:'pool'+str(i)for i,p in enumerate(layout['actor_prefixes'])}
                events=[json.loads(line)for line in(root/'evidence.jsonl').read_bytes().splitlines()]
                for event in events:
                    if event.get('purpose')=='recipe':event['stage']='pool'+str((event['address']-0x5000)//0x100)
                evidence=b''.join(raw(e)for e in events);(root/'evidence.jsonl').write_bytes(evidence)
                manifest=json.loads((root/'manifest.json').read_bytes());manifest['evidence_sha256']=sha(evidence);(root/'manifest.json').write_bytes(raw(manifest))
                bundle=build_present_health_contracts(root,raw(layout),recipe_path=root/'recipe.json')
                self.assertEqual(bundle['actor_read_stages'],{p:stage for p,stage in layout['actor_read_stages'].items()if int(p[11:15])not in absent})
                self.assertEqual(len(bundle['contracts']),2-len(absent))
                if absent:
                    self.assertFalse(bundle['previous_contracts_carried'])
                    self.assertEqual(bundle['requested_layout_sha256'],sha(raw(layout)))
                    events=[e for e in events if e.get('kind')!='guard_check'];evidence=b''.join(raw(e)for e in events)
                    (root/'evidence.jsonl').write_bytes(evidence);manifest['evidence_sha256']=sha(evidence);(root/'manifest.json').write_bytes(raw(manifest))
                    with self.assertRaisesRegex(ValueError,'unchecked_profile_guard'):build_present_health_contracts(root,raw(layout),recipe_path=root/'recipe.json')

    def test_requested_map_must_be_complete_before_empty_prefix_removal(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);_,layout_raw=health_acquisition(root,(0,));layout=json.loads(layout_raw)
            layout['actor_read_stages']={layout['actor_prefixes'][1]:'fixture'}
            with self.assertRaisesRegex(ValueError,'invalid_actor_read_stages'):build_present_health_contracts(root,raw(layout),recipe_path=root/'recipe.json')

    def test_all_empty_forward_alternatives_retain_no_stage_or_candidate(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);_,_,_,template=optional_source(root);c=config(root,template)
            path=Path(c['forward_owner_health_layout']);layout=json.loads(path.read_bytes())
            layout['actor_read_stages']={p:'requested_'+str(i)for i,p in enumerate(layout['actor_prefixes'])}
            path.write_bytes(raw(layout));c['forward_owner_health_layout_sha256']=sha(path.read_bytes());epoch=root/'epoch';epoch.mkdir()
            options=forward_adapter_options(c,root,epoch)
            self.assertEqual(options['forward_owner_health_contracts'],[])
            self.assertEqual(json.loads((epoch/'forward-health-layout.json').read_bytes())['actor_read_stages'],{})
            bundle=json.loads((epoch/'forward-health-bundle.json').read_bytes())
            self.assertEqual(bundle['actor_read_stages'],{});self.assertEqual(bundle['forward_owner_contracts'],[])
            self.assertEqual(bundle['acquisition_empty_bindings'],['aux','alt'])

    def test_paired_forward_empty_alternatives_filter_map_before_real_builder(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);data=paired(alias=True,optional=True,health=True);materialize(root,data)
            profile=json.loads(data[0]);template=json.loads((root/'bindings.json').read_bytes())
            events=[json.loads(line)for line in(root/'evidence.jsonl').read_bytes().splitlines()]
            next_id=1+max(e['id']for e in events if e.get('kind')=='read')
            # Synthetic native-format transcript, not native runtime evidence.
            payload=bytearray(48*16);struct.pack_into('<If',payload,0,1,175.0)
            for i in range(2):
                event=dict(kind='read',purpose='recipe',stage='pool'+str(i),id=next_id+i,address=0xa000,
                    attempted=True,error=None,requested_bytes=len(payload),returned_bytes=len(payload),
                    bytes_hex=payload.hex(),read_start_ticks=10,read_end_ticks=20)
                events.insert(-1,event)
            evidence=b''.join(raw(e)for e in events);(root/'evidence.jsonl').write_bytes(evidence)
            manifest=json.loads((root/'manifest.json').read_bytes());manifest.update(evidence_sha256=sha(evidence),fields=len(profile['fields']),
                guard_declarations=len(profile['guards'])+sum(len(f.get('guards',[]))for f in profile['fields']))
            (root/'manifest.json').write_bytes(raw(manifest))
            prefixes=[b['owned_field_prefix']for b in template['bindings']]
            layout=dict(schema='overwatch-decoder.health-layout/1',executable_sha256=profile['target']['executable_sha256'],recipe_sha256=template['recipe_sha256'],
                extent_size=48*16,read_stage='legacy_unused',slot_count=48,slot_stride=16,membership_offset=0,scalar_offset=4,
                actor_prefixes=prefixes,scalar_field_suffix='_direct_candidate',actor_read_stages={p:'pool'+str(i//2)for i,p in enumerate(prefixes)},
                supported_forward_owners=[dict(binding_id=b['binding_id'],owner_prefix=b['owned_field_prefix'])for b in template['bindings']])
            path=root/'layout.json';path.write_bytes(raw(layout));epoch=root/'epoch';epoch.mkdir()
            c=dict(forward_owner_bindings=str(root/'bindings.json'),forward_owner_bindings_sha256=sha((root/'bindings.json').read_bytes()),
                recipe=str(root/'recipe.json'),forward_owner_health_layout=str(path),forward_owner_health_layout_sha256=sha(path.read_bytes()))
            options=forward_adapter_options(c,root,epoch);self.assertEqual(len(options['forward_owner_health_contracts']),2)
            effective=json.loads((epoch/'forward-health-layout.json').read_bytes())
            self.assertEqual(effective['actor_read_stages'],{prefixes[0]:'pool0',prefixes[2]:'pool1'})
            bundle=json.loads((epoch/'forward-health-bundle.json').read_bytes())
            self.assertEqual(bundle['actor_read_stages'],effective['actor_read_stages'])
            self.assertTrue(all(len(d['slots'])==48 for d in bundle['forward_owner_contracts']))
            self.assertEqual(bundle['acquisition_empty_bindings'],['route0_alt','route1_alt'])


if __name__=='__main__':unittest.main()
