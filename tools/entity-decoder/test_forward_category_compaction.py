"""Current native flags remain neutral, source-bound forward-owner candidates."""
import copy
from pathlib import Path
import tempfile
import unittest

from aggregate_partitions import canonical
from compact_live_entities import CompactLiveEntities,encode
from compact_live_roster import CompactLiveRoster
from forward_owner_validation import validate_forward_owner_frame,CATEGORY_METADATA_KEYS
from test_compact_forward_owners import attach,unknown
from test_compact_live_entities import fixture,raw,new_epoch,pointer
from test_compact_live_roster import fixture as roster_fixture,transition
from test_forward_owner_validation import with_forward


def category(frame,*,low=1<<9,high=0x80000000):
    node=frame['forward_owner_projection'];node.update(forward_category_output_enabled=True,forward_category_contract_sha256='a9'*32,forward_category_native_review_sha256='b9'*32)
    row=node['relations'][0];identity=row['identity_evidence'];start=node['timing']['start_ticks']+1;end=start+1;prefix=row['owned_field_prefix']
    fields=copy.deepcopy(identity[3:])+[dict(field=prefix+'category_flags_'+half+'_research',value=v,read_start_ticks=start,read_end_ticks=end,guard_ids=[0,1,2,3,4,5,6])for half,v in [('low',low if low<(1<<31)else low-(1<<32)),('high',high if high<(1<<31)else high-(1<<32))]]
    selected=[i for i,b in enumerate([5,9])if low&(1<<b)];reason=('unsupported_mode_bits'if low&((1<<14)|(1<<15))else'absent_or_ambiguous_category'if len(selected)!=1 else None)
    row.update(raw_flags_candidate=dict(low_u32=low,high_u32=high,assembled_u64_hex=f'0x{high:08x}{low:08x}',selected_category_indices=selected),
        raw_category_candidate=None if reason else selected[0],raw_category_reason=reason,raw_category_evidence=dict(fields=fields,
        forward_identity_fields=copy.deepcopy(identity),contract_sha256=node['forward_category_contract_sha256'],forward_contract_sha256=node['contract_sha256'],
        native_review_sha256=node['forward_category_native_review_sha256'],profile_sha256=node['profile_sha256'],build_sha256=node['target']['executable_sha256'],
        source=copy.deepcopy(node['source_evidence']),frame_timing=copy.deepcopy(node['timing']),algorithm=dict(ordered_bits=[5,9],clear_bits=[14,15],supported_categories=[0,1]),
        conditions=[dict(role='unlinked_owner',width=8,mask=1<<57,equals=0,guarded_value=0,guard_ids=[5]),
                    dict(role='zero_override',width=4,mask=0xffffffff,equals=0,guarded_value=0,guard_ids=[6])],
        current_displayed_body=None,public_state_eligible=False,visibility='unknown'))
    return frame


def category_window(window):
    window=with_forward(window);entry=window['forward_owner_projections']['p1'];category(dict(forward_owner_projection=entry['projection']))
    for key in CATEGORY_METADATA_KEYS:window['forward_owner_sources']['p1'][key]=entry['projection'][key]
    entry['source_admission']=copy.deepcopy(window['forward_owner_sources']['p1']);return window


def blank_category(frame,reason='guard_failed'):
    row=frame['forward_owner_projection']['relations'][0]
    row.update(raw_flags_candidate=None,raw_category_candidate=None,raw_category_evidence=None,raw_category_reason=reason)
    return frame


class ForwardCategoryCompactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_exact_source_and_roster_values_pointers_and_no_team_semantics(self):
        frame=category(attach(fixture(self.root)[0]));out=CompactLiveEntities().consume(raw(frame));c=out['forward_owners'][0]['category_candidate']
        self.assertEqual(c['value'],{k:frame['forward_owner_projection']['relations'][0][k]for k in ('raw_flags_candidate','raw_category_candidate')})
        self.assertEqual(c['status'],'candidate');self.assertEqual(c['raw_status'],'observed');self.assertIsNotNone(pointer(frame,c['evidence_ref']))
        self.assertIsNone(c['current_displayed_body']);self.assertNotIn('team_candidate',c['value']);self.assertNotIn('relative_allegiance_candidate',c['value'])
        window=category_window(roster_fixture(self.root)[0]);line=canonical(window)+b'\n';out=CompactLiveRoster().consume(line)
        fast=CompactLiveRoster()._consume_decoded(line,window);self.assertEqual(encode(out),encode(fast))
        candidate=out['forward_owners'][0]['category_candidate'];self.assertEqual(candidate['value'],c['value']);self.assertIsNotNone(pointer(window,candidate['evidence_ref']))
        self.assertEqual(out['forward_owner_projections']['p1']['projection']['forward_category_native_review_sha256'],'b9'*32)

    def test_default_bytes_unchanged_when_extension_absent(self):
        frame=attach(fixture(self.root)[0]);before=CompactLiveEntities().consume(raw(frame))
        frame2=category(copy.deepcopy(frame));node=frame2['forward_owner_projection']
        for key in CATEGORY_METADATA_KEYS:node.pop(key)
        for key in ('raw_flags_candidate','raw_category_candidate','raw_category_evidence','raw_category_reason'):node['relations'][0].pop(key)
        self.assertEqual(encode(before),encode(CompactLiveEntities().consume(raw(frame2))))
        self.assertNotIn('category_candidate',before['forward_owners'][0])

    def test_mask_errors_retain_raw_flags_without_invented_category(self):
        for low,reason in [(1<<14,'unsupported_mode_bits'),(0,'absent_or_ambiguous_category'),((1<<5)|(1<<9),'absent_or_ambiguous_category')]:
            with self.subTest(low=low):
                frame=category(attach(fixture(self.root)[0]),low=low);c=CompactLiveEntities().consume(raw(frame))['forward_owners'][0]['category_candidate']
                self.assertEqual(c['status'],'unknown');self.assertEqual(c['raw_status'],'observed');self.assertEqual(c['reason'],reason)
                self.assertIsNone(c['value']['raw_category_candidate']);self.assertEqual(c['value']['raw_flags_candidate']['low_u32'],low)
        frame=category(attach(fixture(self.root)[0]));row=frame['forward_owner_projection']['relations'][0];row['raw_category_evidence']['algorithm']['supported_categories']=[0];row.update(raw_category_candidate=None,raw_category_reason='unsupported_category')
        self.assertEqual(CompactLiveEntities().consume(raw(frame))['forward_owners'][0]['category_candidate']['reason'],'unsupported_category')

    def test_tampered_identity_source_masks_conditions_and_samples_rejected(self):
        frame=category(attach(fixture(self.root)[0]))
        mutations={
            'forward_contract':lambda r:r['raw_category_evidence'].update(forward_contract_sha256='12'*32),
            'category_contract':lambda r:r['raw_category_evidence'].update(contract_sha256='13'*32),
            'native_review':lambda r:r['raw_category_evidence'].update(native_review_sha256='14'*32),
            'profile':lambda r:r['raw_category_evidence'].update(profile_sha256='15'*32),
            'time':lambda r:r['raw_category_evidence']['frame_timing'].update(sequence=999),
            'source':lambda r:r['raw_category_evidence']['source'].update(evidence_sha256='16'*32),
            'identity':lambda r:r['raw_category_evidence']['forward_identity_fields'][2].update(value=999),
            'owner_word':lambda r:r['raw_category_evidence']['fields'][0].update(value=999),
            'half_word':lambda r:r['raw_category_evidence']['fields'][2].update(value=0),
            'span':lambda r:r['raw_category_evidence']['fields'][3].update(read_end_ticks=99999),
            'dependency':lambda r:r['raw_category_evidence']['fields'][2].update(guard_ids=[5,6]),
            'hex':lambda r:r['raw_flags_candidate'].update(assembled_u64_hex='0x0000000000000000'),
            'invented_team':lambda r:r['raw_flags_candidate'].update(team_candidate='friendly'),
            'selected':lambda r:r['raw_flags_candidate'].update(selected_category_indices=[0]),
            'category':lambda r:r.update(raw_category_candidate=0),
            'algorithm':lambda r:r['raw_category_evidence']['algorithm'].update(ordered_bits=[4,8]),
            'overlap_masks':lambda r:r['raw_category_evidence']['algorithm'].update(clear_bits=[9]),
            'condition_value':lambda r:r['raw_category_evidence']['conditions'][0].update(guarded_value=1<<57),
            'condition_guard':lambda r:r['raw_category_evidence']['conditions'][0].update(guard_ids=[99]),
            'override_mask':lambda r:r['raw_category_evidence']['conditions'][1].update(mask=1),
            'reason':lambda r:r.update(raw_category_reason='unsupported_mode_bits'),
        }
        for name,mutate in mutations.items():
            with self.subTest(name=name):
                bad=copy.deepcopy(frame);mutate(bad['forward_owner_projection']['relations'][0])
                with self.assertRaises(ValueError):validate_forward_owner_frame(bad)
        declarations={w['field']:'i32'for w in frame['forward_owner_projection']['relations'][0]['identity_evidence']}
        row=frame['forward_owner_projection']['relations'][0];declarations.update({name:f['type']for name,f in row['owned_fields'].items()});declarations.update({w['field']:'i32'for w in row['controller_hero_asset_label_evidence']['fields']})
        with self.assertRaises(ValueError):validate_forward_owner_frame(frame,declarations)
        declarations.update({w['field']:'i32'for w in row['raw_category_evidence']['fields']});validate_forward_owner_frame(frame,declarations)

    def test_epoch_gaps_unknown_transitions_never_fill_category(self):
        first,second=fixture(self.root);category(attach(first));category(attach(second));blank_category(second);second['gap_before']['skipped_slots']=1;unknown(second)
        p=CompactLiveEntities();p.consume(raw(first));out=p.consume(raw(second));c=out['forward_owners'][0]['category_candidate'];self.assertIsNone(c['value']);self.assertEqual(c['raw_status'],'unknown')
        fresh=category(attach(new_epoch(fixture(self.root)[1],first['timing']['end_ticks'])));fresh['forward_owner_projection']['forward_category_contract_sha256']='17'*32;fresh['forward_owner_projection']['relations'][0]['raw_category_evidence']['contract_sha256']='17'*32
        p=CompactLiveEntities();p.consume(raw(first));self.assertEqual(p.consume(raw(fresh))['forward_owners'][0]['category_candidate']['value']['raw_category_candidate'],1)
        same=category(attach(fixture(self.root)[1]));same['forward_owner_projection']['forward_category_native_review_sha256']='18'*32;same['forward_owner_projection']['relations'][0]['raw_category_evidence']['native_review_sha256']='18'*32;p=CompactLiveEntities();p.consume(raw(first))
        with self.assertRaises(ValueError):p.consume(raw(same))
        windows=roster_fixture(self.root);first=category_window(windows[0]);p=CompactLiveRoster();p.consume(raw(first));later=copy.deepcopy(windows[1]);later.update(forward_owner_sources=copy.deepcopy(first['forward_owner_sources']),forward_owner_projections={})
        row=copy.deepcopy(first['forward_owners'][0]);row.update(status='unknown',reason='gap_in_window',projection_ref=None,relation_index=None);later['forward_owners']=[row]
        out=p.consume(raw(later));self.assertIsNone(out['forward_owners'][0]['category_candidate']['value'])
        out=p.consume(raw(transition(later)));self.assertIsNone(out['forward_owners'][0]['category_candidate']['value']);self.assertEqual(out['forward_owners'][0]['category_candidate']['raw_status'],'unknown')


if __name__=='__main__':unittest.main()
