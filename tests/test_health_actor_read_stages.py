"""Caller-pinned stage separation, with synthetic saved evidence only."""
import copy
import struct

import pytest

from test_build_health_contracts import SavedAcquisition, PREFIX, builder, encoded, digest

SECOND = 'controller_0001_body_0000_'


def paired(tmp_path, *, alias=False, different_memberships=False):
    saved=SavedAcquisition(tmp_path/'acquisition')
    first_guards=copy.deepcopy(saved.profile['guards'])
    fields=copy.deepcopy(saved.profile['fields'])
    for field in fields:
        field['name']=field['name'].replace(PREFIX,SECOND)
        if not alias:field['address']+=0x1000
    saved.profile['fields'].extend(fields)
    second=copy.deepcopy(saved.events[0]);second['stage']='second_extent';second['id']=2
    if not alias:
        second['address']+=0x1000
        guards=copy.deepcopy(first_guards)
        for guard in guards:guard['address']+=0x1000
        saved.profile['guards'].extend(guards)
    data=bytearray.fromhex(second['bytes_hex']);struct.pack_into('<f',data,4,201.0)
    if different_memberships:
        assert alias
        struct.pack_into('<I',data,0,11);struct.pack_into('<I',data,16,22)
        # Separate local dependency sets model two explicitly supplied snapshots;
        # conflicting membership words cannot share one global assertion.
        saved.profile['guards']=first_guards[:1]
        for field in saved.profile['fields']:
            if field['type']=='f32':
                guards=copy.deepcopy(first_guards[1:])
                if field['name'].startswith(SECOND):
                    for index,guard in enumerate(guards):
                        guard['bytes_hex']=data[16*index:16*index+4].hex()
                field['guards']=guards
    second['bytes_hex']=data.hex();second.update(read_start_ticks=30,read_end_ticks=40)
    saved.events.append(second)
    saved.layout['actor_prefixes'].append(SECOND)
    saved.layout['actor_read_stages']={PREFIX:'fixture_pool_extent',SECOND:'second_extent'}
    saved.persist()
    return saved


def test_two_owners_match_only_their_explicit_stage(tmp_path):
    saved=paired(tmp_path)
    bundle=saved.build();first,second=bundle['contracts']
    assert bundle['actor_read_stages']==saved.layout['actor_read_stages']
    assert second['slots'][0]['membership_address']-first['slots'][0]['membership_address']==0x1000
    saved.layout['actor_read_stages'][SECOND]='fixture_pool_extent'
    with pytest.raises(builder.InvalidHealthAcquisition,match='ambiguous_or_missing_actor_extent'):saved.build()


def test_same_address_aliases_keep_distinct_scalar_reads_and_evidence(tmp_path):
    saved=paired(tmp_path,alias=True)
    bundle=saved.build();first,second=bundle['contracts']
    assert first['slots'][0]['membership_address']==second['slots'][0]['membership_address']
    assert [s['membership_u32']for s in first['slots']]==[1,2,0]
    assert [s['membership_u32']for s in second['slots']]==[1,2,0]
    assert first['slots'][0]['field_name']!=second['slots'][0]['field_name']
    assert bundle['acquisition_evidence_sha256']==saved.manifest['evidence_sha256']
    assert bundle['layout_sha256']==digest(encoded(saved.layout))
    assert not bundle['public_state_eligible']
    # The second stage's different scalar bytes do not overwrite the first read.
    assert struct.unpack_from('<f',bytes.fromhex(saved.events[0]['bytes_hex']),4)[0]==175.0
    assert struct.unpack_from('<f',bytes.fromhex(saved.events[1]['bytes_hex']),4)[0]==201.0


def test_contradictory_memberships_reject_even_with_separate_local_expectations(tmp_path):
    saved=paired(tmp_path,alias=True,different_memberships=True)
    with pytest.raises(builder.InvalidHealthAcquisition,match='divergent_membership_reads'):saved.build()


def test_different_extents_may_use_the_same_explicit_stage(tmp_path):
    saved=paired(tmp_path)
    saved.events[1]['stage']='fixture_pool_extent'
    saved.layout['actor_read_stages'][SECOND]='fixture_pool_extent'
    saved.persist()
    assert len(saved.build()['contracts'])==2


def test_same_stage_same_address_still_cannot_serve_two_actors(tmp_path):
    saved=paired(tmp_path,alias=True)
    saved.layout['actor_read_stages'][SECOND]='fixture_pool_extent'
    with pytest.raises(builder.InvalidHealthAcquisition,match='extent_shared_by_actors'):saved.build()


@pytest.mark.parametrize('change',['missing','extra','none','empty','long','nonstring','wrong'])
def test_mapping_exact_keys_and_bounded_stage_names(tmp_path,change):
    saved=paired(tmp_path);mapping=saved.layout['actor_read_stages']
    if change=='missing':mapping.pop(SECOND)
    elif change=='extra':mapping['undeclared_']='second_extent'
    elif change=='none':saved.layout['actor_read_stages']=None
    elif change=='empty':mapping[SECOND]=''
    elif change=='long':mapping[SECOND]='x'*129
    elif change=='nonstring':mapping[SECOND]=True
    else:mapping[SECOND]='not_the_read_stage'
    with pytest.raises(builder.InvalidHealthAcquisition):saved.build()


def test_duplicate_json_actor_mapping_is_rejected(tmp_path):
    saved=paired(tmp_path)
    raw=encoded(saved.layout).replace(b'"second_extent"',b'"second_extent", "'+SECOND.encode()+b'": "fixture_pool_extent"')
    with pytest.raises(builder.InvalidHealthAcquisition):builder.build_contracts(saved.directory,raw)


@pytest.mark.parametrize('change',['scalar','membership'])
def test_divergent_repeats_reject_within_stage_even_when_another_stage_matches(tmp_path,change):
    saved=paired(tmp_path,alias=True)
    event=copy.deepcopy(saved.events[1]);data=bytearray.fromhex(event['bytes_hex'])
    if change=='scalar':struct.pack_into('<f',data,4,99.0)
    else:struct.pack_into('<I',data,0,12)
    event['bytes_hex']=data.hex();saved.events.append(event);saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition,match='divergent_extent_reads'):saved.build()


@pytest.mark.parametrize('change',['hash','missing_empty_guard','wrong_membership_guard','incomplete_read'])
def test_stage_map_cannot_bypass_source_or_membership_guards(tmp_path,change):
    saved=paired(tmp_path,alias=True)
    if change=='hash':
        with(saved.directory/'evidence.jsonl').open('ab')as file:file.write(b' ')
    else:
        if change=='incomplete_read':saved.events[1]['returned_bytes']-=4
        else:
            if change=='missing_empty_guard':saved.profile['guards'].pop()
            else:saved.profile['guards'][1]['bytes_hex']='0c000000'
        saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition):saved.build()


def test_absent_map_keeps_legacy_bundle_bytes_and_explicit_single_stage_agrees(tmp_path):
    saved=SavedAcquisition(tmp_path/'legacy');old=saved.build()
    assert 'actor_read_stages'not in old
    saved.layout['actor_read_stages']={PREFIX:saved.layout['read_stage']}
    explicit=saved.build()
    explicit.pop('actor_read_stages');explicit['layout_sha256']=old['layout_sha256']
    assert encoded(explicit)==encoded(old)
    saved.layout.pop('actor_read_stages')
    assert encoded(saved.build())==encoded(old)
