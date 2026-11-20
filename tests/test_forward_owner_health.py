"""Forward ownership stays distinct from reciprocal-body health semantics."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

import pytest
from overwatch_decoder.health_projection import ForwardOwnerHealthContract, InvalidHealthBinding, PoolHealthContract

PREFIX = "controller_0000_aux_0000_"
BINDING = "synthetic_forward_owner"
PINS = dict(acquisition_evidence_sha256="b"*64, forward_contract_sha256="c"*64,
            recipe_sha256="d"*64, acquisition_manifest_sha256="e"*64)


def raw(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture():
    target = dict(pid=7, image_name="fixture.exe", creation_file_time=8,
                  executable_sha256="a"*64, architecture="x64")
    names = ["controller_0000_handle_candidate_i32", "controller_0000_manager_key_candidate_i32",
             "controller_0000_forward_reference_candidate_i32", PREFIX+"handle_candidate_i32",
             PREFIX+"manager_key_candidate_i32"]
    words = [17, 29, 53, 41, 53]
    fields = [dict(name=name, type="i32", address=0x2000+4*i) for i,name in enumerate(names)]
    guards = [dict(address=0x2000, bytes_hex=struct.pack("<5I", *words).hex())]
    slots = []
    for i in range(48):
        member = i+1 if i<2 else 0
        name = PREFIX+f"pool_{i:04d}_direct_candidate" if member else None
        scalar = 0x4004+16*i if member else None
        slots.append(dict(index=i,membership_address=0x4000+16*i,membership_u32=member,
                          field_name=name,scalar_address=scalar))
        guards.append(dict(address=0x4000+16*i,bytes_hex=struct.pack("<I",member).hex()))
        if member: fields.append(dict(name=name,type="f32",address=scalar))
    profile = dict(schema="overwatch-decoder.field-profile/1",target=target,fields=fields,guards=guards)
    profile_raw = raw(profile)
    contract = ForwardOwnerHealthContract.from_profile(profile_raw,owner_prefix=PREFIX,slots=slots,
                                                       binding_id=BINDING,**PINS)
    frame = dict(schema="overwatch-decoder.field-stream/1",kind="frame",source="process_memory",target=target,
        profile_sha256=digest(profile_raw),sequence=1,start_ticks=0,end_ticks=100,
        monotonic_frequency=1000,skipped_intervals_before=0,fields={},
        guards_before=[dict(ok=True,error=None,start_ticks=1,end_ticks=9)for _ in guards],
        guards_after=[dict(ok=True,error=None,start_ticks=80,end_ticks=90)for _ in guards])
    for field,value in zip(fields,[*words,279.99998474121094,93.0]):
        frame['fields'][field['name']]=dict(type=field['type'],status="observed",value=value,
            read_start_ticks=20,read_end_ticks=30,guard_ids=list(range(len(guards))))
    identity = [dict(field=name,value=value,read_start_ticks=20,read_end_ticks=30,
                     guard_ids=list(range(len(guards))))for name,value in zip(names,words)]
    def key(role,indexes):
        values = [(fields[i]['address'],words[i])for i in indexes]
        payload = ["overwatch-decoder.guarded-object-relation/1",role,target,values]
        return role+":"+digest(json.dumps(payload,sort_keys=True,separators=(",",":")).encode())
    row=dict(binding_id=BINDING,owned_field_prefix=PREFIX,controller_object_key=key("controller",[0,1]),
             forward_owner_object_key=key("owner",[3,4]),relation_status="observed",reason=None,
             identity_evidence=identity,owned_fields={name:copy.deepcopy(value)for name,value in frame['fields'].items()
                                                    if name.startswith(PREFIX)},current_displayed_body=None)
    projection=dict(schema="overwatch-decoder.guarded-forward-owner-relations/1",profile_sha256=contract.profile_sha256,
        target=target,source="process_memory",contract_sha256=PINS['forward_contract_sha256'],
        source_evidence=dict(recipe_sha256=PINS['recipe_sha256'],evidence_sha256=PINS['acquisition_evidence_sha256'],
                             acquisition_manifest_sha256=PINS['acquisition_manifest_sha256']),
        timing={k:frame[k]for k in ('sequence','start_ticks','end_ticks','monotonic_frequency')},
        relations=[row],public_state_eligible=False,visibility="unknown")
    return contract,frame,projection,profile,slots


def test_complete_sum_has_owner_identity_and_never_promotes_body():
    contract,frame,p,_,_ = fixture()
    value=contract.project(frame,forward_relation_projection=p)
    assert value['raw_sum']==372.99998474121094
    assert value['schema']=='overwatch-decoder.forward-owner-pool-sum/1'
    assert value['forward_owner_object_key']==p['relations'][0]['forward_owner_object_key']
    assert value['controller_object_key']==p['relations'][0]['controller_object_key']
    assert value['supplied_layout_slots']==48 and value['occupied_pool_count']==2
    assert value['current_displayed_body']is None and 'body_object_key'not in value
    assert not value['public_state_eligible']and value['visibility']=='unknown'
    assert 'address'not in json.dumps(value)
    value['identity_evidence'][0]['value']=-1
    assert contract.project(frame,forward_relation_projection=p)['identity_evidence'][0]['value']==17


@pytest.mark.parametrize('case', ['gap','native_gap','bad_skip','unknown','membership_before','membership_after',
    'owner_identity','controller_identity','reference','negative','nan','guard_ids','field_time','extra_pool'])
def test_bad_current_storage_or_gap_never_yields_partial_sum(case):
    c,f,p,_,_=fixture();name=PREFIX+'pool_0001_direct_candidate'
    if case=='native_gap':f['skipped_intervals_before']=1
    if case=='bad_skip':f['skipped_intervals_before']=False
    if case=='unknown':f['fields'][name]['status']='unknown'
    if case.startswith('membership_'):f['guards_'+case.removeprefix('membership_')][-1]['ok']=False
    if case=='owner_identity':f['fields'][PREFIX+'handle_candidate_i32']['value']+=1
    if case=='controller_identity':f['fields']['controller_0000_handle_candidate_i32']['value']+=1
    if case=='reference':f['fields']['controller_0000_forward_reference_candidate_i32']['value']+=1
    if case=='negative':f['fields'][name]['value']=-1
    if case=='nan':f['fields'][name]['value']=float('nan')
    if case=='guard_ids':f['fields'][name]['guard_ids']=[]
    if case=='field_time':f['fields'][name]['read_end_ticks']=101
    if case=='extra_pool':f['fields'][PREFIX+'pool_0048_direct_candidate']={}
    assert c.project(f,forward_relation_projection=p,gap=case=='gap')is None


@pytest.mark.parametrize('case',['schema','profile','target','frequency','timing','source','contract','binding','prefix',
    'controller_key','owner_key','duplicate','unknown','body_promotion','identity_order','identity_value',
    'identity_read','identity_ids','owned_value','owned_missing','public','float_identity','float_timing','malformed_row'])
def test_projection_must_bind_same_frame_full_identity_and_original_samples(case):
    c,f,p,_,_=fixture();row=p['relations'][0]
    if case=='schema':p['schema']='overwatch-decoder.guarded-object-relations/1'
    if case=='profile':p['profile_sha256']='f'*64
    if case=='target':p['target']=dict(p['target'],creation_file_time=9)
    if case=='frequency':p['timing']['monotonic_frequency']+=1
    if case=='timing':p['timing']['end_ticks']+=1
    if case=='source':p['source_evidence']['evidence_sha256']='f'*64
    if case=='contract':p['contract_sha256']='f'*64
    if case=='binding':row['binding_id']='other'
    if case=='prefix':row['owned_field_prefix']='controller_0001_aux_0000_'
    if case=='controller_key':row['controller_object_key']='controller:'+'f'*64
    if case=='owner_key':row['forward_owner_object_key']='owner:'+'f'*64
    if case=='duplicate':p['relations'].append(copy.deepcopy(row))
    if case=='unknown':row['relation_status']='unknown'
    if case=='body_promotion':row['current_displayed_body']='body:'+'f'*64
    if case=='identity_order':row['identity_evidence'].reverse()
    if case=='identity_value':row['identity_evidence'][0]['value']+=1
    if case=='float_identity':row['identity_evidence'][0]['value']=17.0
    if case=='float_timing':p['timing']['sequence']=1.0
    if case=='malformed_row':p['relations']=[None]
    if case=='identity_read':row['identity_evidence'][0]['read_end_ticks']+=1
    if case=='identity_ids':row['identity_evidence'][0]['guard_ids']=[]
    if case=='owned_value':row['owned_fields'][PREFIX+'pool_0000_direct_candidate']['value']+=1
    if case=='owned_missing':row['owned_fields'].pop(PREFIX+'pool_0000_direct_candidate')
    if case=='public':p['public_state_eligible']=True
    assert c.project(f,forward_relation_projection=p)is None


def test_default_policy_and_complete_membership_or_identity_dependency_cannot_be_relaxed():
    _,_,_,p,slots=fixture()
    with pytest.raises(InvalidHealthBinding,match='unsupported_actor_prefix'):
        PoolHealthContract.from_profile(raw(p),actor_prefix=PREFIX,slots=slots,acquisition_evidence_sha256='b'*64)
    with pytest.raises(InvalidHealthBinding,match='48_slots'):
        ForwardOwnerHealthContract.from_profile(raw(p),owner_prefix=PREFIX,slots=slots[:-1],binding_id=BINDING,**PINS)
    # Scalar-only dependencies omit the guarded owner's identity.
    p['fields'][-1]['guards']=p['guards'][1:]
    p['fields'][-2]['guards']=p['guards'][1:]
    p['fields'][3]['guards']=[p['guards'][0]];p['fields'][4]['guards']=[p['guards'][0]]
    p['guards']=[]
    with pytest.raises(InvalidHealthBinding,match='forward_identity_not_scalar_dependency'):
        ForwardOwnerHealthContract.from_profile(raw(p),owner_prefix=PREFIX,slots=slots,binding_id=BINDING,**PINS)


def test_builder_explicit_forward_option_source_pins_and_no_renaming(tmp_path):
    path=Path(__file__).resolve().parents[1]/'tools/entity-decoder/build_health_contracts.py'
    spec=importlib.util.spec_from_file_location('forward_health_builder',path);builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    _,_,_,profile,slots=fixture();recipe=dict(target=profile['target'])
    extent=bytearray(48*16)
    for i,slot in enumerate(slots):struct.pack_into('<I',extent,i*16,slot['membership_u32'])
    event=dict(kind='read',purpose='recipe',stage='fixture48',requested_bytes=len(extent),returned_bytes=len(extent),
               attempted=True,address=0x4000,bytes_hex=extent.hex(),error=None,read_start_ticks=1,read_end_ticks=2)
    profile_raw=raw(profile);recipe_raw=raw(recipe);evidence=raw(event)
    manifest=dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,target=profile['target'],
                  fields=len(profile['fields']),guard_declarations=len(profile['guards']),profile_sha256=digest(profile_raw),
                  evidence_sha256=digest(evidence),recipe_sha256=digest(recipe_raw))
    for name,data in [('profile.json',profile_raw),('manifest.json',raw(manifest)),('recipe.json',recipe_raw),('evidence.jsonl',evidence)]:
        (tmp_path/name).write_bytes(data)
    layout=dict(schema='overwatch-decoder.health-layout/1',executable_sha256=profile['target']['executable_sha256'],
                recipe_sha256=digest(recipe_raw),extent_size=len(extent),read_stage='fixture48',slot_count=48,
                slot_stride=16,membership_offset=0,scalar_offset=4,actor_prefixes=[PREFIX],scalar_field_suffix='_direct_candidate',
                supported_forward_owners=[dict(owner_prefix=PREFIX,binding_id=BINDING,forward_contract_sha256='c'*64)])
    with pytest.raises(builder.InvalidHealthAcquisition,match='opt_in_required'):
        builder.build_contracts(tmp_path,raw(layout))
    result=builder.build_contracts(tmp_path,raw(layout),allow_forward_owners=True)
    assert result['contracts']==[] and len(result['forward_owner_contracts'])==1
    d=result['forward_owner_contracts'][0]
    assert d['owner_prefix']==PREFIX and d['recipe_sha256']==manifest['recipe_sha256']
    assert d['acquisition_manifest_sha256']==digest(raw(manifest))
    assert d['slots']==slots and (tmp_path/'profile.json').read_bytes()==profile_raw
    contract=ForwardOwnerHealthContract.from_profile(profile_raw,**d)
    assert contract.owner_prefix==PREFIX
    layout['supported_forward_owners'].append(copy.deepcopy(layout['supported_forward_owners'][0]))
    with pytest.raises(builder.InvalidHealthAcquisition,match='invalid_supported_forward_owner'):
        builder.build_contracts(tmp_path,raw(layout),allow_forward_owners=True)


def test_malformed_projection_input_remains_unknown():
    c,f,_,_,_=fixture()
    for value in (None,[],"invalid",{}):
        assert c.project(f,forward_relation_projection=value)is None
