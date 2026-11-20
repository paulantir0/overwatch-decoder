"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const M = require("./model.js");
function fixture() {
  const frame = (t, objects, more = {}) => ({
    t,
    end: t + 0.001,
    epoch: "a",
    sequence: 0,
    skipped: 0,
    continuity_valid: true,
    unknown_count: 0,
    objects,
    ...more,
  });
  return {
    schema: "overwatch-decoder.entity-replay/1",
    public_state_eligible: false,
    epochs: [{ id: "a" }, { id: "b" }],
    start_seconds: 1,
    end_seconds: 2.041,
    objects: [{ index: 0, key: "structural-A", label: "Object 001" }],
    frames: [
      frame(1, [[0, 1, 2, 3, true]], { continuity_valid: false }),
      frame(1.02, [[0, 4, 5, 6, true]]),
      frame(1.06, [[0, 7, 8, 9, null]], {
        skipped: 1,
        continuity_valid: false,
      }),
      frame(1.08, [], { unknown_count: 1, continuity_valid: false }),
      frame(2, [[0, 20, 21, 22, true]], {
        epoch: "b",
        continuity_valid: false,
      }),
      frame(2.02, [[0, 23, 24, 25, true]], { epoch: "b" }),
      frame(2.04, [[0, 26, 27, 28, true]], { epoch: "b" }),
    ],
  };
}
test("exact positions and self association; no interpolation", () => {
  const m = M.create(fixture());
  assert.deepEqual(M.sampleAt(m, 1.01).objects, [[0, 1, 2, 3, true]]);
  assert.deepEqual(M.sampleAt(m, 1.02).objects, [[0, 4, 5, 6, true]]);
  assert.equal(M.sampleAt(m, 1.06).objects[0][4], null);
});
test("startup, skipped slot, unknown frame and long gap show no stale objects", () => {
  const m = M.create(fixture());
  for (const t of [0, 0.99, 1.05, 1.08, 1.5, 3])
    assert.equal(M.sampleAt(m, t).objects.length, 0, `${t}`);
  assert.equal(M.nextObserved(m, 1.5), 2);
  assert.equal(M.nextObserved(m, 3), null);
});
test("trails break at skipped interval, unknown read and new epoch", () => {
  const m = M.create(fixture());
  assert.equal(M.trail(m, 1, 0).length, 2);
  assert.deepEqual(M.trail(m, 2, 0), [[7, 8, 9]]);
  assert.deepEqual(M.trail(m, 3, 0), []);
  assert.deepEqual(M.trail(m, 4, 0), [[20, 21, 22]]);
  assert.equal(M.trail(m, 6, 0).length, 3);
});
test("timeline coverage excludes gaps and keeps epoch separation", () => {
  const m = M.create(fixture());
  assert.equal(m.segments.length, 3);
  assert.ok(m.segments[0].end < 1.05);
  assert.equal(m.segments[1].start, 1.06);
  assert.equal(m.segments[2].epoch, "b");
  assert.equal(m.positionCount, 6);
});
test("reject duplicate objects, nonfinite positions, ambiguous self and time reversal", () => {
  for (const mutate of [
    (d) => d.frames[0].objects.push(d.frames[0].objects[0]),
    (d) => (d.frames[0].objects[0][1] = Infinity),
    (d) => (d.frames[1].t = 1),
    (d) => (d.frames[0].epoch = "missing"),
    (d) => (d.frames[0].objects[0][0] = 400),
    (d) => (d.end_seconds = NaN),
    (d) => (d.public_state_eligible = true),
  ]) {
    const d = fixture();
    mutate(d);
    assert.throws(() => M.create(d));
  }
});
test("all-unknown recording stays blank, including final sample", () => {
  const d = fixture();
  d.frames.forEach((f) => {
    f.objects = [];
    f.unknown_count = 1;
    f.continuity_valid = false;
  });
  const m = M.create(d);
  assert.equal(m.segments.length, 0);
  assert.equal(M.nextObserved(m, 0), null);
  assert.equal(M.sampleAt(m, 2).active, false);
});
test("time formatting handles zero precision and minute rounding", () => {
  assert.equal(M.formatTime(501, 0), "08:21");
  assert.equal(M.formatTime(59.999, 2), "01:00.00");
  assert.equal(M.formatTime(1.2), "00:01.20");
});

test("rotation candidates require a current object and disappear in gaps", () => {
  const data = fixture();
  data.frames[0].rotations = [[0, 0, 0, 0, 1]];
  const m = M.create(data);
  assert.deepEqual(M.sampleAt(m, 1).rotations, [[0, 0, 0, 0, 1]]);
  for (const t of [0, 1.02, 1.05, 1.08, 3])
    assert.deepEqual(M.sampleAt(m, t).rotations, []);
  for (const rotations of [
    [[99, 0, 0, 0, 1]],
    [[0, 0, 0, NaN, 1]],
    [
      [0, 0, 0, 0, 1],
      [0, 0, 0, 0, 1],
    ],
  ]) {
    const invalid = fixture();
    invalid.frames[0].rotations = rotations;
    assert.throws(() => M.create(invalid));
  }
});

test("illustrative quaternion projection normalizes a copy and rejects bad norms", () => {
  assert.deepEqual(M.candidateForward([0, 0, 0, 1]), [0, 0, 1]);
  const q = [0, Math.SQRT1_2, 0, Math.SQRT1_2],
    copy = [...q];
  const forward = M.candidateForward(q);
  assert.ok(Math.abs(forward[0] - 1) < 1e-12);
  assert.ok(Math.abs(forward[2]) < 1e-12);
  assert.deepEqual(q, copy);
  for (const bad of [[0, 0, 0, 0], [0, 0, 0, 2], [NaN, 0, 0, 1], null])
    assert.equal(M.candidateForward(bad), null);
});

test("video offset maps session time and keeps absent video outside its duration", () => {
  assert.deepEqual(M.videoTime(0, 2, 10), { t: 0, available: false });
  assert.deepEqual(M.videoTime(2, 2, 10), { t: 0, available: true });
  assert.deepEqual(M.videoTime(7, 2, 10), { t: 5, available: true });
  assert.deepEqual(M.videoTime(12, 2, 10), { t: 10, available: false });
  assert.deepEqual(M.videoTime(0, -2, 10), { t: 2, available: true });
});

function healthFixture() {
  const data = fixture(),
    frame = data.frames[0];
  frame.start_ticks = "9007199254741010";
  frame.end_ticks = "9007199254741020";
  frame.self_pools = {
    object: 0,
    declared_count: 3,
    pools: [425, 100, 226.377258].map((value, i) => [
      i,
      i * 16,
      i + 1,
      value,
      "9007199254741013",
      "9007199254741014",
    ]),
  };
  return data;
}
test("self health candidate uses every declared pool and clears on gaps or missing reads", () => {
  const data = healthFixture(),
    model = M.create(data);
  const health = M.selfHealthCandidate(M.sampleAt(model, 1));
  assert.equal(health.display_ceil_candidate, 752);
  assert.equal(health.declared_pool_count, 3);
  assert.equal(health.status, "candidate");
  assert.deepEqual(health.pools, data.frames[0].self_pools.pools);
  for (const t of [0, 1.02, 1.05, 1.08, 2])
    assert.equal(M.selfHealthCandidate(M.sampleAt(model, t)), null);
  data.frames[0].self_pools.pools.forEach((p) => (p[3] = 0));
  assert.equal(
    M.selfHealthCandidate(M.sampleAt(M.create(data), 1)).display_ceil_candidate,
    0,
  );
});
test("self pools reject partial declarations, wrong actors and stale or malformed reads", () => {
  for (const mutate of [
    (f) => f.self_pools.pools.pop(),
    (f) => (f.self_pools.object = 9),
    (f) => (f.objects[0][4] = false),
    (f) => (f.self_pools.pools[1][0] = 0),
    (f) => (f.self_pools.pools[1][1] = 0),
    (f) => (f.self_pools.pools[0][3] = NaN),
    (f) => (f.self_pools.pools[0][3] = -1),
    (f) => (f.self_pools.pools[0][4] = "9007199254741009"),
    (f) => (f.self_pools.pools[0][5] = "9007199254741021"),
    (f) => (f.self_pools.pools[0][4] = 9007199254741013),
  ]) {
    const data = healthFixture();
    mutate(data.frames[0]);
    assert.throws(() => M.create(data));
  }
});

test("compact fields clear in gaps and never become inferred identities", () => {
  const data = fixture();
  data.frames[0].fields = [{object:0, health:{value:50,validation_status:"fixture_only"}, username:{value:null,validation_status:"unknown"}}];
  const model = M.create(data);
  assert.equal(M.observationFields(M.sampleAt(model,1.01),0).health.value,50);
  assert.equal(M.observationFields(M.sampleAt(model,1.5),0),null);
  assert.equal(M.observationFields(M.sampleAt(model,1.01),99),null);
});
test("damage timeline excludes future events and rejects attacker attribution", () => {
  const data = fixture();
  const event = (t) => ({schema:"overwatch-decoder.session-observation/1",kind:"damage",public_state_eligible:false,
    direction:"outgoing_candidate",attacker:null,exact_damage:null,t,amount_truncated:10});
  data.events = [event(1),event(2)];
  const model=M.create(data);
  assert.equal(M.eventsAt(model,.9).length,0);
  assert.equal(M.eventsAt(model,1.5).length,1);
  assert.equal(M.eventsAt(model,3,1).length,1);
  data.events[0].attacker="inferred";
  assert.throws(()=>M.create(data),/damage feedback/);
});
function incomingFixture(t = 1) {
  const stamp = (start, end) => ({start_ticks:String(start),end_ticks:String(end),frequency:1000,clock:"windows_qpc"});
  const actor = (id) => ({entity_id:`body:${id}`,controller_id:`controller:${id}`,visibility:"unknown",numeric_team:null,
    hero:{value:"Fixture hero",validation_status:"synthetic_only"},relation:{value:"enemy",validation_status:"synthetic_only"}});
  return {schema:"overwatch-decoder.session-observation/1",kind:"incoming_source",source_schema:"overwatch-decoder.private.incoming-source-observation/1",
    public_state_eligible:false,atomic:false,visibility:"unknown",previous_values_carried:false,continuity:"unknown",
    status:"observed",observation_id:"a".repeat(64),reason:null,t,semantics:"repeated_active_source_observation",
    unique_hit:false,exact_damage:null,impact_timestamp:null,numeric_team:null,timestamp:stamp(100,110),
    observed_build_sha256:"b".repeat(64),semantic_review_sha256:"c".repeat(64),
    source_actor:{...actor("source"),position_observations:[
      {value:[1,2,3],timestamp:stamp(82,83),roster_timestamp:stamp(80,90)},
      {value:[4,5,6],timestamp:stamp(122,123),roster_timestamp:stamp(120,130)}]},
    recipient_actor:actor("recipient")};
}
test("incoming history preserves source samples and hides idle unknowns without carrying identities", () => {
  const data=fixture(), observed=incomingFixture(), idle={...incomingFixture(1.1),status:"unknown",reason:"context_inactive",source_actor:null,recipient_actor:null};
  const rejected={...idle,t:1.2,reason:"bracket_too_old"};
  data.events=[observed,idle,rejected,incomingFixture(2)];
  const model=M.create(data);
  assert.equal(M.eventsAt(model,.9).length,0);
  assert.deepEqual(M.eventsAt(model,1.15),[observed]);
  assert.deepEqual(M.eventsAt(model,1.3,1),[rejected]);
  assert.equal(model.data.events.length,4); // Idle records remain in evidence.
  const shown=M.eventPresentation(observed);
  assert.match(shown.label,/incoming source observed.*Fixture hero.*enemy/);
  assert.match(shown.detail,/1.00, 2.00, 3.00.*4.00, 5.00, 6.00/);
  assert.match(shown.detail,/not hit counts/);
  assert.equal(shown.entityId,"body:source");
  assert.equal(M.eventPresentation(rejected).entityId,null);
});
test("incoming source timeline rejects stale positions, invented hits and unknown actor carryover", () => {
  for (const mutate of [
    (e)=>e.unique_hit=true,(e)=>e.exact_damage=3,(e)=>e.impact_timestamp="now",
    (e)=>e.visibility="visible",(e)=>e.numeric_team=2,(e)=>e.atomic=true,
    (e)=>e.previous_values_carried=true,(e)=>e.source_actor.position_observations.pop(),
    (e)=>e.source_actor.position_observations[0].value[0]=Infinity,
    (e)=>e.source_actor.position_observations[0].timestamp.end_ticks="99",
    (e)=>e.source_actor.position_observations[1].roster_timestamp.end_ticks="200",
    (e)=>e.source_actor.position_observations[1].timestamp.frequency=100,
    (e)=>e.source_actor.relation.validation_status="unknown",(e)=>e.status="unknown",
    (e)=>e.source_actor=null,(e)=>e.observed_build_sha256=null,
  ]) {
    const data=fixture(),event=incomingFixture();mutate(event);data.events=[event];
    assert.throws(()=>M.create(data),/incoming source observation/);
  }
});
test("untimed source controls remain evidence only and cannot carry an observed actor", () => {
  const data=fixture(), control={...incomingFixture(),status:"unknown",reason:"source_closed",t:null,timestamp:null,source_actor:null,recipient_actor:null};
  data.untimed_events=[control];
  const model=M.create(data);
  assert.equal(model.data.untimed_events[0],control);
  assert.deepEqual(M.eventsAt(model,10),[]);
  control.status="observed";
  assert.throws(()=>M.create(data),/incoming source observation/);
});
test("compact held partition objects expire by their own source timestamp", () => {
  const data=fixture();data.compact_observations=true;data.origin_ticks="0";data.frequency=1000;
  data.field_samples=[{object:0,source_timestamp:{end_ticks:"960"}}];
  for(const f of data.frames)f.field_refs=[0];
  const model=M.create(data);
  assert.equal(M.sampleAt(model,1).objects.length,1);
  assert.equal(M.sampleAt(model,1.011).objects.length,0);
});
test("compact 20 Hz updates hold for at most 50 ms without inventing continuity or sample rate", () => {
  const data=fixture();data.compact_observations=true;data.origin_ticks="0";data.frequency=1000;
  data.frames=data.frames.slice(0,2);data.frames[1].t=1.05;data.frames[1].end=1.051;data.end_seconds=1.051;
  data.field_samples=[{object:0,source_timestamp:{end_ticks:"1000"}},{object:0,source_timestamp:{end_ticks:"1050"}}];
  data.frames.forEach((f,i)=>{f.field_refs=[i];f.continuity_valid=false;});
  const model=M.create(data);
  assert.ok(Math.abs(model.updateInterval-.05)<1e-9);
  assert.equal(M.sampleAt(model,1.04).objects.length,1);
  assert.equal(M.sampleAt(model,1.09).objects.length,1);
  assert.equal(M.sampleAt(model,1.101).objects.length,0);
  data.frames=data.frames.slice(0,1);data.end_seconds=1.001;
  assert.equal(M.create(data).updateInterval,null);
});
test("bounded chunk selection leaves unknown gaps and rejects remote URLs", () => {
  const data={schema:"overwatch-decoder.entity-replay-index/1",public_state_eligible:false,end_seconds:4,
    chunks:[{url:"/chunks/0000.json",start_seconds:1,end_seconds:2,bytes:100,sha256:"a".repeat(64)},
      {url:"/chunks/0001.json",start_seconds:3,end_seconds:4,bytes:100,sha256:"b".repeat(64)}]};
  const index=M.createIndex(data);
  assert.equal(M.chunkAt(index,.5),-1);assert.equal(M.chunkAt(index,1),0);assert.equal(M.chunkAt(index,2.5),-1);assert.equal(M.chunkAt(index,3.5),1);
  data.chunks[0].url="https://external.invalid/private.json";
  assert.throws(()=>M.createIndex(data),/Invalid replay chunk/);
});

function playbackFixture() {
  const data=fixture();
  data.compact_observations=true; data.origin_ticks="0";data.frequency=1000000;
  data.frames=data.frames.slice(0,2);
  data.frames[0].objects=[[0,1,2,3,true]];
  data.frames[1].t=1.083;data.frames[1].end=1.084;
  data.frames[1].objects=[[0,1,4,3,true]];
  data.end_seconds=1.2;
  data.field_samples=data.frames.map((f,i)=>({object:0,entity_id:"body-a",controller_id:"controller-a",
    source_timestamp:{end_ticks:String(Math.round(f.t*data.frequency))},health:{value:100-i*20}}));
  data.frames.forEach((f,i)=>{f.field_refs=[i];f.continuity_valid=false;});
  return data;
}
test("playback spans an 83 ms update without changing raw positions or interpolating health",()=>{
  const data=playbackFixture(),original=JSON.stringify(data),model=M.create(data);
  const display=M.playbackAt(model,1.06);
  assert.equal(M.sampleAt(model,1.06).active,false);
  assert.equal(display.active,true);
  assert.ok(Math.abs(display.objects[0][2]-(2+2*.06/.083))<1e-10);
  assert.equal(display.recordedFields[0].health.value,100);
  assert.equal(display.displaySamples[0].mode,"interpolated");
  assert.equal(display.presentation_only,true);
  assert.equal(JSON.stringify(data),original);
});
test("playback snaps teleport and owner changes instead of creating a path",()=>{
  for(const mutate of [d=>d.frames[1].objects[0][1]=30,d=>d.field_samples[1].controller_id="controller-b",
      d=>d.frames[1].epoch="b",d=>d.frames[1].skipped=1,d=>d.frames[1].objects[0][4]=false]) {
    const data=playbackFixture();mutate(data);
    const display=M.playbackAt(M.create(data),1.06);
    assert.deepEqual(display.objects,[[0,1,2,3,true]]);
    assert.equal(display.displaySamples[0].mode,"last_recorded");
  }
});
test("playback clears unknown rows immediately, respects source age and never predicts long gaps",()=>{
  const data=playbackFixture();data.frames[1].objects=[];
  assert.equal(M.playbackAt(M.create(data),1.084).active,false);
  const slow=playbackFixture();slow.frames[1].t=2;slow.frames[1].end=2.001;slow.end_seconds=2.01;
  const model=M.create(slow);
  assert.equal(M.playbackAt(model,1.19).active,true);
  assert.equal(M.playbackAt(model,1.201).active,false);
  assert.equal(M.playbackAt(model,.99).active,false);
  assert.equal(M.playbackAt(model,3).active,false);
  slow.field_samples[0].source_timestamp.end_ticks="700000";
  assert.equal(M.playbackAt(M.create(slow),1).active,false);
});
test("playback coverage removes sampling flicker but preserves unknowns and long gaps",()=>{
  const data=playbackFixture();
  const segments=M.playbackSegments(M.create(data));
  assert.equal(segments.length,1);assert.equal(segments[0].start,1);assert.equal(segments[0].end,1.2);
  data.frames[1].objects=[];
  assert.equal(M.playbackSegments(M.create(data))[0].end,1.083);
  data.frames[1].t=2;data.frames[1].end=2.001;data.end_seconds=2.01;
  assert.equal(M.playbackSegments(M.create(data))[0].end,1.2);
});

test("recovered windows require explicit opt-in and retain cancelled recorder status",()=>{
  const fixtureIndex=()=>({schema:"overwatch-decoder.entity-replay-index/1",public_state_eligible:false,repeat_windows:true,
    sealed_prefix_recovery:true,end_seconds:3,origin_ticks:"0",frequency:1000,
    chunks:[{url:"/chunks/0000.json",start_seconds:1,end_seconds:2,bytes:100,sha256:"a".repeat(64),
      recorder_window:1,source_sha256:"b".repeat(64),recovery_status:"verified_sealed_prefix",summary:{frames:1}}],
    gaps:[{start_seconds:0,end_seconds:1},{start_seconds:2,end_seconds:3}],
    session_windows:[{window:1,recorder_accepted:false,manifest_accepted:false,reason:"cancelled",replayed:true,
      start_ticks:"900",end_ticks:"3000",recovery_status:"verified_sealed_prefix",source_sha256:"b".repeat(64),
      recovery_evidence:{...Object.fromEntries(["original_storage_index_sha256","prefix_storage_index_sha256","last_seal_sha256",
        "source_sha256","worker_result_sha256","native_manifest_sha256","worker_selected_sha256",
        "worker_receipts_sha256","observed_build_sha256"].map(k=>[k,"b".repeat(64)])),
        sealed_cohorts:6,source_frames:1,first_end_ticks:"1000",last_end_ticks:"1950",recorder_result_fabricated:false,continuation_inferred:false}}]});
  assert.equal(M.createIndex(fixtureIndex()).session_windows[0].recorder_accepted,false);
  for(const mutate of [d=>delete d.sealed_prefix_recovery,d=>delete d.chunks[0].recovery_status,
    d=>delete d.session_windows[0].recovery_evidence,d=>d.session_windows[0].reason="failed",
    d=>d.session_windows[0].source_sha256="c".repeat(64),d=>d.session_windows[0].recovery_evidence.last_end_ticks="1940",
    d=>d.session_windows[0].recovery_evidence.continuation_inferred=true]) {
    const data=fixtureIndex();mutate(data);assert.throws(()=>M.createIndex(data),/acceptance/);
  }
});

test("cone scope uses only recorded rotations of current actors",()=>{
  const state={active:true,objects:[[0,1,2,3,true],[1,4,5,6,false],[2,7,8,9,null]],
    rotations:[[0,0,0,0,1],[1,0,Math.SQRT1_2,0,Math.SQRT1_2],[2,0,0,0,0],[99,0,0,0,1]]};
  assert.equal(M.facingSamples(state,"all").length,2);
  assert.deepEqual(M.facingSamples(state,"self").map(x=>x.point[0]),[0]);
  assert.deepEqual(M.facingSamples(state,"off"),[]);
  assert.deepEqual(M.facingSamples({...state,active:false},"all"),[]);
  assert.deepEqual(M.facingSamples({...state,rotations:[]},"all"),[]);
  assert.equal(M.facingSamples(state,"self")[0].forward[2],1);
});
test("POV preview anchors to unique self position without inventing aim or FOV",()=>{
  const state={active:true,objects:[[0,1,2,3,true],[1,4,5,6,false]],rotations:[]};
  const preview=M.povPreview(state);
  assert.deepEqual(preview.eye,[1,3.6,3]);
  assert.equal(preview.forward,null);assert.equal(preview.camera_aim_validated,false);assert.equal(preview.fov_validated,false);
  assert.equal(M.povPreview({...state,active:false}),null);
  assert.equal(M.povPreview({...state,objects:[[0,1,2,3,false]]}),null);
  assert.equal(M.povPreview({...state,objects:[[0,1,2,3,true],[1,4,5,6,true]]}),null);
  assert.equal(M.povPreview(state,NaN),null);
  state.rotations=[[0,0,0,0,1]];
  assert.deepEqual(M.povPreview(state).forward,[0,0,1]);
});
test("selected cube POV uses only that current object's position and facing",()=>{
  const state={active:true,objects:[[0,1,2,3,true],[1,4,5,6,false]],rotations:[[0,0,0,0,1],[1,0,Math.SQRT1_2,0,Math.SQRT1_2]]};
  const original=JSON.stringify(state),pov=M.povPreview(state,1.6,1);
  assert.equal(pov.object,1);assert.deepEqual(pov.eye,[4,6.6,6]);
  assert.ok(Math.abs(pov.forward[0]-1)<1e-12);
  assert.equal(M.povPreview(state,1.6,99),null);
  assert.equal(M.povPreview({...state,active:false},1.6,1),null);
  assert.equal(M.povPreview({...state,rotations:[state.rotations[0]]},1.6,1).forward,null);
  assert.equal(JSON.stringify(state),original);
});
test("team colors require current validated relation observations",()=>{
  const state={active:true,objects:[[0,1,2,3,false]],recordedFields:[{object:0,relation:{value:"enemy",validation_status:"current_build_native_ordinary_comparison"}}]};
  assert.equal(M.relationCategory(state,0),"enemy");
  assert.equal(M.relationCategory({...state,active:false},0),null);
  assert.equal(M.relationCategory(state,1),null);
  state.recordedFields[0].relation.validation_status="unknown";
  assert.equal(M.relationCategory(state,0),null);
});
test("health shatters require a fresh positive-to-zero observation of the same body",()=>{
  const field=(value)=>({object:0,entity_id:"body-a",controller_id:"controller-a",health:{value,validation_status:"current_build_native_current_health_pool_sum"},relation:{value:"enemy",validation_status:"current_build_native_ordinary_comparison"}});
  const fixture=()=>({data:{frames:[{t:1,epoch:"a",skipped:0,objects:[[0,1,2,3,false]],fields:[field(20)]},{t:1.08,epoch:"a",skipped:0,objects:[[0,1,2,3,false]],fields:[field(0)]},{t:1.16,epoch:"a",skipped:0,objects:[[0,1,2,3,false]],fields:[field(0)]}]}});
  const model=fixture(),original=JSON.stringify(model),events=M.healthDepletions(model);
  assert.equal(events.length,1);assert.equal(events[0].time,1.08);assert.equal(events[0].confirmed_death,false);
  assert.equal(JSON.stringify(model),original);
  for(const mutate of [m=>m.data.frames[0].fields[0].health.value=0,m=>m.data.frames[0].objects=[],
    m=>m.data.frames[1].t=1.3,m=>m.data.frames[1].epoch="b",m=>m.data.frames[1].skipped=1,
    m=>m.data.frames[1].fields[0].entity_id="body-b",m=>m.data.frames[1].fields[0].controller_id="controller-b",
    m=>m.data.frames[1].fields[0].health.value=null,m=>m.data.frames[1].fields[0].health.validation_status="unknown"]) {
    const candidate=fixture();mutate(candidate);assert.deepEqual(M.healthDepletions(candidate),[]);
  }
});

test("health bars use recorded peaks scoped to body, hero, epoch and build", () => {
  const field=(value,extra={})=>({object:0,controller_id:"owner-a",entity_id:"body-a",hero:{value:"Tracer"},
    health:{value,validation_status:"current_build_native_current_health_pool_sum"},...extra});
  const frame=(f,epoch="a")=>({epoch,objects:[[0,1,2,3,true]],fields:[f]});
  const model={data:{frames:[frame(field(100)),frame(field(175)),frame(field(999,{entity_id:"body-b"})),
    frame(field(800,{hero:{value:"Roadhog"}})),frame(field(700),"b"),frame(field(900,{observed_build_sha256:"other"})),
    frame(field(500,{health:{value:500,validation_status:"unknown"}}))]}};
  const original=JSON.stringify(model),scales=M.observedHealthScales(model);
  const state={active:true,frame:{epoch:"a"},objects:[[0,1,2,3,true]],recordedFields:[field(100)]};
  const bar=M.healthBar(state,0,scales);
  assert.equal(bar.reference,175);assert.equal(bar.fraction,100/175);assert.equal(bar.maximum_health,null);
  assert.equal(M.healthBar({...state,active:false},0,scales),null);
  assert.equal(M.healthBar(state,1,scales),null);
  assert.equal(M.healthBar({...state,recordedFields:[field(null)]},0,scales),null);
  assert.equal(M.healthBar({...state,recordedFields:[field(0)]},0,scales).fraction,0);
  assert.equal(M.healthBar({...state,recordedFields:[field(100,{entity_id:"new-body"})]},0,scales).fraction,null);
  assert.equal(JSON.stringify(model),original);
});
test("reference height uses the stated floor without claiming terrain or clipping below it",()=>{
  assert.equal(M.referenceHeight([0,3,5,8],2),3);
  assert.equal(M.referenceHeight([0,3,-1,8],2),-3);
  assert.equal(M.referenceHeight([0,3,null,8],2),null);
  assert.equal(M.referenceHeight([0,3,5,8],NaN),null);
});
