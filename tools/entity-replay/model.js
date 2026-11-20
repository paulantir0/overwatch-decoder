/* Pure replay model. Recorded positions remain samples, never inferred trajectories. */
(function (root) {
  "use strict";
  const assert = (ok, message) => {
    if (!ok) throw new Error(message);
  };
  const finite = (value) => typeof value === "number" && Number.isFinite(value);
  const safeText = (value) => typeof value === "string" && value.length > 0 && value.length <= 256 && !/[\x00-\x1f]/.test(value);
  function incomingObservation(event) {
    const valid = (ok) => assert(ok, "Invalid or promoted incoming source observation.");
    const stamp = (value, frequency) => {
      valid(value && value.clock === "windows_qpc" && Number.isSafeInteger(value.frequency) && value.frequency > 0 &&
        (frequency === undefined || value.frequency === frequency) &&
        [value.start_ticks, value.end_ticks].every((v) => typeof v === "string" && /^\d{1,20}$/.test(v)));
      const start = BigInt(value.start_ticks), end = BigInt(value.end_ticks);
      valid(start <= end);
      return [start, end];
    };
    valid(event.source_schema === "overwatch-decoder.private.incoming-source-observation/1" &&
      event.unique_hit === false && event.exact_damage === null && event.impact_timestamp === null &&
      event.numeric_team === null && event.visibility === "unknown" && event.atomic === false &&
      event.previous_values_carried === false && event.continuity === "unknown" &&
      event.semantics === "repeated_active_source_observation" &&
      ["observed", "unknown"].includes(event.status));
    if (event.timestamp === null) {
      valid(event.t === null && event.status === "unknown" && event.source_actor === null && event.recipient_actor === null);
      return;
    }
    const context = stamp(event.timestamp);
    if (event.status === "unknown") {
      valid(event.source_actor === null && event.recipient_actor === null);
      return;
    }
    valid([event.observed_build_sha256, event.semantic_review_sha256].every((v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v)));
    for (const actor of [event.source_actor, event.recipient_actor]) {
      valid(actor && safeText(actor.entity_id) && safeText(actor.controller_id) && actor.visibility === "unknown" && actor.numeric_team === null);
      for (const label of [actor.hero, actor.relation]) {
        valid(label && safeText(label.validation_status) && (label.value === null || (safeText(label.value) && label.validation_status !== "unknown")));
      }
      valid(actor.relation.value === null || ["self", "ally", "enemy"].includes(actor.relation.value));
    }
    const positions = event.source_actor.position_observations;
    valid(Array.isArray(positions) && positions.length === 2);
    const endpoints = positions.map((position) => {
      valid(Array.isArray(position.value) && position.value.length === 3 && position.value.every(finite));
      const read = stamp(position.timestamp, event.timestamp.frequency);
      const roster = stamp(position.roster_timestamp, event.timestamp.frequency);
      valid(roster[0] <= read[0] && read[1] <= roster[1]);
      return roster;
    });
    valid(endpoints[0][1] <= context[0] && context[1] <= endpoints[1][0] &&
      (endpoints[1][1] - endpoints[0][0]) * 1000n <= BigInt(event.timestamp.frequency) * 100n);
  }
  function createIndex(data) {
    assert(data?.schema === "overwatch-decoder.entity-replay-index/1" && data.public_state_eligible === false &&
      Array.isArray(data.chunks) && (data.chunks.length > 0 || data.repeat_windows === true) && data.chunks.length <= 240 &&
      finite(data.end_seconds) && data.end_seconds >= 0, "Invalid replay chunk index.");
    let end = -Infinity;
    data.chunks.forEach((chunk, i) => {
      assert(chunk.url === `/chunks/${String(i).padStart(4,"0")}.json` && finite(chunk.start_seconds) &&
        finite(chunk.end_seconds) && chunk.start_seconds >= 0 && chunk.end_seconds >= chunk.start_seconds &&
        chunk.start_seconds >= end && Number.isSafeInteger(chunk.bytes) && chunk.bytes > 0 && chunk.bytes <= 128*1024*1024 &&
        typeof chunk.sha256 === "string" && /^[a-f0-9]{64}$/.test(chunk.sha256), "Invalid replay chunk.");
      independentRoster(chunk);
      end=chunk.end_seconds;
    });
    assert(data.end_seconds >= end, "Chunk exceeds index time bounds.");
    if (data.repeat_windows === true) {
      assert(Array.isArray(data.session_windows) && data.session_windows.length <= 240 &&
        Array.isArray(data.gaps) && data.gaps.length <= 241, "Missing repeat-window coverage.");
      const gaps = [];
      let cursor = 0;
      data.chunks.forEach((chunk) => {
        const n = chunk.recorder_window;
        const window = data.session_windows[n - 1];
        const recovered = data.sealed_prefix_recovery === true &&
          window?.recorder_accepted === false && window.manifest_accepted === false && window.reason === "cancelled" &&
          window.recovery_status === "verified_sealed_prefix" && chunk.recovery_status === "verified_sealed_prefix" &&
          validRecovery(data, window, chunk);
        assert(Number.isSafeInteger(n) && window?.window === n && (window.recorder_accepted === true || recovered) &&
          window.replayed === true && chunk.source_sha256 === window.source_sha256,
          "Replay chunk lacks matching recorder acceptance.");
        if (chunk.start_seconds > cursor) gaps.push([cursor, chunk.start_seconds]);
        cursor = chunk.end_seconds;
      });
      if (cursor < data.end_seconds) gaps.push([cursor, data.end_seconds]);
      assert(gaps.length === data.gaps.length && gaps.every(([lo, hi], i) =>
        data.gaps[i].start_seconds === lo && data.gaps[i].end_seconds === hi), "Invalid replay gaps.");
      if (Object.hasOwn(data,"overlapping_windows") || data.session_windows.some((w)=>w &&
          (Object.hasOwn(w,"overlap_selection") || Object.hasOwn(w,"launch_qpc_ticks")))) validateOverlapIndex(data);
    }
    return data;
  }
  const rosterSources=["roster-00","roster-01"];
  function independentRoster(data) {
    if (!Object.hasOwn(data,"roster_sources") && !Object.hasOwn(data,"multi_source_snapshot")) return false;
    assert(data.multi_source_snapshot===false && Array.isArray(data.roster_sources) &&
      data.roster_sources.length===2 && rosterSources.every((id,i)=>data.roster_sources[i]===id),
      "Invalid independent roster topology.");
    return true;
  }
  const workerHashes=["worker_result_sha256","native_manifest_sha256","worker_selected_sha256","worker_receipts_sha256"];
  const validHashes=(proof,keys)=>proof && keys.every((k)=>typeof proof[k]==="string" && /^[a-f0-9]{64}$/.test(proof[k]));
  const validTicks=(stamps)=>stamps.every((v)=>typeof v==="string" && /^\d{1,20}$/.test(v));
  function validRecovery(index, window, chunk) {
    const proof=window.recovery_evidence;
    if (!proof || proof.source_sha256 !== window.source_sha256 || proof.recorder_result_fabricated !== false ||
        proof.continuation_inferred !== false) return false;
    const view=index.overlapping_windows===true ? window.overlap_selection : null;
    if (index.overlapping_windows===true && (!view || typeof view!=="object")) return false;
    if (!validHashes(proof,[...workerHashes,"original_storage_index_sha256","prefix_storage_index_sha256",
      "last_seal_sha256","source_sha256","observed_build_sha256"]) ||
        !Number.isInteger(proof.sealed_cohorts) || proof.sealed_cohorts<1 || proof.sealed_cohorts>64 ||
        !Number.isInteger(proof.source_frames) || proof.source_frames<1 || proof.source_frames>100000 ||
        proof.source_frames!==(view ? view.source_frames : chunk.summary?.frames)) return false;
    const stamps=[index.origin_ticks,window.start_ticks,proof.first_end_ticks,proof.last_end_ticks,window.end_ticks];
    if (!Number.isSafeInteger(index.frequency) || index.frequency<=0 || !validTicks(stamps)) return false;
    const [origin,begin,first,last,end]=stamps.map(BigInt);
    if (!(origin<=begin && begin<=first && first<=last && last<end)) return false;
    return view ? view.source_first_end_ticks===proof.first_end_ticks && view.source_last_end_ticks===proof.last_end_ticks :
      chunk.start_seconds===Number(first-origin)/index.frequency &&
      chunk.end_seconds===Math.min(Number(last-origin)/index.frequency+.05,Number(end-origin)/index.frequency);
  }
  function validateOverlapIndex(index) {
    const {frequency,window_seconds:duration,successor_lead_seconds:lead}=index;
    assert(index.overlapping_windows===true && index.successor_timing_basis==="recorder_launch_qpc" &&
      Number.isSafeInteger(frequency) && frequency>0 && Number.isInteger(duration) && duration>=20 && duration<=60 &&
      Number.isInteger(lead) && lead>0 && lead<duration && validTicks([index.origin_ticks]), "Invalid overlap view clock.");
    const origin=BigInt(index.origin_ticks);
    const seconds=(ticks)=>Number(ticks-origin)/frequency;
    let prior=null, cutoff=null, next=0;
    index.session_windows.forEach((window,i)=>{
      const n=i+1;
      assert(window?.window===n && typeof window.replayed==="boolean" &&
        validTicks([window.start_ticks,window.end_ticks]) && window.launch_qpc_ticks===window.start_ticks &&
        window.timing_basis==="recorder_launch_qpc" &&
        (window.predecessor_window===null || n>1 && window.predecessor_window===n-1), "Invalid overlap window launch.");
      const begin=BigInt(window.start_ticks), end=BigInt(window.end_ticks);
      assert(origin<=begin && begin<=end && window.start_seconds===seconds(begin) && window.end_seconds===seconds(end),
        "Invalid overlap window range.");
      const chunk=window.replayed ? index.chunks[next++] : null;
      if (window.replayed) assert(chunk?.recorder_window===n,"Duplicate or missing overlap replay window.");
      const view=window.overlap_selection;
      if (view===undefined && !chunk && window.recovery_status!=="verified_sealed_prefix") return;
      assert(view && validHashes(window,["source_sha256"]) && view.cutover_from_window===prior &&
        view.cutover_ticks===cutoff, "Invalid overlap cutover source.");
      const multi=Object.hasOwn(window,"overlap_source_selections") || Object.hasOwn(window,"roster_source_evidence");
      if (multi) validateRosterSelection(window,view,chunk,begin,end);
      if (window.recorder_accepted===true) {
        assert(window.manifest_accepted===true && window.recovery_status==null && chunk?.recovery_status==null &&
          (multi || validHashes(window.overlap_source_evidence,workerHashes)), "Missing or conflicting overlap worker evidence.");
      } else if (!chunk) {
        assert(index.sealed_prefix_recovery===true && window.recorder_accepted===false && window.manifest_accepted===false &&
          window.reason==="cancelled" && window.recovery_status==="verified_sealed_prefix" && validRecovery(index,window,null),
          "Invalid unreplayed overlap recovery evidence.");
      }
      const {source_frames:total,selected_frames:kept,dropped_at_or_before_cutover:before,dropped_straddling_cutover:across}=view;
      assert([total,kept,before,across].every((v)=>Number.isInteger(v) && v>=0 && v<=100000) &&
        total===kept+before+across && across<=(multi ? 2 : 1) && (cutoff!==null || total===kept) && Boolean(kept)===Boolean(chunk),
        "Invalid overlap selection counts.");
      const original=[view.source_first_start_ticks,view.source_first_end_ticks,view.source_last_end_ticks];
      const firstSelected=[view.selected_first_start_ticks,view.selected_first_end_ticks];
      let start, first, last;
      if (total) {
        assert(validTicks(original),"Invalid overlap original source clock.");
        [start,first,last]=original.map(BigInt);
        assert(begin<=start && start<=first && first<=last && last<=end,"Invalid overlap original source range.");
      } else assert(original.every((v)=>v===null),"Empty overlap source has a time range.");
      if (!kept) {
        assert(firstSelected.every((v)=>v===null) && (!total || last<=BigInt(cutoff) || across>0),
          "Unselected overlap source claims coverage.");
        return;
      }
      assert(validTicks(firstSelected),"Invalid overlap selected source clock.");
      const [startKept,firstKept]=firstSelected.map(BigInt);
      const keptLast=multi ? BigInt(view.selected_last_end_ticks) : last;
      assert((multi || start<=startKept) && startKept<=firstKept && first<=firstKept && firstKept<=keptLast &&
        (cutoff===null || startKept>=BigInt(cutoff) && firstKept>BigInt(cutoff)) &&
        (total!==kept || start===startKept && first===firstKept) && kept===chunk.summary?.frames &&
        chunk.start_seconds===seconds(firstKept) &&
        chunk.end_seconds===Math.min(seconds(keptLast)+.05,seconds(end),index.chunks[next]?.start_seconds ?? Infinity),
        "Overlap chunk exceeds selected source range.");
      prior=n; cutoff=original[2];
    });
    assert(next===index.chunks.length,"Duplicate or missing overlap replay window.");
  }
  function validateRosterSelection(window, view, chunk, begin, end) {
    const views=window.overlap_source_selections, proof=window.roster_source_evidence;
    assert(window.recorder_accepted===true && views && proof &&
      Object.keys(views).length===2 && Object.keys(proof).length===2 &&
      (!chunk || independentRoster(chunk)), "Missing independent overlap evidence.");
    const originals=[], selected=[];
    for (const id of rosterSources) {
      const v=views[id];
      assert(v && validHashes(proof[id],workerHashes) && v.cutover_ticks===view.cutover_ticks &&
        v.cutover_from_window===view.cutover_from_window, "Independent overlap proof mismatch.");
      const {source_frames:total,selected_frames:kept,dropped_at_or_before_cutover:before,dropped_straddling_cutover:across}=v;
      assert([total,kept,before,across].every(n=>Number.isSafeInteger(n) && n>=0 && n<=100000) &&
        total===kept+before+across && across<=1 && (v.cutover_ticks!==null || total===kept),
        "Invalid independent overlap counts.");
      const original=[v.source_first_start_ticks,v.source_first_end_ticks,v.source_last_end_ticks];
      const keptFirst=[v.selected_first_start_ticks,v.selected_first_end_ticks];
      if (total) {
        assert(validTicks(original), "Missing independent source times.");
        const [start,first,last]=original.map(BigInt);
        assert(begin<=start && start<=first && first<=last && last<=end, "Independent source outside its window.");
        originals.push(v);
        if (kept) {
          assert(validTicks(keptFirst), "Missing independent selected times.");
          const [lo,hi]=keptFirst.map(BigInt);
          assert(start<=lo && lo<=hi && first<=hi && hi<=last &&
            (v.cutover_ticks===null || lo>=BigInt(v.cutover_ticks) && hi>BigInt(v.cutover_ticks)) &&
            (total!==kept || start===lo && first===hi), "Independent source crosses its cutoff.");
          selected.push(v);
        } else {
          assert(last<=BigInt(v.cutover_ticks) || across>0, "Unselected source has post-cutoff coverage.");
        }
      } else assert(original.every(v=>v===null), "Empty independent source has time bounds.");
      if (!kept) assert(keptFirst.every(v=>v===null), "Empty selection has time bounds.");
    }
    const firstOf=(rows,key)=>rows.reduce((best,row)=>!best || BigInt(row[key])<BigInt(best[key]) ? row : best,null);
    const lastOf=(rows)=>rows.reduce((best,row)=>best===null || BigInt(row.source_last_end_ticks)>BigInt(best) ? row.source_last_end_ticks : best,null);
    const first=firstOf(originals,"source_first_end_ticks"), kept=firstOf(selected,"selected_first_end_ticks");
    assert(["source_frames","selected_frames","dropped_at_or_before_cutover","dropped_straddling_cutover"].every(k=>
      view[k]===rosterSources.reduce((sum,id)=>sum+views[id][k],0)) &&
      view.source_first_start_ticks===(first?.source_first_start_ticks ?? null) &&
      view.source_first_end_ticks===(first?.source_first_end_ticks ?? null) && view.source_last_end_ticks===lastOf(originals) &&
      view.selected_first_start_ticks===(kept?.selected_first_start_ticks ?? null) &&
      view.selected_first_end_ticks===(kept?.selected_first_end_ticks ?? null) && view.selected_last_end_ticks===lastOf(selected),
      "Aggregate overlap does not match independent sources.");
  }
  function validateOverlapChunk(index, entry, data) {
    const window=index.session_windows[entry.recorder_window-1], view=window.overlap_selection;
    const saved=data.epochs[0].overlap_selection;
    assert(saved && Object.keys(view).every((key)=>view[key]===saved[key]) &&
      index.origin_ticks===data.origin_ticks && index.frequency===data.frequency &&
      data.frames.length===view.selected_frames && data.start_seconds===entry.start_seconds,
      "Replay chunk lacks matching overlap selection.");
    const multi=independentRoster(entry);
    assert(multi===independentRoster(data), "Replay chunk roster topology mismatch.");
    if (multi) {
      const selected=data.epochs[0].overlap_source_selections;
      const proofs=data.epochs[0].roster_source_evidence;
      for (const id of rosterSources) {
        const expected=window.overlap_source_selections[id];
        assert(selected?.[id] && Object.keys(expected).every(k=>selected[id][k]===expected[k]) &&
          workerHashes.every(k=>proofs?.[id]?.[k]===window.roster_source_evidence[id][k]),
          "Replay chunk lacks independent source proof.");
        const frames=data.frames.filter(frame=>frame.roster_source_id===id);
        assert(frames.length===expected.selected_frames, "Independent replay sample count mismatch.");
        if (frames.length) assert(frames[0].source_read_bracket[0]===expected.selected_first_start_ticks &&
          frames[0].source_read_bracket[1]===expected.selected_first_end_ticks &&
          frames.at(-1).source_read_bracket[1]===expected.source_last_end_ticks &&
          (expected.cutover_ticks===null || BigInt(frames[0].source_read_bracket[0])>=BigInt(expected.cutover_ticks) &&
            BigInt(frames[0].source_read_bracket[1])>BigInt(expected.cutover_ticks)), "Independent replay crosses its cutoff.");
      }
      return;
    }
    const origin=BigInt(index.origin_ticks), first=data.frames[0].source_read_bracket;
    let previous=BigInt(view.cutover_ticks ?? view.selected_first_start_ticks);
    assert(first?.[0]===view.selected_first_start_ticks && first?.[1]===view.selected_first_end_ticks &&
      data.frames.at(-1).source_read_bracket?.[1]===view.source_last_end_ticks, "Invalid overlap chunk source range.");
    for (const frame of data.frames) {
      const bracket=frame.source_read_bracket;
      assert(Array.isArray(bracket) && bracket.length===3 && validTicks(bracket.slice(0,2)) &&
        validHashes(bracket,[2]) && bracket[1]===frame.end_ticks, "Missing overlap frame source bracket.");
      const [start,end]=bracket.slice(0,2).map(BigInt);
      assert(previous<=start && start<=end && frame.t===Number(end-origin)/index.frequency,
        "Overlap frame crosses its source cutoff.");
      previous=end;
    }
  }
  function chunkAt(index, time) {
    return index.chunks.findIndex((chunk) => time >= chunk.start_seconds && time < chunk.end_seconds);
  }
  function emptyIndexModel(index) {
    // Only used after createIndex verifies the index; never admit an empty ordinary replay.
    return {
      data: {source_sha256: index.source_sha256, start_seconds: 0, end_seconds: index.end_seconds,
        objects: [], frames: [], epochs: [], events: [], untimed_events: [], summary: {},
        note: index.note, compact_observations: true},
      end: index.end_seconds, until: [], segments: [], positionCount: 0, updateInterval: null,
    };
  }
  function inactiveSample() {
    return {index: -1, frame: null, active: false, objects: [], rotations: [], selfPools: null, recordedFields: []};
  }
  function indexSample(index, loadedChunk, model, time) {
    return loadedChunk >= 0 && chunkAt(index, time) === loadedChunk ? sampleAt(model, time) : inactiveSample();
  }
  function recorderWindowAt(index, time) {
    const contains=(window)=>finite(window.start_seconds) && finite(window.end_seconds) &&
      time>=window.start_seconds && time<window.end_seconds;
    if (index.overlapping_windows===true) {
      const entry=index.chunks[chunkAt(index,time)];
      if (entry) return index.session_windows[entry.recorder_window-1];
      for (let i=index.session_windows.length-1;i>=0;i--) if (contains(index.session_windows[i])) return index.session_windows[i];
      return null;
    }
    return index.session_windows?.find(contains) ?? null;
  }
  function create(data) {
    assert(
      data?.schema === "overwatch-decoder.entity-replay/1" &&
        data.public_state_eligible === false,
      "This viewer requires a supported replay export.",
    );
    assert(
      Array.isArray(data.frames) &&
        data.frames.length > 0 &&
        data.frames.length <= 100000,
      "Invalid or oversized frame list.",
    );
    assert(
      Array.isArray(data.objects) && data.objects.length <= 4096,
      "Invalid object list.",
    );
    assert(Array.isArray(data.epochs), "Missing acquisition epochs.");
    assert(
      finite(data.start_seconds) &&
        finite(data.end_seconds) &&
        data.start_seconds === data.frames[0].t &&
        data.end_seconds >= data.frames.at(-1).end,
      "Invalid recording time bounds.",
    );
    const multi=independentRoster(data);
    const epochs = new Set(data.epochs.map((e) => e.id));
    if (multi) assert(validTicks([data.origin_ticks]) && Number.isSafeInteger(data.frequency) &&
      data.frequency>0 && data.compact_observations===true, "Invalid independent roster clock.");
    data.objects.forEach((o, i) =>
      assert(
        o.index === i &&
          typeof o.key === "string" && (!multi || rosterSources.includes(o.roster_source_id)) &&
          typeof o.label === "string" &&
          o.label.length <= 100,
        "Invalid object metadata.",
      ),
    );
    assert(
      new Set(data.objects.map((o) => o.key)).size === data.objects.length,
      "Duplicate object keys.",
    );
    const deltas = [], updateDeltas = [];
    let positionCount = 0,
      previous = null;
    const previousRosterEnds=new Map();
    for (const f of data.frames) {
      assert(
        finite(f.t) &&
          finite(f.end) &&
          f.t >= 0 &&
          f.end >= f.t &&
          (!previous || (multi ? f.t >= previous.t : f.t > previous.t)),
        "Non-monotonic or invalid frame time.",
      );
      assert(
        epochs.has(f.epoch) && typeof f.continuity_valid === "boolean",
        "Invalid frame provenance.",
      );
      assert(
        Number.isSafeInteger(f.skipped) &&
          f.skipped >= 0 &&
          Number.isSafeInteger(f.unknown_count) &&
          f.unknown_count >= 0,
        "Invalid missing-sample counts.",
      );
      assert(
        Array.isArray(f.objects) && f.objects.length <= 4096,
        "Invalid frame objects.",
      );
      if (multi) {
        const bracket=f.source_read_bracket, source=f.roster_source_id;
        assert(rosterSources.includes(source) && safeText(f.source_session_id) && /^\d+$/.test(f.source_segment) &&
          Array.isArray(bracket) && bracket.length===3 && validTicks(bracket.slice(0,2)) && validHashes(bracket,[2]) &&
          bracket[1]===f.end_ticks && f.roster_source_tick===f.end_ticks && f.continuity_valid===false,
          "Missing independent roster frame provenance.");
        const [start,end]=bracket.slice(0,2).map(BigInt), origin=BigInt(data.origin_ticks);
        const key=JSON.stringify([f.epoch,source]), previousEnd=previousRosterEnds.get(key);
        assert(origin<=start && start<=end && (previousEnd===undefined || previousEnd<=start && previousEnd<end) &&
          f.t===Number(end-origin)/data.frequency, "Independent roster frame is out of order.");
        previousRosterEnds.set(key,end);
      }
      const seen = new Set();
      let self = 0;
      for (const p of f.objects) {
        assert(
          Array.isArray(p) &&
            p.length === 5 &&
            Number.isSafeInteger(p[0]) &&
            p[0] >= 0 &&
            p[0] < data.objects.length && (!multi || data.objects[p[0]].roster_source_id===f.roster_source_id) &&
            !seen.has(p[0]) &&
            p.slice(1, 4).every(finite) &&
            (typeof p[4] === "boolean" || p[4] === null),
          "Invalid or duplicate object position.",
        );
        seen.add(p[0]);
        if (p[4] === true) self++;
      }
      assert(self <= 1, "Multiple self objects in one frame.");
      if (f.self_pools != null) {
        const h = f.self_pools;
        assert(
          f.objects.some((p) => p[0] === h.object && p[4] === true) &&
            Number.isSafeInteger(h.declared_count) &&
            h.declared_count > 0 &&
            h.declared_count <= 32 &&
            Array.isArray(h.pools) &&
            h.pools.length === h.declared_count,
          "Incomplete or non-self pool candidate.",
        );
        const ordinals = new Set(),
          physical = new Set();
        const ticks = (v) => typeof v === "string" && /^\d{1,20}$/.test(v);
        assert(
          ticks(f.start_ticks) && ticks(f.end_ticks),
          "Missing pool frame brackets.",
        );
        for (const p of h.pools) {
          assert(
            Array.isArray(p) &&
              p.length === 6 &&
              p.slice(0, 3).every((v) => Number.isSafeInteger(v) && v >= 0) &&
              p[2] <= 0xffffffff &&
              !ordinals.has(p[0]) &&
              !physical.has(p[1]) &&
              finite(p[3]) &&
              p[3] >= 0 &&
              ticks(p[4]) &&
              ticks(p[5]),
            "Invalid or duplicate self pool.",
          );
          assert(
            BigInt(f.start_ticks) <= BigInt(p[4]) &&
              BigInt(p[4]) <= BigInt(p[5]) &&
              BigInt(p[5]) <= BigInt(f.end_ticks),
            "Stale self pool read.",
          );
          ordinals.add(p[0]);
          physical.add(p[1]);
        }
        assert(
          finite(h.pools.reduce((sum, p) => sum + p[3], 0)),
          "Pool sum overflow.",
        );
      }
      if (f.rotations !== undefined) {
        assert(
          Array.isArray(f.rotations) && f.rotations.length <= f.objects.length,
          "Invalid orientation list.",
        );
        const rotated = new Set();
        for (const q of f.rotations) {
          assert(
            Array.isArray(q) &&
              q.length === 5 &&
              seen.has(q[0]) &&
              !rotated.has(q[0]) &&
              q.slice(1).every(finite),
            "Invalid or stale orientation candidate.",
          );
          rotated.add(q[0]);
        }
      }
      positionCount += f.objects.length;
      assert(positionCount <= 2000000, "Position limit exceeded.");
      if (
        previous &&
        previous.epoch === f.epoch &&
        f.continuity_valid &&
        !f.skipped
      ) {
        deltas.push(f.t - previous.t);
      }
      if (previous && previous.epoch === f.epoch) updateDeltas.push(f.t - previous.t);
      previous = f;
    }
    if (data.field_samples !== undefined) {
      assert(Array.isArray(data.field_samples) && data.field_samples.length <= 2000000, "Invalid observation field table.");
      for (const f of data.frames) {
        assert(Array.isArray(f.field_refs) && f.field_refs.every(i=>Number.isSafeInteger(i) &&
          i>=0 && i<data.field_samples.length), "Invalid observation field reference.");
        if (multi) {
          const ids=new Set(f.objects.map(p=>p[0]));
          assert(f.field_refs.length===ids.size && f.field_refs.every(i=>{
            const field=data.field_samples[i], stamp=field?.source_timestamp, bracket=f.source_read_bracket;
            return ids.delete(field?.object) && field.source_sha256===bracket[2] &&
              stamp?.start_ticks===bracket[0] && stamp?.end_ticks===bracket[1] && stamp?.frequency===data.frequency &&
              ["roster_source_id","roster_source_tick","source_session_id","source_segment"].every(k=>field[k]===f[k]);
          }), "Independent roster field provenance mismatch.");
        }
      }
    }
    if (data.events !== undefined) {
      assert(Array.isArray(data.events) && data.events.length <= 100000, "Invalid event list.");
      let lastEvent = -Infinity;
      for (const event of data.events) {
        assert(event.schema === "overwatch-decoder.session-observation/1" && event.public_state_eligible === false &&
          finite(event.t) && event.t >= 0 && event.t >= lastEvent, "Invalid observation timeline.");
        if (event.kind === "incoming_source") incomingObservation(event);
        else assert(event.kind === "damage" && event.direction === "outgoing_candidate" &&
          event.attacker === null && event.exact_damage === null &&
          Number.isSafeInteger(event.amount_truncated) && event.amount_truncated >= 0,
          "Invalid or promoted damage feedback candidate.");
        lastEvent = event.t;
      }
    }
    if (data.untimed_events !== undefined) {
      assert(Array.isArray(data.untimed_events) && data.untimed_events.length + (data.events?.length ?? 0) <= 100000,
        "Invalid untimed observation list.");
      for (const event of data.untimed_events) {
        assert(event.schema === "overwatch-decoder.session-observation/1" && event.public_state_eligible === false &&
          event.kind === "incoming_source" && event.t === null && event.timestamp === null,
          "Invalid untimed source observation.");
        incomingObservation(event);
      }
    }
    if (multi) assert(Array.isArray(data.field_samples), "Missing independent roster field table.");
    deltas.sort((a, b) => a - b);
    updateDeltas.sort((a, b) => a - b);
    const updateInterval = updateDeltas.length ? updateDeltas[Math.floor(updateDeltas.length / 2)] : null;
    const interval = data.compact_observations ? 0.05 : Math.min(
      0.05,
      deltas.length ? deltas[Math.floor(deltas.length / 2)] : 0.02,
    );
    const until = data.frames.map((f, i) => {
      const next = data.frames[i + 1];
      if (!f.objects.length) return f.t;
      if (
        next &&
        next.epoch === f.epoch &&
        next.continuity_valid &&
        next.skipped === 0 &&
        next.t - f.t <= Math.min(0.05, interval * 1.5)
      )
        return next.t;
      return Math.min(next?.t ?? Infinity, f.t + interval);
    });
    const segments = [];
    data.frames.forEach((f, i) => {
      if (!f.objects.length) return;
      const last = segments.at(-1);
      if (
        last &&
        last.epoch === f.epoch &&
        f.continuity_valid &&
        f.skipped === 0 &&
        f.t <= last.end + 1e-8
      ) {
        last.end = until[i];
        last.last = i;
      } else
        segments.push({
          start: f.t,
          end: until[i],
          epoch: f.epoch,
          first: i,
          last: i,
        });
    });
    return {
      data,
      interval,
      updateInterval,
      until,
      segments,
      start: 0,
      end: Math.max(data.end_seconds, until.at(-1)),
      positionCount,
    };
  }
  function selectRoster(model, source) {
    if (!independentRoster(model.data)) return model;
    assert(rosterSources.includes(source), "Unknown independent roster source.");
    const frames=model.data.frames.filter(frame=>frame.roster_source_id===source);
    if (!frames.length) return emptyIndexModel(model.data);
    return {...create({...model.data, frames, start_seconds:frames[0].t}), selectedRoster:source};
  }
  function indexAt(model, time) {
    let low = 0,
      high = model.data.frames.length;
    while (low < high) {
      const mid = (low + high) >>> 1;
      if (model.data.frames[mid].t <= time) low = mid + 1;
      else high = mid;
    }
    return low - 1;
  }
  function sampleAt(model, time) {
    if (independentRoster(model.data) && !model.selectedRoster) return inactiveSample();
    const index = indexAt(model, time),
      frame = model.data.frames[index];
    let objects = frame?.objects ?? [];
    if (model.data.compact_observations && frame) {
      const fields = frame.field_refs.map((i) => model.data.field_samples[i]);
      objects = objects.filter((point) => {
        const field = fields.find((row) => row.object === point[0]);
        if (!field) return false;
        const sampled = Number(BigInt(field.source_timestamp.end_ticks) - BigInt(model.data.origin_ticks)) / model.data.frequency;
        return time >= sampled && time - sampled < 0.05;
      });
    }
    const active =
      !!frame && objects.length > 0 && time < model.until[index];
    return {
      index,
      frame,
      active,
      objects: active ? objects : [],
      rotations: active ? (frame.rotations ?? []) : [],
      selfPools: active ? (frame.self_pools ?? null) : null,
      recordedFields: active ? (frame.field_refs?.map((i) => model.data.field_samples[i]) ?? frame.fields ?? []) : [],
    };
  }
  function observationFields(state, objectIndex) {
    if (!state.active || !state.objects.some((p) => p[0] === objectIndex)) return null;
    return state.recordedFields?.find((row) => row.object === objectIndex) ?? null;
  }
  function relationCategory(state, objectIndex) {
    const relation=observationFields(state,objectIndex)?.relation;
    return relation?.validation_status === "current_build_native_ordinary_comparison" &&
      ["self","ally","enemy"].includes(relation.value) ? relation.value : null;
  }
  function healthScaleKey(epoch, field) {
    if (typeof epoch !== "string" || typeof field?.controller_id !== "string" ||
        typeof field.entity_id !== "string" || typeof field.hero?.value !== "string" ||
        field.health?.validation_status !== "current_build_native_current_health_pool_sum" ||
        !finite(field.health.value) || field.health.value < 0) return null;
    return JSON.stringify([epoch, field.object, field.controller_id, field.entity_id,
      field.hero.value, field.observed_build_sha256 ?? null]);
  }
  // A stable display scale from this recording, never a decoded maximum-health claim.
  function observedHealthScales(model) {
    const scales = new Map();
    for (const frame of model.data.frames) {
      const fields = frame.field_refs?.map(i => model.data.field_samples[i]) ?? frame.fields ?? [];
      for (const field of fields) {
        if (!frame.objects.some(p => p[0] === field.object)) continue;
        const key = healthScaleKey(frame.epoch, field);
        if (key !== null) scales.set(key, Math.max(scales.get(key) ?? 0, field.health.value));
      }
    }
    return scales;
  }
  function healthBar(state, objectIndex, scales) {
    const field = observationFields(state, objectIndex), key = healthScaleKey(state.frame?.epoch, field);
    if (key === null) return null;
    const reference = scales.get(key);
    return {value: field.health.value, reference: reference > 0 ? reference : null,
      fraction: reference > 0 ? Math.min(1, field.health.value / reference) : null,
      basis: "highest_recorded_health_for_this_body_and_hero", maximum_health: null};
  }
  function referenceHeight(point, floorY) {
    return Array.isArray(point) && finite(point[2]) && finite(floorY) ? point[2] - floorY : null;
  }
  function healthDepletions(model) {
    const events=[];let previous=new Map();
    for (const frame of model.data.frames) {
      const fields=frame.field_refs?.map(i=>model.data.field_samples[i]) ?? frame.fields ?? [];
      const current=new Map();
      for (const point of frame.objects) {
        const field=fields.find(f=>f.object===point[0]);
        if (!field || field.health?.validation_status!=="current_build_native_current_health_pool_sum" ||
            !finite(field.health.value) || field.health.value<0 || typeof field.controller_id!=="string" ||
            typeof field.entity_id!=="string") continue;
        const prior=previous.get(point[0]);
        if (prior && prior.field.controller_id===field.controller_id && prior.field.entity_id===field.entity_id &&
            prior.epoch===frame.epoch && frame.t>prior.time && frame.t-prior.time<=0.2 && frame.skipped===0 &&
            prior.field.health.value>0 && field.health.value===0) {
          events.push({time:frame.t,object:point[0],point:[...point],relation:field.relation?.validation_status===
            "current_build_native_ordinary_comparison" ? field.relation.value : null,
            basis:"observed_health_reached_zero",confirmed_death:false});
        }
        current.set(point[0],{time:frame.t,epoch:frame.epoch,field});
      }
      previous=current;
    }
    return events;
  }
  // Presentation only. Raw sampleAt(), field values and exported source frames
  // keep their original timing. Never bridge a window, unknown row or long gap.
  function playbackAt(model, time) {
    if (independentRoster(model.data) && !model.selectedRoster) return inactiveSample();
    const raw = sampleAt(model, time), frame = raw.frame;
    if (!frame || time >= model.end) return raw;
    const next = model.data.frames[raw.index + 1];
    const fields = frame.field_refs?.map((i) => model.data.field_samples[i]) ?? frame.fields ?? [];
    const nextFields = next?.field_refs?.map((i) => model.data.field_samples[i]) ?? next?.fields ?? [];
    const objects = [], displaySamples = [];
    for (const point of frame.objects) {
      const field = fields.find((row) => row.object === point[0]);
      const sampled = model.data.compact_observations
        ? field ? Number(BigInt(field.source_timestamp.end_ticks) - BigInt(model.data.origin_ticks)) / model.data.frequency : -Infinity
        : frame.t;
      const age = time - sampled;
      if (age < 0 || age >= 0.2) continue;
      const endpoint = next?.objects.find((p) => p[0] === point[0]);
      const nextField = nextFields.find((row) => row.object === point[0]);
      const sameOwner = !model.data.compact_observations || (field && nextField &&
        typeof field.entity_id === "string" && typeof field.controller_id === "string" &&
        field.entity_id === nextField.entity_id && field.controller_id === nextField.controller_id &&
        field.hero?.value === nextField.hero?.value && field.relation?.value === nextField.relation?.value);
      const span = next ? next.t - frame.t : Infinity;
      const interpolate = endpoint && endpoint[4] === point[4] && sameOwner &&
        next.epoch === frame.epoch && next.skipped === 0 && span > 0 && span <= 0.2 &&
        (model.data.compact_observations || next.continuity_valid) &&
        Math.hypot(...point.slice(1, 4).map((v, i) => endpoint[i + 1] - v)) <= 3;
      const blend = interpolate ? Math.max(0, Math.min(1, (time - frame.t) / span)) : 0;
      objects.push(interpolate ? [point[0], ...point.slice(1, 4).map((v, i) => v + (endpoint[i + 1] - v) * blend), point[4]] : point);
      displaySamples.push({object:point[0], mode:blend > 0 ? "interpolated" : "last_recorded",
        source_seconds:sampled, age_seconds:age, next_seconds:interpolate ? next.t : null});
    }
    const ids = new Set(objects.map((p) => p[0]));
    return {...raw, active:objects.length > 0, objects,
      rotations:(frame.rotations ?? []).filter((q) => ids.has(q[0])),
      selfPools:ids.has(frame.self_pools?.object) ? frame.self_pools : null,
      recordedFields:fields.filter((row) => ids.has(row.object)), displaySamples,
      presentation_only:true};
  }
  function playbackSegments(model) {
    const segments=[];
    model.data.frames.forEach((frame, i) => {
      let newest=-Infinity;
      for (const point of frame.objects) {
        const field=frame.field_refs?.map((n)=>model.data.field_samples[n]).find((row)=>row.object===point[0]);
        const sampled=model.data.compact_observations
          ? field ? Number(BigInt(field.source_timestamp.end_ticks)-BigInt(model.data.origin_ticks))/model.data.frequency : -Infinity
          : frame.t;
        newest=Math.max(newest,sampled);
      }
      const end=Math.min(newest+0.2, model.data.frames[i+1]?.t ?? model.end, model.end);
      if (end<=frame.t) return;
      const last=segments.at(-1);
      if (last?.epoch===frame.epoch && frame.t<=last.end+1e-8) last.end=end;
      else segments.push({start:frame.t,end,epoch:frame.epoch});
    });
    return segments;
  }
  function eventsAt(model, time, maximum = 12) {
    return (model.data.events ?? []).filter((event) => event.t <= time &&
      !(event.kind === "incoming_source" && event.status === "unknown" && event.reason === "context_inactive")).slice(-maximum);
  }
  function eventPresentation(event) {
    if (event.kind === "incoming_source") {
      if (event.status !== "observed") return {
        label: `incoming source unknown · ${event.reason ?? "unresolved"}`,
        detail: "No source identity is supported for this observation.", entityId: null, color: "#8795a4",
      };
      const actor = event.source_actor;
      const name = actor.hero.value ?? actor.entity_id;
      const relation = actor.relation.value ?? "relation unknown";
      const points = actor.position_observations.map((p) => p.value.map((v) => v.toFixed(2)).join(", ")).join(" → ");
      return {label: `incoming source observed · ${name} (${relation})`,
        detail: `Sampled source positions: ${points}. This timestamp is a source observation, not an exact impact. Repeated observations are not hit counts; exact damage is unknown.`,
        entityId: actor.entity_id, color: "#bd9eff"};
    }
    const target = event.target?.hero ?? event.target?.entity_id ?? "Unknown target";
    return {label: `outgoing candidate · ${event.amount_truncated} (truncated) · ${target}`,
      detail: `${event.validation_status}. Target: ${event.target_status}. Exact damage is unknown.`,
      entityId: event.target_status === "resolved" ? event.target?.entity_id : null, color: "#f5ab67"};
  }
  function selfHealthCandidate(state) {
    if (!state.active || !state.selfPools) return null;
    const sum = state.selfPools.pools.reduce(
      (value, pool) => value + pool[3],
      0,
    );
    return {
      status: "candidate",
      object_index: state.selfPools.object,
      raw_sum: sum,
      display_ceil_candidate: Math.ceil(sum),
      declared_pool_count: state.selfPools.declared_count,
      pools: state.selfPools.pools,
      note: "Arithmetic over all declared self pools; HUD-health semantics require recording-specific video validation. Maximum health, individual pool roles and other players are not inferred.",
    };
  }
  function nextObserved(model, time) {
    for (
      let i = Math.max(0, indexAt(model, time) + 1);
      i < model.data.frames.length;
      i++
    ) {
      if (model.data.frames[i].objects.length) return model.data.frames[i].t;
    }
    return null;
  }
  function trail(model, frameIndex, objectIndex, seconds = 2) {
    const result = [],
      frames = model.data.frames,
      current = frames[frameIndex];
    if (!current) return result;
    for (
      let i = frameIndex;
      i >= 0 && current.t - frames[i].t <= seconds;
      i--
    ) {
      const f = frames[i],
        p = f.objects.find((p) => p[0] === objectIndex);
      if (!p) break;
      result.push(p.slice(1, 4));
      if (
        i === 0 ||
        !f.continuity_valid ||
        f.skipped ||
        f.epoch !== frames[i - 1].epoch ||
        model.until[i - 1] < f.t - 1e-8
      )
        break;
    }
    return result;
  }
  function formatTime(t, precision = 2) {
    const rounded =
      Math.round(Math.max(0, t) * 10 ** precision) / 10 ** precision;
    const minutes = Math.floor(rounded / 60);
    return `${String(minutes).padStart(2, "0")}:${(rounded % 60).toFixed(precision).padStart(precision ? 3 + precision : 2, "0")}`;
  }
  function candidateForward(q) {
    if (!Array.isArray(q) || q.length !== 4 || !q.every(finite)) return null;
    const norm = Math.hypot(...q);
    if (norm < 0.85 || norm > 1.15) return null;
    // Display-only convention: normalized xyzw rotates +Z. Not validated camera aim.
    const [x, y, z, w] = q.map((v) => v / norm);
    return [2 * (x * z + w * y), 2 * (y * z - w * x), 1 - 2 * (x * x + y * y)];
  }
  function facingSamples(state, scope = "all") {
    if (!state.active || !["all", "self"].includes(scope)) return [];
    return state.objects.flatMap((point) => {
      if (scope === "self" && point[4] !== true) return [];
      const rotation=state.rotations.find((row)=>row[0]===point[0]);
      const forward=rotation ? candidateForward(rotation.slice(1)) : null;
      return forward ? [{point,rotation:rotation.slice(1),forward}] : [];
    });
  }
  function povPreview(state, eyeHeight = 1.6, objectIndex = null) {
    if (!state.active || !finite(eyeHeight) || eyeHeight<0 || eyeHeight>3) return null;
    const selves=state.objects.filter((p)=>objectIndex===null ? p[4]===true : p[0]===objectIndex);
    if (selves.length!==1) return null;
    const point=selves[0], facing=facingSamples(state,"all").find((f)=>f.point[0]===point[0]);
    return {object:point[0],eye:[point[1],point[2]+eyeHeight,point[3]],
      forward:facing?.forward ?? null, eye_height_illustrative:true, camera_aim_validated:false, fov_validated:false};
  }
  function videoTime(sessionTime, offset, duration) {
    if (![sessionTime, offset, duration].every(finite) || duration <= 0)
      return null;
    const t = sessionTime - offset;
    return {
      t: Math.max(0, Math.min(duration, t)),
      available: t >= 0 && t < duration,
    };
  }
  const api = {
    create,
    selectRoster,
    createIndex,
    validateOverlapChunk,
    chunkAt,
    emptyIndexModel,
    indexSample,
    recorderWindowAt,
    indexAt,
    sampleAt,
    playbackAt,
    playbackSegments,
    selfHealthCandidate,
    observationFields,
    relationCategory,
    observedHealthScales,
    healthBar,
    referenceHeight,
    healthDepletions,
    eventsAt,
    eventPresentation,
    nextObserved,
    trail,
    formatTime,
    candidateForward,
    facingSamples,
    povPreview,
    videoTime,
  };
  if (typeof module !== "undefined") module.exports = api;
  else root.OverwatchDecoderReplay = api;
})(globalThis);
