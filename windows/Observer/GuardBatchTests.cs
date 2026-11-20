using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Owned synthetic byte sources and saved artifacts; never an application profile.</summary>
public static class GuardBatchTests
{
    private sealed class Memory : IMemorySource
    {
        public TargetIdentity Identity { get; set; } = new(321, "fixture.exe", "synthetic", 9, new string('b', 64), "x64");
        internal readonly Dictionary<ulong, byte> Bytes = new();
        internal readonly List<(ulong Address, int Size, long Start, long End)> Reads = new();
        internal Action<ulong, int>? After;
        internal Func<ulong, int, string?>? Failure;
        internal ulong? Partial;
        internal Memory()
        {
            foreach (ulong page in new ulong[] { 0x1000, 0x2000, 0x3000, 0x4000 })
                for (ulong n = 0; n < 4096; n++) Bytes[page + n] = 0;
            I(0x1000, 1); I(0x1010, 2); Ptr(0x1008, 0x2000); I(0x1800, 3); I(0x1810, 99);
            foreach (ulong a in new ulong[] { 0x2000, 0x3000, 0x4000 }) { I(a, 4); I(a + 8, 7); Bytes[a + 12] = 255; }
        }
        internal void I(ulong a, int n) => Set(a, BitConverter.GetBytes(n));
        internal void Ptr(ulong a, ulong n) => Set(a, BitConverter.GetBytes(n));
        internal void Set(ulong a, byte[] b) { for (int n = 0; n < b.Length; n++) Bytes[a + (ulong)n] = b[n]; }
        public byte[] Read(ulong address, int size)
        {
            long start = Stopwatch.GetTimestamp();
            try
            {
                string? error = Failure?.Invoke(address, size);
                if (error is not null) throw new ObservationException(error, "Synthetic source failure.");
                byte[] result = new byte[size];
                for (int n = 0; n < size; n++)
                    if (!Bytes.TryGetValue(address + (ulong)n, out result[n])) throw new ObservationException("unreadable_range", "Synthetic missing byte.");
                After?.Invoke(address, size); return Partial == address ? result[..^1] : result;
            }
            finally { Reads.Add((address, size, start, Stopwatch.GetTimestamp())); }
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private sealed class Writer(Action<JsonElement> frame) : StringWriter
    {
        private readonly StringBuilder pending = new();
        internal readonly List<JsonElement> Lines = new();
        public override void Write(string? s) => pending.Append(s);
        public override void Write(char c)
        {
            if (c != '\n') { pending.Append(c); return; }
            using var doc = JsonDocument.Parse(pending.ToString()); var e = doc.RootElement.Clone(); pending.Clear(); Lines.Add(e);
            if (e.GetProperty("kind").GetString() == "frame") frame(e);
        }
    }
    private static JsonObject Guard(string key, ulong a, string bytes) => new() { [key] = a, ["bytes_hex"] = bytes };
    private static JsonObject Profile(Memory m) => new()
    {
        ["schema"] = "overwatch-decoder.field-profile/3", ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(m.Identity)),
        ["absolute_guard_reads"] = new JsonObject { ["algorithm"] = GuardBatches.Algorithm },
        ["paths"] = new JsonArray(new JsonObject { ["name"] = "storage", ["root_address"] = 0x1000,
            ["root_guards"] = new JsonArray(Guard("offset", 0, "01000000"), Guard("offset", 16, "02000000")),
            ["hops"] = new JsonArray(new JsonObject { ["pointer_offset"] = 8,
                ["destination_guards"] = new JsonArray(Guard("offset", 0, "04000000")) }) }),
        ["fields"] = new JsonArray(new JsonObject { ["name"] = "value", ["type"] = "i32", ["path"] = "storage", ["offset"] = 8 },
            new JsonObject { ["name"] = "byte", ["type"] = "u8", ["path"] = "storage", ["offset"] = 12 },
            new JsonObject { ["name"] = "other", ["type"] = "i32", ["address"] = 0x1810,
                ["guards"] = new JsonArray(Guard("address", 0x1800, "03000000")) })
    };
    public static int Run()
    {
        int checks = 0, files = 0; string phase = "setup";
        void Check(bool ok, string why)
        { if (!ok) throw new ObservationException("self_test_failed", "guard-batch:" + phase + ":" + why); checks++; }
        void Throws(Action action, string code)
        {
            try { action(); } catch (ObservationException e) { Check(e.Code == code, "expected " + code + " got " + e.Code); return; }
            throw new ObservationException("self_test_failed", "guard-batch:" + phase + ":missing failure " + code);
        }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-batch-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string New(string name) => Path.Combine(root, files++ + "-" + name);
        string Input(JsonObject p) { string path = New("profile.json"); File.WriteAllText(path, p.ToJsonString()); return path; }
        FieldStream.Profile Parse(JsonObject p) => FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p));
        Writer Capture(Memory m, JsonObject? p = null, int frames = 1, Action<int>? next = null,
            Action<CancellationTokenSource>? setup = null, FieldStream.Limits? limits = null)
        {
            using var stop = new CancellationTokenSource(); setup?.Invoke(stop); int count = 0;
            var w = new Writer(_ => { count++; next?.Invoke(count); if (count >= frames) stop.Cancel(); });
            FieldStream.RunBounded(m, Input(p ?? Profile(m)), 10, TimeSpan.FromSeconds(30), w, stop.Token, limits ?? new());
            Check(w.Lines.Count > 0 && w.Lines[^1].GetProperty("kind").GetString() == "summary", "terminal summary"); return w;
        }
        static JsonElement Field(Writer w, string name, int frame = 0) => w.Lines[frame].GetProperty("fields").GetProperty(name);
        void Unknown(Writer w, string name, int frame = 0) => Check(Field(w, name, frame).GetProperty("status").GetString() == "unknown" &&
            Field(w, name, frame).GetProperty("value").ValueKind == JsonValueKind.Null, name + " unknown without stale value");
        void Value(Writer w, string name, int value, int frame = 0) => Check(Field(w, name, frame).GetProperty("status").GetString() == "observed" &&
            Field(w, name, frame).GetProperty("value").GetInt32() == value, name + " observed exact value");
        string Record(bool empty = false, bool relocate = false)
        {
            var m = new Memory(); using var stop = new CancellationTokenSource(); if (empty) stop.Cancel(); int ends = 0;
            m.After = (a, _) => { if (a != 0x1800 || ++ends % 2 != 0) return; if (ends == 2 && relocate) m.Ptr(0x1008, 0x3000); if (ends == 8) stop.Cancel(); };
            string dir = New("recording"); FieldRecording.Record(m, Input(Profile(m)), dir, 10, TimeSpan.FromSeconds(30), stop.Token); return dir;
        }
        try
        {
            phase = "healthy"; var m = new Memory(); var p = Profile(m); var plan = Parse(p).Batching!;
            Check(plan.Policy.maximum_span_bytes == 128 && plan.Policy.maximum_gap_bytes == 32, "explicit v3 defaults");
            Check(plan.Batches.Length == 2 && plan.Batches[0].Guards.SequenceEqual(new[] { 0, 1 }) && plan.Batches[0].Width == 20, "consecutive exact-scope plan");
            Check(plan.ReadBytes == 81 && plan.UnbatchedBytes == 57 && plan.UnbatchedCalls == 13 && plan.GapBytes == 24 && plan.ReadCalls == 11, "full gap budget and physical call plan");
            var w = Capture(m); Value(w, "value", 7); Value(w, "byte", 255); Value(w, "other", 99);
            Check(m.Reads.Select(r => (r.Address, r.Size)).SequenceEqual(new (ulong, int)[] {
                (0x1000,20),(0x1800,4),(0x1008,8),(0x2000,4),(0x2008,4),(0x200c,1),(0x1810,4),(0x2000,4),(0x1008,8),(0x1000,20),(0x1800,4) }), "physical pre path fields reverse-post and absolute-post order: " + string.Join(",", m.Reads.Take(20).Select(r => $"{r.Address:x}/{r.Size}")));
            Check(w.Lines[0].GetProperty("physical_read_calls").GetInt32() == m.Reads.Count &&
                w.Lines[0].GetProperty("physical_read_bytes").GetInt32() == m.Reads.Sum(r => r.Size), "actual counts");
            var batch = w.Lines[0].GetProperty("guard_batches_before")[0];
            Check(batch.GetProperty("start_ticks").GetInt64() <= m.Reads[0].Start && batch.GetProperty("end_ticks").GetInt64() >= m.Reads[0].End,
                "batch interval encloses the actual source call");
            Check(batch.GetProperty("returned_bytes").GetInt32() == 20 && !w.Lines[0].GetProperty("guards_before")[0].TryGetProperty("start_ticks", out _), "one real batch interval, no fake per-slice intervals");
            Check(w.Lines[^1].GetProperty("published_frame_read_bytes").GetInt32() == 81 && w.Lines[^1].GetProperty("guard_gap_read_bytes").GetInt32() == 24, "summary counts gaps");
            Check(w.Lines[^1].GetProperty("unbatched_planned_read_calls_per_frame").GetInt32() == 13 &&
                w.Lines[^1].GetProperty("planned_read_calls_per_frame").GetInt32() == 11, "comparable unbatched and physical call plans");

            phase = "gap-fault"; m = new(); m.Bytes.Remove(0x1006); w = Capture(m);
            Unknown(w, "value"); Unknown(w, "byte"); Value(w, "other", 99);
            Check(!m.Reads.Any(r => r.Address == 0x1008) && m.Reads.Count(r => r.Address == 0x1000) == 2, "failed gap prevents traversal, no fallback or retry");
            Check(w.Lines[0].GetProperty("guard_batches_before")[0].GetProperty("returned_bytes").ValueKind == JsonValueKind.Null, "exception count is unknown, not invented zero");
            phase = "short-buffer"; m = new() { Partial = 0x1000 }; w = Capture(m); Unknown(w, "value"); Value(w, "other", 99);
            Check(w.Lines[0].GetProperty("guards_before").EnumerateArray().Take(2).All(g => !g.GetProperty("ok").GetBoolean() && g.GetProperty("bytes_hex").ValueKind == JsonValueKind.Null), "readable prefix never accepted");
            Check(w.Lines[0].GetProperty("guard_batches_before")[0].GetProperty("returned_bytes").GetInt32() == 19, "known partial return retained");
            phase = "slice-mismatch"; m = new(); m.I(0x1010, 8); w = Capture(m);
            Check(w.Lines[0].GetProperty("guards_before")[0].GetProperty("ok").GetBoolean() && !w.Lines[0].GetProperty("guards_before")[1].GetProperty("ok").GetBoolean(), "successful batch checks slices independently");
            Unknown(w, "value"); Value(w, "other", 99);
            phase = "post-mismatch"; m = new(); m.After = (a, _) => { if (a == 0x2008) m.I(0x1010, 8); }; w = Capture(m); Unknown(w, "value"); Value(w, "other", 99);
            Check(Field(w, "value").GetProperty("reason").GetString() == "path_root_guard_after", "post slice invalidates earlier field read");
            phase = "recovery"; m = new() { Partial = 0x1000 }; w = Capture(m, frames: 2, next: _ => m.Partial = null); Unknown(w, "value"); Value(w, "value", 7, 1);
            phase = "fatal"; m = new(); m.Failure = (a, _) => a == 0x1000 ? "permission_denied" : null; w = Capture(m);
            Unknown(w, "other"); Check(m.Reads.Count == 1, "fatal source error stops all subsequent calls");
            batch = w.Lines[0].GetProperty("guard_batches_after")[0];
            Check(!batch.GetProperty("attempted").GetBoolean() && new[] { "address_hex", "start_ticks", "end_ticks", "returned_bytes" }.All(k => batch.GetProperty(k).ValueKind == JsonValueKind.Null), "unattempted evidence has no read address/count/interval");
            phase = "cancel-during-call"; m = new(); w = Capture(m, setup: c => m.After = (_, _) => c.Cancel());
            Check(m.Reads.Count == 1 && w.Lines[0].GetProperty("guard_batches_before")[0].GetProperty("attempted").GetBoolean(), "completed first call counted despite cancellation"); Unknown(w, "other");
            phase = "cancel-before"; m = new(); w = Capture(m, setup: c => c.Cancel()); Check(m.Reads.Count == 0 && w.Lines.Count == 1, "cancelled zero-frame summary");
            phase = "gap-budget"; m = new(); w = Capture(m, limits: new(ReadBytes: 19)); Check(m.Reads.Count == 0, "full 20-byte span reserved before read, not 8 logical bytes"); Unknown(w, "other");
            phase = "unpublished"; m = new(); w = Capture(m, limits: new(OutputBytes: 8192));
            Check(w.Lines.Count == 1 && w.Lines[0].GetProperty("unpublished_frame_read_calls").GetInt32() == 11 &&
                w.Lines[0].GetProperty("unpublished_frame_read_bytes").GetInt32() == 81 && w.Lines[0].GetProperty("published_frame_read_calls").GetInt32() == 0, "output refusal truthfully accounts for unsaved terminal frame");

            phase = "plan-boundaries"; m = new(); p = Profile(m); p["absolute_guard_reads"]!["maximum_gap_bytes"] = 0;
            Check(Parse(p).Batching!.Batches.Length == 3, "zero-gap policy separates guarded intervals");
            p = Profile(m); p["paths"]![0]!["root_guards"] = new JsonArray(Guard("offset", 16, "02000000"), Guard("offset", 0, "01000000"));
            Check(Parse(p).Batching!.Batches.Length == 3, "descending addresses never sorted");
            p = Profile(m); p["fields"]![2]!["guards"] = new JsonArray(Guard("address", 0x1014, "00000000"));
            Check(Parse(p).Batching!.Batches.Length == 2 && Parse(p).Batching!.Batches[0].Guards.Length == 2, "adjacent different field scopes never combine");
            p = Profile(m); p["paths"]![0]!["root_guards"]!.AsArray().Add(Guard("offset", 1, "000000"));
            Check(Parse(p).Batching!.Batches.Length == 3, "later overlapping lower address preserves order boundary");
            p = Profile(m); p["paths"]![0]!["root_guards"] = new JsonArray(Guard("offset", 0, "01000000"), Guard("offset", 1, "000000"));
            Check(Parse(p).Batching!.Batches[0].Width == 4 && Parse(p).Batching!.Batches[0].GapBytes == 0, "overlap union reads each byte once");
            foreach (Action<JsonObject> mutate in new Action<JsonObject>[] {
                x => x["absolute_guard_reads"]!["algorithm"] = "sort_everything",
                x => x["absolute_guard_reads"]!["hidden_retry"] = true,
                x => x["paths"]![0]!["root_guards"]![0]!["offset"] = 4095 })
            { p = Profile(m); mutate(p); Throws(() => Parse(p), "invalid_field_profile"); }
            foreach (Action<JsonObject> mutate in new Action<JsonObject>[] {
                x => x["absolute_guard_reads"]!["maximum_gap_bytes"] = 33,
                x => x["absolute_guard_reads"]!["maximum_span_bytes"] = 513 })
            { p = Profile(m); mutate(p); Throws(() => Parse(p), "field_profile_limit"); }
            p = Profile(m); p["schema"] = "overwatch-decoder.field-profile/2"; Throws(() => Parse(p), "invalid_field_profile");

            phase = "scope-and-budget";
            var model = Parse(Profile(m));
            var scoped = model with { Guards = [new(0x1000, [1]), new(0x1001, [2])],
                Fields = [new("a", "i32", 0, 4, 1, null, null, [0, 1], 0), new("b", "i32", 0, 4, 1, null, null, [0, 1], 1)],
                Paths = [model.Paths![0] with { RootGuards = [0] }, model.Paths[0] with { RootGuards = [1] }] };
            Check(GuardBatches.Build(scoped, new(128, 32)).Batches.Length == 2, "equal field scopes still respect distinct direct path-root scopes");
            JsonObject FixedProfile(int guards, int fieldCount, int width, int stride) => new()
            {
                ["schema"] = "overwatch-decoder.field-profile/3", ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(m.Identity)),
                ["paths"] = new JsonArray(), ["absolute_guard_reads"] = new JsonObject { ["algorithm"] = GuardBatches.Algorithm, ["maximum_span_bytes"] = 512 },
                ["guards"] = new JsonArray(Enumerable.Range(0, guards).Select(n => (JsonNode)Guard("address", (ulong)(0x10000 + n / 40 * 4096 + n % 40 * stride), new string('0', width * 2))).ToArray()),
                ["fields"] = new JsonArray(Enumerable.Range(0, fieldCount).Select(n => (JsonNode)new JsonObject { ["name"] = "f" + n, ["type"] = "u8", ["address"] = 0x900000 }).ToArray())
            };
            Check(Parse(FixedProfile(40, 1, 1, 1)).Batching!.Batches.Length == 2, "32 logical guards maximum per batch");
            Check(Parse(FixedProfile(1, 128, 1, 1)).Fields.Length == 128, "all 128 fields retained");
            p = FixedProfile(185, 1, 64, 96); Throws(() => Parse(p), "field_profile_limit");
            p["schema"] = "overwatch-decoder.field-profile/1"; p.Remove("absolute_guard_reads"); p.Remove("paths");
            Check(Parse(p).ReadBytes == 23681, "gap reads alone can exceed frame cap despite valid unbatched bytes");

            phase = "record-consumers"; string recorded = Record(relocate: true); var originalHashes = Hashes(recorded);
            var verified = FieldRecordingVerification.Verify(recorded);
            Check(verified.valid && verified.status == "verified_stopped" && verified.frames == 4 && verified.unknown_fields == 3, "strict v3 recording:" + verified.error_code);
            string compact = New("compact.jsonl"), timeline = New("timeline.jsonl");
            var exported = FieldExport.Export(recorded, compact); var summary = FieldSummary.Summarize(recorded); var changed = FieldTimeline.Export(recorded, timeline);
            Check(exported.frames == 4 && changed.frames == 4 && summary.GetProperty("frames").GetInt32() == 4, "all consumers accept validated v3 buffers");
            string compactText = File.ReadAllText(compact), timelineText = File.ReadAllText(timeline);
            Check(!compactText.Contains("address_hex") && !compactText.Contains("bytes_hex") && !timelineText.Contains("address_hex") && !timelineText.Contains("bytes_hex"), "compact outputs omit private structural evidence");
            Check(timelineText.Contains("storage_path_changed") && changed.numeric_changes == 0, "equal numeric value after path relocation resets comparison");
            Check(originalHashes.SequenceEqual(Hashes(recorded)), "all consumers leave source bytes unchanged");
            string empty = Record(empty: true); var emptyResult = FieldRecordingVerification.Verify(empty);
            Check(emptyResult.valid && emptyResult.frames == 0 && FieldSummary.Summarize(empty).GetProperty("frames").GetInt32() == 0, "valid stopped zero frames");
            Check(FieldExport.Export(empty, New("empty.jsonl")).frames == 0 && FieldTimeline.Export(empty, New("empty-timeline.jsonl")).frames == 0, "zero-frame consumers");
            string completed = New("completed"); m = new();
            FieldRecording.Record(m, Input(Profile(m)), completed, 10, TimeSpan.FromMilliseconds(50), default);
            var completedResult = FieldRecordingVerification.Verify(completed);
            // Completion is independent of whether a heavily delayed host gets a frame before the deadline.
            Check(completedResult.valid && completedResult.complete && completedResult.status == "verified_complete", "duration-complete v3 artifact verifies");
            Check(FieldExport.Export(completed, New("completed.jsonl")).source_status == "verified_complete", "compact export preserves source completion");

            phase = "recorded-failures";
            foreach (string failure in new[] { "gap", "partial", "fatal-field", "cancel-field" })
            {
                m = new(); using var end = new CancellationTokenSource(); int passes = 0;
                if (failure == "gap") m.Bytes.Remove(0x1006);
                if (failure == "partial") m.Partial = 0x1000;
                if (failure == "fatal-field") m.Failure = (a, _) => a == 0x2008 ? "permission_denied" : null;
                m.After = (a, _) => { if (failure == "cancel-field" && a == 0x2008 || a == 0x1800 && ++passes == 4) end.Cancel(); };
                string failed = New("recorded-" + failure);
                FieldRecording.Record(m, Input(Profile(m)), failed, 10, TimeSpan.FromSeconds(30), end.Token);
                var result = FieldRecordingVerification.Verify(failed);
                Check(result.valid && result.status == "verified_stopped" && result.frames is >= 1 and <= 2 && result.unknown_fields >= 3,
                    "genuine " + failure + " physical evidence verifies:" + result.error_code);
            }

            phase = "tampering";
            foreach (var mutation in new (string name, Action<JsonObject> edit)[] {
                ("slice", x => x["guards_before"]![0]!["slice_offset"] = 1),
                ("bytes", x => x["guards_before"]![0]!["bytes_hex"] = "ff000000"),
                ("batch-address", x => x["guard_batches_before"]![0]!["address_hex"] = "0000000000001001"),
                ("partial", x => x["guard_batches_before"]![0]!["returned_bytes"] = 19),
                ("attempt", x => x["guard_batches_before"]![0]!["attempted"] = false),
                ("count", x => x["physical_read_calls"] = 12),
                ("gap", x => x["guard_gap_read_bytes"] = 0),
                ("time", x => x["guard_batches_after"]![0]!["start_ticks"] = 0),
                ("mapping", x => x["guards_before"]![1]!["batch_id"] = 1),
                ("terminal", x => x["terminal_reason"] = "cancelled") })
            {
                string copy = New(mutation.name); Copy(recorded, copy); var rows = Raw(copy); mutation.edit(rows[0]); Rewrite(copy, rows);
                var invalid = FieldRecordingVerification.Verify(copy); Check(!invalid.valid && invalid.status == "invalid", "tampered " + mutation.name + " rejected");
                string destination = New("rejected.jsonl"); Throws(() => FieldExport.Export(copy, destination), "invalid_recording"); Check(!File.Exists(destination), "invalid source never published");
            }
            string badSummary = New("summary-count"); Copy(recorded, badSummary); var badRows = Raw(badSummary); badRows[^1]["unpublished_frame_read_bytes"] = 1; Rewrite(badSummary, badRows);
            Check(!FieldRecordingVerification.Verify(badSummary).valid, "summary physical counts exact");
            string badPlan = New("summary-plan"); Copy(recorded, badPlan); badRows = Raw(badPlan);
            badRows[^1]["unbatched_planned_read_calls_per_frame"] = 12; Rewrite(badPlan, badRows);
            Check(!FieldRecordingVerification.Verify(badPlan).valid, "unbatched planned call count recomputed from saved profile");
            phase = "terminal-semantics";
            string terminalMismatch = New("terminal-mismatch"); Copy(recorded, terminalMismatch); var terminalRows = Raw(terminalMismatch);
            terminalRows[^2]["terminal_reason"] = "permission_denied";
            foreach (var field in terminalRows[^2]["fields"]!.AsObject()) field.Value!["reason"] = "permission_denied";
            Rewrite(terminalMismatch, terminalRows); Check(!FieldRecordingVerification.Verify(terminalMismatch).valid, "summary reason must agree with recorded terminal frame");
            string afterTerminal = New("frame-after-terminal"); Copy(recorded, afterTerminal); terminalRows = Raw(afterTerminal);
            terminalRows[0]["terminal_reason"] = "cancelled";
            foreach (var field in terminalRows[0]["fields"]!.AsObject()) { field.Value!["status"] = "unknown"; field.Value!["value"] = null; field.Value!["reason"] = "cancelled"; }
            Rewrite(afterTerminal, terminalRows); var later = FieldRecordingVerification.Verify(afterTerminal);
            Check(!later.valid && later.error_code == "frame_after_terminal", "later frame after terminal is impossible");
            phase = "refused-zero-frame-recording";
            m = new(); p = Profile(m);
            for (int n = 0; n < 40; n++) { var clone = p["fields"]![2]!.DeepClone(); clone["name"] = "more_" + n; p["fields"]!.AsArray().Add(clone); }
            string refusedRecording = New("refused-recording");
            FieldRecording.RecordBounded(m, Input(p), refusedRecording, 10, TimeSpan.FromSeconds(30), default, new(ChunkBytes: 8192));
            var refusedResult = FieldRecordingVerification.Verify(refusedRecording);
            Check(refusedResult.valid && refusedResult.frames == 0 && refusedResult.status == "verified_stopped", "real writer refusal has a valid zero-frame recording:" + refusedResult.error_code);
            string refusedExport = New("refused-export.jsonl"); FieldExport.Export(refusedRecording, refusedExport);
            Check(File.ReadAllText(refusedExport).Contains(GuardBatches.UnpublishedAccounting), "exported aggregate counts retain unpublished accounting qualification");
            var refusedRows = Raw(refusedRecording);
            Check(refusedRows.Length == 1 && refusedRows[0]["unpublished_frames"]!.GetValue<int>() == 1 && refusedRows[0]["unpublished_frame_read_calls"]!.GetValue<int>() > 0, "one genuinely sampled but unpublished frame");
            refusedRows[0]["unpublished_frame_read_calls"] = 1; refusedRows[0]["read_calls"] = 1;
            refusedRows[0]["unpublished_frame_read_bytes"] = 1; refusedRows[0]["read_bytes"] = 1;
            refusedRows[0]["unpublished_frame_guard_gap_bytes"] = 0; refusedRows[0]["guard_gap_read_bytes"] = 0;
            Rewrite(refusedRecording, refusedRows);
            Check(!FieldRecordingVerification.Verify(refusedRecording).valid, "impossible one-byte first batch tail rejected");

            phase = "recovery"; string split = New("split"); Copy(recorded, split); Rewrite(split, Raw(split));
            Check(FieldRecordingVerification.Verify(split).valid, "controlled one-line member layout verifies");
            string[] entries = File.ReadAllLines(Path.Combine(split, "chunks.jsonl")); var last = JsonNode.Parse(entries[^1])!;
            using (var file = File.OpenWrite(Path.Combine(split, "samples.jsonl.gz"))) file.SetLength(last["offset"]!.GetValue<long>() + last["compressed_bytes"]!.GetValue<long>() - 1);
            var prefix = FieldRecordingVerification.Verify(split, true);
            Check(!prefix.valid && prefix.recoverable && !prefix.complete && prefix.frames == 4 && !prefix.terminal_summary_verified, "truncated summary recovers only indexed frames");
            phase = "consumer-control"; using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            string refused = New("cancel.jsonl"); Throws(() => FieldExport.Export(recorded, refused, cancelled.Token), "cancelled"); Check(!File.Exists(refused), "cancelled export unpublished");
            Throws(() => FieldTimeline.Export(recorded, compact), "output_exists");
            return checks;
        }
        finally { Directory.Delete(root, true); }
    }
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string[] Hashes(string dir) => Directory.GetFiles(dir).Order().Select(p => Path.GetFileName(p) + ":" + Hash(File.ReadAllBytes(p))).ToArray();
    private static void Copy(string from, string to) { Directory.CreateDirectory(to); foreach (string f in Directory.GetFiles(from)) File.Copy(f, Path.Combine(to, Path.GetFileName(f))); }
    private static JsonObject[] Raw(string dir)
    {
        using var f = File.OpenRead(Path.Combine(dir, "samples.jsonl.gz")); using var gzip = new GZipStream(f, CompressionMode.Decompress); using var reader = new StreamReader(gzip);
        var rows = new List<JsonObject>(); while (reader.ReadLine() is { } line) rows.Add(JsonNode.Parse(line)!.AsObject()); return rows.ToArray();
    }
    // Cryptographically coherent malicious artifacts exercise semantic checks, not merely digest failure.
    private static void Rewrite(string dir, JsonObject[] rows)
    {
        rows[^1]["frame_output_utf8_bytes"] = rows[..^1].Sum(r => (long)Encoding.UTF8.GetByteCount(r.ToJsonString()) + 1);
        using var samples = new MemoryStream(); using var index = new MemoryStream(); long jsonBytes = 0;
        long checkpoint = rows.Length > 1 ? rows[^2]["end_ticks"]!.GetValue<long>() : rows[0]["monotonic_origin_ticks"]!.GetValue<long>();
        for (int n = 0; n < rows.Length; n++)
        {
            byte[] raw = Encoding.UTF8.GetBytes(rows[n].ToJsonString() + "\n"); using var compressed = new MemoryStream();
            using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true)) gzip.Write(raw);
            byte[] bytes = compressed.ToArray(); byte[] entry = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            { schema = "overwatch-decoder.field-recording-chunk/1", sequence = n, offset = samples.Length, compressed_bytes = bytes.Length, json_bytes = raw.Length,
                first_line = n, lines = 1, compressed_sha256 = Hash(bytes), json_sha256 = Hash(raw), checkpoint_ticks = checkpoint,
                monotonic_frequency = rows[n]["monotonic_frequency"]!.GetValue<long>() }) + "\n");
            samples.Write(bytes); index.Write(entry); jsonBytes += raw.Length;
        }
        byte[] sb = samples.ToArray(), ib = index.ToArray(); File.WriteAllBytes(Path.Combine(dir, "samples.jsonl.gz"), sb); File.WriteAllBytes(Path.Combine(dir, "chunks.jsonl"), ib);
        string path = Path.Combine(dir, "manifest.json"); var manifest = JsonNode.Parse(File.ReadAllBytes(path))!.AsObject(); manifest["stream_summary"] = rows[^1].DeepClone();
        manifest["durable_chunks"] = rows.Length; manifest["durable_lines"] = rows.Length; manifest["durable_compressed_bytes"] = sb.Length;
        manifest["durable_json_bytes"] = jsonBytes; manifest["index_bytes"] = ib.Length;
        manifest["samples_sha256"] = Hash(sb); manifest["durable_samples_prefix_sha256"] = Hash(sb); manifest["index_sha256"] = Hash(ib); manifest["durable_index_prefix_sha256"] = Hash(ib);
        File.WriteAllText(path, manifest.ToJsonString());
    }
}
