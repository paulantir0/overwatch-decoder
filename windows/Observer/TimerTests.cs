using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

public static class TimerTests
{
    internal static byte[] State(long stamp, float baseline, float rate) => BitConverter.GetBytes(stamp).Concat(BitConverter.GetBytes(baseline)).Concat(BitConverter.GetBytes(rate)).ToArray();
    internal static JsonObject Profile(TargetIdentity target, ulong guard = 0xffe, ulong state = 0x2000, ulong clock = 0x3000) => new()
    {
        ["schema"] = "overwatch-decoder.field-profile/4", ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(target)),
        ["guards"] = new JsonArray(new JsonObject { ["address"] = guard, ["bytes_hex"] = "01020304" }),
        ["fields"] = new JsonArray(new JsonObject { ["name"] = "timer", ["type"] = "f32", ["codec"] = TimerCodec.Name,
            ["address"] = state, ["clock_address"] = clock, ["counter_scale_f32_hex"] = "6f12833a" })
    };
    private sealed class Memory : IMemorySource
    {
        public TargetIdentity Identity { get; set; } = new(321, "fixture.exe", "synthetic", 9, new string('b', 64), "x64");
        internal readonly Dictionary<ulong, byte> Bytes = new();
        internal readonly List<(ulong Address, int Size, long Start, long End)> Reads = new();
        internal Action<ulong>? After;
        internal Func<ulong, string?>? Failure;
        internal ulong? Partial;
        internal Memory() { Set(0xffe, [1, 2, 3, 4]); Set(0x2000, State(1000, 12, 1)); Set(0x3000, BitConverter.GetBytes(2000L)); Set(0x4000, BitConverter.GetBytes(99)); }
        internal void Set(ulong a, byte[] b) { for (int i = 0; i < b.Length; i++) Bytes[a + (ulong)i] = b[i]; }
        public byte[] Read(ulong a, int size)
        {
            long start = Stopwatch.GetTimestamp();
            try
            {
                string? error = Failure?.Invoke(a); if (error is not null) throw new ObservationException(error, "Synthetic timer read.");
                byte[] b = Enumerable.Range(0, size).Select(i => Bytes.GetValueOrDefault(a + (ulong)i)).ToArray(); After?.Invoke(a);
                return Partial == a ? b[..^1] : b;
            }
            finally { Reads.Add((a, size, start, Stopwatch.GetTimestamp())); }
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private sealed class Writer(Action<JsonElement> frame) : StringWriter
    {
        private readonly StringBuilder pending = new();
        internal readonly List<JsonElement> Lines = new();
        public override void Write(string? value) => pending.Append(value);
        public override void Write(char c)
        {
            if (c != '\n') { pending.Append(c); return; }
            using var doc = JsonDocument.Parse(pending.ToString()); var row = doc.RootElement.Clone(); pending.Clear(); Lines.Add(row);
            if (row.GetProperty("kind").GetString() == "frame") frame(row);
        }
    }
    public static int Run()
    {
        int assertions = TimerFrameAdmissionTests.Run(), files = 0; string phase = "setup";
        void Check(bool good, string why) { if (!good) throw new ObservationException("self_test_failed", "timer:" + phase + ":" + why); assertions++; }
        void Throws(Action a, string code)
        { try { a(); } catch (ObservationException e) { Check(e.Code == code, "expected " + code + " got " + e.Code); return; } Check(false, "missing " + code); }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-timer-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string New(string label) => Path.Combine(root, files++ + "-" + label);
        string Input(JsonObject p) { string path = New("profile.json"); File.WriteAllText(path, p.ToJsonString()); return path; }
        Writer Capture(Memory m, JsonObject? p = null, int frames = 1, Action<int>? next = null, Action<CancellationTokenSource>? setup = null, FieldStream.Limits? limits = null)
        {
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)); setup?.Invoke(stop); int count = 0;
            var w = new Writer(_ => { count++; next?.Invoke(count); if (count == frames) stop.Cancel(); });
            FieldStream.RunBounded(m, Input(p ?? Profile(m.Identity)), 10, TimeSpan.FromSeconds(30), w, stop.Token, limits ?? new());
            Check(w.Lines.Count > 0 && w.Lines[^1].GetProperty("kind").GetString() == "summary", "summary"); return w;
        }
        static JsonElement F(Writer w, int n = 0) => w.Lines[n].GetProperty("fields").GetProperty("timer");
        void Unknown(Writer w, string error) => Check(F(w).GetProperty("status").GetString() == "unknown" && F(w).GetProperty("value").ValueKind == JsonValueKind.Null && F(w).GetProperty("reason").GetString() == error, "unknown " + error);
        void Value(Writer w, double value, int n = 0) => Check(F(w, n).GetProperty("status").GetString() == "observed" && F(w, n).GetProperty("value").GetDouble() == value, "observed result");
        static string Hash(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));
        try
        {
            phase = "arithmetic";
            double Calc(long clock, long stamp, float baseline, float rate = 1, float scale = .001f)
            { var r = TimerCodec.Evaluate(State(stamp, baseline, rate), BitConverter.GetBytes(clock), scale, null, null); Check(r.Error is null, "finite arithmetic"); return (double)r.Value!; }
            Check(Calc(2000, 1000, 12) == 11 && Calc(15000, 1000, 12) == 0 && Calc(1000, 2000, 12) == 13, "elapsed/clamp/backstep");
            Check(Calc(long.MinValue, long.MaxValue, 12, scale: 1) == 11 && Calc(long.MaxValue, long.MinValue, 12, scale: 1) == 13, "native signed wrap");
            long tricky = (1L << 62) + (1L << 38) + 1;
            Check(Calc(tricky, 0, 0, -1, 1) == (double)((1L << 62) + (1L << 39)), "direct i64 conversion avoids double rounding");
            Check(Calc((1L << 62) + (1L << 38), 0, 0, -1, 1) == (double)(1L << 62), "ties even");
            Check(BitConverter.DoubleToInt64Bits(Calc(1, 1, -0f)) == long.MinValue, "negative zero preserved");
            Check(TimerCodec.Evaluate(State(0, float.NaN, 1), BitConverter.GetBytes(1L), 1, null, null).Error == "non_finite_operand", "nonfinite operand");
            Check(TimerCodec.Evaluate(State(0, 1, float.MaxValue), BitConverter.GetBytes(long.MaxValue), float.MaxValue, null, null).Error == "non_finite_calculation", "nonfinite intermediate");

            phase = "physical-evidence"; var m = new Memory(); var w = Capture(m); Value(w, 11);
            Check(m.Reads.Select(r => (r.Address, r.Size)).SequenceEqual(new[] { (0xffeUL, 4), (0x2000UL, 16), (0x3000UL, 8), (0xffeUL, 4) }), "exact serial cross-page guard/state/clock/post order: " + string.Join(",", m.Reads.Select(r => r.Address.ToString("x") + "/" + r.Size)));
            Check(w.Lines[0].GetProperty("schema").GetString() == "overwatch-decoder.field-stream/4" && w.Lines[0].GetProperty("physical_read_calls").GetInt32() == 4 && w.Lines[0].GetProperty("physical_read_bytes").GetInt32() == 32, "exact budget");
            var operand = F(w).GetProperty("operands");
            foreach (var item in new[] { ("state", 1), ("clock", 2) })
            {
                var o = operand.GetProperty(item.Item1); var r = m.Reads[item.Item2];
                Check(o.GetProperty("start_ticks").GetInt64() <= r.Start && o.GetProperty("end_ticks").GetInt64() >= r.End, "actual source interval enclosed");
                Check(o.GetProperty("returned_bytes").GetInt32() == r.Size && o.GetProperty("bytes_hex").GetString()!.Length == 2 * r.Size, "raw full operands");
            }
            Check(F(w).GetProperty("read_kind").GetString() == "operand_envelope" && F(w).GetProperty("read_start_ticks").GetInt64() == operand.GetProperty("state").GetProperty("start_ticks").GetInt64() && F(w).GetProperty("read_end_ticks").GetInt64() == operand.GetProperty("clock").GetProperty("end_ticks").GetInt64(), "explicit envelope not physical copy");
            phase = "backstep"; m = new(); w = Capture(m, frames: 2, next: n => { if (n == 1) m.Set(0x3000, BitConverter.GetBytes(1985L)); }); Value(w, 11); Check(F(w, 1).GetProperty("value").GetDouble() > 11, "no smoothing or monotonic assumption");
            phase = "residual-compensation"; m = new(); w = Capture(m, frames: 2, next: n => { if (n == 1) m.Set(0x2000, State(1500, 11.5f, 1)); }); Value(w, 11); Value(w, 11, 1);

            phase = "failures";
            foreach (ulong a in new ulong[] { 0x2000, 0x3000 })
            {
                m = new() { Partial = a }; w = Capture(m); Unknown(w, "partial_read");
                Check(F(w).GetProperty("operands").GetProperty(a == 0x2000 ? "state" : "clock").GetProperty("bytes_hex").ValueKind == JsonValueKind.Null, "partial buffer discarded");
                if (a == 0x2000) Check(!m.Reads.Any(r => r.Address == 0x3000), "clock skipped after state gap");
                m = new() { Failure = x => x == a ? "unreadable_range" : null }; w = Capture(m); Unknown(w, "unreadable_range");
            }
            m = new(); m.Set(0xffe, [0, 0, 0, 0]); w = Capture(m); Unknown(w, "guard_mismatch_before"); Check(m.Reads.Count == 2, "guard failure prevents operands");
            m = new(); m.After = a => { if (a == 0x3000) m.Set(0xffe, [0, 0, 0, 0]); }; w = Capture(m); Unknown(w, "guard_mismatch_after"); Check(F(w).GetProperty("operands").GetProperty("state").GetProperty("bytes_hex").ValueKind == JsonValueKind.String, "unknown retains raw operand provenance");
            m = new(); m.Set(0x2000, State(1000, float.PositiveInfinity, 1)); w = Capture(m); Unknown(w, "non_finite_operand");
            m = new(); var p = Profile(m.Identity); p["fields"]![0]!["max"] = 10; w = Capture(m, p); Unknown(w, "out_of_range");
            phase = "fatal-cancel-bounds";
            m = new() { Failure = a => a == 0x2000 ? "permission_denied" : null }; w = Capture(m); Unknown(w, "permission_denied"); Check(m.Reads.Count == 2, "no native calls after fatal");
            m = new(); w = Capture(m, setup: stop => m.After = a => { if (a == 0x2000) stop.Cancel(); }); Unknown(w, "cancelled"); Check(m.Reads.Count == 2 && !F(w).GetProperty("operands").GetProperty("clock").GetProperty("attempted").GetBoolean(), "cancel between operands");
            m = new(); w = Capture(m, limits: new(ReadBytes: 20)); Unknown(w, "read_byte_limit"); Check(m.Reads.Count == 2, "clock charged before read");
            m = new(); w = Capture(m, setup: stop => stop.Cancel()); Check(w.Lines.Count == 1 && m.Reads.Count == 0, "pre-cancel no frame/read");

            phase = "parse"; m = new();
            void Reject(Action<JsonObject> change, string code = "invalid_field_profile") { var bad = Profile(m.Identity); change(bad); Throws(() => FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(bad)), code); }
            Reject(p => p["fields"]![0]!["counter_scale_f32_hex"] = "0000807f"); Reject(p => p["fields"]![0]!["counter_scale_f32_hex"] = "00000080");
            Reject(p => p["fields"]![0]!["counter_scale_f32_hex"] = "bad"); Reject(p => p["fields"]![0]!["codec"] = "expression");
            Reject(p => p["fields"]![0]!["type"] = "i32"); Reject(p => p["fields"]![0]!["address"] = (ulong)long.MaxValue - 14);
            Reject(p => p["fields"]![0]!["clock_address"] = (ulong)long.MaxValue - 6); Reject(p => p["fields"]![0]!["path"] = "unimplemented");
            Reject(p => p["absolute_guard_reads"] = new JsonObject()); Reject(p => p["fields"]![0]!.AsObject().Remove("codec"));
            Reject(p => { var prototype = p["fields"]![0]!.DeepClone(); for (int i = 1; i <= TimerCodec.MaximumTimers; i++) { var f = prototype.DeepClone(); f["name"] = "t" + i; p["fields"]!.AsArray().Add(f); } }, "field_profile_limit");
            p = Profile(m.Identity, state: (ulong)long.MaxValue - 15, clock: (ulong)long.MaxValue - 7); Check(FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)).Fields[0].Width == 16, "inclusive final-byte boundaries");
            p = Profile(m.Identity); p["guards"]!.AsArray().Add(new JsonObject { ["address"] = 0xffe, ["bytes_hex"] = "0102" });
            Check(FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)).Guards.Length == 2, "v4 retains consistent same-start guards of different widths");
            var legacy = p.DeepClone().AsObject(); legacy["schema"] = "overwatch-decoder.field-profile/1";
            foreach (string key in new[] { "codec", "clock_address", "counter_scale_f32_hex" }) legacy["fields"]![0]!.AsObject().Remove(key);
            Throws(() => FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(legacy)), "invalid_field_profile");
            p["guards"]![1]!["bytes_hex"] = "0103"; Throws(() => FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)), "invalid_field_profile");
            p["guards"]![1]!["address"] = 0xfff; p["guards"]![1]!["bytes_hex"] = "0203";
            Check(FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)).Guards.Length == 2, "v4 retains consistent partial overlap");
            p["guards"]![1]!["bytes_hex"] = "0204"; Throws(() => FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)), "invalid_field_profile");
            phase = "independent-fields"; m = new(); p = Profile(m.Identity); p["fields"]!.AsArray().Add(new JsonObject { ["name"] = "other", ["type"] = "i32", ["address"] = 0x4000 });
            m.Failure = a => a == 0x3000 ? "unreadable_range" : null; w = Capture(m, p); Unknown(w, "unreadable_range"); Check(w.Lines[0].GetProperty("fields").GetProperty("other").GetProperty("value").GetInt32() == 99, "timer gap does not poison independent value");

            phase = "full-guard-coverage"; m = new(); p = Profile(m.Identity); var gs = p["guards"]!.AsArray();
            for (int id = 1; id < 220; id++)
            {
                ulong address = 0x5000UL + (ulong)id * 8; m.Set(address, [1, 2, 3, 4]);
                gs.Add(new JsonObject { ["address"] = address, ["bytes_hex"] = "01020304" });
            }
            var second = p["fields"]![0]!.DeepClone(); second["name"] = "second_timer"; p["fields"]!.AsArray().Add(second);
            w = Capture(m, p); Value(w, 11);
            Check(w.Lines[0].GetProperty("guards_before").GetArrayLength() == 220 && w.Lines[0].GetProperty("physical_read_calls").GetInt32() == 444 && w.Lines[0].GetProperty("physical_read_bytes").GetInt32() == 1808, "220 exact guards, two full timer pairs");
            Check(Encoding.UTF8.GetByteCount(w.Lines[0].GetRawText()) < 256 * 1024, "full guard profile fits actual frame cap");

            phase = "field-local-shared-guards"; m = new(); p = Profile(m.Identity);
            var localGuards = new JsonArray();
            for (int id = 0; id < 180; id++)
            {
                ulong address = 0x6000UL + (ulong)id * 8; m.Set(address, [1, 2, 3, 4]);
                localGuards.Add(new JsonObject { ["address"] = address, ["bytes_hex"] = "01020304" });
            }
            p["fields"]![0]!["guards"] = localGuards;
            second = p["fields"]![0]!.DeepClone(); second["name"] = "second_timer"; p["fields"]!.AsArray().Add(second);
            p["fields"]!.AsArray().Add(new JsonObject { ["name"] = "other", ["type"] = "i32", ["address"] = 0x4000 });
            var localProfile = FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p));
            Check(localProfile.Guards.Length == 181 && localProfile.Fields[0].Guards.Length == 181 &&
                localProfile.Fields[1].Guards.SequenceEqual(localProfile.Fields[0].Guards) && localProfile.Fields[2].Guards.Length == 1,
                "361 declarations preserve two full local dependencies and the independent field");
            string localRecording = New("local-guards-record"), localInput = Input(p);
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                FieldRecording.RecordBounded(m, localInput, localRecording, 10, TimeSpan.FromSeconds(30), stop.Token, new(), frame =>
                { if (frame.Sequence == 0) m.Set(0x6000, [0, 0, 0, 0]); else stop.Cancel(); });
            var localVerified = FieldRecordingVerification.Verify(localRecording);
            Check(localVerified.valid && localVerified.frames == 2 && localVerified.unknown_fields == 2,
                "strict verification retains the two timer unknowns after local invalidation");
            using (var rawStream = File.OpenRead(Path.Combine(localRecording, "samples.jsonl.gz")))
            using (var gzip = new GZipStream(rawStream, CompressionMode.Decompress))
            using (var reader = new StreamReader(gzip))
            {
                _ = reader.ReadLine(); using var invalidFrame = JsonDocument.Parse(reader.ReadLine()!);
                var values = invalidFrame.RootElement.GetProperty("fields");
                Check(values.GetProperty("timer").GetProperty("status").GetString() == "unknown" &&
                    values.GetProperty("second_timer").GetProperty("status").GetString() == "unknown" &&
                    values.GetProperty("other").GetProperty("value").GetInt32() == 99,
                    "timer collection failure does not invalidate independent value");
            }
            p = Profile(m.Identity);
            p["guards"] = new JsonArray(Enumerable.Range(0, FieldStream.MaximumTimerGuardDeclarations).Select(_ =>
                (JsonNode)new JsonObject { ["address"] = 0xffe, ["bytes_hex"] = "01020304" }).ToArray());
            Check(FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)).Guards.Length == 1,
                "bounded v4 repeated declarations still deduplicate to one physical check");
            p["guards"]!.AsArray().Add(p["guards"]![0]!.DeepClone());
            Throws(() => FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)), "field_profile_limit");
            p = Profile(m.Identity);
            p["guards"] = new JsonArray(Enumerable.Range(0, FieldStream.MaximumGuards + 1).Select(i =>
                (JsonNode)new JsonObject { ["address"] = 0x6000 + i * 8, ["bytes_hex"] = "01" }).ToArray());
            Throws(() => FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)), "field_profile_limit");

            phase = "record-consumers"; m = new(); p = Profile(m.Identity); string input = Input(p), recording = New("record");
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                int guardReads = 0; m.After = a => { if (a == 0xffe && ++guardReads == 6) stop.Cancel(); };
                FieldRecording.Record(m, input, recording, 10, TimeSpan.FromSeconds(30), stop.Token);
            }
            var verified = FieldRecordingVerification.Verify(recording); Check(verified.valid && verified.frames == 3 && verified.unknown_fields == 1 && !verified.complete, "strict stopped three frames: " + verified.error_code);
            string exported = New("export.jsonl"), timeline = New("timeline.jsonl"); FieldExport.Export(recording, exported); FieldTimeline.Export(recording, timeline);
            foreach (string file in new[] { exported, timeline })
            { string text = File.ReadAllText(file); Check(text.Contains("operand_envelope", StringComparison.Ordinal) && text.Contains("bytes_hex", StringComparison.Ordinal) && !text.Contains("address_hex", StringComparison.Ordinal), "products retain operands/timing without addresses"); }
            var summary = FieldSummary.Summarize(recording); Check(summary.GetProperty("fields")[0].GetProperty("timing_kind").GetString() == "operand_envelope", "summary qualifies timing span");
            string beforeHash = Hash(File.ReadAllBytes(Path.Combine(recording, "samples.jsonl.gz"))); FieldRecordingVerification.Verify(recording); Check(Hash(File.ReadAllBytes(Path.Combine(recording, "samples.jsonl.gz"))) == beforeHash, "source unchanged");

            phase = "mixed-overlap-record"; m = new(); p = Profile(m.Identity);
            p["guards"]!.AsArray().Add(new JsonObject { ["address"] = 0xffe, ["bytes_hex"] = "0102" });
            p["fields"]!.AsArray().Add(new JsonObject { ["name"] = "ordinary", ["type"] = "i32", ["address"] = 0x4000 });
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                int guardReads = 0; m.After = a => { if (a == 0xffe && ++guardReads == 8) stop.Cancel(); };
                string mixed = New("mixed"); FieldRecording.Record(m, Input(p), mixed, 10, TimeSpan.FromSeconds(30), stop.Token);
                var v = FieldRecordingVerification.Verify(mixed);
                Check(v.valid && v.frames == 2 && v.unknown_fields == 2, "mixed scalar/timer and overlapping serial guards verify: " + v.error_code);
                Check(ReadRows(mixed)[0]["fields"]!["ordinary"]!["value"]!.GetValue<int>() == 99, "ordinary value retained with timer");
            }

            phase = "failure-record-verification";
            foreach (string failure in new[] { "state_partial", "clock_gap", "guard_before", "guard_after", "denied", "nonfinite", "negative_zero" })
            {
                m = new();
                if (failure == "state_partial") m.Partial = 0x2000;
                if (failure == "clock_gap") m.Failure = a => a == 0x3000 ? "unreadable_range" : null;
                if (failure == "guard_before") m.Set(0xffe, [0, 0, 0, 0]);
                if (failure == "guard_after") m.After = a => { if (a == 0x3000) m.Set(0xffe, [0, 0, 0, 0]); };
                if (failure == "denied") m.Failure = a => a == 0x2000 ? "permission_denied" : null;
                if (failure == "nonfinite") m.Set(0x2000, State(1000, float.NaN, 1));
                if (failure == "negative_zero") { m.Set(0x2000, State(2000, -0f, 1)); }
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)); int guardCount = 0; var prior = m.After;
                m.After = a => { prior?.Invoke(a); if (a == 0xffe && ++guardCount == 4) stop.Cancel(); };
                string saved = New(failure); FieldRecording.Record(m, Input(Profile(m.Identity)), saved, 10, TimeSpan.FromSeconds(30), stop.Token);
                var v = FieldRecordingVerification.Verify(saved); Check(v.valid && !v.complete && v.frames > 0, failure + " strict proof: " + v.error_code);
                if (failure == "negative_zero") Check(BitConverter.DoubleToInt64Bits(ReadRows(saved)[0]["fields"]!["timer"]!["value"]!.GetValue<double>()) == long.MinValue, "recorded negative zero exact");
            }

            phase = "rehash-tamper";
            var original = ReadRows(recording);
            foreach (var mutation in new Action<JsonObject>[] {
                f => f["value"] = 999,
                f => f["operands"]!["state"]!["bytes_hex"] = Convert.ToHexStringLower(State(1000, 13, 1)),
                f => f["operands"]!["clock"]!["requested_bytes"] = 4,
                f => f["operands"]!["clock"]!["start_ticks"] = f["operands"]!["state"]!["start_ticks"]!.DeepClone(),
                f => f["counter_scale_f32_hex"] = "0000803f",
                f => f["read_kind"] = "physical_read",
                f => f["operands"]!["state"]!["returned_bytes"] = 15,
                f => f["reason"] = "invented"
            })
            {
                string copy = New("tamper"); Directory.CreateDirectory(copy); foreach (string file in Directory.GetFiles(recording)) File.Copy(file, Path.Combine(copy, Path.GetFileName(file)));
                var rows = original.Select(x => x.DeepClone().AsObject()).ToList(); mutation(rows[0]["fields"]!["timer"]!.AsObject()); Repack(copy, rows);
                Check(!FieldRecordingVerification.Verify(copy).valid, "rehash does not bypass semantic verification");
                string dest = New("badexport"); Throws(() => FieldExport.Export(copy, dest), "invalid_recording"); Check(!File.Exists(dest), "invalid source has no export");
            }
            foreach (var mutation in new Action<JsonObject>[] {
                row => row["guards_before"]![0]!["ok"] = false,
                row => row["guards_before"]![0]!["read"]!["bytes_hex"] = "00000000",
                row => row["guards_after"]![0]!["read"]!["address_hex"] = "0000000000000fff",
                row => row["physical_read_calls"] = 3
            })
            {
                string copy = New("guard-tamper"); Directory.CreateDirectory(copy); foreach (string file in Directory.GetFiles(recording)) File.Copy(file, Path.Combine(copy, Path.GetFileName(file)));
                var rows = original.Select(x => x.DeepClone().AsObject()).ToList(); mutation(rows[0]); Repack(copy, rows);
                Check(!FieldRecordingVerification.Verify(copy).valid, "rehash serial guard/count tampering rejected");
            }
            phase = "recovery";
            string truncated = New("truncated"); Directory.CreateDirectory(truncated); foreach (string file in Directory.GetFiles(recording)) File.Copy(file, Path.Combine(truncated, Path.GetFileName(file)));
            Repack(truncated, original); using (var f = File.OpenWrite(Path.Combine(truncated, "samples.jsonl.gz"))) f.SetLength(f.Length - 4);
            var recovery = FieldRecordingVerification.Verify(truncated, true); Check(recovery.recoverable && recovery.frames == 3 && !recovery.complete && !recovery.valid, "recover only indexed complete frame members");
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
    private static List<JsonObject> ReadRows(string directory)
    {
        using var file = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz")); using var gzip = new GZipStream(file, CompressionMode.Decompress); using var reader = new StreamReader(gzip);
        var rows = new List<JsonObject>(); while (reader.ReadLine() is { } s) rows.Add(JsonNode.Parse(s)!.AsObject()); return rows;
    }
    private static void Repack(string directory, List<JsonObject> rows)
    {
        static string Hash(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));
        string manifestPath = Path.Combine(directory, "manifest.json"); var manifest = JsonNode.Parse(File.ReadAllBytes(manifestPath))!.AsObject();
        var summary = rows[^1]; summary["frame_output_utf8_bytes"] = rows.Take(rows.Count - 1).Sum(x => (long)Encoding.UTF8.GetByteCount(x.ToJsonString()) + 1);
        long checkpoint = File.ReadLines(Path.Combine(directory, "chunks.jsonl")).Select(x => JsonNode.Parse(x)!["checkpoint_ticks"]!.GetValue<long>()).Max();
        using var samples = new MemoryStream(); using var index = new MemoryStream(); long rawBytes = 0;
        for (int i = 0; i < rows.Count; i++)
        {
            byte[] raw = Encoding.UTF8.GetBytes(rows[i].ToJsonString() + "\n"); using var buffer = new MemoryStream();
            using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, true)) gzip.Write(raw);
            byte[] member = buffer.ToArray(); byte[] entry = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { schema = "overwatch-decoder.field-recording-chunk/1", sequence = i, offset = samples.Length,
                compressed_bytes = member.Length, json_bytes = raw.Length, first_line = i, lines = 1, compressed_sha256 = Hash(member), json_sha256 = Hash(raw), checkpoint_ticks = checkpoint, monotonic_frequency = rows[i]["monotonic_frequency"]!.GetValue<long>() }) + "\n");
            samples.Write(member); index.Write(entry); rawBytes += raw.Length;
        }
        byte[] bytes = samples.ToArray(), indices = index.ToArray(); File.WriteAllBytes(Path.Combine(directory, "samples.jsonl.gz"), bytes); File.WriteAllBytes(Path.Combine(directory, "chunks.jsonl"), indices);
        manifest["durable_chunks"] = rows.Count; manifest["durable_lines"] = rows.Count; manifest["durable_compressed_bytes"] = bytes.Length; manifest["durable_json_bytes"] = rawBytes; manifest["index_bytes"] = indices.Length;
        manifest["samples_sha256"] = Hash(bytes); manifest["durable_samples_prefix_sha256"] = Hash(bytes); manifest["index_sha256"] = Hash(indices); manifest["durable_index_prefix_sha256"] = Hash(indices); manifest["stream_summary"] = summary.DeepClone();
        File.WriteAllText(manifestPath, manifest.ToJsonString());
    }
}
