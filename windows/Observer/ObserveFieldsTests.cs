using System.Buffers.Binary;
using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

public static class ObserveFieldsTests
{
    private sealed class LiveWriter : StringWriter
    {
        internal Func<JsonElement, bool>? Fail;
        internal bool FailAfterWrite;
        internal Action<JsonElement>? Before;
        public override void Write(string? text)
        {
            using var line = JsonDocument.Parse(text!); Before?.Invoke(line.RootElement);
            bool fail = Fail?.Invoke(line.RootElement) == true;
            if (fail && !FailAfterWrite) throw new IOException("Synthetic pipe failure.");
            base.Write(text);
            if (fail) throw new IOException("Synthetic write outcome unknown.");
        }
    }
    private sealed class Memory : IMemorySource
    {
        internal const ulong Address = 65536;
        internal readonly byte[] Bytes = new byte[64]; internal int Reads;
        internal Action<Memory, ulong>? After; internal string? Failure;
        public TargetIdentity Identity { get; set; } = new(51, "fixture.exe", "fixture", 7, new string('d', 64), "x64");
        internal Memory() { U32(0, 123); U32(4, 1); U32(16, 17); }
        internal void U32(int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(Bytes.AsSpan(offset, 4), value);
        public byte[] Read(ulong address, int size)
        {
            Reads++;
            if (Failure is not null) throw new ObservationException(Failure, "Fixture failure.");
            if (address < Address || address - Address + (ulong)size > (ulong)Bytes.Length) throw new ObservationException("unreadable_range", "Fixture range.");
            byte[] result = Bytes.AsSpan((int)(address - Address), size).ToArray(); After?.Invoke(this, address); return result;
        }
        public void EnsureAlive() { if (Failure == "process_exited") throw new ObservationException(Failure, "Fixture exit."); }
        public IEnumerable<MemoryRegion> Regions() => []; public void Dispose() { }
    }
    private static JsonObject Recipe(TargetIdentity target)
    {
        return JsonNode.Parse(JsonSerializer.Serialize(new
        {
            schema = "overwatch-decoder.acquisition-recipe/1", target = new { image_name = target.ImageName, executable_sha256 = target.ExecutableSha256, architecture = target.Architecture },
            seconds = 10, constants = new { }, functions = new { }, global_guards = "g",
            stages = new[] { new { name = "header", steps = new object[] {
                new { op = "read", name = "header", address = new object[] { "rva", 0, 8 }, size = 8 },
                new { op = "require", test = new object[] { "eq", new object[] { "load", new object[] { "var", "header" }, 0, 4 }, 123 } },
                new { op = "guard", set = "g", value = new object[] { "var", "header" } } } } },
            fields = new[] { new { name = "value", type = "i32", address = new object[] { "rva", 16, 4 }, min = 0, max = 100 } }
        }))!.AsObject();
    }
    public static int Run()
    {
        int assertions = 0, ordinal = 0; string phase = "setup";
        void Check(bool ok, string why) { if (!ok) throw new ObservationException("self_test_failed", "observe:" + phase + ":" + why); assertions++; }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-observe-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string New() => Path.Combine(root, (++ordinal).ToString());
        string Save(JsonObject value) { string p = New() + ".json"; File.WriteAllText(p, value.ToJsonString()); return p; }
        ObserveFields.Result Run(Memory m, string destination, CancellationToken token = default, Action<int, FieldStream.AcceptedFrame>? frame = null,
            ObserveFields.Limits? limits = null, string? recipe = null, TimeSpan? duration = null, TextWriter? live = null, long liveMaximum = LiveFieldOutput.MaximumBytes) =>
            ObserveFields.RunBounded(m, new(Memory.Address, 64, m.Identity.ImageName), recipe ?? Save(Recipe(m.Identity)), destination, 10,
                duration ?? TimeSpan.FromSeconds(10), token, limits ?? new(RetryMilliseconds: 0), frame, live, liveMaximum);
        JsonElement[] Lines(TextWriter writer) => writer.ToString()!.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(row => { using var document = JsonDocument.Parse(row); return document.RootElement.Clone(); }).ToArray();
        JsonElement[] Frames(string directory)
        {
            using var file = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz")); using var gz = new GZipStream(file, CompressionMode.Decompress); using var reader = new StreamReader(gz);
            var rows = new List<JsonElement>(); string? line;
            while ((line = reader.ReadLine()) is not null) { using var d = JsonDocument.Parse(line); if (d.RootElement.GetProperty("kind").GetString() == "frame") rows.Add(d.RootElement.Clone()); }
            return rows.ToArray();
        }
        try
        {
            phase = "guard-lifecycle"; var m = new Memory(); string output = New(); using var lifecycleLive = new LiveWriter();
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                var r = Run(m, output, stop.Token, (segment, f) =>
                {
                    if (segment == 1 && f.Sequence == 0) { m.U32(4, 2); m.U32(16, 23); }
                    if (segment == 2 && f.Sequence == 1) stop.Cancel();
                }, live: lifecycleLive);
                Check(!r.complete && r.stop_reason == "cancelled" && r.acquisitions.Length == 2 && r.segments.Length == 2, "finite lifecycle and cancellation");
                Check(r.segments[0].trigger == "guard_invalidation" && r.segments[0].trigger_sequence == 1 && r.segments[0].frames == 2, "failed frame accepted before rotation");
                Check(r.segments[0].profile_sha256 != r.segments[1].profile_sha256, "fresh profile binds changed collection count");
                Check(r.read_calls == m.Reads && r.requested_read_bytes > 0, "shared source accounting");
                using (var evidence = JsonDocument.Parse(File.ReadLines(Path.Combine(output, "acquisition-0001", "evidence.jsonl")).First()))
                    Check(evidence.RootElement.GetProperty("source_kind").GetString() == "provided_memory_source" && r.source_kind == "provided_memory_source", "fixture source never labeled native");
                foreach (var segment in r.segments)
                { var v = FieldRecordingVerification.Verify(Path.Combine(output, segment.directory)); Check(v.valid && !v.complete, "each stopped segment strictly verifies:" + v.error_code); }
                var a = Frames(Path.Combine(output, r.segments[0].directory)); var b = Frames(Path.Combine(output, r.segments[1].directory));
                Check(a[1].GetProperty("fields").GetProperty("value").GetProperty("value").ValueKind == JsonValueKind.Null && !a[1].GetProperty("guards_before")[0].GetProperty("ok").GetBoolean(), "original invalid frame and guard retained");
                Check(b[0].GetProperty("fields").GetProperty("value").GetProperty("value").GetInt32() == 23, "new profile resumes fresh value");
                Check(r.intervals_without_recorded_frames.Length == 3 && r.intervals_without_recorded_frames.All(g => g.end_ticks >= g.start_ticks), "bounded explicit initial/intersegment/final gaps");
                var gap = r.intervals_without_recorded_frames[1];
                Check(gap.start_ticks == r.segments[0].last_frame_end_ticks && gap.end_ticks == r.segments[1].first_frame_start_ticks && r.acquisitions[1].start_ticks >= gap.start_ticks && r.acquisitions[1].end_ticks <= gap.end_ticks, "gap encloses reacquisition without invented samples");
                Check(r.fields.Single().observed == 3 && r.fields.Single().unknown == 1 && r.active_directory is null, "session coverage and closed operation");
                using var saved = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(output, "manifest.json"))); Check(saved.RootElement.GetProperty("status").GetString() == "finished" && !saved.RootElement.GetProperty("complete").GetBoolean(), "cancelled manifest is not success");
                var rows = Lines(lifecycleLive); var liveFrames = rows.Where(row => row.GetProperty("kind").GetString() == "frame").ToArray();
                Check(rows.First().GetProperty("kind").GetString() == "session_start" && rows.Last().GetProperty("kind").GetString() == "session_end" && liveFrames.Length == 4,
                    "live boundaries and every accepted frame");
                Check(rows.Select((row, i) => row.GetProperty("event_sequence").GetInt64() == i && row.GetProperty("session_id").GetString() == r.session_id).All(ok => ok), "ordered events and session identity");
                Check(rows.Count(row => row.GetProperty("kind").GetString() == "gap") == 3 && rows.Count(row => row.GetProperty("kind").GetString() == "segment_start") == 2 && rows.Count(row => row.GetProperty("kind").GetString() == "segment_end") == 2,
                    "live invalidation has explicit gap and segment boundaries");
                for (int i = 0; i < 4; i++)
                {
                    var raw = i < 2 ? a[i] : b[i - 2]; var liveFrame = liveFrames[i];
                    foreach (string key in new[] { "sequence", "scheduled_slot", "scheduled_ticks", "start_ticks", "end_ticks", "jitter_ticks", "skipped_intervals_before", "skipped_intervals_total", "profile_sha256", "utc_origin", "monotonic_origin_ticks" })
                        Check(raw.GetProperty(key).GetRawText() == liveFrame.GetProperty(key).GetRawText(), "live exact raw sample metadata:" + key);
                    var rawValue = raw.GetProperty("fields").GetProperty("value"); var liveValue = liveFrame.GetProperty("fields").GetProperty("value");
                    foreach (string key in new[] { "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks" })
                        Check(rawValue.GetProperty(key).GetRawText() == liveValue.GetProperty(key).GetRawText(), "live exact original field:" + key);
                    Check(liveValue.GetProperty("read_attempted").ValueKind == JsonValueKind.Null && !liveValue.TryGetProperty("guard_ids", out _) &&
                        liveFrame.GetProperty("recording_state").GetString() == "accepted_not_durability_verified", "v1 attempt uncertainty and no guard/durability claim");
                }
                Check(JsonSerializer.SerializeToElement(r.live_output).GetProperty("completed_write_lines").GetInt64() == rows.Length &&
                    JsonSerializer.SerializeToElement(r.live_output).GetProperty("completed_write_utf8_bytes").GetInt64() == System.Text.Encoding.UTF8.GetByteCount(lifecycleLive.ToString()), "exact live UTF8 accounting");
            }
            phase = "retry-cap"; m = new(); m.U32(0, 0); output = New(); var failed = Run(m, output);
            Check(!failed.complete && failed.stop_reason == "acquisition_retry_limit" && failed.acquisitions.Length == 3 && failed.segments.Length == 0, "failed acquisition retries bounded");
            Check(failed.acquisitions.All(a => a.error == "acquisition_predicate_failed") && !Directory.EnumerateFiles(output, "profile.json", SearchOption.AllDirectories).Any(), "failures preserved with no usable profile");
            phase = "attempt-cap"; m = new(); output = New(); var capped = Run(m, output, frame: (_, f) => { if (f.Sequence == 0) m.U32(4, (uint)m.Reads); }, limits: new(Attempts: 2, RetryMilliseconds: 0));
            Check(!capped.complete && capped.stop_reason == "acquisition_attempt_limit" && capped.segments.Length == 2, "repeated guarded invalidation cannot succeed forever");
            phase = "extended-attempt-cap"; m = new(); output = New();
            var extended = Run(m, output, frame: (_, f) => { if (f.Sequence == 0) m.U32(4, (uint)m.Reads); },
                limits: new(Attempts: 10, RetryMilliseconds: 0));
            Check(!extended.complete && extended.stop_reason == "acquisition_attempt_limit" &&
                extended.acquisitions.Length == 10 && extended.acquisitions.All(a => a.complete) && extended.segments.Length == 10,
                "real acquisition and guard-triggered reacquisition continue beyond eight then stop at configured ten");
            Check(extended.segments.All(s => s.frames == 2 && s.trigger == "guard_invalidation") &&
                extended.fields.Single().observed == 10 && extended.fields.Single().unknown == 10,
                "extended sessions retain observed and invalidating samples in every independent segment");
            foreach (var segment in extended.segments)
                Check(FieldRecordingVerification.Verify(Path.Combine(output, segment.directory)).valid, "extended segment strictly verifies");
            Check(JsonSerializer.SerializeToElement(extended.limits).GetProperty("maximum_acquisition_attempts").GetInt32() == 10,
                "manifest reports configured acquisition cap");
            phase = "default-attempt-cap"; m = new(); output = New();
            var defaultCap = Run(m, output, frame: (_, f) => { if (f.Sequence == 0) m.U32(4, (uint)m.Reads); });
            Check(defaultCap.stop_reason == "acquisition_attempt_limit" && defaultCap.acquisitions.Length == 8 && defaultCap.segments.Length == 8,
                "default acquisition behavior remains eight attempts");
            phase = "extended-failure-cap"; m = new(); m.U32(0, 0); output = New();
            var extendedFailures = Run(m, output, limits: new(Attempts: 128, ConsecutiveFailures: 16, RetryMilliseconds: 0));
            Check(extendedFailures.stop_reason == "acquisition_retry_limit" && extendedFailures.acquisitions.Length == 16 && extendedFailures.segments.Length == 0,
                "explicit sixteen consecutive acquisition failures remain bounded");
            var extendedLimits = JsonSerializer.SerializeToElement(extendedFailures.limits);
            Check(extendedLimits.GetProperty("maximum_acquisition_attempts").GetInt32() == 128 &&
                extendedLimits.GetProperty("maximum_consecutive_acquisition_failures").GetInt32() == 16 &&
                extendedLimits.GetProperty("maximum_read_calls").GetInt64() == ObserveFields.MaximumReadCalls &&
                extendedLimits.GetProperty("maximum_read_bytes").GetInt64() == FieldStream.MaximumReadBytes,
                "effective caps reported without enlarging read budgets");
            phase = "public-acquisition-options"; m = new(); m.U32(0, 0); output = New();
            var publicOptions = ObserveFields.Run(m, new(Memory.Address, 64, m.Identity.ImageName), Save(Recipe(m.Identity)), output, 10,
                TimeSpan.FromSeconds(10), maxAcquisitions: 10, maxConsecutiveAcquisitionFailures: 1);
            Check(publicOptions.stop_reason == "acquisition_retry_limit" && publicOptions.acquisitions.Length == 1 &&
                JsonSerializer.SerializeToElement(publicOptions.limits).GetProperty("maximum_acquisition_attempts").GetInt32() == 10 &&
                JsonSerializer.SerializeToElement(publicOptions.limits).GetProperty("maximum_consecutive_acquisition_failures").GetInt32() == 1,
                "public optional arguments reach effective native session limits");
            phase = "periodic-reacquisition"; m = new(); output = New(); using var periodicLive = new LiveWriter();
            var periodicRecipe = Recipe(m.Identity);
            periodicRecipe["stages"]![0]!["steps"]!.AsArray().Add(JsonNode.Parse("""
                {"op":"read","name":"route","address":["rva",24,4],"size":4}
                """));
            periodicRecipe["fields"]![0]!["address"] = JsonNode.Parse("""
                ["rva",["load",["var","route"],0,4],4]
                """);
            m.U32(24, 16); m.U32(32, 29);
            var periodic = Run(m, output, frame: (segment, f) =>
                { if (segment == 1 && f.Sequence == 0) m.U32(24, 32); },
                recipe: Save(periodicRecipe), limits: new(Attempts: 2, RetryMilliseconds: 0, ReacquireMilliseconds: 1000), live: periodicLive);
            Check(periodic.stop_reason == "acquisition_attempt_limit" && periodic.acquisitions.Length == 2 && periodic.segments.Length == 2,
                "periodic rotations consume the existing acquisition budget");
            Check(periodic.segments.All(s => s.trigger == "periodic_reacquisition" && s.frames > 0 &&
                s.trigger_sequence == s.frames - 1 && s.trigger_frame_end_ticks == s.last_frame_end_ticks &&
                (s.trigger_frame_end_ticks - s.start_ticks) * 1000d / System.Diagnostics.Stopwatch.Frequency >= 1000),
                "only accepted threshold frames rotate and remain the last segment frame");
            Check(periodic.segments.All(s => Frames(Path.Combine(output, s.directory)).Length == s.frames) &&
                Lines(periodicLive).Count(l => l.GetProperty("kind").GetString() == "frame") == periodic.segments.Sum(s => s.frames),
                "periodic boundary loses no recorded or live frames");
            Check(Frames(Path.Combine(output, periodic.segments[0].directory)).All(f => f.GetProperty("fields").GetProperty("value").GetProperty("value").GetInt32() == 17) &&
                Frames(Path.Combine(output, periodic.segments[1].directory)).All(f => f.GetProperty("fields").GetProperty("value").GetProperty("value").GetInt32() == 29),
                "periodic acquisition discovers changed unguarded routing despite stable prior guards");
            Check(JsonSerializer.SerializeToElement(periodic.limits).GetProperty("reacquire_ms").GetInt32() == 1000 &&
                JsonSerializer.SerializeToElement(publicOptions.limits).GetProperty("reacquire_ms").GetInt32() == 0,
                "opt-in interval and unchanged disabled default recorded");
            phase = "periodic-duration"; m = new(); output = New();
            var shortDuration = TimeSpan.FromMilliseconds(200);
            var shortPeriodicLimits = new ObserveFields.Limits(ReacquireMilliseconds: 1000, RetryMilliseconds: 0);
            var shortPeriodic = Run(m, output, duration: shortDuration, limits: shortPeriodicLimits);
            bool observedBeforeDeadline = shortPeriodic.fields.Any(f => f.observed > 0);
            // Startup and initial acquisition both spend the same deadline.
            Check(shortPeriodic.stop_reason == (observedBeforeDeadline ? "duration_elapsed" : "fields_never_observed") &&
                shortPeriodic.complete == observedBeforeDeadline &&
                shortPeriodic.acquisitions.Length <= 1 && shortPeriodic.segments.Length <= 1 &&
                shortPeriodic.segments.All(s => s.trigger != "periodic_reacquisition"),
                $"duration prevents periodic acquisition (stop={shortPeriodic.stop_reason}, complete={shortPeriodic.complete}, " +
                $"attempts={shortPeriodic.acquisitions.Length}, segments={shortPeriodic.segments.Length}, observed={observedBeforeDeadline})");

            phase = "periodic-duration-before-acquisition"; m = new(); output = New();
            using var slowStart = new LiveWriter
            {
                Before = row =>
                {
                    if (row.GetProperty("kind").GetString() == "session_start")
                        Thread.Sleep(shortDuration + TimeSpan.FromMilliseconds(50));
                }
            };
            var expiredAtStartup = Run(m, output, duration: shortDuration, limits: shortPeriodicLimits, live: slowStart);
            Check(expiredAtStartup.stop_reason == "fields_never_observed" && !expiredAtStartup.complete &&
                expiredAtStartup.acquisitions.Length == 0 && expiredAtStartup.segments.Length == 0 &&
                expiredAtStartup.fields.Length == 0 && m.Reads == 0,
                $"startup deadline preserves unobserved failure (stop={expiredAtStartup.stop_reason}, complete={expiredAtStartup.complete}, " +
                $"attempts={expiredAtStartup.acquisitions.Length}, segments={expiredAtStartup.segments.Length}, reads={m.Reads})");
            phase = "periodic-cancellation"; m = new(); output = New();
            using (var periodicStop = new CancellationTokenSource())
            {
                var cancelPeriodic = Run(m, output, periodicStop.Token, (_, f) =>
                { if (f.Sequence == 0) periodicStop.Cancel(); }, limits: new(ReacquireMilliseconds: 1000, RetryMilliseconds: 0));
                Check(cancelPeriodic.stop_reason == "cancelled" && cancelPeriodic.acquisitions.Length == 1,
                    "caller cancellation retains precedence");
            }
            phase = "periodic-invalid-options";
            foreach (int interval in new[] { -1, 1, 999, 30001 })
            {
                m = new(); output = New();
                try
                {
                    ObserveFields.Run(m, new(Memory.Address, 64, m.Identity.ImageName), "unused-invalid-limit-recipe", output, 10,
                        TimeSpan.FromSeconds(1), reacquireMs: interval);
                    Check(false, "invalid reacquisition interval accepted");
                }
                catch (ObservationException e)
                { Check(e.Code == "invalid_arguments" && m.Reads == 0 && !Directory.Exists(output), "interval rejected before reads/output"); }
            }
            phase = "invalid-acquisition-options";
            foreach (var caps in new[] { (0, 3), (129, 3), (-1, 3), (8, 0), (8, 17), (8, -1) })
            {
                m = new(); output = New();
                try
                {
                    ObserveFields.Run(m, new(Memory.Address, 64, m.Identity.ImageName), "unused-invalid-limit-recipe", output, 10,
                        TimeSpan.FromSeconds(1), maxAcquisitions: caps.Item1, maxConsecutiveAcquisitionFailures: caps.Item2);
                    Check(false, "invalid public acquisition caps accepted");
                }
                catch (ObservationException e)
                { Check(e.Code == "invalid_arguments" && m.Reads == 0 && !Directory.Exists(output), "invalid caps rejected before reads or output creation"); }
            }
            foreach (var option in new[] { ("max-acquisitions", "0"), ("max-acquisitions", "129"), ("max-acquisitions", "invalid"),
                ("max-consecutive-acquisition-failures", "0"), ("max-consecutive-acquisition-failures", "17"),
                ("reacquire-ms", "-1"), ("reacquire-ms", "999"), ("reacquire-ms", "30001"), ("reacquire-ms", "invalid") })
            {
                using var capture = new StringWriter(); TextWriter original = Console.Out; int exit;
                try
                {
                    Console.SetOut(capture);
                    exit = Program.Main(["observe-fields", "--pid", "1", "--recipe", "unused-invalid-limit-recipe", "--out", New(), "--" + option.Item1, option.Item2]);
                }
                finally { Console.SetOut(original); }
                using var error = JsonDocument.Parse(capture.ToString());
                Check(exit == 2 && error.RootElement.GetProperty("error").GetProperty("code").GetString() == "invalid_arguments",
                    "CLI cap validation precedes native process access:" + option.Item1 + ":" + option.Item2);
            }
            phase = "all-unknown"; m = new(); m.U32(16, uint.MaxValue); output = New();
            var unknown = Run(m, output, limits: new(RetryMilliseconds: 0, AllUnknownMilliseconds: 30));
            Check(!unknown.complete && unknown.stop_reason == "all_fields_unknown" && unknown.acquisitions.Length == 1 && unknown.fields.Single().observed == 0 && unknown.fields.Single().unknown > 0, "non-guard perpetual unknown stops without pointless reacquisition");
            Check(FieldRecordingVerification.Verify(Path.Combine(output, "segment-0001")).valid, "all-unknown stopped segment valid");
            phase = "identity-and-denial";
            foreach (string reason in new[] { "permission_denied", "identity_mismatch", "process_exited" })
            {
                m = new(); output = New(); var identity = m.Identity;
                var ended = Run(m, output, frame: (_, f) => { if (f.Sequence == 0) { if (reason == "identity_mismatch") m.Identity = identity with { Pid = identity.Pid + 1 }; else m.Failure = reason; } },
                    limits: new(Attempts: 128, ConsecutiveFailures: 16, RetryMilliseconds: 0));
                Check(!ended.complete && ended.stop_reason == reason && ended.acquisitions.Length == 1, "fatal stop without reacquisition:" + reason);
                Check(FieldRecordingVerification.Verify(Path.Combine(output, "segment-0001")).valid, "fatal segment retained:" + reason);
            }
            phase = "cancellation-in-acquisition"; m = new(); output = New();
            using (var stop = new CancellationTokenSource())
            {
                m.After = (_, _) => stop.Cancel(); var r = Run(m, output, stop.Token);
                Check(!r.complete && r.stop_reason == "cancelled" && r.acquisitions.Length == 1 && r.segments.Length == 0, "cancelled acquisition terminates");
                Check(File.Exists(Path.Combine(output, "acquisition-0001", "evidence.jsonl")) && !File.Exists(Path.Combine(output, "acquisition-0001", "profile.json")), "partial acquisition proof retained without profile");
            }
            phase = "zero-and-bounds"; m = new(); output = New(); using (var stop = new CancellationTokenSource())
            { stop.Cancel(); var r = Run(m, output, stop.Token); Check(r.stop_reason == "cancelled" && r.acquisitions.Length == 0 && m.Reads == 0, "pre-cancel no target reads"); }
            m = new(); output = New(); var readLimit = Run(m, output, limits: new(ReadBytes: 20, RetryMilliseconds: 0));
            Check(!readLimit.complete && readLimit.requested_read_bytes <= 20 && readLimit.acquisitions.Length == 1, "read budget shared across acquisition/recording");
            m = new(); output = New(); var callLimit = Run(m, output, limits: new(ReadCalls: 1, RetryMilliseconds: 0));
            Check(!callLimit.complete && callLimit.read_calls == 1 && m.Reads == 1 && callLimit.acquisitions.Length == 1, "session source call budget cannot be exceeded");
            m = new(); output = New(); var outputLimit = Run(m, output, limits: new(JsonBytes: 8192, RetryMilliseconds: 0));
            Check(!outputLimit.complete && outputLimit.stop_reason == "output_byte_limit" && outputLimit.segments.Single().frames == 0 && outputLimit.fields.Single().observed == 0,
                "zero-frame output refusal is incomplete without reacquisition");
            Check(outputLimit.recorded_json_bytes <= 8192 && FieldRecordingVerification.Verify(Path.Combine(output, "segment-0001")).valid, "output-refused segment remains strictly verifiable within shared cap");
            m = new(); output = New(); Directory.CreateDirectory(output); File.WriteAllText(Path.Combine(output, "keep"), "original");
            try { Run(m, output); Check(false, "existing destination accepted"); } catch (ObservationException e) { Check(e.Code == "output_exists" && m.Reads == 0, "existing destination rejected before reads"); }
            Check(File.ReadAllText(Path.Combine(output, "keep")) == "original", "existing content unchanged");
            m = new(); output = New(); var bad = Recipe(m.Identity); bad["unexpected"] = 1;
            var malformed = Run(m, output, recipe: Save(bad)); Check(!malformed.complete && malformed.stop_reason == "invalid_acquisition_recipe" && malformed.acquisitions.Length == 1 && m.Reads == 0, "invalid recipe not retried");
            phase = "live-sink-failure"; m = new(); output = New();
            using (var pipe = new LiveWriter { Fail = row => row.GetProperty("kind").GetString() == "frame" && row.GetProperty("sequence").GetInt64() == 2 })
            {
                var broken = Run(m, output, live: pipe);
                Check(!broken.complete && broken.stop_reason == "live_output_io_error" && broken.segments.Single().frames == 3 && broken.acquisitions.Length == 1,
                    "broken live sink stops acquisition after accepted raw frame");
                Check(Lines(pipe).Count(row => row.GetProperty("kind").GetString() == "frame") == 2 && Frames(Path.Combine(output, "segment-0001")).Length == 3 &&
                    FieldRecordingVerification.Verify(Path.Combine(output, "segment-0001")).valid, "failed delivery retains all raw frames and terminal summary");
                Check(JsonSerializer.SerializeToElement(broken.live_output).GetProperty("partial_or_unconfirmed_write_possible").GetBoolean(), "partial pipe writes explicitly uncertain");
            }
            phase = "live-unconfirmed-write"; m = new(); output = New();
            using (var pipe = new LiveWriter { FailAfterWrite = true, Fail = row => row.GetProperty("kind").GetString() == "frame" })
            {
                var unconfirmed = Run(m, output, live: pipe); var status = JsonSerializer.SerializeToElement(unconfirmed.live_output);
                Check(!unconfirmed.complete && unconfirmed.stop_reason == "live_output_io_error" &&
                    status.GetProperty("completed_write_lines").GetInt64() == Lines(pipe).Length - 1 &&
                    status.GetProperty("partial_or_unconfirmed_write_possible").GetBoolean(), "failed write not counted as confirmed even when bytes escaped");
                Check(FieldRecordingVerification.Verify(Path.Combine(output, "segment-0001")).valid, "unconfirmed live write preserves raw recording");
            }
            phase = "live-bound"; m = new(); output = New();
            using (var bounded = new LiveWriter())
            {
                var limited = Run(m, output, live: bounded, liveMaximum: LiveFieldOutput.EndReserve + 4000);
                Check(!limited.complete && limited.stop_reason == "live_output_byte_limit" && m.Reads < 100 && limited.acquisitions.Length <= 1, "live byte cap stops bounded work");
                var rows = Lines(bounded); Check(rows.Last().GetProperty("kind").GetString() == "session_end" &&
                    System.Text.Encoding.UTF8.GetByteCount(bounded.ToString()) <= LiveFieldOutput.EndReserve + 4000, "reserved end evidence respects output cap");
            }
            phase = "live-backpressure"; m = new(); output = New();
            using (var slow = new LiveWriter { Before = row => { if (row.GetProperty("kind").GetString() == "frame" && row.GetProperty("sequence").GetInt64() == 0) Thread.Sleep(60); } })
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                var delayed = Run(m, output, stop.Token, (_, f) => { if (f.Sequence == 1) stop.Cancel(); }, live: slow);
                var frames = Lines(slow).Where(row => row.GetProperty("kind").GetString() == "frame").ToArray();
                Check(frames.Length == 2 && frames[1].GetProperty("skipped_intervals_before").GetInt64() >= 4 && delayed.segments.Single().skipped_slots >= 4,
                    "synchronous backpressure becomes explicit missed slots without queued catchup");
            }
            phase = "live-timer"; m = new(); output = New();
            BinaryPrimitives.WriteInt64LittleEndian(m.Bytes.AsSpan(16), 100); m.U32(24, BitConverter.SingleToUInt32Bits(20)); m.U32(28, BitConverter.SingleToUInt32Bits(1));
            BinaryPrimitives.WriteInt64LittleEndian(m.Bytes.AsSpan(48), 102);
            var timerRecipe = Recipe(m.Identity); timerRecipe["profile_schema"] = "overwatch-decoder.field-profile/4";
            var timerField = timerRecipe["fields"]![0]!; timerField["type"] = "f32"; timerField["address"] = new JsonArray("rva", 16, 16);
            timerField["codec"] = TimerCodec.Name; timerField["clock_address"] = new JsonArray("rva", 48, 8); timerField["counter_scale_f32_hex"] = "0000803f";
            using (var timerLive = new LiveWriter())
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                var timerRun = Run(m, output, stop.Token, (_, f) => { if (f.Sequence == 0) BinaryPrimitives.WriteInt64LittleEndian(m.Bytes.AsSpan(48), 103); if (f.Sequence == 1) stop.Cancel(); }, recipe: Save(timerRecipe), live: timerLive);
                Check(!timerRun.complete && timerRun.segments.Single().frames == 2, "timer live sample-controlled cancellation");
                string exported = New() + ".jsonl"; FieldExport.Export(Path.Combine(output, "segment-0001"), exported);
                var projected = File.ReadLines(exported).Select(line => { using var d = JsonDocument.Parse(line); return d.RootElement.Clone(); }).Where(row => row.GetProperty("kind").GetString() == "frame").ToArray();
                var liveFrames = Lines(timerLive).Where(row => row.GetProperty("kind").GetString() == "frame").ToArray();
                for (int i = 0; i < 2; i++)
                {
                    var expected = projected[i].GetProperty("fields").GetProperty("value"); var actual = liveFrames[i].GetProperty("fields").GetProperty("value");
                    foreach (var property in expected.EnumerateObject()) Check(JsonElement.DeepEquals(property.Value, actual.GetProperty(property.Name)), "live timer matches strict compact export:" + property.Name);
                    Check(actual.GetProperty("source").GetString() == "calculated_process_memory" && !actual.GetProperty("operands").GetProperty("state").TryGetProperty("address_hex", out _), "timer source and separate operand timing without addresses");
                }
            }
            phase = "healthy-duration"; m = new(); output = New(); using var healthyLive = new LiveWriter();
            var healthy = Run(m, output, duration: TimeSpan.FromSeconds(2), live: healthyLive);
            Check(healthy.complete && healthy.stop_reason == "duration_elapsed" && healthy.fields.Single().observed > 0 && healthy.segments.Length == 1, "finite healthy run completes with observed coverage");
            Check(FieldRecordingVerification.Verify(Path.Combine(output, "segment-0001")).valid, "deadline segment strictly verifies");
            Check(!Directory.EnumerateDirectories(root, ".overwatch-decoder-observation-*", SearchOption.AllDirectories).Any() && !Directory.EnumerateFiles(root, "*.partial", SearchOption.AllDirectories).Any(), "normal cancellation leaves no publication partials");
            return assertions;
        }
        finally { Directory.Delete(root, true); }
    }
}
