using System.Buffers.Binary;
using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

internal static class ObservePreparationTests
{
    private sealed class Memory : IMemorySource
    {
        private readonly object gate = new(); private readonly byte[] bytes = new byte[64];
        private int entered; internal int MaximumConcurrent, Reads;
        public TargetIdentity Identity { get; private set; } = new(19, "fixture.exe", "fixture", 23, new string('e', 64), "x64");
        internal Memory() { Set(0, 123); Set(4, 1); Set(16, 17); Set(24, 16); Set(32, 29); }
        internal void Set(int offset, uint value) { lock (gate) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value); }
        public byte[] Read(ulong address, int size)
        {
            int current = Interlocked.Increment(ref entered); MaximumConcurrent = Math.Max(MaximumConcurrent, current);
            try { lock (gate) { Reads++; return bytes.AsSpan(checked((int)(address - 65536)), size).ToArray(); } }
            finally { Interlocked.Decrement(ref entered); }
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private sealed class Writer : StringWriter
    {
        internal string? FailKind;
        internal Action<JsonElement>? Observe;
        public override void Write(string? value)
        {
            using var doc = JsonDocument.Parse(value!);
            if (doc.RootElement.GetProperty("kind").GetString() == FailKind) throw new IOException("fixture output failure");
            base.Write(value);
            Observe?.Invoke(doc.RootElement);
        }
    }
    private static JsonObject Recipe(Memory memory) => JsonNode.Parse(JsonSerializer.Serialize(new
    {
        schema = "overwatch-decoder.acquisition-recipe/1", target = new { image_name = memory.Identity.ImageName,
            executable_sha256 = memory.Identity.ExecutableSha256, architecture = "x64" }, seconds = 5,
        constants = new { }, functions = new { }, global_guards = "g",
        stages = new[] { new { name = "header", steps = new object[] {
            new { op = "read", name = "header", address = new object[] { "rva", 0, 8 }, size = 8 },
            new { op = "guard", set = "g", value = new object[] { "var", "header" } },
            new { op = "read", name = "route", address = new object[] { "rva", 24, 4 }, size = 4 } } } },
        fields = new[] { new { name = "value", type = "i32", address = new object[] { "rva", new object[] { "load", new object[] { "var", "route" }, 0, 4 }, 4 } } }
    }))!.AsObject();
    private static JsonElement[] Events(Writer writer) => writer.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries)
        .Select(s => JsonDocument.Parse(s).RootElement.Clone()).ToArray();
    public static int Run()
    {
        int assertions = 0, serial = 0;
        void Check(bool ok, string reason) { assertions++; if (!ok) throw new ObservationException("self_test_failed", "preparation:" + reason); }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-preparation-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            foreach (string scenario in new[] { "handoff", "stale", "invalidated", "cancel", "deadline", "fatal", "output", "budget", "attempts", "activation_cancel", "evidence", "retry", "retry_join", "profile_tamper", "fatal_deadline", "unchanged", "unchanged_guard", "unchanged_cancel", "unchanged_fatal", "unchanged_tamper" })
            {
                var memory = new Memory(); string output = Path.Combine(root, (++serial).ToString()), recipe = output + ".json";
                File.WriteAllText(recipe, Recipe(memory).ToJsonString());
                bool deadlineScenario = scenario is "deadline" or "fatal_deadline";
                TimeSpan duration = TimeSpan.FromSeconds(deadlineScenario ? 5 : 6);
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(deadlineScenario ? 20 : 8));
                using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
                using var writer = new Writer { FailKind = scenario == "output" ? "preparation_end" : null };
                int overlappingFrames = 0, activationCalls = 0, stageWorkers = 0, maximumWorkers = 0;
                long sessionDeadline = 0, deadlineBoundary = 0; bool pendingAtDeadlineBoundary = false;
                if (deadlineScenario) writer.Observe = line =>
                {
                    string? kind = line.GetProperty("kind").GetString();
                    if (kind == "session_start") sessionDeadline = line.GetProperty("monotonic_origin_ticks").GetInt64() +
                        checked((long)(duration.TotalSeconds * line.GetProperty("monotonic_frequency").GetInt64()));
                    if (kind != "segment_end") return;
                    deadlineBoundary = line.GetProperty("segment").GetProperty("end_ticks").GetInt64();
                    pendingAtDeadlineBoundary = entered.IsSet && Volatile.Read(ref stageWorkers) == 1 && !release.IsSet;
                    // The recorder has closed its segment. Only this boundary may
                    // release the worker, so it cannot finish early under CI load.
                    release.Set();
                };
                var oldFrameEnds = new List<long>();
                bool identical = scenario.StartsWith("unchanged", StringComparison.Ordinal);
                void Stage(int attempt, string stage)
                {
                    if (stage == "comparison")
                    {
                        if (scenario == "unchanged_cancel") stop.Cancel();
                        if (scenario == "unchanged_fatal") throw new ObservationException("permission_denied", "fixture no-change permission failure");
                        if (scenario == "unchanged_tamper") File.AppendAllText(Path.Combine(output, "acquisition-0002", "profile.json"), " ");
                        return;
                    }
                    if (stage == "activation")
                    {
                        activationCalls++;
                        if (scenario == "stale") memory.Set(4, 2);
                        if (scenario == "activation_cancel") stop.Cancel();
                        if (scenario == "profile_tamper")
                            File.AppendAllText(Path.Combine(output, "acquisition-0002", "profile.json"), " ");
                        return;
                    }
                    if (attempt != 2 || stage != (scenario == "unchanged_guard" ? "prepared" : "header")) return;
                    int active = Interlocked.Increment(ref stageWorkers); maximumWorkers = Math.Max(maximumWorkers, active);
                    try
                    {
                        entered.Set();
                        if (scenario is "deadline" or "fatal_deadline")
                        {
                            if (!release.Wait(TimeSpan.FromSeconds(15)))
                                throw new ObservationException("fixture_wait_timeout", "Deadline boundary did not release preparation.");
                            if (scenario == "fatal_deadline")
                                throw new ObservationException("permission_denied", "fixture fatal failure during deadline join");
                            // Cooperate only after the observed deadline boundary.
                            // Token propagation is checked separately by cancel,
                            // whose callback cancels the token before release.
                            throw new OperationCanceledException("Fixture cooperates after the deadline boundary.");
                        }
                        if (scenario == "fatal") throw new ObservationException("permission_denied", "fixture permission failure");
                        if (scenario == "retry_join")
                        {
                            if (!release.Wait(TimeSpan.FromSeconds(2))) throw new ObservationException("fixture_wait_timeout", "Join fixture not released.");
                            Thread.Sleep(50);
                            throw new ObservationException("unreadable_range", "fixture retryable joined worker");
                        }
                        if (scenario == "retry") throw new ObservationException("unreadable_range", "fixture retryable preparation");
                        if (!release.Wait(TimeSpan.FromSeconds(2))) throw new ObservationException("fixture_wait_timeout", "Fixture did not release worker.");
                    }
                    finally { Interlocked.Decrement(ref stageWorkers); }
                }
                void Frame(int segment, FieldStream.AcceptedFrame frame)
                {
                    if (segment == 1) oldFrameEnds.Add(frame.End);
                    if (segment == 1 && frame.Sequence == 0)
                    { if (identical) memory.Set(16, 29); else memory.Set(24, 32); }
                    if (entered.IsSet && !release.IsSet)
                    {
                        overlappingFrames++;
                        if (deadlineScenario)
                        {
                            // Let the real deadline expire between accepted frames,
                            // not in a fixture read where it would test terminal-read
                            // classification instead of pending-preparation joining.
                            long remaining;
                            while ((remaining = sessionDeadline - System.Diagnostics.Stopwatch.GetTimestamp()) > 0)
                            {
                                int waitMs = (int)Math.Min(1000, Math.Max(1, Math.Ceiling(remaining * 1000d / System.Diagnostics.Stopwatch.Frequency)));
                                if (stop.Token.WaitHandle.WaitOne(waitMs)) break;
                            }
                        }
                        if (scenario == "retry_join")
                        { memory.Set(4, 2); if (frame.GuardInvalidated) release.Set(); }
                        else if (scenario == "unchanged_guard")
                        { memory.Set(4, 2); if (frame.GuardInvalidated) release.Set(); }
                        else if (scenario == "cancel") { stop.Cancel(); release.Set(); }
                        else if (overlappingFrames >= 5 && scenario is not ("deadline" or "fatal_deadline"))
                        {
                            if (scenario == "invalidated") memory.Set(4, 2);
                            release.Set();
                        }
                    }
                    if (scenario != "deadline" && segment == 2 && frame.Sequence == 2) stop.Cancel();
                }
                var result = ObserveFields.RunBounded(memory, new(65536, 64, memory.Identity.ImageName), recipe, output, 10,
                    duration, stop.Token,
                    new(Attempts: scenario == "attempts" ? 1 : scenario == "unchanged" ? 3 : 4, RetryMilliseconds: scenario is "retry" or "retry_join" or "stale" ? 600 : 0, ReacquireMilliseconds: 1000,
                        ReadCalls: scenario == "budget" ? 310 : ObserveFields.MaximumReadCalls,
                        EvidenceBytes: scenario == "evidence" ? 262144 : Acquisition.MaximumEvidenceBytes), Frame, writer,
                    backgroundPreparation: true, fixturePreparationStage: Stage);
                release.Set();
                Check(stageWorkers == 0 && maximumWorkers <= 1 && memory.MaximumConcurrent == 1, scenario + ":joined and serialized");
                Check(result.acquisitions.Length <= (scenario == "attempts" ? 1 : 4), scenario + ":attempt budget");
                var events = Events(writer); string[] kinds = events.Select(e => e.GetProperty("kind").GetString()!).ToArray();
                foreach (var segment in result.segments)
                    Check(FieldRecordingVerification.Verify(Path.Combine(output, segment.directory)).valid, scenario + ":strict recording verification");
                if (scenario == "handoff")
                {
                    Check(overlappingFrames >= 5 && result.segments.Length == 2 && activationCalls == 1, "reader continues during preparation");
                    Check(result.segments[0].trigger == "prepared_reacquisition" && result.acquisitions.Length == 2, "prepared boundary consumes one attempt");
                    var activationEvent = events.Single(e => e.GetProperty("kind").GetString() == "acquisition_end" && e.TryGetProperty("prepared", out _));
                    var proof = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(output, "acquisition-0002", "activation.json"))).RootElement;
                    Check(proof.GetProperty("passed").GetBoolean() && proof.GetProperty("start_ticks").GetInt64() >= result.segments[0].last_frame_end_ticks,
                        "all candidate guards freshly proved after old frame");
                    Check(activationEvent.GetProperty("activation").GetProperty("evidence_sha256").GetString() ==
                        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path.Combine(output, "acquisition-0002", "activation.json")))), "activation proof hash");
                    var values = events.Where(e => e.GetProperty("kind").GetString() == "frame").ToArray();
                    Check(values.Where(e => e.GetProperty("segment").GetInt32() == 1).All(e => e.GetProperty("fields").GetProperty("value").GetProperty("value").GetInt32() == 17) &&
                        values.Where(e => e.GetProperty("segment").GetInt32() == 2).All(e => e.GetProperty("fields").GetProperty("value").GetProperty("value").GetInt32() == 29), "fresh profile values only after activation");
                    Check(values.Length == result.segments.Sum(s => s.frames), "boundary frames retained");
                }
                if (scenario == "unchanged")
                {
                    Check(result.stop_reason == "acquisition_attempt_limit" && result.segments.Length == 1 &&
                        result.acquisitions.Length == 3 && result.unchanged_preparations?.Length == 2, "identical refreshes retain epoch and consume normal attempts");
                    var diagnostics = events.Where(e => e.GetProperty("kind").GetString() == "preparation_no_change").ToArray();
                    Check(diagnostics.Length == 2 && diagnostics.All(e => e.GetProperty("active_acquisition").GetInt32() == 1 &&
                        !e.GetProperty("profile_adopted").GetBoolean()), "no-change diagnostics pin original active acquisition");
                    Check(!kinds.Contains("preparation_discard") && kinds.Count(k => k == "segment_start") == 1 && activationCalls == 0 &&
                        !File.Exists(Path.Combine(output, "acquisition-0002", "activation.json")), "no activation or duplicated epoch for identical profile");
                    Check(result.acquisitions[2].start_ticks >= result.unchanged_preparations![0].comparison_end_ticks +
                        result.monotonic_frequency, "configured refresh interval advances instead of busy looping");
                    Check(events.Where(e => e.GetProperty("kind").GetString() == "frame").Any(e =>
                        e.GetProperty("fields").GetProperty("value").GetProperty("value").GetInt32() == 29), "unchanged profile still reads fresh scalar values");
                }
                if (scenario == "unchanged_guard") Check(!kinds.Contains("preparation_no_change") && result.segments[0].trigger == "guard_invalidation" &&
                    result.segments[0].unknown_fields > 0 && kinds.Contains("preparation_discard"), "known guard invalidation wins over equal profile digest");
                if (scenario is "unchanged_cancel" or "unchanged_fatal" or "unchanged_tamper")
                    Check(!kinds.Contains("preparation_no_change") && result.segments.Length == 1 && kinds.Contains("preparation_discard") &&
                        result.stop_reason == (scenario == "unchanged_cancel" ? "cancelled" : scenario == "unchanged_fatal" ? "permission_denied" : "profile_identity_mismatch"),
                        "no-change cancellation/fatal/hash tamper never adopts or hides error:" + scenario);
                if (scenario == "activation_cancel") Check(result.stop_reason == "cancelled" && result.segments.Length == 1 && kinds.Contains("preparation_discard"), "activation cancellation discards candidate before segment");
                if (scenario == "profile_tamper") Check(result.stop_reason == "profile_identity_mismatch" && result.segments.Length == 1 && kinds.Contains("preparation_discard"), "candidate byte hash pinned at activation");
                if (scenario == "evidence") Check(result.stop_reason == "session_evidence_limit" && result.acquisition_evidence_bytes <= 262144 && result.segments.Length == 1, "activation artifact budget charged before publication");
                if (scenario == "retry") Check(result.acquisitions.Length == 3 && result.acquisitions[1].error == "unreadable_range" && result.segments.Length == 2, "retry consumes attempt and keeps old guarded reader active");
                if (scenario is "retry" or "retry_join")
                {
                    Check(result.acquisitions.Length == 3 && result.acquisitions[1].error == "unreadable_range" && result.segments.Length == 2, "delayed retry resumes after worker failure:" + scenario);
                    Check((result.acquisitions[2].start_ticks-result.acquisitions[1].end_ticks)*1000d/result.monotonic_frequency >= 600, "prepared failure honors retry interval:" + scenario);
                    if (scenario == "retry") Check(oldFrameEnds.Count(t => t > result.acquisitions[1].end_ticks && t < result.acquisitions[2].start_ticks) >= 10, "valid old reader continues during prepared retry delay");
                }
                if (scenario == "stale")
                {
                    var discarded = events.Single(e => e.GetProperty("kind").GetString() == "preparation_discard");
                    Check((result.acquisitions[2].start_ticks-discarded.GetProperty("end_ticks").GetInt64())*1000d/result.monotonic_frequency >= 600, "failed activation honors retry interval before synchronous fallback");
                }
                if (scenario == "stale") Check(kinds.Contains("preparation_discard") && result.acquisitions.Length == 3 && result.segments[1].acquisition == 3, "stale candidate discarded then fresh synchronous acquire");
                if (scenario == "invalidated") Check(result.segments[0].trigger == "guard_invalidation" && result.segments[0].unknown_fields > 0, "invalid old fields never carried while waiting");
                if (scenario == "fatal") Check(result.stop_reason == "permission_denied" && result.segments.Length == 1, "worker permission denial stops reader");
                if (scenario == "output") Check(result.stop_reason == "live_output_io_error" && result.segments.Length == 1, "delivery failure prevents activation");
                if (scenario == "budget") Check(result.requested_read_bytes <= FieldStream.MaximumReadBytes && result.read_calls <= 310, "shared calls reserved without overrun");
                if (scenario == "cancel") Check(result.stop_reason == "cancelled" && result.segments.Length == 1 &&
                    result.acquisitions.Length == 2 && result.acquisitions[1].error == "cancelled" && kinds.Contains("preparation_end"),
                    "cancellation token reaches pending acquisition before its fixture releases");
                if (deadlineScenario)
                {
                    Check(sessionDeadline > 0 && deadlineBoundary >= sessionDeadline && pendingAtDeadlineBoundary,
                        "real deadline boundary observes still-pending preparation:" + scenario);
                    int boundaryEvent = Array.IndexOf(kinds,"segment_end"), preparationEvent = Array.IndexOf(kinds,"preparation_end"), terminalEvent = Array.IndexOf(kinds,"session_end");
                    Check(boundaryEvent >= 0 && preparationEvent > boundaryEvent && terminalEvent > preparationEvent &&
                        result.acquisitions.Length == 2 && result.acquisitions[1].end_ticks >= deadlineBoundary,
                        "pending preparation is joined and reported between segment and session end:" + scenario);
                }
                if (scenario == "deadline") Check(result.stop_reason == "duration_elapsed" && result.segments.Length == 1 &&
                    result.acquisitions[1].error == "cancelled", "deadline joins still-pending preparation");
                if (scenario == "fatal_deadline") Check(result.stop_reason == "permission_denied" && result.segments.Length == 1 &&
                    result.acquisitions[1].error == "permission_denied", "fatal worker result at deadline join cannot become clean duration");
                if (scenario == "attempts") Check(result.stop_reason == "acquisition_attempt_limit" && !kinds.Contains("preparation_start"), "no worker past reserved attempt budget");
            }
            byte[] original = [1, 2, 3], altered = [1, 2, 4];
            string originalHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(original));
            string alteredHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(altered));
            Check(ObserveFields.IdenticalPreparedBytes(original, original, originalHash) &&
                !ObserveFields.IdenticalPreparedBytes(original, altered, alteredHash), "actual bytes distinguish identical and different profiles");
            try { ObserveFields.IdenticalPreparedBytes(original, altered, originalHash); Check(false, "claimed same hash with different bytes accepted"); }
            catch (ObservationException e) { Check(e.Code == "profile_identity_mismatch", "claimed same hash does not replace byte rehash"); }
            using var invalidOutput = new StringWriter(); TextWriter oldOutput = Console.Out;
            try
            {
                Console.SetOut(invalidOutput);
                Check(Program.Main(["observe-fields", "--pid", "1", "--recipe", "unused", "--out", Path.Combine(root,"invalid"),
                    "--background-prepare", "true"]) == 2, "CLI rejects background without interval before opening process");
            }
            finally { Console.SetOut(oldOutput); }
            Check(!Directory.Exists(Path.Combine(root,"invalid")), "invalid opt-in creates no artifacts");
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
