using System.Buffers.Binary;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Owned output publication only: no external process or application reads.</summary>
public static class ObservationManifestTests
{
    private sealed class Memory : IMemorySource
    {
        internal const ulong Address = 65536;
        internal int Reads;
        public TargetIdentity Identity { get; } = new(63, "fixture.exe", "fixture", 13, new string('f', 64), "x64");
        public byte[] Read(ulong address, int size)
        {
            Reads++;
            var bytes = new byte[size];
            if (address == Address) BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0); // Deliberate predicate failure.
            return bytes;
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static string Recipe(Memory memory) => JsonSerializer.Serialize(new
    {
        schema = "overwatch-decoder.acquisition-recipe/1",
        target = new { image_name = memory.Identity.ImageName, executable_sha256 = memory.Identity.ExecutableSha256, architecture = "x64" },
        seconds = 10, constants = new { }, functions = new { }, global_guards = "g",
        stages = new[] { new { name = "root", steps = new object[] {
            new { op = "read", name = "root", address = new object[] { "rva", 0, 4 }, size = 4 },
            new { op = "require", test = new object[] { "eq", new object[] { "load", new object[] { "var", "root" }, 0, 4 }, 123 } },
            new { op = "guard", set = "g", value = new object[] { "var", "root" } }
        } } },
        fields = new[] { new { name = "value", type = "i32", address = new object[] { "rva", 16, 4 } } }
    });
    private static Exception Failure(int code) => code == 5 ? new UnauthorizedAccessException("Synthetic owned-output denial.") :
        new IOException("Synthetic owned-output failure.", unchecked((int)(0x80070000u | (uint)code)));
    public static int Run()
    {
        int assertions = 0, number = 0;
        void Check(bool ok, string label)
        { if (!ok) throw new ObservationException("self_test_failed", "observation-manifest:" + label); assertions++; }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-manifest-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string New() => Path.Combine(root, (++number).ToString());
        JsonElement Read(string path) => JsonSerializer.Deserialize<JsonElement>(File.ReadAllBytes(path));
        JsonElement[] Lines(StringWriter live) => live.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => JsonSerializer.Deserialize<JsonElement>(line)).ToArray();
        ObserveFields.Result Observe(string output, Action<string, string, int>? move = null, StringWriter? live = null,
            CancellationToken token = default, Memory? memory = null)
        {
            memory ??= new(); string recipe = New() + ".json"; File.WriteAllText(recipe, Recipe(memory));
            return ObserveFields.RunBounded(memory, new(Memory.Address, 64, memory.Identity.ImageName), recipe, output, 10,
                TimeSpan.FromSeconds(10), token, new(RetryMilliseconds: 0), liveOutput: live, fixtureManifestMove: move);
        }
        bool Finished(string pending) => Read(pending).GetProperty("status").GetString() == "finished";
        try
        {
            var baseline = Observe(New());
            Check(baseline.stop_reason == "acquisition_retry_limit" && baseline.acquisitions.Length == 3 && baseline.manifest_publication.final_manifest_saved &&
                baseline.manifest_publication.current_result_saved && baseline.manifest_publication.error is null, "healthy terminal publication flags");
            foreach (int code in new[] { 5, 32, 33 })
            {
                string output = New(); using var live = new StringWriter(); var memory = new Memory(); int injected = 0;
                var transient = Observe(output, (pending, destination, attempt) =>
                {
                    if (Path.GetDirectoryName(destination) == output && !Finished(pending) && injected < 2)
                    { injected++; throw Failure(code); }
                }, live, memory: memory);
                Check(injected == 2 && transient.stop_reason == "acquisition_retry_limit" && transient.acquisitions.Length == 3 && memory.Reads == 3,
                    "transient publication retries do not duplicate target work:" + code);
                Check(transient.manifest_publication.current_result_saved && !Directory.EnumerateFiles(output, "*.partial").Any() &&
                    Lines(live).Last().GetProperty("kind").GetString() == "session_end", "transient owned-output replacement recovers:" + code);
            }
            foreach (int code in new[] { 5, 32, 33, 112 })
            {
                string output = New(); using var live = new StringWriter(); int calls = 0; string? pendingPath = null;
                var failed = Observe(output, (pending, _, attempt) =>
                {
                    if (!Finished(pending)) return;
                    calls++; pendingPath ??= pending; Check(pendingPath == pending && attempt == calls, "same complete pending file for bounded retry:" + code);
                    throw Failure(code);
                }, live);
                Check(calls == (code == 112 ? 1 : ObserveFields.ManifestMoveAttempts) && failed.stop_reason == "manifest_publication_failed" && !failed.complete &&
                    !failed.manifest_publication.final_manifest_saved && !failed.manifest_publication.current_result_saved, "permanent terminal failure is bounded and unsaved:" + code);
                Check(failed.manifest_publication.native_error_code == code && failed.manifest_publication.operation_stop_reason == "acquisition_retry_limit" &&
                    failed.manifest_publication.error == (code == 5 ? "output_permission_denied" : "output_io_error"), "terminal error preserves native code and operation result:" + code);
                Check(Read(Path.Combine(output, "manifest.json")).GetProperty("status").GetString() == "running" &&
                    Directory.EnumerateFiles(output, "*.partial").Count() == 1 && Read(pendingPath!).GetProperty("status").GetString() == "finished", "stale manifest and pending evidence preserved:" + code);
                var terminal = Lines(live).Last(); var summary = terminal.GetProperty("result_before_this_write");
                Check(terminal.GetProperty("kind").GetString() == "session_end" && summary.GetProperty("stop_reason").GetString() == "manifest_publication_failed" &&
                    !summary.GetProperty("manifest_publication").GetProperty("final_manifest_saved").GetBoolean(), "live terminal explicitly reports unsaved final state:" + code);
                Check(failed.read_calls == 3 && failed.acquisitions.Length == 3 && failed.segments.Length == 0 &&
                    failed.acquisitions.All(a => a.error == "acquisition_predicate_failed" && File.Exists(Path.Combine(output, a.directory, "evidence.jsonl"))), "acquisition evidence retained without semantic changes:" + code);
            }
            {
                string output = New(); using var live = new StringWriter(); int finals = 0, calls = 0;
                var failedRefresh = Observe(output, (pending, _, attempt) =>
                {
                    if (!Finished(pending)) return;
                    if (attempt == 1) finals++;
                    if (finals == 2) { calls++; throw Failure(5); }
                }, live);
                Check(finals == 2 && calls == ObserveFields.ManifestMoveAttempts && failedRefresh.stop_reason == "manifest_publication_failed" &&
                    failedRefresh.manifest_publication.final_manifest_saved && !failedRefresh.manifest_publication.current_result_saved, "post-terminal failure distinguishes prior saved final from current state");
                var rows = Lines(live); var earlier = rows[^2].GetProperty("result_before_this_write"); var later = rows[^1].GetProperty("result_before_this_write");
                Check(rows[^2].GetProperty("kind").GetString() == "session_end" && rows[^1].GetProperty("kind").GetString() == "session_finalization_error" &&
                    earlier.GetProperty("manifest_publication").GetProperty("current_result_saved").GetBoolean() &&
                    !later.GetProperty("manifest_publication").GetProperty("current_result_saved").GetBoolean(), "post-terminal error reports changed publication truth");
                Check(Read(Path.Combine(output, "manifest.json")).GetProperty("stop_reason").GetString() == "acquisition_retry_limit" &&
                    Directory.EnumerateFiles(output, "*.partial").Count() == 1, "prior finished file not replaced by an unwritten failure report");
                Check(JsonSerializer.SerializeToElement(failedRefresh.live_output).GetProperty("completed_write_lines").GetInt64() == rows.Length &&
                    rows.Select((row, i) => row.GetProperty("event_sequence").GetInt64() == i).All(ok => ok), "fallback event has exact returned live counters and order");
            }
            {
                string output = New(); using var live = new StringWriter(); int calls = 0;
                var failed = Observe(output, (pending, destination, _) =>
                { if (Path.GetDirectoryName(destination) == output) { calls++; throw Failure(5); } }, live);
                Check(calls == 2 * ObserveFields.ManifestMoveAttempts && failed.stop_reason == "manifest_publication_failed" && failed.acquisitions.Length == 0 &&
                    failed.manifest_publication.operation_stop_reason == "output_permission_denied", "checkpoint and final failure both bounded with terminal fallback");
                Check(Lines(live).Last().GetProperty("kind").GetString() == "session_end" && Directory.EnumerateFiles(output, "*.partial").Count() == 2, "reproduced checkpoint-final failure leaves both complete partials");
            }
            {
                string output = New(); using var cancelled = new CancellationTokenSource(); int calls = 0;
                var interrupted = Observe(output, (pending, destination, _) =>
                {
                    if (Path.GetDirectoryName(destination) != output || Finished(pending)) return;
                    calls++; cancelled.Cancel(); throw Failure(32);
                }, token: cancelled.Token);
                Check(calls == 1 && interrupted.read_calls == 0 && interrupted.stop_reason == "output_io_error" && interrupted.manifest_publication.current_result_saved,
                    "cancellation ends checkpoint retry wait while allowing bounded terminal publication");
            }
            // Direct publisher tests avoid acquisition/recording timing and operate only on our own files.
            string directory = New(); Directory.CreateDirectory(directory); string destinationPath = Path.Combine(directory, "manifest.json");
            File.WriteAllText(destinationPath, "original");
            try { ObserveFields.WriteManifest(directory, baseline with { note = new string('x', 300000) }); Check(false, "oversized metadata accepted"); }
            catch (ObservationException e) { Check(e.Code == "observation_manifest_limit" && File.ReadAllText(destinationPath) == "original" && !Directory.EnumerateFiles(directory, "*.partial").Any(), "metadata cap enforced before writing pending artifact"); }
            if (OperatingSystem.IsWindows())
            {
                using (var held = new FileStream(destinationPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    int attempts = 0;
                    try
                    {
                        ObserveFields.WriteManifest(directory, baseline, fixtureMove: (_, _, attempt) => attempts = attempt);
                        Check(false, "permanently locked native manifest replaced");
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    {
                        Check(attempts == ObserveFields.ManifestMoveAttempts && (e.HResult & 0xffff) is 5 or 32 or 33 &&
                            File.ReadAllText(destinationPath) == "original", "native reader denies replacement within bounded attempts");
                    }
                }
                var reader = new FileStream(destinationPath, FileMode.Open, FileAccess.Read, FileShare.Read); int releasedAt = 0;
                try
                {
                    ObserveFields.WriteManifest(directory, baseline, fixtureMove: (_, _, attempt) =>
                    { releasedAt = attempt; if (attempt == 2) reader.Dispose(); });
                    Check(releasedAt == 2 && Read(destinationPath).GetProperty("status").GetString() == "finished", "native retry succeeds after denying reader closes");
                }
                finally { reader.Dispose(); }
                string lockedOutput = New(); using var lockedLive = new StringWriter(); FileStream? heldManifest = null;
                try
                {
                    var lockedRun = Observe(lockedOutput, (_, destination, _) =>
                    {
                        if (Path.GetDirectoryName(destination) == lockedOutput)
                            heldManifest ??= new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read);
                    }, lockedLive);
                    Check(lockedRun.stop_reason == "manifest_publication_failed" && !lockedRun.manifest_publication.final_manifest_saved &&
                        !lockedRun.manifest_publication.current_result_saved && lockedRun.manifest_publication.native_error_code is 5 or 32 or 33,
                        "native permanent denying reader produces explicit unsaved terminal result");
                    Check(Lines(lockedLive).Last().GetProperty("kind").GetString() == "session_end" && lockedRun.read_calls == 0 &&
                        Directory.EnumerateFiles(lockedOutput, "*.partial").Count() == 2, "native locked checkpoint and final preserve evidence and emit terminal fallback");
                }
                finally { heldManifest?.Dispose(); }
            }
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
