using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using OverwatchDecoder.SessionRecorder;

static class ObservationHandoffTests
{
    private const long MiB = 1048576;
    private const string Gameplay = "read_only_user_gameplay";

    public static async Task<int> Run(string root)
    {
        int checks = 0;
        void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; }

        string package = Path.Combine(root, "observation-handoff-package");
        string bundle = Path.Combine(package, "bundle");
        Directory.CreateDirectory(bundle);
        string runtime = Path.Combine(package, "python.exe"), entry = Path.Combine(bundle, "run.py");
        string inventory = Path.Combine(bundle, "inventory.json");
        File.WriteAllText(runtime, "portable fake launcher");
        File.WriteAllText(entry, "pinned synthetic entry");
        File.WriteAllBytes(inventory, JsonSerializer.SerializeToUtf8Bytes(new {
            files = new[] { new { path = "run.py", size = new FileInfo(entry).Length, sha256 = RosterCapture.Hash(entry) } } }));
        ObservationPlan Plan() => new() {
            PythonExecutable = "python.exe", PythonSha256 = RosterCapture.Hash(runtime), BundleDirectory = "bundle",
            InventorySha256 = RosterCapture.Hash(inventory), Entrypoint = "run.py", CaptureScope = ObservationScope.ReadOnlyUserGameplay,
            StorageFormat = ObservationStorageFormat.CohortsV1, StorageCohortMiB = 1, ContinueObservationWindows = true,
            WindowSeconds = 20, SuccessorLeadSeconds = 6, MaximumWindows = 5, MaximumOutputMiB = 4500
        };

        Check(!JsonSerializer.SerializeToElement(new ObservationPlan()).TryGetProperty("SuccessorLeadSeconds", out _),
            "The disabled handoff setting preserves the default settings serialization");
        var defaultCapture = new ObservationCapture(123, new ObservationPlan(), package, root, () => true, _ => { });
        Check(!JsonSerializer.SerializeToElement(defaultCapture.Summary).TryGetProperty("overlapping_windows", out _),
            "The default summary retains the serial schema");
        foreach (Action<ObservationPlan> invalid in new Action<ObservationPlan>[] {
            plan => plan.SuccessorLeadSeconds = -1,
            plan => plan.SuccessorLeadSeconds = plan.WindowSeconds,
            plan => plan.MaximumWindows = 1,
            plan => { plan.ContinueObservationWindows = false; plan.MaximumWindows = 1; },
            plan => plan.StorageFormat = ObservationStorageFormat.FlatV1,
            plan => plan.CaptureScope = ObservationScope.ControlledPractice
        })
        {
            var plan = Plan(); invalid(plan);
            try { ObservationCapture.Validate(package, plan); }
            catch (InvalidDataException) { checks++; continue; }
            throw new Exception("Unsupported observation handoff plan accepted.");
        }

        var chain = await Exercise("chain", Plan(), root, package);
        Check(chain.Peak == 2 && chain.Launches == 4 && chain.Closes == 4, "A chain uses at most two owned producers");
        Check(chain.Starts.Select(x => x.Time).SequenceEqual(new[] { 0, 14, 28, 42 }),
            "Each eligible successor uses its own predecessor launch time");
        Check(chain.Starts[1].Budget == (4500 - 4096 - 64) * MiB
            && chain.Starts.All(x => x.Budget <= 4096 * MiB), "Active caps and both log reserves fit the total budget");
        Check(chain.Accepted.SequenceEqual(new[] { 1, 2, 3, 4 }) && chain.Error is null && chain.Gaps.Length == 0,
            "Finish drains two already-active windows and never launches another");
        var summary = chain.Summary;
        Check(summary.GetProperty("overlapping_windows").GetBoolean()
            && summary.GetProperty("successor_lead_seconds").GetInt32() == 6
            && summary.GetProperty("successor_timing_basis").GetString() == "recorder_launch_qpc",
            "The manifest names the opt-in timing basis");
        Check(chain.Journal.Where(IsStart).All(row => row.GetProperty("qpc_ticks").GetInt64() ==
            row.GetProperty("launch_qpc_ticks").GetInt64() && row.GetProperty("timing_basis").GetString() == "recorder_launch_qpc"),
            "Start markers retain the launch QPC");
        Check(chain.Journal.Where(IsStart).Skip(1).Select(row => row.GetProperty("predecessor_window").GetInt32())
            .SequenceEqual(new[] { 1, 2, 3 }), "Overlap names each active predecessor");

        var reverse = await Exercise("out-of-order", Plan(), root, package);
        Check(reverse.Journal.Where(row => Kind(row) == "observation_window_end").Select(Window).SequenceEqual(new[] { 2, 1, 3 })
            && reverse.Accepted.SequenceEqual(new[] { 1, 2, 3 }), "Actual completion order and sorted accepted numbers are both preserved");
        Check(reverse.Starts.Select(x => x.Time).SequenceEqual(new[] { 0, 14, 21 }),
            "An early-finishing successor cannot trigger a second successor from the same parent");

        var low = Plan(); low.MaximumOutputMiB = 300;
        var fallback = await Exercise("low-budget", low, root, package);
        Check(fallback.Peak == 1 && fallback.Starts.Select(x => x.Time).SequenceEqual(new[] { 0, 21 })
            && fallback.Starts[0].Budget == 268 * MiB && fallback.Error is null,
            "Insufficient reserve falls back to verified serial windows");

        foreach (string mode in new[] { "no-position", "unavailable" })
        {
            var result = await Exercise(mode, Plan(), root, package);
            bool unavailable = mode == "unavailable";
            Check(result.Peak == 1 && result.Starts[1].Time == (unavailable ? 35 : 21)
                && result.Pauses.SequenceEqual(new[] { unavailable ? 15 : 1 }),
                "Status, empty entities, and unknown positions cannot prime a successor: " + mode);
            Check(result.Accepted.SequenceEqual(unavailable ? new[] { 2 } : new[] { 1, 2 })
                && result.Gaps.Length == (unavailable ? 1 : 0) && result.Error is null,
                "Verified source-unavailable windows remain gaps with a bounded retry: " + mode);
        }

        foreach (string mode in new[] { "cancel", "target-exit", "hard-error", "cleanup-fault" })
        {
            var result = await Exercise(mode, Plan(), root, package);
            Check(result.Launches == 2 && result.Closes == 2 && result.Accepted.Length == 0,
                "Each active job closes exactly once and no unverified window is accepted: " + mode);
            Check(result.Gaps.Order().SequenceEqual(new[] { 1, 2 }) && (result.Error is null) == (mode == "cancel"),
                "Each active window records its own failure or cancellation gap: " + mode);
        }

        var limitedPlan = Plan(); limitedPlan.MaximumWindows = 2;
        var limited = await Exercise("attempts", limitedPlan, root, package);
        Check(limited.Launches == 2 && limited.Accepted.SequenceEqual(new[] { 1, 2 })
            && limited.Error == "Observation attempt limit reached.", "No rollover exceeds the attempt cap");
        foreach (string mode in new[] { "wall", "log", "window-budget" })
        {
            var plan = Plan();
            if (mode == "window-budget") plan.MaximumOutputMiB = 300;
            var result = await Exercise(mode, plan, root, package);
            string error = mode == "window-budget" ? "output byte bound" : mode;
            Check(result.Launches == 1 && result.Closes == 1 && result.Gaps.SequenceEqual(new[] { 1 })
                && result.Error?.Contains(error, StringComparison.OrdinalIgnoreCase) == true, "A stalled or oversized owned job fails closed: " + mode);
        }
        return checks;
    }

    private static async Task<RunResult> Exercise(string mode, ObservationPlan plan, string root, string package)
    {
        int now = 0, count = 0, running = 0, peak = 0, closes = 0;
        long origin = Stopwatch.GetTimestamp();
        bool alive = true;
        var events = new List<JsonElement>();
        var starts = new List<(int Time, long Budget)>();
        var pauses = new List<int>();
        using var cancellation = new CancellationTokenSource();
        ObservationCapture? capture = null;
        capture = new ObservationCapture(123, plan, package, Path.Combine(root, "handoff-" + mode), () => alive,
            item =>
            {
                var row = JsonSerializer.SerializeToElement(item);
                events.Add(row);
                if (Kind(row) != "observation_receipt") return;
                int window = Window(row);
                if (window == 4 && mode == "chain" || window == 3 && mode == "out-of-order"
                    || window == 2 && mode is "low-budget" or "unavailable" or "no-position")
                    capture!.RequestFinishAfterWindow();
                if (window == 2 && mode is "cancel" or "cleanup-fault") cancellation.Cancel();
                if (window == 2 && mode == "target-exit") alive = false;
            },
            (info, log) =>
            {
                int window = ++count, start = now;
                long budget = long.Parse(Arg(info, "--maximum-total-bytes"));
                starts.Add((start, budget));
                if (++running > peak) peak = running;
                var fixture = new ObservationStorageTests.Fixture(Arg(info, "--output"));
                fixture.Open();
                fixture.Add("overwatch-decoder.private.combined-status/1");
                if (mode is not ("unavailable" or "wall" or "log") || window > 1)
                {
                    AddEntities(fixture, 1, Array.Empty<object>());
                    AddEntities(fixture, 2, new[] { new { position = (double[]?)null } });
                    if (mode != "no-position" || window > 1)
                        AddEntities(fixture, 3, new[] { new { position = new[] { 1.0, 2.0, 3.0 } } });
                }
                if (mode == "log")
                {
                    using var oversized = File.Create(log);
                    oversized.SetLength(32 * MiB + 1);
                }
                if (mode == "window-budget")
                {
                    using var oversized = File.Create(Path.Combine(fixture.Root, "oversized.bin"));
                    oversized.SetLength(budget + 1);
                }
                bool unavailable = mode == "unavailable" && window == 1;
                int code = unavailable ? 7 : mode == "hard-error" && window == 2 ? 4 : 0;
                int lifetime = mode is "wall" or "log" or "window-budget" ? int.MaxValue
                    : window == 2 && mode is "out-of-order" or "hard-error" ? 3 : 20;
                return new Child(() => now - start >= lifetime, code, () =>
                {
                    closes++; running--;
                    if (mode == "cleanup-fault" && window == 1) throw new IOException("Synthetic cleanup failure.");
                    if (now - start < lifetime || code == 4) return;
                    fixture.Seal();
                    var result = JsonNode.Parse(fixture.Result().GetRawText())!;
                    result["capture_scope"] = Gameplay;
                    if (unavailable)
                    {
                        result["cli_exit_code"] = 7; result["status"] = "partial";
                        result["source_unavailable"] = true; result["source_stop_reason"] = "acquisition_retry_limit";
                    }
                    File.WriteAllText(Path.Combine(fixture.Root, "result.json"), result.ToJsonString());
                });
            },
            (delay, token) => { token.ThrowIfCancellationRequested(); int seconds = (int)delay.TotalSeconds;
                pauses.Add(seconds); now += seconds; return Task.CompletedTask; },
            () => origin + now * Stopwatch.Frequency,
            (_, token) => { token.ThrowIfCancellationRequested(); now++; return Task.CompletedTask; });
        capture.Start(cancellation.Token);
        await capture.Completion!.WaitAsync(TimeSpan.FromSeconds(10));
        var summary = JsonSerializer.SerializeToElement(capture.Summary);
        return new RunResult(count, closes, peak, starts.ToArray(), pauses.ToArray(), events.ToArray(), summary,
            summary.GetProperty("accepted_window_numbers").EnumerateArray().Select(x => x.GetInt32()).ToArray(),
            events.Where(row => Kind(row) == "observation_window_gap").Select(Window).ToArray(), capture.Error);
    }

    private static void AddEntities(ObservationStorageTests.Fixture fixture, int sequence, object entities)
    {
        byte[] data = ObservationStorageTests.Fixture.Line(new { schema = "overwatch-decoder.private.selected-compact/1",
            combined_sequence = sequence, capture_scope = Gameplay, entities });
        using (var stream = new FileStream(fixture.DataPath, FileMode.Append)) stream.Write(data);
        fixture.RecordReceipt(data);
    }

    private static string? Kind(JsonElement row) => row.GetProperty("kind").GetString();
    private static int Window(JsonElement row) => row.GetProperty("window").GetInt32();
    private static bool IsStart(JsonElement row) => Kind(row) == "observation_window_start";
    private static string Arg(ProcessStartInfo info, string name) => info.ArgumentList[info.ArgumentList.IndexOf(name) + 1];

    private sealed record RunResult(int Launches, int Closes, int Peak, (int Time, long Budget)[] Starts, int[] Pauses,
        JsonElement[] Journal, JsonElement Summary, int[] Accepted, int[] Gaps, string? Error);

    private sealed class Child(Func<bool> exited, int code, Action close) : IRosterChild
    {
        public bool HasExited => exited();
        public int ExitCode => code;
        public void Dispose() => close();
    }
}
