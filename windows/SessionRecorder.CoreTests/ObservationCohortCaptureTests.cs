using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using OverwatchDecoder.SessionRecorder;

static class ObservationCohortCaptureTests
{
    public static async Task<int> Run(string root)
    {
        int checks = 0;
        void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
        void Reject(Action action)
        {
            try { action(); } catch (InvalidDataException) { checks++; return; }
            throw new Exception("Invalid observation storage plan accepted.");
        }
        string package = Path.Combine(root, "cohort-capture-package"), bundle = Path.Combine(package, "bundle");
        Directory.CreateDirectory(bundle);
        string runtime = Path.Combine(package, "python.exe"), entry = Path.Combine(bundle, "run.py");
        File.WriteAllText(runtime, "pinned fixture runtime; injected portable launcher");
        File.WriteAllText(entry, "pinned synthetic entry");
        void PinEntry() => File.WriteAllBytes(Path.Combine(bundle, "inventory.json"), JsonSerializer.SerializeToUtf8Bytes(new {
            files = new[] { new { path = "run.py", size = new FileInfo(entry).Length, sha256 = RosterCapture.Hash(entry) } } }));
        PinEntry();
        ObservationPlan Plan() => new() { PythonExecutable = "python.exe", PythonSha256 = RosterCapture.Hash(runtime),
            BundleDirectory = "bundle", InventorySha256 = RosterCapture.Hash(Path.Combine(bundle, "inventory.json")),
            Entrypoint = "run.py", StorageFormat = ObservationStorageFormat.CohortsV1, StorageCohortMiB = 1,
            MaximumWindows = 1, MaximumOutputMiB = 128 };
        Check(new ObservationPlan().StorageFormat == ObservationStorageFormat.FlatV1
            && new ObservationPlan().StorageCohortMiB == 16, "Storage stays opt-in with a finite default cohort size");
        var parsed = JsonSerializer.Deserialize<ObservationPlan>("{\"StorageFormat\":\"cohorts_v1\",\"StorageCohortMiB\":16}")!;
        Check(parsed.StorageFormat == ObservationStorageFormat.CohortsV1, "Explicit storage format parses");
        var plan = Plan(); ObservationCapture.Validate(package, plan); checks++;
        var command = ObservationCapture.Command(123, plan, package, "output with spaces");
        string[] args = command.ArgumentList.ToArray();
        Check(args.Contains("--storage-cohort-bytes") && args[Array.IndexOf(args, "--storage-cohort-bytes") + 1] == "1048576"
            && args[Array.IndexOf(args, "--maximum-total-bytes") + 1] == "134217728"
            && args.Contains("output with spaces") && !command.UseShellExecute, "Cohort byte limits are separate exact arguments");
        plan.StorageFormat = ObservationStorageFormat.FlatV1;
        Check(!ObservationCapture.Command(123, plan, package, "out").ArgumentList.Contains("--storage-cohort-bytes"), "Flat command has no storage flags");
        plan.WindowSeconds = 61; Reject(() => ObservationCapture.Validate(package, plan));
        plan.StorageFormat = ObservationStorageFormat.CohortsV1;
        foreach (int seconds in new[] { 20, 60, 61, 1800 }) { plan.WindowSeconds = seconds; ObservationCapture.Validate(package, plan); checks++; }
        plan.WindowSeconds = 1801; Reject(() => ObservationCapture.Validate(package, plan));
        plan.WindowSeconds = 19; Reject(() => ObservationCapture.Validate(package, plan)); plan.WindowSeconds = 20;
        plan.MaximumWindows = 2; Reject(() => ObservationCapture.Validate(package, plan)); plan.MaximumWindows = 1;
        foreach (int size in new[] { 0, 257 }) { plan.StorageCohortMiB = size; Reject(() => ObservationCapture.Validate(package, plan)); }
        plan.StorageCohortMiB = 256; ObservationCapture.Validate(package, plan); checks++;
        plan.MaximumOutputMiB = 65536;
        var maximumCommand = ObservationCapture.Command(123, plan, package, "out").ArgumentList.ToArray();
        Check(maximumCommand[Array.IndexOf(maximumCommand, "--maximum-total-bytes") + 1] == "68719476736",
            "Whole-directory maximum converts to bytes without 32-bit overflow");
        plan.StorageFormat = (ObservationStorageFormat)99; Reject(() => ObservationCapture.Validate(package, plan));
        Reject(() => ObservationCapture.Command(123, plan, package, "out"));

        // The root can exit before owned descendants finish. Verification must
        // happen after the launcher's cleanup, including a metadata-only drain.
        plan = Plan(); int disposed = 0; string? output = null; var events = new List<JsonElement>();
        var afterCleanup = new ObservationCapture(123, plan, package, Path.Combine(root, "cohorts-after-cleanup"), () => true,
            row => events.Add(JsonSerializer.SerializeToElement(row)), (info, _) => {
                output = Argument(info, "--output");
                return new Child(() => {
                    disposed++; var f = new ObservationStorageTests.Fixture(output);
                    for (int i = 0; i < 140; i++) { f.Open(); f.Add(); f.Seal(); }
                    File.WriteAllText(Path.Combine(output, "result.json"), f.Result().GetRawText());
                });
            });
        afterCleanup.Start(CancellationToken.None); await afterCleanup.Completion!;
        Check(afterCleanup.Error is null && !afterCleanup.HasGaps && disposed == 1, "Owned cleanup precedes final draining and verification");
        Check(events.Count(e => e.GetProperty("kind").GetString() == "observation_receipt") == 140
            && JsonSerializer.SerializeToElement(afterCleanup.Summary).GetProperty("sealed_storage_cohorts").GetInt32() == 140,
            "Final draining crosses more than one control-record poll without restarting a producer");
        Check(events.Where(e => e.GetProperty("kind").GetString() == "observation_receipt")
            .All(e => e.GetProperty("window").GetInt32() == 1 && !e.GetProperty("receipt").GetProperty("sealed_acceptance").GetBoolean()),
            "Existing receipt envelopes retain provisional storage paths within one window");
        Check(!JsonSerializer.Serialize(events).Contains("fixture_private_value"), "Cohort receipt events never duplicate source values");
        using (File.Open(Path.Combine(output!, "storage-index.jsonl"), FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { checks++; }

        var failedCleanup = new ObservationCapture(123, Plan(), package, Path.Combine(root, "cohorts-cleanup-fails"), () => true,
            _ => { }, (_, _) => new Child(() => throw new IOException("owned cleanup fixture failed")));
        failedCleanup.Start(CancellationToken.None); await failedCleanup.Completion!;
        Check(failedCleanup.HasGaps && failedCleanup.Error?.Contains("owned cleanup") == true, "Failed owned cleanup cannot accept a cohort result");

        foreach (int lead in new[] { 0, 8 })
        foreach (string mode in new[] { "build", "wrong-scope", "other-failure", "malformed", "oversized", "missing" })
        {
            var diagnosticPlan = Plan();
            diagnosticPlan.CaptureScope = ObservationScope.ReadOnlyUserGameplay;
            diagnosticPlan.ContinueObservationWindows = true;
            diagnosticPlan.MaximumWindows = 3;
            diagnosticPlan.MaximumOutputMiB = 256;
            diagnosticPlan.SuccessorLeadSeconds = lead;
            int closes = 0;
            var journal = new List<JsonElement>();
            var capture = new ObservationCapture(123, diagnosticPlan, package, Path.Combine(root, $"build-diagnostic-{lead}-{mode}"),
                () => true, value => journal.Add(JsonSerializer.SerializeToElement(value)),
                (info, _) => new Child(() =>
                {
                    closes++;
                    string output = Argument(info, "--output");
                    Directory.CreateDirectory(output);
                    string result = Path.Combine(output, "result.json");
                    if (mode == "missing") return;
                    if (mode is "malformed" or "oversized")
                    {
                        File.WriteAllText(result, mode == "malformed" ? "{" : new string(' ', 1048577));
                        return;
                    }
                    File.WriteAllBytes(result, JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        schema = "overwatch-decoder.private.combined-run/2",
                        capture_scope = mode == "wrong-scope" ? "controlled_practice" : "read_only_user_gameplay",
                        cli_exit_code = 1,
                        status = "failed",
                        cleanup_errors = Array.Empty<string>(),
                        error = mode == "other-failure" ? "ValueError('unrelated failure contains admission_build')" : "ValueError('admission_build')"
                    }));
                }, code: 1));
            capture.Start(CancellationToken.None);
            await capture.Completion!.WaitAsync(TimeSpan.FromSeconds(5));
            string expected = mode == "build"
                ? "The running game build differs from the observation package. Use a package verified for the installed game build."
                : "Observation producer exited with code 1";
            Check(capture.Error == expected && journal.Last().GetProperty("summary").GetProperty("error").GetString() == expected,
                "The UI error and terminal journal distinguish an exact build failure from other diagnostics: " + mode);
            Check(closes == 1 && capture.AttemptedWindows == 1 && capture.CompletedWindows == 0 && capture.HasGaps
                && !journal.Any(row => row.GetProperty("kind").GetString() == "observation_window_end"),
                "The diagnostic cannot accept or retry a failed observation window: " + mode);
        }

        foreach (string mode in new[] { "partial", "cancel", "target-exit", "corrupt-seal", "missing-seal", "wrong-scope", "wrong-result", "wrong-schema", "empty", "missing-result" })
        {
            using var cancellation = new CancellationTokenSource(); bool alive = true; int closes = 0;
            var capture = new ObservationCapture(123, Plan(), package, Path.Combine(root, "cohort-fixture-" + mode), () => alive,
                value => {
                    if (JsonSerializer.SerializeToElement(value).GetProperty("kind").GetString() != "observation_receipt") return;
                    if (mode == "cancel") cancellation.Cancel();
                    if (mode == "target-exit") alive = false;
                }, (info, _) => {
                    var fixture = new ObservationStorageTests.Fixture(Argument(info, "--output")); fixture.Open();
                    if (mode != "empty") fixture.Add();
                    if (mode is not ("cancel" or "target-exit" or "missing-seal")) fixture.Seal();
                    if (mode == "corrupt-seal")
                    {
                        string[] index = File.ReadAllLines(fixture.IndexPath); var seal = JsonNode.Parse(index[1])!;
                        seal["files"]![0]!["sha256"] = new string('0', 64); index[1] = seal.ToJsonString();
                        File.WriteAllLines(fixture.IndexPath, index);
                    }
                    var result = JsonNode.Parse(fixture.Result().GetRawText())!;
                    if (mode == "partial") { result["cli_exit_code"] = 7; result["status"] = "partial"; }
                    if (mode == "wrong-scope") result["capture_scope"] = "read_only_user_gameplay";
                    if (mode == "wrong-result") result["output_rows"] = 99;
                    if (mode == "wrong-schema") result["schema"] = "overwatch-decoder.private.combined-run/1";
                    if (mode != "missing-result") File.WriteAllText(Path.Combine(fixture.Root, "result.json"), result.ToJsonString());
                    return new Child(() => closes++, mode is not ("cancel" or "target-exit"), mode == "partial" ? 7 : 0);
                });
            capture.Start(cancellation.Token); await capture.Completion!.WaitAsync(TimeSpan.FromSeconds(5));
            Check(closes == 1 && capture.HasGaps, "Every partial/failed cohort producer closes exactly once: " + mode);
            var summary = JsonSerializer.SerializeToElement(capture.Summary);
            Check(summary.GetProperty("completed_windows").GetInt32() == (mode == "partial" ? 1 : 0), "Only verified partial results finalize a window: " + mode);
            Check((capture.Error is null) == (mode is "partial" or "cancel"), "Failure reason survives finalization: " + mode);
            if (mode == "empty") Check(capture.Error!.Contains("no compact rows"), "No-row failure is not a seal or result failure");
        }

        // A finished source-unavailable window is a gap. A later window can attach
        // on the same target lifetime, and cancellation keeps its accepted predecessor.
        foreach (string mode in new[] { "menu-recover-stop", "unobserved-recover-stop", "finish-chunk", "target-exit", "invalid-source-stop" })
        {
            plan = Plan();
            plan.ContinueObservationWindows = true;
            plan.MaximumWindows = 3;
            plan.MaximumOutputMiB = 256;
            Reject(() => ObservationCapture.Validate(package, plan));
            plan.CaptureScope = ObservationScope.ReadOnlyUserGameplay;
            ObservationCapture.Validate(package, plan);
            using var cancellation = new CancellationTokenSource();
            bool alive = true;
            int launches = 0, closes = 0;
            var budgets = new List<long>();
            var pauses = new List<TimeSpan>();
            var history = new List<JsonElement>();
            ObservationCapture? rolling = null;
            rolling = new ObservationCapture(123, plan, package, Path.Combine(root, "rolling-" + mode), () => alive,
                value =>
                {
                    var row = JsonSerializer.SerializeToElement(value);
                    history.Add(row);
                    if (row.GetProperty("kind").GetString() == "observation_receipt" && row.GetProperty("window").GetInt32() == 3)
                        cancellation.Cancel();
                    if (mode == "finish-chunk" && row.GetProperty("kind").GetString() == "observation_receipt" && row.GetProperty("window").GetInt32() == 2)
                        rolling!.RequestFinishAfterWindow();
                    if (mode == "target-exit" && row.GetProperty("kind").GetString() == "observation_window_gap")
                        alive = false;
                },
                (info, log) =>
                {
                    int window = ++launches;
                    Check(info.ArgumentList.Contains("--read-only-user-gameplay") && Argument(info, "--pid") == "123", "Each bounded window uses the selected scope and target");
                    budgets.Add(long.Parse(Argument(info, "--maximum-total-bytes")));
                    File.WriteAllText(log, "Owned producer fixture log");
                    var fixture = new ObservationStorageTests.Fixture(Argument(info, "--output"));
                    fixture.Open(); fixture.Add();
                    if (window != 3)
                    {
                        fixture.Seal();
                        var result = JsonNode.Parse(fixture.Result().GetRawText())!;
                        result["capture_scope"] = "read_only_user_gameplay";
                        if (window == 1)
                        {
                            result["cli_exit_code"] = 7; result["status"] = "partial";
                            result["source_unavailable"] = true;
                            result["source_stop_reason"] = mode switch
                            {
                                "invalid-source-stop" => "permission_denied",
                                "unobserved-recover-stop" => "fields_never_observed",
                                _ => "acquisition_retry_limit"
                            };
                        }
                        File.WriteAllText(Path.Combine(fixture.Root, "result.json"), result.ToJsonString());
                    }
                    return new Child(() => closes++, exited: window != 3, code: window == 1 ? 7 : 0);
                },
                (delay, token) => { token.ThrowIfCancellationRequested(); pauses.Add(delay); return Task.CompletedTask; });
            rolling.Start(cancellation.Token); await rolling.Completion!.WaitAsync(TimeSpan.FromSeconds(10));
            var summary = JsonSerializer.SerializeToElement(rolling.Summary);
            var accepted = summary.GetProperty("accepted_window_numbers").EnumerateArray().Select(x => x.GetInt32()).ToArray();
            Check(summary.GetProperty("repeat_windows").GetBoolean() && rolling.HasGaps && launches == closes,
                "Repeated capture retains explicit gaps and closes every owned child");
            if (mode is "menu-recover-stop" or "unobserved-recover-stop")
            {
                Check(launches == 3 && accepted.SequenceEqual(new[] { 2 }) && rolling.Error is null,
                    "Menu unavailability retries and user stop preserves only the verified window");
                Check(budgets[0] == 224 * 1048576L && budgets[1] < budgets[0] && budgets[2] < budgets[1],
                    "Remaining observation budget charges earlier windows and reserves the owned log");
                Check(pauses.SequenceEqual(new[] { TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(1) }),
                    "A source-unavailable window backs off longer than a successful window");
                Check(history.Where(x => x.GetProperty("kind").GetString() == "observation_window_gap")
                    .Select(x => x.GetProperty("reason").GetString()).SequenceEqual(new[] { "source_unavailable", "cancelled" }),
                    "Source loss and the interrupted active tail have distinct gap evidence");
                Check(history.Single(x => x.GetProperty("kind").GetString() == "observation_window_end")
                    .GetProperty("accepted").GetBoolean(), "Accepted window is journaled for replay");
            }
            else if (mode == "finish-chunk")
            {
                Check(launches == 2 && accepted.SequenceEqual(new[] { 2 }) && rolling.Error is null
                    && rolling.State == "Observation recording finished",
                    "Finish request accepts the active window and starts no successor");
                Check(history.Where(x => x.GetProperty("kind").GetString() == "observation_window_gap")
                    .Select(x => x.GetProperty("reason").GetString()).SequenceEqual(new[] { "source_unavailable" }),
                    "Graceful finish adds no cancellation gap to the sealed active window");
            }
            else Check(launches == 1 && accepted.Length == 0 && rolling.Error is not null,
                "Target lifetime end or an invalid source stop cannot launch another window");
        }

        // Optional saved-data repack: this exercises the full capture adapter and
        // byte-limited final draining, not only the standalone tail helper.
        if (Environment.GetEnvironmentVariable("OVERWATCH_DECODER_STORAGE_CAPTURE_FIXTURE") is { Length: > 0 } saved)
        {
            var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(saved, "result.json")))!;
            int cohorts = expected["storage_cohorts"]!.GetValue<int>();
            if (cohorts is < 1 or > 4096) throw new InvalidDataException("Fixture cohort bound.");
            var savedPlan = Plan(); savedPlan.StorageCohortMiB = 16;
            var capture = new ObservationCapture(123, savedPlan, package, Path.Combine(root, "saved-cohort-capture"), () => true,
                _ => { }, (info, _) => new Child(() => {
                    string target = Argument(info, "--output"); Directory.CreateDirectory(target);
                    foreach (string name in new[] { "storage-index.jsonl", "result.json" })
                        File.Copy(ObservationCapture.Contained(saved, name), Path.Combine(target, name));
                    for (int i = 1; i <= cohorts; i++)
                    {
                        string name = $"cohort-{i:D6}"; Directory.CreateDirectory(Path.Combine(target, name));
                        foreach (string file in new[] { "game-state.jsonl", "delivery-receipts.jsonl" })
                            File.Copy(ObservationCapture.Contained(saved, name + "/" + file), Path.Combine(target, name, file));
                    }
                }));
            capture.Start(CancellationToken.None); await capture.Completion!;
            Check(capture.Error is null && !capture.HasGaps, "Saved rotated original bytes pass the capture adapter");
            var summary = JsonSerializer.SerializeToElement(capture.Summary);
            Check(summary.GetProperty("receipt_rows").GetInt64() == expected["output_rows"]!.GetValue<long>()
                && summary.GetProperty("sealed_storage_cohorts").GetInt32() == cohorts, "Saved-data row and seal counts survive byte-limited drain");
        }

        // Optional cross-language process test uses only a supplied local Python.
        // Runtime substitution is confined to this injected test launcher; the
        // production command's pinned entry and every storage/scope argument run.
        string? python = Environment.GetEnvironmentVariable("OVERWATCH_DECODER_STORAGE_PRODUCER_PYTHON");
        if (!string.IsNullOrEmpty(python))
        {
            File.Copy(Path.Combine(AppContext.BaseDirectory, "Fixtures", "cohort_producer.py"), entry, true); PinEntry();
            foreach (string mode in new[] { "success", "partial", "cancel", "corrupt-seal", "missing-seal", "wrong-scope", "wrong-result", "wrong-schema", "empty", "missing-result", "exit-code", "directory-bound" })
            {
                plan = Plan(); if (mode == "success") plan.CaptureScope = ObservationScope.ReadOnlyUserGameplay;
                using var cancellation = new CancellationTokenSource();
                var received = new List<JsonElement>(); ProcessChild? child = null; string? produced = null; bool liveReceipt = false;
                var capture = new ObservationCapture(123, plan, package, Path.Combine(root, "cohort-process-" + mode), () => true,
                    value => {
                        var row = JsonSerializer.SerializeToElement(value); received.Add(row);
                        if (row.GetProperty("kind").GetString() != "observation_receipt") return;
                        if (!liveReceipt)
                        {
                            liveReceipt = true;
                            Check(row.GetProperty("receipt").GetProperty("source_path").GetString() == "cohort-000001/game-state.jsonl"
                                && !row.GetProperty("receipt").GetProperty("sealed_acceptance").GetBoolean(), "Live original-byte receipt precedes seal acceptance");
                            File.WriteAllText(Path.Combine(produced!, "receipt-seen"), "fixture acknowledgement");
                            if (mode == "cancel") cancellation.Cancel();
                        }
                    }, (info, _) => {
                        produced = Argument(info, "--output");
                        var actual = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = info.WorkingDirectory };
                        foreach (string item in info.ArgumentList) actual.ArgumentList.Add(item);
                        actual.ArgumentList.Add("--fixture-mode"); actual.ArgumentList.Add(mode);
                        return child = new ProcessChild(Process.Start(actual)!);
                    });
                capture.Start(cancellation.Token); await capture.Completion!.WaitAsync(TimeSpan.FromSeconds(20));
                Check(child is { Disposals: 1, Closed: true }, "Actual fixture process is deterministically closed: " + mode);
                var summary = JsonSerializer.SerializeToElement(capture.Summary);
                if (mode is "success" or "partial")
                {
                    Check(capture.Error is null && capture.HasGaps == (mode == "partial") && summary.GetProperty("completed_windows").GetInt32() == 1,
                        "Verified complete/partial producer result: " + mode);
                    Check(summary.GetProperty("receipt_rows").GetInt64() == 3301 && summary.GetProperty("sealed_storage_cohorts").GetInt32() == 4,
                        "Exit drains multiple row-limited polls and final seals: " + mode);
                    Check(received.Count(e => e.GetProperty("kind").GetString() == "observation_window_start") == 1,
                        "Rotation never restarts the producer");
                }
                else if (mode == "cancel") Check(capture.Error is null && capture.HasGaps && summary.GetProperty("completed_windows").GetInt32() == 0,
                    "Cancellation preserves an incomplete provisional tail");
                else Check(capture.Error is not null && capture.HasGaps && summary.GetProperty("completed_windows").GetInt32() == 0,
                    "Malformed/incomplete producer cannot be accepted: " + mode);
                Check(!JsonSerializer.Serialize(received).Contains("fixture_private_value"), "No raw source values reach journal: " + mode);
                using (File.Open(Path.Combine(produced!, "storage-index.jsonl"), FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { checks++; }
            }
        }
        return checks;
    }
    private static string Argument(ProcessStartInfo info, string flag)
    { var args = info.ArgumentList.ToArray(); return args[Array.IndexOf(args, flag) + 1]; }
    private sealed class Child(Action dispose, bool exited = true, int code = 0) : IRosterChild
    { public bool HasExited => exited; public int ExitCode => code; public void Dispose() => dispose(); }
    private sealed class ProcessChild(Process process) : IRosterChild
    {
        public bool HasExited => process.HasExited;
        public int ExitCode => process.ExitCode;
        public int Disposals { get; private set; }
        public bool Closed { get; private set; }
        public void Dispose()
        {
            Disposals++;
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); Closed = process.WaitForExit(5000); }
            finally { process.Dispose(); }
            if (!Closed) throw new IOException("Fixture process did not close.");
        }
    }
}
