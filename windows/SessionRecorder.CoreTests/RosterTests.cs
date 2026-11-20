using System.Diagnostics;
using System.Text.Json;
using OverwatchDecoder.SessionRecorder;

static class RosterTests
{
    public static async Task<int> Run(string root)
    {
        int checks = 0;
        void Check(bool ok, string message) { if (!ok) throw new Exception(message); checks++; }
        string package = Path.Combine(root, "roster-package"); Directory.CreateDirectory(package);
        string python = Path.Combine(package, "python"), bundle = Path.Combine(package, "bundle"); Directory.CreateDirectory(python); Directory.CreateDirectory(bundle);
        File.WriteAllText(Path.Combine(python, "python.exe"), "explicit synthetic runtime");
        File.WriteAllText(Path.Combine(bundle, "bootstrap.py"), "explicit synthetic entrypoint");
        File.WriteAllText(Path.Combine(bundle, "bootstrap-config.json"), "{}");
        string Inventory(string path)
        {
            var pins = Directory.GetFiles(path).Where(f => Path.GetFileName(f) != "inventory.json").ToDictionary(f => Path.GetFileName(f)!,
                f => new { bytes = new FileInfo(f).Length, sha256 = RosterCapture.Hash(f) });
            File.WriteAllBytes(Path.Combine(path, "inventory.json"), JsonSerializer.SerializeToUtf8Bytes(pins));
            return RosterCapture.Hash(Path.Combine(path, "inventory.json"));
        }
        var plan = new RosterPlan { PythonDirectory = "python", BundleDirectory = "bundle", Entrypoint = "bootstrap.py",
            EntrypointSha256 = RosterCapture.Hash(Path.Combine(bundle, "bootstrap.py")), PythonInventorySha256 = Inventory(python),
            BundleInventorySha256 = Inventory(bundle), MaximumSlices = 2, SliceSeconds = 15, MaximumOutputMiB = 128,
            MaximumConsecutiveFailures = 1, RetryDelaySeconds = 1 };
        RosterCapture.Validate(package, plan); checks++;
        Check(new CaptureSettings().Roster is null, "roster is disabled by default");
        var start = RosterCapture.CreateStartInfo("python path.exe", "bundle path", "output path", 17, 123456, plan);
        string[] args = start.ArgumentList.ToArray();
        Check(!start.UseShellExecute && args.Contains("--target-creation-file-time") && args.Contains("123456") && args.Contains("--pid") && args.Contains("17"), "original lifetime passed explicitly without shell");
        Check(args.Take(2).SequenceEqual(new[] { "-I", "-B" }) && args.Contains("--inventory-sha256") && args.Contains("--seconds"), "isolated finite pinned command");
        Check(WindowsRosterChild.Quote("") == "\"\"" && WindowsRosterChild.Quote("a\\") == "\"a\\\\\"" && WindowsRosterChild.Quote("a\"b") == "\"a\\\"b\"", "Windows argument quoting preserves quotes and trailing slash");
        long utc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks, creation = new DateTime(utc, DateTimeKind.Utc).ToFileTimeUtc();
        int launched = 0, closed = 0;
        string Argument(ProcessStartInfo command, string name) { var a = command.ArgumentList.ToArray(); return a[Array.IndexOf(a, name) + 1]; }
        void Result(ProcessStartInfo command, bool wrongTarget = false)
        {
            string output = Argument(command, "--output"); Directory.CreateDirectory(output);
            string worker = Path.Combine(output, "bootstrap-worker-status.json");
            string recording = Path.Combine(output, "recording"); Directory.CreateDirectory(recording);
            File.WriteAllText(Path.Combine(recording, "compact-roster.jsonl"), "{\"synthetic_fixture\":true}\n");
            File.WriteAllBytes(Path.Combine(recording, "status.json"), JsonSerializer.SerializeToUtf8Bytes(new { complete = true, error = (string?)null }));
            File.WriteAllBytes(Path.Combine(recording, "aggregate-result.json"), JsonSerializer.SerializeToUtf8Bytes(new {
                schema = "overwatch-decoder.local-roster-runtime-result/1", windows = 2, transport_error = (string?)null, compact_sha256 = RosterCapture.Hash(Path.Combine(recording, "compact-roster.jsonl")) }));
            File.WriteAllBytes(worker, JsonSerializer.SerializeToUtf8Bytes(new { schema = "overwatch-decoder.raw-roster-bootstrap-result/1", stage = "finished", input_inventory_sha256 = plan.BundleInventorySha256, runtime_status_sha256 = RosterCapture.Hash(Path.Combine(recording, "status.json")), complete = true, bootstrap = new { target = new { pid = wrongTarget ? 18 : 17, creation_file_time = creation } } }));
            File.WriteAllBytes(Path.Combine(output, "bootstrap-status.json"), JsonSerializer.SerializeToUtf8Bytes(new {
                schema = "overwatch-decoder.raw-roster-bootstrap-result/1", complete = true, error = (string?)null, input_inventory_sha256 = plan.BundleInventorySha256, owned_job_closed = true, worker_status_sha256 = RosterCapture.Hash(worker) }));
        }
        var events = new List<JsonElement>();
        var capture = new RosterCapture(17, utc, plan, package, Path.Combine(root, "roster-success"), () => true,
            e => events.Add(JsonSerializer.SerializeToElement(e)), (command, _) => {
                launched++; Result(command);
                Directory.CreateDirectory(Path.Combine(command.WorkingDirectory, "__pycache__"));
                File.WriteAllText(Path.Combine(command.WorkingDirectory, "__pycache__", "generated.pyc"), "owned slice only");
                return new Child(() => closed++, true); }, 1);
        capture.Start(CancellationToken.None); await capture.Completion!;
        Check(capture.Error is null && capture.Slices == 2 && capture.FinalizedWindows == 4 && launched == 2 && closed == 2, "two finite owned slices finish");
        Check(events.Count(e => e.GetProperty("kind").GetString() == "roster_slice_start") == 2 && events.Where(e => e.GetProperty("kind").GetString() == "roster_slice_start").All(e => e.GetProperty("source_gap_before").GetBoolean() && !e.GetProperty("previous_values_carried").GetBoolean()), "every slice announces unknown boundary without carry");
        Check(!Directory.Exists(Path.Combine(bundle, "__pycache__")), "executed copies cannot mutate master input package");
        try { capture.Start(CancellationToken.None); throw new Exception("duplicate roster start accepted"); } catch (InvalidOperationException) { checks++; }
        var summary = JsonSerializer.SerializeToElement(capture.Summary);
        Check(!summary.GetProperty("continuity_across_slices").GetBoolean() && !summary.GetProperty("public_state_eligible").GetBoolean(), "private noncontinuous output");
        Check(capture.AttemptedSlices == 2 && summary.GetProperty("attempted_slices").GetInt32() == 2, "attempts counted separately from complete slices");
        var retryPlan = JsonSerializer.Deserialize<RosterPlan>(JsonSerializer.Serialize(plan))!;
        retryPlan.MaximumConsecutiveFailures = 2;
        int retryLaunches = 0, retryCloses = 0;
        var retryEvents = new List<JsonElement>();
        var retryPaths = new List<string>();
        string retryDestination = Path.Combine(root, "roster-recovery");
        var recovered = new RosterCapture(17, utc, retryPlan, package, retryDestination, () => true,
            e => retryEvents.Add(JsonSerializer.SerializeToElement(e)), (command, _) => {
                retryLaunches++;
                Check(retryCloses == retryLaunches - 1, "previous owned job closes before recovery launch");
                Check(Argument(command, "--pid") == "17" && Argument(command, "--target-creation-file-time") == creation.ToString(), "recovery retains original process lifetime");
                Check(File.ReadAllText(Path.Combine(command.WorkingDirectory, "bootstrap.py")) == "explicit synthetic entrypoint", "recovery executes fresh pinned input copies");
                retryPaths.Add(Argument(command, "--output"));
                Result(command);
                if (retryLaunches == 1) File.AppendAllText(Path.Combine(command.WorkingDirectory, "bootstrap.py"), " first attempt only");
                return new Child(() => retryCloses++, true, retryLaunches == 1 ? 7 : 0);
            }, 1);
        recovered.Start(CancellationToken.None); await recovered.Completion!;
        Check(recovered.Error is null && recovered.AttemptedSlices == 2 && recovered.Slices == 1 && recovered.IncompleteSlices == 1
            && recovered.FinalizedWindows == 2 && retryCloses == 2, "failed child can recover without counting its result as verified output");
        Check(retryPaths.Distinct().Count() == 2 && retryPaths.All(Directory.Exists), "failed evidence is retained in separate output from recovery");
        var retryEvent = retryEvents.Single(e => e.GetProperty("kind").GetString() == "roster_slice_retry");
        Check(retryEvent.GetProperty("fresh_census_required").GetBoolean() && retryEvent.GetProperty("source_gap_before").GetBoolean()
            && !retryEvent.GetProperty("previous_values_carried").GetBoolean() && retryEvent.GetProperty("next_slice").GetInt32() == 2, "retry announces fresh census and explicit unknown gap");
        using (var failedReceipt = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(retryDestination, "slice-0001", "slice.json"))))
        {
            var value = failedReceipt.RootElement;
            Check(!value.GetProperty("complete").GetBoolean() && value.GetProperty("owned_job_closed").GetBoolean()
                && value.GetProperty("reason").GetString() == "bootstrap_failed" && value.GetProperty("exit_code").GetInt32() == 7
                && value.GetProperty("finalized_windows").GetInt32() == 0, "failed receipt never certifies even a superficially complete result");
        }
        foreach (bool reset in new[] { false, true })
        {
            var boundedPlan = JsonSerializer.Deserialize<RosterPlan>(JsonSerializer.Serialize(retryPlan))!;
            boundedPlan.MaximumSlices = 4;
            int tries = 0, disposals = 0;
            var bounded = new RosterCapture(17, utc, boundedPlan, package, Path.Combine(root, "roster-retry-bound-" + reset), () => true,
                _ => { }, (command, _) => {
                    tries++; bool success = reset && tries % 2 == 0;
                    if (success) Result(command);
                    return new Child(() => disposals++, true, success ? 0 : 7);
                }, 1);
            bounded.Start(CancellationToken.None); await bounded.Completion!;
            Check(reset ? bounded.Error is null && tries == 4 && bounded.Slices == 2 && bounded.FinalizedWindows == 4
                : bounded.Error is not null && bounded.Error.Contains("consecutive-failure limit") && tries == 2 && bounded.Slices == 0,
                reset ? "verified success resets consecutive failure count" : "consecutive failure bound stops retries before total slice limit");
            Check(disposals == tries && bounded.AttemptedSlices == tries && bounded.IncompleteSlices == 2, "all recovery attempts remain accounted and closed");
        }
        foreach (string mode in new[] { "cancel", "target", "input", "cleanup", "slice-limit" })
        {
            var interruptedPlan = JsonSerializer.Deserialize<RosterPlan>(JsonSerializer.Serialize(retryPlan))!;
            if (mode == "slice-limit") interruptedPlan.MaximumSlices = 1;
            bool alive = true; int tries = 0, disposals = 0, retries = 0;
            using var stop = new CancellationTokenSource();
            string original = File.ReadAllText(Path.Combine(bundle, "bootstrap.py"));
            var interrupted = new RosterCapture(17, utc, interruptedPlan, package, Path.Combine(root, "roster-retry-stop-" + mode), () => alive,
                e => {
                    var value = JsonSerializer.SerializeToElement(e);
                    if (value.GetProperty("kind").GetString() != "roster_slice_retry") return;
                    retries++;
                    if (mode == "cancel") stop.Cancel();
                    if (mode == "target") alive = false;
                    if (mode == "input") File.AppendAllText(Path.Combine(bundle, "bootstrap.py"), " changed during retry delay");
                }, (_, _) => {
                    tries++;
                    return new Child(() => { disposals++; if (mode == "cleanup") throw new IOException("owned cleanup failed"); }, true, 7);
                }, 1);
            try { interrupted.Start(stop.Token); await interrupted.Completion!; }
            finally { File.WriteAllText(Path.Combine(bundle, "bootstrap.py"), original); }
            Check(tries == 1 && disposals == 1 && interrupted.AttemptedSlices == 1 && interrupted.IncompleteSlices == 1,
                "recovery cannot bypass stop, target, input, cleanup or slice bounds:" + mode);
            Check(mode == "cancel" ? interrupted.Error is null : interrupted.Error is not null, "interrupted retry has accurate final status:" + mode);
            Check(retries == (mode is "cleanup" or "slice-limit" ? 0 : 1), "no retry scheduled after unsafe cleanup or exhausted slice budget:" + mode);
        }
        foreach (string mode in new[] { "cancel", "target", "exit", "wrongtarget", "wall", "output", "log", "exited-log", "exited-wall", "cleanup-log", "success-log", "cleanup-result", "cleanup", "zerojson", "wrongsource", "wrongcompact" })
        {
            bool alive = true; int disposal = 0; using var stop = new CancellationTokenSource();
            string destination = Path.Combine(root, "roster-" + mode);
            var terminalPlan = JsonSerializer.Deserialize<RosterPlan>(JsonSerializer.Serialize(plan))!;
            if (mode != "exit") terminalPlan.MaximumConsecutiveFailures = 3;
            var test = new RosterCapture(17, utc, terminalPlan, package, destination, () => alive, _ => { }, (command, log) => {
                if (mode == "cancel") stop.Cancel();
                if (mode == "target") alive = false;
                if (mode == "exited-wall") Thread.Sleep(20);
                if (mode == "wrongtarget") Result(command, true);
                if (mode is "cleanup" or "zerojson" or "wrongsource" or "wrongcompact" or "success-log" or "cleanup-result") Result(command);
                if (mode == "zerojson") File.WriteAllText(Path.Combine(Argument(command, "--output"), "recording", "aggregate-result.json"), "{\"schema\":\"overwatch-decoder.local-roster-runtime-result/1\",\"windows\":0}");
                if (mode == "wrongcompact") File.AppendAllText(Path.Combine(Argument(command, "--output"), "recording", "compact-roster.jsonl"), "changed");
                if (mode == "wrongsource")
                {
                    string status = Path.Combine(Argument(command, "--output"), "bootstrap-status.json");
                    File.WriteAllText(status, File.ReadAllText(status).Replace(plan.BundleInventorySha256, new string('0', 64)));
                }
                if (mode is "output" or "log" or "exited-log" or "success-log")
                {
                    using var f = File.Create(mode == "output" ? Path.Combine(destination, "oversized.bin") : log);
                    f.SetLength((mode == "output" ? 129L : 33L) * 1024 * 1024);
                }
                return new Child(() => {
                    disposal++;
                    if (mode == "cleanup") throw new IOException("synthetic owned cleanup error");
                    if (mode == "cleanup-log") { using var f = File.Create(log); f.SetLength(33L * 1024 * 1024); }
                    if (mode == "cleanup-result") File.AppendAllText(Path.Combine(Argument(command, "--output"), "recording", "compact-roster.jsonl"), "changed before cleanup finished");
                }, mode is "exit" or "exited-log" or "exited-wall" or "cleanup-log" or "success-log" or "cleanup-result" or "wrongtarget" or "cleanup" or "zerojson" or "wrongsource" or "wrongcompact",
                    mode is "exit" or "exited-log" or "exited-wall" or "cleanup-log" ? 9 : 0);
            }, 1, mode is "wall" or "exited-wall" ? 10 : 2000);
            test.Start(stop.Token); await test.Completion!;
            Check(disposal == 1 && test.Slices == 0 && test.IncompleteSlices == 1, "failure always owns disposal:" + mode);
            Check(mode == "cancel" ? test.Error is null : test.Error is not null, "failure/cancel status explicit:" + mode);
            if (mode is "wall" or "exited-wall") Check(test.Error!.Contains("wall deadline"), "wall deadline is the actual rejection");
            if (mode == "output") Check(test.Error!.Contains("output limit"), "size cap is the actual rejection");
            if (mode is "log" or "exited-log" or "cleanup-log" or "success-log") Check(test.Error!.Contains("log limit"), "log cap is the actual rejection");
            using var final = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(destination, "status.json")));
            Check(final.RootElement.GetProperty("state").GetString() == test.State && final.RootElement.GetProperty("output_bytes").GetInt64() == test.OutputBytes, "final stream state and measured bytes are published:" + mode);
            using var receipt = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(destination, "slice-0001", "slice.json")));
            Check(!receipt.RootElement.GetProperty("complete").GetBoolean() && receipt.RootElement.GetProperty("owned_job_closed").GetBoolean() == (mode != "cleanup"), "partial/failed slice never claimed complete:" + mode);
        }
        string existing = Path.Combine(root, "roster-existing"); Directory.CreateDirectory(existing);
        File.WriteAllText(Path.Combine(existing, "status.json"), "existing owned evidence");
        var collision = new RosterCapture(17, utc, plan, package, existing, () => true, _ => { }, (_, _) => throw new Exception("must not launch"), 1);
        collision.Start(CancellationToken.None); await collision.Completion!;
        Check(collision.Error is not null && File.ReadAllText(Path.Combine(existing, "status.json")) == "existing owned evidence", "existing output is rejected without overwrite");
        int forbidden = 0;
        var absent = new RosterCapture(17, utc, plan, package, Path.Combine(root, "roster-absent"), () => false, _ => { }, (_, _) => { forbidden++; throw new Exception(); }, 1);
        absent.Start(CancellationToken.None); await absent.Completion!; Check(forbidden == 0 && absent.Error is not null, "ended target prevents launch");
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel(); string destination = Path.Combine(root, "roster-pre-cancel");
            var test = new RosterCapture(17, utc, plan, package, destination, () => true, _ => { }, (_, _) => throw new Exception(), 1);
            test.Start(cancelled.Token); await test.Completion!; Check(!Directory.Exists(destination), "pre-cancel has no artifacts/children");
        }
        foreach (string mode in new[] { "entry", "inventory", "escape", "unlisted", "duration", "slices", "storage", "no-failures", "many-failures", "no-delay", "long-delay" })
        {
            var altered = JsonSerializer.Deserialize<RosterPlan>(JsonSerializer.Serialize(plan))!;
            if (mode == "entry") altered.EntrypointSha256 = new string('0', 64);
            if (mode == "inventory") altered.PythonInventorySha256 = new string('0', 64);
            if (mode == "escape") altered.Entrypoint = "../outside.py";
            if (mode == "unlisted") File.WriteAllText(Path.Combine(bundle, "unexpected.py"), "unapproved");
            if (mode == "duration") altered.SliceSeconds = 121;
            if (mode == "slices") altered.MaximumSlices = 65;
            if (mode == "storage") altered.MaximumOutputMiB = 8193;
            if (mode == "no-failures") altered.MaximumConsecutiveFailures = 0;
            if (mode == "many-failures") altered.MaximumConsecutiveFailures = 9;
            if (mode == "no-delay") altered.RetryDelaySeconds = 0;
            if (mode == "long-delay") altered.RetryDelaySeconds = 31;
            try { RosterCapture.Validate(package, altered); throw new Exception("invalid roster plan accepted:" + mode); }
            catch (InvalidDataException) { checks++; }
            if (mode == "unlisted") File.Delete(Path.Combine(bundle, "unexpected.py"));
        }
        File.AppendAllText(Path.Combine(bundle, "bootstrap.py"), "changed");
        try { RosterCapture.Validate(package, plan); throw new Exception("mutated bundle accepted"); } catch (InvalidDataException) { checks++; }
        return checks;
    }
    private sealed class Child(Action close, bool exited, int exit = 0) : IRosterChild
    { public bool HasExited => exited; public int ExitCode => exit; public void Dispose() => close(); }
}
