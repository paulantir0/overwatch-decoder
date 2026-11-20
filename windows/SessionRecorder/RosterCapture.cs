using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.SessionRecorder;

public sealed class RosterPlan
{
    public string PythonDirectory { get; set; } = "";
    public string PythonExecutable { get; set; } = "python.exe";
    public string PythonInventorySha256 { get; set; } = "";
    public string BundleDirectory { get; set; } = "";
    public string BundleInventorySha256 { get; set; } = "";
    public string Entrypoint { get; set; } = "tools/entity-decoder/bootstrap_raw_roster.py";
    public string EntrypointSha256 { get; set; } = "";
    public string Config { get; set; } = "bootstrap-config.json";
    public int SliceSeconds { get; set; } = 60;
    public int MaximumSlices { get; set; } = 1;
    public int MaximumConsecutiveFailures { get; set; } = 3;
    public int RetryDelaySeconds { get; set; } = 5;
    public int IntervalMs { get; set; } = 50;
    public int MaximumOutputMiB { get; set; } = 4096;
}

/// <summary>Optional finite, private research JSON slices. Never infers continuity or field semantics.</summary>
public sealed class RosterCapture
{
    internal const int SliceWallSeconds = 330;
    private readonly RosterPlan plan;
    private readonly string package, directory;
    private readonly int pid;
    private readonly long creationFileTime;
    private readonly Func<bool> targetAlive;
    private readonly Action<object> emit;
    private readonly Func<ProcessStartInfo, string, IRosterChild> launch;
    private readonly int pollMs, wallMs;
    private volatile string state = "Configured";
    private int slices, attemptedSlices, incompleteSlices, started;
    private long outputBytes, outputMeasuredQpc, finalizedWindows, lastStorageCheck;
    public string State => state;
    public string? Error { get; private set; }
    public Task? Completion { get; private set; }
    public int Slices => Volatile.Read(ref slices);
    public int AttemptedSlices => Volatile.Read(ref attemptedSlices);
    public int IncompleteSlices => Volatile.Read(ref incompleteSlices);
    public long FinalizedWindows => Interlocked.Read(ref finalizedWindows);
    public long OutputBytes => Interlocked.Read(ref outputBytes);
    public object Summary => new { schema = "overwatch-decoder.capture-roster/1", state, error = Error, slices = Slices,
        directory = "roster", attempted_slices = AttemptedSlices, output_bytes = OutputBytes, output_bytes_measured_qpc = Interlocked.Read(ref outputMeasuredQpc), incomplete_slices = IncompleteSlices, finalized_windows = FinalizedWindows, target_pid = pid, target_creation_file_time = creationFileTime,
        maximum_slices = plan.MaximumSlices, slice_seconds = plan.SliceSeconds, interval_ms = plan.IntervalMs,
        maximum_consecutive_failures = plan.MaximumConsecutiveFailures, retry_delay_seconds = plan.RetryDelaySeconds,
        maximum_output_bytes = (long)plan.MaximumOutputMiB * 1024 * 1024, slice_wall_seconds = SliceWallSeconds,
        continuity_across_slices = false, visibility = "unknown", public_state_eligible = false,
        note = "Independent research slices retain native timestamps and evidence. Gaps and incomplete tails are unknown." };

    public RosterCapture(int pid, long targetStartUtcTicks, RosterPlan plan, string package, string directory,
        Func<bool> targetAlive, Action<object> emit) : this(pid, targetStartUtcTicks, plan, package, directory,
            targetAlive, emit, WindowsRosterChild.Start, 250) { }

    internal RosterCapture(int pid, long targetStartUtcTicks, RosterPlan plan, string package, string directory,
        Func<bool> targetAlive, Action<object> emit, Func<ProcessStartInfo, string, IRosterChild> launch, int pollMs, int wallMs = SliceWallSeconds * 1000)
    {
        this.pid = pid; creationFileTime = new DateTime(targetStartUtcTicks, DateTimeKind.Utc).ToFileTimeUtc();
        this.plan = plan; this.package = Path.GetFullPath(package); this.directory = Path.GetFullPath(directory);
        this.targetAlive = targetAlive; this.emit = emit; this.launch = launch; this.pollMs = pollMs; this.wallMs = wallMs;
    }

    public void Start(CancellationToken token)
    {
        if (Interlocked.Exchange(ref started, 1) != 0) throw new InvalidOperationException("Roster capture is single use.");
        Completion = Task.Run(() => RunAsync(token));
    }

    internal static void Validate(string package, RosterPlan plan)
    {
        if (plan.SliceSeconds is < 15 or > 120 || plan.MaximumSlices is < 1 or > 64 || plan.IntervalMs is < 20 or > 1000
            || plan.MaximumConsecutiveFailures is < 1 or > 8 || plan.RetryDelaySeconds is < 1 or > 30
            || plan.MaximumOutputMiB is < 128 or > 8192) throw new InvalidDataException("Invalid roster capture bounds.");
        var python = Inventory(package, plan.PythonDirectory, plan.PythonInventorySha256);
        _ = Asset(python.Root, python.Files, plan.PythonExecutable);
        var bundle = Inventory(package, plan.BundleDirectory, plan.BundleInventorySha256);
        string entry = Asset(bundle.Root, bundle.Files, plan.Entrypoint);
        if (!plan.Entrypoint.EndsWith(".py", StringComparison.Ordinal) || Hash(entry) != plan.EntrypointSha256)
            throw new InvalidDataException("Roster entrypoint pin mismatch.");
        _ = Asset(bundle.Root, bundle.Files, plan.Config);
    }

    private async Task RunAsync(CancellationToken token)
    {
        bool ownsDirectory = false;
        try
        {
            token.ThrowIfCancellationRequested(); Validate(package, plan);
            if (Directory.Exists(directory)) throw new IOException("New roster output directory required.");
            Directory.CreateDirectory(directory); ownsDirectory = true; Save(Path.Combine(directory, "status.json"), Summary);
            int consecutiveFailures = 0;
            for (int n = 1; n <= plan.MaximumSlices; n++)
            {
                token.ThrowIfCancellationRequested(); RequireTarget(); CheckOutput();
                state = "Preparing JSON slice";
                string slice = Path.Combine(directory, $"slice-{n:D4}"); Directory.CreateDirectory(slice);
                var python = Inventory(package, plan.PythonDirectory, plan.PythonInventorySha256);
                var bundle = Inventory(package, plan.BundleDirectory, plan.BundleInventorySha256);
                long copyBytes = python.Files.Values.Sum(p => p.Bytes) + bundle.Files.Values.Sum(p => p.Bytes)
                    + new FileInfo(python.InventoryPath).Length + new FileInfo(bundle.InventoryPath).Length;
                if (copyBytes > (long)plan.MaximumOutputMiB * 1024 * 1024 - OutputBytes)
                    throw new IOException("Roster output limit leaves no room for pinned input copies.");
                // Execute fresh copies: imported bytecode and output never alter the pinned master package.
                string pyCopy = Path.Combine(slice, "python"), input = Path.Combine(slice, "input");
                Copy(python, pyCopy, token); Copy(bundle, input, token); CheckOutput(); RequireTarget(); token.ThrowIfCancellationRequested();
                string output = Path.Combine(slice, "output"); long before = Stopwatch.GetTimestamp();
                var command = CreateStartInfo(Path.Combine(pyCopy, plan.PythonExecutable), input, output, pid, creationFileTime, plan);
                long sliceWindows = 0;
                string log = Path.Combine(slice, "bootstrap.log"); bool closed = false; int? exit = null; string reason = "failed";
                Interlocked.Increment(ref attemptedSlices);
                emit(new { kind = "roster_slice_start", slice = n, qpc_ticks = before, qpc_frequency = Stopwatch.Frequency,
                    target_pid = pid, target_creation_file_time = creationFileTime, previous_values_carried = false,
                    source_gap_before = true, path = $"roster/slice-{n:D4}/output/recording/compact-roster.jsonl" });
                IRosterChild? child = null;
                try
                {
                    child = launch(command, log); state = "Collecting JSON slice (unverified)";
                    while (!child.HasExited)
                    {
                        token.ThrowIfCancellationRequested(); RequireTarget(); CheckOutput(false);
                        CheckSliceBounds(before, log);
                        await Task.Delay(pollMs, token).ConfigureAwait(false);
                    }
                    exit = child.ExitCode;
                    token.ThrowIfCancellationRequested(); RequireTarget(); CheckOutput(); CheckSliceBounds(before, log);
                    reason = exit != 0 ? "bootstrap_failed" : "bootstrap_exited";
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { reason = "recording_stopped_partial_slice"; throw; }
                finally
                {
                    Exception? cleanupError = null, resultError = null;
                    if (child is not null)
                    {
                        try { child.Dispose(); closed = true; }
                        catch (Exception error) { cleanupError = error; reason = "owned_cleanup_failed"; }
                        state = "Finalizing JSON slice";
                    }
                    if (closed && reason is "bootstrap_exited" or "bootstrap_failed")
                    {
                        try
                        {
                            // Descendants may write after the root exits; assess final files only after owned cleanup.
                            token.ThrowIfCancellationRequested(); RequireTarget(); CheckOutput(); CheckSliceBounds(before, log);
                            if (reason == "bootstrap_exited")
                            {
                                sliceWindows = VerifyResult(output, pid, creationFileTime, plan.BundleInventorySha256);
                                reason = "finite_slice_finished";
                            }
                        }
                        catch (Exception error)
                        {
                            resultError = error;
                            reason = error is OperationCanceledException && token.IsCancellationRequested
                                ? "recording_stopped_partial_slice" : "result_verification_failed";
                        }
                    }
                    var receipt = new { schema = "overwatch-decoder.capture-roster-slice/1", slice = n, start_qpc = before,
                        end_qpc = Stopwatch.GetTimestamp(), qpc_frequency = Stopwatch.Frequency, reason, exit_code = exit,
                        owned_job_closed = closed, finalized_windows = sliceWindows, complete = reason == "finite_slice_finished" && closed,
                        target_pid = pid, target_creation_file_time = creationFileTime,
                        plan.BundleInventorySha256, plan.PythonInventorySha256, plan.EntrypointSha256,
                        continuity_across_slices = false, previous_values_carried = false, visibility = "unknown", public_state_eligible = false };
                    if (!receipt.complete) Interlocked.Increment(ref incompleteSlices);
                    Save(Path.Combine(slice, "slice.json"), receipt); emit(new { kind = "roster_slice_end", receipt });
                    if (cleanupError is not null) throw new IOException("Roster owned cleanup failed.", cleanupError);
                    if (resultError is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(resultError);
                }
                if (reason == "bootstrap_failed")
                {
                    consecutiveFailures++;
                    if (n == plan.MaximumSlices || consecutiveFailures >= plan.MaximumConsecutiveFailures)
                        throw new IOException($"Roster bootstrap failed (exit {exit}); slice or consecutive-failure limit reached. Inspect the preserved slice receipts.");
                    // Only a terminated child with successful owned-job cleanup reaches this branch.
                    // The next iteration rechecks the original target and copies pinned inputs for a fresh census.
                    state = "Waiting to retry JSON (unknown gap)";
                    Save(Path.Combine(directory, "status.json"), Summary);
                    emit(new { kind = "roster_slice_retry", failed_slice = n, next_slice = n + 1,
                        qpc_ticks = Stopwatch.GetTimestamp(), qpc_frequency = Stopwatch.Frequency,
                        exit_code = exit, consecutive_failures = consecutiveFailures, delay_seconds = plan.RetryDelaySeconds,
                        fresh_census_required = true, previous_values_carried = false, source_gap_before = true });
                    await Task.Delay(TimeSpan.FromSeconds(plan.RetryDelaySeconds), token).ConfigureAwait(false);
                    continue;
                }
                consecutiveFailures = 0;
                Interlocked.Increment(ref slices); Interlocked.Add(ref finalizedWindows, sliceWindows);
                state = "Between JSON slices (unknown gap)"; Save(Path.Combine(directory, "status.json"), Summary);
            }
            state = "JSON slice limit reached";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { state = "Stopped (tail may be partial)"; }
        catch (Exception error) { Error = error.Message; state = "JSON unavailable"; emit(new { kind = "roster_error", qpc_ticks = Stopwatch.GetTimestamp(), error = Error }); }
        finally
        {
            if (ownsDirectory)
            {
                try { CheckOutput(); }
                catch (Exception error) { Error ??= error.Message; state = "JSON unavailable"; }
                try { Save(Path.Combine(directory, "status.json"), Summary); }
                catch (Exception error) { Error ??= error.Message; state = "JSON unavailable"; }
            }
        }
    }

    private void RequireTarget() { if (!targetAlive()) throw new IOException("The selected original process lifetime ended."); }
    private void CheckSliceBounds(long start, string log)
    {
        if (Stopwatch.GetElapsedTime(start).TotalMilliseconds > wallMs) throw new TimeoutException("Roster slice wall deadline.");
        if (File.Exists(log) && new FileInfo(log).Length > 32L * 1024 * 1024) throw new IOException("Roster child log limit.");
    }
    private void CheckOutput(bool force = true)
    {
        long now = Stopwatch.GetTimestamp();
        if (!force && lastStorageCheck != 0 && Stopwatch.GetElapsedTime(lastStorageCheck, now).TotalSeconds < 1) return;
        lastStorageCheck = now;
        long bytes = 0; int files = 0;
        if (!Directory.Exists(directory)) return;
        foreach (string path in SafeFiles(directory, 262144, true))
        {
            long length;
            try { length = new FileInfo(path).Length; }
            catch (FileNotFoundException) { continue; } // Atomic status publication can replace a temporary file.
            bytes = checked(bytes + length);
            Interlocked.Exchange(ref outputBytes, bytes); Interlocked.Exchange(ref outputMeasuredQpc, Stopwatch.GetTimestamp());
            if (++files > 262144 || bytes > (long)plan.MaximumOutputMiB * 1024 * 1024) throw new IOException("Roster output limit reached.");
        }
    }
    private static IEnumerable<string> SafeFiles(string root, int maximum, bool transient = false)
    {
        var pending = new Stack<(string Path, int Depth)>(); pending.Push((root, 0)); int count = 0;
        while (pending.TryPop(out var current))
        {
            foreach (string path in Directory.EnumerateFileSystemEntries(current.Path))
            {
                FileAttributes attributes;
                try { attributes = File.GetAttributes(path); }
                catch (FileNotFoundException) when (transient) { continue; }
                if (++count > maximum || current.Depth >= 64 || (attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Roster file count, depth or link limit.");
                if ((attributes & FileAttributes.Directory) != 0) pending.Push((path, current.Depth + 1));
                else yield return path;
            }
        }
    }

    internal static ProcessStartInfo CreateStartInfo(string python, string bundle, string output, int pid, long creation, RosterPlan plan)
    {
        var command = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = bundle };
        foreach (string value in new[] { "-I", "-B", Path.Combine(bundle, plan.Entrypoint), "--bundle", bundle,
            "--inventory-sha256", plan.BundleInventorySha256, "--config", plan.Config, "--output", output,
            "--pid", pid.ToString(System.Globalization.CultureInfo.InvariantCulture), "--target-creation-file-time", creation.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--seconds", plan.SliceSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture), "--interval-ms", plan.IntervalMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--ready-timeout", "20", "--cleanup-seconds", "15" }) command.ArgumentList.Add(value);
        return command;
    }
    internal static long VerifyResult(string output, int pid, long creation, string inventoryPin)
    {
        using var status = JsonDocument.Parse(Read(Path.Combine(output, "bootstrap-status.json"), 1024 * 1024));
        var root = status.RootElement;
        if (root.GetProperty("schema").GetString() != "overwatch-decoder.raw-roster-bootstrap-result/1" || !root.GetProperty("complete").GetBoolean()
            || !root.GetProperty("owned_job_closed").GetBoolean() || root.GetProperty("error").ValueKind != JsonValueKind.Null
            || root.GetProperty("input_inventory_sha256").GetString() != inventoryPin) throw new InvalidDataException("Roster bootstrap completion was not verified.");
        using var worker = JsonDocument.Parse(Read(Path.Combine(output, "bootstrap-worker-status.json"), 1024 * 1024));
        var target = worker.RootElement.GetProperty("bootstrap").GetProperty("target");
        if (worker.RootElement.GetProperty("schema").GetString() != "overwatch-decoder.raw-roster-bootstrap-result/1"
            || worker.RootElement.GetProperty("stage").GetString() != "finished"
            || worker.RootElement.GetProperty("input_inventory_sha256").GetString() != inventoryPin
            || !worker.RootElement.GetProperty("complete").GetBoolean() || target.GetProperty("pid").GetInt32() != pid
            || target.GetProperty("creation_file_time").GetInt64() != creation
            || root.GetProperty("worker_status_sha256").GetString() != Hash(Path.Combine(output, "bootstrap-worker-status.json")))
            throw new InvalidDataException("Roster result process lifetime or worker pin mismatch.");
        string runtime = Path.Combine(output, "recording", "status.json");
        using var runtimeStatus = JsonDocument.Parse(Read(runtime, 1024 * 1024));
        if (worker.RootElement.GetProperty("runtime_status_sha256").GetString() != Hash(runtime)
            || !runtimeStatus.RootElement.GetProperty("complete").GetBoolean()
            || runtimeStatus.RootElement.GetProperty("error").ValueKind != JsonValueKind.Null)
            throw new InvalidDataException("Roster runtime completion pin mismatch.");
        using var aggregate = JsonDocument.Parse(Read(Path.Combine(output, "recording", "aggregate-result.json"), 4 * 1024 * 1024));
        var summary = aggregate.RootElement; long windows = summary.GetProperty("windows").GetInt64();
        string compact = Path.Combine(output, "recording", "compact-roster.jsonl");
        if (summary.GetProperty("schema").GetString() != "overwatch-decoder.local-roster-runtime-result/1"
            || windows is < 1 or > 1000000 || summary.GetProperty("transport_error").ValueKind != JsonValueKind.Null
            || !File.Exists(compact) || new FileInfo(compact).Length == 0
            || summary.GetProperty("compact_sha256").GetString() != Hash(compact))
            throw new InvalidDataException("No verified roster JSON windows were acquired.");
        return windows;
    }
    private static byte[] Read(string path, long maximum)
    { if (new FileInfo(path).Length > maximum) throw new InvalidDataException("Roster asset exceeds its bound."); return File.ReadAllBytes(path); }
    internal static string Hash(string path) { using var file = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    private static void Save(string path, object value)
    { string pending = path + ".partial"; File.WriteAllBytes(pending, JsonSerializer.SerializeToUtf8Bytes(value)); File.Move(pending, path, true); }
    private sealed record Pin(long Bytes, string Sha256);
    private sealed record Assets(string Root, string InventoryPath, Dictionary<string, Pin> Files);
    private static string Contained(string root, string name)
    {
        if (string.IsNullOrEmpty(name) || name.Contains('\\') || name.Contains(':') || Path.IsPathRooted(name)
            || name.Split('/').Any(p => p is "" or "." or "..")) throw new InvalidDataException("Roster paths must be simple relative paths.");
        string value = Path.GetFullPath(Path.Combine(root, name));
        if (!value.StartsWith(Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Roster asset escapes its package.");
        for (string? p = value; p is not null; p = Path.GetDirectoryName(p))
        { if ((File.Exists(p) || Directory.Exists(p)) && (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Roster links are forbidden."); if (p == Path.GetFullPath(root)) break; }
        return value;
    }
    private static string Asset(string root, Dictionary<string, Pin> files, string name)
    {
        string value = Contained(root, name);
        if (!files.TryGetValue(name, out var pin) || !File.Exists(value) || new FileInfo(value).Length != pin.Bytes || Hash(value) != pin.Sha256)
            throw new InvalidDataException("Roster asset pin mismatch.");
        return value;
    }
    private static Assets Inventory(string package, string name, string expected)
    {
        string root = Contained(Path.GetFullPath(package), name);
        string inventory = Contained(root, "inventory.json");
        if (expected.Length != 64 || expected.Any(c => !char.IsAsciiHexDigit(c) || char.IsAsciiLetterUpper(c)) || Hash(inventory) != expected)
            throw new InvalidDataException("Roster inventory pin mismatch.");
        using var doc = JsonDocument.Parse(Read(inventory, 4 * 1024 * 1024));
        var pins = new Dictionary<string, Pin>(StringComparer.Ordinal); long bytes = 0;
        foreach (var entry in doc.RootElement.EnumerateObject())
        {
            long length = entry.Value.GetProperty("bytes").GetInt64(); string sha = entry.Value.GetProperty("sha256").GetString() ?? "";
            if (length < 0 || sha.Length != 64 || !pins.TryAdd(entry.Name, new(length, sha)) || pins.Count > 4096 || (bytes = checked(bytes + length)) > 512L * 1024 * 1024)
                throw new InvalidDataException("Roster inventory bounds or duplicate path.");
            _ = Asset(root, pins, entry.Name);
        }
        if (pins.Count == 0) throw new InvalidDataException("Empty roster inventory.");
        var actual = SafeFiles(root, 16384).Select(p => Path.GetRelativePath(root, p).Replace('\\', '/')).ToHashSet(StringComparer.Ordinal);
        actual.Remove("inventory.json");
        if (!actual.SetEquals(pins.Keys)) throw new InvalidDataException("Uninventoried roster package file.");
        return new(root, inventory, pins);
    }
    private static void Copy(Assets source, string destination, CancellationToken token)
    {
        Directory.CreateDirectory(destination);
        foreach (string name in source.Files.Keys)
        {
            token.ThrowIfCancellationRequested(); string original = Asset(source.Root, source.Files, name), output = Contained(destination, name);
            Directory.CreateDirectory(Path.GetDirectoryName(output)!); File.Copy(original, output, false);
            if (Hash(output) != source.Files[name].Sha256) throw new IOException("Roster input copy changed.");
        }
        File.Copy(source.InventoryPath, Path.Combine(destination, "inventory.json"), false);
    }
}

internal interface IRosterChild : IDisposable { bool HasExited { get; } int ExitCode { get; } }

/// <summary>Suspended creation closes the launch-before-job-assignment race. The target is never enrolled.</summary>
internal sealed class WindowsRosterChild : IRosterChild
{
    private nint job, process;
    public bool HasExited => WaitForSingleObject(process, 0) == 0;
    public int ExitCode { get { if (!GetExitCodeProcess(process, out uint code)) throw new Win32Exception(); return checked((int)code); } }
    internal static IRosterChild Start(ProcessStartInfo command, string log)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Roster capture requires Windows.");
        var child = new WindowsRosterChild(); nint thread = 0, output = -1, input = -1;
        try
        {
            child.job = CreateJobObjectW(0, null); if (child.job == 0) throw new Win32Exception();
            var limits = new JobLimits(); limits.Basic.LimitFlags = 0x2000; // KILL_ON_JOB_CLOSE; no breakaway.
            if (!SetInformationJobObject(child.job, 9, ref limits, (uint)Marshal.SizeOf<JobLimits>())) throw new Win32Exception();
            var security = new Security { Length = Marshal.SizeOf<Security>(), Inherit = 1 };
            output = CreateFileW(log, 0x40000000, 1, ref security, 1, 0x80, 0); input = CreateFileW("NUL", 0x80000000, 1, ref security, 3, 0x80, 0);
            if (output == -1 || input == -1) throw new Win32Exception();
            var startup = new Startup { Size = Marshal.SizeOf<Startup>(), Flags = 0x100, Input = input, Output = output, Error = output };
            string text = Quote(command.FileName) + " " + string.Join(" ", command.ArgumentList.Select(Quote));
            if (!CreateProcessW(command.FileName, new StringBuilder(text), 0, 0, true, 0x08000004, 0, command.WorkingDirectory, ref startup, out var info)) throw new Win32Exception();
            child.process = info.Process; thread = info.Thread;
            if (!AssignProcessToJobObject(child.job, child.process))
            {
                // Assignment can fail under an incompatible host job. The suspended
                // owned root has not run and must not survive outside our job.
                int error = Marshal.GetLastWin32Error(); TerminateProcess(child.process, 1); throw new Win32Exception(error);
            }
            if (ResumeThread(thread) == uint.MaxValue) throw new Win32Exception();
            return child;
        }
        catch { child.Dispose(); throw; }
        finally { if (thread != 0) CloseHandle(thread); if (output != -1) CloseHandle(output); if (input != -1) CloseHandle(input); }
    }
    public void Dispose()
    {
        try
        {
            if (job != 0)
            {
                if (!TerminateJobObject(job, 1)) throw new Win32Exception();
                long start = Stopwatch.GetTimestamp();
                while (true)
                {
                    if (!QueryInformationJobObject(job, 1, out var accounting, (uint)Marshal.SizeOf<JobAccounting>(), 0)) throw new Win32Exception();
                    if (accounting.Active == 0) break;
                    if (Stopwatch.GetElapsedTime(start).TotalSeconds >= 5) throw new IOException("Roster owned job still has active descendants.");
                    Thread.Sleep(25);
                }
                if (process != 0 && WaitForSingleObject(process, 5000) != 0) throw new IOException("Roster owned child did not exit.");
            }
        }
        finally
        {
            if (job != 0) { CloseHandle(job); job = 0; }
            if (process != 0) { CloseHandle(process); process = 0; }
        }
    }
    internal static string Quote(string value)
    {
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); result.Append(c); slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }
    [StructLayout(LayoutKind.Sequential)] private struct Security { public int Length; public nint Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits { public long ProcessTime, JobTime; public uint LimitFlags; public nuint Minimum, Maximum; public uint Active; public nuint Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong A, B, C, D, E, F; }
    [StructLayout(LayoutKind.Sequential)] private struct JobAccounting { public long User, Kernel, PeriodUser, PeriodKernel; public uint Faults, Total, Active, Terminated; }
    [StructLayout(LayoutKind.Sequential)] private struct JobLimits { public BasicLimits Basic; public IoCounters Io; public nuint ProcessMemory, JobMemory, PeakProcess, PeakJob; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Startup { public int Size; public nint Reserved, Desktop, Title; public uint X, Y, Width, Height, XChars, YChars, Fill, Flags; public ushort Show, ReservedSize; public nint ReservedBytes, Input, Output, Error; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo { public nint Process, Thread; public uint Pid, Tid; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint CreateJobObjectW(nint security, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(nint job, int kind, ref JobLimits limits, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcessW(string application, StringBuilder command, nint processAttributes, nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, nint environment, string directory, ref Startup startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AssignProcessToJobObject(nint job, nint process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(nint thread);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateJobObject(nint job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryInformationJobObject(nint job, int kind, out JobAccounting accounting, uint size, nint returned);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateProcess(nint process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(nint handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(nint process, out uint exit);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(nint handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint CreateFileW(string name, uint access, uint sharing, ref Security security, uint creation, uint flags, nint template);
}
