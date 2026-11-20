using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace OverwatchDecoder.SessionRecorder;

[JsonConverter(typeof(JsonStringEnumConverter<ObservationScope>))]
public enum ObservationScope
{
    [JsonStringEnumMemberName("controlled_practice")] ControlledPractice,
    [JsonStringEnumMemberName("read_only_user_gameplay")] ReadOnlyUserGameplay
}

[JsonConverter(typeof(JsonStringEnumConverter<ObservationStorageFormat>))]
public enum ObservationStorageFormat
{
    [JsonStringEnumMemberName("flat_v1")] FlatV1,
    [JsonStringEnumMemberName("cohorts_v1")] CohortsV1
}

/// <summary>A pinned private producer, owned by this recording. No decoder semantics live here.</summary>
public sealed class ObservationPlan
{
    public string PythonExecutable { get; set; } = "";
    public string PythonSha256 { get; set; } = "";
    public string BundleDirectory { get; set; } = "";
    public string InventorySha256 { get; set; } = "";
    public string Entrypoint { get; set; } = "run_combined.py";
    public ObservationScope CaptureScope { get; set; } = ObservationScope.ControlledPractice;
    public int WindowSeconds { get; set; } = 45;
    public int MaximumWindows { get; set; } = 1;
    public bool ContinueObservationWindows { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int SuccessorLeadSeconds { get; set; }
    public int MaximumOutputMiB { get; set; } = 4096;
    public ObservationStorageFormat StorageFormat { get; set; } = ObservationStorageFormat.FlatV1;
    public int StorageCohortMiB { get; set; } = 16;
}

public sealed class ObservationCapture
{
    private readonly ObservationPlan plan;
    private readonly string package, directory;
    private readonly int pid;
    private readonly Func<bool> targetAlive;
    private readonly Action<object> emit;
    private readonly Func<ProcessStartInfo, string, IRosterChild> launch;
    private readonly Func<TimeSpan, CancellationToken, Task> pauseBetweenWindows;
    private readonly Func<long> handoffTimestamp;
    private readonly Func<TimeSpan, CancellationToken, Task> handoffPoll;
    private const long MiB = 1048576;
    private const long LogLimit = 32 * MiB;
    private const long RepeatedWindowByteLimit = 4096 * MiB;
    private const string HandoffTimingBasis = "recorder_launch_qpc";
    private readonly ConcurrentQueue<int> acceptedWindows = new();
    private readonly object handoffLaunchGate = new();
    private readonly TaskCompletionSource finishAfterWindow = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int windows, started, attemptedWindows, incompleteWindows;
    private long rows, outputBytes;
    private int storageCohorts;
    private string state = "Configured";
    public string? Error { get; private set; }
    public Task? Completion { get; private set; }
    public string State => state;
    public bool HasGaps => incompleteWindows > 0;
    public int CompletedWindows => Volatile.Read(ref windows);
    public int AttemptedWindows => Volatile.Read(ref attemptedWindows);
    public long ReceiptRows => Interlocked.Read(ref rows);
    public string ScopeLabel => Label(plan.CaptureScope);
    public string ProgressLabel => $"{ScopeLabel}: {State} · {CompletedWindows}/{AttemptedWindows} verified windows · {ReceiptRows:N0} receipts";
    internal static string StorageValue(ObservationStorageFormat format) => format switch
    {
        ObservationStorageFormat.FlatV1 => "flat_v1",
        ObservationStorageFormat.CohortsV1 => "cohorts_v1",
        _ => throw new InvalidDataException("Unsupported observation storage format.")
    };
    internal static string ScopeValue(ObservationScope scope) => scope switch
    {
        ObservationScope.ControlledPractice => "controlled_practice",
        ObservationScope.ReadOnlyUserGameplay => "read_only_user_gameplay",
        _ => throw new InvalidDataException("Unsupported observation capture scope.")
    };
    public static string Label(ObservationScope scope) => scope switch
    {
        ObservationScope.ControlledPractice => "Controlled Practice Range",
        ObservationScope.ReadOnlyUserGameplay => "Read-only user gameplay (no game inputs)",
        _ => throw new InvalidDataException("Unsupported observation capture scope.")
    };
    public object Summary
    {
        get
        {
            var summary = new
            {
                schema = "overwatch-decoder.capture-observations/1", directory = "observations", state, error = Error,
                capture_scope = ScopeValue(plan.CaptureScope), game_input_control = false, completed_windows = windows,
                incomplete_windows = incompleteWindows, receipt_rows = rows, output_bytes = outputBytes, window_seconds = plan.WindowSeconds,
                maximum_windows = plan.MaximumWindows, repeat_windows = plan.ContinueObservationWindows, attempted_windows = AttemptedWindows,
                accepted_window_numbers = acceptedWindows.Order().ToArray(), maximum_output_bytes = plan.MaximumOutputMiB * MiB,
                maximum_window_output_bytes = plan.ContinueObservationWindows ? Math.Min(plan.MaximumOutputMiB * MiB, RepeatedWindowByteLimit) : plan.MaximumOutputMiB * MiB,
                storage_format = Enum.IsDefined(plan.StorageFormat) ? StorageValue(plan.StorageFormat) : "unknown",
                storage_cohort_mib = plan.StorageCohortMiB, sealed_storage_cohorts = storageCohorts,
                continuity_across_windows = false, whole_match_claim = false, all_current_roster_claim = false,
                public_state_eligible = false, visibility = "unknown",
                note = plan.ContinueObservationWindows
                    ? "Repeated finite producers on the selected target lifetime. Only verified windows are accepted. Gaps and incomplete tails remain unknown."
                    : plan.StorageFormat == ObservationStorageFormat.CohortsV1
                    ? "One finite producer with rotated storage. Live cohort receipts are provisional; final window acceptance verifies seals and result. Storage rotation does not establish acquisition continuity."
                    : "Independent bounded producer windows. Receipt timing is not source read timing. Raw source evidence stays in each window; events contain hashes and offsets only."
            };
            if (plan.SuccessorLeadSeconds == 0) return summary;
            var handoff = JsonSerializer.SerializeToNode(summary)!.AsObject();
            handoff["overlapping_windows"] = true;
            handoff["successor_lead_seconds"] = plan.SuccessorLeadSeconds;
            handoff["successor_timing_basis"] = HandoffTimingBasis;
            return handoff;
        }
    }

    public ObservationCapture(int pid, ObservationPlan plan, string package, string directory, Func<bool> targetAlive, Action<object> emit)
        : this(pid, plan, package, directory, targetAlive, emit, WindowsRosterChild.Start) { }
    internal ObservationCapture(int pid, ObservationPlan plan, string package, string directory, Func<bool> targetAlive,
        Action<object> emit, Func<ProcessStartInfo, string, IRosterChild> launch, Func<TimeSpan, CancellationToken, Task>? pauseBetweenWindows = null,
        Func<long>? handoffTimestamp = null, Func<TimeSpan, CancellationToken, Task>? handoffPoll = null)
    {
        this.pid = pid; this.plan = plan; this.package = package; this.directory = directory;
        this.targetAlive = targetAlive; this.emit = emit; this.launch = launch;
        this.pauseBetweenWindows = pauseBetweenWindows ?? Task.Delay;
        this.handoffTimestamp = handoffTimestamp ?? Stopwatch.GetTimestamp;
        this.handoffPoll = handoffPoll ?? Task.Delay;
    }

    private static bool Pin(string value) => value.Length == 64 && value.All(c => char.IsAsciiHexDigit(c) && !char.IsAsciiLetterUpper(c));
    private static string Hash(string path) { using var file = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    internal static string Contained(string package, string relative)
    {
        if (string.IsNullOrEmpty(relative) || relative.Contains('\\') || relative.Contains(':') || Path.IsPathRooted(relative) || relative.Split('/').Any(p => p is "" or "." or ".."))
            throw new InvalidDataException("Observation assets must have simple package-relative paths.");
        string root = Path.GetFullPath(package), result = Path.GetFullPath(Path.Combine(root, relative));
        if (!result.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Observation asset escapes package.");
        for (string? current = result; current is not null; current = Path.GetDirectoryName(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Observation package links are forbidden.");
            if (current == root) break;
        }
        return result;
    }
    internal static void Validate(string package, ObservationPlan plan)
    {
        _ = StorageValue(plan.StorageFormat);
        bool cohorts = plan.StorageFormat == ObservationStorageFormat.CohortsV1;
        if (plan.WindowSeconds < 20 || plan.WindowSeconds > (cohorts ? 1800 : 60)
            || plan.MaximumWindows is < 1 or > 240 || (cohorts && plan.MaximumWindows != 1 && !plan.ContinueObservationWindows)
            || (plan.ContinueObservationWindows && (!cohorts || plan.CaptureScope != ObservationScope.ReadOnlyUserGameplay
                || plan.WindowSeconds > 60 || plan.MaximumOutputMiB < 160))
            || plan.SuccessorLeadSeconds < 0 || plan.SuccessorLeadSeconds >= plan.WindowSeconds
            || (plan.SuccessorLeadSeconds > 0 && (!plan.ContinueObservationWindows || plan.MaximumWindows < 2))
            || plan.MaximumOutputMiB is < 128 or > 65536 || plan.StorageCohortMiB is < 1 or > 256)
            throw new InvalidDataException("Invalid observation capture bounds.");
        _ = ScopeValue(plan.CaptureScope);
        string python = Contained(package, plan.PythonExecutable), bundle = Contained(package, plan.BundleDirectory);
        if (!Pin(plan.PythonSha256) || Hash(python) != plan.PythonSha256) throw new InvalidDataException("Observation Python pin mismatch.");
        string inventory = Contained(bundle, "inventory.json");
        if (!Pin(plan.InventorySha256) || new FileInfo(inventory).Length > 4 * 1048576 || Hash(inventory) != plan.InventorySha256) throw new InvalidDataException("Observation inventory pin mismatch.");
        using var document = JsonDocument.Parse(File.ReadAllBytes(inventory));
        var seen = new HashSet<string>(StringComparer.Ordinal); long total = 0;
        foreach (var row in document.RootElement.GetProperty("files").EnumerateArray())
        {
            string name = row.GetProperty("path").GetString() ?? "", sha = row.GetProperty("sha256").GetString() ?? "";
            long size = row.GetProperty("size").GetInt64();
            if (!seen.Add(name) || seen.Count > 4096 || size < 0 || !Pin(sha) || (total = checked(total + size)) > 1024L * 1048576) throw new InvalidDataException("Observation inventory bound.");
            string file = Contained(bundle, name);
            if (!File.Exists(file) || new FileInfo(file).Length != size || Hash(file) != sha) throw new InvalidDataException("Observation bundle asset pin mismatch.");
        }
        if (!seen.Contains(plan.Entrypoint) || !plan.Entrypoint.EndsWith(".py", StringComparison.Ordinal)) throw new InvalidDataException("Observation entrypoint is not pinned.");
    }
    internal static ProcessStartInfo Command(int pid, ObservationPlan plan, string package, string output, long? windowByteBudget = null)
    {
        _ = StorageValue(plan.StorageFormat);
        string bundle = Contained(package, plan.BundleDirectory);
        var command = new ProcessStartInfo(Contained(package, plan.PythonExecutable)) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = bundle };
        foreach (string argument in new[] { "-B", Contained(bundle, plan.Entrypoint), "--pid", pid.ToString(), "--seconds", plan.WindowSeconds.ToString(), plan.CaptureScope switch { ObservationScope.ControlledPractice => "--practice-range", ObservationScope.ReadOnlyUserGameplay => "--read-only-user-gameplay", _ => throw new InvalidDataException("Unsupported observation capture scope.") }, "--output", output }) command.ArgumentList.Add(argument);
        if (plan.StorageFormat == ObservationStorageFormat.CohortsV1)
        {
            command.ArgumentList.Add("--storage-cohort-bytes");
            command.ArgumentList.Add(((long)plan.StorageCohortMiB * 1048576).ToString(System.Globalization.CultureInfo.InvariantCulture));
            command.ArgumentList.Add("--maximum-total-bytes");
            command.ArgumentList.Add((windowByteBudget ?? plan.MaximumOutputMiB * MiB).ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        return command;
    }
    internal static void VerifyResult(string directory, long rows, int code, ObservationScope scope = ObservationScope.ControlledPractice)
    {
        string path = Path.Combine(directory, "result.json"), data = Path.Combine(directory, "game-state.jsonl");
        if (new FileInfo(path).Length > 1048576) throw new InvalidDataException("Observation result bound.");
        using var document = JsonDocument.Parse(File.ReadAllBytes(path)); var result = document.RootElement;
        bool hasScope = result.TryGetProperty("capture_scope", out var recordedScope);
        if ((hasScope && recordedScope.GetString() != ScopeValue(scope)) || (!hasScope && scope != ObservationScope.ControlledPractice))
            throw new InvalidDataException("Observation producer capture scope mismatch.");
        if (result.GetProperty("schema").GetString() != "overwatch-decoder.private.combined-run/1" || result.GetProperty("cli_exit_code").GetInt32() != code
            || result.GetProperty("status").GetString() != (code == 0 ? "complete" : "partial")
            || result.GetProperty("error").ValueKind != JsonValueKind.Null || result.GetProperty("cleanup_errors").GetArrayLength() != 0
            || result.GetProperty("output_rows").GetInt64() != rows || result.GetProperty("output_bytes").GetInt64() != new FileInfo(data).Length
            || result.GetProperty("output_sha256").GetString() != Hash(data)) throw new InvalidDataException("Observation result or compact digest mismatch.");
    }
    public void Start(CancellationToken token)
    {
        if (Interlocked.Exchange(ref started, 1) != 0) throw new InvalidOperationException("Observation capture is single use.");
        Completion = Task.Run(() => plan.SuccessorLeadSeconds == 0 ? RunAsync(token) : RunHandoffAsync(token));
    }
    /// <summary>Let active children seal their windows and prevent another launch.</summary>
    public void RequestFinishAfterWindow()
    {
        lock (handoffLaunchGate) finishAfterWindow.TrySetResult();
    }

    private bool FinishRequested()
    {
        if (!finishAfterWindow.Task.IsCompleted) return false;
        state = "Observation recording finished";
        return true;
    }

    private void Budget() => Interlocked.Exchange(ref outputBytes, MeasureDirectory(directory, (long)plan.MaximumOutputMiB * 1048576));
    internal static long MeasureDirectory(string directory, long maximumBytes, Action<string>? beforeMetadata = null)
    {
        for (int attempt = 0; ; attempt++)
        {
            try { return MeasureOnce(directory, maximumBytes, beforeMetadata); }
            catch (FileNotFoundException) when (attempt < 2) { }
            catch (DirectoryNotFoundException) when (attempt < 2) { }
        }
    }
    private static long MeasureOnce(string directory, long maximumBytes, Action<string>? beforeMetadata)
    {
        long bytes = 0; int count = 0;
        var pending = new Stack<string>(); pending.Push(directory);
        while (pending.TryPop(out string? folder))
        {
            foreach (string path in Directory.EnumerateFileSystemEntries(folder))
            {
                beforeMetadata?.Invoke(path);
                if (++count > 262144 || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Observation output entry bound or link.");
                if (Directory.Exists(path)) pending.Push(path);
                else
                {
                    long length = new FileInfo(path).Length;
                    if (path.EndsWith(".log", StringComparison.OrdinalIgnoreCase) && length > LogLimit) throw new IOException("Observation log byte bound.");
                    bytes = checked(bytes + length);
                }
                if (bytes > maximumBytes) throw new IOException("Observation output byte bound.");
            }
        }
        return bytes;
    }
    private void MarkWindowGap(int window, string reason, long? ticks = null)
    {
        incompleteWindows++;
        if (window != 0)
            emit(new { kind = "observation_window_gap", window, qpc_ticks = ticks ?? Stopwatch.GetTimestamp(), reason, continuity_to_next = false });
    }

    private IOException ProducerExitError(string output, int code)
    {
        var fallback = new IOException("Observation producer exited with code " + code);
        if (code != 1) return fallback;
        try
        {
            // Read only a bounded diagnostic after the owned job has closed.
            // A failed result cannot accept rows or change retry behavior.
            using var stream = File.OpenRead(Contained(output, "result.json"));
            long length = stream.Length;
            if (length is <= 0 or > MiB) return fallback;
            byte[] raw = new byte[(int)length];
            stream.ReadExactly(raw);
            if (stream.ReadByte() != -1) return fallback;
            using var document = JsonDocument.Parse(raw);
            var result = document.RootElement;
            string schema = plan.StorageFormat == ObservationStorageFormat.CohortsV1
                ? "overwatch-decoder.private.combined-run/2" : "overwatch-decoder.private.combined-run/1";
            if (result.GetProperty("schema").GetString() == schema
                && result.GetProperty("capture_scope").GetString() == ScopeValue(plan.CaptureScope)
                && result.GetProperty("cli_exit_code").TryGetInt32(out int reportedCode) && reportedCode == code
                && result.GetProperty("status").GetString() == "failed"
                && result.GetProperty("cleanup_errors").GetArrayLength() == 0
                && result.GetProperty("error").GetString() == "ValueError('admission_build')")
                return new IOException("The running game build differs from the observation package. Use a package verified for the installed game build.");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
            or JsonException or InvalidOperationException or KeyNotFoundException) { }
        return fallback;
    }

    private bool VerifyStorageWindow(string output, ObservationStorageTail storage, int code)
    {
        string result = Path.Combine(output, "result.json");
        if (new FileInfo(result).Length > MiB) throw new InvalidDataException("Observation result bound.");
        using var document = JsonDocument.Parse(File.ReadAllBytes(result));
        var metadata = document.RootElement;
        storage.VerifyResult(metadata, code, plan.CaptureScope);
        if (!plan.ContinueObservationWindows || !metadata.TryGetProperty("source_unavailable", out var flag)) return false;
        bool unavailable = flag.GetBoolean();
        if (unavailable && (code != 7 || !metadata.TryGetProperty("source_stop_reason", out var stopReason)
            || stopReason.GetString() is not ("acquisition_retry_limit" or "acquisition_attempt_limit" or "fields_never_observed")))
            throw new InvalidDataException("Invalid source-unavailable terminal result.");
        return unavailable;
    }

    private sealed class HandoffWindow(int number, string output, string log, long limit, long started, ObservationStorageTail tail)
    {
        internal readonly int Number = number;
        internal readonly string Output = output, Log = log;
        internal readonly long Limit = limit, Started = started;
        internal readonly ObservationStorageTail Tail = tail;
        internal IRosterChild? Child;
        internal bool SawPosition, StartedSuccessor;

        internal void CloseChild()
        {
            var child = Child;
            Child = null;
            child?.Dispose();
        }
    }

    // The tail's receipt identifies a bounded original line. Recheck its hash
    // before using a nonempty position as a launch hint. Only seals/results can
    // accept the window, and no values are copied to the recorder journal.
    private static bool HasPosition(string output, object receipt)
    {
        var reference = JsonSerializer.SerializeToElement(receipt);
        if (reference.GetProperty("source_schema").GetString() != "overwatch-decoder.private.selected-compact/1") return false;
        string path = Contained(output, reference.GetProperty("source_path").GetString()!);
        long offset = reference.GetProperty("source_offset").GetInt64();
        int size = reference.GetProperty("source_bytes").GetInt32();
        if (offset < 0 || size < 1 || size > 2 * MiB) throw new InvalidDataException("Observation readiness line bound.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        stream.Position = offset;
        var bytes = new byte[size];
        stream.ReadExactly(bytes);
        if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != reference.GetProperty("source_sha256").GetString())
            throw new InvalidDataException("Observation readiness source changed.");
        using var document = JsonDocument.Parse(bytes);
        var row = document.RootElement;
        return row.TryGetProperty("capture_scope", out var scope) && scope.GetString() == "read_only_user_gameplay"
            && row.TryGetProperty("entities", out var entities) && entities.ValueKind == JsonValueKind.Array
            && entities.EnumerateArray().Any(entity => entity.ValueKind == JsonValueKind.Object
                && entity.TryGetProperty("position", out var position) && position.ValueKind == JsonValueKind.Array
                && position.GetArrayLength() == 3 && position.EnumerateArray().All(axis =>
                    axis.ValueKind == JsonValueKind.Number && axis.TryGetDouble(out double value) && double.IsFinite(value)));
    }

    private async Task RunHandoffAsync(CancellationToken token)
    {
        var active = new List<HandoffWindow>(2);
        long closedBytes = 0, scan = handoffTimestamp();
        int closedCohorts = 0;
        bool createdDirectory = false;
        Task? nextLaunch = null;
        var leadAt = TimeSpan.FromSeconds(plan.WindowSeconds - plan.SuccessorLeadSeconds);
        var wallLimit = TimeSpan.FromSeconds(plan.WindowSeconds + 50);

        void RequireLive()
        {
            token.ThrowIfCancellationRequested();
            if (!targetAlive()) throw new IOException("Selected target lifetime ended.");
        }
        void CheckWindow(HandoffWindow window)
        {
            RequireLive();
            if (Stopwatch.GetElapsedTime(window.Started, handoffTimestamp()) > wallLimit)
                throw new IOException("Observation window wall limit.");
        }
        long WindowBytes(HandoffWindow window)
        {
            long logBytes = File.Exists(window.Log) ? new FileInfo(window.Log).Length : 0;
            if (logBytes > LogLimit) throw new IOException("Observation log byte bound.");
            return logBytes + (Directory.Exists(window.Output) ? MeasureDirectory(window.Output, window.Limit) : 0);
        }
        bool TryLaunch(HandoffWindow? predecessor)
        {
            long reserved = active.Sum(window => window.Limit + LogLimit);
            long limit = Math.Min(RepeatedWindowByteLimit, plan.MaximumOutputMiB * MiB - closedBytes - reserved - LogLimit);
            if (limit < 128 * MiB) return false;
            Validate(package, plan);
            lock (handoffLaunchGate)
            {
                RequireLive();
                if (finishAfterWindow.Task.IsCompleted || predecessor?.Child?.HasExited == true) return false;
                int number = AttemptedWindows + 1;
                string output = Path.Combine(directory, $"window-{number:D4}");
                string log = Path.Combine(directory, $"window-{number:D4}.log");
                long stamp = handoffTimestamp();
                var window = new HandoffWindow(number, output, log, limit, stamp, new ObservationStorageTail(
                    output, limit, maximumCohortBytes: plan.StorageCohortMiB * MiB, maximumIndexBytes: 64 * MiB));
                active.Add(window);
                Volatile.Write(ref attemptedWindows, number);
                try { window.Child = launch(Command(pid, plan, package, output, limit), log); }
                finally
                {
                    emit(new { kind = "observation_window_start", capture_scope = ScopeValue(plan.CaptureScope), window = number,
                        qpc_ticks = stamp, continuity_from_previous = false, launch_qpc_ticks = stamp, timing_basis = HandoffTimingBasis,
                        predecessor_window = predecessor?.Number });
                }
                if (predecessor is not null) predecessor.StartedSuccessor = true;
                state = "Recording observation window " + number;
                return true;
            }
        }
        void ReadTail(HandoffWindow window, bool lookForPosition)
        {
            foreach (var receipt in window.Tail.Read())
            {
                emit(new { kind = "observation_receipt", window = window.Number, qpc_ticks = handoffTimestamp(), receipt });
                Interlocked.Increment(ref rows);
                if (lookForPosition && !window.SawPosition) window.SawPosition = HasPosition(window.Output, receipt);
            }
            storageCohorts = closedCohorts + active.Sum(current => current.Tail.SealedCohorts);
        }
        void RecordFailure(Exception error)
        {
            if (Error is null) Error = error.Message;
            else if (Error != error.Message) Error += " | " + error.Message;
            state = "Failed; incomplete tail unknown";
        }
        string gapReason = "failed";
        try
        {
            RequireLive(); Validate(package, plan);
            if (Directory.Exists(directory)) throw new IOException("New observation directory required.");
            Directory.CreateDirectory(directory);
            createdDirectory = true;
            while (true)
            {
                RequireLive();
                if (active.Count == 0)
                {
                    if (FinishRequested()) return;
                    if (AttemptedWindows == plan.MaximumWindows)
                    {
                        Error = "Observation attempt limit reached.";
                        state = "Observation window limit reached";
                        return;
                    }
                    if (nextLaunch is not null)
                    {
                        if (await Task.WhenAny(nextLaunch, finishAfterWindow.Task) == nextLaunch) await nextLaunch;
                        nextLaunch = null;
                    }
                    if (!TryLaunch(null))
                    {
                        if (FinishRequested()) return;
                        Error = "Remaining observation budget is below the minimum window allowance.";
                        state = "Observation byte budget exhausted";
                        return;
                    }
                }
                foreach (var window in active.ToArray())
                {
                    CheckWindow(window);
                    bool exited = window.Child!.HasExited;
                    ReadTail(window, !exited && !window.StartedSuccessor && !finishAfterWindow.Task.IsCompleted);
                    if (!exited) continue;
                    int code = window.Child.ExitCode;
                    window.CloseChild();
                    do
                    {
                        CheckWindow(window);
                        ReadTail(window, false);
                    } while (window.Tail.MadeProgress);
                    if (code is not (0 or 7)) throw ProducerExitError(window.Output, code);
                    if (window.Tail.Rows == 0) throw new IOException("Observation producer emitted no compact rows.");
                    window.Tail.Complete();
                    bool unavailable = VerifyStorageWindow(window.Output, window.Tail, code);
                    if (unavailable && window.SawPosition)
                        throw new InvalidDataException("Source-unavailable result contradicts the observed position.");
                    closedBytes += WindowBytes(window);
                    Budget();
                    CheckWindow(window);
                    closedCohorts += window.Tail.SealedCohorts;
                    window.Tail.Dispose();
                    active.Remove(window);
                    if (!unavailable)
                    {
                        acceptedWindows.Enqueue(window.Number);
                        Interlocked.Increment(ref windows);
                        emit(new { kind = "observation_window_end", window = window.Number, qpc_ticks = handoffTimestamp(),
                            accepted = true, producer_exit_code = code, continuity_to_next = false });
                    }
                    if (code == 7) MarkWindowGap(window.Number, unavailable ? "source_unavailable" : "producer_partial", handoffTimestamp());
                    if (!finishAfterWindow.Task.IsCompleted && AttemptedWindows < plan.MaximumWindows
                        && (unavailable || active.Count == 0 && nextLaunch is null))
                    {
                        state = unavailable ? "Waiting for observations in the next window" : "Between observation windows";
                        nextLaunch = pauseBetweenWindows(TimeSpan.FromSeconds(unavailable ? 15 : 1), token);
                    }
                }
                if (active.Count == 0) continue;
                if (Stopwatch.GetElapsedTime(scan, handoffTimestamp()) >= TimeSpan.FromSeconds(1))
                {
                    Budget();
                    foreach (var window in active) _ = WindowBytes(window);
                    scan = handoffTimestamp();
                }
                if (nextLaunch?.IsCompleted == true)
                {
                    await nextLaunch;
                    nextLaunch = null;
                }
                if (active.Count == 1 && nextLaunch is null && AttemptedWindows < plan.MaximumWindows
                    && !finishAfterWindow.Task.IsCompleted)
                {
                    var parent = active[0];
                    if (parent.SawPosition && !parent.StartedSuccessor
                        && Stopwatch.GetElapsedTime(parent.Started, handoffTimestamp()) >= leadAt)
                        TryLaunch(parent);
                }
                await handoffPoll(TimeSpan.FromMilliseconds(100), token);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            gapReason = "cancelled";
            state = active.Count == 0 ? "Observation recording stopped" : "Stopped; incomplete tail unknown";
        }
        catch (Exception ex)
        {
            if (active.Count == 0) MarkWindowGap(0, gapReason);
            RecordFailure(ex);
        }
        finally
        {
            foreach (var window in active)
            {
                try { window.CloseChild(); }
                catch (Exception ex) { RecordFailure(ex); }
            }
            foreach (var window in active)
            {
                try { _ = WindowBytes(window); }
                catch (Exception ex) { RecordFailure(ex); }
                finally { window.Tail.Dispose(); }
                MarkWindowGap(window.Number, gapReason, handoffTimestamp());
            }
            if (createdDirectory)
            {
                try { Budget(); }
                catch (Exception ex) { RecordFailure(ex); }
            }
            emit(new { kind = "observation_capture_end", qpc_ticks = handoffTimestamp(), summary = Summary });
        }
    }

    private async Task RunAsync(CancellationToken token)
    {
        int activeWindow = 0;
        try
        {
            token.ThrowIfCancellationRequested(); Validate(package, plan);
            if (Directory.Exists(directory)) throw new IOException("New observation directory required.");
            Directory.CreateDirectory(directory);
            for (int n = 1; n <= plan.MaximumWindows; n++)
            {
                token.ThrowIfCancellationRequested(); if (!targetAlive()) throw new IOException("Selected target lifetime ended.");
                Validate(package, plan);
                long windowByteBudget = plan.MaximumOutputMiB * MiB;
                if (plan.ContinueObservationWindows)
                {
                    Budget();
                    // The per-window producer cap excludes the launcher's external log.
                    windowByteBudget = Math.Min(RepeatedWindowByteLimit, windowByteBudget - outputBytes - LogLimit);
                    if (windowByteBudget < 128 * MiB)
                    {
                        Error = "Remaining observation budget is below the minimum window allowance.";
                        state = "Observation byte budget exhausted";
                        return;
                    }
                }
                if (FinishRequested()) return;
                activeWindow = n;
                Volatile.Write(ref attemptedWindows, n);
                string output = Path.Combine(directory, $"window-{n:D4}");
                emit(new { kind = "observation_window_start", capture_scope = ScopeValue(plan.CaptureScope), window = n, qpc_ticks = Stopwatch.GetTimestamp(), continuity_from_previous = false });
                state = plan.StorageFormat == ObservationStorageFormat.CohortsV1 && !plan.ContinueObservationWindows
                    ? "Recording observations" : "Recording observation window " + n;
                bool unavailable = false;
                int code;
                int precedingCohorts = storageCohorts;
                using (var storage = plan.StorageFormat == ObservationStorageFormat.CohortsV1
                    ? new ObservationStorageTail(output, windowByteBudget,
                        maximumCohortBytes: (long)plan.StorageCohortMiB * 1048576,
                        maximumIndexBytes: 64L * 1048576) : null)
                {
                    var flat = storage is null ? new ObservationReceiptTail(Path.Combine(output, "game-state.jsonl")) : null;
                    void ReadTail()
                    {
                        IEnumerable<object> batch = storage is null ? flat!.Read() : storage.Read();
                        foreach (var receipt in batch) { emit(new { kind = "observation_receipt", window = n, qpc_ticks = Stopwatch.GetTimestamp(), receipt }); Interlocked.Increment(ref rows); }
                        if (storage is not null) storageCohorts = precedingCohorts + storage.SealedCohorts;
                    }
                    long start = Stopwatch.GetTimestamp(), scan = start;
                    // Final files may still change after the root exits. Close the
                    // owned job before draining and verifying its immutable result.
                    token.ThrowIfCancellationRequested();
                    if (!targetAlive()) throw new IOException("Selected target lifetime ended.");
                    using (var child = launch(Command(pid, plan, package, output, windowByteBudget), Path.Combine(directory, $"window-{n:D4}.log")))
                    {
                        while (true)
                        {
                            token.ThrowIfCancellationRequested(); if (!targetAlive()) throw new IOException("Selected target lifetime ended.");
                            ReadTail();
                            if (Stopwatch.GetElapsedTime(scan).TotalSeconds >= 1) { Budget(); scan = Stopwatch.GetTimestamp(); }
                            if (child.HasExited) { code = child.ExitCode; break; }
                            if (Stopwatch.GetElapsedTime(start).TotalSeconds > plan.WindowSeconds + 50) throw new IOException("Observation window wall limit.");
                            await Task.Delay(100, token);
                        }
                    }
                    token.ThrowIfCancellationRequested(); if (!targetAlive()) throw new IOException("Selected target lifetime ended.");
                    // A poll can consume only metadata or stop at its bounded row/
                    // byte limit. Drain control-only progress too, before Complete.
                    do
                    {
                        token.ThrowIfCancellationRequested(); if (!targetAlive()) throw new IOException("Selected target lifetime ended.");
                        ReadTail();
                    } while (storage?.MadeProgress == true);
                    Budget();
                    if (code is not (0 or 7)) throw ProducerExitError(output, code);
                    long count = storage?.Rows ?? flat!.Rows;
                    if (storage is not null) storage.Complete(); else flat!.Complete();
                    if (count == 0) throw new IOException("Observation producer emitted no compact rows.");
                    if (storage is not null) unavailable = VerifyStorageWindow(output, storage, code);
                    else VerifyResult(output, count, code, plan.CaptureScope);
                }
                Budget();
                if (!unavailable)
                {
                    acceptedWindows.Enqueue(n);
                    Interlocked.Increment(ref windows);
                    emit(new { kind = "observation_window_end", window = n, qpc_ticks = Stopwatch.GetTimestamp(), accepted = true,
                        producer_exit_code = code, continuity_to_next = false });
                }
                if (code == 7) MarkWindowGap(n, unavailable ? "source_unavailable" : "producer_partial");
                activeWindow = 0;
                if (FinishRequested()) return;
                if (n < plan.MaximumWindows)
                {
                    state = unavailable ? "Waiting for observations in the next window" : "Between observation windows";
                    var pause = pauseBetweenWindows(TimeSpan.FromSeconds(unavailable ? 15 : 1), token);
                    if (await Task.WhenAny(pause, finishAfterWindow.Task) == pause) await pause;
                    if (FinishRequested()) return;
                }
            }
            if (plan.ContinueObservationWindows)
            {
                Error = "Observation attempt limit reached.";
                state = "Observation window limit reached";
            }
            else state = plan.StorageFormat == ObservationStorageFormat.CohortsV1 ? "Observation recording finished" : "Bounded windows finished";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            if (activeWindow != 0 || !plan.ContinueObservationWindows) MarkWindowGap(activeWindow, "cancelled");
            state = activeWindow == 0 && plan.ContinueObservationWindows ? "Observation recording stopped" : "Stopped; incomplete tail unknown";
        }
        catch (Exception ex)
        {
            MarkWindowGap(activeWindow, "failed");
            Error = ex.Message;
            state = "Failed; incomplete tail unknown";
        }
        finally { emit(new { kind = "observation_capture_end", qpc_ticks = Stopwatch.GetTimestamp(), summary = Summary }); }
    }
}

/// <summary>Follows append-only source lines. Journals receipts, never duplicates raw evidence.</summary>
internal sealed class ObservationReceiptTail(string path)
{
    private long offset, consumed;
    private readonly List<byte> pending = [];
    internal long Rows { get; private set; }
    internal IEnumerable<object> Read()
    {
        if (!File.Exists(path)) yield break;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (stream.Length < offset) throw new InvalidDataException("Observation stream was truncated.");
        stream.Position = offset; var buffer = new byte[65536]; int read;
        while ((read = stream.Read(buffer)) > 0)
        {
            offset += read;
            for (int i = 0; i < read; i++)
            {
                pending.Add(buffer[i]); if (pending.Count > 2 * 1048576) throw new InvalidDataException("Observation line bound.");
                if (buffer[i] != 10) continue;
                byte[] line = pending.ToArray(); pending.Clear();
                using var doc = JsonDocument.Parse(line); string? schema = doc.RootElement.GetProperty("schema").GetString();
                if (schema is not ("overwatch-decoder.private.selected-compact/1" or "overwatch-decoder.private.damage-feedback-candidate/1" or "overwatch-decoder.private.incoming-source-observation/1" or "overwatch-decoder.private.combined-status/1")) throw new InvalidDataException("Unsupported observation schema.");
                var receipt = new { source_schema = schema, source_offset = consumed, source_bytes = line.Length, source_sha256 = Convert.ToHexStringLower(SHA256.HashData(line)) };
                consumed += line.Length; Rows++; yield return receipt;
            }
        }
    }
    internal void Complete() { if (!File.Exists(path) || new FileInfo(path).Length != offset || pending.Count != 0) throw new InvalidDataException("Observation stream ended with a partial line."); }
}
