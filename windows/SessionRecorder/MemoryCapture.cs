using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using OverwatchDecoder.Observer;

namespace OverwatchDecoder.SessionRecorder;

public sealed class MemoryCapture
{
    private readonly int pid;
    private readonly long targetStartUtcTicks;
    private readonly MemoryPlan plan;
    private readonly string sourcePath, directory;
    private readonly Action<object> emit;
    private long frames, unknownFields, acquisitionGaps;
    private volatile string state = "Waiting";
    public string Name => plan.Name;
    public bool Required => plan.Required;
    public string State => state;
    public long Frames => Interlocked.Read(ref frames);
    public long UnknownFields => Interlocked.Read(ref unknownFields);
    public long AcquisitionGaps => Interlocked.Read(ref acquisitionGaps);
    public string? Error { get; private set; }
    public object? Identity { get; private set; }
    public Task? Completion { get; private set; }

    public MemoryCapture(int pid, long targetStartUtcTicks, MemoryPlan plan, string package, string directory, Action<object> emit)
    {
        this.pid = pid; this.targetStartUtcTicks = targetStartUtcTicks; this.plan = plan; this.directory = directory; this.emit = emit;
        sourcePath = CaptureSettings.PackagePath(package, plan.Path);
        Directory.CreateDirectory(directory);
        File.Copy(sourcePath, Path.Combine(directory, plan.Kind + ".json"));
    }

    public void Start(CancellationToken token) => Completion = Task.Run(() => Run(token));

    private void Run(CancellationToken token)
    {
        try
        {
            using var memory = new NativeMemory(pid);
            if (DateTime.FromFileTimeUtc(memory.Identity.CreationFileTime).Ticks != targetStartUtcTicks)
                throw new ObservationException("identity_mismatch", "The selected process lifetime changed before memory capture.");
            Identity = new { memory.Identity.Pid, memory.Identity.ImageName, memory.Identity.CreationFileTime, memory.Identity.ExecutableSha256, memory.Identity.Architecture };
            var module = Acquisition.MainModule(memory);
            emit(new { kind = "memory_target", name = Name, qpc_ticks = Stopwatch.GetTimestamp(), identity = Identity });
            int attempt = 0;
            while (!token.IsCancellationRequested)
            {
                string output = Path.Combine(directory, $"part-{++attempt:D4}");
                state = "Acquiring";
                emit(new { kind = "memory_part_start", name = Name, part = attempt, qpc_ticks = Stopwatch.GetTimestamp() });
                if (plan.Kind == "recipe")
                {
                    using var live = new ProgressWriter(output + ".live.jsonl.gz", this);
                    var result = ObserveFields.Run(memory, module, sourcePath, output, plan.IntervalMs, TimeSpan.FromMinutes(5), token, live,
                        allowFieldShapeChanges: true);
                    emit(new { kind = "memory_part_end", name = Name, part = attempt, qpc_ticks = Stopwatch.GetTimestamp(), result.stop_reason,
                        result.complete, frames = result.segments.Sum(s => s.frames), result.manifest_publication });
                    if (result.stop_reason is "permission_denied" or "identity_mismatch" or "module_identity_mismatch" or "process_exited")
                        throw new InvalidOperationException(result.stop_reason);
                    if (!result.manifest_publication.final_manifest_saved || result.manifest_publication.error is not null)
                        throw new IOException("Memory recording could not publish its final manifest.");
                    if (result.stop_reason != "duration_elapsed" && !token.IsCancellationRequested)
                    {
                        Interlocked.Increment(ref acquisitionGaps);
                        state = "Waiting for supported state";
                        if (token.WaitHandle.WaitOne(TimeSpan.FromSeconds(5))) break;
                    }
                }
                else
                {
                    state = "Recording candidate fields";
                    object result = FieldRecording.Record(memory, sourcePath, output, plan.IntervalMs, TimeSpan.FromMinutes(5), token, stopOnUnknown: true);
                    using var doc = JsonDocument.Parse(JsonSerializer.Serialize(result));
                    var root = doc.RootElement;
                    if (root.TryGetProperty("stream_summary", out var summary) && summary.ValueKind == JsonValueKind.Object)
                    {
                        if (summary.TryGetProperty("frames", out var n)) Interlocked.Add(ref frames, n.GetInt64());
                        if (summary.TryGetProperty("unknown_fields", out var u)) Interlocked.Add(ref unknownFields, u.GetInt64());
                    }
                    string reason = root.GetProperty("stop_reason").GetString() ?? "unknown";
                    emit(new { kind = "memory_part_end", name = Name, part = attempt, qpc_ticks = Stopwatch.GetTimestamp(), result });
                    if (reason == "cancelled" && token.IsCancellationRequested) break;
                    if (reason != "duration_elapsed") { state = "Unavailable: " + reason; Error = reason; return; }
                }
                if (attempt >= 256) throw new InvalidOperationException("Memory part limit reached.");
            }
            state = "Stopped";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { state = "Stopped"; }
        catch (Exception ex)
        {
            Error = ex is ObservationException observed ? observed.Code + ": " + observed.Message : ex.Message;
            state = "Unavailable";
            emit(new { kind = "memory_error", name = Name, qpc_ticks = Stopwatch.GetTimestamp(), error = Error });
        }
    }

    private sealed class ProgressWriter : TextWriter
    {
        private readonly StreamWriter writer;
        private readonly MemoryCapture owner;
        public override Encoding Encoding => Encoding.UTF8;
        public ProgressWriter(string path, MemoryCapture owner)
        {
            this.owner = owner;
            writer = new StreamWriter(new GZipStream(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536), CompressionLevel.Fastest),
                new UTF8Encoding(false), 65536);
        }
        private long lastFlush = Stopwatch.GetTimestamp();
        public override void Write(string? value)
        {
            if (value is null) return;
            writer.Write(value);
            using var doc = JsonDocument.Parse(value);
            if (doc.RootElement.TryGetProperty("kind", out var kind) && kind.GetString() == "frame")
            {
                Interlocked.Increment(ref owner.frames); owner.state = "Recording";
                if (doc.RootElement.TryGetProperty("fields", out var fields))
                    foreach (var field in fields.EnumerateObject())
                        if (field.Value.GetProperty("status").GetString() != "observed") Interlocked.Increment(ref owner.unknownFields);
            }
        }
        public override void Flush()
        {
            if (Stopwatch.GetElapsedTime(lastFlush).TotalSeconds >= 1) { writer.Flush(); lastFlush = Stopwatch.GetTimestamp(); }
        }
        protected override void Dispose(bool disposing) { if (disposing) writer.Dispose(); base.Dispose(disposing); }
    }
}
