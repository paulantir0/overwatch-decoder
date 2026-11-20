using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OverwatchDecoder.Observer;

// A recording sink accepts whole UTF-8 lines or refuses before accepting one. Ordinary TextWriter behavior is unchanged.
internal interface IFieldRecordingSink
{
    string? WriteFrame(string line);
    void WriteSummary(string line);
}

/// <summary>Bounded, guarded observations under user-declared labels, never a gameplay decoder.</summary>
public static class FieldStream
{
    public const int MaximumProfileBytes = 256 * 1024;
    public const int MaximumFields = 160;
    public const int MaximumGuards = 256;
    // Retain the former 12 declarations per field allowance at the current 160-field cap.
    // These are repeated dependency declarations, not additional physical guard reads.
    public const int MaximumTimerGuardDeclarations = MaximumFields * 12;
    public const int MaximumGuardBytes = 64;
    public const int MaximumReadBytesPerFrame = 32 * 1024;
    public const long MaximumReadBytes = 8L * 1024 * 1024 * 1024;
    public const long MaximumOutputBytes = 512L * 1024 * 1024;
    public const int MaximumLineBytes = 512 * 1024;
    private const int SummaryReserve = 8192;

    internal sealed record Guard(ulong Address, byte[] Expected);
    internal sealed record Field(string Name, string Type, ulong Address, int Width, int Components,
        double? Min, double? Max, int[] Guards, int? PathId = null, uint Offset = 0, TimerCodec.Config? Timer = null, PoolSumCodec.Config? Pool = null);
    internal sealed record Profile(TargetIdentity Target, string Hash, Guard[] Guards, Field[] Fields, int ReadBytes, byte[] Raw, PointerPaths.Path[]? Paths = null, GuardBatches.Plan? Batching = null, bool V4 = false)
    { public bool V2 => Paths is not null; public string StreamSchema => V4 ? "overwatch-decoder.field-stream/4" : Batching is not null ? "overwatch-decoder.field-stream/3" : V2 ? "overwatch-decoder.field-stream/2" : "overwatch-decoder.field-stream/1"; }
    internal sealed record Reading(byte[]? Bytes, long Start, long End, string? Error, bool Attempted, int? ReturnedBytes = null);
    internal sealed record GuardResult(bool ok, long start_ticks, long end_ticks, string? error);
    internal sealed record FieldResult(string type, string status, object? value, string? reason,
        long? read_start_ticks, long? read_end_ticks, int[] guard_ids, [property: JsonIgnore] string? ReadError = null, [property: JsonIgnore] TimerCodec.Evidence? Timer = null, [property: JsonIgnore] PoolSumCodec.Evidence? Pool = null);
    private sealed record PointerFieldResult(string type, string status, object? value, string? reason,
        long? read_start_ticks, long? read_end_ticks, int[] guard_ids,
        int? path_id, string? read_address_hex, bool read_attempted);
    private sealed record BatchFieldResult(string type, string status, object? value, string? reason,
        long? read_start_ticks, long? read_end_ticks, int[] guard_ids,
        int? path_id, string? read_address_hex, bool read_attempted, string? read_error);
    // Explicit wire properties avoid a serialize/parse/mutate/serialize round trip for each v2 frame.
    // Extension data is absent for v1; v2 adds only its existing private trace properties.
    internal sealed record Frame
    {
        public required string schema { get; init; }
        public string kind { get; init; } = "frame";
        public string source { get; init; } = "process_memory";
        public string interpretation { get; init; } = "profile_declared_research";
        public string visibility { get; init; } = "research";
        public bool runtime_semantics_validated { get; init; }
        public bool public_state_eligible { get; init; }
        public bool atomic { get; init; }
        public required object target { get; init; }
        public required string profile_sha256 { get; init; }
        public long sequence { get; init; }
        public long scheduled_slot { get; init; }
        public long scheduled_ticks { get; init; }
        public long start_ticks { get; init; }
        public long end_ticks { get; init; }
        public long jitter_ticks { get; init; }
        public long skipped_intervals_before { get; init; }
        public long skipped_intervals_total { get; init; }
        public DateTimeOffset utc_origin { get; init; }
        public long utc_origin_before_ticks { get; init; }
        public long monotonic_origin_ticks { get; init; }
        public long monotonic_frequency { get; init; }
        public int requested_interval_ms { get; init; }
        public required string scheduler_backend { get; init; }
        public bool hard_realtime { get; init; }
        public required object guards_before { get; init; }
        public required object guards_after { get; init; }
        public required object fields { get; init; }
        [JsonExtensionData] public Dictionary<string, object?>? Trace { get; init; }
    }
    internal sealed record Limits(long ReadBytes = MaximumReadBytes, long OutputBytes = MaximumOutputBytes);
    // Synchronous notification only after the complete frame is accepted by its output sink.
    // This is not a durability assertion; the recording's terminal flush/index establishes that.
    internal sealed record AcceptedFrame(long Sequence, long Start, long End, long MissedSlots,
        bool GuardInvalidated, string? Terminal, IReadOnlyDictionary<string, FieldResult> Fields,
        Frame Timing, IReadOnlyDictionary<string, bool>? AttemptedFields, string? RecordingLine = null);

    public static object Run(IMemorySource source, string profilePath, int intervalMs, TimeSpan duration,
        TextWriter output, CancellationToken token) => RunBounded(source, profilePath, intervalMs, duration, output, token, new());

    internal static object RunBounded(IMemorySource source, string profilePath, int intervalMs, TimeSpan duration,
        TextWriter output, CancellationToken token, Limits limits, Action<AcceptedFrame>? acceptedFrame = null)
    {
        if (intervalMs is < 10 or > 10_000 || duration <= TimeSpan.Zero || duration > TimeSpan.FromHours(10) ||
            limits.ReadBytes <= 0 || limits.ReadBytes > MaximumReadBytes ||
            limits.OutputBytes < SummaryReserve || limits.OutputBytes > (output is IFieldRecordingSink ? FieldRecording.MaximumJsonBytes : MaximumOutputBytes))
            throw new ObservationException("invalid_arguments", "Field stream limits, interval or duration are invalid.");
        Profile profile = Load(profilePath);
        VerifyIdentity(source, profile.Target); // Fail before output for an unrelated process or build.
        using var wait = PreciseWait.Create(token);
        long frequency = Stopwatch.Frequency;
        long originBefore = Stopwatch.GetTimestamp();
        DateTimeOffset utc = DateTimeOffset.UtcNow;
        long origin = Stopwatch.GetTimestamp();
        long interval = Math.Max(1, (long)(intervalMs * (double)frequency / 1000));
        long deadline = checked(origin + (long)(duration.TotalSeconds * frequency));
        long frames = 0, slot = 0, skipped = 0, readBytes = 0, readCalls = 0, outputBytes = 0, unknownFields = 0;
        long maxJitter = 0, maxFrame = 0, maxWrite = 0;
        long publishedCalls = 0, publishedBytes = 0, publishedGapBytes = 0, totalGapBytes = 0;
        int unpublishedFrames = 0;
        string stop = "duration_elapsed";
        var errors = new Dictionary<string, long>(StringComparer.Ordinal);
        object target = Snapshots.PublicIdentity(profile.Target);

        string? ControlError()
        {
            if (token.IsCancellationRequested) return "cancelled";
            return Stopwatch.GetTimestamp() >= deadline ? "duration_elapsed" : null;
        }
        Reading Read(ulong address, int size, ref string? terminal)
        {
            long start = Stopwatch.GetTimestamp();
            string? error = terminal ?? ControlError();
            byte[]? bytes = null; bool attempted = false; int? returned = null; long physicalEnd = start;
            if (error is null && readBytes > limits.ReadBytes - size) error = "read_byte_limit";
            if (error is null)
            {
                try
                {
                    readBytes += size; readCalls++; attempted = true;
                    if (profile.Batching is not null) start = Stopwatch.GetTimestamp();
                    try { bytes = source.Read(address, size); }
                    finally { if (profile.Batching is not null) physicalEnd = Stopwatch.GetTimestamp(); }
                    returned = bytes.Length;
                    if (bytes.Length != size) { bytes = null; error = "partial_read"; }
                }
                catch (ObservationException e) { error = e.Code; }
                catch (OperationCanceledException) { error = "cancelled"; }
            }
            if (error is not null)
            {
                bytes = null;
                errors[error] = errors.GetValueOrDefault(error) + 1;
                if (Fatal(error)) terminal = error;
            }
            return new(bytes, start, profile.Batching is null ? Stopwatch.GetTimestamp() : physicalEnd, error, attempted, returned);
        }
        GuardResult[] CheckGuards(ref string? terminal)
        {
            var checks = new GuardResult[profile.Guards.Length];
            for (int n = 0; n < checks.Length; n++)
            {
                Guard g = profile.Guards[n];
                Reading read = Read(g.Address, g.Expected.Length, ref terminal);
                bool ok = read.Bytes is not null && read.Bytes.AsSpan().SequenceEqual(g.Expected);
                checks[n] = new(ok, read.Start, read.End, read.Error ?? (ok ? null : "guard_mismatch"));
            }
            return checks;
        }

        while (true)
        {
            if (token.IsCancellationRequested) { stop = "cancelled"; break; }
            long scheduled = checked(origin + slot * interval);
            if (scheduled >= deadline) break;
            wait.WaitUntil(scheduled);
            if (token.IsCancellationRequested) { stop = "cancelled"; break; }
            long start = Stopwatch.GetTimestamp();
            if (start >= deadline) break;
            long missed = Math.Max(0, (start - origin) / interval - slot);
            slot += missed; skipped += missed; scheduled = origin + slot * interval;
            string? terminal = null;
            try { VerifyIdentity(source, profile.Target); }
            catch (ObservationException e) { terminal = e.Code; }
            long callsBefore = readCalls, bytesBefore = readBytes;
            GuardBatches.Pass? batchBefore = profile.Batching is null ? null : GuardBatches.Read(profile, Read, ref terminal);
            var before = batchBefore?.Checks ?? CheckGuards(ref terminal);
            var paths = profile.V2 ? PointerPaths.Resolve(profile, Read, id => before[id].ok, ref terminal) : [];
            var fields = new Dictionary<string, FieldResult>(StringComparer.Ordinal);
            var addresses = profile.V2 ? new Dictionary<string, ulong?>() : null;
            var attemptedFields = profile.V2 ? new Dictionary<string, bool>() : null;
            long frameUnknown = 0;
            foreach (Field f in profile.Fields)
            {
                string? reason = terminal ?? GuardError(f, before, "before") ?? (f.PathId is { } pathId ? paths[pathId].Error : null);
                ulong? address = f.PathId is { } pid ? PointerPaths.FieldAddress(paths[pid], f, ref reason) : f.Address;
                Reading? read = null; object? value = null;
                if (f.Pool is not null)
                {
                    var evidence = PoolSumCodec.Read(f, Read, reason, ref terminal);
                    (value, reason) = PoolSumCodec.Decode(f, evidence);
                    addresses![f.Name] = evidence.snapshot_a.attempted ? f.Address : null;
                    attemptedFields![f.Name] = evidence.snapshot_a.attempted;
                    fields.Add(f.Name, new(f.Type, reason is null ? "observed" : "unknown", value, reason,
                        evidence.Start, evidence.End, f.Guards, evidence.Error, Pool: evidence));
                    continue;
                }
                if (f.Timer is not null)
                {
                    var evidence = TimerCodec.Read(f, Read, reason, ref terminal);
                    (value, reason) = TimerCodec.Decode(f, evidence);
                    addresses![f.Name] = evidence.state.attempted ? f.Address : null;
                    attemptedFields![f.Name] = evidence.state.attempted;
                    fields.Add(f.Name, new(f.Type, reason is null ? "observed" : "unknown", value, reason,
                        evidence.Start, evidence.End, f.Guards, evidence.Error, evidence));
                    continue;
                }
                if (reason is null)
                {
                    read = Read(address!.Value, f.Width, ref terminal);
                    reason = read.Error;
                    if (reason is null) (value, reason) = Decode(f, read.Bytes!);
                }
                if (profile.V2)
                {
                    addresses![f.Name] = read?.Attempted == true ? address : null;
                    attemptedFields![f.Name] = read?.Attempted == true;
                }
                fields.Add(f.Name, new(f.Type, reason is null ? "observed" : "unknown", value, reason,
                    read?.Start, read?.End, f.Guards, read?.Error));
            }
            if (profile.V2) PointerPaths.Postcheck(profile, paths, Read, ref terminal);
            GuardBatches.Pass? batchAfter = profile.Batching is null ? null : GuardBatches.Read(profile, Read, ref terminal);
            var after = batchAfter?.Checks ?? CheckGuards(ref terminal);
            long frameGaps = profile.Batching is { } plan ? plan.Batches.Where(b => batchBefore!.Batches[b.Id].attempted).Sum(b => b.GapBytes) +
                plan.Batches.Where(b => batchAfter!.Batches[b.Id].attempted).Sum(b => b.GapBytes) : 0;
            totalGapBytes += frameGaps;
            try { VerifyIdentity(source, profile.Target); }
            catch (ObservationException e) { terminal = e.Code; }
            terminal ??= ControlError();
            if (profile.V2) PointerPaths.Finish(profile, paths, id => after[id].ok, terminal);
            foreach (Field f in profile.Fields)
            {
                FieldResult result = fields[f.Name];
                string? reason = terminal ?? result.reason ?? (f.PathId is { } pid ? paths[pid].Error : null) ?? GuardError(f, after, "after");
                if (reason is not null)
                {
                    fields[f.Name] = result with { status = "unknown", value = null, reason = reason };
                    frameUnknown++;
                }
            }
            long end = Stopwatch.GetTimestamp();
            var frame = new Frame
            {
                schema = profile.StreamSchema, kind = "frame", source = "process_memory",
                interpretation = "profile_declared_research", visibility = "research",
                runtime_semantics_validated = false, public_state_eligible = false, atomic = false,
                target = target, profile_sha256 = profile.Hash, sequence = frames, scheduled_slot = slot,
                scheduled_ticks = scheduled, start_ticks = start, end_ticks = end, jitter_ticks = start - scheduled,
                skipped_intervals_before = missed, skipped_intervals_total = skipped,
                utc_origin = utc, utc_origin_before_ticks = originBefore, monotonic_origin_ticks = origin,
                monotonic_frequency = frequency, requested_interval_ms = intervalMs,
                scheduler_backend = wait.Backend, hard_realtime = false,
                guards_before = before, guards_after = after, fields = fields
            };
            string line = SerializeFrame(frame, profile, fields, paths, addresses, attemptedFields, batchBefore, batchAfter,
                readCalls - callsBefore, readBytes - bytesBefore, frameGaps, terminal);
            int bytes = Encoding.UTF8.GetByteCount(line) + 1;
            if (bytes > MaximumLineBytes || bytes > limits.OutputBytes - SummaryReserve - outputBytes)
            { unpublishedFrames = 1; stop = "output_byte_limit"; break; }
            long writeStart = Stopwatch.GetTimestamp();
            if (output is IFieldRecordingSink sink)
            {
                string? refusal = sink.WriteFrame(line);
                if (refusal is not null) { unpublishedFrames = 1; stop = refusal; break; }
            }
            else { output.Write(line); output.Write('\n'); output.Flush(); }
            maxWrite = Math.Max(maxWrite, Stopwatch.GetTimestamp() - writeStart);
            outputBytes += bytes; unknownFields += frameUnknown; frames++; slot++;
            publishedCalls += readCalls - callsBefore; publishedBytes += readBytes - bytesBefore; publishedGapBytes += frameGaps;
            maxJitter = Math.Max(maxJitter, start - scheduled); maxFrame = Math.Max(maxFrame, end - start);
            acceptedFrame?.Invoke(new(frames - 1, start, end, missed,
                before.Any(g => !g.ok) || after.Any(g => !g.ok) || paths.Any(p => p.Error is not null), terminal, fields, frame, attemptedFields, line));
            if (terminal is not null) { stop = terminal; break; }
        }
        var summary = new
        {
            schema = profile.StreamSchema, kind = "summary", source = "process_memory",
            interpretation = "profile_declared_research", visibility = "research",
            runtime_semantics_validated = false, public_state_eligible = false, atomic = false,
            target, profile_sha256 = profile.Hash, started_utc = utc, finished_utc = DateTimeOffset.UtcNow,
            utc_origin_before_ticks = originBefore, monotonic_origin_ticks = origin, monotonic_frequency = frequency,
            requested_interval_ms = intervalMs, requested_duration_s = duration.TotalSeconds,
            elapsed_ms = (Stopwatch.GetTimestamp() - origin) * 1000d / frequency,
            frames, skipped_intervals = skipped, unknown_fields = unknownFields,
            read_calls = readCalls, read_bytes = readBytes, frame_output_utf8_bytes = outputBytes,
            maximum_jitter_ms = maxJitter * 1000d / frequency, maximum_frame_ms = maxFrame * 1000d / frequency,
            maximum_write_ms = maxWrite * 1000d / frequency, scheduler = wait.Diagnostics(), errors,
            stop_reason = stop, complete = stop == "duration_elapsed",
            maximum_profile_bytes = MaximumProfileBytes, maximum_fields = MaximumFields, maximum_guards = MaximumGuards,
            planned_read_bytes_per_frame = profile.ReadBytes, maximum_read_bytes_per_frame = MaximumReadBytesPerFrame,
            maximum_read_bytes = limits.ReadBytes, maximum_output_utf8_bytes = limits.OutputBytes,
            note = "Labels and guards are profile declarations, not proof of gameplay meaning, visibility or ownership. " +
                "Before/after guards can miss intervening reuse that restores identical bytes. Sequential reads are not atomic."
        };
        string summaryLine = JsonSerializer.Serialize(summary);
        if (profile.V2)
        {
            var enriched = JsonSerializer.SerializeToNode(summary)!.AsObject();
            enriched["private_address_trace"] = true;
            enriched["maximum_paths"] = PointerPaths.MaximumPaths;
            enriched["maximum_hops_per_path"] = PointerPaths.MaximumHops;
            enriched["maximum_read_calls_per_frame"] = PointerPaths.MaximumCalls;
            if (profile.Batching is { } batches)
            {
                enriched["absolute_guard_reads"] = JsonSerializer.SerializeToNode(batches.Policy);
                enriched["planned_read_calls_per_frame"] = batches.ReadCalls;
                enriched["unbatched_planned_read_bytes_per_frame"] = batches.UnbatchedBytes;
                enriched["unbatched_planned_read_calls_per_frame"] = batches.UnbatchedCalls;
                enriched["planned_guard_gap_bytes_per_frame"] = batches.GapBytes;
                enriched["published_frame_read_calls"] = publishedCalls;
                enriched["published_frame_read_bytes"] = publishedBytes;
                enriched["published_frame_guard_gap_bytes"] = publishedGapBytes;
                enriched["unpublished_frames"] = unpublishedFrames;
                enriched["unpublished_read_accounting"] = GuardBatches.UnpublishedAccounting;
                enriched["unpublished_frame_read_calls"] = readCalls - publishedCalls;
                enriched["unpublished_frame_read_bytes"] = readBytes - publishedBytes;
                enriched["unpublished_frame_guard_gap_bytes"] = totalGapBytes - publishedGapBytes;
                enriched["guard_gap_read_bytes"] = totalGapBytes;
            }
            summaryLine = enriched.ToJsonString();
        }
        if (Encoding.UTF8.GetByteCount(summaryLine) + 1 > SummaryReserve)
            throw new ObservationException("output_byte_limit", "Summary exceeds its reserved output budget.");
        if (output is IFieldRecordingSink sinkSummary) sinkSummary.WriteSummary(summaryLine);
        else { output.Write(summaryLine); output.Write('\n'); output.Flush(); }
        return profile.V2 ? JsonSerializer.Deserialize<JsonElement>(summaryLine) : summary;
    }

    internal static string SerializeFrame(Frame frame, Profile profile, IReadOnlyDictionary<string, FieldResult> fields,
        PointerPaths.State[] paths, IReadOnlyDictionary<string, ulong?>? addresses, IReadOnlyDictionary<string, bool>? attempted,
        GuardBatches.Pass? before = null, GuardBatches.Pass? after = null, long calls = 0, long bytes = 0, long gaps = 0, string? terminal = null)
    {
        if (!profile.V2) return JsonSerializer.Serialize(frame);
        var enriched = new Dictionary<string, object>(fields.Count, StringComparer.Ordinal);
        foreach (var field in profile.Fields)
        {
            FieldResult result = fields[field.Name]; bool read = attempted![field.Name];
            string? address = addresses![field.Name] is { } a ? PointerPaths.Hex(a) : null;
            if (field.Pool is { } pool)
            {
                enriched.Add(field.Name, new PoolSumCodec.Wire(result.type, result.status, result.value, result.reason,
                    result.read_start_ticks, result.read_end_ticks, result.guard_ids, null, address, read, result.ReadError,
                    PoolSumCodec.Name, pool.Span, pool.Slots, "operand_envelope", result.Pool!));
                continue;
            }
            if (field.Timer is { } timer)
            {
                enriched.Add(field.Name, new TimerCodec.Wire(result.type, result.status, result.value, result.reason,
                    result.read_start_ticks, result.read_end_ticks, result.guard_ids, null, address, read, result.ReadError,
                    TimerCodec.Name, timer.ScaleHex, "operand_envelope", result.Timer!));
                continue;
            }
            enriched.Add(field.Name, profile.Batching is null ?
                new PointerFieldResult(result.type, result.status, result.value, result.reason,
                    read ? result.read_start_ticks : null, read ? result.read_end_ticks : null, result.guard_ids, field.PathId, address, read) :
                new BatchFieldResult(result.type, result.status, result.value, result.reason,
                    read ? result.read_start_ticks : null, read ? result.read_end_ticks : null, result.guard_ids, field.PathId, address, read, result.ReadError));
        }
        var trace = new Dictionary<string, object?> { ["private_address_trace"] = true, ["path_traces"] = paths.Select((path, id) => path.Evidence(id)) };
        if (profile.Batching is not null)
        {
            if (!profile.V4) { trace["guard_batches_before"] = before!.Batches; trace["guard_batches_after"] = after!.Batches; }
            trace["terminal_reason"] = terminal;
            trace["physical_read_calls"] = calls; trace["physical_read_bytes"] = bytes; trace["guard_gap_read_bytes"] = gaps;
            frame = frame with { guards_before = profile.V4 ? TimerCodec.GuardEvidence(before!) : before!.Guards,
                guards_after = profile.V4 ? TimerCodec.GuardEvidence(after!) : after!.Guards };
        }
        return JsonSerializer.Serialize(frame with { fields = enriched, Trace = trace });
    }

    private static string? GuardError(Field field, GuardResult[] checks, string phase)
    {
        foreach (int id in field.Guards)
            if (!checks[id].ok) return checks[id].error == "guard_mismatch" ? "guard_mismatch_" + phase : "guard_read_" + phase + ":" + checks[id].error;
        return null;
    }

    private static (object? value, string? error) Decode(Field field, byte[] bytes)
    {
        double[] values = new double[field.Components];
        for (int n = 0; n < values.Length; n++)
        {
            values[n] = field.Type switch
            {
                "u8" => bytes[0],
                "i32" or "i32x4" => BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(n * 4)),
                "f64" => BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(bytes)),
                _ => BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(n * 4)))
            };
            if (!double.IsFinite(values[n])) return (null, "non_finite");
            if (field.Min is { } min && values[n] < min || field.Max is { } max && values[n] > max)
                return (null, "out_of_range");
        }
        if (field.Type == "i32x4") return (values.Select(v => (int)v).ToArray(), null);
        if (field.Components > 1) return (values, null);
        if (field.Type is "u8" or "i32") return ((int)values[0], null);
        return (values[0], null);
    }

    internal static bool Fatal(string code) => code is "permission_denied" or "process_exited" or "identity_mismatch" or
        "cancelled" or "duration_elapsed" or "read_byte_limit";

    private static void VerifyIdentity(IMemorySource source, TargetIdentity expected)
    {
        source.EnsureAlive();
        TargetIdentity actual = source.Identity;
        if (actual.Pid != expected.Pid || actual.CreationFileTime != expected.CreationFileTime ||
            actual.ImageName != expected.ImageName || actual.Architecture != expected.Architecture ||
            !actual.ExecutableSha256.Equals(expected.ExecutableSha256, StringComparison.OrdinalIgnoreCase))
            throw new ObservationException("identity_mismatch", "Field profile does not match the observed process and build.");
    }

    internal static byte[] ValidatedProfileBytes(IMemorySource source, string path)
    {
        Profile profile = Load(path);
        VerifyIdentity(source, profile.Target);
        return profile.Raw;
    }

    private static Profile Load(string path)
    {
        try
        {
            using var input = File.OpenRead(path);
            if (input.Length > MaximumProfileBytes) throw Limit();
            using var buffer = new MemoryStream();
            byte[] part = new byte[8192];
            while (true)
            {
                int count = input.Read(part, 0, Math.Min(part.Length, MaximumProfileBytes - (int)buffer.Length + 1));
                if (count == 0) break;
                if (count > MaximumProfileBytes - buffer.Length) throw Limit();
                buffer.Write(part, 0, count);
            }
            return ParseProfileBytes(buffer.ToArray());
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { throw Invalid(); }
    }

    internal static Profile ParseProfileBytes(byte[] raw) => ParseProfileBytes(raw, false);
    internal static Profile ParseTimerProjection(byte[] raw) => ParseProfileBytes(raw, true);
    private static Profile ParseProfileBytes(byte[] raw, bool timerProjection)
    {
        try
        {
            if (raw.Length > MaximumProfileBytes) throw Limit();
            using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 16 });
            JsonElement root = doc.RootElement;
            if (root.GetProperty("schema").GetString() == "overwatch-decoder.field-profile/4") return TimerCodec.Parse(root, raw);
            if (root.GetProperty("schema").GetString() is "overwatch-decoder.field-profile/2" or "overwatch-decoder.field-profile/3") return PointerPaths.Parse(root, raw);
            Properties(root, "schema", "target", "guards", "fields");
            if (root.GetProperty("schema").GetString() != "overwatch-decoder.field-profile/1") throw Invalid();
            JsonElement t = root.GetProperty("target");
            Properties(t, "pid", "image_name", "creation_file_time", "executable_sha256", "architecture");
            string name = t.GetProperty("image_name").GetString() ?? "";
            string hash = t.GetProperty("executable_sha256").GetString() ?? "";
            var target = new TargetIdentity(t.GetProperty("pid").GetInt32(), name, "", t.GetProperty("creation_file_time").GetInt64(),
                hash, t.GetProperty("architecture").GetString() ?? "");
            if (target.Pid <= 0 || target.CreationFileTime <= 0 || target.Architecture != "x64" || name.Length is < 1 or > 128 ||
                name.Any(c => char.IsControl(c) || c is '/' or '\\') || hash.Length != 64 || !hash.All(Uri.IsHexDigit)) throw Invalid();
            var guards = new List<Guard>(); int guardReferences = 0;
            int[] ParseGuards(JsonElement parent)
            {
                if (!parent.TryGetProperty("guards", out var list)) return [];
                if (list.ValueKind != JsonValueKind.Array) throw Invalid();
                var ids = new List<int>();
                foreach (JsonElement g in list.EnumerateArray())
                {
                    // v4 may repeat the same checks on separate field dependencies.
                    // Keep declarations bounded without turning those checks into globals.
                    if (++guardReferences > (timerProjection ? MaximumTimerGuardDeclarations : MaximumGuards)) throw Limit();
                    Properties(g, "address", "bytes_hex");
                    string hex = g.GetProperty("bytes_hex").GetString() ?? "";
                    if (hex.Length is < 2 or > MaximumGuardBytes * 2 || hex.Length % 2 != 0 || !hex.All(Uri.IsHexDigit)) throw Invalid();
                    byte[] expected = Convert.FromHexString(hex);
                    ulong address = Address(g, expected.Length);
                    int id = guards.FindIndex(x => x.Address == address && x.Expected.AsSpan().SequenceEqual(expected));
                    if (id < 0)
                    {
                        if (guards.Count >= MaximumGuards) throw Limit();
                        id = guards.Count; guards.Add(new(address, expected));
                    }
                    if (!ids.Contains(id)) ids.Add(id);
                }
                return ids.ToArray();
            }
            int[] global = ParseGuards(root);
            JsonElement array = root.GetProperty("fields");
            if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() == 0) throw Invalid();
            if (array.GetArrayLength() > MaximumFields) throw Limit();
            var fields = new List<Field>(); var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement f in array.EnumerateArray())
            {
                Properties(f, "name", "type", "address", "guards", "min", "max");
                string label = f.GetProperty("name").GetString() ?? "";
                if (label.Length is < 1 or > 64 || !label.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.') || !names.Add(label)) throw Invalid();
                string type = f.GetProperty("type").GetString() ?? "";
                int components = type switch { "u8" or "i32" or "f32" or "f64" => 1, "f32x3" => 3, "f32x4" or "i32x4" => 4, _ => throw Invalid() };
                int width = type == "u8" ? 1 : type == "f64" ? 8 : 4 * components;
                double? Range(string key) => f.TryGetProperty(key, out var bound) ? bound.GetDouble() : null;
                double? min = Range("min"), max = Range("max");
                if (min is { } lo && !double.IsFinite(lo) || max is { } hi && !double.IsFinite(hi) || min > max) throw Invalid();
                int[] effective = global.Concat(ParseGuards(f)).Distinct().ToArray();
                if (effective.Length == 0) throw Invalid();
                if (timerProjection)
                {
                    // v4 retains distinct exact guards even when their consistent byte ranges overlap.
                    // The v1 rule below is deliberately unchanged.
                    var bytes = new Dictionary<ulong, byte>();
                    foreach (int id in effective)
                        for (int i = 0; i < guards[id].Expected.Length; i++)
                        {
                            ulong at = guards[id].Address + (ulong)i; byte value = guards[id].Expected[i];
                            if (bytes.TryGetValue(at, out byte previous) && previous != value) throw Invalid();
                            bytes[at] = value;
                        }
                }
                else foreach (var group in effective.Select(i => guards[i]).GroupBy(g => g.Address))
                    if (group.Count() > 1) throw Invalid();
                fields.Add(new(label, type, Address(f, width), width, components, min, max, effective));
            }
            int readBytes = 2 * guards.Sum(g => g.Expected.Length) + fields.Sum(f => f.Width);
            if (readBytes > MaximumReadBytesPerFrame) throw Limit();
            return new(target, Convert.ToHexStringLower(SHA256.HashData(raw)), guards.ToArray(), fields.ToArray(), readBytes, raw);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { throw Invalid(); }
    }

    private static ulong Address(JsonElement item, int width)
    {
        ulong address = item.GetProperty("address").GetUInt64();
        if (address == 0 || address > (ulong)long.MaxValue - (ulong)(width - 1)) throw Invalid();
        return address;
    }
    private static void Properties(JsonElement element, params string[] allowed)
    {
        if (element.ValueKind != JsonValueKind.Object) throw Invalid();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty p in element.EnumerateObject())
            if (!names.Add(p.Name) || !allowed.Contains(p.Name, StringComparer.Ordinal)) throw Invalid();
    }
    private static ObservationException Invalid() => new("invalid_field_profile", "Field profile is malformed, unguarded or unsupported.");
    private static ObservationException Limit() => new("field_profile_limit", "Field profile exceeds a bounded input, field, guard or read-size limit.");
}
