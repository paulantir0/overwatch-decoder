using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Sparse comparisons of strictly verified saved observations; never inferred events.</summary>
public static class FieldTimeline
{
    public const long MaximumOutputBytes = 8L * 1024 * 1024 * 1024;
    public const int MaximumLineBytes = FieldStream.MaximumLineBytes, MaximumReasonsPerField = 64, MaximumReasonEntries = 1024;
    internal sealed record Limits(long OutputBytes = MaximumOutputBytes, int ReasonsPerField = MaximumReasonsPerField,
        int ReasonEntries = MaximumReasonEntries, FieldRecordingVerification.Limits? Verification = null);
    public sealed record Result(string schema, string status, bool complete, string source_status, bool source_complete,
        long frames, long emitted_frames, long numeric_changes, long unknown_fields, long skipped_intervals,
        long output_lines, long output_utf8_bytes, string output_sha256, string profile_sha256, string manifest_sha256,
        string samples_sha256, string index_sha256, string source_json_sha256, double elapsed_ms);

    public static Result Export(string directory, string outputPath, CancellationToken cancellationToken = default) =>
        ExportBounded(directory, outputPath, cancellationToken, new());

    internal static Result ExportBounded(string directory, string outputPath, CancellationToken token, Limits limits,
        Action<long>? afterLine = null)
    {
        if (limits.OutputBytes is < 1 or > MaximumOutputBytes || limits.ReasonsPerField is < 1 or > MaximumReasonsPerField ||
            limits.ReasonEntries is < 1 or > MaximumReasonEntries)
            throw new ObservationException("invalid_arguments", "Invalid timeline limits.");
        var clock = Stopwatch.StartNew(); string source = Path.GetFullPath(directory), destination = Path.GetFullPath(outputPath);
        if (FieldExport.Inside(source, destination))
            throw new ObservationException("invalid_arguments", "Timeline destination must be outside the source recording.");
        if (Path.Exists(destination)) throw new ObservationException("output_exists", "Timeline destination already exists.");
        if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Timeline cancelled.");
        string temporary = Path.Combine(Path.GetDirectoryName(destination)!, ".overwatch-decoder-timeline-" + Guid.NewGuid().ToString("N") + ".partial");
        bool created = false;
        try
        {
            if (Directory.Exists(source) && FieldExport.Inside(FieldExport.ResolveDirectory(source),
                Path.Combine(FieldExport.ResolveDirectory(Path.GetDirectoryName(destination)!), Path.GetFileName(destination))))
                throw new ObservationException("invalid_arguments", "Timeline destination must be outside the source recording.");
            using var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024);
            created = true;
            using var sink = new TimelineSink(output, token, limits, afterLine);
            // The sink sees exactly the buffers validated by this call, never a reopened input.
            var verified = FieldRecordingVerification.VerifyBounded(directory, false, token, limits.Verification ?? new(), sink);
            if (!verified.valid)
                throw new ObservationException(verified.error_code == "cancelled" ? "cancelled" : "invalid_recording",
                    "Timeline rejected: " + verified.error_code + ". No final output was published.");
            sink.Finish(verified); output.Flush(true);
            if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Timeline cancelled.");
            string hash = sink.Hash; long bytes = output.Position; output.Dispose();
            File.Move(temporary, destination, overwrite: false); created = false;
            return new("overwatch-decoder.field-change-timeline-result/1", "exported", true, verified.status, verified.complete,
                verified.frames, sink.EmittedFrames, sink.Changes, verified.unknown_fields, verified.skipped_intervals,
                sink.Lines, bytes, hash, verified.profile_sha256!, sink.ManifestHash, verified.samples_prefix_sha256,
                verified.index_prefix_sha256, verified.json_prefix_sha256, clock.Elapsed.TotalMilliseconds);
        }
        catch (FieldRecordingVerification.SinkException e)
        {
            if (e.InnerException is ObservationException known) ExceptionDispatchInfo.Capture(known).Throw();
            if (e.InnerException is OperationCanceledException) throw new ObservationException("cancelled", "Timeline cancelled.");
            if (e.InnerException is UnauthorizedAccessException) throw new ObservationException("output_permission_denied", "Timeline output access denied.");
            if (e.InnerException is IOException) throw new ObservationException("output_io_error", "Timeline output write failed.");
            throw;
        }
        catch (UnauthorizedAccessException) { throw new ObservationException("output_permission_denied", "Timeline output access denied."); }
        catch (IOException)
        { throw new ObservationException(Path.Exists(destination) ? "output_exists" : "output_io_error", "Timeline output could not be published."); }
        finally { if (created) File.Delete(temporary); }
    }

    private sealed record Frame(long sequence, long scheduled_slot, long scheduled_ticks, long start_ticks, long end_ticks,
        long jitter_ticks, long skipped_intervals_before, long skipped_intervals_total, string scheduler_backend);
    private sealed record Sample(Frame Frame, string Status, JsonElement Value, string? Reason, long? Start, long? End, bool? Attempted, JsonElement? Calculation = null);
    private sealed class FieldState(string name, string type)
    {
        internal readonly string Name = name, Type = type;
        internal Sample? Last, RunFirst;
        internal string? Route;
        internal long Segment = -1, RunSamples, Known, Unknown, Changes, Pairs;
        internal readonly Dictionary<string, long> Reasons = new(StringComparer.Ordinal);
    }
    private sealed record Item(FieldState Field, string Kind, string[] Resets, Sample? Before, Sample After,
        Sample? ClosedFirst, long ClosedSamples);

    private sealed class TimelineSink(FileStream output, CancellationToken token, Limits limits, Action<long>? afterLine)
        : FieldRecordingVerification.IValidatedSink, IDisposable
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private JsonDocument? profile, manifest;
        private JsonElement? summary;
        private FieldState[] fields = [];
        private Frame? lastFrame;
        private bool header, v2;
        private long frames, frameSkips, origin, intervalTicks;
        private int reasonEntries;
        public string ManifestHash { get; private set; } = "";
        public long Lines { get; private set; }
        public long EmittedFrames { get; private set; }
        public long Changes => fields.Sum(f => f.Changes);
        public string Hash => Convert.ToHexStringLower(hash.GetCurrentHash());
        private void Control()
        { if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Timeline cancelled. No final output was published."); }
        public void Metadata(ReadOnlyMemory<byte> p, ReadOnlyMemory<byte> m)
        {
            Control(); profile = JsonDocument.Parse(p); manifest = JsonDocument.Parse(m);
            ManifestHash = Convert.ToHexStringLower(SHA256.HashData(m.Span));
            v2 = profile.RootElement.GetProperty("schema").GetString() is "overwatch-decoder.field-profile/2" or "overwatch-decoder.field-profile/3" or "overwatch-decoder.field-profile/4";
            // The verifier enforces the profile's full field bound; do not impose a smaller projection limit.
            fields = profile.RootElement.GetProperty("fields").EnumerateArray()
                .Select(f => new FieldState(f.GetProperty("name").GetString()!, f.GetProperty("type").GetString()!)).ToArray();
        }
        private void Line(Action<Utf8JsonWriter> write)
        {
            Control(); using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer)) { write(writer); writer.Flush(); }
            buffer.WriteByte((byte)'\n');
            if (buffer.Length > MaximumLineBytes || buffer.Length > limits.OutputBytes - output.Position)
                throw new ObservationException("timeline_byte_limit", "Timeline exceeds its output bound. No final output was published.");
            ReadOnlySpan<byte> bytes = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
            output.Write(bytes); hash.AppendData(bytes); Lines++; afterLine?.Invoke(Lines); Control();
        }
        private static void Begin(Utf8JsonWriter w, string kind)
        { w.WriteStartObject(); w.WriteString("schema", "overwatch-decoder.field-change-timeline/1"); w.WriteString("kind", kind); }
        private static void Copy(Utf8JsonWriter w, JsonElement e, params string[] names)
        { foreach (string name in names) if (e.TryGetProperty(name, out var value)) { w.WritePropertyName(name); value.WriteTo(w); } }
        private void Header(JsonElement first)
        {
            JsonElement p = profile!.RootElement, m = manifest!.RootElement;
            origin = first.GetProperty("monotonic_origin_ticks").GetInt64();
            intervalTicks = Math.Max(1, (long)(first.GetProperty("requested_interval_ms").GetInt32() *
                (double)first.GetProperty("monotonic_frequency").GetInt64() / 1000));
            Line(w =>
            {
                Begin(w, "metadata"); w.WriteString("data_classification", "private_research");
                w.WriteString("source", "process_memory"); w.WriteString("interpretation", "profile_declared_research");
                w.WriteString("visibility", "research"); w.WriteBoolean("public_state_eligible", false);
                w.WriteBoolean("runtime_semantics_validated", false); w.WriteBoolean("atomic", false); w.WriteBoolean("hard_realtime", false);
                w.WriteString("revision", Program.Revision); w.WriteString("source_profile_schema", p.GetProperty("schema").GetString());
                w.WriteString("source_stream_schema", first.GetProperty("schema").GetString());
                w.WriteString("source_manifest_sha256", ManifestHash);
                Copy(w, m, "target", "profile_sha256", "samples_sha256", "index_sha256", "requested_interval_ms", "requested_duration_s");
                w.WritePropertyName("source_recording"); w.WriteStartObject();
                Copy(w, m, "schema", "revision", "started_utc", "finished_utc", "complete", "stop_reason", "failure"); w.WriteEndObject();
                Copy(w, first, "utc_origin_before_ticks", "monotonic_origin_ticks", "monotonic_frequency");
                w.WritePropertyName("utc_origin"); first.GetProperty(first.GetProperty("kind").GetString() == "frame" ? "utc_origin" : "started_utc").WriteTo(w);
                w.WriteString("utc_mapping", "utc_origin + (ticks - monotonic_origin_ticks) / monotonic_frequency seconds; origin sampled between utc_origin_before_ticks and monotonic_origin_ticks");
                w.WritePropertyName("fields"); w.WriteStartArray();
                foreach (var field in p.GetProperty("fields").EnumerateArray())
                { w.WriteStartObject(); Copy(w, field, "name", "type", "min", "max", "codec", "counter_scale_f32_hex"); w.WriteEndObject(); }
                w.WriteEndArray(); w.WriteString("note", "Sparse numeric comparisons, not game events or inferred event times. Only adjacent observed frames in adjacent scheduled slots with unchanged verified storage routes are compared. Unknowns and missing slots are not filled. Status runs describe recorded samples only. Omitted frames have no numeric/status/route change, but continuous observation between reads is never established. Values and labels remain private; omitting structural traces is not anonymization. Allocation reuse that passes all guards is not detected. A signed-zero difference is numerically equal. V1 read_attempted is unknown (null).");
                w.WriteNumber("maximum_output_utf8_bytes", limits.OutputBytes); w.WriteNumber("maximum_line_utf8_bytes", MaximumLineBytes);
                w.WriteNumber("maximum_reasons_per_field", limits.ReasonsPerField); w.WriteNumber("maximum_reason_entries", limits.ReasonEntries);
                w.WriteEndObject();
            }); header = true;
        }
        private static Frame Clock(JsonElement e) => new(e.GetProperty("sequence").GetInt64(), e.GetProperty("scheduled_slot").GetInt64(),
            e.GetProperty("scheduled_ticks").GetInt64(), e.GetProperty("start_ticks").GetInt64(), e.GetProperty("end_ticks").GetInt64(),
            e.GetProperty("jitter_ticks").GetInt64(), e.GetProperty("skipped_intervals_before").GetInt64(),
            e.GetProperty("skipped_intervals_total").GetInt64(), e.GetProperty("scheduler_backend").GetString()!);
        private static long? Tick(JsonElement e, string name) => e.GetProperty(name).ValueKind == JsonValueKind.Null ? null : e.GetProperty(name).GetInt64();
        private static Sample ReadSample(Frame frame, JsonElement f) => new(frame, f.GetProperty("status").GetString()!,
            f.GetProperty("value").Clone(), f.GetProperty("reason").GetString(), Tick(f, "read_start_ticks"), Tick(f, "read_end_ticks"),
            f.TryGetProperty("read_attempted", out var attempted) ? attempted.GetBoolean() : null,
            f.TryGetProperty("codec", out _) ? f.Clone() : null);
        private string? Route(JsonElement frame, JsonElement field, Sample sample)
        {
            if (sample.Status != "observed") return null;
            if (!v2) return "fixed_profile_address";
            // Compare every plain pointer slot AND destination, not just the final field address. The strict
            // verifier has already checked corresponding before/after bytes and all guards in this frame.
            var parts = new List<string> { field.GetProperty("read_address_hex").GetString()! };
            if (field.TryGetProperty("operands", out var operands))
                foreach (var operand in operands.EnumerateObject()) parts.Add(operand.Value.GetProperty("address_hex").GetString()!);
            if (field.GetProperty("path_id").ValueKind != JsonValueKind.Null)
            {
                int id = field.GetProperty("path_id").GetInt32(); var trace = frame.GetProperty("path_traces")[id];
                if (trace.GetProperty("status").GetString() != "observed") return null;
                foreach (var hop in trace.GetProperty("hops").EnumerateArray())
                {
                    var before = hop.GetProperty("pointer_before");
                    if (!before.GetProperty("attempted").GetBoolean() || before.GetProperty("bytes_hex").ValueKind != JsonValueKind.String) return null;
                    parts.Add(before.GetProperty("address_hex").GetString()!); parts.Add(before.GetProperty("bytes_hex").GetString()!);
                }
            }
            return string.Join(':', parts);
        }
        private static bool SameValue(string type, JsonElement a, JsonElement b)
        {
            if (type is "u8" or "i32") return a.GetInt32() == b.GetInt32();
            if (type == "i32x4") return a.EnumerateArray().Select(x => x.GetInt32()).SequenceEqual(b.EnumerateArray().Select(x => x.GetInt32()));
            if (type is "f32" or "f64") return a.GetDouble() == b.GetDouble();
            return a.EnumerateArray().Select(x => x.GetDouble()).SequenceEqual(b.EnumerateArray().Select(x => x.GetDouble()));
        }
        private static void SampleJson(Utf8JsonWriter w, Sample? s)
        {
            if (s is null) { w.WriteNullValue(); return; }
            w.WriteStartObject(); w.WritePropertyName("frame"); JsonSerializer.Serialize(w, s.Frame);
            w.WriteString("status", s.Status); w.WritePropertyName("value"); s.Value.WriteTo(w); w.WriteString("reason", s.Reason);
            w.WritePropertyName("read_start_ticks"); JsonSerializer.Serialize(w, s.Start);
            w.WritePropertyName("read_end_ticks"); JsonSerializer.Serialize(w, s.End);
            w.WritePropertyName("read_attempted"); JsonSerializer.Serialize(w, s.Attempted);
            if (s.Calculation is { } calculation) TimerCodec.CopyCompact(w, calculation);
            w.WriteEndObject();
        }
        private static void RunJson(Utf8JsonWriter w, Sample? first, Sample? last, long count)
        {
            if (first is null) { w.WriteNullValue(); return; }
            w.WriteStartObject(); w.WriteNumber("recorded_samples", count);
            w.WritePropertyName("first"); SampleJson(w, first); w.WritePropertyName("last"); SampleJson(w, last); w.WriteEndObject();
        }
        private void Gap(Utf8JsonWriter w, long count, long nextSlot)
        {
            if (count == 0) { w.WriteNullValue(); return; }
            long last, firstTicks, lastTicks;
            try
            { last = checked(nextSlot + count - 1); firstTicks = checked(origin + nextSlot * intervalTicks); lastTicks = checked(origin + last * intervalTicks); }
            catch (OverflowException) { throw new ObservationException("timeline_time_range", "Missing-slot timing exceeds integer timestamp bounds."); }
            w.WriteStartObject(); w.WriteNumber("missing_slots", count); w.WriteNumber("first_missing_slot", nextSlot);
            w.WriteNumber("last_missing_slot", last); w.WriteNumber("first_missing_scheduled_ticks", firstTicks);
            w.WriteNumber("last_missing_scheduled_ticks", lastTicks);
            w.WriteString("evidence", "scheduled slots without a recorded frame; no field values or event times are inferred"); w.WriteEndObject();
        }
        public void Chunk(ReadOnlyMemory<byte> json)
        {
            int start = 0;
            for (int n = 0; n < json.Length; n++)
            {
                if (json.Span[n] != (byte)'\n') continue;
                Control(); using var doc = JsonDocument.Parse(json.Slice(start, n - start)); start = n + 1; JsonElement row = doc.RootElement;
                if (!header) Header(row);
                if (row.GetProperty("kind").GetString() == "summary") { summary = row.Clone(); continue; }
                Frame clock = Clock(row); var items = new List<Item>();
                foreach (FieldState state in fields)
                {
                    var value = row.GetProperty("fields").GetProperty(state.Name); Sample current = ReadSample(clock, value);
                    Sample? prior = state.Last; string? route = Route(row, value, current); var reset = new List<string>();
                    if (current.Status == "observed") state.Known++;
                    else
                    {
                        state.Unknown++; string reason = current.Reason!;
                        if (!state.Reasons.ContainsKey(reason))
                        {
                            if (state.Reasons.Count >= limits.ReasonsPerField || reasonEntries >= limits.ReasonEntries)
                                throw new ObservationException("timeline_reason_limit", "Timeline reason counters exceed their bound.");
                            state.Reasons.Add(reason, 0); reasonEntries++;
                        }
                        state.Reasons[reason]++;
                    }
                    if (prior is null) reset.Add("first_sample");
                    if (clock.skipped_intervals_before > 0) reset.Add("missed_slots");
                    if (prior is not null && current.Status != prior.Status) reset.Add(current.Status == "observed" ? "unknown_recovery" : "became_unknown");
                    if (prior is not null && current.Reason != prior.Reason && current.Status == prior.Status) reset.Add("unknown_reason_changed");
                    if (current.Status == "observed" && route is null) reset.Add("storage_trace_unavailable");
                    if (prior?.Status == "observed" && current.Status == "observed")
                    {
                        if (state.Route is null) reset.Add("previous_storage_trace_unavailable");
                        else if (route is not null && !StringComparer.OrdinalIgnoreCase.Equals(state.Route, route)) reset.Add("storage_path_changed");
                    }
                    bool boundary = reset.Count > 0;
                    bool eligible = !boundary && prior?.Status == "observed" && current.Status == "observed";
                    if (eligible) state.Pairs++;
                    bool changed = eligible && !SameValue(state.Type, prior!.Value, current.Value);
                    Sample? closed = boundary ? state.RunFirst : null; long closedCount = boundary ? state.RunSamples : 0;
                    if (boundary) { state.Segment++; state.RunFirst = current; state.RunSamples = 0; }
                    state.RunSamples++;
                    if (boundary || changed)
                    {
                        string kind = changed ? "numeric_change" : current.Status == "observed" ? "baseline" :
                            prior is null ? "unknown" : current.Status != prior.Status || current.Reason != prior.Reason ? "status_change" : "reset";
                        items.Add(new(state, kind, reset.ToArray(), prior, current, closed, closedCount));
                    }
                    if (changed) state.Changes++;
                    state.Last = current; state.Route = route;
                }
                if (items.Count > 0 || clock.skipped_intervals_before > 0)
                {
                    Line(w =>
                    {
                        Begin(w, "frame"); w.WritePropertyName("frame"); JsonSerializer.Serialize(w, clock);
                        w.WritePropertyName("gap_before"); Gap(w, clock.skipped_intervals_before, clock.scheduled_slot - clock.skipped_intervals_before);
                        w.WritePropertyName("observations"); w.WriteStartArray();
                        foreach (var item in items)
                        {
                            w.WriteStartObject(); w.WriteString("field", item.Field.Name); w.WriteString("type", item.Field.Type);
                            w.WriteString("kind", item.Kind); w.WriteNumber("comparison_segment", item.Field.Segment);
                            w.WritePropertyName("reset_reasons"); JsonSerializer.Serialize(w, item.Resets);
                            w.WritePropertyName("before"); SampleJson(w, item.Before); w.WritePropertyName("after"); SampleJson(w, item.After);
                            w.WritePropertyName("closed_status_run"); RunJson(w, item.ClosedFirst, item.Before, item.ClosedSamples);
                            w.WritePropertyName("sampling_comparison_envelope");
                            if (item.Kind != "numeric_change") w.WriteNullValue();
                            else
                            {
                                w.WriteStartObject(); w.WriteNumber("start_ticks", item.Before!.Start!.Value); w.WriteNumber("end_ticks", item.After.End!.Value);
                                w.WriteString("meaning", "enclosing sampling evidence only; not an event occurrence time or duration"); w.WriteEndObject();
                            }
                            w.WriteEndObject();
                        }
                        w.WriteEndArray(); w.WriteEndObject();
                    }); EmittedFrames++;
                }
                frames++; frameSkips = clock.skipped_intervals_total; lastFrame = clock; Control();
            }
        }
        public void Finish(FieldRecordingVerification.Result verified)
        {
            Control(); var s = summary!.Value;
            if (frames != verified.frames) throw new ObservationException("invalid_recording", "Timeline frame count differs from verification.");
            Line(w =>
            {
                Begin(w, "summary"); w.WriteString("source_verification_status", verified.status); w.WriteBoolean("source_recording_complete", verified.complete);
                w.WriteString("source_json_sha256", verified.json_prefix_sha256);
                Copy(w, s, "frames", "unknown_fields", "skipped_intervals", "stop_reason", "complete", "started_utc", "finished_utc", "elapsed_ms");
                w.WriteNumber("emitted_frames", EmittedFrames); w.WriteNumber("omitted_frames", frames - EmittedFrames); w.WriteNumber("numeric_changes", Changes);
                w.WritePropertyName("last_recorded_frame"); JsonSerializer.Serialize(w, lastFrame);
                w.WritePropertyName("trailing_gap"); Gap(w, verified.skipped_intervals - frameSkips, lastFrame is null ? 0 : lastFrame.scheduled_slot + 1);
                w.WriteString("end_evidence", "last samples are historical observations, not current values; no observation is implied after their read ends or within missing slots");
                w.WritePropertyName("fields"); w.WriteStartArray();
                foreach (var f in fields)
                {
                    w.WriteStartObject(); w.WriteString("name", f.Name); w.WriteString("type", f.Type);
                    w.WriteNumber("observed_count", f.Known); w.WriteNumber("unknown_count", f.Unknown);
                    w.WritePropertyName("unknown_reasons"); JsonSerializer.Serialize(w, f.Reasons);
                    w.WriteNumber("numeric_changes", f.Changes); w.WriteNumber("eligible_adjacent_pairs", f.Pairs);
                    w.WriteNumber("comparison_segments", f.Segment + 1); w.WritePropertyName("last_sample"); SampleJson(w, f.Last);
                    w.WritePropertyName("final_status_run"); RunJson(w, f.RunFirst, f.Last, f.RunSamples); w.WriteEndObject();
                }
                w.WriteEndArray(); w.WriteEndObject();
            });
        }
        public void Dispose() { profile?.Dispose(); manifest?.Dispose(); hash.Dispose(); }
    }
}
