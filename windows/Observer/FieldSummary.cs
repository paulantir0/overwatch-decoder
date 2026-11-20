using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Bounded offline numeric observations, never event inference or gameplay interpretation.</summary>
public static class FieldSummary
{
    public const int MaximumReasonsPerField = 64, MaximumReasonEntries = 1024, MaximumReportBytes = 1024 * 1024;
    internal sealed record Limits(int ReasonsPerField = MaximumReasonsPerField, int ReasonEntries = MaximumReasonEntries,
        int ReportBytes = MaximumReportBytes, FieldRecordingVerification.Limits? Verification = null);

    public static JsonElement Summarize(string directory, CancellationToken cancellationToken = default) =>
        SummarizeBounded(directory, cancellationToken, new());

    internal static JsonElement SummarizeBounded(string directory, CancellationToken token, Limits limits, Action<long>? afterFrame = null)
    {
        if (limits.ReasonsPerField is < 1 or > MaximumReasonsPerField || limits.ReasonEntries is < 1 or > MaximumReasonEntries ||
            limits.ReportBytes is < 1 or > MaximumReportBytes)
            throw new ObservationException("invalid_arguments", "Invalid summary limits.");
        var clock = Stopwatch.StartNew(); using var sink = new SummarySink(token, limits, afterFrame);
        try
        {
            var verification = FieldRecordingVerification.VerifyBounded(directory, false, token, limits.Verification ?? new(), sink);
            if (!verification.valid)
                throw new ObservationException(verification.error_code == "cancelled" ? "cancelled" : "invalid_recording",
                    "Summary rejected: " + verification.error_code + ". No partial report was produced.");
            return sink.Finish(verification, clock.Elapsed.TotalMilliseconds);
        }
        catch (FieldRecordingVerification.SinkException e)
        {
            // Sink bounds/cancellation must not be relabeled as malformed source data by verifier handlers.
            ExceptionDispatchInfo.Capture(e.InnerException!).Throw(); throw;
        }
    }

    private sealed record ReadTime(long start_ticks, long end_ticks);
    private sealed record ComponentRange(int component, double? minimum, double? maximum);
    private sealed class FieldStats(string name, string type, int components, double? min, double? max, string? codec)
    {
        internal readonly string Name = name, Type = type;
        internal readonly double? DeclaredMin = min, DeclaredMax = max;
        internal readonly double?[] Min = new double?[components], Max = new double?[components];
        internal readonly Dictionary<string, long> Reasons = new(StringComparer.Ordinal);
        internal long Known, Unknown, Changes, AdjacentPairs, ReadIntervals, PreviousSlot = -1;
        internal double[]? Previous;
        internal ReadTime? FirstRead, LastRead, FirstObservedRead, LastObservedRead;
        internal long? MaximumReadDuration, MaximumObservedGap;
        internal object Report()
        {
            var report = new
        {
            name = Name, type = Type, declared_min = DeclaredMin, declared_max = DeclaredMax,
            observed_count = Known, unknown_count = Unknown, unknown_reasons = Reasons,
            components = Min.Select((value, n) => new ComponentRange(n, value, Max[n])).ToArray(),
            recorded_read_intervals = ReadIntervals, first_read = FirstRead, last_read = LastRead,
            first_observed_read = FirstObservedRead, last_observed_read = LastObservedRead,
            observed_numeric_changes = Changes, eligible_adjacent_observed_pairs = AdjacentPairs,
            largest_observed_sampling_gap_ticks = MaximumObservedGap, largest_read_duration_ticks = MaximumReadDuration
        };
            if (codec is null) return report;
            var enriched = System.Text.Json.JsonSerializer.SerializeToNode(report)!.AsObject();
            enriched["codec"] = codec; enriched["timing_kind"] = "operand_envelope";
            enriched["timing_note"] = "Read-time statistics describe the enclosing span of separate operand reads, not one physical read or atomic sample. Numeric changes are calculated observations.";
            return enriched;
        }
    }

    private sealed class SummarySink(CancellationToken token, Limits limits, Action<long>? afterFrame)
        : FieldRecordingVerification.IValidatedSink, IDisposable
    {
        private JsonDocument? profile, manifest;
        private JsonElement? summary;
        private FieldStats[] fields = [];
        private string manifestHash = "";
        private int reasonEntries;
        private long frames;
        private void Control()
        { if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Summary cancelled. No partial report was produced."); }
        public void Metadata(ReadOnlyMemory<byte> profileBytes, ReadOnlyMemory<byte> manifestBytes)
        {
            Control(); profile = JsonDocument.Parse(profileBytes); manifest = JsonDocument.Parse(manifestBytes);
            manifestHash = Convert.ToHexStringLower(SHA256.HashData(manifestBytes.Span));
            fields = profile.RootElement.GetProperty("fields").EnumerateArray().Select(f => new FieldStats(
                f.GetProperty("name").GetString()!, f.GetProperty("type").GetString()!,
                f.GetProperty("type").GetString() switch { "f32x3" => 3, "f32x4" or "i32x4" => 4, _ => 1 },
                f.TryGetProperty("min", out var min) ? min.GetDouble() : null,
                f.TryGetProperty("max", out var max) ? max.GetDouble() : null,
                f.TryGetProperty("codec", out var codec) ? codec.GetString() : null)).ToArray();
        }
        public void Chunk(ReadOnlyMemory<byte> json)
        {
            int start = 0;
            for (int n = 0; n < json.Length; n++)
            {
                if (json.Span[n] != (byte)'\n') continue;
                Control(); using var doc = JsonDocument.Parse(json.Slice(start, n - start)); start = n + 1;
                JsonElement row = doc.RootElement;
                if (row.GetProperty("kind").GetString() == "summary") { summary = row.Clone(); continue; }
                long slot = row.GetProperty("scheduled_slot").GetInt64(); var values = row.GetProperty("fields");
                foreach (var f in fields)
                {
                    JsonElement value = values.GetProperty(f.Name); ReadTime? read = null;
                    if (value.GetProperty("read_start_ticks").ValueKind != JsonValueKind.Null)
                    {
                        read = new(value.GetProperty("read_start_ticks").GetInt64(), value.GetProperty("read_end_ticks").GetInt64());
                        f.FirstRead ??= read; f.LastRead = read; f.ReadIntervals++;
                        f.MaximumReadDuration = Math.Max(f.MaximumReadDuration ?? 0, read.end_ticks - read.start_ticks);
                    }
                    if (value.GetProperty("status").GetString() == "unknown")
                    {
                        f.Unknown++; f.Previous = null; string reason = value.GetProperty("reason").GetString()!;
                        if (!f.Reasons.ContainsKey(reason))
                        {
                            if (f.Reasons.Count >= limits.ReasonsPerField || reasonEntries >= limits.ReasonEntries)
                                throw new ObservationException("summary_reason_limit", "Summary exceeds its distinct-reason bound. No reasons were silently omitted.");
                            reasonEntries++;
                        }
                        f.Reasons[reason] = f.Reasons.GetValueOrDefault(reason) + 1;
                        continue;
                    }
                    double[] observed = f.Min.Length == 1 ? [value.GetProperty("value").GetDouble()] :
                        value.GetProperty("value").EnumerateArray().Select(v => v.GetDouble()).ToArray();
                    f.Known++; f.FirstObservedRead ??= read;
                    if (f.LastObservedRead is { } last)
                        f.MaximumObservedGap = Math.Max(f.MaximumObservedGap ?? 0, read!.start_ticks - last.start_ticks);
                    f.LastObservedRead = read;
                    for (int component = 0; component < observed.Length; component++)
                    {
                        f.Min[component] = Math.Min(f.Min[component] ?? observed[component], observed[component]);
                        f.Max[component] = Math.Max(f.Max[component] ?? observed[component], observed[component]);
                    }
                    if (f.Previous is { } previous && slot == f.PreviousSlot + 1)
                    { f.AdjacentPairs++; if (!previous.SequenceEqual(observed)) f.Changes++; }
                    f.Previous = observed; f.PreviousSlot = slot;
                }
                frames++; afterFrame?.Invoke(frames); Control();
            }
        }
        public JsonElement Finish(FieldRecordingVerification.Result verified, double elapsedMs)
        {
            Control(); JsonElement p = profile!.RootElement, m = manifest!.RootElement, s = summary!.Value;
            var report = new
            {
                schema = "overwatch-decoder.field-summary/1", status = "summarized", complete = true,
                source_status = verified.status, source_complete = verified.complete,
                data_classification = "private_research", source = "process_memory",
                interpretation = "profile_declared_research", visibility = "research",
                runtime_semantics_validated = false, public_state_eligible = false, atomic = false,
                revision = Program.Revision, source_revision = m.TryGetProperty("revision", out var revision) && revision.ValueKind == JsonValueKind.String ? revision.GetString() : null,
                target = p.GetProperty("target"), profile_schema = p.GetProperty("schema"), stream_schema = s.GetProperty("schema"),
                profile_sha256 = verified.profile_sha256, manifest_sha256 = manifestHash,
                samples_sha256 = verified.samples_prefix_sha256, index_sha256 = verified.index_prefix_sha256,
                source_json_sha256 = verified.json_prefix_sha256,
                source_stop_reason = m.GetProperty("stop_reason"), stream_stop_reason = s.GetProperty("stop_reason"),
                frames = verified.frames, unknown_fields = verified.unknown_fields, skipped_intervals = verified.skipped_intervals,
                timing = new
                {
                    utc_origin = s.GetProperty("started_utc"), utc_origin_before_ticks = s.GetProperty("utc_origin_before_ticks"),
                    monotonic_origin_ticks = s.GetProperty("monotonic_origin_ticks"), monotonic_frequency = s.GetProperty("monotonic_frequency"),
                    finished_utc = s.GetProperty("finished_utc"), requested_interval_ms = s.GetProperty("requested_interval_ms"),
                    requested_duration_s = s.GetProperty("requested_duration_s"), source_elapsed_ms = s.GetProperty("elapsed_ms")
                },
                fields = fields.Select(f => f.Report()).ToArray(), summary_elapsed_ms = elapsedMs,
                maximum_reasons_per_field = limits.ReasonsPerField, maximum_reason_entries = limits.ReasonEntries,
                maximum_report_utf8_bytes = limits.ReportBytes,
                note = "Numeric changes are observations, not game events. A vector change counts once when any component differs. Comparisons require consecutive observed frames and consecutive scheduled slots; unknowns and missed slots break adjacency. Ranges use observed values only. Sampling gaps compare consecutive observed read starts, including gaps across unknowns or missed slots. Read intervals retain recorded timestamps; v1 does not always distinguish an unattempted read on a terminal control stop. No units, visibility, ownership, velocity or gameplay meaning are inferred. Names, values and reasons remain private research data; this is not anonymization."
            };
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(report);
            if (bytes.Length > limits.ReportBytes) throw new ObservationException("summary_byte_limit", "Summary exceeds its report byte bound. No partial report was produced.");
            Control(); using var doc = JsonDocument.Parse(bytes); JsonElement result = doc.RootElement.Clone(); Control(); return result;
        }
        public void Dispose() { profile?.Dispose(); manifest?.Dispose(); }
    }
}
