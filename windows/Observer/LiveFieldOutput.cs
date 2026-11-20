using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

// One synchronous bounded projection; never owns the caller's writer or queues frames.
internal sealed class LiveFieldOutput(TextWriter output, string sessionId, long maximum = LiveFieldOutput.MaximumBytes, bool includeEvidence = false)
{
    internal const long MaximumBytes = 512L * 1024 * 1024;
    internal const int MaximumLineBytes = FieldStream.MaximumLineBytes, EndReserve = 256 * 1024;
    internal string? LastEventSha256 { get; private set; }
    internal long Lines { get; private set; }
    internal long Bytes { get; private set; }
    internal string? Error { get; private set; }
    private long maximumWriteTicks, totalWriteTicks;
    private bool uncertainWrite;
    private FieldStream.Profile? identityProfile;
    private EntityIdentityProjection? identityProjection;
    internal object Status() => new
    {
        enabled = true, schema = "overwatch-decoder.field-live/1", completed_write_lines = Lines, completed_write_utf8_bytes = Bytes,
        maximum_utf8_bytes = maximum, maximum_line_utf8_bytes = MaximumLineBytes, error = Error,
        partial_or_unconfirmed_write_possible = uncertainWrite,
        maximum_write_ms = maximumWriteTicks * 1000d / Stopwatch.Frequency,
        total_write_ms = totalWriteTicks * 1000d / Stopwatch.Frequency,
        delivery = "Synchronous writer calls returned; downstream consumption and recording durability are not established. Counts exclude a failed or interrupted write."
    };
    internal bool Write(string kind, Action<Utf8JsonWriter> content, bool final = false)
    {
        if (Error is not null && !(final && Error is "live_output_byte_limit" or "live_line_byte_limit")) return false;
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject(); writer.WriteString("schema", "overwatch-decoder.field-live/1"); writer.WriteString("kind", kind);
            writer.WriteString("session_id", sessionId); writer.WriteNumber("event_sequence", Lines);
            writer.WriteNumber("emitted_ticks", Stopwatch.GetTimestamp()); writer.WriteNumber("monotonic_frequency", Stopwatch.Frequency);
            content(writer); writer.WriteEndObject(); writer.Flush();
        }
        buffer.WriteByte((byte)'\n');
        if (buffer.Length > MaximumLineBytes) { Error ??= "live_line_byte_limit"; return false; }
        if (buffer.Length > maximum - Bytes - (final ? 0 : EndReserve)) { Error ??= "live_output_byte_limit"; return false; }
        long start = Stopwatch.GetTimestamp();
        try
        {
            output.Write(Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length))); output.Flush();
            LastEventSha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length))));
            Lines++; Bytes += buffer.Length; return true;
        }
        catch (IOException) { Error = "live_output_io_error"; uncertainWrite = true; return false; }
        catch (UnauthorizedAccessException) { Error = "live_output_permission_denied"; uncertainWrite = true; return false; }
        catch (ObjectDisposedException) { Error = "live_output_closed"; uncertainWrite = true; return false; }
        catch (OperationCanceledException) { Error = "live_output_cancelled"; uncertainWrite = true; return false; }
        finally { long elapsed = Stopwatch.GetTimestamp() - start; totalWriteTicks += elapsed; maximumWriteTicks = Math.Max(maximumWriteTicks, elapsed); }
    }
    internal static void Property<T>(Utf8JsonWriter writer, string name, T value)
    { writer.WritePropertyName(name); JsonSerializer.Serialize(writer, value); }
    internal bool StorageSealed(int segment, int acquisition, string profileHash, int globalOrdinal, StorageSeal seal) =>
        Write("storage_cohort_sealed", w =>
        {
            w.WriteNumber("segment", segment); w.WriteNumber("acquisition", acquisition);
            w.WriteString("profile_sha256", profileHash); w.WriteNumber("storage_cohort_ordinal", globalOrdinal);
            Property(w, "index_record", seal.Record); w.WriteString("index_record_sha256", seal.RecordHash);
        });
    internal bool Frame(int segment, FieldStream.Profile profile, FieldStream.AcceptedFrame sample)
    {
        if (includeEvidence && sample.RecordingLine is null)
        { Error ??= "live_recording_evidence_missing"; return false; }
        if (!ReferenceEquals(identityProfile, profile))
        { identityProfile = profile; identityProjection = EntityIdentityProjection.Create(profile); }
        return Write("frame", w =>
        {
            var f = sample.Timing;
            w.WriteNumber("segment", segment); w.WriteString("profile_sha256", profile.Hash); Property(w, "target", f.target);
            w.WriteString("source", "process_memory"); w.WriteString("interpretation", "profile_declared_research");
            w.WriteString("data_classification", "private_research"); w.WriteBoolean("public_state_eligible", false);
            w.WriteBoolean("atomic", false); w.WriteString("recording_state", "accepted_not_durability_verified");
            w.WriteNumber("sequence", f.sequence); w.WriteNumber("scheduled_slot", f.scheduled_slot); w.WriteNumber("scheduled_ticks", f.scheduled_ticks);
            w.WriteNumber("start_ticks", f.start_ticks); w.WriteNumber("end_ticks", f.end_ticks); w.WriteNumber("jitter_ticks", f.jitter_ticks);
            w.WriteNumber("skipped_intervals_before", f.skipped_intervals_before); w.WriteNumber("skipped_intervals_total", f.skipped_intervals_total);
            Property(w, "utc_origin", f.utc_origin); w.WriteNumber("utc_origin_before_ticks", f.utc_origin_before_ticks); w.WriteNumber("monotonic_origin_ticks", f.monotonic_origin_ticks);
            w.WriteString("scheduler_backend", f.scheduler_backend); w.WriteBoolean("hard_realtime", false); w.WriteNumber("requested_interval_ms", f.requested_interval_ms);
            Property(w, "terminal_reason", sample.Terminal);
            w.WritePropertyName("fields"); w.WriteStartObject();
            foreach (var field in profile.Fields)
            {
                var value = sample.Fields[field.Name]; bool? attempted = sample.AttemptedFields is null ? null : sample.AttemptedFields[field.Name];
                bool bracket = !profile.V2 || field.Timer is not null || field.Pool is not null || attempted == true;
                w.WritePropertyName(field.Name); w.WriteStartObject(); w.WriteString("type", value.type); w.WriteString("status", value.status);
                w.WriteString("source", field.Timer is null && field.Pool is null ? "process_memory" : "calculated_process_memory");
                Property(w, "value", value.value); Property(w, "reason", value.reason);
                Property(w, "read_start_ticks", bracket ? value.read_start_ticks : null); Property(w, "read_end_ticks", bracket ? value.read_end_ticks : null);
                Property(w, "read_attempted", attempted); Property(w, "read_error", value.ReadError);
                if (field.Pool is { } pool)
                {
                    w.WriteString("codec", PoolSumCodec.Name); w.WriteNumber("pool_span", pool.Span);
                    Property(w, "pool_slots", pool.Slots); w.WriteString("read_kind", "operand_envelope");
                    w.WritePropertyName("operands"); w.WriteStartObject(); Operand(w, "snapshot_a", value.Pool!.snapshot_a); Operand(w, "snapshot_b", value.Pool.snapshot_b); w.WriteEndObject();
                }
                if (field.Timer is { } timer)
                {
                    w.WriteString("codec", TimerCodec.Name); w.WriteString("counter_scale_f32_hex", timer.ScaleHex); w.WriteString("read_kind", "operand_envelope");
                    w.WritePropertyName("operands"); w.WriteStartObject(); Operand(w, "state", value.Timer!.state); Operand(w, "clock", value.Timer.clock); w.WriteEndObject();
                }
                w.WriteEndObject();
            }
            w.WriteEndObject();
            identityProjection?.Write(w, sample.Fields);
            if (includeEvidence)
            {
                // Reuse the exact accepted wire representation, including v2+ enrichment.
                // The synchronous callback does not establish recording durability.
                w.WritePropertyName("recording_frame");
                w.WriteRawValue(sample.RecordingLine!, skipInputValidation: true);
            }
        });
    }
    private static void Operand(Utf8JsonWriter w, string name, TimerCodec.Operand operand)
    {
        w.WritePropertyName(name); w.WriteStartObject(); w.WriteBoolean("attempted", operand.attempted); w.WriteNumber("requested_bytes", operand.requested_bytes);
        Property(w, "returned_bytes", operand.returned_bytes); Property(w, "bytes_hex", operand.bytes_hex);
        Property(w, "start_ticks", operand.start_ticks); Property(w, "end_ticks", operand.end_ticks); Property(w, "error", operand.error); w.WriteEndObject();
    }
}
