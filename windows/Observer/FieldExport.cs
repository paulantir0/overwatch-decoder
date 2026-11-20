using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Offline, lossless-in-frames projection. Does not open a target process or copy private address traces.</summary>
public static class FieldExport
{
    public const long MaximumOutputBytes = 8L * 1024 * 1024 * 1024;
    internal const int MaximumLineBytes = FieldStream.MaximumLineBytes;
    internal sealed record Limits(long OutputBytes = MaximumOutputBytes,
        FieldRecordingVerification.Limits? Verification = null);
    public sealed record Result(string schema, string status, bool complete, string source_status,
        bool source_complete, long frames, long unknown_fields, long skipped_intervals, long output_lines,
        long output_utf8_bytes, string output_sha256, string profile_sha256, string manifest_sha256,
        string samples_sha256, string index_sha256, string source_json_sha256, double elapsed_ms);

    public static Result Export(string directory, string outputPath, CancellationToken cancellationToken = default) =>
        ExportBounded(directory, outputPath, cancellationToken, new());

    internal static Result ExportBounded(string directory, string outputPath, CancellationToken token, Limits limits,
        Action<long>? afterLine = null)
    {
        var timer = Stopwatch.StartNew();
        if (limits.OutputBytes is < 1 or > MaximumOutputBytes)
            throw new ObservationException("invalid_arguments", "Invalid export output bound.");
        string destination = Path.GetFullPath(outputPath), source = Path.GetFullPath(directory);
        // Keep even transient export files out of the source recording, including its descendants.
        if (Inside(source, destination))
            throw new ObservationException("invalid_arguments", "Export destination must be outside the source recording.");
        if (Path.Exists(destination)) throw new ObservationException("output_exists", "Export destination already exists.");
        if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Export cancelled.");
        string temporary = Path.Combine(Path.GetDirectoryName(destination)!, ".overwatch-decoder-export-" + Guid.NewGuid().ToString("N") + ".partial");
        bool created = false;
        try
        {
            if (Directory.Exists(source) && Inside(ResolveDirectory(source),
                Path.Combine(ResolveDirectory(Path.GetDirectoryName(destination)!), Path.GetFileName(destination))))
                throw new ObservationException("invalid_arguments", "Export destination must be outside the source recording.");
            using var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024);
            created = true;
            using var sink = new ExportSink(output, limits.OutputBytes, token, afterLine);
            var verified = FieldRecordingVerification.VerifyBounded(directory, false, token, limits.Verification ?? new(), sink);
            if (!verified.valid)
                throw new ObservationException(verified.error_code == "cancelled" ? "cancelled" : "invalid_recording",
                    "Export rejected: " + verified.error_code + ". No final output was published.");
            sink.Finish(verified);
            output.Flush(true);
            if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Export cancelled.");
            string hash = sink.Hash;
            long bytes = output.Position;
            output.Dispose();
            // This is the publication boundary: no overwrite, including an output created after preflight.
            File.Move(temporary, destination, overwrite: false);
            created = false;
            return new("overwatch-decoder.field-export-result/1", "exported", true, verified.status, verified.complete,
                verified.frames, verified.unknown_fields, verified.skipped_intervals, sink.Lines, bytes, hash,
                verified.profile_sha256!, sink.ManifestHash, verified.samples_prefix_sha256,
                verified.index_prefix_sha256, verified.json_prefix_sha256, timer.Elapsed.TotalMilliseconds);
        }
        catch (FieldRecordingVerification.SinkException e)
        {
            if (e.InnerException is ObservationException known) ExceptionDispatchInfo.Capture(known).Throw();
            if (e.InnerException is OperationCanceledException) throw new ObservationException("cancelled", "Export cancelled.");
            if (e.InnerException is UnauthorizedAccessException) throw new ObservationException("output_permission_denied", "Export output access denied.");
            if (e.InnerException is IOException) throw new ObservationException("output_io_error", "Export output write failed.");
            throw;
        }
        catch (UnauthorizedAccessException) { throw new ObservationException("output_permission_denied", "Export output access denied."); }
        catch (IOException)
        {
            throw new ObservationException(Path.Exists(destination) ? "output_exists" : "output_io_error",
                "Export output could not be published.");
        }
        finally
        {
            // Abrupt process termination may leave only an explicitly named .partial file, never the destination.
            if (created) File.Delete(temporary);
        }
    }

    internal static bool Inside(string directory, string path)
    {
        string relative = Path.GetRelativePath(directory, path);
        return !Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }
    internal static string ResolveDirectory(string path)
    {
        string full = Path.GetFullPath(path), current = Path.GetPathRoot(full)!;
        foreach (string part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var directory = new DirectoryInfo(Path.Combine(current, part));
            current = directory.ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? directory.FullName;
        }
        return current;
    }

    private sealed class ExportSink(FileStream output, long maximum, CancellationToken token, Action<long>? afterLine)
        : FieldRecordingVerification.IValidatedSink, IDisposable
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private JsonDocument? profile, manifest;
        private JsonElement? summary;
        private bool headerWritten;
        private EntityIdentityProjection? identityProjection;
        public long Lines { get; private set; }
        public string ManifestHash { get; private set; } = "";
        public string Hash => Convert.ToHexStringLower(hash.GetCurrentHash());
        public void Metadata(ReadOnlyMemory<byte> profileBytes, ReadOnlyMemory<byte> manifestBytes)
        {
            profile = JsonDocument.Parse(profileBytes); manifest = JsonDocument.Parse(manifestBytes);
            identityProjection = EntityIdentityProjection.Create(FieldStream.ParseProfileBytes(profileBytes.ToArray()));
            ManifestHash = Convert.ToHexStringLower(SHA256.HashData(manifestBytes.Span));
        }
        private void Control()
        { if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Export cancelled."); }
        private void Line(Action<Utf8JsonWriter> write)
        {
            Control();
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer)) { write(writer); writer.Flush(); }
            buffer.WriteByte((byte)'\n');
            if (buffer.Length > MaximumLineBytes || buffer.Length > maximum - output.Position)
                throw new ObservationException("export_byte_limit", "Export output exceeds its byte bound.");
            ReadOnlySpan<byte> bytes = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
            output.Write(bytes); hash.AppendData(bytes); Lines++;
            afterLine?.Invoke(Lines); Control();
        }
        private static void Copy(Utf8JsonWriter writer, JsonElement source, params string[] names)
        {
            foreach (string name in names)
                if (source.TryGetProperty(name, out var value)) { writer.WritePropertyName(name); value.WriteTo(writer); }
        }
        private static void Begin(Utf8JsonWriter w, string kind)
        { w.WriteStartObject(); w.WriteString("schema", "overwatch-decoder.field-timeline/1"); w.WriteString("kind", kind); }
        private void Header(JsonElement first)
        {
            JsonElement p = profile!.RootElement, m = manifest!.RootElement;
            Line(w =>
            {
                Begin(w, "metadata");
                w.WriteString("source", "process_memory"); w.WriteString("interpretation", "profile_declared_research");
                w.WriteString("data_classification", "private_research");
                w.WriteString("visibility", "research"); w.WriteBoolean("public_state_eligible", false);
                w.WriteBoolean("runtime_semantics_validated", false); w.WriteBoolean("atomic", false);
                w.WriteBoolean("hard_realtime", false); w.WriteBoolean("address_traces_included", false);
                w.WriteString("exporter_revision", Program.Revision);
                w.WriteString("source_recording_schema", m.GetProperty("schema").GetString());
                w.WriteString("source_profile_schema", p.GetProperty("schema").GetString());
                w.WriteString("source_stream_schema", first.GetProperty("schema").GetString());
                w.WriteString("source_manifest_sha256", ManifestHash);
                w.WritePropertyName("source_recording"); w.WriteStartObject();
                Copy(w, m, "revision", "started_utc", "finished_utc", "complete", "stop_reason", "failure",
                    "samples_sha256", "index_sha256", "durable_json_bytes", "durable_compressed_bytes", "durable_lines", "durable_chunks");
                w.WriteEndObject();
                Copy(w, m, "target", "profile_sha256", "requested_interval_ms", "requested_duration_s");
                Copy(w, first, "utc_origin_before_ticks", "monotonic_origin_ticks", "monotonic_frequency");
                w.WritePropertyName("utc_origin");
                first.GetProperty(first.GetProperty("kind").GetString() == "frame" ? "utc_origin" : "started_utc").WriteTo(w);
                w.WriteString("utc_mapping", "utc_origin + (ticks - monotonic_origin_ticks) / monotonic_frequency seconds; origin sampled between utc_origin_before_ticks and monotonic_origin_ticks");
                w.WritePropertyName("fields"); w.WriteStartArray();
                foreach (var field in p.GetProperty("fields").EnumerateArray())
                { w.WriteStartObject(); Copy(w, field, "name", "type", "min", "max", "codec", "counter_scale_f32_hex"); w.WriteEndObject(); }
                w.WriteEndArray();
                w.WriteString("note", "Every recorded frame is retained. Labels are profile declarations, not validated gameplay meanings or visibility. Guard and address evidence is omitted; hashes identify the private recording needed to audit it. Numeric field values and labels are not general-purpose redacted.");
                w.WriteEndObject();
            });
            headerWritten = true;
        }
        public void Chunk(ReadOnlyMemory<byte> json)
        {
            int start = 0;
            for (int n = 0; n < json.Length; n++)
            {
                if (json.Span[n] != (byte)'\n') continue;
                Control(); using var doc = JsonDocument.Parse(json.Slice(start, n - start)); start = n + 1;
                JsonElement e = doc.RootElement;
                if (!headerWritten) Header(e);
                if (e.GetProperty("kind").GetString() == "summary") { summary = e.Clone(); continue; }
                Line(w =>
                {
                    Begin(w, "frame");
                    Copy(w, e, "sequence", "scheduled_slot", "scheduled_ticks", "start_ticks", "end_ticks", "jitter_ticks",
                        "skipped_intervals_before", "skipped_intervals_total", "scheduler_backend");
                    w.WritePropertyName("fields"); w.WriteStartObject();
                    foreach (var field in e.GetProperty("fields").EnumerateObject())
                    {
                        w.WritePropertyName(field.Name); w.WriteStartObject();
                        Copy(w, field.Value, "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks", "read_attempted", "read_error");
                        TimerCodec.CopyCompact(w, field.Value);
                        w.WriteEndObject();
                    }
                    w.WriteEndObject();
                    identityProjection?.Write(w, e.GetProperty("fields"));
                    w.WriteEndObject();
                });
            }
        }
        public void Finish(FieldRecordingVerification.Result verification)
        {
            if (summary is not { } s || !headerWritten) throw new ObservationException("invalid_recording", "Missing export summary.");
            Line(w =>
            {
                Begin(w, "summary"); w.WriteString("source_verification_status", verification.status);
                w.WriteBoolean("source_recording_complete", verification.complete);
                w.WriteString("source_json_sha256", verification.json_prefix_sha256);
                Copy(w, s, "started_utc", "finished_utc", "requested_duration_s", "elapsed_ms", "frames", "skipped_intervals",
                    "unknown_fields", "read_calls", "read_bytes", "frame_output_utf8_bytes", "maximum_jitter_ms", "maximum_frame_ms",
                    "maximum_write_ms", "stop_reason", "complete");
                Copy(w, s, "published_frame_read_calls", "published_frame_read_bytes", "published_frame_guard_gap_bytes",
                    "unpublished_frames", "unpublished_read_accounting", "unpublished_frame_read_calls", "unpublished_frame_read_bytes",
                    "unpublished_frame_guard_gap_bytes", "guard_gap_read_bytes");
                w.WriteEndObject();
            });
        }
        public void Dispose() { profile?.Dispose(); manifest?.Dispose(); hash.Dispose(); }
    }
}
