using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Bounded durable storage for the exact named-field JSONL contract. No additional interpretation.</summary>
public static class FieldRecording
{
    public const long MaximumJsonBytes = 32L * 1024 * 1024 * 1024;
    public const long MaximumCompressedBytes = 2L * 1024 * 1024 * 1024;
    public const long MaximumIndexBytes = 64L * 1024 * 1024;
    public const int MaximumChunkBytes = 1024 * 1024;
    private const long MinimumFreeBytes = 32L * 1024 * 1024;
    private const int TailReserve = 64 * 1024;
    internal sealed record Limits(long JsonBytes = MaximumJsonBytes, long CompressedBytes = MaximumCompressedBytes,
        long IndexBytes = MaximumIndexBytes, int ChunkBytes = MaximumChunkBytes);

    public static object Record(IMemorySource source, string profilePath, string outDirectory,
        int intervalMs, TimeSpan duration, CancellationToken token, bool stopOnUnknown = false, StorageRotation? storage = null) =>
        RecordBounded(source, profilePath, outDirectory, intervalMs, duration, token, new(), stopOnUnknown: stopOnUnknown, storage: storage);

    internal static object RecordBounded(IMemorySource source, string profilePath, string outDirectory,
        int intervalMs, TimeSpan duration, CancellationToken token, Limits limits,
        Action<FieldStream.AcceptedFrame>? acceptedFrame = null, long readBytes = FieldStream.MaximumReadBytes,
        bool stopOnUnknown = false, StorageRotation? storage = null, Action<StorageSeal>? cohortSealed = null)
    {
        storage?.Validate();
        if (intervalMs is < 10 or > 10_000 || duration <= TimeSpan.Zero || duration > TimeSpan.FromHours(10) ||
            limits.JsonBytes < 8192 || limits.JsonBytes > MaximumJsonBytes ||
            limits.CompressedBytes < TailReserve || limits.CompressedBytes > MaximumCompressedBytes ||
            limits.IndexBytes < 4096 || limits.IndexBytes > MaximumIndexBytes ||
            limits.ChunkBytes is < 8192 or > MaximumChunkBytes)
            throw new ObservationException("invalid_arguments", "Named recording limits, interval or duration are invalid.");
        if (Directory.Exists(outDirectory) || File.Exists(outDirectory))
            throw new ObservationException("output_exists", "Named recording destination must not already exist.");
        byte[] profileBytes = FieldStream.ValidatedProfileBytes(source, profilePath);
        string profileHash = Hash(profileBytes);
        using var profile = JsonDocument.Parse(profileBytes);
        JsonElement target = profile.RootElement.GetProperty("target").Clone();
        Directory.CreateDirectory(outDirectory);
        string savedProfile = Path.Combine(outDirectory, "profile.json");
        WriteNew(savedProfile, profileBytes);
        DateTimeOffset started = DateTimeOffset.UtcNow;
        object? streamSummary = null;
        string? failure = null;
        ChunkWriter? writer = null;
        using var epochStop = stopOnUnknown ? CancellationTokenSource.CreateLinkedTokenSource(token) : null;
        bool firstUnknown = false;
        string NormalizeSummary(string line)
        {
            if (!firstUnknown) return line;
            var summary = JsonSerializer.Deserialize<System.Text.Json.Nodes.JsonObject>(line)!;
            // Preserve explicit terminal errors; only our accepted-frame stop replaces the loop exit.
            if (summary["stop_reason"]?.GetValue<string>() is "cancelled" or "duration_elapsed")
            {
                summary["stop_reason"] = "first_unknown";
                summary["complete"] = false;
            }
            return summary.ToJsonString();
        }
        void Frame(FieldStream.AcceptedFrame frame)
        {
            if (stopOnUnknown && !token.IsCancellationRequested && frame.Terminal is null &&
                frame.Fields.Any(field => field.Value.status != "observed" && !(field.Value.Pool is not null && field.Value.reason == "pool_membership_changed")))
            {
                firstUnknown = true;
                epochStop!.Cancel();
            }
            acceptedFrame?.Invoke(frame);
        }
        object Manifest(string status)
        {
            var manifest = new
            {
                schema = "overwatch-decoder.field-recording/1", status, source = "process_memory",
                interpretation = "profile_declared_research", visibility = "research", public_state_eligible = false,
                runtime_semantics_validated = false, atomic = false, revision = Program.Revision, target,
                profile_sha256 = profileHash, started_utc = started,
                finished_utc = status == "recording" ? (DateTimeOffset?)null : DateTimeOffset.UtcNow,
                requested_interval_ms = intervalMs, requested_duration_s = duration.TotalSeconds,
                compression = "gzip_concatenated_members_whole_jsonl_lines",
                recovery = "Use complete index entries to validate and decode the durable samples prefix; ignore unindexed tail bytes.",
                samples_file = "samples.jsonl.gz", index_file = "chunks.jsonl", profile_file = "profile.json",
                durable_chunks = writer?.Chunks ?? 0, durable_lines = writer?.DurableLines ?? 0,
                durable_compressed_bytes = writer?.CompressedBytes ?? 0, durable_json_bytes = writer?.JsonBytes ?? 0,
                index_bytes = writer?.IndexBytes ?? 0, pending_lines = writer?.PendingLines ?? 0,
                samples_sha256 = writer?.SummaryWritten == true ? writer.SamplesHash : null,
                index_sha256 = writer?.SummaryWritten == true ? writer.IndexHash : null,
                durable_samples_prefix_sha256 = writer?.SamplesHash, durable_index_prefix_sha256 = writer?.IndexHash,
                terminal_summary_written = writer?.SummaryWritten ?? false,
                maximum_json_bytes = limits.JsonBytes, maximum_compressed_bytes = limits.CompressedBytes,
                maximum_index_bytes = limits.IndexBytes, maximum_chunk_json_bytes = limits.ChunkBytes,
                minimum_free_disk_bytes = MinimumFreeBytes, target_chunk_interval_ms = 1000,
                maximum_chunk_commit_ms = (writer?.MaximumCommitTicks ?? 0) * 1000d / Stopwatch.Frequency,
                total_chunk_commit_ms = (writer?.TotalCommitTicks ?? 0) * 1000d / Stopwatch.Frequency,
                failure, stream_summary = streamSummary,
                stop_reason = failure ?? (streamSummary is null ? null :
                    JsonSerializer.SerializeToElement(streamSummary).GetProperty("stop_reason").GetString()),
                complete = failure is null && writer?.SummaryWritten == true && streamSummary is not null &&
                    JsonSerializer.SerializeToElement(streamSummary).GetProperty("complete").GetBoolean(),
                note = "Frames retain every serialized field, unknown and read timestamp. Chunk compression and disk flush latency " +
                    "are part of measured output time and may skip sample slots. Hard termination can lose the pending chunk; " +
                    "synchronous blocked I/O can extend checkpoint intervals. No gameplay or realtime guarantee."
            };
            bool pointerProfile = profile.RootElement.GetProperty("schema").GetString() is "overwatch-decoder.field-profile/2" or "overwatch-decoder.field-profile/3" or "overwatch-decoder.field-profile/4";
            if (pointerProfile || storage is not null)
            {
                var metadata = JsonSerializer.SerializeToNode(manifest)!.AsObject();
                if (storage is not null)
                {
                    metadata["schema"] = "overwatch-decoder.field-recording/2";
                    metadata.Remove("samples_file"); metadata.Remove("index_file");
                    metadata["storage_index_file"] = "storage-index.jsonl";
                    metadata["storage_cohort_bytes"] = storage.CohortBytes;
                    metadata["maximum_storage_cohorts"] = storage.MaximumCohorts;
                    metadata["storage_cohorts"] = writer?.Storage?.SealedCount ?? 0;
                    metadata["storage_index_bytes"] = writer?.Storage?.IndexBytes ?? 0;
                    metadata["storage_index_sha256"] = writer?.SummaryWritten == true ? writer.Storage?.IndexHash : null;
                    metadata["durable_storage_index_prefix_sha256"] = writer?.Storage?.IndexHash;
                    metadata["recovery"] = "Validate the sealed storage-index chain and original chunks in one continuous frame state. Unsealed files and unindexed tails are not complete evidence.";
                }
                if (pointerProfile)
                {
                metadata["private_address_trace"] = true;
                metadata["profile_schema"] = profile.RootElement.GetProperty("schema").GetString();
                metadata["stream_schema"] = profile.RootElement.GetProperty("schema").GetString()!.Replace("field-profile", "field-stream", StringComparison.Ordinal);
                if (profile.RootElement.GetProperty("schema").GetString() is "overwatch-decoder.field-profile/3" or "overwatch-decoder.field-profile/4")
                    metadata["unpublished_read_accounting"] = GuardBatches.UnpublishedAccounting;
                }
                return metadata;
            }
            return manifest;
        }
        WriteManifest(outDirectory, Manifest("recording"));
        try
        {
            writer = new ChunkWriter(outDirectory, limits, stopOnUnknown ? NormalizeSummary : null, storage, profileHash, cohortSealed);
            streamSummary = FieldStream.RunBounded(source, savedProfile, intervalMs, duration, writer, epochStop?.Token ?? token,
                new(ReadBytes: readBytes, OutputBytes: limits.JsonBytes), stopOnUnknown ? Frame : acceptedFrame);
            if (firstUnknown)
                streamSummary = JsonSerializer.Deserialize<JsonElement>(NormalizeSummary(JsonSerializer.Serialize(streamSummary)));
        }
        catch (IOException) { failure = "output_io_error"; }
        catch (UnauthorizedAccessException) { failure = "output_permission_denied"; }
        catch (ObservationException e) { failure = e.Code; }
        finally
        {
            try { writer?.Dispose(); }
            catch (IOException) { failure ??= "output_io_error"; }
            catch (UnauthorizedAccessException) { failure ??= "output_permission_denied"; }
        }
        object result = Manifest("finished");
        // A physical output failure may also prevent this final manifest; the earlier manifest/index still describe recovery.
        WriteManifest(outDirectory, result);
        return result;
    }

    internal sealed class ChunkWriter : TextWriter, IFieldRecordingSink
    {
        public override Encoding Encoding => Encoding.UTF8;
        private readonly FileStream? samples;
        private readonly FileStream? index;
        private readonly MemoryStream pending = new();
        private readonly Limits limits;
        private readonly string directory;
        private readonly IncrementalHash sampleHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private readonly IncrementalHash indexHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long checkpoint = Stopwatch.GetTimestamp();
        private long diskChecked = Stopwatch.GetTimestamp() - Stopwatch.Frequency;
        private bool disposed;
        private readonly Func<string, string>? summaryTransform;
        public long Chunks { get; private set; }
        public long DurableLines { get; private set; }
        public long PendingLines { get; private set; }
        public long CompressedBytes { get; private set; }
        public long JsonBytes { get; private set; }
        public long IndexBytes { get; private set; }
        public string? SamplesHash { get; private set; }
        public string? IndexHash { get; private set; }
        public bool SummaryWritten { get; private set; }
        public long MaximumCommitTicks { get; private set; }
        public long TotalCommitTicks { get; private set; }
        internal FieldStorageCohorts? Storage { get; }
        private readonly StorageRotation? storageOptions;

        internal ChunkWriter(string directory, Limits limits, Func<string, string>? summaryTransform = null,
            StorageRotation? storage = null, string? profileHash = null, Action<StorageSeal>? cohortSealed = null)
        {
            this.directory = directory; this.limits = limits; this.summaryTransform = summaryTransform;
            storageOptions = storage;
            if (storage is not null)
            {
                Storage = new(directory, profileHash!, storage, limits.IndexBytes, () => IndexBytes, cohortSealed);
                return;
            }
            samples = new FileStream(Path.Combine(directory, "samples.jsonl.gz"), FileMode.CreateNew,
                FileAccess.Write, FileShare.Read, 64 * 1024);
            try
            {
                index = new FileStream(Path.Combine(directory, "chunks.jsonl"), FileMode.CreateNew,
                    FileAccess.Write, FileShare.Read, 4096);
            }
            catch { samples.Dispose(); throw; }
        }

        public string? WriteFrame(string line)
        {
            byte[] bytes = Line(line);
            if (bytes.Length > limits.ChunkBytes) return "recording_chunk_limit";
            long now = Stopwatch.GetTimestamp();
            if (now - diskChecked >= Stopwatch.Frequency)
            {
                if (new DriveInfo(Path.GetPathRoot(Path.GetFullPath(directory))!).AvailableFreeSpace < MinimumFreeBytes)
                    return "free_disk_limit";
                diskChecked = now;
            }
            if (pending.Length + bytes.Length > limits.ChunkBytes) Commit();
            if (Storage is not null)
            {
                // Reserve raw summary plus gzip overhead before accepting a frame. A cap refusal
                // leaves room for the ordinary terminal summary in the last allowed cohort.
                const int reserve = 16384;
                if (bytes.LongLength + reserve > storageOptions!.CohortBytes) return "storage_cohort_chunk_limit";
                if (Storage.NeedsSpace(pending.Length + bytes.Length + reserve))
                {
                    Commit();
                    if (Storage.NeedsSpace(bytes.Length + reserve) && !Storage.Rotate(Chunks, DurableLines))
                        return "storage_cohort_limit";
                }
            }
            // Reserve a conservative raw-size bound for this member plus the terminal summary. Gzip is never allowed
            // to consume the summary reserve. This may stop a little early near the cap, but never drops accepted frames.
            if (CompressedBytes + pending.Length + bytes.Length + 8192 > limits.CompressedBytes - TailReserve)
                return "compressed_byte_limit";
            if (IndexBytes + (Storage?.IndexBytes ?? 0) + (Storage is null ? 4096 : 8192) > limits.IndexBytes) return "index_byte_limit";
            pending.Write(bytes); PendingLines++;
            if (pending.Length >= limits.ChunkBytes || now - checkpoint >= Stopwatch.Frequency) Commit();
            return null;
        }

        public void WriteSummary(string line)
        {
            byte[] bytes = Line(summaryTransform?.Invoke(line) ?? line);
            if (bytes.Length > 8192) throw new IOException("Named recording summary exceeds its reserved size.");
            if (pending.Length + bytes.Length > limits.ChunkBytes) Commit();
            pending.Write(bytes); PendingLines++;
            Commit(); Storage?.Seal(true); SummaryWritten = true;
        }

        private void Commit()
        {
            if (PendingLines == 0) return;
            long commitStart = Stopwatch.GetTimestamp();
            // Compression and hashing finish synchronously before pending is reused. Include only
            // the live prefix: buffer capacity can retain bytes from a previous, larger member.
            ReadOnlySpan<byte> raw = pending.GetBuffer().AsSpan(0, checked((int)pending.Length));
            using var compressed = new MemoryStream();
            using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true)) gzip.Write(raw);
            byte[] member = compressed.ToArray();
            byte[] entry = Line(JsonSerializer.Serialize(new
            {
                schema = "overwatch-decoder.field-recording-chunk/1", sequence = Chunks, offset = Storage?.CurrentBytes ?? CompressedBytes,
                compressed_bytes = member.Length, json_bytes = raw.Length, first_line = DurableLines,
                lines = PendingLines, compressed_sha256 = Hash(member), json_sha256 = Hash(raw),
                checkpoint_ticks = Stopwatch.GetTimestamp(), monotonic_frequency = Stopwatch.Frequency
            }));
            if (member.Length > limits.CompressedBytes - CompressedBytes || entry.Length > limits.IndexBytes - IndexBytes)
                throw new IOException("Named recording reserved output bound was exceeded.");
            // Publish the durable index entry only after the whole gzip member has reached stable storage.
            if (Storage is not null) Storage.Write(member, entry, raw.Length, PendingLines);
            else
            {
                samples!.Write(member); samples.Flush(true);
                index!.Write(entry); index.Flush(true);
            }
            sampleHash.AppendData(member); indexHash.AppendData(entry);
            CompressedBytes += member.Length; JsonBytes += raw.Length; IndexBytes += entry.Length;
            Chunks++; DurableLines += PendingLines; PendingLines = 0;
            pending.SetLength(0); checkpoint = Stopwatch.GetTimestamp();
            long elapsed = checkpoint - commitStart;
            TotalCommitTicks += elapsed; MaximumCommitTicks = Math.Max(MaximumCommitTicks, elapsed);
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposing || disposed) return;
            disposed = true;
            // Never retry a failed write or silently publish a pending suffix during disposal.
            SamplesHash = Convert.ToHexStringLower(sampleHash.GetHashAndReset());
            IndexHash = Convert.ToHexStringLower(indexHash.GetHashAndReset());
            try { samples?.Dispose(); }
            finally { index?.Dispose(); Storage?.Dispose(); pending.Dispose(); sampleHash.Dispose(); indexHash.Dispose(); }
            base.Dispose(disposing);
        }

        private static byte[] Line(string text)
        {
            ReadOnlySpan<char> chars = text.AsSpan();
            byte[] bytes = new byte[checked(Encoding.UTF8.GetByteCount(chars) + 1)];
            Encoding.UTF8.GetBytes(chars, bytes);
            bytes[^1] = (byte)'\n';
            return bytes;
        }
    }

    private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static void WriteNew(string path, byte[] bytes)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        file.Write(bytes); file.Flush(true);
    }
    private static void WriteManifest(string directory, object value)
    {
        string pending = Path.Combine(directory, "manifest.pending.json");
        WriteNew(pending, JsonSerializer.SerializeToUtf8Bytes(value));
        File.Move(pending, Path.Combine(directory, "manifest.json"), true);
    }
}
