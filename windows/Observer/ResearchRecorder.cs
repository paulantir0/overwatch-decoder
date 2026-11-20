using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Private, timed byte observations. Candidate addresses have no established game meaning.</summary>
public static class ResearchRecorder
{
    public const int MaximumCandidates = 16_384;
    public const int MaximumPages = 4096;
    public const int PageSize = 4096;
    public const long MaximumCompressedBytes = 2L * 1024 * 1024 * 1024;
    public const long MaximumJsonBytes = 4L * 1024 * 1024 * 1024;
    public const long MaximumReadBytes = 512L * 1024 * 1024 * 1024;
    private const long MinimumFreeBytes = 32L * 1024 * 1024;
    private const long MaximumCandidateFileBytes = 8L * 1024 * 1024;
    private const long MaximumManifestBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(); // Explicit null means currently unknown.

    private sealed record Candidate(int id, ulong address, string baseline_bytes_hex, long baseline_sampled_ticks);
    private sealed record Page(int id, ulong address, Candidate[] candidates);
    private sealed record Change(int id, bool available, string? bytes_hex);
    private sealed record PageSample(int page_id, long start_ticks, long end_ticks, bool ok,
        string? error, int? native_code, Change[] changes);
    private sealed record Batch(string kind, long sequence, long scheduled_slot, long scheduled_ticks,
        long start_ticks, long end_ticks, long jitter_ticks, long skipped_intervals_before, PageSample[] pages);
    private sealed record Loaded(TargetIdentity identity, string type, int width, Candidate[] candidates,
        Page[] pages, string manifestHash, string candidatesHash);

    internal sealed record Limits(long CompressedBytes = MaximumCompressedBytes,
        long JsonBytes = MaximumJsonBytes, long ReadBytes = MaximumReadBytes);

    public static object Record(IMemorySource source, string candidateDirectory, string outDirectory,
        int intervalMs, TimeSpan duration, CancellationToken cancellation) =>
        RecordBounded(source, candidateDirectory, outDirectory, intervalMs, duration, cancellation, new());

    internal static object RecordBounded(IMemorySource source, string candidateDirectory, string outDirectory,
        int intervalMs, TimeSpan duration, CancellationToken cancellation, Limits limits)
    {
        if (intervalMs is < 10 or > 10_000 || duration <= TimeSpan.Zero || duration > TimeSpan.FromHours(10) ||
            limits.CompressedBytes <= 0 || limits.JsonBytes <= 0 || limits.ReadBytes <= 0)
            throw new ObservationException("invalid_arguments", "Interval must be 10..10000 ms; duration must be positive and at most 10 hours.");
        if (Directory.Exists(outDirectory) || File.Exists(outDirectory))
            throw new ObservationException("output_exists", "Recording destination must not already exist.");

        Loaded loaded = Load(source, candidateDirectory);
        Directory.CreateDirectory(outDirectory);
        string dictionaryPath = Path.Combine(outDirectory, "dictionary.jsonl");
        using (var dictionary = new StreamWriter(new FileStream(dictionaryPath, FileMode.CreateNew), new UTF8Encoding(false)))
            foreach (var candidate in loaded.candidates) dictionary.WriteLine(JsonSerializer.Serialize(candidate, Json));
        string dictionaryHash = Hash(dictionaryPath);
        string recordingPath = Path.Combine(outDirectory, "samples.jsonl.gz");
        using var scheduler = PreciseWait.Create(cancellation);
        long frequency = Stopwatch.Frequency;
        // UTC is bracketed by monotonic samples rather than claimed to be an exact simultaneous reading.
        long originBefore = Stopwatch.GetTimestamp();
        DateTimeOffset originUtc = DateTimeOffset.UtcNow;
        long origin = Stopwatch.GetTimestamp();
        long intervalTicks = Math.Max(1, (long)(intervalMs * (double)frequency / 1000));
        long durationTicks = (long)(duration.TotalSeconds * frequency);
        long deadline = checked(origin + durationTicks);
        long batches = 0, slotsSkipped = 0, readBytes = 0, successfulReadBytes = 0, jsonBytes = 0;
        long compressedBytes = 0, pageReads = 0, failedPages = 0, maximumJitter = 0, maximumBatch = 0;
        long slot = 0, lastKeyframe = long.MinValue, maximumWrite = 0;
        string?[] previous = new string?[loaded.candidates.Length];
        var errors = new Dictionary<string, long>();
        string stop = "duration_elapsed";
        bool finalizedStream = false;

        object Summary(string status, string? recordingHash) => new
        {
            schema = "overwatch-decoder.memory-recording/1", status, source = "process_memory", visibility = "research",
            runtime_semantics_validated = false, public_state_eligible = false, atomic = false,
            revision = Program.Revision, target = Snapshots.PublicIdentity(loaded.identity), loaded.type,
            candidate_count = loaded.candidates.Length, page_count = loaded.pages.Length,
            parent_manifest_sha256 = loaded.manifestHash, parent_candidates_sha256 = loaded.candidatesHash,
            dictionary_sha256 = dictionaryHash, samples_sha256 = recordingHash,
            compression = "gzip_concatenated_members_one_json_line_per_member",
            started_utc = originUtc, finished_utc = status == "recording" ? (DateTimeOffset?)null : DateTimeOffset.UtcNow,
            utc_origin_before_ticks = originBefore, monotonic_origin_ticks = origin,
            monotonic_frequency = frequency, requested_interval_ms = intervalMs, interval_ticks = intervalTicks,
            scheduler = scheduler.Diagnostics(),
            requested_duration_s = duration.TotalSeconds, elapsed_ms = (Stopwatch.GetTimestamp() - origin) * 1000d / frequency,
            batches, skipped_intervals = slotsSkipped, read_calls = pageReads, attempted_read_bytes = readBytes,
            successful_read_bytes = successfulReadBytes, failed_pages = failedPages, errors,
            maximum_jitter_ms = maximumJitter * 1000d / frequency,
            maximum_batch_ms = maximumBatch * 1000d / frequency, maximum_write_ms = maximumWrite * 1000d / frequency,
            uncompressed_json_bytes = jsonBytes, compressed_bytes = compressedBytes,
            maximum_candidates = MaximumCandidates, maximum_pages = MaximumPages,
            maximum_bytes_per_batch = MaximumPages * PageSize,
            maximum_compressed_bytes = limits.CompressedBytes, maximum_json_bytes = limits.JsonBytes,
            maximum_read_bytes = limits.ReadBytes, minimum_free_disk_bytes = MinimumFreeBytes,
            stop_reason = status == "recording" ? null : stop,
            complete = status == "finished" && stop == "duration_elapsed" && finalizedStream,
            all_reads_succeeded = failedPages == 0,
            note = "Sequential candidate bytes only. Keyframes replace all values; deltas replace listed values. " +
                "An unavailable value is unknown, never a retained current value. Page timestamps bound each read. " +
                "A completed recording may contain explicit read gaps. No hard realtime guarantee or gameplay interpretation."
        };

        WriteManifest(outDirectory, Summary("recording", null));
        try
        {
            using var output = new FileStream(recordingPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                64 * 1024, FileOptions.SequentialScan);
            long lastDiskCheck = origin - frequency;
            while (true)
            {
                if (cancellation.IsCancellationRequested) { stop = "cancelled"; break; }
                long scheduled = checked(origin + slot * intervalTicks);
                if (scheduled >= deadline) break;
                scheduler.WaitUntil(scheduled);
                if (cancellation.IsCancellationRequested) { stop = "cancelled"; break; }
                long start = Stopwatch.GetTimestamp();
                if (start >= deadline) break;
                long latestSlot = (start - origin) / intervalTicks;
                long skippedBefore = Math.Max(0, latestSlot - slot);
                slot += skippedBefore; slotsSkipped += skippedBefore;
                scheduled = origin + slot * intervalTicks;
                VerifyIdentity(source, loaded.identity);
                if (start - lastDiskCheck >= frequency)
                {
                    CheckFreeDisk(outDirectory);
                    lastDiskCheck = start;
                }
                bool keyframe = batches == 0 || start - lastKeyframe >= frequency;
                var samples = new List<PageSample>(loaded.pages.Length);
                bool stopAfterBatch = false;
                foreach (var page in loaded.pages)
                {
                    long readStart = Stopwatch.GetTimestamp();
                    string? error = null; int? nativeCode = null; byte[]? bytes = null;
                    if (stopAfterBatch) error = "not_sampled";
                    else if (cancellation.IsCancellationRequested)
                    { error = stop = "cancelled"; stopAfterBatch = true; }
                    else if (readStart >= deadline)
                    { error = "duration_elapsed"; stopAfterBatch = true; }
                    else if (readBytes > limits.ReadBytes - PageSize)
                    { error = stop = "read_byte_limit"; stopAfterBatch = true; }
                    else
                    {
                        try
                        {
                            readBytes += PageSize; pageReads++;
                            bytes = source.Read(page.address, PageSize);
                            if (bytes.Length != PageSize)
                                throw new ObservationException("partial_read", "Memory source returned an incomplete page.");
                            VerifyIdentity(source, loaded.identity);
                            successfulReadBytes += bytes.Length;
                        }
                        catch (ObservationException e)
                        {
                            bytes = null; error = e.Code; nativeCode = e.NativeCode;
                            if (Fatal(e.Code)) { stop = e.Code; stopAfterBatch = true; }
                        }
                    }
                    long readEnd = Stopwatch.GetTimestamp();
                    if (error is not null)
                    { failedPages++; errors[error] = errors.GetValueOrDefault(error) + 1; }
                    var changes = new List<Change>();
                    foreach (var candidate in page.candidates)
                    {
                        string? current = bytes is null ? null : Convert.ToHexStringLower(
                            bytes.AsSpan((int)(candidate.address - page.address), loaded.width));
                        if (keyframe || current != previous[candidate.id])
                            changes.Add(new(candidate.id, current is not null, current));
                        previous[candidate.id] = current;
                    }
                    samples.Add(new(page.id, readStart, readEnd, bytes is not null, error, nativeCode, changes.ToArray()));
                }
                long end = Stopwatch.GetTimestamp();
                var batch = new Batch(keyframe ? "keyframe" : "delta", batches, slot, scheduled,
                    start, end, start - scheduled, skippedBefore, samples.ToArray());
                byte[] serialized = JsonSerializer.SerializeToUtf8Bytes(batch, Json);
                if (serialized.LongLength + 1 > limits.JsonBytes - jsonBytes)
                { stop = "json_byte_limit"; break; }
                long writeStart = Stopwatch.GetTimestamp();
                byte[] member = CompressLine(serialized);
                if (member.LongLength > limits.CompressedBytes - compressedBytes)
                { stop = "compressed_byte_limit"; break; }
                // Finish each gzip member before appending it. A clean cancellation preserves all earlier members.
                output.Write(member); output.Flush();
                jsonBytes += serialized.LongLength + 1; compressedBytes += member.LongLength;
                maximumWrite = Math.Max(maximumWrite, Stopwatch.GetTimestamp() - writeStart);
                maximumJitter = Math.Max(maximumJitter, start - scheduled);
                maximumBatch = Math.Max(maximumBatch, end - start);
                if (keyframe) lastKeyframe = start;
                batches++; slot++;
                if (stopAfterBatch) break;
            }
            output.Flush(true);
            finalizedStream = true;
        }
        catch (ObservationException e) { stop = e.Code; errors[e.Code] = errors.GetValueOrDefault(e.Code) + 1; }
        catch (OperationCanceledException) { stop = "cancelled"; }
        catch (IOException) { stop = "io_error"; }
        catch (UnauthorizedAccessException) { stop = "output_permission_denied"; }
        string? hash = null;
        try
        {
            if (File.Exists(recordingPath))
            { compressedBytes = new FileInfo(recordingPath).Length; hash = Hash(recordingPath); }
        }
        catch (IOException) { stop = "io_error"; }
        var summary = Summary("finished", hash);
        WriteManifest(outDirectory, summary);
        return summary;
    }

    private static Loaded Load(IMemorySource source, string directory)
    {
        try
        {
            string manifestPath = Path.Combine(directory, "manifest.json");
            string candidatesPath = Path.Combine(directory, "candidates.jsonl");
            byte[] manifestBytes = ReadBounded(manifestPath, MaximumManifestBytes);
            byte[] candidateBytes = ReadBounded(candidatesPath, MaximumCandidateFileBytes);
            using var manifest = JsonDocument.Parse(manifestBytes);
            var root = manifest.RootElement;
            if (root.GetProperty("schema").GetString() != "overwatch-decoder.memory-candidates/1")
                throw new ObservationException("invalid_manifest", "Unsupported candidate schema.");
            string candidateHash = Convert.ToHexStringLower(SHA256.HashData(candidateBytes));
            if (!string.Equals(candidateHash, root.GetProperty("candidates_sha256").GetString(), StringComparison.OrdinalIgnoreCase))
                throw new ObservationException("digest_mismatch", "Candidate digest does not match the manifest.");
            var target = root.GetProperty("target");
            var identity = new TargetIdentity(target.GetProperty("pid").GetInt32(),
                target.GetProperty("image_name").GetString()!, "", target.GetProperty("creation_file_time").GetInt64(),
                target.GetProperty("executable_sha256").GetString()!, target.GetProperty("architecture").GetString()!);
            VerifyIdentity(source, identity);
            string type = root.GetProperty("type").GetString()!;
            int width = type switch { "i32" or "f32" => 4, "f64" => 8, _ => 0 };
            if (width == 0) throw new ObservationException("invalid_manifest", "Unsupported candidate type.");
            int expected = root.GetProperty("candidates").GetInt32();
            if (expected < 1 || expected > MaximumCandidates)
                throw new ObservationException("candidate_limit", "Candidate count must be between 1 and 16384; refine the input first.");
            var candidates = new List<Candidate>(expected);
            ulong previous = 0;
            using var reader = new StringReader(Encoding.UTF8.GetString(candidateBytes));
            while (reader.ReadLine() is { } line)
            {
                if (candidates.Count == MaximumCandidates)
                    throw new ObservationException("candidate_limit", "Candidate count exceeded 16384; refine the input first.");
                if (line.Length > 512 || line.Length == 0)
                    throw new ObservationException("invalid_manifest", "Invalid candidate record size.");
                using var item = JsonDocument.Parse(line);
                var value = item.RootElement;
                ulong address = value.GetProperty("address").GetUInt64();
                string hex = value.GetProperty("bytes_hex").GetString()!;
                if (address > (ulong)long.MaxValue - (ulong)width || address % (ulong)width != 0 ||
                    (candidates.Count != 0 && address <= previous) || hex.Length != width * 2 || !hex.All(Uri.IsHexDigit))
                    throw new ObservationException("invalid_manifest", "Candidates must be aligned, increasing, bounded addresses with valid bytes.");
                candidates.Add(new(candidates.Count, address, hex.ToLowerInvariant(), value.GetProperty("sampled_ticks").GetInt64()));
                previous = address;
            }
            if (candidates.Count != expected)
                throw new ObservationException("invalid_manifest", "Candidate count does not match the manifest.");
            var pages = candidates.GroupBy(c => c.address & ~4095UL)
                .Select((group, index) => new Page(index, group.Key, group.ToArray())).ToArray();
            if (pages.Length > MaximumPages)
                throw new ObservationException("page_limit", "Candidates span more than 4096 pages; refine the input first.");
            return new(identity, type, width, candidates.ToArray(), pages,
                Convert.ToHexStringLower(SHA256.HashData(manifestBytes)), candidateHash);
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException or NullReferenceException)
        { throw new ObservationException("invalid_manifest", "Malformed candidate manifest or records."); }
    }

    private static void VerifyIdentity(IMemorySource source, TargetIdentity expected)
    {
        source.EnsureAlive();
        var actual = source.Identity;
        if (actual.Pid != expected.Pid || actual.CreationFileTime != expected.CreationFileTime ||
            !string.Equals(actual.ExecutableSha256, expected.ExecutableSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(actual.ImageName, expected.ImageName, StringComparison.OrdinalIgnoreCase) ||
            actual.Architecture != expected.Architecture)
            throw new ObservationException("identity_mismatch", "Candidates belong to a different process instance or executable.");
    }

    private static bool Fatal(string code) => code is "permission_denied" or "process_exited" or "identity_mismatch";

    private static void CheckFreeDisk(string directory)
    {
        string root = Path.GetPathRoot(Path.GetFullPath(directory))!;
        if (new DriveInfo(root).AvailableFreeSpace < MinimumFreeBytes)
            throw new ObservationException("disk_space_limit", "Recording stopped before exhausting the output volume.");
    }

    private static byte[] CompressLine(byte[] json)
    {
        using var memory = new MemoryStream();
        using (var gzip = new GZipStream(memory, CompressionLevel.Fastest, true))
        { gzip.Write(json); gzip.WriteByte((byte)'\n'); }
        return memory.ToArray();
    }

    private static string Hash(string path)
    { using var file = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }

    private static byte[] ReadBounded(string path, long maximum)
    {
        using var input = File.OpenRead(path);
        if (input.Length > maximum)
            throw new ObservationException("candidate_file_limit", "Candidate input exceeds the bounded file size.");
        using var output = new MemoryStream();
        byte[] buffer = new byte[8192];
        while (true)
        {
            // Check actual bytes too: a file may grow after the length check.
            int read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, maximum - output.Length + 1));
            if (read == 0) return output.ToArray();
            if (read > maximum - output.Length)
                throw new ObservationException("candidate_file_limit", "Candidate input exceeds the bounded file size.");
            output.Write(buffer, 0, read);
        }
    }

    private static void WriteManifest(string directory, object summary)
    {
        string temporary = Path.Combine(directory, "manifest.json.tmp");
        File.WriteAllText(temporary, JsonSerializer.Serialize(summary, Json) + "\n", new UTF8Encoding(false));
        File.Move(temporary, Path.Combine(directory, "manifest.json"), true);
    }
}
