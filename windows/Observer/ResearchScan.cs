using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Private numeric candidates, never a gameplay decoder.</summary>
public static class ResearchScan
{
    public record Candidate(ulong address, string bytes_hex, long sampled_ticks);

    public static byte[] Pattern(string type, string value)
    {
        const NumberStyles number = NumberStyles.Float;
        var culture = CultureInfo.InvariantCulture;
        if (type == "i32" && int.TryParse(value, NumberStyles.Integer, culture, out int i)) return BitConverter.GetBytes(i);
        if (type == "f32" && float.TryParse(value, number, culture, out float f) && float.IsFinite(f)) return BitConverter.GetBytes(f);
        if (type == "f64" && double.TryParse(value, number, culture, out double d) && double.IsFinite(d)) return BitConverter.GetBytes(d);
        throw new ObservationException("invalid_arguments", "Use a finite i32, f32 or f64 value.");
    }

    public static IEnumerable<int> Matches(byte[] bytes, byte[] pattern, ulong baseAddress)
    {
        int start = 0;
        while (start <= bytes.Length - pattern.Length)
        {
            int found = bytes.AsSpan(start).IndexOf(pattern);
            if (found < 0) yield break;
            int offset = start + found;
            if ((baseAddress + (ulong)offset) % (ulong)pattern.Length == 0) yield return offset;
            start = offset + 1;
        }
    }

    public static void NewDirectory(string directory)
    {
        if (Directory.Exists(directory) || File.Exists(directory))
            throw new ObservationException("output_exists", "Research output must not already exist.");
        Directory.CreateDirectory(directory);
    }

    public static object Scan(IMemorySource source, string directory, string type, string value,
        bool allReadable, int maximumCandidates, TimeSpan duration, CancellationToken cancellation)
    {
        byte[] pattern = Pattern(type, value);
        if (maximumCandidates < 1 || maximumCandidates > 1_000_000 || duration <= TimeSpan.Zero)
            throw new ObservationException("invalid_arguments", "Invalid candidate or time limit.");
        NewDirectory(directory);
        DateTimeOffset started = DateTimeOffset.UtcNow;
        var clock = Stopwatch.StartNew();
        int candidates = 0, failed = 0, chunks = 0; long bytes = 0, expected = 0;
        string stop = "complete";
        bool mapComplete = false;
        var errors = new Dictionary<string, int>();
        string candidatePath = Path.Combine(directory, "candidates.jsonl");
        using (var output = new StreamWriter(new FileStream(candidatePath, FileMode.CreateNew)))
        {
            try
            {
                var regions = source.Regions().Where(r => r.Readable && (allReadable ||
                    (r.Protection & 0xff) is 0x04 or 0x08 or 0x40 or 0x80)).ToList();
                expected = checked(regions.Sum(r => checked((long)r.Length)));
                mapComplete = true;
                foreach (var region in regions)
                {
                    for (ulong offset = 0; offset < region.Length;)
                    {
                        if (cancellation.IsCancellationRequested) { stop = "cancelled"; goto Done; }
                        if (clock.Elapsed >= duration) { stop = "time_limit"; goto Done; }
                        int length = (int)Math.Min((ulong)NativeMemory.MaxRead, region.Length - offset);
                        ulong address = checked(region.Address + offset);
                        long sampled = Stopwatch.GetTimestamp();
                        try
                        {
                            byte[] buffer = source.Read(address, length);
                            bytes += buffer.Length; chunks++;
                            foreach (int match in Matches(buffer, pattern, address))
                            {
                                // Seeing one additional match establishes actual truncation.
                                if (candidates == maximumCandidates) { stop = "candidate_limit"; goto Done; }
                                output.WriteLine(JsonSerializer.Serialize(new Candidate(address + (ulong)match,
                                    Convert.ToHexStringLower(pattern), sampled)));
                                candidates++;
                            }
                        }
                        catch (ObservationException e)
                        {
                            failed++; errors[e.Code] = errors.GetValueOrDefault(e.Code) + 1;
                            if (e.Code is "permission_denied" or "process_exited" or "identity_mismatch")
                            { stop = e.Code; goto Done; }
                        }
                        offset += (ulong)length;
                    }
                }
            }
            catch (ObservationException e) { stop = e.Code; }
        Done:;
        }
        var manifest = new
        {
            schema = "overwatch-decoder.memory-candidates/1", source = "process_memory", visibility = "research",
            runtime_semantics_validated = false, public_state_eligible = false,
            revision = Program.Revision, target = Snapshots.PublicIdentity(source.Identity), type, value,
            alignment = pattern.Length, scope = allReadable ? "readable" : "readable_writable",
            started_utc = started, finished_utc = DateTimeOffset.UtcNow, elapsed_ms = clock.Elapsed.TotalMilliseconds,
            monotonic_frequency = Stopwatch.Frequency, map_enumeration_complete = mapComplete,
            bytes_in_scope = expected, bytes_read = bytes, chunks, failed_chunks = failed, errors,
            candidates, maximum_candidates = maximumCandidates, stop_reason = stop,
            complete = stop == "complete" && failed == 0 && bytes == expected,
            atomic = false, candidates_sha256 = Hash(candidatePath)
        };
        SaveManifest(directory, manifest);
        return manifest;
    }

    public static string Hash(string path)
    {
        using var file = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(file));
    }

    public static void SaveManifest(string directory, object manifest) =>
        File.WriteAllText(Path.Combine(directory, "manifest.json"), JsonSerializer.Serialize(manifest, Program.Json) + "\n");

    public static JsonDocument OpenManifest(string directory)
    {
        var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "manifest.json")));
        if (doc.RootElement.GetProperty("schema").GetString() != "overwatch-decoder.memory-candidates/1")
        { doc.Dispose(); throw new ObservationException("invalid_manifest", "Unsupported candidate schema."); }
        string digest = Hash(Path.Combine(directory, "candidates.jsonl"));
        if (doc.RootElement.GetProperty("candidates_sha256").GetString() != digest)
        { doc.Dispose(); throw new ObservationException("digest_mismatch", "Candidate file digest does not match."); }
        return doc;
    }

    public static void MatchIdentity(IMemorySource source, JsonElement target)
    {
        if (source.Identity.Pid != target.GetProperty("pid").GetInt32() ||
            source.Identity.CreationFileTime != target.GetProperty("creation_file_time").GetInt64() ||
            source.Identity.ExecutableSha256 != target.GetProperty("executable_sha256").GetString())
            throw new ObservationException("identity_mismatch", "Candidates belong to a different process instance or build.");
        source.EnsureAlive();
    }

    public static object Refine(IMemorySource source, string input, string directory, string value,
        CancellationToken cancellation)
    {
        using var prior = OpenManifest(input);
        MatchIdentity(source, prior.RootElement.GetProperty("target"));
        string type = prior.RootElement.GetProperty("type").GetString()!;
        byte[] pattern = Pattern(type, value);
        NewDirectory(directory);
        var started = DateTimeOffset.UtcNow;
        var clock = Stopwatch.StartNew();
        int examined = 0, kept = 0, failed = 0;
        var errors = new Dictionary<string, int>();
        string stop = "complete";
        string outputPath = Path.Combine(directory, "candidates.jsonl");
        using (var output = new StreamWriter(new FileStream(outputPath, FileMode.CreateNew)))
        {
            ulong page = ulong.MaxValue, previous = 0;
            byte[]? cached = null;
            long sampled = 0;
            foreach (string line in File.ReadLines(Path.Combine(input, "candidates.jsonl")))
            {
                if (cancellation.IsCancellationRequested) { stop = "cancelled"; break; }
                var candidate = JsonSerializer.Deserialize<Candidate>(line) ?? throw new ObservationException("invalid_manifest", "Invalid candidate.");
                if (++examined > 1_000_000 || (examined > 1 && candidate.address <= previous) ||
                    candidate.address % (ulong)pattern.Length != 0 || candidate.bytes_hex.Length != pattern.Length * 2)
                    throw new ObservationException("invalid_manifest", "Candidates must be bounded, aligned and increasing.");
                previous = candidate.address;
                try
                {
                    ulong nextPage = candidate.address & ~4095UL;
                    if (nextPage != page)
                    {
                        page = nextPage; cached = null; sampled = Stopwatch.GetTimestamp();
                        try { cached = source.Read(page, 4096); }
                        catch (ObservationException e) when (e.Code is "unreadable_range" or "partial_read" || e.NativeCode == 299) { }
                    }
                    byte[] current;
                    if (cached is null) { sampled = Stopwatch.GetTimestamp(); current = source.Read(candidate.address, pattern.Length); }
                    else current = cached.AsSpan((int)(candidate.address - page), pattern.Length).ToArray();
                    if (current.AsSpan().SequenceEqual(pattern))
                    {
                        output.WriteLine(JsonSerializer.Serialize(new Candidate(candidate.address,
                            Convert.ToHexStringLower(current), sampled))); kept++;
                    }
                }
                catch (ObservationException e)
                {
                    failed++;
                    errors[e.Code] = errors.GetValueOrDefault(e.Code) + 1;
                    if (e.Code is "permission_denied" or "process_exited" or "identity_mismatch") { stop = e.Code; break; }
                }
            }
        }
        var manifest = new
        {
            schema = "overwatch-decoder.memory-candidates/1", source = "process_memory", visibility = "research",
            runtime_semantics_validated = false, public_state_eligible = false,
            revision = Program.Revision, target = Snapshots.PublicIdentity(source.Identity), type, value,
            parent_manifest_sha256 = Hash(Path.Combine(input, "manifest.json")),
            parent_complete = prior.RootElement.GetProperty("complete").GetBoolean(),
            started_utc = started, finished_utc = DateTimeOffset.UtcNow, elapsed_ms = clock.Elapsed.TotalMilliseconds,
            monotonic_frequency = Stopwatch.Frequency, candidates = kept, examined, failed_reads = failed, errors,
            stop_reason = stop, complete = stop == "complete" && failed == 0, atomic = false,
            completeness_scope = "Provided candidates only; does not establish exhaustive initial discovery or gameplay semantics.",
            candidates_sha256 = Hash(outputPath)
        };
        SaveManifest(directory, manifest);
        return manifest;
    }
}
