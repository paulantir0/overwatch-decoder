using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

public static class Snapshots
{
    public static object Probe(IMemorySource source)
    {
        var regions = source.Regions().ToList();
        var readable = regions.Where(r => r.Readable).ToList();
        int passed = 0, failed = 0;
        var errors = new Dictionary<string, int>();
        // Small permission probes; no returned bytes are exposed in the JSON.
        foreach (var r in readable.Take(8))
        {
            try { source.Read(r.Address, (int)Math.Min(64UL, r.Length)); passed++; }
            catch (ObservationException e)
            {
                if (e.Code is "permission_denied" or "process_exited" or "identity_mismatch") throw;
                failed++; errors[e.Code] = errors.GetValueOrDefault(e.Code) + 1;
            }
        }
        return new
        {
            target = PublicIdentity(source.Identity), region_count = regions.Count,
            readable_regions = readable.Count, readable_bytes = readable.Sum(r => (decimal)r.Length),
            read_probes_passed = passed, read_probes_failed = failed, errors,
            gameplay_decoder = "unavailable", gameplay_fields_validated = 0
        };
    }

    public static object PublicIdentity(TargetIdentity identity) => new
    {
        pid = identity.Pid, image_name = identity.ImageName,
        creation_file_time = identity.CreationFileTime,
        executable_sha256 = identity.ExecutableSha256, architecture = identity.Architecture
    };

    public static object Capture(IMemorySource source, string directory, long maximumBytes,
        TimeSpan duration, CancellationToken cancellation)
    {
        if (maximumBytes < 1 || duration <= TimeSpan.Zero)
            throw new ObservationException("invalid_arguments", "Snapshot byte and time limits must be positive.");
        if (Directory.Exists(directory) || File.Exists(directory))
            throw new ObservationException("output_exists", "Snapshot destination must not already exist.");
        Directory.CreateDirectory(directory);
        var start = DateTimeOffset.UtcNow;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        long bytes = 0, expected = 0; int chunks = 0, failures = 0;
        string stop = "complete";
        bool mapComplete = false;
        var regions = new List<MemoryRegion>();
        // The manifest and bytes are private research artifacts, never API gameplay data.
        using var records = new StreamWriter(Path.Combine(directory, "chunks.jsonl"), false);
        try
        {
            regions = source.Regions().Where(r => r.Readable).ToList();
            expected = checked(regions.Sum(r => checked((long)r.Length)));
            mapComplete = true;
            using var data = new FileStream(Path.Combine(directory, "memory.bin"), FileMode.CreateNew,
                FileAccess.Write, FileShare.None, NativeMemory.MaxRead);
            foreach (var region in regions)
            {
                for (ulong offset = 0; offset < region.Length;)
                {
                    if (cancellation.IsCancellationRequested) { stop = "cancelled"; goto Done; }
                    if (clock.Elapsed >= duration) { stop = "time_limit"; goto Done; }
                    if (bytes >= maximumBytes) { stop = "byte_limit"; goto Done; }
                    int size = (int)Math.Min((ulong)Math.Min(NativeMemory.MaxRead, maximumBytes - bytes), region.Length - offset);
                    ulong address = checked(region.Address + offset);
                    long monotonic = System.Diagnostics.Stopwatch.GetTimestamp();
                    try
                    {
                        byte[] chunk = source.Read(address, size);
                        long readEnd = System.Diagnostics.Stopwatch.GetTimestamp();
                        long fileOffset = data.Position;
                        data.Write(chunk);
                        bytes += chunk.Length; chunks++;
                        records.WriteLine(JsonSerializer.Serialize(new
                        {
                            address, length = size, file_offset = fileOffset,
                            sampled_utc = DateTimeOffset.UtcNow, monotonic_ticks = monotonic,
                            read_start_ticks = monotonic, read_end_ticks = readEnd,
                            protection = region.Protection, region_type = region.Type,
                            sha256 = Convert.ToHexStringLower(SHA256.HashData(chunk)), ok = true
                        }));
                    }
                    catch (ObservationException e)
                    {
                        long readEnd = System.Diagnostics.Stopwatch.GetTimestamp();
                        failures++;
                        records.WriteLine(JsonSerializer.Serialize(new
                        {
                            address, length = size, monotonic_ticks = monotonic,
                            read_start_ticks = monotonic, read_end_ticks = readEnd,
                            ok = false, error = e.Code, native_code = e.NativeCode
                        }));
                        if (e.Code is "permission_denied" or "process_exited" or "identity_mismatch")
                        { stop = e.Code; goto Done; }
                    }
                    offset += (ulong)size;
                }
            }
        Done:
            data.Flush(true);
        }
        catch (ObservationException e) { stop = e.Code; }
        catch (IOException) { stop = "io_error"; }
        finally { records.Flush(); }
        var summary = new
        {
            schema = "overwatch-decoder.memory-snapshot/1", source = "process_memory", visibility = "research",
            target = PublicIdentity(source.Identity), started_utc = start, finished_utc = DateTimeOffset.UtcNow,
            monotonic_frequency = System.Diagnostics.Stopwatch.Frequency,
            read_timing = "Chunk read_start_ticks and read_end_ticks enclose source.Read, including failed attempts, before file/report work. monotonic_ticks is a backward-compatible alias of read_start_ticks. sampled_utc is a later record-construction time, not an exact read boundary. Older chunks without read_end_ticks have unknown read duration.",
            elapsed_ms = clock.Elapsed.TotalMilliseconds, map_enumeration_complete = mapComplete,
            readable_bytes_at_start = expected, bytes_captured = bytes, chunks, failed_chunks = failures,
            maximum_bytes = maximumBytes, maximum_duration_s = duration.TotalSeconds,
            stop_reason = stop, complete = stop == "complete" && failures == 0 && bytes == expected,
            atomic = false, note = "Sequential read samples; target continues running. Not an atomic game-state snapshot."
        };
        File.WriteAllText(Path.Combine(directory, "manifest.json"), JsonSerializer.Serialize(summary, Program.Json) + "\n");
        return summary;
    }
}
