using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Searches saved, hash-checked chunks. Never reads the live process.</summary>
public static class SnapshotSearch
{
    public static object Find(string input, string output, string text, string encoding,
        int maximumMatches, CancellationToken cancellation)
    {
        if (text.Length is < 2 or > 256 || maximumMatches is < 1 or > 100000)
            throw new ObservationException("invalid_arguments", "Text must be 2..256 characters; match limit 1..100000.");
        byte[] pattern = encoding switch
        {
            "utf8" => Encoding.UTF8.GetBytes(text), "utf16" => Encoding.Unicode.GetBytes(text),
            _ => throw new ObservationException("invalid_arguments", "Encoding must be utf8 or utf16.")
        };
        using var original = JsonDocument.Parse(File.ReadAllText(Path.Combine(input, "manifest.json")));
        if (original.RootElement.GetProperty("schema").GetString() != "overwatch-decoder.memory-snapshot/1")
            throw new ObservationException("invalid_manifest", "Unsupported snapshot schema.");
        ResearchScan.NewDirectory(output);
        var clock = Stopwatch.StartNew();
        var started = DateTimeOffset.UtcNow;
        int chunks = 0, gaps = 0, matches = 0;
        long checkedBytes = 0;
        string stop = "complete";
        string matchesPath = Path.Combine(output, "matches.jsonl");
        using (var file = File.OpenRead(Path.Combine(input, "memory.bin")))
        using (var results = new StreamWriter(new FileStream(matchesPath, FileMode.CreateNew)))
        {
            foreach (string line in File.ReadLines(Path.Combine(input, "chunks.jsonl")))
            {
                if (cancellation.IsCancellationRequested) { stop = "cancelled"; break; }
                if (clock.Elapsed >= TimeSpan.FromMinutes(10)) { stop = "time_limit"; break; }
                if (++chunks > 1_000_000 || line.Length > 65536)
                    throw new ObservationException("invalid_manifest", "Snapshot record limit exceeded.");
                using var doc = JsonDocument.Parse(line);
                var r = doc.RootElement;
                if (!r.GetProperty("ok").GetBoolean()) { gaps++; continue; }
                long readStart = r.GetProperty("monotonic_ticks").GetInt64();
                if (r.TryGetProperty("read_start_ticks", out var explicitStart) &&
                    (explicitStart.ValueKind != JsonValueKind.Number || !explicitStart.TryGetInt64(out long declaredStart) || declaredStart != readStart))
                    throw new ObservationException("invalid_manifest", "Snapshot read start disagrees with its legacy start marker.");
                long? readEnd = null;
                if (r.TryGetProperty("read_end_ticks", out var explicitEnd) && explicitEnd.ValueKind != JsonValueKind.Null)
                {
                    if (explicitEnd.ValueKind != JsonValueKind.Number || !explicitEnd.TryGetInt64(out long declaredEnd) || declaredEnd < readStart)
                        throw new ObservationException("invalid_manifest", "Invalid snapshot read end.");
                    readEnd = declaredEnd;
                }
                int length = r.GetProperty("length").GetInt32();
                long offset = r.GetProperty("file_offset").GetInt64();
                ulong address = r.GetProperty("address").GetUInt64();
                if (length is < 1 or > NativeMemory.MaxRead || offset < 0 || offset > file.Length - length ||
                    address > (ulong)long.MaxValue - (ulong)length)
                    throw new ObservationException("invalid_manifest", "Invalid snapshot byte range.");
                file.Position = offset;
                byte[] bytes = new byte[length]; file.ReadExactly(bytes);
                string hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
                if (hash != r.GetProperty("sha256").GetString())
                    throw new ObservationException("digest_mismatch", "Snapshot chunk hash does not match.");
                checkedBytes += length;
                int position = 0;
                while (position <= bytes.Length - pattern.Length)
                {
                    int found = bytes.AsSpan(position).IndexOf(pattern);
                    if (found < 0) break;
                    int at = position + found;
                    position = at + 1;
                    if (encoding == "utf16" && (address + (ulong)at) % 2 != 0) continue;
                    if (matches == maximumMatches) { stop = "match_limit"; goto Done; }
                    results.WriteLine(JsonSerializer.Serialize(new
                    {
                        address = address + (ulong)at, bytes = pattern.Length,
                        sampled_ticks = readStart, read_start_ticks = readStart, read_end_ticks = readEnd,
                        sampled_utc = r.GetProperty("sampled_utc").GetString(),
                        source_chunk_address = address, source_chunk_length = length,
                        source_chunk_file_offset = offset, source_chunk_sha256 = hash
                    }));
                    matches++;
                }
            }
        Done:;
        }
        var manifest = new
        {
            schema = "overwatch-decoder.snapshot-text-search/1", source = "captured_process_memory", visibility = "research",
            runtime_semantics_validated = false, public_state_eligible = false,
            target = original.RootElement.GetProperty("target").Clone(),
            snapshot_manifest_sha256 = ResearchScan.Hash(Path.Combine(input, "manifest.json")),
            snapshot_complete = original.RootElement.GetProperty("complete").GetBoolean(),
            monotonic_frequency = original.RootElement.GetProperty("monotonic_frequency").GetInt64(),
            read_timing = "Match read_start_ticks and sampled_ticks are the source chunk read start. read_end_ticks is copied when recorded, otherwise null; legacy read duration is unknown. sampled_utc is the original later record-construction time, not an exact read boundary.",
            revision = Program.Revision, encoding, query = text, maximum_matches = maximumMatches,
            started_utc = started, finished_utc = DateTimeOffset.UtcNow, elapsed_ms = clock.Elapsed.TotalMilliseconds,
            matches, records_visited = chunks, source_read_gaps = gaps, hash_verified_bytes = checkedBytes,
            stop_reason = stop, complete = stop == "complete", matches_sha256 = ResearchScan.Hash(matchesPath),
            coverage = "Within successful chunks only. Matches spanning chunk boundaries are excluded; snapshot gaps and temporal skew remain."
        };
        ResearchScan.SaveManifest(output, manifest);
        return manifest;
    }
}
