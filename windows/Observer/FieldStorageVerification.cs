using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

public static partial class FieldRecordingVerification
{
    private sealed record StorageInput(string Directory, long FirstChunk, long Chunks, long FirstLine, long Lines,
        long CompressedBytes, long JsonBytes, long IndexBytes, string SamplesHash, string IndexHash, bool Terminal);
    private sealed record StoragePlan(StorageInput[] Inputs, long IndexBytes, string IndexHash, long CohortBytes);

    private static void NotLink(string path) =>
        Need((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "storage_path_link");

    private static StoragePlan ReadStoragePlan(string directory, JsonElement manifest, string profileHash,
        Limits limits, Action control)
    {
        Need(Text(manifest, "storage_index_file") == "storage-index.jsonl", "invalid_storage_index_path");
        long cohortBytes = Number(manifest, "storage_cohort_bytes"), maximum = Number(manifest, "maximum_storage_cohorts");
        Need(cohortBytes is >= StorageRotation.MinimumBytes and <= StorageRotation.MaximumBytes &&
            maximum is >= 1 and <= StorageRotation.MaximumCount, "invalid_storage_limits");
        NotLink(directory); string path = Path.Combine(directory, "storage-index.jsonl"); NotLink(path);
        using var file = Open(path); long length = file.Length;
        Need(length <= limits.IndexBytes && length <= 4096L * StorageRotation.MaximumCount, "storage_index_byte_limit");
        var entries = new List<StorageInput>(); using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long chunks = 0, lines = 0, compressed = 0, json = 0, indexed = 0; string? previous = null; bool terminal = false;
        while (file.Position < length)
        {
            control(); Need(entries.Count < maximum && !terminal, "storage_cohort_count_or_terminal_order");
            byte[] raw = ReadIndexLine(file, length); using var document = Parse(raw); JsonElement entry = document.RootElement;
            Keys(entry, "schema", "ordinal", "directory", "profile_sha256", "previous_record_sha256", "first_chunk", "chunks",
                "first_line", "lines", "compressed_bytes", "json_bytes", "index_bytes", "samples_sha256", "index_sha256", "terminal_summary_included");
            string name = "storage-" + (entries.Count + 1).ToString("D6");
            Need(Text(entry, "schema") == "overwatch-decoder.field-storage-cohort/1" && Number(entry, "ordinal") == entries.Count + 1 &&
                Text(entry, "directory") == name && Digest(entry, "profile_sha256") == profileHash &&
                Number(entry, "first_chunk") == chunks && Number(entry, "first_line") == lines, "storage_order_or_profile");
            Need(previous is null ? entry.GetProperty("previous_record_sha256").ValueKind == JsonValueKind.Null :
                Digest(entry, "previous_record_sha256") == previous, "storage_chain_hash_mismatch");
            long nc = Number(entry, "chunks"), nl = Number(entry, "lines"), ns = Number(entry, "compressed_bytes"),
                nj = Number(entry, "json_bytes"), ni = Number(entry, "index_bytes");
            Need(nc > 0 && nc <= limits.Chunks - chunks && nl > 0 && nl <= limits.Lines - lines &&
                ns > 0 && ns <= cohortBytes && ns <= limits.CompressedBytes - compressed &&
                nj > 0 && nj <= limits.JsonBytes - json && ni > 0 && ni <= limits.IndexBytes - length - indexed,
                "storage_cohort_budget");
            string child = Path.Combine(directory, name); NotLink(child);
            NotLink(Path.Combine(child, "samples.jsonl.gz")); NotLink(Path.Combine(child, "chunks.jsonl"));
            terminal = Flag(entry, "terminal_summary_included");
            entries.Add(new(child, chunks, nc, lines, nl, ns, nj, ni, Digest(entry, "samples_sha256"), Digest(entry, "index_sha256"), terminal));
            chunks += nc; lines += nl; compressed += ns; json += nj; indexed += ni;
            previous = Hash(raw); hash.AppendData(raw);
        }
        Need(file.Length == length && entries.Count == Number(manifest, "storage_cohorts") &&
            length == Number(manifest, "storage_index_bytes"), "storage_index_count_mismatch");
        string digest = CurrentHash(hash);
        Need(Digest(manifest, "durable_storage_index_prefix_sha256") == digest &&
            (!Flag(manifest, "terminal_summary_written") || Digest(manifest, "storage_index_sha256") == digest), "storage_index_hash_mismatch");
        // Only generated immediate cohort paths are permitted. Unexpected/unsealed cohorts cannot make a strict capture complete.
        int directories = 0;
        foreach (string child in Directory.EnumerateFileSystemEntries(directory, "storage-*"))
        {
            control(); if (Path.GetFileName(child) == "storage-index.jsonl") continue;
            Need(++directories <= entries.Count, "unsealed_or_unindexed_storage");
            Need(Directory.Exists(child) && entries.Any(e => e.Directory == child), "unexpected_storage_path"); NotLink(child);
        }
        Need(directories == entries.Count, "missing_storage_cohort");
        return new(entries.ToArray(), length, digest, cohortBytes);
    }

    private static string HashStorageFile(FileStream file, long expected, Action control)
    {
        Need(file.Length == expected, "storage_file_length_mismatch");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); byte[] buffer = new byte[64 * 1024];
        while (file.Position < expected)
        {
            control(); int count = file.Read(buffer, 0, (int)Math.Min(buffer.Length, expected - file.Position));
            Need(count > 0, "truncated_storage_file"); hash.AppendData(buffer, 0, count);
        }
        Need(file.Length == expected && file.ReadByte() == -1, "input_changed"); file.Position = 0;
        return CurrentHash(hash);
    }
}
