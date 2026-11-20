using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Storage boundaries only. Never acquires memory, changes a profile, or restarts a sampler.</summary>
public sealed record StorageRotation(long CohortBytes, int MaximumCohorts = 256)
{
    public const long MinimumBytes = 65536, MaximumBytes = 1024L * 1024 * 1024;
    public const int MaximumCount = 4096;
    internal void Validate()
    {
        if (CohortBytes is < MinimumBytes or > MaximumBytes || MaximumCohorts is < 1 or > MaximumCount)
            throw new ObservationException("invalid_arguments", "Storage cohort bytes/count are outside their bounded ranges.");
    }
}

internal sealed record StorageCohort(string schema, int ordinal, string directory, string profile_sha256,
    string? previous_record_sha256, long first_chunk, long chunks, long first_line, long lines,
    long compressed_bytes, long json_bytes, long index_bytes, string samples_sha256,
    string index_sha256, bool terminal_summary_included);
internal sealed record StorageSeal(StorageCohort Record, string RecordHash);

internal sealed class FieldStorageCohorts : IDisposable
{
    private readonly string root, profile;
    private readonly StorageRotation options;
    private readonly long indexLimit;
    private readonly Func<long> chunkIndexBytes;
    private readonly Action<StorageSeal>? sealedCallback;
    private readonly FileStream catalog;
    private readonly IncrementalHash catalogHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly IncrementalHash samplesHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly IncrementalHash chunksHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private FileStream? samples, index;
    private int opened;
    private long firstChunk, firstLine, chunks, lines, jsonBytes, chunkBytes;
    private string? previous;
    private bool disposed;
    internal long CurrentBytes { get; private set; }
    internal long IndexBytes { get; private set; }
    internal int SealedCount { get; private set; }
    internal string? IndexHash { get; private set; }
    internal bool LastCohort => opened == options.MaximumCohorts;
    internal int OpenOutputStreams => (samples is null ? 0 : 1) + (index is null ? 0 : 1) + (disposed ? 0 : 1);
    internal FieldStorageCohorts(string root, string profile, StorageRotation options, long indexLimit,
        Func<long> chunkIndexBytes, Action<StorageSeal>? sealedCallback)
    {
        options.Validate(); this.root = root; this.profile = profile; this.options = options;
        this.indexLimit = indexLimit; this.chunkIndexBytes = chunkIndexBytes; this.sealedCallback = sealedCallback;
        catalog = new(Path.Combine(root, "storage-index.jsonl"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        try { OpenNext(0, 0); } catch { Dispose(); throw; }
    }
    // Raw pending bytes plus a conservative gzip/summary allowance are checked before a frame is accepted.
    internal bool NeedsSpace(long conservativeBytes) => conservativeBytes > options.CohortBytes - CurrentBytes;
    internal bool Rotate(long nextChunk, long nextLine)
    {
        if (LastCohort) return false;
        Seal(false); OpenNext(nextChunk, nextLine); return true;
    }
    private void OpenNext(long nextChunk, long nextLine)
    {
        string path = Path.Combine(root, "storage-" + (opened + 1).ToString("D6"));
        if (Directory.Exists(path) || File.Exists(path)) throw new ObservationException("storage_path_exists", "Storage cohort must be new.");
        Directory.CreateDirectory(path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new ObservationException("storage_path_link", "Storage cohorts cannot be links.");
        samples = new(Path.Combine(path, "samples.jsonl.gz"), FileMode.CreateNew, FileAccess.Write, FileShare.Read, 64 * 1024);
        try { index = new(Path.Combine(path, "chunks.jsonl"), FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096); }
        catch { samples.Dispose(); samples = null; throw; }
        opened++; firstChunk = nextChunk; firstLine = nextLine;
        CurrentBytes = chunks = lines = jsonBytes = chunkBytes = 0;
    }
    internal void Write(byte[] member, byte[] entry, long rawBytes, long lineCount)
    {
        if (member.LongLength > options.CohortBytes - CurrentBytes)
            throw new ObservationException("storage_cohort_chunk_limit", "The next compressed chunk cannot fit the cohort; no bytes were written.");
        if (entry.LongLength + 4096 > indexLimit - chunkIndexBytes() - IndexBytes)
            throw new ObservationException("index_byte_limit", "Storage index reserve exhausted.");
        samples!.Write(member); samples.Flush(true);
        index!.Write(entry); index.Flush(true);
        samplesHash.AppendData(member); chunksHash.AppendData(entry);
        CurrentBytes += member.Length; chunkBytes += entry.Length; jsonBytes += rawBytes; lines += lineCount; chunks++;
    }
    internal void Seal(bool terminal)
    {
        if (samples is null || index is null) throw new ObservationException("storage_seal_state", "No active storage cohort.");
        samples.Dispose(); samples = null; index.Dispose(); index = null;
        var record = new StorageCohort("overwatch-decoder.field-storage-cohort/1", opened, "storage-" + opened.ToString("D6"), profile,
            previous, firstChunk, chunks, firstLine, lines, CurrentBytes, jsonBytes, chunkBytes,
            Convert.ToHexStringLower(samplesHash.GetHashAndReset()), Convert.ToHexStringLower(chunksHash.GetHashAndReset()), terminal);
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record) + "\n");
        if (bytes.Length > 4096 || bytes.Length > indexLimit - chunkIndexBytes() - IndexBytes)
            throw new ObservationException("index_byte_limit", "Storage seal exceeds its bounded index budget.");
        catalog.Write(bytes); catalog.Flush(true); catalogHash.AppendData(bytes); IndexBytes += bytes.Length;
        previous = Convert.ToHexStringLower(SHA256.HashData(bytes)); SealedCount++;
        sealedCallback?.Invoke(new(record, previous));
    }
    public void Dispose()
    {
        if (disposed) return; disposed = true;
        IndexHash = Convert.ToHexStringLower(catalogHash.GetHashAndReset());
        try { samples?.Dispose(); }
        finally
        {
            samples = null;
            try { index?.Dispose(); }
            finally { index = null; catalog.Dispose(); catalogHash.Dispose(); samplesHash.Dispose(); chunksHash.Dispose(); }
        }
    }
}
