using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.SessionRecorder;

/// <summary>
/// Follows the opt-in combined-storage protocol. Live receipts describe provisional
/// bytes; a seal verifies a cohort. This class neither launches producers nor admits
/// gameplay semantics. ObservationCapture enables it only for cohorts_v1 plans.
/// </summary>
internal sealed class ObservationStorageTail : IDisposable
{
    private const string IndexName = "storage-index.jsonl";
    private const string DataName = "game-state.jsonl";
    private const string ReceiptsName = "delivery-receipts.jsonl";
    private const int MaximumLine = 2 * 1048576;
    private const int MaximumIndexLine = 4096;
    private readonly string directory;
    private readonly long maximumBytes, maximumCohortBytes, maximumIndexBytes;
    private readonly int maximumCohorts;
    private readonly LineCursor index;
    private readonly IncrementalHash outputHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly IncrementalHash indexHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private ActiveCohort? active;
    private Seal? pendingSeal;
    private string? previousSealHash;
    private long indexRecords, indexBytes, deliveryReceiptBytes;
    private int cohorts;
    private bool failed, complete, disposed, emptySeal;

    internal long Rows { get; private set; }
    internal long Bytes { get; private set; }
    internal int SealedCohorts => cohorts;
    internal long DeliveryReceiptBytes => deliveryReceiptBytes;
    internal bool MadeProgress { get; private set; }
    internal string OutputSha256 => Hex(outputHash.GetCurrentHash());
    internal string IndexSha256 => Hex(indexHash.GetCurrentHash());

    internal ObservationStorageTail(string directory, long maximumBytes,
        long maximumCohortBytes = 256L * 1048576, int maximumCohorts = 4096,
        long maximumIndexBytes = 16L * 1048576)
    {
        if (maximumBytes is <= 0 or > 64L * 1024 * 1048576
            || maximumCohortBytes is <= 0 or > 256L * 1048576
            || maximumCohorts is < 1 or > 4096 || maximumIndexBytes is <= 0 or > 64L * 1048576)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes), "Invalid storage-tail bounds.");
        this.directory = Path.GetFullPath(directory);
        this.maximumBytes = maximumBytes; this.maximumCohortBytes = maximumCohortBytes;
        this.maximumCohorts = maximumCohorts; this.maximumIndexBytes = maximumIndexBytes;
        index = new LineCursor(() => PathFor(IndexName), MaximumIndexLine, maximumIndexBytes);
    }

    // Each poll has bounded rows/control records and at most one maximum-size line
    // beyond its four-MiB data target. A caller must drain while MadeProgress before
    // final completion; metadata-only progress need not produce a data receipt.
    internal IReadOnlyList<object> Read(int maximumRows = 1024)
    {
        EnsureOpen();
        if (maximumRows is < 1 or > 4096) throw new ArgumentOutOfRangeException(nameof(maximumRows));
        try
        {
            MadeProgress = false;
            var receipts = new List<object>(); long pollBytes = 0; int controls = 0;
            while (receipts.Count < maximumRows && pollBytes < 4 * 1048576 && controls < 128)
            {
                if (active is null)
                {
                    byte[]? line = ReadIndexLine(); if (line is null) break;
                    if (emptySeal) throw Invalid("Empty cohort must be the only terminal cohort.");
                    using var document = Parse(line); var value = document.RootElement;
                    Identity(value, "open"); ExactKeys(value, "schema", "kind", "ordinal", "directory", "previous_seal_sha256");
                    if (cohorts >= maximumCohorts) throw Invalid("Storage cohort count bound.");
                    string cohort = value.GetProperty("directory").GetString()!;
                    foreach (string file in new[] { DataName, ReceiptsName })
                        if (!File.Exists(PathFor(cohort + "/" + file))) throw Invalid("Opened cohort file missing.");
                    active = new ActiveCohort(cohort, cohorts + 1, Rows,
                        new LineCursor(() => PathFor(cohort + "/" + DataName), MaximumLine, maximumCohortBytes));
                    controls++; MadeProgress = true; continue;
                }
                if (pendingSeal is null)
                {
                    byte[]? line = ReadIndexLine();
                    if (line is not null)
                    {
                        using var document = Parse(line); var value = document.RootElement;
                        Identity(value, "seal");
                        ExactKeys(value, "schema", "kind", "ordinal", "directory", "previous_seal_sha256", "files", "first_combined_sequence", "last_combined_sequence");
                        pendingSeal = ParseSeal(value, line); controls++; MadeProgress = true;
                    }
                }
                byte[]? data = active.Cursor.Next();
                if (data is not null)
                {
                    if (data.Length > maximumBytes - Bytes - deliveryReceiptBytes - indexBytes) throw Invalid("Combined storage byte bound.");
                    using var document = Parse(data); var value = document.RootElement;
                    string? schema = value.GetProperty("schema").GetString();
                    if (schema is not ("overwatch-decoder.private.selected-compact/1" or "overwatch-decoder.private.damage-feedback-candidate/1" or "overwatch-decoder.private.incoming-source-observation/1" or "overwatch-decoder.private.combined-status/1")
                        || Number(value, "combined_sequence") != Rows) throw Invalid("Combined source schema or sequence.");
                    long sourceOffset = active.Bytes;
                    active.Hash.AppendData(data); outputHash.AppendData(data);
                    active.Rows++; active.Bytes += data.Length; Bytes += data.Length; Rows++;
                    if (pendingSeal is not null && (active.Rows > pendingSeal.Data.Rows || active.Bytes > pendingSeal.Data.Bytes))
                        throw Invalid("Source exceeds published seal.");
                    receipts.Add(new { source_schema = schema, source_path = active.Directory + "/" + DataName,
                        storage_cohort = active.Ordinal, source_offset = sourceOffset, source_bytes = data.Length,
                        source_sha256 = Hex(SHA256.HashData(data)), combined_sequence = Rows - 1,
                        sealed_acceptance = false, durability_verified = false });
                    pollBytes += data.Length; MadeProgress = true; continue;
                }
                if (pendingSeal is null) break;
                active.Cursor.Complete();
                Seal seal = pendingSeal;
                if (active.Rows != seal.Data.Rows || active.Bytes != seal.Data.Bytes
                    || Hex(active.Hash.GetCurrentHash()) != seal.Data.Sha256
                    || (active.Rows == 0 ? seal.First is not null || seal.Last is not null
                        : seal.First != active.FirstSequence || seal.Last != Rows - 1))
                    throw Invalid("Sealed data does not match consumed bytes or sequence.");
                if (seal.Receipts.Bytes > maximumBytes - Bytes - deliveryReceiptBytes - indexBytes)
                    throw Invalid("Combined storage byte bound.");
                VerifyCohort(active.Directory, seal);
                if (active.Rows == 0 && cohorts != 0) throw Invalid("Empty cohort must be the only terminal cohort.");
                emptySeal = active.Rows == 0; deliveryReceiptBytes += seal.Receipts.Bytes;
                previousSealHash = seal.LineSha256; cohorts++;
                active.Dispose(); active = null; pendingSeal = null;
                controls++; MadeProgress = true;
            }
            return receipts;
        }
        catch { failed = true; throw; }
    }

    internal void Complete()
    {
        EnsureOpen();
        try
        {
            index.Complete();
            if (active is not null || pendingSeal is not null || cohorts == 0 || indexRecords != 2L * cohorts)
                throw Invalid("Unsealed or incomplete storage tail.");
            // Verify the index before following any historical file declaration.
            VerifyFile("", new FileSeal(IndexName, indexBytes, indexRecords, IndexSha256));
            // Re-read immutable seals and their files at finalization. Keep only one
            // index line in memory, rather than retaining every historical cohort.
            using var again = new LineCursor(() => PathFor(IndexName), MaximumIndexLine, maximumIndexBytes);
            using var freshHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long bytes = 0, records = 0; int ordinal = 0; string? previous = null;
            while (again.Next() is { } line)
            {
                freshHash.AppendData(line); bytes += line.Length; records++;
                using var document = Parse(line); var value = document.RootElement;
                string kind = records % 2 == 1 ? "open" : "seal";
                if (kind == "open") ordinal++;
                CheckIdentity(value, kind, ordinal, previous);
                if (kind == "open") continue;
                string cohort = value.GetProperty("directory").GetString()!;
                Seal seal = ParseSeal(value, line);
                VerifyCohort(cohort, seal); previous = seal.LineSha256;
            }
            again.Complete();
            if (bytes != indexBytes || records != indexRecords || Hex(freshHash.GetCurrentHash()) != IndexSha256)
                throw Invalid("Storage index changed after consumption.");
            complete = true;
        }
        catch { failed = true; throw; }
    }

    internal void VerifyResult(JsonElement result, int code, ObservationScope scope)
    {
        if (!complete || failed || disposed) throw Invalid("Storage completion is required.");
        Unique(result);
        if (Rows == 0 || code is not (0 or 7) || result.GetProperty("schema").GetString() != "overwatch-decoder.private.combined-run/2"
            || result.GetProperty("cli_exit_code").GetInt32() != code
            || result.GetProperty("status").GetString() != (code == 0 ? "complete" : "partial")
            || result.GetProperty("error").ValueKind != JsonValueKind.Null
            || result.GetProperty("cleanup_errors").GetArrayLength() != 0
            || result.GetProperty("capture_scope").GetString() != ObservationCapture.ScopeValue(scope)
            || Number(result, "output_rows") != Rows || Number(result, "output_bytes") != Bytes
            || result.GetProperty("output_sha256").GetString() != OutputSha256
            || Number(result, "delivery_receipt_bytes") != deliveryReceiptBytes
            || Number(result, "storage_index_bytes") != indexBytes || Number(result, "storage_index_records") != indexRecords
            || Number(result, "storage_cohorts") != cohorts || result.GetProperty("storage_index_sha256").GetString() != IndexSha256)
            throw Invalid("Combined storage result mismatch.");
    }

    private byte[]? ReadIndexLine()
    {
        byte[]? line = index.Next(); if (line is null) return null;
        if (indexRecords >= 2L * maximumCohorts) throw Invalid("Storage index record bound.");
        if (line.Length > maximumBytes - Bytes - deliveryReceiptBytes - indexBytes) throw Invalid("Combined storage byte bound.");
        indexHash.AppendData(line); indexBytes += line.Length; indexRecords++;
        return line;
    }
    private void Identity(JsonElement value, string kind) => CheckIdentity(value, kind, cohorts + 1, previousSealHash);
    private static void CheckIdentity(JsonElement value, string kind, int ordinal, string? previous)
    {
        if (value.GetProperty("schema").GetString() != "overwatch-decoder.private.combined-storage/1"
            || value.GetProperty("kind").GetString() != kind || Number(value, "ordinal") != ordinal
            || value.GetProperty("directory").GetString() != $"cohort-{ordinal:D6}"
            || value.GetProperty("previous_seal_sha256").GetString() != previous)
            throw Invalid("Storage index identity, order or seal chain.");
    }
    private Seal ParseSeal(JsonElement value, byte[] raw)
    {
        var files = value.GetProperty("files");
        if (files.ValueKind != JsonValueKind.Array || files.GetArrayLength() != 2) throw Invalid("Storage seal files.");
        FileSeal data = ParseFile(files[0], DataName), receipts = ParseFile(files[1], ReceiptsName);
        if (data.Rows != receipts.Rows || data.Bytes + receipts.Bytes > maximumCohortBytes) throw Invalid("Storage receipt row count or cohort byte bound.");
        long? first = NullableNumber(value, "first_combined_sequence"), last = NullableNumber(value, "last_combined_sequence");
        if (data.Rows == 0)
        {
            string empty = Hex(SHA256.HashData(Array.Empty<byte>()));
            if (data.Bytes != 0 || receipts.Bytes != 0 || data.Sha256 != empty || receipts.Sha256 != empty || first is not null || last is not null)
                throw Invalid("Nonempty metadata in empty cohort.");
        }
        else if (data.Bytes == 0 || receipts.Bytes == 0 || first is null || last is null || last < first || last - first != data.Rows - 1)
            throw Invalid("Storage sequence range.");
        return new Seal(data, receipts, first, last, Hex(SHA256.HashData(raw)));
    }
    private FileSeal ParseFile(JsonElement value, string expected)
    {
        ExactKeys(value, "path", "bytes", "rows", "sha256");
        long bytes = Number(value, "bytes"), rows = Number(value, "rows");
        string? sha = value.GetProperty("sha256").GetString();
        if (value.GetProperty("path").GetString() != expected || bytes > maximumCohortBytes || !IsHash(sha) || rows > bytes)
            throw Invalid("Storage file declaration.");
        return new FileSeal(expected, bytes, rows, sha!);
    }
    private void VerifyFile(string cohort, FileSeal expected)
    {
        string file = PathFor(cohort.Length == 0 ? expected.Path : cohort + "/" + expected.Path);
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (stream.Length != expected.Bytes) throw Invalid("Sealed file size.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[65536]; long bytes = 0, rows = 0; int read; byte last = 0;
        while ((read = stream.Read(buffer)) > 0)
        {
            if (read > expected.Bytes - bytes) throw Invalid("Sealed file grew.");
            hash.AppendData(buffer.AsSpan(0, read)); bytes += read;
            foreach (byte item in buffer.AsSpan(0, read)) if (item == 10) rows++;
            last = buffer[read - 1];
        }
        if (bytes != expected.Bytes || stream.Length != bytes || rows != expected.Rows
            || (bytes != 0 && last != 10) || Hex(hash.GetCurrentHash()) != expected.Sha256)
            throw Invalid("Sealed file hash, rows or final line.");
    }
    private void VerifyCohort(string cohort, Seal seal)
    {
        using var data = new LineCursor(() => PathFor(cohort + "/" + DataName), MaximumLine, maximumCohortBytes);
        using var receipts = new LineCursor(() => PathFor(cohort + "/" + ReceiptsName), MaximumIndexLine, maximumCohortBytes);
        using var dataHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var receiptHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long sequence = seal.First ?? 0, rows = 0, sourceBytes = 0, receiptBytes = 0;
        while (data.Next() is { } raw)
        {
            byte[] receipt = receipts.Next() ?? throw Invalid("Missing delivery receipt.");
            sourceBytes += raw.Length; receiptBytes += receipt.Length;
            if (sourceBytes > seal.Data.Bytes || receiptBytes > seal.Receipts.Bytes) throw Invalid("Sealed file grew.");
            dataHash.AppendData(raw); receiptHash.AppendData(receipt);
            using var sourceDocument = Parse(raw); using var receiptDocument = Parse(receipt);
            var source = sourceDocument.RootElement; var value = receiptDocument.RootElement;
            if (Number(source, "combined_sequence") != sequence || Number(value, "combined_sequence") != sequence
                || value.GetProperty("line_sha256").GetString() != Hex(SHA256.HashData(raw)))
                throw Invalid("Delivery receipt does not identify exact source line.");
            sequence++; rows++;
        }
        if (receipts.Next() is not null || rows != seal.Data.Rows || sourceBytes != seal.Data.Bytes || receiptBytes != seal.Receipts.Bytes
            || Hex(dataHash.GetCurrentHash()) != seal.Data.Sha256 || Hex(receiptHash.GetCurrentHash()) != seal.Receipts.Sha256)
            throw Invalid("Sealed file hash, rows or bytes.");
        data.Complete(); receipts.Complete();
    }
    private string PathFor(string relative) => ObservationCapture.Contained(directory, relative);
    private void EnsureOpen()
    {
        if (disposed || failed || complete) throw Invalid("Storage tail is closed.");
    }
    private static JsonDocument Parse(byte[] line)
    {
        var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 64 });
        try { Unique(document.RootElement); return document; } catch { document.Dispose(); throw; }
    }
    private static void Unique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            { if (!names.Add(property.Name)) throw Invalid("Duplicate JSON property."); Unique(property.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Unique(item);
    }
    private static void ExactKeys(JsonElement value, params string[] keys)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(keys))
            throw Invalid("Storage index fields.");
    }
    private static long Number(JsonElement value, string key)
    {
        var item = value.GetProperty(key);
        if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt64(out long result) || result < 0)
            throw Invalid("Storage nonnegative integer required.");
        return result;
    }
    private static long? NullableNumber(JsonElement value, string key) => value.GetProperty(key).ValueKind == JsonValueKind.Null ? null : Number(value, key);
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(c => char.IsAsciiHexDigit(c) && !char.IsAsciiLetterUpper(c));
    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    private static InvalidDataException Invalid(string reason) => new(reason);

    public void Dispose()
    {
        if (disposed) return;
        disposed = true; active?.Dispose(); active = null; index.Dispose(); outputHash.Dispose(); indexHash.Dispose();
    }
    private sealed record FileSeal(string Path, long Bytes, long Rows, string Sha256);
    private sealed record Seal(FileSeal Data, FileSeal Receipts, long? First, long? Last, string LineSha256);
    private sealed class ActiveCohort(string directory, int ordinal, long firstSequence, LineCursor cursor) : IDisposable
    {
        internal readonly string Directory = directory;
        internal readonly int Ordinal = ordinal;
        internal readonly long FirstSequence = firstSequence;
        internal readonly LineCursor Cursor = cursor;
        internal readonly IncrementalHash Hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        internal long Rows, Bytes;
        public void Dispose() { Cursor.Dispose(); Hash.Dispose(); }
    }
    private sealed class LineCursor(Func<string> path, int maximumLine, long maximumBytes) : IDisposable
    {
        private FileStream? stream;
        private readonly byte[] buffer = new byte[65536];
        private readonly MemoryStream pending = new();
        private int start, end;
        private long readBytes;
        internal byte[]? Next()
        {
            string current = path();
            if (stream is null)
            {
                if (!File.Exists(current)) return null;
                stream = new FileStream(current, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            }
            if (stream.Length < readBytes || stream.Length > maximumBytes) throw Invalid("Source truncation or byte bound.");
            while (true)
            {
                if (start == end)
                {
                    start = 0; end = stream.Read(buffer); readBytes += end;
                    if (readBytes > maximumBytes) throw Invalid("Source byte bound.");
                    if (end == 0) return null;
                }
                int newline = buffer.AsSpan(start, end - start).IndexOf((byte)10);
                int count = newline < 0 ? end - start : newline + 1;
                if (pending.Length + count > maximumLine) throw Invalid("Source line bound.");
                pending.Write(buffer, start, count); start += count;
                if (newline < 0) continue;
                byte[] result = pending.ToArray(); pending.SetLength(0); return result;
            }
        }
        internal void Complete()
        {
            if (stream is null || !File.Exists(path()) || stream.Length != readBytes || start != end || pending.Length != 0)
                throw Invalid("Incomplete source line or unread tail.");
        }
        public void Dispose() { stream?.Dispose(); pending.Dispose(); }
    }
}
