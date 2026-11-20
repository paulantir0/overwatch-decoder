using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OverwatchDecoder.Observer;

/// <summary>Offline integrity checking. Reads only fixed recording filenames; never opens a process or writes data.</summary>
public static partial class FieldRecordingVerification
{
    public sealed record Result(string schema, string mode, string status, bool valid, bool complete,
        bool terminal_summary_verified, bool recoverable, long verified_chunks, long verified_lines,
        long frames, long unknown_fields, long skipped_intervals, long verified_compressed_bytes,
        long verified_json_bytes, long verified_index_bytes, long? unverified_compressed_bytes,
        long? unverified_index_bytes, string? profile_sha256, string samples_prefix_sha256,
        string index_prefix_sha256, string json_prefix_sha256, string? error_code, long? error_chunk,
        double elapsed_ms,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] object? storage = null);

    internal sealed record Limits(long JsonBytes = FieldRecording.MaximumJsonBytes,
        long CompressedBytes = FieldRecording.MaximumCompressedBytes, long IndexBytes = FieldRecording.MaximumIndexBytes,
        int ChunkBytes = FieldRecording.MaximumChunkBytes, int LineBytes = FieldStream.MaximumLineBytes,
        long Lines = 3_600_001, int Chunks = 200_000, int TimeMs = 900_000);
    // Export consumes these exact validated buffers, never a second read of the input. A sink failure must
    // escape the input-error handlers below (in particular IOException must not become input_io_error).
    internal interface IValidatedSink
    {
        void Metadata(ReadOnlyMemory<byte> profile, ReadOnlyMemory<byte> manifest);
        void Chunk(ReadOnlyMemory<byte> json);
    }
    internal sealed class SinkException(Exception inner) : Exception("Validated recording sink failed.", inner);
    private static void Deliver(Action callback)
    { try { callback(); } catch (Exception e) { throw new SinkException(e); } }
    private sealed class Invalid(string code) : Exception { public string Code { get; } = code; }
    private sealed record Guard(ulong Address, string Hex, int Width);
    private sealed record Field(string Name, string Type, int Width, int Components, double? Min, double? Max, int[] Guards);
    private sealed record Profile(JsonElement Target, string Hash, Guard[] Guards, Field[] Fields, int ReadBytes, FieldStream.Profile? PointerModel = null);
    private sealed class State
    {
        public long Frames, Unknown, Skips, FrameBytes, MaxJitter, MaxFrame, LastEnd, NextSlot;
        public long Origin, OriginBefore, Frequency, MinimumReads, MinimumReadBytes, GuardGapBytes;
        public int IntervalMs;
        public string? Utc, PhysicalStop, LastTerminalReason;
        public bool BatchFrame;
        public JsonElement? Summary;
        public State Copy() => (State)MemberwiseClone();
    }

    public static Result Verify(string directory, bool recoverIndexedPrefix = false, CancellationToken cancellationToken = default) =>
        VerifyBounded(directory, recoverIndexedPrefix, cancellationToken, new());

    internal static Result VerifyBounded(string directory, bool recover, CancellationToken token, Limits limits,
        IValidatedSink? sink = null)
    {
        var timer = Stopwatch.StartNew();
        using var sampleHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var indexHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var jsonHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long chunks = 0, lines = 0, compressed = 0, json = 0, indexed = 0, sampleLength = -1, indexLength = -1, checkpoint = -1;
        string? profileHash = null, error = null; long? errorChunk = null; bool valid = false, complete = false;
        var state = new State();
        StoragePlan? storage = null;
        void Control()
        {
            if (token.IsCancellationRequested) throw new Invalid("cancelled");
            if (timer.ElapsedMilliseconds > limits.TimeMs) throw new Invalid("verification_time_limit");
        }
        try
        {
            Need(limits.JsonBytes is > 0 and <= FieldRecording.MaximumJsonBytes &&
                limits.CompressedBytes is > 0 and <= FieldRecording.MaximumCompressedBytes &&
                limits.IndexBytes is > 0 and <= FieldRecording.MaximumIndexBytes &&
                limits.ChunkBytes is > 0 and <= FieldRecording.MaximumChunkBytes &&
                limits.LineBytes is > 0 and <= FieldStream.MaximumLineBytes && limits.Lines is > 0 and <= 3_600_001 &&
                limits.Chunks is > 0 and <= 200_000 && limits.TimeMs is > 0 and <= 900_000, "invalid_verification_limits");
            Control();
            byte[] profileBytes = ReadSmall(Path.Combine(directory, "profile.json"), FieldStream.MaximumProfileBytes);
            Profile profile = ParseProfile(profileBytes); profileHash = profile.Hash;
            byte[] manifestBytes = ReadSmall(Path.Combine(directory, "manifest.json"), 256 * 1024);
            using var manifestDoc = Parse(manifestBytes);
            JsonElement manifest = manifestDoc.RootElement;
            string recordingSchema = Text(manifest, "schema");
            bool rotated = recordingSchema == "overwatch-decoder.field-recording/2";
            Need((rotated || recordingSchema == "overwatch-decoder.field-recording/1") &&
                (rotated || Text(manifest, "samples_file") == "samples.jsonl.gz" && Text(manifest, "index_file") == "chunks.jsonl") &&
                Text(manifest, "profile_file") == "profile.json" &&
                Text(manifest, "compression") == "gzip_concatenated_members_whole_jsonl_lines", "invalid_manifest");
            Common(manifest, profile, recordingSchema);
            if (profile.PointerModel is not null)
                Need(Flag(manifest, "private_address_trace") && Text(manifest, "profile_schema") == (profile.PointerModel.V4 ? "overwatch-decoder.field-profile/4" : profile.PointerModel.Batching is null ? "overwatch-decoder.field-profile/2" : "overwatch-decoder.field-profile/3") &&
                    Text(manifest, "stream_schema") == profile.PointerModel.StreamSchema, "missing_private_trace_label");
            if (profile.PointerModel?.Batching is not null)
                Need(Text(manifest, "unpublished_read_accounting") == GuardBatches.UnpublishedAccounting, "batch_accounting_qualification");
            Need(Text(manifest, "status") is "recording" or "finished", "invalid_manifest");
            long declaredJson = Number(manifest, "maximum_json_bytes"), declaredSamples = Number(manifest, "maximum_compressed_bytes"),
                declaredIndex = Number(manifest, "maximum_index_bytes"), declaredChunk = Number(manifest, "maximum_chunk_json_bytes");
            Need(declaredJson is >= 8192 and <= FieldRecording.MaximumJsonBytes &&
                declaredSamples is >= 65536 and <= FieldRecording.MaximumCompressedBytes &&
                declaredIndex is >= 4096 and <= FieldRecording.MaximumIndexBytes &&
                declaredChunk is >= 8192 and <= FieldRecording.MaximumChunkBytes, "invalid_manifest_budget");
            if (sink is not null) Deliver(() => sink.Metadata(profileBytes, manifestBytes));
            if (rotated) storage = ReadStoragePlan(directory, manifest, profileHash, limits, Control);
            if (storage is not null)
            {
                sampleLength = storage.Inputs.Sum(input => input.CompressedBytes);
                indexLength = storage.Inputs.Sum(input => input.IndexBytes);
            }
            var inputs = storage?.Inputs ?? [new StorageInput(directory, 0, 0, 0, 0, 0, 0, 0, "", "", false)];
            foreach (var input in inputs)
            {
            using var samples = Open(Path.Combine(input.Directory, "samples.jsonl.gz"));
            using var index = Open(Path.Combine(input.Directory, "chunks.jsonl"));
            using var cohortSamplesHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var cohortIndexHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long localSamples = samples.Length, localIndex = index.Length;
            long baseCompressed = compressed, baseIndexed = indexed, baseJson = json, baseChunks = chunks, baseLines = lines;
            if (storage is null) { sampleLength = localSamples; indexLength = localIndex; }
            Need(sampleLength <= limits.CompressedBytes && indexLength + (storage?.IndexBytes ?? 0) <= limits.IndexBytes, "input_byte_limit");
            if (storage is not null)
            {
                Need(input.FirstChunk == chunks && input.FirstLine == lines, "storage_chunk_or_line_gap");
                // Verify the sealed file domains before admitting any of this cohort to a recoverable prefix.
                Need(HashStorageFile(samples, input.CompressedBytes, Control) == input.SamplesHash &&
                    HashStorageFile(index, input.IndexBytes, Control) == input.IndexHash, "storage_file_hash_mismatch");
                Need(indexLength + storage.IndexBytes <= declaredIndex, "manifest_budget_mismatch");
            }
            while (index.Position < localIndex)
            {
                Control(); errorChunk = chunks;
                Need(chunks < limits.Chunks, "chunk_count_limit");
                byte[] entryBytes = ReadIndexLine(index, localIndex);
                using var entryDoc = Parse(entryBytes);
                JsonElement entry = entryDoc.RootElement;
                Keys(entry, "schema", "sequence", "offset", "compressed_bytes", "json_bytes", "first_line", "lines",
                    "compressed_sha256", "json_sha256", "checkpoint_ticks", "monotonic_frequency");
                Need(Text(entry, "schema") == "overwatch-decoder.field-recording-chunk/1" && Number(entry, "sequence") == chunks &&
                    Number(entry, "offset") == compressed - baseCompressed && Number(entry, "first_line") == lines, "index_order_or_gap");
                long memberBytes = Number(entry, "compressed_bytes"), rawBytes = Number(entry, "json_bytes"), count = Number(entry, "lines");
                Need(memberBytes is >= 18 && memberBytes <= limits.ChunkBytes + 8192L && rawBytes > 0 && rawBytes <= limits.ChunkBytes &&
                    rawBytes <= limits.JsonBytes - json && count > 0 && count <= limits.Lines - lines, "decompression_or_count_limit");
                Need(rawBytes <= declaredChunk && rawBytes <= declaredJson - json && memberBytes <= declaredSamples - compressed &&
                    entryBytes.Length <= declaredIndex - indexed, "manifest_budget_mismatch");
                Need(memberBytes <= localSamples - (compressed - baseCompressed), "truncated_member");
                byte[] member = new byte[(int)memberBytes]; samples.ReadExactly(member);
                Need(Hash(member) == Digest(entry, "compressed_sha256"), "compressed_hash_mismatch");
                byte[] raw = Inflate(member, (int)rawBytes, Control);
                Need(Hash(raw) == Digest(entry, "json_sha256"), "json_hash_mismatch");
                var next = state.Copy(); long actualLines = 0; int start = 0;
                for (int n = 0; n < raw.Length; n++)
                {
                    if (raw[n] != (byte)'\n') continue;
                    Control();
                    Need(n > start && n - start + 1 <= limits.LineBytes, "invalid_or_oversized_json_line");
                    ValidateLine(raw.AsMemory(start, n - start), n - start + 1, profile, next);
                    actualLines++; start = n + 1;
                }
                Need(start == raw.Length && actualLines == count, "chunk_line_count_or_boundary");
                long nowCheckpoint = Number(entry, "checkpoint_ticks");
                Need(nowCheckpoint >= checkpoint && nowCheckpoint >= next.LastEnd &&
                    Number(entry, "monotonic_frequency") == next.Frequency, "invalid_checkpoint_time");
                // A chunk contributes to recovery only after every byte and line has passed. Never accept part of a member.
                sampleHash.AppendData(member); indexHash.AppendData(entryBytes); jsonHash.AppendData(raw);
                cohortSamplesHash.AppendData(member); cohortIndexHash.AppendData(entryBytes);
                state = next; checkpoint = nowCheckpoint; chunks++; lines += count;
                compressed += memberBytes; json += rawBytes; indexed += entryBytes.Length;
                if (sink is not null) Deliver(() => sink.Chunk(raw));
            }
            Need(samples.Length == localSamples && index.Length == localIndex, "input_changed");
            Need(compressed - baseCompressed == localSamples, "unindexed_sample_tail");
            if (storage is not null)
                Need(chunks - baseChunks == input.Chunks && lines - baseLines == input.Lines &&
                    json - baseJson == input.JsonBytes && indexed - baseIndexed == input.IndexBytes &&
                    CurrentHash(cohortSamplesHash) == input.SamplesHash && CurrentHash(cohortIndexHash) == input.IndexHash &&
                    input.Terminal == (state.Summary is not null), "storage_cohort_content_mismatch");
            }
            Control(); errorChunk = chunks;
            Need(compressed == sampleLength, "unindexed_sample_tail");
            Need(state.Summary is not null, "missing_terminal_summary");
            JsonElement summary = state.Summary!.Value;
            Need(Text(manifest, "status") == "finished" && Flag(manifest, "terminal_summary_written"), "unfinished_manifest");
            Need(Equal(manifest.GetProperty("stream_summary"), summary), "manifest_summary_mismatch");
            Need(Number(manifest, "durable_chunks") == chunks && Number(manifest, "durable_lines") == lines &&
                Number(manifest, "durable_compressed_bytes") == compressed && Number(manifest, "durable_json_bytes") == json &&
                Number(manifest, "index_bytes") == indexed && Number(manifest, "pending_lines") == 0, "manifest_count_mismatch");
            string sh = CurrentHash(sampleHash), ih = CurrentHash(indexHash);
            Need(Digest(manifest, "samples_sha256") == sh && Digest(manifest, "durable_samples_prefix_sha256") == sh &&
                Digest(manifest, "index_sha256") == ih && Digest(manifest, "durable_index_prefix_sha256") == ih, "manifest_hash_mismatch");
            bool noFailure = manifest.GetProperty("failure").ValueKind == JsonValueKind.Null;
            bool expectedComplete = noFailure && Flag(summary, "complete");
            Need(Flag(manifest, "complete") == expectedComplete &&
                Text(manifest, "stop_reason") == (noFailure ? Text(summary, "stop_reason") : Text(manifest, "failure")) &&
                Number(manifest, "requested_interval_ms") == state.IntervalMs &&
                Real(manifest, "requested_duration_s") == Real(summary, "requested_duration_s"), "manifest_completion_mismatch");
            valid = true; complete = expectedComplete; errorChunk = null;
        }
        catch (Invalid e) { error = e.Code; }
        catch (InvalidDataException) { error = "invalid_gzip"; }
        catch (EndOfStreamException) { error = "truncated_input"; }
        catch (UnauthorizedAccessException) { error = "input_permission_denied"; }
        catch (IOException) { error = "input_io_error"; }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException or ArgumentException)
        { error = "malformed_recording"; }
        bool recoverable = !valid && chunks > 0;
        string status = valid ? (complete ? "verified_complete" : "verified_stopped") :
            error == "cancelled" ? "cancelled" : recover && recoverable ? "recoverable_prefix" : "invalid";
        return new(storage is null ? "overwatch-decoder.field-recording-verification/1" : "overwatch-decoder.field-recording-verification/2", recover ? "recover_indexed_prefix" : "strict", status,
            valid, complete, state.Summary is not null, recoverable, chunks, lines, state.Frames, state.Unknown,
            state.Summary is { } s ? Number(s, "skipped_intervals") : state.Skips,
            compressed, json, indexed, sampleLength < 0 ? null : Math.Max(0, sampleLength - compressed),
            indexLength < 0 ? null : Math.Max(0, indexLength - indexed),
            profileHash, CurrentHash(sampleHash), CurrentHash(indexHash), CurrentHash(jsonHash), error, errorChunk, timer.Elapsed.TotalMilliseconds,
            storage is null ? null : new { cohorts = storage.Inputs.Length, storage_index_bytes = storage.IndexBytes,
                storage_index_sha256 = storage.IndexHash, maximum_cohort_bytes = storage.CohortBytes,
                hash_domain = "samples/index prefixes concatenate original cohort file bytes in ordinal order; JSON prefix concatenates original decompressed lines" });
    }

    private static FileStream Open(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024);
    private static byte[] ReadSmall(string path, int maximum)
    {
        using var file = Open(path); Need(file.Length <= maximum, "metadata_byte_limit");
        byte[] bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
        Need(file.ReadByte() == -1, "input_changed"); return bytes;
    }
    private static byte[] ReadIndexLine(FileStream file, long length)
    {
        using var line = new MemoryStream();
        while (file.Position < length)
        {
            int value = file.ReadByte(); Need(value >= 0, "truncated_index"); line.WriteByte((byte)value);
            Need(line.Length <= 4096, "index_line_limit");
            if (value == '\n') return line.ToArray();
        }
        throw new Invalid("partial_index_line");
    }
    private static byte[] Inflate(byte[] member, int size, Action control)
    {
        // The writer emits an ordinary header without optional fields. Check the footer ourselves because some
        // decompression runtimes return EOF for a truncated trailer instead of reporting an error.
        Need(member[0] == 0x1f && member[1] == 0x8b && member[2] == 8 && member[3] == 0, "invalid_gzip_header");
        byte[] raw = new byte[size];
        using var input = new MemoryStream(member, false); using var gzip = new GZipStream(input, CompressionMode.Decompress);
        int offset = 0;
        while (offset < raw.Length)
        {
            control(); int n = gzip.Read(raw, offset, Math.Min(64 * 1024, raw.Length - offset));
            Need(n > 0, "truncated_or_short_gzip"); offset += n;
        }
        Need(gzip.ReadByte() == -1, "decompression_byte_limit");
        Need(BinaryPrimitives.ReadUInt32LittleEndian(member.AsSpan(member.Length - 4)) == (uint)size &&
            BinaryPrimitives.ReadUInt32LittleEndian(member.AsSpan(member.Length - 8)) == Crc(raw), "gzip_trailer_mismatch");
        return raw;
    }
    private static readonly uint[] CrcTable = MakeCrcTable();
    private static uint[] MakeCrcTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < table.Length; i++)
        {
            uint value = i;
            for (int n = 0; n < 8; n++) value = (value >> 1) ^ (0xedb88320u & (uint)-(int)(value & 1));
            table[i] = value;
        }
        return table;
    }
    private static uint Crc(byte[] bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in bytes) crc = CrcTable[(crc ^ b) & 255] ^ (crc >> 8);
        return ~crc;
    }
    private static JsonDocument Parse(ReadOnlyMemory<byte> bytes)
    {
        var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 20 });
        try { Unique(doc.RootElement); return doc; } catch { doc.Dispose(); throw; }
    }
    private static void Unique(JsonElement e)
    {
        if (e.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty p in e.EnumerateObject()) { Need(names.Add(p.Name), "duplicate_json_key"); Unique(p.Value); }
        }
        else if (e.ValueKind == JsonValueKind.Array) foreach (JsonElement x in e.EnumerateArray()) Unique(x);
    }
    private static void Keys(JsonElement e, params string[] allowed)
    {
        Need(e.ValueKind == JsonValueKind.Object && e.EnumerateObject().All(p => allowed.Contains(p.Name, StringComparer.Ordinal)), "unsupported_json_property");
    }
    private static string Text(JsonElement e, string key) => e.GetProperty(key).GetString() ?? throw new Invalid("missing_text");
    private static long Number(JsonElement e, string key) => e.GetProperty(key).GetInt64();
    private static double Real(JsonElement e, string key)
    { double n = e.GetProperty(key).GetDouble(); Need(double.IsFinite(n), "non_finite_metadata"); return n; }
    private static bool Flag(JsonElement e, string key) => e.GetProperty(key).GetBoolean();
    private static string Digest(JsonElement e, string key)
    { string s = Text(e, key); Need(s.Length == 64 && s.All(Uri.IsHexDigit), "invalid_digest"); return s.ToLowerInvariant(); }
    private static void Need(bool condition, string code) { if (!condition) throw new Invalid(code); }
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string CurrentHash(IncrementalHash hash) => Convert.ToHexStringLower(hash.GetCurrentHash());
    private static bool Equal(JsonElement a, JsonElement b)
    {
        if (a.ValueKind != b.ValueKind) return false;
        return a.ValueKind switch
        {
            JsonValueKind.Object => a.EnumerateObject().Count() == b.EnumerateObject().Count() &&
                a.EnumerateObject().All(p => b.TryGetProperty(p.Name, out var x) && Equal(p.Value, x)),
            JsonValueKind.Array => a.GetArrayLength() == b.GetArrayLength() && a.EnumerateArray().Zip(b.EnumerateArray()).All(x => Equal(x.First, x.Second)),
            JsonValueKind.Number => a.GetRawText() == b.GetRawText() || a.TryGetDecimal(out decimal x) && b.TryGetDecimal(out decimal y) && x == y,
            JsonValueKind.String => a.GetString() == b.GetString(),
            _ => true
        };
    }

    private static Profile ParseProfile(byte[] bytes)
    {
        using var doc = Parse(bytes); JsonElement root = doc.RootElement;
        if (Text(root, "schema") is "overwatch-decoder.field-profile/2" or "overwatch-decoder.field-profile/3" or "overwatch-decoder.field-profile/4")
        {
            FieldStream.Profile model;
            try { model = FieldStream.ParseProfileBytes(bytes); }
            catch (ObservationException e) { throw new Invalid(e.Code); }
            return new(root.GetProperty("target").Clone(), model.Hash,
                model.Guards.Select(g => new Guard(g.Address, Convert.ToHexStringLower(g.Expected), g.Expected.Length)).ToArray(),
                model.Fields.Select(f => new Field(f.Name, f.Type, f.Width, f.Components, f.Min, f.Max, f.Guards)).ToArray(), model.ReadBytes, model);
        }
        Keys(root, "schema", "target", "guards", "fields"); Need(Text(root, "schema") == "overwatch-decoder.field-profile/1", "invalid_profile");
        JsonElement target = root.GetProperty("target");
        Keys(target, "pid", "image_name", "creation_file_time", "executable_sha256", "architecture");
        string name = Text(target, "image_name");
        Need(target.GetProperty("pid").GetInt32() > 0 && Number(target, "creation_file_time") > 0 && Text(target, "architecture") == "x64" &&
            name.Length is > 0 and <= 128 && !name.Any(c => char.IsControl(c) || c is '/' or '\\'), "invalid_profile_identity");
        _ = Digest(target, "executable_sha256");
        var guards = new List<Guard>(); int declarations = 0;
        ulong Address(JsonElement e, int width)
        { ulong a = e.GetProperty("address").GetUInt64(); Need(a > 0 && a <= (ulong)long.MaxValue - (uint)(width - 1), "invalid_profile_address"); return a; }
        int[] Guards(JsonElement e)
        {
            if (!e.TryGetProperty("guards", out var array)) return [];
            Need(array.ValueKind == JsonValueKind.Array, "invalid_profile_guards"); var ids = new List<int>();
            foreach (var g in array.EnumerateArray())
            {
                Need(++declarations <= FieldStream.MaximumGuards, "profile_guard_limit"); Keys(g, "address", "bytes_hex");
                string hex = Text(g, "bytes_hex").ToLowerInvariant();
                Need(hex.Length is > 0 and <= FieldStream.MaximumGuardBytes * 2 && hex.Length % 2 == 0 && hex.All(Uri.IsHexDigit), "invalid_profile_guard");
                ulong a = Address(g, hex.Length / 2); int id = guards.FindIndex(x => x.Address == a && x.Hex == hex);
                if (id < 0) { id = guards.Count; guards.Add(new(a, hex, hex.Length / 2)); }
                if (!ids.Contains(id)) ids.Add(id);
            }
            return ids.ToArray();
        }
        int[] global = Guards(root); var fields = new List<Field>(); var names = new HashSet<string>(StringComparer.Ordinal);
        JsonElement list = root.GetProperty("fields"); Need(list.ValueKind == JsonValueKind.Array && list.GetArrayLength() is > 0 and <= FieldStream.MaximumFields, "profile_field_limit");
        foreach (var f in list.EnumerateArray())
        {
            Keys(f, "name", "type", "address", "guards", "min", "max"); string label = Text(f, "name"), type = Text(f, "type");
            Need(label.Length is > 0 and <= 64 && label.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.') && names.Add(label), "invalid_profile_field_name");
            int components = type switch { "u8" or "i32" or "f32" or "f64" => 1, "f32x3" => 3, "f32x4" or "i32x4" => 4, _ => throw new Invalid("invalid_profile_type") };
            int width = type == "u8" ? 1 : type == "f64" ? 8 : components * 4; _ = Address(f, width);
            double? min = f.TryGetProperty("min", out _) ? Real(f, "min") : null, max = f.TryGetProperty("max", out _) ? Real(f, "max") : null;
            Need(!(min > max), "invalid_profile_range"); int[] ids = global.Concat(Guards(f)).Distinct().ToArray();
            Need(ids.Length > 0 && ids.Select(i => guards[i].Address).Distinct().Count() == ids.Length, "invalid_profile_guards");
            fields.Add(new(label, type, width, components, min, max, ids));
        }
        int planned = guards.Sum(g => g.Width) * 2 + fields.Sum(f => f.Width);
        Need(planned <= FieldStream.MaximumReadBytesPerFrame, "profile_read_limit");
        return new(target.Clone(), Hash(bytes), guards.ToArray(), fields.ToArray(), planned);
    }

    private static void Common(JsonElement e, Profile p, string schema)
    {
        Need(Text(e, "schema") == schema && Text(e, "source") == "process_memory" &&
            Text(e, "interpretation") == "profile_declared_research" && Text(e, "visibility") == "research" &&
            !Flag(e, "runtime_semantics_validated") && !Flag(e, "public_state_eligible") && !Flag(e, "atomic"), "invalid_provenance");
        Need(Digest(e, "profile_sha256") == p.Hash && Equal(e.GetProperty("target"), p.Target), "profile_or_target_mismatch");
    }
    private static void ValidateLine(ReadOnlyMemory<byte> bytes, int lineBytes, Profile profile, State s)
    {
        using var doc = Parse(bytes); JsonElement e = doc.RootElement; Common(e, profile, profile.PointerModel?.StreamSchema ?? "overwatch-decoder.field-stream/1");
        if (profile.PointerModel is not null) Need(Flag(e, "private_address_trace"), "missing_private_trace_label");
        Need(s.Summary is null, "line_after_summary");
        string kind = Text(e, "kind"); Need(kind is "frame" or "summary", "unsupported_line_kind");
        long origin = Number(e, "monotonic_origin_ticks"), frequency = Number(e, "monotonic_frequency"), beforeOrigin = Number(e, "utc_origin_before_ticks");
        int interval = e.GetProperty("requested_interval_ms").GetInt32(); string utc = Text(e, kind == "frame" ? "utc_origin" : "started_utc");
        Need(origin >= 0 && beforeOrigin >= 0 && beforeOrigin <= origin && frequency is > 0 and <= 1_000_000_000_000 &&
            interval is >= 10 and <= 10000 && DateTimeOffset.TryParse(utc, out _), "invalid_time_origin");
        if (s.Utc is null) { s.Origin = origin; s.OriginBefore = beforeOrigin; s.Frequency = frequency; s.IntervalMs = interval; s.Utc = utc; }
        Need(origin == s.Origin && beforeOrigin == s.OriginBefore && frequency == s.Frequency && interval == s.IntervalMs && utc == s.Utc, "changed_time_origin");
        if (kind == "summary")
        {
            if (profile.PointerModel is not null)
                Need(Number(e, "maximum_paths") == PointerPaths.MaximumPaths && Number(e, "maximum_hops_per_path") == PointerPaths.MaximumHops &&
                    Number(e, "maximum_read_calls_per_frame") == PointerPaths.MaximumCalls, "path_summary_limits");
            Need(lineBytes <= 8192 && Number(e, "frames") == s.Frames && Number(e, "unknown_fields") == s.Unknown &&
                Number(e, "frame_output_utf8_bytes") == s.FrameBytes && Number(e, "skipped_intervals") >= s.Skips, "summary_count_mismatch");
            Need(Number(e, "read_calls") >= s.MinimumReads && Number(e, "read_bytes") >= s.MinimumReadBytes &&
                Number(e, "read_bytes") <= FieldStream.MaximumReadBytes && Number(e, "planned_read_bytes_per_frame") == profile.ReadBytes, "summary_read_mismatch");
            Need(Number(e, "maximum_read_bytes") is > 0 and <= FieldStream.MaximumReadBytes &&
                Number(e, "read_bytes") <= Number(e, "maximum_read_bytes") &&
                Number(e, "maximum_output_utf8_bytes") is >= 8192 and <= FieldRecording.MaximumJsonBytes &&
                s.FrameBytes + lineBytes <= Number(e, "maximum_output_utf8_bytes"), "summary_budget_mismatch");
            Need(Close(Real(e, "maximum_jitter_ms"), s.MaxJitter * 1000d / frequency) &&
                Close(Real(e, "maximum_frame_ms"), s.MaxFrame * 1000d / frequency) && Real(e, "maximum_write_ms") >= 0 &&
                Real(e, "elapsed_ms") >= Math.Max(0, (s.LastEnd - origin) * 1000d / frequency), "summary_time_mismatch");
            Need(Real(e, "requested_duration_s") is > 0 and <= 36000 &&
                Flag(e, "complete") == (Text(e, "stop_reason") == "duration_elapsed"), "summary_completion_mismatch");
            if (profile.PointerModel?.Batching is { } batching) BatchSummary(e, batching, s);
            s.Summary = e.Clone(); return;
        }
        Need(s.LastTerminalReason is null, "frame_after_terminal");
        s.BatchFrame = profile.PointerModel?.Batching is not null; s.PhysicalStop = null;
        Need(!Flag(e, "hard_realtime"), "invalid_realtime_claim");
        long start = Number(e, "start_ticks"), end = Number(e, "end_ticks"), slot = Number(e, "scheduled_slot"), missed = Number(e, "skipped_intervals_before");
        long intervalTicks = Math.Max(1, (long)(interval * (double)frequency / 1000));
        Need(Number(e, "sequence") == s.Frames && missed >= 0 && slot == checked(s.NextSlot + missed) &&
            Number(e, "skipped_intervals_total") == checked(s.Skips + missed), "frame_sequence_or_skip_mismatch");
        long scheduled = checked(origin + slot * intervalTicks);
        Need(Number(e, "scheduled_ticks") == scheduled && start >= scheduled && start >= s.LastEnd && end >= start &&
            Number(e, "jitter_ticks") == start - scheduled && (start - origin) / intervalTicks == slot, "frame_time_mismatch");
        JsonElement pre = e.GetProperty("guards_before"), post = e.GetProperty("guards_after");
        Need(pre.ValueKind == JsonValueKind.Array && post.ValueKind == JsonValueKind.Array &&
            pre.GetArrayLength() == profile.Guards.Length && post.GetArrayLength() == profile.Guards.Length, "guard_count_mismatch");
        long readsBefore = s.MinimumReads, bytesBefore = s.MinimumReadBytes, gapsBefore = s.GuardGapBytes;
        long cursor = start;
        void Times(long a, long b) { Need(a >= cursor && b >= a && b <= end, "read_time_order"); cursor = b; }
        void GuardPass(JsonElement pass, string phase)
        {
            if (profile.PointerModel?.V4 == true) { SerialGuardPass(pass, profile.PointerModel, e.GetProperty("terminal_reason").GetString(), Times, s); return; }
            if (profile.PointerModel?.Batching is not null) { BatchPass(e.GetProperty("guard_batches_" + phase), pass, profile.PointerModel, Times, s); return; }
            int id = 0;
            foreach (var g in pass.EnumerateArray())
            {
                Keys(g, "ok", "start_ticks", "end_ticks", "error"); Times(Number(g, "start_ticks"), Number(g, "end_ticks"));
                if (Flag(g, "ok")) { Need(g.GetProperty("error").ValueKind == JsonValueKind.Null, "guard_status_mismatch"); s.MinimumReads++; s.MinimumReadBytes += profile.Guards[id].Width; }
                else Need(Text(g, "error").Length is > 0 and <= 256, "guard_status_mismatch");
                id++;
            }
        }
        GuardPass(pre, "before");
        PointerProof? proof = profile.PointerModel is { } model ? PointerBefore(e, model, pre, Times, s) : null;
        JsonElement fields = e.GetProperty("fields"); Need(fields.ValueKind == JsonValueKind.Object && fields.EnumerateObject().Count() == profile.Fields.Length, "field_count_mismatch");
        foreach (Field field in profile.Fields)
        {
            JsonElement f = fields.GetProperty(field.Name);
            var pool = profile.PointerModel?.Fields.FirstOrDefault(x => x.Name == field.Name && x.Pool is not null);
            if (pool is not null)
            {
                Need(Text(f, "type") == field.Type && f.GetProperty("guard_ids").EnumerateArray().Select(x => x.GetInt32()).SequenceEqual(field.Guards), "field_type_or_guards_mismatch");
                PoolField(f, pool, pre, post, e.GetProperty("terminal_reason").GetString(), Times, s);
                if (Text(f, "status") == "unknown") s.Unknown++;
                continue;
            }
            var timer = profile.PointerModel?.Fields.FirstOrDefault(x => x.Name == field.Name && x.Timer is not null);
            if (timer is not null)
            {
                Need(Text(f, "type") == field.Type && f.GetProperty("guard_ids").EnumerateArray().Select(x => x.GetInt32()).SequenceEqual(field.Guards), "field_type_or_guards_mismatch");
                TimerField(f, timer, pre, post, e.GetProperty("terminal_reason").GetString(), Times, s);
                if (Text(f, "status") == "unknown") s.Unknown++;
                continue;
            }
            if (proof is null) Keys(f, "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks", "guard_ids");
            else if (profile.PointerModel?.Batching is not null)
                Keys(f, "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks", "guard_ids", "path_id", "read_address_hex", "read_attempted", "read_error");
            else Keys(f, "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks", "guard_ids", "path_id", "read_address_hex", "read_attempted");
            Need(Text(f, "type") == field.Type && f.GetProperty("guard_ids").EnumerateArray().Select(x => x.GetInt32()).SequenceEqual(field.Guards), "field_type_or_guards_mismatch");
            bool hasRead = f.GetProperty("read_start_ticks").ValueKind != JsonValueKind.Null;
            Need(hasRead == (f.GetProperty("read_end_ticks").ValueKind != JsonValueKind.Null), "partial_read_time");
            if (hasRead) Times(Number(f, "read_start_ticks"), Number(f, "read_end_ticks"));
            if (proof is not null) PointerField(f, field.Name, proof, pre, s, hasRead);
            string status = Text(f, "status");
            if (status == "unknown") { Need(f.GetProperty("value").ValueKind == JsonValueKind.Null && Text(f, "reason").Length is > 0 and <= 256, "unknown_value_retained"); s.Unknown++; }
            else
            {
                Need(status == "observed" && hasRead && f.GetProperty("reason").ValueKind == JsonValueKind.Null &&
                    field.Guards.All(i => Flag(pre[i], "ok") && Flag(post[i], "ok")), "unguarded_observed_value");
                JsonElement value = f.GetProperty("value");
                if (field.Type == "i32") _ = value.GetInt32();
                if (field.Type == "u8") Need(value.TryGetByte(out _), "invalid_field_value");
                JsonElement[] values = field.Components == 1 ? [value] : value.EnumerateArray().ToArray();
                Need(values.Length == field.Components, "vector_component_count");
                foreach (var x in values)
                { if (field.Type == "i32x4") Need(x.TryGetInt32(out _), "invalid_field_value");
                  double v = x.GetDouble(); Need(double.IsFinite(v) && !(v < field.Min) && !(v > field.Max), "invalid_field_value"); }
                if (proof is null) { s.MinimumReads++; s.MinimumReadBytes += field.Width; }
            }
        }
        if (proof is not null) PointerAfter(proof, post, Times, s);
        GuardPass(post, "after");
        if (profile.PointerModel?.Batching is not null)
        {
            Need(Number(e, "physical_read_calls") == s.MinimumReads - readsBefore &&
                Number(e, "physical_read_bytes") == s.MinimumReadBytes - bytesBefore &&
                Number(e, "guard_gap_read_bytes") == s.GuardGapBytes - gapsBefore, "batch_frame_read_counts");
            var terminal = e.GetProperty("terminal_reason");
            if (terminal.ValueKind != JsonValueKind.Null)
            {
                Need(terminal.ValueKind == JsonValueKind.String && FieldStream.Fatal(Text(e, "terminal_reason")) &&
                    fields.EnumerateObject().All(f => Text(f.Value, "status") == "unknown" && Text(f.Value, "reason") == terminal.GetString()), "batch_terminal_fields");
                s.LastTerminalReason = terminal.GetString();
            }
            Need(s.PhysicalStop is null || s.LastTerminalReason is not null, "batch_missing_terminal_reason");
        }
        s.Frames++; s.FrameBytes += lineBytes; s.Skips += missed; s.NextSlot = slot + 1; s.LastEnd = end;
        s.MaxJitter = Math.Max(s.MaxJitter, start - scheduled); s.MaxFrame = Math.Max(s.MaxFrame, end - start);
    }
    private static bool Close(double a, double b) => Math.Abs(a - b) <= 1e-8 * Math.Max(1, Math.Abs(b));
}
