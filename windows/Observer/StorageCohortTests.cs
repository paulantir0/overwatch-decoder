using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

public static class StorageCohortTests
{
    public static object? Metrics { get; private set; }
    private sealed class Memory : IMemorySource
    {
        internal const ulong Base = 65536;
        internal uint Version = 1; internal string? Failure; private int counter;
        public TargetIdentity Identity { get; } = new(63, "fixture.exe", "fixture", 11, new string('e', 64), "x64");
        public byte[] Read(ulong address, int size)
        {
            EnsureAlive();
            if (address == Base && size == 8) return BitConverter.GetBytes(123u).Concat(BitConverter.GetBytes(Version)).ToArray();
            if (address >= Base + 16 && address + (ulong)size <= Base + 4096 && size == 4)
                return BitConverter.GetBytes(unchecked((uint)Interlocked.Increment(ref counter) * 1664525u + 1013904223u));
            throw new ObservationException("unreadable_range", "Owned fixture range.");
        }
        public void EnsureAlive() { if (Failure is not null) throw new ObservationException(Failure, "Owned fixture exit."); }
        public IEnumerable<MemoryRegion> Regions() => []; public void Dispose() { }
    }
    private sealed class Live : StringWriter
    {
        internal int Seals; internal bool FailSeal;
        public override void Write(string? text)
        {
            using var d = JsonDocument.Parse(text!);
            if (d.RootElement.GetProperty("kind").GetString() == "storage_cohort_sealed")
            { if (FailSeal) throw new IOException("Owned fixture output failure."); Seals++; }
            base.Write(text);
        }
    }
    private static string Hash(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));
    private static JsonObject Obj(string p) => JsonNode.Parse(File.ReadAllBytes(p))!.AsObject();
    private static byte[] Inflate(byte[] b)
    { using var input = new MemoryStream(b); using var gz = new GZipStream(input, CompressionMode.Decompress); using var output = new MemoryStream(); gz.CopyTo(output); return output.ToArray(); }
    private static JsonObject[] Cohorts(string p) => File.ReadAllLines(Path.Combine(p, "storage-index.jsonl")).Select(x => JsonNode.Parse(x)!.AsObject()).ToArray();
    // Recompute every enclosing byte/hash domain so a semantic mutation reaches frame validation.
    private static void Rehash(string directory)
    {
        var cohorts = Cohorts(directory); string? previous = null;
        using var samples = new MemoryStream(); using var indices = new MemoryStream(); var catalog = new StringBuilder();
        foreach (var cohort in cohorts)
        {
            string child = Path.Combine(directory, cohort["directory"]!.GetValue<string>());
            byte[] sb = File.ReadAllBytes(Path.Combine(child, "samples.jsonl.gz")), ib = File.ReadAllBytes(Path.Combine(child, "chunks.jsonl"));
            cohort["compressed_bytes"] = sb.Length; cohort["index_bytes"] = ib.Length;
            cohort["samples_sha256"] = Hash(sb); cohort["index_sha256"] = Hash(ib); cohort["previous_record_sha256"] = previous;
            string line = cohort.ToJsonString() + "\n"; previous = Hash(Encoding.UTF8.GetBytes(line)); catalog.Append(line); samples.Write(sb); indices.Write(ib);
        }
        byte[] cb = Encoding.UTF8.GetBytes(catalog.ToString()); File.WriteAllBytes(Path.Combine(directory, "storage-index.jsonl"), cb);
        var manifest = Obj(Path.Combine(directory, "manifest.json"));
        manifest["storage_index_bytes"] = cb.Length; manifest["storage_index_sha256"] = Hash(cb); manifest["durable_storage_index_prefix_sha256"] = Hash(cb);
        manifest["durable_compressed_bytes"] = samples.Length; manifest["index_bytes"] = indices.Length;
        manifest["samples_sha256"] = Hash(samples.ToArray()); manifest["durable_samples_prefix_sha256"] = Hash(samples.ToArray());
        manifest["index_sha256"] = Hash(indices.ToArray()); manifest["durable_index_prefix_sha256"] = Hash(indices.ToArray());
        File.WriteAllText(Path.Combine(directory, "manifest.json"), manifest.ToJsonString());
    }
    private static byte[] Raw(string p) => Cohorts(p).SelectMany(c => Inflate(File.ReadAllBytes(Path.Combine(p, c["directory"]!.GetValue<string>(), "samples.jsonl.gz")))).ToArray();
    private static JsonElement[] Rows(string text) => text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => JsonSerializer.Deserialize<JsonElement>(x)).ToArray();
    private static JsonObject Recipe(TargetIdentity t) => JsonSerializer.SerializeToNode(new
    {
        schema = "overwatch-decoder.acquisition-recipe/1", target = new { image_name = t.ImageName, executable_sha256 = t.ExecutableSha256, architecture = t.Architecture },
        seconds = 10, constants = new { }, functions = new { }, global_guards = "g",
        stages = new[] { new { name = "header", steps = new object[] {
            new { op = "read", name = "header", address = new object[] { "rva", 0, 8 }, size = 8 },
            new { op = "require", test = new object[] { "eq", new object[] { "load", new object[] { "var", "header" }, 0, 4 }, 123 } },
            new { op = "guard", set = "g", value = new object[] { "var", "header" } } } } },
        fields = Enumerable.Range(0, 32).Select(i => new { name = "value" + i, type = "i32", address = new object[] { "rva", 16 + i * 4, 4 } }).ToArray()
    })!.AsObject();
    public static int Run()
    {
        int assertions = 0, ordinal = 0; string phase = "setup";
        void Check(bool b, string why) { if (!b) throw new ObservationException("self_test_failed", "storage:" + phase + ":" + why); assertions++; }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-storage-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string New() => Path.Combine(root, (++ordinal).ToString());
        ObserveFields.Result Capture(Memory m, string path, Live live, CancellationToken token = default,
            Action<int, FieldStream.AcceptedFrame>? frame = null, int maximum = 256, bool background = false, double seconds = 15)
        {
            string recipe = New() + ".json"; File.WriteAllText(recipe, Recipe(m.Identity).ToJsonString());
            return ObserveFields.RunBounded(m, new(Memory.Base, 4096, m.Identity.ImageName), recipe, path, 10, TimeSpan.FromSeconds(seconds), token,
                new(RetryMilliseconds: 0, ReacquireMilliseconds: background ? 5000 : 0), frame, live, liveEvidence: true,
                backgroundPreparation: background, storage: new(65536, maximum));
        }
        string Copy(string source)
        {
            string dest = New(); Directory.CreateDirectory(dest);
            foreach (string d in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories)) Directory.CreateDirectory(Path.Combine(dest, Path.GetRelativePath(source, d)));
            foreach (string f in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories)) File.Copy(f, Path.Combine(dest, Path.GetRelativePath(source, f)));
            return dest;
        }
        try
        {
            phase = "continuous-rotation"; var m = new Memory(); string output = New(); using var live = new Live();
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var result = Capture(m, output, live, stop.Token, (_, _) => { if (live.Seals >= 3) stop.Cancel(); });
            Check(result.stop_reason == "cancelled" && result.acquisitions.Length == 1 && result.segments.Length == 1, "rotation never reacquires or starts epoch");
            string segment = Path.Combine(output, result.segments.Single().directory); var records = Cohorts(segment);
            var verified = FieldRecordingVerification.Verify(segment);
            Check(records.Length >= 4 && verified.valid && !verified.complete, "four sealed cohorts strictly verify:" + verified.error_code);
            Check(records.All(c => c["compressed_bytes"]!.GetValue<long>() <= 65536), "strict compressed cohort bound");
            var raw = Rows(Encoding.UTF8.GetString(Raw(segment))); var frames = raw.Where(r => r.GetProperty("kind").GetString() == "frame").ToArray();
            Check(frames.Select((f, i) => f.GetProperty("sequence").GetInt64() == i).All(x => x), "continuous frame sequence");
            Check(frames.Select(f => f.GetProperty("monotonic_origin_ticks").GetInt64()).Distinct().Count() == 1, "one clock origin");
            var events = Rows(live.ToString()); var seals = events.Where(e => e.GetProperty("kind").GetString() == "storage_cohort_sealed").ToArray();
            Check(events.Select((e, i) => e.GetProperty("event_sequence").GetInt64() == i).All(x => x), "continuous event sequence");
            Check(events.Count(e => e.GetProperty("kind").GetString() == "segment_start") == 1 && events.Count(e => e.GetProperty("kind").GetString() == "gap") == 2, "no storage gaps or epochs");
            Check(events.Last(e => e.GetProperty("kind").GetString() == "storage_cohort_sealed").GetProperty("event_sequence").GetInt64() < events.Single(e => e.GetProperty("kind").GetString() == "segment_end").GetProperty("event_sequence").GetInt64(), "final seal precedes segment end");
            var catalog = File.ReadAllLines(Path.Combine(segment, "storage-index.jsonl"));
            Check(seals.Length == records.Length && seals.Select((e, i) => e.GetProperty("storage_cohort_ordinal").GetInt32() == i + 1 && e.GetProperty("index_record_sha256").GetString() == Hash(Encoding.UTF8.GetBytes(catalog[i] + "\n"))).All(x => x), "seal exact LF hash and global ordinal");
            var liveFrames = events.Where(e => e.GetProperty("kind").GetString() == "frame").ToArray();
            Check(frames.Select((f, i) => f.GetRawText() == liveFrames[i].GetProperty("recording_frame").GetRawText()).All(x => x), "live raw frame bytes unchanged");
            foreach (string file in Directory.EnumerateFiles(output, "*", SearchOption.AllDirectories)) { using var exclusive = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
            Check(true, "all artifact handles closed");

            phase = "default-byte-parity"; string flat = New(); Directory.CreateDirectory(flat);
            File.Copy(Path.Combine(segment, "profile.json"), Path.Combine(flat, "profile.json"));
            FieldRecording.ChunkWriter writer;
            using (writer = new(flat, new()))
            { foreach (var row in raw) { if (row.GetProperty("kind").GetString() == "frame") Check(writer.WriteFrame(row.GetRawText()) is null, "same frame admitted"); else writer.WriteSummary(row.GetRawText()); } }
            Check(Inflate(File.ReadAllBytes(Path.Combine(flat, "samples.jsonl.gz"))).SequenceEqual(Raw(segment)), "default and rotated JSONL exact byte parity");
            var manifest = Obj(Path.Combine(segment, "manifest.json"));
            foreach (string key in manifest.Select(p => p.Key).Where(k => k.Contains("storage", StringComparison.Ordinal)).ToArray()) manifest.Remove(key);
            manifest["schema"] = "overwatch-decoder.field-recording/1"; manifest["samples_file"] = "samples.jsonl.gz"; manifest["index_file"] = "chunks.jsonl";
            manifest["durable_chunks"] = writer.Chunks; manifest["durable_compressed_bytes"] = writer.CompressedBytes; manifest["index_bytes"] = writer.IndexBytes;
            manifest["samples_sha256"] = writer.SamplesHash; manifest["durable_samples_prefix_sha256"] = writer.SamplesHash;
            manifest["index_sha256"] = writer.IndexHash; manifest["durable_index_prefix_sha256"] = writer.IndexHash;
            File.WriteAllText(Path.Combine(flat, "manifest.json"), manifest.ToJsonString()); var flatCheck = FieldRecordingVerification.Verify(flat);
            Check(flatCheck.valid && flatCheck.frames == verified.frames && flatCheck.json_prefix_sha256 == verified.json_prefix_sha256, "default strict semantic parity:" + flatCheck.error_code);

            phase = "corruption";
            foreach (string corruption in new[] { "hash", "truncate", "ordinal", "profile", "chain", "range", "unsealed" })
            {
                string bad = Copy(segment); string catPath = Path.Combine(bad, "storage-index.jsonl"); var rows = Cohorts(bad);
                if (corruption is "hash" or "truncate")
                { string p = Path.Combine(bad, "storage-000002", "samples.jsonl.gz"); byte[] b = File.ReadAllBytes(p); if (corruption == "hash") b[^1] ^= 1; else b = b[..^1]; File.WriteAllBytes(p, b); }
                else if (corruption == "unsealed") Directory.CreateDirectory(Path.Combine(bad, "storage-999999"));
                else
                { if (corruption == "ordinal") rows[0]["ordinal"] = 2; if (corruption == "profile") rows[0]["profile_sha256"] = new string('a', 64); if (corruption == "chain") rows[1]["previous_record_sha256"] = new string('b', 64); if (corruption == "range") rows[1]["first_line"] = 0; File.WriteAllText(catPath, string.Concat(rows.Select(r => r.ToJsonString() + "\n"))); }
                var badResult = FieldRecordingVerification.Verify(bad, true);
                Check(!badResult.valid && !badResult.complete, corruption + " rejected");
                if (corruption is "hash" or "truncate") Check(badResult.recoverable && badResult.frames > 0 && badResult.frames < verified.frames, "only earlier verified cohort recovered");
            }
            string semantic = Copy(segment); string childPath = Path.Combine(semantic, "storage-000001");
            var entries = File.ReadAllLines(Path.Combine(childPath, "chunks.jsonl")).Select(l => JsonNode.Parse(l)!.AsObject()).ToArray();
            byte[] original = File.ReadAllBytes(Path.Combine(childPath, "samples.jsonl.gz")); using var rewritten = new MemoryStream();
            for (int i = 0; i < entries.Length; i++)
            {
                var entry = entries[i]; byte[] member = original.AsSpan((int)entry["offset"]!.GetValue<long>(), entry["compressed_bytes"]!.GetValue<int>()).ToArray();
                if (i == 0)
                {
                    byte[] json = Inflate(member); string text = Encoding.UTF8.GetString(json); int at = text.IndexOf("\"sequence\":0", StringComparison.Ordinal);
                    Check(at >= 0, "semantic mutation locates first sequence"); text = text[..at] + "\"sequence\":1" + text[(at + "\"sequence\":0".Length)..]; json = Encoding.UTF8.GetBytes(text);
                    using var encoded = new MemoryStream(); using (var gzip = new GZipStream(encoded, CompressionLevel.Fastest, true)) gzip.Write(json); member = encoded.ToArray();
                    entry["compressed_bytes"] = member.Length; entry["compressed_sha256"] = Hash(member); entry["json_sha256"] = Hash(json);
                }
                entry["offset"] = rewritten.Length; rewritten.Write(member);
            }
            File.WriteAllBytes(Path.Combine(childPath, "samples.jsonl.gz"), rewritten.ToArray());
            File.WriteAllText(Path.Combine(childPath, "chunks.jsonl"), string.Concat(entries.Select(e => e.ToJsonString() + "\n"))); Rehash(semantic);
            var semanticResult = FieldRecordingVerification.Verify(semantic);
            Check(!semanticResult.valid && semanticResult.error_code is not ("storage_file_hash_mismatch" or "storage_index_hash_mismatch" or "compressed_hash_mismatch" or "json_hash_mismatch"), "rehash cannot hide broken frame sequence:" + semanticResult.error_code);
            phase = "caps"; using var capLive = new Live(); output = New();
            var capped = Capture(new(), output, capLive, maximum: 1);
            Check(capped.stop_reason == "storage_cohort_limit" && capped.acquisitions.Length == 1 && capLive.Seals == 1, "cohort cap stops same sampler");
            Check(FieldRecordingVerification.Verify(Path.Combine(output, capped.segments.Single().directory)).valid, "cap terminal strictly verifies");
            using var globalLive = new Live(); output = New(); m = new();
            var global = Capture(m, output, globalLive, frame: (_, f) => { if (f.Sequence == 0) m.Version++; }, maximum: 2);
            Check(global.stop_reason == "storage_cohort_limit" && global.segments.Length == 2 && globalLive.Seals == 2, "cohort cap global across actual guard epochs");
            Check(global.fields.All(f => f.unknown == 2), "guard failure unknowns never resumed");
            phase = "failure"; using var failureLive = new Live(); output = New();
            var failure = Capture(new(), output, failureLive, frame: (_, f) => { if (f.Sequence == 0) Directory.CreateDirectory(Path.Combine(output, "segment-0001", "storage-000002")); });
            Check(!failure.complete && failure.stop_reason == "storage_path_exists", "rotation path failure closed:" + failure.stop_reason);
            using var pipe = new Live { FailSeal = true }; output = New(); var pipeResult = Capture(new(), output, pipe);
            Check(!pipeResult.complete && pipeResult.stop_reason == "live_output_io_error", "seal publication failure closed:" + pipeResult.stop_reason);
            using var exit = new Live(); output = New(); m = new(); var exited = Capture(m, output, exit, frame: (_, f) => { if (f.Sequence == 2) m.Failure = "process_exited"; });
            Check(!exited.complete && exited.stop_reason == "process_exited", "target lifetime preserved");
            phase = "background-refresh"; using var refreshLive = new Live(); output = New();
            var refresh = Capture(new(), output, refreshLive, background: true, seconds: 6.2);
            Check(refresh.complete && refresh.acquisitions.Length >= 2 && refresh.segments.Length == 1 && refresh.unchanged_preparations!.Length >= 1, "five second refresh without storage reacquisition");
            Check(FieldRecordingVerification.Verify(Path.Combine(output, refresh.segments.Single().directory)).valid, "refreshed recording strictly verifies");
            phase = "bounded-tracking"; string stress = New(); Directory.CreateDirectory(stress); long before = GC.GetTotalMemory(true); int maxHandles = 0;
            var storage = new FieldStorageCohorts(stress, new string('a', 64), new(65536, 1000), 16 * 1024 * 1024, () => 0, null);
            using (storage)
            { for (int i = 0; i < 1000; i++) { maxHandles = Math.Max(maxHandles, storage.OpenOutputStreams); storage.Write(new byte[64], Encoding.UTF8.GetBytes("{}\n"), 64, 1); if (i < 999) Check(storage.Rotate(i + 1, i + 1), "bounded stress rotation"); } storage.Seal(true); Check(storage.OpenOutputStreams == 1, "sealed cohort closes two streams"); }
            Check(storage.OpenOutputStreams == 0 && maxHandles == 3 && GC.GetTotalMemory(true) - before < 16 * 1024 * 1024, "bounded handles and retained managed memory");
            phase = "preflight"; string oversized = New(); Directory.CreateDirectory(oversized);
            using (var small = new FieldRecording.ChunkWriter(oversized, new(), storage: new(65536), profileHash: new string('a', 64)))
            { Check(small.WriteFrame(new string('x', 65536)) == "storage_cohort_chunk_limit" && small.DurableLines == 0, "oversized frame refused before accepting bytes"); }
            Check(Program.StorageOption(new()) is null, "storage disabled by default");
            foreach (var options in new[] { new Dictionary<string, string> { ["storage-cohort-bytes"] = "1" }, new Dictionary<string, string> { ["max-storage-cohorts"] = "2" }, new Dictionary<string, string> { ["storage-cohort-bytes"] = "65536", ["max-storage-cohorts"] = "4097" } })
            { try { Program.StorageOption(options); Check(false, "invalid CLI rejected"); } catch (ObservationException e) { Check(e.Code == "invalid_arguments", "bounded CLI validation"); } }
            Metrics = new { frames = verified.frames, cohorts = records.Length, acquisitions = result.acquisitions.Length, segments = result.segments.Length,
                cohort_byte_limit = 65536, maximum_actual_cohort_bytes = records.Max(r => r["compressed_bytes"]!.GetValue<long>()), skipped_intervals = verified.skipped_intervals,
                unchanged_background_refreshes = refresh.unchanged_preparations!.Length, stress_cohorts = 1000, maximum_open_output_streams = maxHandles, default_jsonl_byte_parity = true, game_validation = false };
            return assertions;
        }
        finally { Directory.Delete(root, true); }
    }
}
