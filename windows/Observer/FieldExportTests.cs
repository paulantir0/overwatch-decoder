using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Small synthetic artifacts only; export never reads a live process.</summary>
public static class FieldExportTests
{
    private sealed class Fixture : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(321, "fixture.exe", "private-test-path", 9, new string('b', 64), "x64");
        public Action<int>? AfterValue;
        public int Values;
        public bool V2;
        private ulong pointer = 0x2000;
        private bool first = true;
        public byte[] Read(ulong address, int size)
        {
            if (first) { first = false; Thread.Sleep(40); }
            if (address == 0x800) return BitConverter.GetBytes(9);
            if (address == 0x1000) return BitConverter.GetBytes(1);
            if (address == 0x1010) return BitConverter.GetBytes(pointer);
            if (address is 0x2000 or 0x3000) return BitConverter.GetBytes(2);
            if (address is 0x2008 or 0x3008)
            {
                if (Values == 1) pointer = 0x3000; // A guarded in-frame relocation: unknown, not stale.
                return BitConverter.GetBytes(address == 0x2008 ? 123 : 456)[..size];
            }
            if (address == 0x900) return new[] { -1.25f, float.Epsilon, 123.456f }.SelectMany(BitConverter.GetBytes).ToArray();
            if (address == 0x920) return BitConverter.GetBytes(Math.BitIncrement(1d));
            if (address == 0x940) return new[] { int.MinValue, -1, 0, int.MaxValue }.SelectMany(BitConverter.GetBytes).ToArray();
            if (address == 0x930) return [0];
            if (address == 0x931) return [255];
            AfterValue?.Invoke(++Values);
            if (!V2 && Values == 2) throw new ObservationException("partial_read", "Synthetic unavailable value.");
            return BitConverter.GetBytes(Values);
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }

    public static int Run()
    {
        int count = 0, id = 0; string phase = "setup";
        void Check(bool ok, string why)
        { if (!ok) throw new ObservationException("self_test_failed", "field-export:" + phase + ":" + why); count++; }
        void Throws(Action action, string code)
        {
            try { action(); }
            catch (ObservationException e) { Check(e.Code == code, "expected " + code + " got " + e.Code); return; }
            throw new ObservationException("self_test_failed", "field-export:" + phase + ":expected " + code);
        }
        static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        static JsonObject Object(string path) => JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        static void Save(string path, JsonNode value) => File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(value));
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-field-export-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string Destination() => Path.Combine(root, "export-" + id++ + ".jsonl");
        string Capture(bool v2 = false, bool duration = false, bool noFrames = false)
        {
            var source = new Fixture { V2 = v2 }; using var stop = new CancellationTokenSource();
            if (!duration) source.AfterValue = n => { if (n == 4) stop.Cancel(); };
            if (noFrames) stop.Cancel();
            var profile = new JsonObject
            {
                ["schema"] = "overwatch-decoder.field-profile/" + (v2 ? "2" : "1"),
                ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(source.Identity)),
                ["guards"] = new JsonArray(new JsonObject { ["address"] = 0x800, ["bytes_hex"] = "09000000" }),
                ["fields"] = new JsonArray(
                    new JsonObject { ["name"] = "vector_candidate", ["type"] = "f32x3", ["address"] = 0x900 },
                    new JsonObject { ["name"] = "integer_vector_candidate", ["type"] = "i32x4", ["address"] = 0x940 },
                    new JsonObject { ["name"] = "double_candidate", ["type"] = "f64", ["address"] = 0x920 },
                    new JsonObject { ["name"] = "zero_byte_candidate", ["type"] = "u8", ["address"] = 0x930 },
                    new JsonObject { ["name"] = "max_byte_candidate", ["type"] = "u8", ["address"] = 0x931 },
                    new JsonObject { ["name"] = "counter_candidate", ["type"] = "i32", ["address"] = 0x808 })
            };
            if (v2)
            {
                profile["paths"] = new JsonArray(new JsonObject
                {
                    ["name"] = "storage", ["root_address"] = 0x1000,
                    ["root_guards"] = new JsonArray(new JsonObject { ["offset"] = 0, ["bytes_hex"] = "01000000" }),
                    ["hops"] = new JsonArray(new JsonObject
                    {
                        ["pointer_offset"] = 16,
                        ["destination_guards"] = new JsonArray(new JsonObject { ["offset"] = 0, ["bytes_hex"] = "02000000" })
                    })
                });
                profile["fields"]!.AsArray().Insert(0, new JsonObject { ["name"] = "moving_candidate", ["type"] = "i32", ["path"] = "storage", ["offset"] = 8 });
                profile["fields"]!.AsArray().Insert(1, new JsonObject { ["name"] = "moving_byte_candidate", ["type"] = "u8", ["path"] = "storage", ["offset"] = 8 });
            }
            string path = Path.Combine(root, "profile-" + id++ + ".json"); Save(path, profile);
            string directory = Path.Combine(root, "recording-" + id++);
            FieldRecording.RecordBounded(source, path, directory, 10,
                duration ? TimeSpan.FromMilliseconds(40) : TimeSpan.FromSeconds(30), stop.Token, new(ChunkBytes: 8192));
            return directory;
        }
        JsonElement[] Recorded(string directory)
        {
            using var input = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz"));
            using var gzip = new GZipStream(input, CompressionMode.Decompress); using var reader = new StreamReader(gzip);
            var rows = new List<JsonElement>();
            while (reader.ReadLine() is { } line) { using var doc = JsonDocument.Parse(line); rows.Add(doc.RootElement.Clone()); }
            return rows.ToArray();
        }
        static JsonElement[] Exported(string path) => File.ReadLines(path).Select(line =>
        { using var doc = JsonDocument.Parse(line); return doc.RootElement.Clone(); }).ToArray();
        Dictionary<string, string> Fingerprint(string directory) => Directory.GetFiles(directory)
            .ToDictionary(path => Path.GetFileName(path), path => Hash(File.ReadAllBytes(path)));
        void Unchanged(Dictionary<string, string> before, string directory)
        { Check(before.OrderBy(x => x.Key).SequenceEqual(Fingerprint(directory).OrderBy(x => x.Key)), "source files unchanged"); }
        string Copy(string from)
        {
            string directory = Path.Combine(root, "copy-" + id++); Directory.CreateDirectory(directory);
            foreach (string file in Directory.GetFiles(from)) File.Copy(file, Path.Combine(directory, Path.GetFileName(file)));
            return directory;
        }
        void NoPartial(string destination)
        { Check(!Path.Exists(destination) && !Directory.GetFiles(root, ".overwatch-decoder-export-*.partial").Any(), "no destination or partial remains"); }
        void Reject(string directory, string code = "invalid_recording", FieldExport.Limits? limits = null, bool expectProjection = false)
        {
            var before = Fingerprint(directory); string destination = Destination(); long written = 0;
            Throws(() => FieldExport.ExportBounded(directory, destination, default, limits ?? new(), n => written = n), code);
            if (expectProjection) Check(written > 1, "late source rejection follows real temporary frame writes");
            NoPartial(destination); Unchanged(before, directory);
        }
        void Redacted(JsonElement e)
        {
            if (e.ValueKind == JsonValueKind.Object)
                foreach (var p in e.EnumerateObject())
                {
                    Check(p.Name is not ("address" or "address_hex" or "read_address_hex" or "root_address" or "bytes_hex" or
                        "guards" or "guard_ids" or "guards_before" or "guards_after" or "paths" or "path_id" or "path_traces"), "no private trace property");
                    Redacted(p.Value);
                }
            else if (e.ValueKind == JsonValueKind.Array) foreach (var item in e.EnumerateArray()) Redacted(item);
        }
        // Rewrite all members with coherent hashes to exercise semantic validation, not just a hash failure.
        void Rewrite(string directory, Action<JsonObject[]> change)
        {
            var rows = Recorded(directory).Select(e => JsonNode.Parse(e.GetRawText())!.AsObject()).ToArray();
            change(rows);
            rows[^1]["frame_output_utf8_bytes"] = rows[..^1].Sum(x => (long)JsonSerializer.SerializeToUtf8Bytes(x).Length + 1);
            JsonObject manifest = Object(Path.Combine(directory, "manifest.json"));
            long checkpoint = File.ReadLines(Path.Combine(directory, "chunks.jsonl")).Select(x => JsonNode.Parse(x)!["checkpoint_ticks"]!.GetValue<long>()).Max();
            using var samples = new MemoryStream(); using var index = new MemoryStream(); long total = 0;
            for (int n = 0; n < rows.Length; n++)
            {
                byte[] raw = Encoding.UTF8.GetBytes(rows[n].ToJsonString() + "\n"); using var buffer = new MemoryStream();
                using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, true)) gzip.Write(raw);
                byte[] member = buffer.ToArray();
                byte[] entry = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
                {
                    schema = "overwatch-decoder.field-recording-chunk/1", sequence = n, offset = samples.Length, compressed_bytes = member.Length,
                    json_bytes = raw.Length, first_line = n, lines = 1, compressed_sha256 = Hash(member), json_sha256 = Hash(raw),
                    checkpoint_ticks = checkpoint, monotonic_frequency = rows[n]["monotonic_frequency"]!.GetValue<long>()
                }) + "\n");
                samples.Write(member); index.Write(entry); total += raw.Length;
            }
            byte[] sb = samples.ToArray(), ib = index.ToArray();
            File.WriteAllBytes(Path.Combine(directory, "samples.jsonl.gz"), sb); File.WriteAllBytes(Path.Combine(directory, "chunks.jsonl"), ib);
            manifest["durable_chunks"] = rows.Length; manifest["durable_lines"] = rows.Length;
            manifest["durable_compressed_bytes"] = sb.Length; manifest["durable_json_bytes"] = total; manifest["index_bytes"] = ib.Length;
            manifest["samples_sha256"] = Hash(sb); manifest["durable_samples_prefix_sha256"] = Hash(sb);
            manifest["index_sha256"] = Hash(ib); manifest["durable_index_prefix_sha256"] = Hash(ib);
            manifest["stream_summary"] = rows[^1].DeepClone(); Save(Path.Combine(directory, "manifest.json"), manifest);
        }
        try
        {
            phase = "roundtrip-v1-v2";
            string v1 = Capture(), v2 = Capture(v2: true);
            foreach (string directory in new[] { v1, v2 })
            {
                var before = Fingerprint(directory); var raw = Recorded(directory); string path = Destination();
                var result = FieldExport.Export(directory, path); var rows = Exported(path);
                Check(result.complete && !result.source_complete && result.source_status == "verified_stopped", "stopped source distinguished from successful export");
                Check(result.frames == 4 && rows.Length == raw.Length + 1 && result.output_lines == rows.Length, "all frames and exactly one header/summary");
                Check(result.skipped_intervals >= 1, "skipped slots retained under a controlled slow first read");
                Check(result.output_sha256 == Hash(File.ReadAllBytes(path)) && result.output_utf8_bytes == new FileInfo(path).Length, "output hash and bytes");
                Check(result.manifest_sha256 == before["manifest.json"] && result.profile_sha256 == before["profile.json"] &&
                    result.samples_sha256 == before["samples.jsonl.gz"] && result.index_sha256 == before["chunks.jsonl"], "exact artifact provenance");
                Check(!rows[0].GetProperty("public_state_eligible").GetBoolean() && !rows[0].GetProperty("runtime_semantics_validated").GetBoolean(), "research only");
                foreach (string key in new[] { "utc_origin", "utc_origin_before_ticks", "monotonic_origin_ticks", "monotonic_frequency" })
                    Check(rows[0].GetProperty(key).ToString() == raw[0].GetProperty(key).ToString(), "origin preserved " + key);
                for (int n = 0; n < raw.Length - 1; n++)
                {
                    foreach (string key in new[] { "sequence", "scheduled_slot", "scheduled_ticks", "start_ticks", "end_ticks", "jitter_ticks", "skipped_intervals_before", "skipped_intervals_total", "scheduler_backend" })
                        Check(rows[n + 1].GetProperty(key).GetRawText() == raw[n].GetProperty(key).GetRawText(), "frame preserved " + key);
                    foreach (var f in raw[n].GetProperty("fields").EnumerateObject())
                        foreach (string key in new[] { "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks", "read_attempted" })
                            if (f.Value.TryGetProperty(key, out var value))
                                Check(rows[n + 1].GetProperty("fields").GetProperty(f.Name).GetProperty(key).GetRawText() == value.GetRawText(), "field preserved " + key);
                }
                Check(rows[2].GetProperty("fields").GetProperty(directory == v1 ? "counter_candidate" : "moving_candidate").GetProperty("status").GetString() == "unknown", "read gap or moved pointer stays unknown");
                Check(rows[1].GetProperty("fields").GetProperty("zero_byte_candidate").GetProperty("value").GetRawText() == "0" &&
                    rows[1].GetProperty("fields").GetProperty("max_byte_candidate").GetProperty("value").GetRawText() == "255", "recorded u8 endpoints exported as exact JSON integers");
                if (directory == v2)
                    Check(rows[1].GetProperty("fields").GetProperty("moving_byte_candidate").GetProperty("value").GetRawText() == "123" &&
                        rows[2].GetProperty("fields").GetProperty("moving_byte_candidate").GetProperty("value").ValueKind == JsonValueKind.Null &&
                        rows[3].GetProperty("fields").GetProperty("moving_byte_candidate").GetProperty("value").GetRawText() == "200",
                        "one-byte path recording exports initial value, relocation unknown and fresh low byte");
                Check(rows[^1].GetProperty("frames").GetInt32() == 4 && rows[^1].GetProperty("stop_reason").GetString() == "cancelled", "terminal summary preserved");
                foreach (var row in rows) Redacted(row);
                Check(new FileInfo(path).Length < raw.Sum(row => Encoding.UTF8.GetByteCount(row.GetRawText()) + 1), "projection reduces decoded fixture size");
                Unchanged(before, directory);
            }
            phase = "complete-and-zero-frame-stopped";
            foreach (bool empty in new[] { false, true })
            {
                string directory = Capture(duration: !empty, noFrames: empty), path = Destination();
                var result = FieldExport.Export(directory, path); var rows = Exported(path);
                Check(result.source_complete == !empty, "source completion preserved");
                Check(rows[0].GetProperty("kind").GetString() == "metadata" && rows[^1].GetProperty("kind").GetString() == "summary", "origin from frame or zero-frame summary");
                if (empty) Check(rows.Length == 2 && result.frames == 0, "no invented empty-source frames");
            }
            phase = "corruption-and-truncation";
            string bad = Copy(v1); var m = Object(Path.Combine(bad, "manifest.json")); m["durable_lines"] = 100; Save(Path.Combine(bad, "manifest.json"), m); Reject(bad, expectProjection: true);
            bad = Copy(v1); File.AppendAllText(Path.Combine(bad, "samples.jsonl.gz"), "tail"); Reject(bad);
            bad = Copy(v1); using (var f = File.OpenWrite(Path.Combine(bad, "samples.jsonl.gz"))) f.SetLength(f.Length - 1); Reject(bad);
            bad = Copy(v1); File.AppendAllText(Path.Combine(bad, "chunks.jsonl"), "{"); Reject(bad);
            bad = Copy(v1); File.WriteAllText(Path.Combine(bad, "profile.json"), "{}"); Reject(bad);
            bad = Copy(v2); Rewrite(bad, rows => rows[0]["path_traces"]![0]!["hops"]![0]!["pointer_after"]!["bytes_hex"] = "0030000000000000"); Reject(bad);
            phase = "forged-byte-values-with-recomputed-hashes";
            foreach (string directory in new[] { v1, v2 })
            {
                foreach (string literal in new[] { "-1", "256", "1.5", "255.0", "\"255\"", "null" })
                {
                    bad = Copy(directory);
                    Rewrite(bad, rows => rows[0]["fields"]!["max_byte_candidate"]!["value"] = JsonNode.Parse(literal));
                    var verified = FieldRecordingVerification.Verify(bad);
                    Check(!verified.valid && verified.frames == 0 && verified.error_code is "invalid_field_value" or "malformed_recording",
                        "strict u8 verifier rejects non-byte JSON value " + literal);
                    Reject(bad);
                }
            }
            phase = "forged-integer-vectors-with-recomputed-hashes";
            foreach (string directory in new[] { v1, v2 })
            {
                foreach (string literal in new[] { "[1,2,3]", "[1,2,3,4,5]", "[1,2,3,2147483648]", "[-2147483649,2,3,4]", "[1.5,2,3,4]", "[1.0,2,3,4]", "[null,2,3,4]", "[\"1\",2,3,4]", "1" })
                {
                    bad = Copy(directory);
                    Rewrite(bad, rows => rows[0]["fields"]!["integer_vector_candidate"]!["value"] = JsonNode.Parse(literal));
                    Check(!FieldRecordingVerification.Verify(bad).valid, "strict i32x4 rejects malformed vector " + literal);
                    Reject(bad);
                }
            }
            phase = "bounds-cancellation-and-no-overwrite";
            Reject(v1, "export_byte_limit", new(OutputBytes: 1));
            Reject(v1, limits: new(Verification: new(JsonBytes: 1)));
            string output = Destination(); File.WriteAllText(output, "existing sentinel");
            Throws(() => FieldExport.Export(v1, output), "output_exists"); Check(File.ReadAllText(output) == "existing sentinel", "existing file preserved");
            string directoryOut = Path.Combine(root, "existing-directory"); Directory.CreateDirectory(directoryOut);
            Throws(() => FieldExport.Export(v1, directoryOut), "output_exists");
            Throws(() => FieldExport.Export(v1, Path.Combine(v1, "new.jsonl")), "invalid_arguments");
            if (!OperatingSystem.IsWindows())
            {
                string alias = Path.Combine(root, "source-alias"); Directory.CreateSymbolicLink(alias, v1);
                Throws(() => FieldExport.Export(v1, Path.Combine(alias, "new.jsonl")), "invalid_arguments");
                Check(!File.Exists(Path.Combine(v1, "new.jsonl")), "symlink alias does not write into source");
                Directory.Delete(alias);
            }
            foreach (int cancelAt in new[] { 0, 1, 3, 6 })
            {
                using var stop = new CancellationTokenSource(); if (cancelAt == 0) stop.Cancel(); output = Destination();
                Throws(() => FieldExport.ExportBounded(v2, output, stop.Token, new(), n => { if (n == cancelAt) stop.Cancel(); }), "cancelled");
                NoPartial(output);
            }
            output = Destination();
            Throws(() => FieldExport.ExportBounded(v1, output, default, new(), n => { if (n == 1) File.WriteAllText(output, "racing sentinel"); }), "output_exists");
            Check(File.ReadAllText(output) == "racing sentinel" && !Directory.GetFiles(root, ".overwatch-decoder-export-*.partial").Any(), "publication race preserves existing output");
            output = Destination();
            Throws(() => FieldExport.ExportBounded(v1, output, default, new(), _ => throw new IOException("synthetic output error")), "output_io_error");
            NoPartial(output);
        }
        catch (ObservationException) { throw; }
        catch (Exception e) { throw new ObservationException("self_test_failed", "field-export:" + phase + ":" + e.GetType().Name); }
        finally { Directory.Delete(root, true); }
        return count;
    }
}
