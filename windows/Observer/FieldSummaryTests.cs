using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Synthetic values and a deterministic saved clock; no live process or application data.</summary>
public static class FieldSummaryTests
{
    private sealed class Fixture(CancellationTokenSource stop) : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(321, "fixture.exe", "private-fixture-path", 9, new string('b', 64), "x64");
        private int guards;
        public byte[] Read(ulong address, int size)
        {
            if (address == 0x1000) { if (++guards == 16) stop.Cancel(); return [1]; }
            if (address == 0x1100) return [4];
            if (address == 0x1008) return BitConverter.GetBytes(0x2000UL);
            if (address == 0x2000) return [2];
            int frame = (guards - 1) / 2;
            if (address == 0x2008 && frame != 2) return [(byte)new[] { 0, 255, 5, 7, 9, 10, 11, 12 }[frame]];
            if (address == 0x2010)
            {
                float[][] vectors = [[1, 2, 3], [1, 4, 3], [1, 4, 3], [2, 4, 3], [2, 4, 3], [3, 5, 6], [3, 5, 6], [4, 6, 7]];
                return vectors[frame].SelectMany(BitConverter.GetBytes).ToArray();
            }
            throw new ObservationException("unreadable_range", "Synthetic read gap.");
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }

    public static int Run()
    {
        int assertions = 0, id = 0; string phase = "setup";
        void Check(bool condition, string message)
        { if (!condition) throw new ObservationException("self_test_failed", "field-summary:" + phase + ":" + message); assertions++; }
        void Throws(Action action, string code)
        {
            try { action(); }
            catch (ObservationException e) { Check(e.Code == code, "expected " + code + " got " + e.Code); return; }
            throw new ObservationException("self_test_failed", "field-summary:" + phase + ":expected " + code);
        }
        static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        static JsonObject Object(string path) => JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        static void Save(string path, JsonNode value) => File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(value));
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-field-summary-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        Dictionary<string, string> Hashes(string directory) => Directory.GetFiles(directory).ToDictionary(p => Path.GetFileName(p), p => Hash(File.ReadAllBytes(p)));
        string Copy(string from)
        {
            string directory = Path.Combine(root, "copy-" + id++); Directory.CreateDirectory(directory);
            foreach (string file in Directory.GetFiles(from)) File.Copy(file, Path.Combine(directory, Path.GetFileName(file)));
            return directory;
        }
        JsonObject[] ReadRows(string directory)
        {
            using var file = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz")); using var gzip = new GZipStream(file, CompressionMode.Decompress);
            using var reader = new StreamReader(gzip); var rows = new List<JsonObject>();
            while (reader.ReadLine() is { } line) rows.Add(JsonNode.Parse(line)!.AsObject());
            return rows.ToArray();
        }
        string Capture(bool v2, bool empty = false, bool duration = false)
        {
            using var cancel = new CancellationTokenSource(); if (empty) cancel.Cancel(); var source = new Fixture(cancel);
            var p = new JsonObject
            {
                ["schema"] = "overwatch-decoder.field-profile/" + (v2 ? "2" : "1"), ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(source.Identity)),
                ["guards"] = new JsonArray(new JsonObject { ["address"] = 0x1000, ["bytes_hex"] = "01" }),
                ["fields"] = new JsonArray(
                    new JsonObject { ["name"] = "byte_candidate", ["type"] = "u8", ["address"] = 0x2008, ["min"] = 0, ["max"] = 255 },
                    new JsonObject { ["name"] = "vector_candidate", ["type"] = "f32x3", ["address"] = 0x2010 },
                    new JsonObject { ["name"] = "gap_candidate", ["type"] = "f64", ["address"] = 0x2030 },
                    new JsonObject { ["name"] = "unread_candidate", ["type"] = "u8", ["address"] = 0x2040,
                        ["guards"] = new JsonArray(new JsonObject { ["address"] = 0x1100, ["bytes_hex"] = "03" }) })
            };
            if (v2)
            {
                p["paths"] = new JsonArray(new JsonObject
                {
                    ["name"] = "storage", ["root_address"] = 0x1000,
                    ["root_guards"] = new JsonArray(new JsonObject { ["offset"] = 0, ["bytes_hex"] = "01" }),
                    ["hops"] = new JsonArray(new JsonObject { ["pointer_offset"] = 8,
                        ["destination_guards"] = new JsonArray(new JsonObject { ["offset"] = 0, ["bytes_hex"] = "02" }) })
                });
                for (int n = 0; n < 2; n++)
                { var f = p["fields"]![n]!.AsObject(); f.Remove("address"); f["path"] = "storage"; f["offset"] = n == 0 ? 8 : 16; }
            }
            string profile = Path.Combine(root, "profile-" + id++ + ".json"); Save(profile, p);
            string directory = Path.Combine(root, "recording-" + id++);
            FieldRecording.RecordBounded(source, profile, directory, 10, duration ? TimeSpan.FromMilliseconds(1) : TimeSpan.FromSeconds(30),
                cancel.Token, new(ChunkBytes: 8192));
            return directory;
        }
        void FixedClock(string directory)
        {
            // Only synthetic saved evidence is retimed. This avoids scheduling-dependent expected change counts.
            JsonObject[] rows = ReadRows(directory); Check(rows.Length == 9, "sample-controlled eight frames plus summary");
            long origin = rows[0]["monotonic_origin_ticks"]!.GetValue<long>(), frequency = rows[0]["monotonic_frequency"]!.GetValue<long>();
            long interval = Math.Max(1, (long)(10d * frequency / 1000)); long[] slots = [0, 1, 2, 3, 4, 8, 9, 10];
            long maximumFrame = 0, end = origin;
            for (int n = 0; n < 8; n++)
            {
                var stamps = new List<(JsonObject owner, string name, long value)>();
                void Find(JsonNode? node)
                {
                    if (node is JsonObject o)
                        foreach (var item in o)
                        {
                            if (item.Key is "start_ticks" or "end_ticks" or "read_start_ticks" or "read_end_ticks" && item.Value is not null)
                                stamps.Add((o, item.Key, item.Value.GetValue<long>()));
                            else Find(item.Value);
                        }
                    else if (node is JsonArray a) foreach (var child in a) Find(child);
                }
                Find(rows[n]); var ordered = stamps.Select(x => x.value).Distinct().Order().ToArray();
                var mapping = ordered.Select((value, rank) => (value, ticks: origin + slots[n] * interval + rank * 100L)).ToDictionary(x => x.value, x => x.ticks);
                foreach (var stamp in stamps) stamp.owner[stamp.name] = mapping[stamp.value];
                rows[n]["scheduled_slot"] = slots[n]; rows[n]["scheduled_ticks"] = origin + slots[n] * interval; rows[n]["jitter_ticks"] = 0;
                rows[n]["skipped_intervals_before"] = n == 5 ? 3 : 0; rows[n]["skipped_intervals_total"] = n >= 5 ? 3 : 0;
                end = rows[n]["end_ticks"]!.GetValue<long>(); maximumFrame = Math.Max(maximumFrame, end - rows[n]["start_ticks"]!.GetValue<long>());
            }
            rows[^1]["skipped_intervals"] = 3; rows[^1]["maximum_jitter_ms"] = 0;
            rows[^1]["maximum_frame_ms"] = maximumFrame * 1000d / frequency; rows[^1]["elapsed_ms"] = (end - origin) * 1000d / frequency + 1;
            rows[^1]["frame_output_utf8_bytes"] = rows[..^1].Sum(x => (long)JsonSerializer.SerializeToUtf8Bytes(x).Length + 1);
            using var samples = new MemoryStream(); using var index = new MemoryStream(); long json = 0;
            for (int n = 0; n < rows.Length; n++)
            {
                byte[] raw = Encoding.UTF8.GetBytes(rows[n].ToJsonString() + "\n"); using var member = new MemoryStream();
                using (var gzip = new GZipStream(member, CompressionLevel.Fastest, true)) gzip.Write(raw);
                byte[] compressed = member.ToArray();
                byte[] entry = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { schema = "overwatch-decoder.field-recording-chunk/1", sequence = n,
                    offset = samples.Length, compressed_bytes = compressed.Length, json_bytes = raw.Length, first_line = n, lines = 1,
                    compressed_sha256 = Hash(compressed), json_sha256 = Hash(raw), checkpoint_ticks = end + 100, monotonic_frequency = frequency }) + "\n");
                samples.Write(compressed); index.Write(entry); json += raw.Length;
            }
            byte[] sb = samples.ToArray(), ib = index.ToArray(); File.WriteAllBytes(Path.Combine(directory, "samples.jsonl.gz"), sb); File.WriteAllBytes(Path.Combine(directory, "chunks.jsonl"), ib);
            var manifest = Object(Path.Combine(directory, "manifest.json"));
            manifest["stream_summary"] = rows[^1].DeepClone(); manifest["durable_chunks"] = rows.Length; manifest["durable_lines"] = rows.Length;
            manifest["durable_compressed_bytes"] = sb.Length; manifest["durable_json_bytes"] = json; manifest["index_bytes"] = ib.Length;
            manifest["samples_sha256"] = Hash(sb); manifest["durable_samples_prefix_sha256"] = Hash(sb);
            manifest["index_sha256"] = Hash(ib); manifest["durable_index_prefix_sha256"] = Hash(ib); Save(Path.Combine(directory, "manifest.json"), manifest);
            var verified = FieldRecordingVerification.Verify(directory); Check(verified.valid && verified.frames == 8 && verified.skipped_intervals == 3, "deterministic fixture is strictly valid:" + verified.error_code);
        }
        JsonElement Field(JsonElement report, string name) => report.GetProperty("fields").EnumerateArray().Single(f => f.GetProperty("name").GetString() == name);
        try
        {
            foreach (bool v2 in new[] { false, true })
            {
                phase = "numeric-summary-v" + (v2 ? 2 : 1);
                string directory = Capture(v2); FixedClock(directory); var hashes = Hashes(directory); var rows = ReadRows(directory);
                JsonElement report = FieldSummary.Summarize(directory), b = Field(report, "byte_candidate"), vector = Field(report, "vector_candidate");
                Check(report.GetProperty("complete").GetBoolean() && !report.GetProperty("source_complete").GetBoolean() && report.GetProperty("source_status").GetString() == "verified_stopped", "report success preserves stopped source");
                Check(report.GetProperty("frames").GetInt32() == 8 && report.GetProperty("skipped_intervals").GetInt32() == 3, "all source frames and skipped slots");
                Check(b.GetProperty("observed_count").GetInt32() == 6 && b.GetProperty("unknown_count").GetInt32() == 2 &&
                    b.GetProperty("unknown_reasons").GetProperty("unreadable_range").GetInt32() == 1 && b.GetProperty("unknown_reasons").GetProperty("cancelled").GetInt32() == 1, "unknowns grouped without stale values");
                Check(b.GetProperty("components")[0].GetProperty("minimum").GetInt32() == 0 && b.GetProperty("components")[0].GetProperty("maximum").GetInt32() == 255, "u8 endpoint range");
                Check(b.GetProperty("eligible_adjacent_observed_pairs").GetInt32() == 3 && b.GetProperty("observed_numeric_changes").GetInt32() == 3, "unknown and skipped slot each break byte comparisons");
                Check(vector.GetProperty("observed_count").GetInt32() == 7 && vector.GetProperty("observed_numeric_changes").GetInt32() == 2 && vector.GetProperty("eligible_adjacent_observed_pairs").GetInt32() == 5, "vector changes counted once and skip excluded");
                for (int n = 0; n < 3; n++) Check(vector.GetProperty("components")[n].GetProperty("minimum").GetDouble() == n + 1 &&
                    vector.GetProperty("components")[n].GetProperty("maximum").GetDouble() == new[] { 3, 5, 6 }[n], "vector component range " + n);
                JsonObject ByteRow(int n) => rows[n]["fields"]!["byte_candidate"]!.AsObject();
                Check(b.GetProperty("first_read").GetProperty("start_ticks").GetInt64() == ByteRow(0)["read_start_ticks"]!.GetValue<long>() &&
                    b.GetProperty("last_read").GetProperty("end_ticks").GetInt64() == ByteRow(7)["read_end_ticks"]!.GetValue<long>(), "actual read boundaries include unknown reads");
                Check(b.GetProperty("last_observed_read").GetProperty("end_ticks").GetInt64() == ByteRow(6)["read_end_ticks"]!.GetValue<long>(), "last observed boundary excludes cancelled frame");
                Check(b.GetProperty("largest_observed_sampling_gap_ticks").GetInt64() == ByteRow(5)["read_start_ticks"]!.GetValue<long>() - ByteRow(4)["read_start_ticks"]!.GetValue<long>(), "largest observed gap spans missed slots");
                Check(b.GetProperty("largest_read_duration_ticks").GetInt64() == Enumerable.Range(0, 8).Max(n => ByteRow(n)["read_end_ticks"]!.GetValue<long>() - ByteRow(n)["read_start_ticks"]!.GetValue<long>()), "maximum recorded field read duration");
                var never = Field(report, "unread_candidate");
                Check(never.GetProperty("observed_count").GetInt32() == 0 && never.GetProperty("unknown_count").GetInt32() == 8 &&
                    never.GetProperty("first_read").ValueKind == JsonValueKind.Null && never.GetProperty("components")[0].GetProperty("minimum").ValueKind == JsonValueKind.Null &&
                    never.GetProperty("largest_observed_sampling_gap_ticks").ValueKind == JsonValueKind.Null, "unread field has null coverage and ranges");
                Check(Field(report, "gap_candidate").GetProperty("recorded_read_intervals").GetInt32() == 8, "failed read intervals remain measured");
                Check(report.GetProperty("profile_sha256").GetString() == hashes["profile.json"] && report.GetProperty("manifest_sha256").GetString() == hashes["manifest.json"] &&
                    report.GetProperty("samples_sha256").GetString() == hashes["samples.jsonl.gz"] && report.GetProperty("index_sha256").GetString() == hashes["chunks.jsonl"], "exact artifact provenance");
                Check(hashes.OrderBy(x => x.Key).SequenceEqual(Hashes(directory).OrderBy(x => x.Key)), "source unchanged");
                string text = JsonSerializer.Serialize(report, Program.Json);
                Check(text.Contains("\"first_read\":null") && !text.Contains("address") && !text.Contains("bytes_hex") && !text.Contains(root), "CLI serialization retains nulls and omits structural addresses");

                phase = "strict-failure-and-cancellation";
                string bad = Copy(directory); var manifest = Object(Path.Combine(bad, "manifest.json")); manifest["durable_lines"] = 99; Save(Path.Combine(bad, "manifest.json"), manifest);
                long consumed = 0; Throws(() => FieldSummary.SummarizeBounded(bad, default, new(), n => consumed = n), "invalid_recording");
                Check(consumed == 8, "late manifest failure discards accumulated report");
                bad = Copy(directory); using (var file = File.OpenWrite(Path.Combine(bad, "samples.jsonl.gz"))) file.SetLength(file.Length - 1);
                Throws(() => FieldSummary.Summarize(bad), "invalid_recording");
                foreach (int cancelAt in new[] { 0, 3, 8 })
                {
                    using var cancel = new CancellationTokenSource(); if (cancelAt == 0) cancel.Cancel();
                    Throws(() => FieldSummary.SummarizeBounded(directory, cancel.Token, new(), n => { if (n == cancelAt) cancel.Cancel(); }), "cancelled");
                }
                Throws(() => FieldSummary.SummarizeBounded(directory, default, new(ReasonsPerField: 1)), "summary_reason_limit");
                Throws(() => FieldSummary.SummarizeBounded(directory, default, new(ReasonEntries: 2)), "summary_reason_limit");
                Throws(() => FieldSummary.SummarizeBounded(directory, default, new(ReportBytes: 1)), "summary_byte_limit");
                Throws(() => FieldSummary.SummarizeBounded(directory, default, new(Verification: new(JsonBytes: 1))), "invalid_recording");
                Throws(() => FieldSummary.SummarizeBounded(directory, default, new(ReasonsPerField: 0)), "invalid_arguments");
                Check(hashes.OrderBy(x => x.Key).SequenceEqual(Hashes(directory).OrderBy(x => x.Key)), "failure paths leave source unchanged");

                phase = "zero-frames-and-complete";
                var empty = FieldSummary.Summarize(Capture(v2, empty: true));
                Check(empty.GetProperty("frames").GetInt32() == 0 && !empty.GetProperty("source_complete").GetBoolean(), "zero-frame stopped recording summarized");
                var emptyField = Field(empty, "byte_candidate");
                Check(emptyField.GetProperty("observed_count").GetInt32() == 0 && emptyField.GetProperty("unknown_count").GetInt32() == 0 &&
                    emptyField.GetProperty("largest_read_duration_ticks").ValueKind == JsonValueKind.Null && emptyField.GetProperty("unknown_reasons").EnumerateObject().Count() == 0, "no invented empty-source observations");
                var completed = FieldSummary.Summarize(Capture(v2, duration: true));
                Check(completed.GetProperty("source_complete").GetBoolean() && completed.GetProperty("source_status").GetString() == "verified_complete", "duration completion distinct from stopped");
            }
        }
        catch (ObservationException) { throw; }
        catch (Exception e) { throw new ObservationException("self_test_failed", "field-summary:" + phase + ":" + e.GetType().Name); }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
