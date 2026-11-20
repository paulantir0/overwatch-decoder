using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Synthetic saved observations with deterministic clocks, never application memory.</summary>
public static class FieldTimelineTests
{
    private sealed class Fixture(CancellationTokenSource stop, int frameCount) : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(321, "fixture.exe", "private-fixture-path", 9, new string('b', 64), "x64");
        private int guards;
        public byte[] Read(ulong address, int size)
        {
            if (address == 0x800) { if (++guards == frameCount * 2) stop.Cancel(); return [1]; }
            int frame = (guards - 1) / 2;
            if (address == 0x808) return BitConverter.GetBytes(frame >= 7 ? 0x3000UL : 0x2000UL);
            if (address is 0x2000 or 0x3000) return [2];
            if (address is 0x2008 or 0x3008) return BitConverter.GetBytes(frame >= 8 ? 0x5000UL : 0x4000UL);
            if (address is 0x4000 or 0x5000) return [3];
            if (address is 0x4008 or 0x5008)
            {
                if (frame is 2 or 3) throw new ObservationException(frame == 2 ? "partial_read" : "unreadable_range", "Synthetic read gap.");
                return [(byte)new[] { 0, 255, 0, 0, 255, 10, 11, 11, 11, 12, 12, 13 }[frame]];
            }
            if (address is 0x4010 or 0x5010)
                return new[] { frame == 0 ? -0f : 0f, frame == 2 ? float.Epsilon : 0, -float.MaxValue }.SelectMany(BitConverter.GetBytes).ToArray();
            if (address == 0x900) return BitConverter.GetBytes(int.MinValue);
            if (address == 0x910) return BitConverter.GetBytes(Math.BitIncrement(1d));
            if (address == 0x940) return new[] { float.MinValue, float.MaxValue, float.Epsilon, -float.Epsilon }.SelectMany(BitConverter.GetBytes).ToArray();
            throw new ObservationException("unreadable_range", "Synthetic missing address.");
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }

    public static int Run()
    {
        int count = 0, id = 0; string phase = "setup";
        void Check(bool ok, string why)
        { if (!ok) throw new ObservationException("self_test_failed", "field-timeline:" + phase + ":" + why); count++; }
        void Throws(Action action, string code)
        {
            try { action(); }
            catch (ObservationException e) { Check(e.Code == code, "expected " + code + " got " + e.Code); return; }
            throw new ObservationException("self_test_failed", "field-timeline:" + phase + ":expected " + code);
        }
        static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        static JsonObject Object(string path) => JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        static void Save(string path, JsonNode value) => File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(value));
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-field-timeline-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string Destination() => Path.Combine(root, "timeline-" + id++ + ".jsonl");
        Dictionary<string, string> Hashes(string directory) => Directory.GetFiles(directory).ToDictionary(p => Path.GetFileName(p), p => Hash(File.ReadAllBytes(p)));
        string Copy(string from)
        {
            string directory = Path.Combine(root, "copy-" + id++); Directory.CreateDirectory(directory);
            foreach (string file in Directory.GetFiles(from)) File.Copy(file, Path.Combine(directory, Path.GetFileName(file)));
            return directory;
        }
        JsonObject[] Raw(string directory)
        {
            using var file = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz")); using var gzip = new GZipStream(file, CompressionMode.Decompress);
            using var reader = new StreamReader(gzip); var rows = new List<JsonObject>();
            while (reader.ReadLine() is { } line) rows.Add(JsonNode.Parse(line)!.AsObject());
            return rows.ToArray();
        }
        JsonElement[] Timeline(string path) => File.ReadLines(path).Select(x => { using var doc = JsonDocument.Parse(x); return doc.RootElement.Clone(); }).ToArray();
        string Capture(bool v2, bool empty = false, int fieldCount = 4, bool wide = false)
        {
            using var stop = new CancellationTokenSource(); if (empty) stop.Cancel(); var source = new Fixture(stop, 12);
            var p = new JsonObject
            {
                ["schema"] = "overwatch-decoder.field-profile/" + (v2 ? "2" : "1"), ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(source.Identity)),
                ["guards"] = new JsonArray(new JsonObject { ["address"] = 0x800, ["bytes_hex"] = "01" }),
                ["fields"] = new JsonArray(
                    new JsonObject { ["name"] = "byte_candidate", ["type"] = "u8", ["address"] = 0x4008 },
                    new JsonObject { ["name"] = "vector_candidate", ["type"] = "f32x3", ["address"] = 0x4010 },
                    new JsonObject { ["name"] = "integer_candidate", ["type"] = "i32", ["address"] = 0x900 },
                    new JsonObject { ["name"] = "double_candidate", ["type"] = "f64", ["address"] = 0x910 })
            };
            for (int n = 4; n < fieldCount; n++) p["fields"]!.AsArray().Add(new JsonObject { ["name"] = "fixed_" + n, ["type"] = "i32", ["address"] = 0x900 });
            if (wide)
                p["fields"] = new JsonArray(Enumerable.Range(0, fieldCount).Select(n => (JsonNode)new JsonObject
                { ["name"] = n.ToString("D3") + new string('v', 61), ["type"] = "f32x4", ["address"] = 0x940 }).ToArray());
            if (v2)
            {
                p["paths"] = new JsonArray(new JsonObject
                {
                    ["name"] = "storage", ["root_address"] = 0x800,
                    ["root_guards"] = new JsonArray(new JsonObject { ["offset"] = 0, ["bytes_hex"] = "01" }),
                    ["hops"] = new JsonArray(
                        new JsonObject { ["pointer_offset"] = 8, ["destination_guards"] = new JsonArray(new JsonObject { ["offset"] = 0, ["bytes_hex"] = "02" }) },
                        new JsonObject { ["pointer_offset"] = 8, ["destination_guards"] = new JsonArray(new JsonObject { ["offset"] = 0, ["bytes_hex"] = "03" }) })
                });
                for (int n = 0; n < 2; n++)
                { var f = p["fields"]![n]!.AsObject(); f.Remove("address"); f["path"] = "storage"; f["offset"] = n == 0 ? 8 : 16; }
            }
            string profile = Path.Combine(root, "profile-" + id++ + ".json"); Save(profile, p);
            string directory = Path.Combine(root, "recording-" + id++);
            FieldRecording.Record(source, profile, directory, 10, TimeSpan.FromSeconds(30), stop.Token); return directory;
        }
        // Repack synthetic artifacts with coherent hashes. Input readers still perform full semantic verification.
        void Rewrite(string directory, JsonObject[] rows, bool complete = false)
        {
            rows[^1]["frame_output_utf8_bytes"] = rows[..^1].Sum(x => (long)JsonSerializer.SerializeToUtf8Bytes(x).Length + 1);
            using var samples = new MemoryStream(); using var index = new MemoryStream(); long total = 0;
            long end = rows.Length == 1 ? rows[0]["monotonic_origin_ticks"]!.GetValue<long>() : rows[^2]["end_ticks"]!.GetValue<long>();
            for (int n = 0; n < rows.Length; n++)
            {
                byte[] raw = Encoding.UTF8.GetBytes(rows[n].ToJsonString() + "\n"); using var member = new MemoryStream();
                using (var gzip = new GZipStream(member, CompressionLevel.Fastest, true)) gzip.Write(raw);
                byte[] compressed = member.ToArray();
                byte[] entry = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { schema = "overwatch-decoder.field-recording-chunk/1", sequence = n,
                    offset = samples.Length, compressed_bytes = compressed.Length, json_bytes = raw.Length, first_line = n, lines = 1,
                    compressed_sha256 = Hash(compressed), json_sha256 = Hash(raw), checkpoint_ticks = end + 100,
                    monotonic_frequency = rows[n]["monotonic_frequency"]!.GetValue<long>() }) + "\n");
                samples.Write(compressed); index.Write(entry); total += raw.Length;
            }
            byte[] sb = samples.ToArray(), ib = index.ToArray(); File.WriteAllBytes(Path.Combine(directory, "samples.jsonl.gz"), sb); File.WriteAllBytes(Path.Combine(directory, "chunks.jsonl"), ib);
            var manifest = Object(Path.Combine(directory, "manifest.json")); manifest["stream_summary"] = rows[^1].DeepClone();
            manifest["durable_chunks"] = rows.Length; manifest["durable_lines"] = rows.Length;
            manifest["durable_compressed_bytes"] = sb.Length; manifest["durable_json_bytes"] = total; manifest["index_bytes"] = ib.Length;
            manifest["samples_sha256"] = Hash(sb); manifest["durable_samples_prefix_sha256"] = Hash(sb);
            manifest["index_sha256"] = Hash(ib); manifest["durable_index_prefix_sha256"] = Hash(ib);
            if (complete) { manifest["complete"] = true; manifest["stop_reason"] = "duration_elapsed"; }
            Save(Path.Combine(directory, "manifest.json"), manifest);
        }
        void FixedClock(string directory)
        {
            var rows = Raw(directory); Check(rows.Length == 13, "sample-controlled 12 frames plus summary");
            const long origin = 9_007_199_254_741_111, frequency = 10_000_000, interval = 100_000;
            long[] slots = [0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14]; long maximumFrame = 0, end = origin;
            for (int n = 0; n < 12; n++)
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
                var mapping = ordered.Select((value, rank) => (value, ticks: origin + slots[n] * interval + rank * 10L)).ToDictionary(x => x.value, x => x.ticks);
                foreach (var stamp in stamps) stamp.owner[stamp.name] = mapping[stamp.value];
                rows[n]["scheduled_slot"] = slots[n]; rows[n]["scheduled_ticks"] = origin + slots[n] * interval; rows[n]["jitter_ticks"] = 0;
                rows[n]["skipped_intervals_before"] = n == 6 ? 3 : 0; rows[n]["skipped_intervals_total"] = n >= 6 ? 3 : 0;
                end = rows[n]["end_ticks"]!.GetValue<long>(); maximumFrame = Math.Max(maximumFrame, end - rows[n]["start_ticks"]!.GetValue<long>());
            }
            foreach (var row in rows) { row["monotonic_origin_ticks"] = origin; row["utc_origin_before_ticks"] = origin - 10; row["monotonic_frequency"] = frequency; }
            rows[^1]["skipped_intervals"] = 5; rows[^1]["maximum_jitter_ms"] = 0;
            rows[^1]["maximum_frame_ms"] = maximumFrame * 1000d / frequency; rows[^1]["elapsed_ms"] = (end - origin) * 1000d / frequency + 30;
            Rewrite(directory, rows); var verified = FieldRecordingVerification.Verify(directory);
            Check(verified.valid && verified.frames == 12 && verified.skipped_intervals == 5, "deterministic fixture strictly valid:" + verified.error_code);
        }
        void NoPartial(string path) => Check(!Path.Exists(path) && !Directory.GetFiles(root, ".overwatch-decoder-timeline-*.partial").Any(), "no output or partial remains");
        void Reject(string directory, string code = "invalid_recording", FieldTimeline.Limits? limits = null, bool late = false)
        {
            string destination = Destination(); long lines = 0; var before = Hashes(directory);
            Throws(() => FieldTimeline.ExportBounded(directory, destination, default, limits ?? new(), n => lines = n), code);
            if (late) Check(lines >= 2, "late failure follows header and real temporary frame output");
            NoPartial(destination); Check(before.OrderBy(x => x.Key).SequenceEqual(Hashes(directory).OrderBy(x => x.Key)), "rejected source unchanged");
        }
        void Redacted(JsonElement e)
        {
            if (e.ValueKind == JsonValueKind.Object)
                foreach (var p in e.EnumerateObject())
                {
                    Check(p.Name is not ("address" or "address_hex" or "read_address_hex" or "root_address" or "bytes_hex" or "path_id" or "path_traces" or "guards" or "guard_ids"), "no structural trace property");
                    Redacted(p.Value);
                }
            else if (e.ValueKind == JsonValueKind.Array) foreach (var item in e.EnumerateArray()) Redacted(item);
        }
        try
        {
            foreach (bool v2 in new[] { false, true })
            {
                phase = "comparisons-v" + (v2 ? 2 : 1);
                string directory = Capture(v2); FixedClock(directory); var before = Hashes(directory); var raw = Raw(directory);
                string destination = Destination(); var result = FieldTimeline.Export(directory, destination); var rows = Timeline(destination);
                var emitted = rows.Where(r => r.GetProperty("kind").GetString() == "frame").ToArray();
                JsonElement Row(int sequence) => emitted.Single(x => x.GetProperty("frame").GetProperty("sequence").GetInt32() == sequence);
                JsonElement Item(int sequence, string field) => Row(sequence).GetProperty("observations").EnumerateArray().Single(x => x.GetProperty("field").GetString() == field);
                var summary = rows[^1]; var byteSummary = summary.GetProperty("fields")[0];
                Check(result.complete && !result.source_complete && result.source_status == "verified_stopped", "successful timeline retains stopped source");
                Check(result.frames == 12 && result.skipped_intervals == 5 && result.emitted_frames < 12, "sparse output retains total coverage");
                Check(result.output_sha256 == Hash(File.ReadAllBytes(destination)) && result.output_utf8_bytes == new FileInfo(destination).Length, "output exact hash and byte length");
                Check(result.profile_sha256 == before["profile.json"] && result.manifest_sha256 == before["manifest.json"] && result.samples_sha256 == before["samples.jsonl.gz"] && result.index_sha256 == before["chunks.jsonl"], "source hashes retained");
                Check(Item(0, "byte_candidate").GetProperty("kind").GetString() == "baseline" && Item(1, "byte_candidate").GetProperty("kind").GetString() == "numeric_change", "first sample baseline then 0 to255 change");
                Check(Item(2, "byte_candidate").GetProperty("after").GetProperty("reason").GetString() == "partial_read" && Item(3, "byte_candidate").GetProperty("reset_reasons")[0].GetString() == "unknown_reason_changed", "unknown reasons remain distinct");
                Check(Item(4, "byte_candidate").GetProperty("kind").GetString() == "baseline" && Item(4, "byte_candidate").GetProperty("after").GetProperty("value").GetInt32() == 255, "equal value after unknown is a fresh baseline");
                Check(Row(6).GetProperty("gap_before").GetProperty("missing_slots").GetInt32() == 3 && Item(6, "byte_candidate").GetProperty("kind").GetString() == "baseline", "missed slots break numeric comparisons");
                Check(summary.GetProperty("trailing_gap").GetProperty("missing_slots").GetInt32() == 2 && summary.GetProperty("trailing_gap").GetProperty("first_missing_slot").GetInt32() == 15, "trailing summary skips not hidden");
                Check(byteSummary.GetProperty("observed_count").GetInt32() == 9 && byteSummary.GetProperty("unknown_count").GetInt32() == 3 && byteSummary.GetProperty("numeric_changes").GetInt32() == 3, "unknown coverage and valid byte change counts");
                Check(byteSummary.GetProperty("last_sample").GetProperty("status").GetString() == "unknown" && byteSummary.GetProperty("last_sample").GetProperty("value").ValueKind == JsonValueKind.Null, "final unknown never retains stale value");
                Check(summary.GetProperty("last_recorded_frame").GetProperty("sequence").GetInt32() == 11, "final actual frame evidence");
                if (v2)
                {
                    Check(raw[6]["fields"]!["byte_candidate"]!["read_address_hex"]!.GetValue<string>() == raw[7]["fields"]!["byte_candidate"]!["read_address_hex"]!.GetValue<string>(), "fixture intermediate relocation retains same leaf");
                    foreach (int sequence in new[] { 7, 8 })
                        Check(Item(sequence, "byte_candidate").GetProperty("kind").GetString() == "baseline" && Item(sequence, "byte_candidate").GetProperty("reset_reasons")[0].GetString() == "storage_path_changed", "full route relocation resets even equal values");
                    Check(!Row(7).GetProperty("observations").EnumerateArray().Any(x => x.GetProperty("field").GetString() == "integer_candidate"), "path-local relocation preserves independent field continuity");
                }
                else Check(!emitted.Any(x => x.GetProperty("frame").GetProperty("sequence").GetInt32() is 7 or 8), "stable v1 frames omitted");
                foreach (var row in emitted)
                    foreach (var item in row.GetProperty("observations").EnumerateArray())
                        foreach (string side in new[] { "before", "after" })
                        {
                            var sample = item.GetProperty(side); if (sample.ValueKind == JsonValueKind.Null) continue;
                            int sequence = sample.GetProperty("frame").GetProperty("sequence").GetInt32(); string name = item.GetProperty("field").GetString()!;
                            var saved = raw[sequence]["fields"]![name]!;
                            foreach (string key in new[] { "value", "read_start_ticks", "read_end_ticks" })
                                Check(sample.GetProperty(key).GetRawText() == (saved[key]?.ToJsonString() ?? "null"), "raw numeric/timing token preserved " + key);
                            Check(sample.GetProperty("frame").GetProperty("start_ticks").GetInt64() == raw[sequence]["start_ticks"]!.GetValue<long>(), "ticks above2^53 remain integers");
                        }
                Check(!Row(1).GetProperty("observations").EnumerateArray().Any(x => x.GetProperty("field").GetString() == "vector_candidate"), "signed zero alone does not count as a numeric change");
                Check(Item(2, "vector_candidate").GetProperty("kind").GetString() == "numeric_change", "unrelated field remains comparable during byte read gap");
                Check(summary.GetProperty("fields")[2].GetProperty("numeric_changes").GetInt32() == 0 && summary.GetProperty("fields")[3].GetProperty("numeric_changes").GetInt32() == 0, "unchanged int/double omitted");
                foreach (var row in rows) Redacted(row);
                Check(before.OrderBy(x => x.Key).SequenceEqual(Hashes(directory).OrderBy(x => x.Key)), "source unchanged after success");

                phase = "strict-failures";
                string bad = Copy(directory); var m = Object(Path.Combine(bad, "manifest.json")); m["durable_lines"] = 99; Save(Path.Combine(bad, "manifest.json"), m); Reject(bad, late: true);
                bad = Copy(directory); using (var file = File.OpenWrite(Path.Combine(bad, "samples.jsonl.gz"))) file.SetLength(file.Length - 1); Reject(bad, late: true);
                bad = Copy(directory); File.AppendAllText(Path.Combine(bad, "chunks.jsonl"), "{"); Reject(bad, late: true);
                bad = Copy(directory); var corrupt = Raw(bad); corrupt[0]["fields"]!["byte_candidate"]!["value"] = 256; Rewrite(bad, corrupt); Reject(bad);
                Reject(directory, "timeline_byte_limit", new(OutputBytes: 1));
                Reject(directory, "timeline_byte_limit", new(OutputBytes: result.output_utf8_bytes - 1024), late: true);
                Reject(directory, "timeline_reason_limit", new(ReasonsPerField: 1));
                Reject(directory, "timeline_reason_limit", new(ReasonEntries: 1));
                Reject(directory, limits: new(Verification: new(JsonBytes: 1)));
                if (v2)
                {
                    bad = Copy(directory); var forged = Raw(bad);
                    forged[0]["path_traces"]![0]!["hops"]![0]!["pointer_after"]!["bytes_hex"] = "0030000000000000";
                    Rewrite(bad, forged); Reject(bad);
                }
                foreach (int cancelAt in new[] { 0, 1, 4, rows.Length })
                {
                    using var cancel = new CancellationTokenSource(); if (cancelAt == 0) cancel.Cancel(); destination = Destination();
                    Throws(() => FieldTimeline.ExportBounded(directory, destination, cancel.Token, new(), n => { if (n == cancelAt) cancel.Cancel(); }), "cancelled"); NoPartial(destination);
                }
                destination = Destination(); File.WriteAllText(destination, "sentinel");
                Throws(() => FieldTimeline.Export(directory, destination), "output_exists"); Check(File.ReadAllText(destination) == "sentinel", "existing output preserved");
                destination = Destination();
                Throws(() => FieldTimeline.ExportBounded(directory, destination, default, new(), n => { if (n == 1) File.WriteAllText(destination, "race"); }), "output_exists");
                Check(File.ReadAllText(destination) == "race" && !Directory.GetFiles(root, ".overwatch-decoder-timeline-*.partial").Any(), "publication race preserves output and cleans temporary");
                Throws(() => FieldTimeline.Export(directory, Path.Combine(directory, "inside.jsonl")), "invalid_arguments");
                if (!OperatingSystem.IsWindows())
                {
                    string alias = Path.Combine(root, "alias-" + id++); Directory.CreateSymbolicLink(alias, directory);
                    Throws(() => FieldTimeline.Export(directory, Path.Combine(alias, "inside.jsonl")), "invalid_arguments"); Directory.Delete(alias);
                }
                phase = "source-snapshot-no-reread";
                bad = Copy(directory); destination = Destination();
                var copied = Hashes(bad);
                var snapshot = FieldTimeline.ExportBounded(bad, destination, default, new(), n =>
                { if (n == 1) File.WriteAllText(Path.Combine(bad, "profile.json"), "{}"); });
                Check(snapshot.profile_sha256 == copied["profile.json"] && Timeline(destination)[0].GetProperty("fields").GetArrayLength() == 4,
                    "projection uses verifier profile snapshot without reopening changed file");
                phase = "complete-source";
                bad = Copy(directory); var completed = Raw(bad); completed[^1]["complete"] = true; completed[^1]["stop_reason"] = "duration_elapsed"; Rewrite(bad, completed, true);
                destination = Destination(); Check(FieldTimeline.Export(bad, destination).source_complete, "verified complete distinct from stopped");
            }
            phase = "all-unknown-and-zero-trailing-gap";
            string allUnknown = Capture(false); FixedClock(allUnknown); var unknownRows = Raw(allUnknown);
            foreach (var frame in unknownRows[..^1])
                foreach (var f in frame["fields"]!.AsObject())
                { f.Value!["status"] = "unknown"; f.Value["value"] = null; f.Value["reason"] = "unreadable_range"; }
            unknownRows[^1]["unknown_fields"] = 48; Rewrite(allUnknown, unknownRows);
            string unknownOutput = Destination(); var unknownResult = FieldTimeline.Export(allUnknown, unknownOutput); var unknownTimeline = Timeline(unknownOutput);
            Check(unknownResult.numeric_changes == 0 && unknownResult.emitted_frames == 2, "unchanged unknown samples emit only initial/gap boundaries");
            Check(unknownTimeline[^1].GetProperty("fields")[0].GetProperty("final_status_run").GetProperty("recorded_samples").GetInt32() == 6,
                "final unknown span closes with exact recorded sample count after gap");
            string emptyGap = Capture(true, true); var emptyRows = Raw(emptyGap); emptyRows[0]["skipped_intervals"] = 3; Rewrite(emptyGap, emptyRows);
            string emptyOutput = Destination(); _ = FieldTimeline.Export(emptyGap, emptyOutput);
            Check(Timeline(emptyOutput)[^1].GetProperty("trailing_gap").GetProperty("first_missing_slot").GetInt32() == 0,
                "zero-frame stopped source can retain trailing skipped slots");
            phase = "maximum-vector-boundary-line";
            string wide = Capture(false, fieldCount: FieldStream.MaximumFields, wide: true); FixedClock(wide);
            string wideOutput = Destination(); var wideResult = FieldTimeline.Export(wide, wideOutput);
            int maximumWideLine = File.ReadLines(wideOutput).Max(line => Encoding.UTF8.GetByteCount(line) + 1);
            Check(maximumWideLine > 262144 && maximumWideLine <= FieldTimeline.MaximumLineBytes && Timeline(wideOutput)[0].GetProperty("fields").GetArrayLength() == FieldStream.MaximumFields, "wide vector timeline retains every field within expanded line cap");
            Reject(wide, "timeline_byte_limit", new(OutputBytes: wideResult.output_utf8_bytes - 1024), late: true);
            phase = "full-field-bound-and-empty";
            foreach (bool empty in new[] { true, false })
            {
                string directory = Capture(true, empty, FieldStream.MaximumFields); if (!empty) FixedClock(directory);
                string destination = Destination(); var result = FieldTimeline.Export(directory, destination); var rows = Timeline(destination);
                Check(rows[0].GetProperty("fields").GetArrayLength() == FieldStream.MaximumFields && rows[^1].GetProperty("fields").GetArrayLength() == FieldStream.MaximumFields, "all supported profile fields retained");
                if (empty) Check(result.frames == 0 && rows.Length == 2 && rows[^1].GetProperty("last_recorded_frame").ValueKind == JsonValueKind.Null && rows[^1].GetProperty("fields")[FieldStream.MaximumFields - 1].GetProperty("last_sample").ValueKind == JsonValueKind.Null, "zero-frame source has metadata/provenance and null final evidence");
            }
        }
        catch (ObservationException) { throw; }
        catch (Exception e) { throw new ObservationException("self_test_failed", "field-timeline:" + phase + ":" + e.GetType().Name + ":" + e.Message); }
        finally { Directory.Delete(root, true); }
        return count;
    }
}
