using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Portable offline verification tests using only synthetic recordings and deliberate corruption.</summary>
public static class FieldRecordingVerificationTests
{
    private sealed class Fixture : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(321, "fixture.exe", "synthetic", 9, new string('b', 64), "x64");
        public Action<int>? OnValue { get; set; }
        public int Values { get; private set; }
        public byte[] Read(ulong address, int size)
        {
            if (address == 4096) return BitConverter.GetBytes(1);
            OnValue?.Invoke(++Values);
            if (Values == 2) throw new ObservationException("partial_read", "Synthetic read gap.");
            return BitConverter.GetBytes(Values);
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }

    public static int Run()
    {
        int assertions = 0, id = 0; string phase = "setup";
        void Check(bool condition, string message)
        {
            if (!condition) throw new ObservationException("self_test_failed", "field-recording-verification:" + phase + ":" + message);
            assertions++;
        }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-offline-verification-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        static JsonObject Object(string path) => JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        static void Save(string path, JsonNode value) => File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(value));
        string Copy(string from)
        {
            string directory = Path.Combine(root, "copy-" + id++); Directory.CreateDirectory(directory);
            foreach (string path in Directory.GetFiles(from)) File.Copy(path, Path.Combine(directory, Path.GetFileName(path)));
            return directory;
        }
        List<JsonObject> ReadLines(string directory)
        {
            using var samples = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz"));
            using var gzip = new GZipStream(samples, CompressionMode.Decompress); using var reader = new StreamReader(gzip);
            var result = new List<JsonObject>();
            while (reader.ReadLine() is { } line) result.Add(JsonNode.Parse(line)!.AsObject());
            return result;
        }
        void Repack(string directory, List<JsonObject> rows, Action<int, byte[]>? alterMember = null)
        {
            JsonObject manifest = Object(Path.Combine(directory, "manifest.json"));
            JsonObject? summary = rows.LastOrDefault(x => x["kind"]!.GetValue<string>() == "summary");
            long frameBytes = rows.TakeWhile(x => x["kind"]!.GetValue<string>() != "summary")
                .Sum(x => (long)JsonSerializer.SerializeToUtf8Bytes(x).Length + 1);
            if (summary is not null) summary["frame_output_utf8_bytes"] = frameBytes;
            long checkpoint = File.ReadLines(Path.Combine(directory, "chunks.jsonl")).Select(x => JsonNode.Parse(x)!["checkpoint_ticks"]!.GetValue<long>()).Max();
            using var sampleBytes = new MemoryStream(); using var indexBytes = new MemoryStream(); long rawCount = 0;
            for (int n = 0; n < rows.Count; n++)
            {
                byte[] raw = Encoding.UTF8.GetBytes(rows[n].ToJsonString() + "\n"); using var memberBuffer = new MemoryStream();
                using (var gzip = new GZipStream(memberBuffer, CompressionLevel.Fastest, true)) gzip.Write(raw);
                byte[] member = memberBuffer.ToArray(); alterMember?.Invoke(n, member);
                byte[] entry = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
                {
                    schema = "overwatch-decoder.field-recording-chunk/1", sequence = n, offset = sampleBytes.Length,
                    compressed_bytes = member.Length, json_bytes = raw.Length, first_line = n, lines = 1,
                    compressed_sha256 = Hash(member), json_sha256 = Hash(raw), checkpoint_ticks = checkpoint,
                    monotonic_frequency = rows[n]["monotonic_frequency"]!.GetValue<long>()
                }) + "\n");
                sampleBytes.Write(member); indexBytes.Write(entry); rawCount += raw.Length;
            }
            byte[] sample = sampleBytes.ToArray(), index = indexBytes.ToArray();
            File.WriteAllBytes(Path.Combine(directory, "samples.jsonl.gz"), sample); File.WriteAllBytes(Path.Combine(directory, "chunks.jsonl"), index);
            manifest["durable_chunks"] = rows.Count; manifest["durable_lines"] = rows.Count;
            manifest["durable_compressed_bytes"] = sample.Length; manifest["durable_json_bytes"] = rawCount;
            manifest["index_bytes"] = index.Length; manifest["pending_lines"] = 0;
            manifest["samples_sha256"] = Hash(sample); manifest["durable_samples_prefix_sha256"] = Hash(sample);
            manifest["index_sha256"] = Hash(index); manifest["durable_index_prefix_sha256"] = Hash(index);
            if (summary is not null) manifest["stream_summary"] = summary.DeepClone();
            Save(Path.Combine(directory, "manifest.json"), manifest);
        }
        void EditIndex(string directory, int entry, Action<JsonObject> edit)
        {
            string path = Path.Combine(directory, "chunks.jsonl"); var entries = File.ReadAllLines(path).Select(x => JsonNode.Parse(x)!.AsObject()).ToArray();
            edit(entries[entry]); File.WriteAllText(path, string.Join('\n', entries.Select(x => x.ToJsonString())) + "\n", new UTF8Encoding(false));
        }
        void ReplaceFirstMember(string directory, byte[] member, long declaredJsonBytes)
        {
            File.WriteAllBytes(Path.Combine(directory, "samples.jsonl.gz"), member);
            EditIndex(directory, 0, e =>
            {
                e["compressed_bytes"] = member.Length; e["compressed_sha256"] = Hash(member);
                e["json_bytes"] = declaredJsonBytes;
            });
        }
        FieldRecordingVerification.Result Reject(string directory, string code, long? chunks = null)
        {
            var result = FieldRecordingVerification.Verify(directory);
            Check(!result.valid && !result.complete && result.status == "invalid", "strict rejection");
            Check(result.error_code == code, "expected " + code + ", actual " + result.error_code);
            if (chunks is { } count) Check(result.verified_chunks == count, "only complete earlier chunks counted");
            return result;
        }
        FieldRecordingVerification.Result Recover(string directory, string code, long chunks)
        {
            var r = FieldRecordingVerification.Verify(directory, true);
            Check(!r.valid && !r.complete && r.recoverable && r.status == "recoverable_prefix", "explicit incomplete recovery");
            Check(r.error_code == code && r.verified_chunks == chunks, "error and contiguous prefix preserved");
            return r;
        }
        try
        {
            phase = "writer-roundtrip";
            var fixture = new Fixture(); string profile = Path.Combine(root, "profile.json");
            File.WriteAllText(profile, JsonSerializer.Serialize(new
            {
                schema = "overwatch-decoder.field-profile/1", target = Snapshots.PublicIdentity(fixture.Identity),
                guards = new[] { new { address = 4096, bytes_hex = "01000000" } },
                fields = new[] { new { name = "counter_candidate", type = "i32", address = 4128 } }
            }));
            string original = Path.Combine(root, "original"); using (var stop = new CancellationTokenSource())
            {
                fixture.OnValue = n => { if (n == 8) stop.Cancel(); };
                FieldRecording.RecordBounded(fixture, profile, original, 10, TimeSpan.FromSeconds(30), stop.Token, new(ChunkBytes: 8192));
            }
            var valid = FieldRecordingVerification.Verify(original);
            Check(valid.valid && !valid.complete && valid.status == "verified_stopped", "clean cancellation is verified, not complete");
            Check(valid.frames == 8 && valid.unknown_fields == 2 && valid.terminal_summary_verified, "all frames and unknowns retained");
            Check(valid.error_code is null && valid.unverified_compressed_bytes == 0 && valid.unverified_index_bytes == 0, "no hidden suffix");
            Check(valid.samples_prefix_sha256 == Hash(File.ReadAllBytes(Path.Combine(original, "samples.jsonl.gz"))), "whole compressed hash independently computed");
            Check(valid.index_prefix_sha256 == Hash(File.ReadAllBytes(Path.Combine(original, "chunks.jsonl"))), "whole index hash independently computed");
            Check(valid.profile_sha256 == Hash(File.ReadAllBytes(profile)), "private profile bytes verified");
            var before = Directory.GetFiles(original).ToDictionary(p => Path.GetFileName(p), p => Hash(File.ReadAllBytes(p)));
            _ = FieldRecordingVerification.Verify(original, true);
            Check(Directory.GetFiles(original).All(p => Hash(File.ReadAllBytes(p)) == before[Path.GetFileName(p)]), "verification writes nothing");
            string output = JsonSerializer.Serialize(valid);
            Check(!output.Contains("address", StringComparison.OrdinalIgnoreCase) && !output.Contains(root) && !output.Contains("fixture.exe"), "report contains no target paths, addresses or values");
            string baseline = Copy(original); Repack(baseline, ReadLines(baseline));
            valid = FieldRecordingVerification.Verify(baseline);
            Check(valid.valid && valid.verified_chunks == 9, "independent whole-line members accepted");

            phase = "duration-completion";
            string completed = Path.Combine(root, "completed");
            FieldRecording.Record(new Fixture(), profile, completed, 10, TimeSpan.FromMilliseconds(40), default);
            valid = FieldRecordingVerification.Verify(completed);
            Check(valid.valid && valid.complete && valid.status == "verified_complete", "duration completion validated without a minimum wall-clock sample assumption");

            phase = "compressed-tamper";
            string changed = Copy(baseline); byte[] bad = File.ReadAllBytes(Path.Combine(changed, "samples.jsonl.gz")); bad[15] ^= 1;
            File.WriteAllBytes(Path.Combine(changed, "samples.jsonl.gz"), bad); Reject(changed, "compressed_hash_mismatch", 0);
            Check(!FieldRecordingVerification.Verify(changed, true).recoverable, "no invented prefix when first member fails");
            changed = Copy(baseline); Repack(changed, ReadLines(changed), (n, member) => { if (n == 1) member[^8] ^= 1; });
            var gzipBad = FieldRecordingVerification.Verify(changed);
            Check(!gzipBad.valid && gzipBad.error_code is "invalid_gzip" or "gzip_trailer_mismatch", "CRC corruption rejected even after hash recomputation");
            Check(gzipBad.verified_chunks == 1, "invalid CRC excludes whole chunk");

            phase = "truncated-member-and-index";
            changed = Copy(baseline); using (var file = new FileStream(Path.Combine(changed, "samples.jsonl.gz"), FileMode.Open, FileAccess.Write)) file.SetLength(file.Length - 4);
            Reject(changed, "truncated_member", 8); var recovered = Recover(changed, "truncated_member", 8);
            Check(recovered.frames == 8 && !recovered.terminal_summary_verified, "all earlier frames recovered without summary");
            changed = Copy(baseline); string indexPath = Path.Combine(changed, "chunks.jsonl");
            byte[] idx = File.ReadAllBytes(indexPath); File.WriteAllBytes(indexPath, idx[..^5]);
            Reject(changed, "partial_index_line", 8); recovered = Recover(changed, "partial_index_line", 8);
            Check(recovered.unverified_index_bytes > 0 && recovered.unverified_compressed_bytes > 0, "torn suffix explicitly counted");
            changed = Copy(baseline); EditIndex(changed, 1, e => e["offset"] = e["offset"]!.GetValue<long>() + 1);
            Reject(changed, "index_order_or_gap", 1); Recover(changed, "index_order_or_gap", 1);
            changed = Copy(baseline); EditIndex(changed, 1, e => e["json_sha256"] = new string('a', 64));
            Reject(changed, "json_hash_mismatch", 1); Recover(changed, "json_hash_mismatch", 1);

            phase = "unindexed-tail-and-stale-manifest";
            changed = Copy(baseline); using (var f = new FileStream(Path.Combine(changed, "samples.jsonl.gz"), FileMode.Append)) f.Write([0x1f, 0x8b, 8]);
            Reject(changed, "unindexed_sample_tail", 9); recovered = Recover(changed, "unindexed_sample_tail", 9);
            Check(recovered.unverified_compressed_bytes == 3 && recovered.terminal_summary_verified && !recovered.complete, "terminal prefix does not make ignored tail complete");
            changed = Copy(baseline); JsonObject manifest = Object(Path.Combine(changed, "manifest.json"));
            manifest["status"] = "recording"; manifest["terminal_summary_written"] = false; Save(Path.Combine(changed, "manifest.json"), manifest);
            Reject(changed, "unfinished_manifest", 9); Recover(changed, "unfinished_manifest", 9);
            changed = Copy(baseline); var rows = ReadLines(changed); rows.RemoveAt(rows.Count - 1); Repack(changed, rows);
            Reject(changed, "missing_terminal_summary", 8); Recover(changed, "missing_terminal_summary", 8);

            phase = "semantic-corruption-with-new-hashes";
            changed = Copy(baseline); rows = ReadLines(changed); rows[1]["sequence"] = 6; Repack(changed, rows);
            Reject(changed, "frame_sequence_or_skip_mismatch", 1); Recover(changed, "frame_sequence_or_skip_mismatch", 1);
            changed = Copy(baseline); rows = ReadLines(changed); rows[1]["fields"]!["counter_candidate"]!["value"] = 999; Repack(changed, rows);
            Reject(changed, "unknown_value_retained", 1);
            changed = Copy(baseline); rows = ReadLines(changed); rows[0]["guards_after"]![0]!["ok"] = false; rows[0]["guards_after"]![0]!["error"] = "guard_mismatch"; Repack(changed, rows);
            Reject(changed, "unguarded_observed_value", 0);
            changed = Copy(baseline); rows = ReadLines(changed); rows[0]["fields"]!["counter_candidate"]!["guard_ids"] = new JsonArray(2); Repack(changed, rows);
            Reject(changed, "field_type_or_guards_mismatch", 0);
            changed = Copy(baseline); rows = ReadLines(changed); rows[0]["fields"]!["counter_candidate"]!["read_start_ticks"] = rows[0]["end_ticks"]!.GetValue<long>() + 1; Repack(changed, rows);
            Reject(changed, "read_time_order", 0);
            changed = Copy(baseline); rows = ReadLines(changed); rows[1]["profile_sha256"] = new string('d', 64); Repack(changed, rows);
            Reject(changed, "profile_or_target_mismatch", 1);
            changed = Copy(baseline); rows = ReadLines(changed); rows[^1]["unknown_fields"] = 0; Repack(changed, rows);
            Reject(changed, "summary_count_mismatch", 8);
            changed = Copy(baseline); rows = ReadLines(changed); rows.Add((JsonObject)rows[0].DeepClone()); Repack(changed, rows);
            Reject(changed, "line_after_summary", 9);
            changed = Copy(baseline); manifest = Object(Path.Combine(changed, "manifest.json")); manifest["complete"] = true;
            Save(Path.Combine(changed, "manifest.json"), manifest); Reject(changed, "manifest_completion_mismatch", 9);

            phase = "profile-and-manifest-integrity";
            changed = Copy(baseline); File.AppendAllText(Path.Combine(changed, "profile.json"), " "); Reject(changed, "profile_or_target_mismatch", 0);
            changed = Copy(baseline); File.WriteAllText(Path.Combine(changed, "profile.json"), "{\"schema\":\"overwatch-decoder.field-profile/1\",\"schema\":\"duplicate\"}"); Reject(changed, "duplicate_json_key", 0);
            changed = Copy(baseline); manifest = Object(Path.Combine(changed, "manifest.json")); manifest["samples_file"] = "../outside";
            Save(Path.Combine(changed, "manifest.json"), manifest); Reject(changed, "invalid_manifest", 0);
            changed = Copy(baseline); manifest = Object(Path.Combine(changed, "manifest.json")); manifest["samples_sha256"] = new string('c', 64);
            Save(Path.Combine(changed, "manifest.json"), manifest); Reject(changed, "manifest_hash_mismatch", 9);

            phase = "bounds-and-cancellation";
            changed = Copy(baseline); EditIndex(changed, 0, e => e["json_bytes"] = long.MaxValue);
            Reject(changed, "decompression_or_count_limit", 0);
            changed = Copy(baseline); EditIndex(changed, 0, e => e["json_bytes"] = 1);
            Reject(changed, "decompression_byte_limit", 0);
            changed = Copy(baseline);
            using (var bomb = new MemoryStream())
            {
                using (var gzip = new GZipStream(bomb, CompressionLevel.SmallestSize, true)) gzip.Write(new byte[8 * 1024 * 1024]);
                byte[] member = bomb.ToArray(); Check(member.Length < 16 * 1024, "high-ratio synthetic gzip fixture");
                ReplaceFirstMember(changed, member, 128);
            }
            Reject(changed, "decompression_byte_limit", 0);
            changed = Copy(baseline);
            int firstSize = JsonNode.Parse(File.ReadLines(Path.Combine(changed, "chunks.jsonl")).First())!["compressed_bytes"]!.GetValue<int>();
            byte[] firstMember = File.ReadAllBytes(Path.Combine(changed, "samples.jsonl.gz"))[..(firstSize - 4)];
            long firstJson = JsonNode.Parse(File.ReadLines(Path.Combine(changed, "chunks.jsonl")).First())!["json_bytes"]!.GetValue<long>();
            ReplaceFirstMember(changed, firstMember, firstJson);
            valid = FieldRecordingVerification.Verify(changed);
            Check(!valid.valid && valid.verified_chunks == 0 && valid.error_code is "gzip_trailer_mismatch" or "invalid_gzip" or "truncated_or_short_gzip",
                "missing gzip trailer rejected even when indexed length and compressed hash are updated");
            changed = Copy(baseline); File.WriteAllText(Path.Combine(changed, "profile.json"), new string('x', FieldStream.MaximumProfileBytes + 1));
            Reject(changed, "metadata_byte_limit", 0);
            changed = Copy(baseline); File.WriteAllText(Path.Combine(changed, "chunks.jsonl"), new string('x', 4097) + "\n");
            Reject(changed, "index_line_limit", 0);
            valid = FieldRecordingVerification.VerifyBounded(baseline, false, default, new(CompressedBytes: 1));
            Check(valid.error_code == "input_byte_limit" && valid.verified_chunks == 0, "compressed input cap before decode");
            valid = FieldRecordingVerification.VerifyBounded(baseline, false, default, new(JsonBytes: 1));
            Check(valid.error_code == "decompression_or_count_limit" && valid.verified_chunks == 0, "decoded total cap before allocation");
            valid = FieldRecordingVerification.VerifyBounded(baseline, false, default, new(LineBytes: 128));
            Check(valid.error_code == "invalid_or_oversized_json_line", "per-line bound");
            valid = FieldRecordingVerification.VerifyBounded(baseline, false, default, new(Chunks: 1));
            Check(valid.error_code == "chunk_count_limit" && valid.verified_chunks == 1, "chunk work bound");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            valid = FieldRecordingVerification.Verify(baseline, true, cancelled.Token);
            Check(valid.status == "cancelled" && !valid.valid && !valid.complete && valid.verified_chunks == 0, "pre-cancellation performs no verification");
        }
        catch (ObservationException) { throw; }
        catch (Exception e)
        { throw new ObservationException("self_test_failed", "field-recording-verification:" + phase + ":" + e.GetType().Name); }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
