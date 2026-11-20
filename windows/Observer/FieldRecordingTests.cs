using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Portable storage/recovery tests. No external process or application-specific profile.</summary>
public static class FieldRecordingTests
{
    private sealed class Fixture : IMemorySource
    {
        public TargetIdentity Identity { get; set; } = new(321, "fixture.exe", "private-test-path", 9, new string('b', 64), "x64");
        public int Values { get; private set; }
        public int DelayFirstReadMs { get; set; }
        public int FailValue { get; set; }
        public Action<int>? OnValue { get; set; }
        private bool first = true;
        public byte[] Read(ulong address, int size)
        {
            if (first) { first = false; if (DelayFirstReadMs > 0) Thread.Sleep(DelayFirstReadMs); }
            if (address == 4096) return BitConverter.GetBytes(1);
            Values++; OnValue?.Invoke(Values);
            if (Values == FailValue) throw new ObservationException("partial_read", "Synthetic unavailable sample.");
            return BitConverter.GetBytes(Values);
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }

    public static int Run()
    {
        int assertions = 0; string phase = "setup";
        void Check(bool condition, string description)
        {
            if (!condition) throw new ObservationException("self_test_failed", "field-recording:" + phase + ":" + description);
            assertions++;
        }
        void Throws(Action action, string code)
        {
            try { action(); }
            catch (ObservationException e) { Check(e.Code == code, "expected " + code + ", actual " + e.Code); return; }
            throw new ObservationException("self_test_failed", "field-recording:" + phase + ":expected " + code);
        }
        static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        static JsonElement Element(object value) => JsonSerializer.SerializeToElement(value);
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-field-recording-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); int id = 0;
        string Profile(Fixture source)
        {
            string path = Path.Combine(root, "profile-" + id++ + ".json");
            File.WriteAllText(path, JsonSerializer.Serialize(new
            {
                schema = "overwatch-decoder.field-profile/1", target = Snapshots.PublicIdentity(source.Identity),
                guards = new[] { new { address = 4096, bytes_hex = "01000000" } },
                fields = new[] { new { name = "counter_candidate", type = "i32", address = 4128 } }
            }));
            return path;
        }
        (JsonElement manifest, string directory) Capture(Fixture source, int count = 4,
            FieldRecording.Limits? limits = null, bool cancelBefore = false)
        {
            using var stop = new CancellationTokenSource();
            if (cancelBefore) stop.Cancel();
            source.OnValue = n => { if (n >= count) stop.Cancel(); };
            string directory = Path.Combine(root, "recording-" + id++);
            object result = FieldRecording.RecordBounded(source, Profile(source), directory, 10,
                TimeSpan.FromSeconds(30), stop.Token, limits ?? new(ChunkBytes: 8192));
            return (Element(result), directory);
        }
        byte[] ReadPrefix(string directory, JsonElement? manifest = null)
        {
            using var result = new MemoryStream();
            using var samples = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz"));
            long offset = 0, lines = 0, sequence = 0;
            foreach (string text in File.ReadLines(Path.Combine(directory, "chunks.jsonl")))
            {
                using var entryDoc = JsonDocument.Parse(text); JsonElement e = entryDoc.RootElement;
                Check(e.GetProperty("sequence").GetInt64() == sequence++, "ordered chunk sequence");
                Check(e.GetProperty("offset").GetInt64() == offset, "contiguous compressed prefix");
                Check(e.GetProperty("first_line").GetInt64() == lines, "contiguous JSONL lines");
                byte[] member = new byte[e.GetProperty("compressed_bytes").GetInt32()]; samples.ReadExactly(member);
                Check(Hash(member) == e.GetProperty("compressed_sha256").GetString(), "member SHA-256");
                using var input = new MemoryStream(member); using var gzip = new GZipStream(input, CompressionMode.Decompress);
                using var raw = new MemoryStream(); gzip.CopyTo(raw); byte[] bytes = raw.ToArray();
                Check(bytes.Length == e.GetProperty("json_bytes").GetInt64(), "uncompressed byte count");
                Check(Hash(bytes) == e.GetProperty("json_sha256").GetString(), "JSON SHA-256");
                Check(bytes.Length > 0 && bytes[^1] == (byte)'\n', "whole-line member boundary");
                long memberLines = Encoding.UTF8.GetString(bytes).Count(c => c == '\n');
                Check(memberLines == e.GetProperty("lines").GetInt64(), "member line count");
                result.Write(bytes); offset += member.Length; lines += memberLines;
            }
            if (manifest is { } m)
            {
                Check(m.GetProperty("durable_lines").GetInt64() == lines, "manifest line count");
                Check(m.GetProperty("durable_json_bytes").GetInt64() == result.Length, "manifest JSON byte count");
                Check(m.GetProperty("durable_compressed_bytes").GetInt64() == offset, "manifest compressed byte count");
                Check(m.GetProperty("samples_sha256").GetString() == Hash(File.ReadAllBytes(Path.Combine(directory, "samples.jsonl.gz"))), "whole samples hash");
                Check(m.GetProperty("index_sha256").GetString() == Hash(File.ReadAllBytes(Path.Combine(directory, "chunks.jsonl"))), "whole index hash");
            }
            return result.ToArray();
        }
        JsonElement[] Lines(byte[] bytes) => Encoding.UTF8.GetString(bytes).Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => { using var doc = JsonDocument.Parse(line); return doc.RootElement.Clone(); }).ToArray();
        try
        {
            phase = "guarded-stream-roundtrip";
            var source = new Fixture { FailValue = 2, DelayFirstReadMs = 80 };
            var recording = Capture(source);
            var lines = Lines(ReadPrefix(recording.directory, recording.manifest));
            Check(lines.Length == 5, "four sample-controlled frames plus summary");
            JsonElement Field(int n) => lines[n].GetProperty("fields").GetProperty("counter_candidate");
            Check(Field(0).GetProperty("value").GetInt32() == 1, "fresh first value");
            Check(Field(1).GetProperty("value").ValueKind == JsonValueKind.Null && Field(1).GetProperty("reason").GetString() == "partial_read", "read gap preserved as unknown");
            Check(Field(2).GetProperty("value").GetInt32() == 3, "recovery is fresh");
            Check(Field(3).GetProperty("value").ValueKind == JsonValueKind.Null, "cancelled in-flight value is unknown");
            Check(lines[^1].GetProperty("kind").GetString() == "summary" && lines[^1].GetProperty("stop_reason").GetString() == "cancelled", "terminal cancellation summary");
            Check(lines[^1].GetProperty("skipped_intervals").GetInt64() >= 1, "slow sampling skips slots");
            Check(!recording.manifest.GetProperty("complete").GetBoolean(), "cancelled is incomplete");
            Check(recording.manifest.GetProperty("terminal_summary_written").GetBoolean(), "summary durably indexed");
            Check(lines[^1].GetRawText() == recording.manifest.GetProperty("stream_summary").GetRawText(), "manifest retains exact summary values");
            byte[] savedProfile = File.ReadAllBytes(Path.Combine(recording.directory, "profile.json"));
            Check(Hash(savedProfile) == recording.manifest.GetProperty("profile_sha256").GetString(), "exact profile snapshot hash");
            for (int n = 0; n < 4; n++)
            {
                Check(lines[n].GetProperty("sequence").GetInt32() == n, "frame sequence preserved");
                Check(lines[n].GetProperty("profile_sha256").GetString() == Hash(savedProfile), "frame profile provenance");
                Check(lines[n].GetProperty("target").GetProperty("pid").GetInt32() == source.Identity.Pid, "frame target provenance");
                Check(lines[n].GetProperty("end_ticks").GetInt64() >= lines[n].GetProperty("start_ticks").GetInt64(), "frame read time bounds preserved");
                Check(lines[n].GetProperty("guards_before").GetArrayLength() == 1 && lines[n].GetProperty("guards_after").GetArrayLength() == 1, "both guard passes preserved");
            }

            phase = "exact-utf8-and-interrupted-prefix";
            string direct = Path.Combine(root, "direct"); Directory.CreateDirectory(direct);
            string text = "{\"text\":\"λ雪🙂\",\"payload\":\"" + new string('x', 3700) + "\"}";
            using (var writer = new FieldRecording.ChunkWriter(direct, new(ChunkBytes: 8192)))
            {
                Check(writer.WriteFrame(text) is null && writer.WriteFrame(text) is null && writer.WriteFrame(text) is null, "whole lines accepted");
                Check(writer.Chunks == 1 && writer.PendingLines == 1, "one complete member and one pending line");
            }
            byte[] prefix = ReadPrefix(direct);
            Check(prefix.SequenceEqual(Encoding.UTF8.GetBytes(text + "\n" + text + "\n")), "byte-exact roundtrip without newline or Unicode rewriting");
            using (var tail = new FileStream(Path.Combine(direct, "samples.jsonl.gz"), FileMode.Append)) tail.Write([0x1f, 0x8b, 0x08]);
            Check(ReadPrefix(direct).SequenceEqual(prefix), "indexed prefix survives an unindexed torn member");

            phase = "reused-buffer-exact-members";
            direct = Path.Combine(root, "reused-buffer"); Directory.CreateDirectory(direct);
            // Force three different member lengths regardless of scheduler pauses. The second
            // frame leaves too little space for the summary, and the final short member must not
            // include any bytes retained beyond MemoryStream.Length from its earlier large members.
            string ExactLine(int bytes)
            {
                const string head = "{\"payload\":\"雪🙂λ\",\"padding\":\"", tail = "\"}";
                return head + new string('x', bytes - Encoding.UTF8.GetByteCount(head + tail) - 1) + tail;
            }
            string[] exactLines = [ExactLine(8192), ExactLine(8191), "{}"];
            using (var writer = new FieldRecording.ChunkWriter(direct, new(ChunkBytes: 8192)))
            {
                Check(writer.WriteFrame(exactLines[0]) is null && writer.WriteFrame(exactLines[1]) is null, "exact-boundary lines accepted");
                writer.WriteSummary(exactLines[2]);
                Check(writer.Chunks == 3 && writer.PendingLines == 0 && writer.DurableLines == 3, "forced member boundaries unchanged");
            }
            using (var expected = new MemoryStream())
            {
                foreach (string row in exactLines)
                {
                    // Frozen e995 encoder/compressor behavior, kept as an independent byte oracle.
                    byte[] raw = Encoding.UTF8.GetBytes(row + "\n");
                    using var member = new MemoryStream();
                    using (var gzip = new GZipStream(member, CompressionLevel.Fastest, true)) gzip.Write(raw);
                    expected.Write(member.ToArray());
                }
                Check(File.ReadAllBytes(Path.Combine(direct, "samples.jsonl.gz")).SequenceEqual(expected.ToArray()), "compressed member bytes equal the original copy-based path");
            }
            Check(ReadPrefix(direct).SequenceEqual(Encoding.UTF8.GetBytes(string.Join('\n', exactLines) + "\n")), "reused capacity never leaks stale suffix bytes");

            phase = "utf8-edge-compatibility";
            direct = Path.Combine(root, "utf8-edges"); Directory.CreateDirectory(direct);
            // The storage layer preserves its original UTF-8 replacement behavior as well as NUL,
            // escaped characters and non-ASCII text; these are byte tests, not valid profile input.
            string[] edgeLines = ["", "\0", "\\\"\t\r", "λ雪🙂", "\ud800", "\udc00", "a\ud800z"];
            using (var writer = new FieldRecording.ChunkWriter(direct, new(ChunkBytes: 8192)))
            {
                foreach (string row in edgeLines) Check(writer.WriteFrame(row) is null, "UTF-8 edge accepted");
                writer.WriteSummary("{}");
            }
            Check(ReadPrefix(direct).SequenceEqual(Encoding.UTF8.GetBytes(string.Join('\n', edgeLines.Append("{}")) + "\n")), "all UTF-8 edge bytes match prior encoder");

            phase = "budget-stops-with-summary";
            recording = Capture(new Fixture(), count: 100, limits: new(JsonBytes: 8192));
            lines = Lines(ReadPrefix(recording.directory, recording.manifest));
            Check(lines.Length == 1 && lines[0].GetProperty("stop_reason").GetString() == "output_byte_limit", "JSON cap leaves a summary");
            Check(recording.manifest.GetProperty("durable_json_bytes").GetInt64() <= 8192, "JSON bound enforced");
            recording = Capture(new Fixture(), count: 100, limits: new(CompressedBytes: 65536));
            lines = Lines(ReadPrefix(recording.directory, recording.manifest));
            Check(lines.Length == 1 && lines[0].GetProperty("stop_reason").GetString() == "compressed_byte_limit", "compressed cap leaves a summary");
            Check(recording.manifest.GetProperty("durable_compressed_bytes").GetInt64() <= 65536, "compressed bound enforced");

            recording = Capture(new Fixture(), count: 100, limits: new(IndexBytes: 4096, ChunkBytes: 8192));
            lines = Lines(ReadPrefix(recording.directory, recording.manifest));
            Check(lines[^1].GetProperty("stop_reason").GetString() == "index_byte_limit", "index cap leaves a summary");
            Check(recording.manifest.GetProperty("index_bytes").GetInt64() <= 4096, "index bound enforced");

            phase = "preflight-and-overwrite";
            source = new Fixture(); string path = Profile(source); string destination = Path.Combine(root, "identity-rejected");
            source.Identity = source.Identity with { CreationFileTime = 100 };
            Throws(() => FieldRecording.Record(source, path, destination, 10, TimeSpan.FromSeconds(1), default), "identity_mismatch");
            Check(!Directory.Exists(destination), "identity rejection creates no recording");
            source = new Fixture(); path = Profile(source);
            Throws(() => FieldRecording.Record(source, path, recording.directory, 10, TimeSpan.FromSeconds(1), default), "output_exists");
            Throws(() => FieldRecording.Record(source, path, destination, 1, TimeSpan.FromSeconds(1), default), "invalid_arguments");
            File.WriteAllText(path, "{}");
            Throws(() => FieldRecording.Record(source, path, destination, 10, TimeSpan.FromSeconds(1), default), "invalid_field_profile");

            phase = "already-cancelled-and-duration-completion";
            recording = Capture(new Fixture(), cancelBefore: true);
            lines = Lines(ReadPrefix(recording.directory, recording.manifest));
            Check(lines.Length == 1 && lines[0].GetProperty("frames").GetInt64() == 0, "pre-cancellation still writes summary");
            source = new Fixture(); path = Profile(source); destination = Path.Combine(root, "duration");
            JsonElement completed = Element(FieldRecording.Record(source, path, destination, 10, TimeSpan.FromMilliseconds(40), default));
            Check(completed.GetProperty("complete").GetBoolean(), "duration completion distinguished from cancellation");
            lines = Lines(ReadPrefix(destination, completed));
            Check(lines[^1].GetProperty("stop_reason").GetString() == "duration_elapsed", "duration summary present even under slow scheduling");
        }
        catch (ObservationException) { throw; }
        catch (Exception e)
        { throw new ObservationException("self_test_failed", "field-recording:" + phase + ":" + e.GetType().Name); }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
