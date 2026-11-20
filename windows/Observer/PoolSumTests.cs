using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

internal static class PoolSumTests
{
    private sealed class Memory : IMemorySource
    {
        public TargetIdentity Identity { get; set; } = new(321, "fixture.exe", "synthetic", 9, new string('b', 64), "x64");
        internal byte[] Pool = Buffer(1, 10, 0, 20, 0, 30);
        internal byte[] Guard = [1, 2, 3, 4];
        internal Action? AfterPool; internal string? Failure; internal bool Partial; internal int PoolReads; internal int FailReadNumber;
        public byte[] Read(ulong address, int size)
        {
            if (address == 0x1000) return Guard.ToArray();
            PoolReads++; if (Failure is not null && (FailReadNumber == 0 || FailReadNumber == PoolReads)) throw new ObservationException(Failure, "synthetic pool read");
            byte[] result = Pool.AsSpan(0, size).ToArray(); AfterPool?.Invoke(); return Partial ? result[..^1] : result;
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static byte[] Buffer(uint m0, float v0, uint m1, float v1, uint m2, float v2)
    {
        var b = new byte[24]; int i = 0;
        foreach (var (m, v) in new[] { (m0, v0), (m1, v1), (m2, v2) })
        { BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(i), m); BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(i + 4), BitConverter.SingleToInt32Bits(v)); i += 8; }
        return b;
    }
    private static JsonObject Profile(Memory m)
    {
        var p = TimerTests.Profile(m.Identity, guard: 0x1000); p["fields"] = new JsonArray(new JsonObject
        { ["name"] = "pool", ["type"] = "f32", ["address"] = 0x2000, ["codec"] = PoolSumCodec.Name, ["pool_span"] = 24,
            ["pool_slots"] = new JsonArray(Enumerable.Range(0, 3).Select(i => (JsonNode)new JsonObject { ["membership_offset"] = i * 8, ["scalar_offset"] = i * 8 + 4 }).ToArray()) });
        return p;
    }
    public static int Run()
    {
        int assertions = 0, serial = 0;
        void Check(bool ok, string why) { assertions++; if (!ok) throw new ObservationException("self_test_failed", "pool:" + why); }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-pool-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string New(string name) => Path.Combine(root, (serial++) + "-" + name);
        string Record(Memory m, int frames = 1, Action<int>? next = null, JsonObject? profile = null, bool stopOnUnknown = false)
        {
            string input = New("profile.json"), dir = New("record"); File.WriteAllText(input, (profile ?? Profile(m)).ToJsonString());
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)); int n = 0;
            using var liveText = new StringWriter(); var live = new LiveFieldOutput(liveText, "fixture");
            var model = FieldStream.ParseProfileBytes(File.ReadAllBytes(input));
            FieldRecording.RecordBounded(m, input, dir, 10, TimeSpan.FromSeconds(30), stop.Token, new(), frame => { Check(live.Frame(0, model, frame), "live projection"); n++; next?.Invoke(n); if (n == frames) stop.Cancel(); }, stopOnUnknown: stopOnUnknown);
            var liveRows = liveText.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (model.Fields.Any(f => f.Pool is not null))
                using (var line = JsonDocument.Parse(liveRows[0])) Check(line.RootElement.GetProperty("fields").GetProperty("pool").GetProperty("operands").TryGetProperty("snapshot_b", out _), "live raw pool evidence");
            var v = FieldRecordingVerification.Verify(dir); Check(v.valid && v.frames == frames, "strict record verification:" + v.error_code + ":frames=" + v.frames + ":expected=" + frames); return dir;
        }
        void Reject(Action<JsonObject> mutate, string code = "invalid_field_profile")
        {
            var p = Profile(new()); mutate(p);
            try { FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(p)); Check(false, "profile accepted"); }
            catch (ObservationException e) { Check(e.Code == code, "profile rejected:" + e.Code); }
        }
        try
        {
            var m = new Memory(); var parsed = FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(Profile(m))); var config = parsed.Fields[0].Pool!;
            Check(parsed.ReadBytes == 56 && parsed.Batching!.ReadCalls == 4, "physical double-read accounting");
            double Eval(byte[] b) { var v = PoolSumCodec.Evaluate(config, b, b); Check(v.Error is null, "finite"); return (double)v.Value!; }
            Check(Eval(Buffer(1, 16777216, 1, 1, 1, -16777216)) == 0, "ordered binary32 rounding, not double accumulator");
            Check(Eval(Buffer(0, float.NaN, 0, float.PositiveInfinity, 0, 1)) == 0, "empty slots not interpreted");
            Check(PoolSumCodec.Evaluate(config, Buffer(1, float.NaN, 0, 0, 0, 0), Buffer(1, 0, 0, 0, 0, 0)).Error == "non_finite_operand", "occupied NaN");
            var overflow = Buffer(1, float.MaxValue, 1, float.MaxValue, 0, 0);
            Check(PoolSumCodec.Evaluate(config, overflow, overflow).Error == "non_finite_calculation", "overflow");
            Check(PoolSumCodec.Evaluate(config, m.Pool, m.Pool, max: 9).Error == "out_of_range", "range");
            Check(PoolSumCodec.Evaluate(config, m.Pool, m.Pool[..^1]).Error == "pool_buffer_size", "short span");
            string record = Record(m, 5, n => {
                if (n == 1) m.Pool = Buffer(1, 10, 1, 20, 0, 30);
                if (n == 2) m.Pool = Buffer(0, 10, 1, 20, 0, 30);
                if (n == 3) m.AfterPool = () => { m.Pool = Buffer(1, 10, 1, 20, 0, 30); m.AfterPool = null; };
            }, stopOnUnknown: true);
            var rows = ReadRows(record); double?[] expected = [10, 30, 20, null, 30];
            for (int i = 0; i < 5; i++)
            {
                var field = rows[i]["fields"]!["pool"]!;
                Check(expected[i] is null ? field["reason"]!.GetValue<string>() == "pool_membership_changed" && field["value"] is null : field["value"]!.GetValue<double>() == expected[i], "activation/deactivation/race/recovery frame" + i);
            }
            Check(FieldRecordingVerification.Verify(record).unknown_fields == 1, "race field unknown only, next frame recovers");
            Check(m.PoolReads == 10, "two physical snapshots per frame");
            m = new(); m.AfterPool = () => { m.Pool = Buffer(1, 999, 0, 20, 0, 30); m.AfterPool = null; };
            Check(ReadRows(Record(m))[0]["fields"]!["pool"]!["value"]!.GetValue<double>() == 10, "value comes from A not B");
            foreach (string failure in new[] { "read", "read_b", "partial", "stale_before", "stale_after", "nan", "race_zero", "race_nonzero" })
            {
                m = new(); string reason;
                if (failure is "read" or "read_b") { m.Failure = "unreadable_range"; m.FailReadNumber = failure == "read_b" ? 2 : 0; reason = "unreadable_range"; }
                else if (failure == "partial") { m.Partial = true; reason = "partial_read"; }
                else if (failure == "stale_before") { m.Guard = [0, 0, 0, 0]; reason = "guard_mismatch_before"; }
                else if (failure == "stale_after") { m.AfterPool = () => m.Guard = [0, 0, 0, 0]; reason = "guard_mismatch_after"; }
                else if (failure == "nan") { m.Pool = Buffer(1, float.NaN, 0, 0, 0, 0); reason = "non_finite_operand"; }
                else { m.AfterPool = () => m.Pool = failure == "race_zero" ? Buffer(1, 10, 0, 20, 1, 30) : Buffer(2, 10, 0, 20, 0, 30); reason = "pool_membership_changed"; }
                var f = ReadRows(Record(m))[0]["fields"]!["pool"]!; Check(f["reason"]!.GetValue<string>() == reason && f["value"] is null, "failure:" + failure);
                if (failure == "read_b") Check(m.PoolReads == 2, "second read failure retained");
                if (failure == "stale_before") Check(m.PoolReads == 0, "identity guard prevents pool reads");
                if (failure is "read" or "partial") Check(m.PoolReads == 1, "second read skipped after first failure");
            }
            m = new(); var wrong = Profile(m); wrong["target"]!["creation_file_time"] = 8;
            try { Record(m, profile: wrong); Check(false, "wrong lifetime accepted"); }
            catch (ObservationException e) { Check(e.Code == "identity_mismatch" && m.PoolReads == 0, "wrong target rejected before pool"); }
            Reject(p => p["fields"]![0]!["pool_span"] = 4097);
            Reject(p => p["fields"]![0]!["pool_slots"]![1]!["membership_offset"] = 0);
            Reject(p => p["fields"]![0]!["pool_slots"]![0]!["scalar_offset"] = 1);
            Reject(p => p["fields"]![0]!["pool_slots"]![2]!["scalar_offset"] = 24);
            Reject(p => p["fields"]![0]!["pool_slots"]![0]!["extra"] = 1);
            Reject(p => p["fields"]![0]!["clock_address"] = 1);
            Reject(p => p["fields"]![0]!["address"] = ulong.MaxValue - 8);
            Reject(p => p["fields"]![0]!["pool_slots"] = new JsonArray());
            Reject(p => { p["fields"]![0]!["pool_span"] = 4096; p["fields"]![0]!["pool_slots"] = new JsonArray(Enumerable.Range(0, 257).Select(i => (JsonNode)new JsonObject { ["membership_offset"] = 8*i, ["scalar_offset"] = 8*i+4 }).ToArray()); });
            Reject(p => { var f = p["fields"]![0]!; f["pool_span"] = 4096; for (int i = 1; i < 4; i++) { var clone = f.DeepClone(); clone["name"] = "p" + i; p["fields"]!.AsArray().Add(clone); } }, "field_profile_limit");
            m = new(); var template = Profile(m)["fields"]![0]!.DeepClone();
            var recipe = new JsonObject {
                ["schema"] = "overwatch-decoder.acquisition-recipe/1", ["profile_schema"] = "overwatch-decoder.field-profile/4",
                ["target"] = new JsonObject { ["image_name"] = m.Identity.ImageName, ["executable_sha256"] = m.Identity.ExecutableSha256, ["architecture"] = "x64" },
                ["seconds"] = 5, ["constants"] = new JsonObject(), ["functions"] = new JsonObject(), ["global_guards"] = "g",
                ["stages"] = JsonNode.Parse("[{\"name\":\"identity\",\"steps\":[{\"op\":\"read\",\"name\":\"header\",\"address\":4096,\"size\":4},{\"op\":\"guard\",\"set\":\"g\",\"value\":[\"slice\",[\"var\",\"header\"],0,4]},{\"op\":\"check\",\"set\":\"g\"}]}]"),
                ["fields"] = new JsonArray(template) };
            string acquisition = New("acquisition");
            Acquisition.RunBytes(m, new Acquisition.Module(0x1000, 0x3000, m.Identity.ImageName), JsonSerializer.SerializeToUtf8Bytes(recipe), acquisition, CancellationToken.None);
            var acquired = FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(acquisition, "profile.json")));
            Check(acquired.Fields[0].Pool!.Slots.SequenceEqual(config.Slots) && acquired.Guards.Length == 1, "acquisition emits codec layout, only static guard");
            string acquiredRecord = Record(m, profile: JsonNode.Parse(File.ReadAllBytes(Path.Combine(acquisition, "profile.json")))!.AsObject());
            Check(ReadRows(acquiredRecord)[0]["fields"]!["pool"]!["value"]!.GetValue<double>() == 10, "acquisition-to-recording-to-verifier");
            // An empty collection partition still emits guarded ordinary context
            // fields. It must not need a fabricated timer/pool sentinel.
            var ordinary = Profile(m); ordinary["fields"] = new JsonArray();
            for (int i = 0; i < 9; i++)
                ordinary["fields"]!.AsArray().Add(new JsonObject { ["name"] = "context" + i, ["type"] = "i32", ["address"] = 0x1000,
                    ["guards"] = new JsonArray(Enumerable.Range(0, i < 5 ? 14 : 13)
                        .Select(_ => ordinary["guards"]![0]!.DeepClone()).ToArray()) });
            // 123 declarations, one distinct guard, nine four-byte scalar reads.
            var ordinaryParsed = FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(ordinary));
            Check(ordinaryParsed.V4 && ordinaryParsed.Fields.Length == 9 && ordinaryParsed.Guards.Length == 1 &&
                ordinaryParsed.Fields.All(f => f.Pool is null && f.Timer is null) && ordinaryParsed.ReadBytes == 44,
                "ordinary-only v4 shares guard and physical read accounting");
            var ordinaryRecipe = recipe.DeepClone().AsObject(); ordinaryRecipe["fields"] = ordinary["fields"]!.DeepClone();
            foreach (var f in ordinaryRecipe["fields"]!.AsArray()) f!["guards"] = "g";
            string ordinaryAcquisition = New("ordinary-acquisition");
            Acquisition.RunBytes(m, new Acquisition.Module(0x1000, 0x3000, m.Identity.ImageName),
                JsonSerializer.SerializeToUtf8Bytes(ordinaryRecipe), ordinaryAcquisition, CancellationToken.None);
            _ = Record(m, profile: JsonNode.Parse(File.ReadAllBytes(Path.Combine(ordinaryAcquisition, "profile.json")))!.AsObject());
            string ordinaryRecord = Record(m, profile: ordinary);
            var ordinaryRows = ReadRows(ordinaryRecord);
            Check(ordinaryRows[0]["schema"]!.GetValue<string>() == "overwatch-decoder.field-stream/4" &&
                ordinaryRows[0]["fields"]!.AsObject().All(f => f.Value!["value"]!.GetValue<int>() == 0x04030201),
                "ordinary-only acquisition recording and strict verification preserve native v4 wire");
            void RejectOrdinary(Action<JsonObject> change, string expected = "field_profile_limit")
            {
                var bad = ordinary.DeepClone().AsObject(); change(bad);
                try { FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(bad)); Check(false, "ordinary-only bounds accepted"); }
                catch (ObservationException e) { Check(e.Code == expected, "ordinary-only bound retained:" + e.Code); }
            }
            // Exactly 1920 shared declarations, not 1920 physical guards.
            var boundaryProfile = ordinary.DeepClone().AsObject();
            boundaryProfile["guards"] = new JsonArray(); boundaryProfile["fields"] = new JsonArray();
            for (int i = 0; i < 160; i++)
                boundaryProfile["fields"]!.AsArray().Add(new JsonObject { ["name"] = "boundary" + i, ["type"] = "i32", ["address"] = 0x1000,
                    ["guards"] = new JsonArray(Enumerable.Range(0, 12).Select(_ => ordinary["guards"]![0]!.DeepClone()).ToArray()) });
            var boundaryParsed = FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(boundaryProfile));
            Check(boundaryParsed.Fields.Length == 160 && boundaryParsed.Guards.Length == 1 && boundaryParsed.ReadBytes == 648 &&
                boundaryParsed.Batching!.ReadCalls == 162 && boundaryParsed.Fields.All(f => f.Guards.SequenceEqual(new[] { 0 })),
                "1920 shared declarations accepted with unchanged field, distinct-guard and read bounds");
            _ = Record(m, profile: boundaryProfile);
            boundaryProfile["fields"]![0]!["guards"]!.AsArray().Add(ordinary["guards"]![0]!.DeepClone());
            try { FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(boundaryProfile)); Check(false, "1921 declarations accepted"); }
            catch (ObservationException e) { Check(e.Code == "field_profile_limit", "1921 declarations rejected"); }
            // Keep physical byte/call bounds comfortably below their caps while
            // exceeding the former serialized v4 evidence envelope.
            var envelope = ordinary.DeepClone().AsObject();
            envelope["guards"] = new JsonArray(Enumerable.Range(0, 180).Select(i => (JsonNode)new JsonObject
                { ["address"] = 0x10000 + i * 64, ["bytes_hex"] = new string('0', 128) }).ToArray());
            envelope["fields"] = new JsonArray(Enumerable.Range(0, 128).Select(i => (JsonNode)new JsonObject
                { ["name"] = "field" + i + new string('x', 50), ["type"] = "f32x4", ["address"] = 0x1000 }).ToArray());
            var projection = envelope.DeepClone(); projection["schema"] = "overwatch-decoder.field-profile/1";
            var envelopeModel = FieldStream.ParseTimerProjection(JsonSerializer.SerializeToUtf8Bytes(projection)) with { V4 = true, Paths = [] };
            var envelopeBatches = envelopeModel.Guards.Select((g, id) => new GuardBatches.Batch(id, g.Address, g.Expected.Length, 0, [id])).ToArray();
            envelopeModel = envelopeModel with { Batching = new GuardBatches.Plan(new(64, 0, TimerCodec.SerialGuards), envelopeBatches,
                envelopeModel.ReadBytes, 488, envelopeModel.ReadBytes, 488, 0) };
            Check(envelopeModel.ReadBytes <= 32768 && envelopeModel.Guards.Length * 2 + envelopeModel.Fields.Length <= 512 &&
                TimerFrameAdmission.Estimate(envelopeModel) > 262144 && TimerFrameAdmission.Estimate(envelopeModel) <= FieldStream.MaximumLineBytes, "evidence fixture fits reviewed expanded envelope with physical bounds unchanged");
            Check(FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(envelope)).Fields.Length == 128, "former envelope rejection admitted within expanded line cap");
            RejectOrdinary(p => { p["guards"] = new JsonArray(Enumerable.Range(0, 257).Select(i => (JsonNode)new JsonObject
                { ["address"] = 0x10000 + i * 64, ["bytes_hex"] = "00000000" }).ToArray()); });
            RejectOrdinary(p => { p["guards"] = new JsonArray(Enumerable.Range(0, 256).Select(i => (JsonNode)new JsonObject
                { ["address"] = 0x10000 + i * 64, ["bytes_hex"] = new string('0', 128) }).ToArray());
                foreach (var f in p["fields"]!.AsArray()) f!.AsObject().Remove("guards"); });
            RejectOrdinary(p => p["fields"]![0]!["pool_span"] = 24, "invalid_field_profile");
            foreach (bool bytes in new[] { false, true })
            {
                string copy = New("ordinary-tamper"); Directory.CreateDirectory(copy);
                foreach (string file in Directory.GetFiles(ordinaryRecord)) File.Copy(file, Path.Combine(copy, Path.GetFileName(file)));
                var changed = ordinaryRows.Select(x => x.DeepClone().AsObject()).ToList();
                if (bytes) changed[0]["guards_before"]![0]!["read"]!["bytes_hex"] = "00000000";
                else changed[0]["fields"]!["context0"]!["read_address_hex"] = "0000000000001001";
                Repack(copy, changed);
                Check(!FieldRecordingVerification.Verify(copy).valid, "ordinary-only strict rehashed guard/address tamper rejected");
            }
            string exported = New("export"), timeline = New("timeline"); FieldExport.Export(record, exported); FieldTimeline.Export(record, timeline);
            foreach (string path in new[] { exported, timeline }) { string text = File.ReadAllText(path); Check(text.Contains("pool_sum_f32") && text.Contains("snapshot_b") && !text.Contains("address_hex"), "compact evidence retained"); }
            foreach (Action<JsonNode> change in new Action<JsonNode>[] {
                f => f["value"] = 999,
                f => f["pool_slots"]![0]!["scalar_offset"] = 12,
                f => f["operands"]!["snapshot_b"]!["bytes_hex"] = Convert.ToHexStringLower(Buffer(2, 10, 0, 20, 0, 30)),
                f => f["operands"]!["snapshot_b"]!["start_ticks"] = f["operands"]!["snapshot_a"]!["start_ticks"]!.DeepClone(),
                f => f["operands"]!["snapshot_a"]!["returned_bytes"] = 23,
                f => f["operands"]!["snapshot_a"]!["address_hex"] = "0000000000002001"
            })
            {
                string copy = New("tamper"); Directory.CreateDirectory(copy); foreach (string file in Directory.GetFiles(record)) File.Copy(file, Path.Combine(copy, Path.GetFileName(file)));
                var changed = rows.Select(x => x.DeepClone().AsObject()).ToList(); change(changed[0]["fields"]!["pool"]!); Repack(copy, changed);
                Check(!FieldRecordingVerification.Verify(copy).valid, "strict rehashed tamper rejection");
            }
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
    private static List<JsonObject> ReadRows(string directory)
    {
        using var file = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz")); using var gzip = new GZipStream(file, CompressionMode.Decompress); using var reader = new StreamReader(gzip);
        var rows = new List<JsonObject>(); while (reader.ReadLine() is { } s) rows.Add(JsonNode.Parse(s)!.AsObject()); return rows;
    }
    private static void Repack(string directory, List<JsonObject> rows)
    {
        static string Hash(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));
        string manifestPath = Path.Combine(directory, "manifest.json"); var manifest = JsonNode.Parse(File.ReadAllBytes(manifestPath))!.AsObject();
        var summary = rows[^1]; summary["frame_output_utf8_bytes"] = rows.Take(rows.Count - 1).Sum(x => (long)Encoding.UTF8.GetByteCount(x.ToJsonString()) + 1);
        long checkpoint = File.ReadLines(Path.Combine(directory, "chunks.jsonl")).Select(x => JsonNode.Parse(x)!["checkpoint_ticks"]!.GetValue<long>()).Max();
        using var samples = new MemoryStream(); using var index = new MemoryStream(); long rawBytes = 0;
        for (int i = 0; i < rows.Count; i++)
        {
            byte[] raw = Encoding.UTF8.GetBytes(rows[i].ToJsonString() + "\n"); using var buffer = new MemoryStream();
            using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, true)) gzip.Write(raw);
            byte[] member = buffer.ToArray(); byte[] entry = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { schema = "overwatch-decoder.field-recording-chunk/1", sequence = i, offset = samples.Length,
                compressed_bytes = member.Length, json_bytes = raw.Length, first_line = i, lines = 1, compressed_sha256 = Hash(member), json_sha256 = Hash(raw), checkpoint_ticks = checkpoint, monotonic_frequency = rows[i]["monotonic_frequency"]!.GetValue<long>() }) + "\n");
            samples.Write(member); index.Write(entry); rawBytes += raw.Length;
        }
        byte[] bytes = samples.ToArray(), indices = index.ToArray(); File.WriteAllBytes(Path.Combine(directory, "samples.jsonl.gz"), bytes); File.WriteAllBytes(Path.Combine(directory, "chunks.jsonl"), indices);
        manifest["durable_chunks"] = rows.Count; manifest["durable_lines"] = rows.Count; manifest["durable_compressed_bytes"] = bytes.Length; manifest["durable_json_bytes"] = rawBytes; manifest["index_bytes"] = indices.Length;
        manifest["samples_sha256"] = Hash(bytes); manifest["durable_samples_prefix_sha256"] = Hash(bytes); manifest["index_sha256"] = Hash(indices); manifest["durable_index_prefix_sha256"] = Hash(indices); manifest["stream_summary"] = summary.DeepClone();
        File.WriteAllText(manifestPath, manifest.ToJsonString());
    }
}
