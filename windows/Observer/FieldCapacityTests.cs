using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

// Owned zero-filled fixtures exercise transport capacity, never application semantics.
internal static class FieldCapacityTests
{
    private sealed class Memory : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(17, "fixture.exe", "synthetic", 9, new string('b', 64), "x64");
        internal bool Corrupt;
        internal int Calls;
        public byte[] Read(ulong address, int size) { Calls++; var result = new byte[size]; if (Corrupt && address == 4096) result[0] = 1; return result; }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static JsonObject Profile(Memory source, int count, string schema = "overwatch-decoder.field-profile/4") => new()
    {
        ["schema"] = schema, ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(source.Identity)),
        ["guards"] = new JsonArray(Enumerable.Range(0, 256).Select(i => (JsonNode)new JsonObject
            { ["address"] = 4096 + i * 8, ["bytes_hex"] = "00000000" }).ToArray()),
        ["fields"] = new JsonArray(Enumerable.Range(0, count).Select(i => (JsonNode)new JsonObject
            { ["name"] = "value_" + i, ["type"] = "f32x4", ["address"] = 1048576 + i * 16 }).ToArray())
    };
    private static JsonObject RepeatedDependencies(Memory source)
    {
        // Sanitized observed workload dimensions. Storage layout/values are owned zero fixtures.
        var result = Profile(source, 139); result["guards"] = new JsonArray();
        var fields = result["fields"]!.AsArray();
        for (int i = 0; i < fields.Count; i++)
        {
            var field = fields[i]!.AsObject(); field["address"] = 1048576 + i * 256;
            field["type"] = i < 10 ? "f32x4" : i < 20 ? "f32x3" : i < 30 ? "f32" : "i32";
            field["guards"] = new JsonArray(Enumerable.Range(0, i < 45 ? 11 : 12).Select(j => (JsonNode)new JsonObject
                { ["address"] = 4096 + ((i * 12 + j) % 211) * 8, ["bytes_hex"] = "00000000" }).ToArray());
            if (i >= 20 && i < 30)
            {
                field["codec"] = "pool_sum_f32"; field["pool_span"] = 64;
                field["pool_slots"] = new JsonArray(Enumerable.Range(0, 4).Select(j => (JsonNode)new JsonObject
                    { ["membership_offset"] = j * 16, ["scalar_offset"] = j * 16 + 4 }).ToArray());
            }
        }
        return result;
    }
    internal static int Run()
    {
        int assertions = 0;
        void Check(bool ok, string name) { assertions++; if (!ok) throw new ObservationException("self_test_failed", "field-capacity:" + name); }
        void Reject(JsonObject value)
        {
            try { FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(value)); Check(false, "oversized profile admitted"); }
            catch (ObservationException error) { Check(error.Code == "field_profile_limit", "bounded profile rejection"); }
        }
        var source = new Memory();
        foreach (string schema in new[] { "overwatch-decoder.field-profile/1", "overwatch-decoder.field-profile/4" })
            foreach (int count in new[] { 128, 129, 160 })
            {
                var parsed = FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(Profile(source, count, schema)));
                Check(parsed.Fields.Length == count && parsed.Guards.Length == 256 && parsed.Fields.All(f => f.Guards.Length == 256), "all declared fields and dependencies retained");
            }
        Reject(Profile(source, 161));
        var tooManyGuards = Profile(source, 160); tooManyGuards["guards"]!.AsArray().Add(new JsonObject { ["address"] = 99999, ["bytes_hex"] = "00" }); Reject(tooManyGuards);
        var readBound = Profile(source, 160); foreach (var guard in readBound["guards"]!.AsArray()) guard!["bytes_hex"] = new string('0', 128); Reject(readBound);
        var references = Profile(source, 160); references["fields"]![0]!["guards"] = new JsonArray(Enumerable.Range(0, FieldStream.MaximumTimerGuardDeclarations - 256 + 1).Select(_ => references["guards"]![0]!.DeepClone()).ToArray()); Reject(references);
        Check(FieldStream.MaximumReadBytesPerFrame == 32768 && PointerPaths.MaximumCalls == 1024 && FieldStream.MaximumTimerGuardDeclarations == 1920 && FieldStream.MaximumProfileBytes == 262144, "declaration budget follows field cap; physical and profile caps unchanged");
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-field-capacity-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            var dependencies = RepeatedDependencies(source); byte[] dependencyBytes = JsonSerializer.SerializeToUtf8Bytes(dependencies);
            var dependencyModel = FieldStream.ParseProfileBytes(dependencyBytes);
            Check(dependencyModel.Fields.Length == 139 && dependencyModel.Guards.Length == 211 &&
                dependencyModel.Fields.Sum(f => f.Guards.Length) == 1623 && dependencyModel.Batching!.ReadCalls == 571,
                "139 fields and 1623 local declarations retain exact 211 checks and 571 physical calls");
            Check(dependencyModel.ReadBytes == 3684 && TimerFrameAdmission.Estimate(dependencyModel) <= FieldStream.MaximumLineBytes,
                "repeated dependency fixture fits unchanged byte and serialized envelope bounds");
            Check(dependencyModel.Fields.All(f => f.Guards.Length is 11 or 12), "local guards are not globalized");
            string dependencyPath = Path.Combine(root, "dependencies.json"), dependencyRecording = Path.Combine(root, "dependencies");
            File.WriteAllBytes(dependencyPath, dependencyBytes);
            using (var stopDependencies = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                int dependencyFrames = 0;
                FieldRecording.RecordBounded(source, dependencyPath, dependencyRecording, 10, TimeSpan.FromSeconds(10), stopDependencies.Token, new(), frame =>
                {
                    int affected = dependencyModel.Fields.Count(f => f.Guards.Contains(0));
                    Check(frame.Fields.Count == 139 && frame.Fields.Count(f => f.Value.status == "unknown") == (dependencyFrames == 0 ? 0 : affected),
                        "failed shared guard nulls exactly dependent fields without field omission");
                    if (++dependencyFrames == 1) source.Corrupt = true; else stopDependencies.Cancel();
                });
                var checkedDependencies = FieldRecordingVerification.Verify(dependencyRecording);
                Check(checkedDependencies.valid && checkedDependencies.frames == 2, "dependency-heavy native fixture strictly verifies");
            }
            source.Corrupt = false;
            var profile = Profile(source, 160); byte[] raw = JsonSerializer.SerializeToUtf8Bytes(profile);
            var model = FieldStream.ParseProfileBytes(raw);
            Check(model.ReadBytes == 4608 && model.Batching!.ReadCalls == 672 && TimerFrameAdmission.Estimate(model) <= FieldStream.MaximumLineBytes, "wide fixture physical plan remains bounded");
            // The public field cap rejects these shapes earlier. Construct internal plans to
            // isolate the independent physical-call guard, with read/evidence limits fitting.
            FieldStream.Profile Calls(int count) => model with
            {
                Fields = Enumerable.Range(0, count).Select(i => new FieldStream.Field("call" + i, "u8", 1048576, 1, 1, null, null, [0])).ToArray(),
                ReadBytes = 2048 + count
            };
            var atCalls = Calls(512); Check(TimerFrameAdmission.Estimate(atCalls) <= FieldStream.MaximumLineBytes && GuardBatches.Serial(atCalls).ReadCalls == 1024, "independent call ceiling admits exact bound");
            var overCalls = Calls(513); Check(TimerFrameAdmission.Estimate(overCalls) <= FieldStream.MaximumLineBytes, "call rejection isolates physical calls from evidence size");
            try { GuardBatches.Serial(overCalls); Check(false, "1025 calls accepted"); }
            catch (ObservationException error) { Check(error.Code == "field_profile_limit", "1025 physical calls rejected"); }
            string path = Path.Combine(root, "profile.json"), recording = Path.Combine(root, "recording"); File.WriteAllBytes(path, raw);
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var liveText = new StringWriter(); var live = new LiveFieldOutput(liveText, new string('a', 32), includeEvidence: true); int frames = 0;
            FieldRecording.RecordBounded(source, path, recording, 10, TimeSpan.FromSeconds(10), stop.Token, new(), frame =>
            {
                Check(frame.Fields.Count == 160 && live.Frame(0, model, frame), "wide native evidence accepted by live envelope");
                if (++frames == 1) source.Corrupt = true; else stop.Cancel();
            });
            var verified = FieldRecordingVerification.Verify(recording);
            Check(verified.valid && verified.frames == 2 && verified.unknown_fields == 160, "wide recording strictly verifies observed and guard-unknown frames");
            foreach (string line in liveText.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                int size = Encoding.UTF8.GetByteCount(line) + 1;
                using var eventDoc = JsonDocument.Parse(line); var e = eventDoc.RootElement;
                Check(size > 262144 && size <= FieldStream.MaximumLineBytes && e.GetProperty("fields").EnumerateObject().Count() == 160, "wide live line retains every field above legacy line cap");
                Check(e.GetProperty("recording_frame").GetProperty("guards_before").GetArrayLength() == 256, "all original guard evidence retained");
            }
            var output = new StringWriter(); var bounded = new LiveFieldOutput(output, new string('a', 32));
            Check(bounded.Write("fixture", w => w.WriteString("padding", new string('x', FieldStream.MaximumLineBytes - 1024))), "near-cap line accepted");
            long before = bounded.Lines;
            Check(!bounded.Write("fixture", w => w.WriteString("padding", new string('x', FieldStream.MaximumLineBytes))) && bounded.Lines == before && bounded.Error == "live_line_byte_limit", "oversized line rejected before publication");
            try { FieldStream.ParseProfileBytes(raw.Concat(Enumerable.Repeat((byte)' ', 262145 - raw.Length)).ToArray()); Check(false, "oversized profile bytes accepted"); }
            catch (ObservationException error) { Check(error.Code == "field_profile_limit", "profile byte cap unchanged"); }
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
