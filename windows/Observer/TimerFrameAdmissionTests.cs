using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

internal static class TimerFrameAdmissionTests
{
    private sealed class Memory : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(int.MaxValue, new string('☃', 128), "synthetic", long.MaxValue, new string('f', 64), "x64");
        internal readonly Dictionary<ulong, byte[]> Data = new();
        internal Func<ulong, string?>? Error;
        internal ulong? Short;
        public byte[] Read(ulong address, int size)
        {
            if (Error?.Invoke(address) is { } error) throw new ObservationException(error, "Synthetic sizing error.");
            byte[] bytes = Data[address].ToArray(); return Short == address ? bytes[..^1] : bytes;
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => []; public void Dispose() { }
    }
    private static JsonObject Profile(Memory m, int guards, int fields = 14)
    {
        var p = TimerTests.Profile(m.Identity); var gs = new JsonArray(); p["guards"] = gs; p["fields"] = new JsonArray();
        int[] widths = [1, 4, 8, 16, 32, 64]; string[] types = ["u8", "i32", "f32", "f64", "f32x3", "f32x4"];
        for (int i = 0; i < guards; i++)
        {
            ulong address = 0x1000UL + (ulong)i * 128; byte[] bytes = Enumerable.Repeat((byte)0xa5, widths[i % widths.Length]).ToArray();
            gs.Add(new JsonObject { ["address"] = address, ["bytes_hex"] = Convert.ToHexStringLower(bytes) }); m.Data[address] = bytes;
        }
        for (int i = 0; i < fields; i++)
        {
            ulong address = 0x100000UL + (ulong)i * 128; string type = i < 2 ? "f32" : types[i % types.Length];
            var f = new JsonObject { ["name"] = "field_" + i.ToString("D3") + new string('x', 55), ["type"] = type, ["address"] = address };
            if (i < 2)
            {
                f["codec"] = TimerCodec.Name; f["clock_address"] = address + 64; f["counter_scale_f32_hex"] = "0000803f";
                m.Data[address] = TimerTests.State(long.MinValue, i == 0 ? float.MaxValue : -0f, 0); m.Data[address + 64] = BitConverter.GetBytes(long.MinValue);
            }
            else m.Data[address] = type switch
            {
                "u8" => [255], "i32" => BitConverter.GetBytes(int.MinValue), "f32" => BitConverter.GetBytes(-float.Epsilon), "f64" => BitConverter.GetBytes(double.MinValue),
                _ => new[] { float.MinValue, -float.Epsilon, -0f, float.MaxValue }.Take(type == "f32x3" ? 3 : 4).SelectMany(BitConverter.GetBytes).ToArray()
            };
            p["fields"]!.AsArray().Add(f);
        }
        return p;
    }
    private sealed class Writer(Action afterFrame) : StringWriter
    {
        private readonly StringBuilder pending = new();
        internal readonly List<JsonElement> Lines = [];
        public override void Write(string? value) => pending.Append(value);
        public override void Write(char value)
        {
            if (value != '\n') { pending.Append(value); return; }
            using var d = JsonDocument.Parse(pending.ToString()); Lines.Add(d.RootElement.Clone()); pending.Clear();
            if (Lines[^1].GetProperty("kind").GetString() == "frame") afterFrame();
        }
    }
    internal static int Run()
    {
        int assertions = 0, number = 0;
        void Check(bool condition, string name) { if (!condition) throw new ObservationException("self_test_failed", "v4-admission:" + name); assertions++; }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-v4-admission-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            // Include profiles beyond the former flat estimate's boundary, retaining all 256 unique guards.
            foreach (int count in new[] { 226, 228, 236, 246, 256 })
            {
                var m = new Memory(); byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(Profile(m, count)); var profile = FieldStream.ParseProfileBytes(bytes);
                int bound = TimerFrameAdmission.Estimate(profile);
                Check(profile.Guards.Length == count && profile.Fields.Length == 14 && profile.Fields.All(f => f.Guards.Length == count), "all widths/dependencies retained:" + count);
                Check(bound <= FieldStream.MaximumLineBytes && profile.Batching!.ReadCalls == count * 2 + 16, "native envelope fits with exact read plan:" + count);
            }
            var source = new Memory(); byte[] raw = JsonSerializer.SerializeToUtf8Bytes(Profile(source, 256)); var parsed = FieldStream.ParseProfileBytes(raw);
            string input = Path.Combine(root, "profile.json"); File.WriteAllBytes(input, raw); int estimate = TimerFrameAdmission.Estimate(parsed);
            void Capture(string name, Action? configure = null)
            {
                source.Error = null; source.Short = null; configure?.Invoke(); using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var writer = new Writer(stop.Cancel); FieldStream.Run(source, input, 10, TimeSpan.FromSeconds(10), writer, stop.Token);
                var frame = writer.Lines.First(x => x.GetProperty("kind").GetString() == "frame"); int size = Encoding.UTF8.GetByteCount(frame.GetRawText()) + 1;
                Check(size <= estimate, "actual complete serialized frame within native envelope:" + name);
                // Independent token widening of observed wire data covers signed integer extremes and optional nulls.
                var padded = JsonNode.Parse(frame.GetRawText())!;
                void Widen(JsonNode? node)
                {
                    if (node is JsonObject obj)
                        foreach (string key in obj.Select(x => x.Key).ToArray())
                        {
                            if (key.EndsWith("_ticks", StringComparison.Ordinal) && obj[key] is not null) obj[key] = long.MinValue;
                            else if (key == "returned_bytes" && obj[key] is not null) obj[key] = int.MaxValue;
                            else Widen(obj[key]);
                        }
                    else if (node is JsonArray array) foreach (var child in array) Widen(child);
                }
                Widen(padded); Check(Encoding.UTF8.GetByteCount(padded.ToJsonString()) + 1 <= estimate, "widest read/count token envelope:" + name);
            }
            Capture("finite-extremes");
            foreach (string code in new[] { "native_error", "permission_denied", "process_exited", "identity_mismatch", "invalid_region", "invalid_address", "invalid_read_size", "unreadable_range", "partial_read", "cancelled", "duration_elapsed", "read_byte_limit", "unsupported_architecture" })
            {
                Check(code.Length <= TimerFrameAdmission.NativeCodeBytes && code.All(char.IsAscii), "documented native code envelope:" + code);
                Capture("guard-" + code, () => source.Error = _ => code);
            }
            Capture("maximum-ascii-code-envelope", () => source.Error = _ => new string('e', TimerFrameAdmission.NativeCodeBytes));
            byte[] savedGuard = source.Data[0x1000]; source.Data[0x1000] = [0]; Capture("guard-mismatch-before"); source.Data[0x1000] = savedGuard;
            int postReads = 0; Capture("guard-read-after", () => source.Error = a => a == 0x1000 && ++postReads == 2 ? "unreadable_range" : null);
            Capture("state-gap", () => source.Error = a => a == 0x100000 ? "unreadable_range" : null);
            Capture("clock-gap", () => source.Error = a => a == 0x100040 ? "unreadable_range" : null);
            Capture("partial-state", () => source.Short = 0x100000);
            source.Data[0x100000] = TimerTests.State(0, float.NaN, 1); Capture("nonfinite-state");
            source.Data[0x100000] = TimerTests.State(0, 1, float.MaxValue); source.Data[0x100040] = BitConverter.GetBytes(long.MaxValue); Capture("nonfinite-result");
            // Every finite source/type example above uses the production serializer. One strict recording checks the ordinary consumers too.
            source = new Memory(); raw = JsonSerializer.SerializeToUtf8Bytes(Profile(source, 256)); File.WriteAllBytes(input, raw);
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                string recorded = Path.Combine(root, "recording-" + number++);
                FieldRecording.RecordBounded(source, input, recorded, 10, TimeSpan.FromSeconds(10), stop.Token, new(), _ => stop.Cancel());
                var result = FieldRecordingVerification.Verify(recorded); Check(result.valid && result.frames == 1 && result.unknown_fields == 0, "max-guard complete frame strictly verifies");
            }
            source.Error = _ => new string('☃', 256);
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                var writer = new Writer(stop.Cancel); FieldStream.Run(source, input, 10, TimeSpan.FromSeconds(10), writer, stop.Token);
                Check(writer.Lines.Count == 1 && writer.Lines[0].GetProperty("stop_reason").GetString() == "output_byte_limit" && writer.Lines[0].GetProperty("unpublished_frames").GetInt32() == 1,
                    "arbitrary escaped provider errors still fail actual line cap without publishing oversized frame");
            }
            try { FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(Profile(new Memory(), 256, FieldStream.MaximumFields + 1))); Check(false, "oversize profile admitted"); }
            catch (ObservationException error) { Check(error.Code == "field_profile_limit", "expanded field ceiling still rejects oversized profiles"); }
            return assertions;
        }
        finally { Directory.Delete(root, true); }
    }
}
