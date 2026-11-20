using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Portable accepted-frame evidence tests; no external process access.</summary>
internal static class LiveFieldEvidenceTests
{
    private sealed class Memory : IMemorySource
    {
        internal const ulong Address = 65536;
        internal readonly byte[] Bytes = new byte[64];
        public TargetIdentity Identity { get; } = new(81, "fixture.exe", "private-fixture", 12, new string('a', 64), "x64");
        internal Memory()
        {
            BinaryPrimitives.WriteInt32LittleEndian(Bytes, 123);
            BinaryPrimitives.WriteInt64LittleEndian(Bytes.AsSpan(16), 100);
            BinaryPrimitives.WriteSingleLittleEndian(Bytes.AsSpan(24), 20);
            BinaryPrimitives.WriteSingleLittleEndian(Bytes.AsSpan(28), 1);
            BinaryPrimitives.WriteInt64LittleEndian(Bytes.AsSpan(48), 102);
        }
        public byte[] Read(ulong address, int size)
        {
            if (address < Address || address - Address > (ulong)(Bytes.Length - size))
                throw new ObservationException("unreadable_range", "Fixture range.");
            return Bytes.AsSpan((int)(address - Address), size).ToArray();
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static JsonObject Recipe(Memory source, bool timer)
    {
        var result = JsonNode.Parse(JsonSerializer.Serialize(new
        {
            schema = "overwatch-decoder.acquisition-recipe/1",
            target = new { image_name = source.Identity.ImageName, executable_sha256 = source.Identity.ExecutableSha256, architecture = "x64" },
            seconds = 10, constants = new { }, functions = new { }, global_guards = "g",
            stages = new[] { new { name = "root", steps = new object[] {
                new { op = "read", name = "header", address = new object[] { "rva", 0, 8 }, size = 8 },
                new { op = "guard", set = "g", value = new object[] { "var", "header" } }
            } } },
            fields = new[] { new { name = "value", type = "i32", address = new object[] { "rva", 16, 4 } } }
        }))!.AsObject();
        if (timer)
        {
            result["profile_schema"] = "overwatch-decoder.field-profile/4";
            var field = result["fields"]![0]!;
            field["type"] = "f32"; field["address"] = new JsonArray("rva", 16, 16);
            field["codec"] = TimerCodec.Name; field["clock_address"] = new JsonArray("rva", 48, 8);
            field["counter_scale_f32_hex"] = "0000803f";
        }
        return result;
    }
    internal static int Run()
    {
        int assertions = 0;
        void Check(bool condition, string label)
        { if (!condition) throw new ObservationException("self_test_failed", "live-evidence:" + label); assertions++; }
        void Invalid(Action action)
        {
            try { action(); }
            catch (ObservationException error) { Check(error.Code == "invalid_arguments", "flag validation error"); return; }
            Check(false, "invalid flag accepted");
        }
        Check(!Program.LiveEvidenceOption(new(), false) && !Program.LiveEvidenceOption(new(), true), "default disabled");
        Check(!Program.LiveEvidenceOption(new() { ["live-evidence"] = "false" }, false), "explicit false without JSONL");
        Check(Program.LiveEvidenceOption(new() { ["live-evidence"] = "true" }, true), "explicit true with JSONL");
        Invalid(() => Program.LiveEvidenceOption(new() { ["live-evidence"] = "true" }, false));
        foreach (string value in new[] { "TRUE", "1", "", "yes" })
            Invalid(() => Program.LiveEvidenceOption(new() { ["live-evidence"] = value }, true));
        using var source = new Memory();
        Invalid(() => ObserveFields.RunBounded(source, new(Memory.Address, 64, "fixture.exe"), "missing", "missing", 10,
            TimeSpan.FromSeconds(1), default, new(), liveEvidence: true));
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-live-evidence-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            foreach (bool timer in new[] { false, true })
            foreach (bool enabled in new[] { false, true })
            {
                using var memory = new Memory(); using var live = new StringWriter();
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                string tag = $"{timer}-{enabled}", recipe = Path.Combine(root, tag + ".json"), output = Path.Combine(root, tag);
                File.WriteAllText(recipe, Recipe(memory, timer).ToJsonString()); var accepted = new List<string>();
                var result = ObserveFields.RunBounded(memory, new(Memory.Address, 64, "fixture.exe"), recipe, output, 10,
                    TimeSpan.FromSeconds(10), stop.Token, new(RetryMilliseconds: 0), (_, frame) =>
                    {
                        accepted.Add(frame.RecordingLine!);
                        if (frame.Sequence == 0) memory.Bytes[4] = 1; // Invalidate the exact acquired guard.
                        else stop.Cancel();
                    }, liveOutput: live, liveEvidence: enabled);
                Check(result.segments.Length == 1 && result.segments[0].frames == 2, "accepted invalidation frame retained");
                string segment = Path.Combine(output, "segment-0001");
                Check(FieldRecordingVerification.Verify(segment).valid, "durable recording independently verifies");
                using var file = File.OpenRead(Path.Combine(segment, "samples.jsonl.gz"));
                using var gzip = new GZipStream(file, CompressionMode.Decompress); using var reader = new StreamReader(gzip);
                var recorded = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Where(line => JsonDocument.Parse(line).RootElement.GetProperty("kind").GetString() == "frame").ToArray();
                Check(recorded.SequenceEqual(accepted), "callback holds exact accepted recording line");
                var events = live.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(line => JsonSerializer.Deserialize<JsonElement>(line)).ToArray();
                var frames = events.Where(row => row.GetProperty("kind").GetString() == "frame").ToArray();
                Check(frames.Length == recorded.Length, "one live event per accepted frame");
                for (int i = 0; i < frames.Length; i++)
                {
                    Check(frames[i].GetProperty("recording_state").GetString() == "accepted_not_durability_verified" &&
                        !frames[i].GetProperty("public_state_eligible").GetBoolean(), "acceptance and privacy qualification");
                    Check(frames[i].TryGetProperty("recording_frame", out var evidence) == enabled, "opt-in only");
                    if (!enabled) continue;
                    Check(evidence.GetRawText() == recorded[i], "exact full accepted v1/v4 wire parity");
                    Check(evidence.GetProperty("guards_before").ValueKind == JsonValueKind.Array &&
                        evidence.GetProperty("guards_after").ValueKind == JsonValueKind.Array &&
                        evidence.GetProperty("fields").GetProperty("value").GetProperty("guard_ids").GetArrayLength() > 0,
                        "full guard evidence retained");
                    Check(evidence.GetProperty("fields").GetProperty("value").GetProperty("status").GetString() ==
                        (i == 0 ? "observed" : "unknown"), "guard mismatch remains unknown");
                    if (timer) Check(evidence.GetProperty("private_address_trace").GetBoolean() &&
                        evidence.GetProperty("fields").GetProperty("value").TryGetProperty("operands", out _), "v4 enrichment retained");
                }
                var start = events[0];
                Check(enabled ? start.GetProperty("address_traces_included").ValueKind == JsonValueKind.Null &&
                        start.GetProperty("recording_frame_included").GetBoolean() :
                    !start.GetProperty("address_traces_included").GetBoolean() && !start.TryGetProperty("recording_frame_included", out _),
                    "default metadata unchanged and opt-in trace capability explicit");
            }
            // v2 path failures have enrichment absent from AcceptedFrame.Timing too.
            var fixture = FieldSerializationTests.Fixture(true, "failed_pointer");
            string wire = FieldSerializationTests.Direct(fixture);
            var sample = new FieldStream.AcceptedFrame(123, fixture.Frame.start_ticks, fixture.Frame.end_ticks, 2, true, null,
                fixture.Fields, fixture.Frame, fixture.Attempted, wire);
            using var capture = new StringWriter(); var writer = new LiveFieldOutput(capture, "fixture", includeEvidence: true);
            Check(writer.Frame(1, fixture.Profile, sample), "v2 path evidence accepted");
            Check(JsonDocument.Parse(capture.ToString()).RootElement.GetProperty("recording_frame").GetRawText() == wire, "v2 path evidence exact");
            using var absent = new StringWriter(); var missing = new LiveFieldOutput(absent, "fixture", includeEvidence: true);
            Check(!missing.Frame(1, fixture.Profile, sample with { RecordingLine = null }) && absent.ToString() == "" &&
                missing.Error == "live_recording_evidence_missing", "missing evidence fails closed");
            // A recording-sized line can exceed the unchanged live cap once its envelope is added.
            string large = "{\"padding\":\"" + new string('x', LiveFieldOutput.MaximumLineBytes - 100) + "\"}";
            Check(Encoding.UTF8.GetByteCount(large) < LiveFieldOutput.MaximumLineBytes, "fixture recording line below cap");
            using var bounded = new StringWriter(); var capped = new LiveFieldOutput(bounded, "fixture", includeEvidence: true);
            Check(!capped.Frame(1, fixture.Profile, sample with { RecordingLine = large }) && capped.Error == "live_line_byte_limit" &&
                capped.Lines == 0 && capped.Bytes == 0 && bounded.ToString() == "", "over-cap live line refused without truncation or partial write");
            Check(capped.Write("session_end", w => w.WriteString("reason", capped.Error), final: true), "reserved terminal evidence still writable");
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
