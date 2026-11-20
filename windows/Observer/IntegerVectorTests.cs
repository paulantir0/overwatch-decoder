using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

internal static class IntegerVectorTests
{
    private sealed class Memory : IMemorySource
    {
        internal int Header = 1;
        internal int VectorReads;
        internal int[] Values = [int.MinValue, -1, 0, int.MaxValue];
        internal bool Partial;
        public TargetIdentity Identity { get; } = new(31, "fixture.exe", "fixture", 19, new string('a', 64), "x64");
        public byte[] Read(ulong address, int size)
        {
            if (address is 0x1000 or 0x2000) return BitConverter.GetBytes(Header);
            if (address == 0x1010) return BitConverter.GetBytes(0x2000UL);
            if (address is 0x1020 or 0x2020)
            {
                VectorReads++;
                if (size != 16) throw new ObservationException("fixture_wrong_width", "Integer vector must request 16 bytes.");
                var bytes = Values.SelectMany(BitConverter.GetBytes).ToArray(); return Partial ? bytes[..^1] : bytes;
            }
            throw new ObservationException("unreadable_range", "Synthetic fixture range.");
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    internal static int Run()
    {
        int assertions = 0;
        void Check(bool ok, string why) { assertions++; if (!ok) throw new ObservationException("self_test_failed", "i32x4:" + why); }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-i32x4-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            var memory = new Memory();
            JsonObject Profile(int version) => new()
            {
                ["schema"] = "overwatch-decoder.field-profile/" + version,
                ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(memory.Identity)),
                ["guards"] = new JsonArray(new JsonObject { ["address"] = 0x1000, ["bytes_hex"] = "01000000" }),
                ["fields"] = new JsonArray(new JsonObject { ["name"] = "words", ["type"] = "i32x4", ["address"] = 0x1020 })
            };
            for (int version = 1; version <= 4; version++)
            {
                var profile = Profile(version);
                if (version is 2 or 3) profile["paths"] = new JsonArray();
                if (version == 2)
                {
                    profile["paths"] = JsonNode.Parse("[{\"name\":\"storage\",\"root_address\":4096,\"root_guards\":[{\"offset\":0,\"bytes_hex\":\"01000000\"}],\"hops\":[{\"pointer_offset\":16,\"destination_guards\":[{\"offset\":0,\"bytes_hex\":\"01000000\"}]}]}]");
                    var declaration = profile["fields"]![0]!.AsObject(); declaration.Remove("address"); declaration["path"] = "storage"; declaration["offset"] = 32;
                }
                if (version == 3) profile["absolute_guard_reads"] = new JsonObject { ["algorithm"] = GuardBatches.Algorithm, ["maximum_span_bytes"] = 128, ["maximum_gap_bytes"] = 32 };
                var parsed = FieldStream.ParseProfileBytes(JsonSerializer.SerializeToUtf8Bytes(profile));
                Check(parsed.Fields[0].Components == 4 && parsed.Fields[0].Width == 16 && parsed.ReadBytes == (version == 2 ? 48 : 24), "v" + version + " exact accounting");
                string input = Path.Combine(root, "profile" + version + ".json"), recording = Path.Combine(root, "record" + version);
                File.WriteAllText(input, profile.ToJsonString());
                using var stop = new CancellationTokenSource(); int before = memory.VectorReads;
                FieldRecording.RecordBounded(memory, input, recording, 10, TimeSpan.FromSeconds(2), stop.Token, new(), frame =>
                {
                    Check(frame.Fields["words"].value is int[] words && words.SequenceEqual(memory.Values), "v" + version + " signed int array"); stop.Cancel();
                });
                var verification = FieldRecordingVerification.Verify(recording);
                Check(memory.VectorReads == before + 1 && verification.valid, "v" + version + " one physical vector read and strict recording verification: " + verification.error_code + ", reads=" + (memory.VectorReads-before));
                string export = Path.Combine(root, "export" + version); FieldExport.Export(recording, export);
                var exported = File.ReadLines(export).Select(x => JsonNode.Parse(x)!).Single(x => x["kind"]?.GetValue<string>() == "frame");
                Check(exported["fields"]!["words"]!["value"]!.ToJsonString() == "[-2147483648,-1,0,2147483647]", "export exact signed integers");
                var summary = FieldSummary.Summarize(recording); var field = summary.GetProperty("fields")[0];
                Check(field.GetProperty("components").GetArrayLength() == 4 && field.GetProperty("components")[0].GetProperty("minimum").GetInt32() == int.MinValue, "four exact summary components");
                FieldTimeline.Export(recording, Path.Combine(root, "timeline" + version));
            }
            foreach (bool partial in new[] { false, true })
            {
                memory.Partial = partial; var profile = Profile(4); if (!partial) profile["fields"]![0]!["min"] = 0;
                string input = Path.Combine(root, partial ? "partial.json" : "range.json"); File.WriteAllText(input, profile.ToJsonString());
                using var stop = new CancellationTokenSource(); using var output = new StringWriter();
                FieldStream.RunBounded(memory, input, 10, TimeSpan.FromSeconds(2), output, stop.Token, new(), frame =>
                { Check(frame.Fields["words"].value is null && frame.Fields["words"].reason == (partial ? "partial_read" : "out_of_range"), "whole vector unknown on short read or component range"); stop.Cancel(); });
            }
            memory.Partial = false;
            var recipe = new JsonObject
            {
                ["schema"] = "overwatch-decoder.acquisition-recipe/1", ["profile_schema"] = "overwatch-decoder.field-profile/4",
                ["target"] = new JsonObject { ["image_name"] = memory.Identity.ImageName, ["executable_sha256"] = memory.Identity.ExecutableSha256, ["architecture"] = "x64" },
                ["seconds"] = 5, ["constants"] = new JsonObject(), ["functions"] = new JsonObject(), ["global_guards"] = "g",
                ["stages"] = JsonNode.Parse("[{\"name\":\"header\",\"steps\":[{\"op\":\"read\",\"name\":\"header\",\"address\":4096,\"size\":4},{\"op\":\"guard\",\"set\":\"g\",\"value\":[\"var\",\"header\"]}]}]"),
                ["fields"] = Profile(4)["fields"]!.DeepClone()
            };
            string recipePath = Path.Combine(root, "recipe.json"), sessionPath = Path.Combine(root, "session"); File.WriteAllText(recipePath, recipe.ToJsonString());
            using var sessionStop = new CancellationTokenSource(); using var live = new StringWriter();
            var result = ObserveFields.RunBounded(memory, new(0x1000, 0x100, memory.Identity.ImageName), recipePath, sessionPath, 10, TimeSpan.FromSeconds(3),
                sessionStop.Token, new(RetryMilliseconds: 0), (segment, frame) =>
                {
                    if (segment == 1 && frame.Sequence == 0) memory.Header = 2;
                    if (segment == 2 && frame.Sequence == 0)
                    { Check(frame.Fields["words"].value is int[] words && words.SequenceEqual(memory.Values), "freshly reacquired vector observed"); sessionStop.Cancel(); }
                }, live, liveEvidence: true);
            Check(result.acquisitions.Length == 2 && result.acquisitions.All(a => a.complete) && result.segments.Length == 2, "recipe-to-acquired-session guard invalidation and fresh reacquisition");
            foreach (var segment in result.segments)
                Check(FieldRecordingVerification.Verify(Path.Combine(sessionPath, segment.directory)).valid, "reacquired segment strict verification");
            Check(live.ToString().Contains("[-2147483648,-1,0,2147483647]"), "live evidence preserves signed integer array");
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
