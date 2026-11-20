using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Dynamic synthetic actor rows; ordinal labels deliberately change actor meaning.</summary>
public static class ObserveFieldShapeTests
{
    private static object[] E(params object[] values) => values;
    private static object V(string name) => E("var", name);
    private sealed class Memory : IMemorySource
    {
        internal const ulong Address = 65536;
        internal readonly byte[] Bytes = new byte[4096];
        internal long Reads, RequestedBytes;
        private ulong epoch;
        public TargetIdentity Identity { get; } = new(62, "fixture.exe", "fixture", 12, new string('e', 64), "x64");
        internal Memory() { Actors(0, 1); }
        private void Put(int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(Bytes.AsSpan(offset, 8), value);
        internal void Actors(params int[] actors)
        {
            Put(0, ++epoch); Put(8, (ulong)actors.Length);
            for (int i = 0; i < actors.Length; i++) Put(32 + i * 8, Address + (ulong)(128 + actors[i] * 128));
            for (int i = 0; i < 3; i++) { Put(128 + i * 128, (ulong)(100 + i)); Put(136 + i * 128, (ulong)(11 * (i + 1))); }
        }
        public byte[] Read(ulong address, int size)
        {
            Reads++; RequestedBytes += size;
            if (address < Address || address - Address > (ulong)(Bytes.Length - size)) throw new ObservationException("unreadable_range", "Fixture range.");
            return Bytes.AsSpan((int)(address - Address), size).ToArray();
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static string Recipe(Memory memory) => JsonSerializer.Serialize(new
    {
        schema = "overwatch-decoder.acquisition-recipe/1",
        target = new { image_name = memory.Identity.ImageName, executable_sha256 = memory.Identity.ExecutableSha256, architecture = "x64" },
        seconds = 10, constants = new { }, functions = new { }, global_guards = "global",
        stages = new[] { new { name = "actors", steps = new object[] {
            new { op = "read", name = "root", address = E("rva", 0, 16), size = 16 },
            new { op = "guard", set = "global", value = V("root") },
            new { op = "scan", name = "rows", count = E("load", V("root"), 8, 8), index = "index", keep = new[] { "actor", "local_guards" }, steps = new object[] {
                new { op = "read", name = "entry", address = E("rva", E("add", 32, E("mul", V("index"), 8)), 8), size = 8 },
                new { op = "guard", set = "local_guards", value = V("entry") },
                new { op = "let", name = "actor", value = E("load", V("entry"), 0, 8) },
                new { op = "read", name = "actor_header", address = V("actor"), size = 8 },
                new { op = "guard", set = "local_guards", value = V("actor_header") }
            } }
        } } },
        fields = Array.Empty<object>(),
        field_collections = new[] { new { rows = "rows", prefix = "actor", fields = new[] {
            new { name = "value", type = "i32", address = E("add", V("actor"), 8), guards = "local_guards", min = 0, max = 100 }
        } } }
    });
    public static int Run()
    {
        int assertions = 0, number = 0;
        void Check(bool ok, string label)
        { if (!ok) throw new ObservationException("self_test_failed", "observe-field-shape:" + label); assertions++; }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-field-shapes-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        ObserveFields.Result Observe(Memory memory, string output, bool allow = false,
            Action<int, FieldStream.AcceptedFrame>? frame = null, CancellationToken token = default,
            TextWriter? live = null, ObserveFields.Limits? limits = null)
        {
            string recipe = Path.Combine(root, "recipe-" + ++number + ".json"); File.WriteAllText(recipe, Recipe(memory));
            return ObserveFields.RunBounded(memory, new(Memory.Address, (ulong)memory.Bytes.Length, memory.Identity.ImageName), recipe,
                output, 10, TimeSpan.FromSeconds(10), token, limits ?? new(RetryMilliseconds: 0), frame, live,
                allowFieldShapeChanges: allow);
        }
        JsonElement[] Lines(string text) => text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => JsonSerializer.Deserialize<JsonElement>(line)).ToArray();
        JsonElement[] Frames(string directory)
        {
            using var gz = new GZipStream(File.OpenRead(Path.Combine(directory, "samples.jsonl.gz")), CompressionMode.Decompress);
            using var reader = new StreamReader(gz);
            return Lines(reader.ReadToEnd()).Where(line => line.GetProperty("kind").GetString() == "frame").ToArray();
        }
        try
        {
            var memory = new Memory(); string output = Path.Combine(root, "dynamic"); using var live = new StringWriter();
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var result = Observe(memory, output, true, (segment, frame) =>
            {
                if (frame.Sequence != 0) return;
                if (segment == 1) memory.Actors(1, 2, 0); // B, C, A: add and reorder.
                else if (segment == 2) memory.Actors(2); // C: remove two rows.
                else if (segment == 3) memory.Actors(0, 1); // A, B: names return with new actors.
                else stop.Cancel();
            }, stop.Token, live);
            Check(result.stop_reason == "cancelled" && !result.complete && result.acquisitions.Length == 4 && result.segments.Length == 4, "dynamic cancellation and finite segments");
            Check(result.read_calls == memory.Reads && result.requested_read_bytes == memory.RequestedBytes, "physical reads share exact accounting");
            Check(result.segments.Take(3).All(s => s.trigger == "guard_invalidation" && s.frames == 2) && result.segments[3].frames == 1, "invalid accepted frame precedes each reacquisition");
            Check(result.segments.Select(s => s.profile_sha256).Distinct().Count() == 4, "every epoch has fresh profile hash");
            Check(result.intervals_without_recorded_frames.Length == 5 && result.intervals_without_recorded_frames.All(g => g.end_ticks >= g.start_ticks), "explicit nonnegative session and rotation gaps");
            var starts = Lines(live.ToString()).Where(line => line.GetProperty("kind").GetString() == "segment_start").ToArray();
            int[][] values = [[11, 22], [22, 33, 11], [33], [11, 22]];
            for (int i = 0; i < result.segments.Length; i++)
            {
                var segment = result.segments[i]; string directory = Path.Combine(output, segment.directory);
                var verification = FieldRecordingVerification.Verify(directory);
                Check(verification.valid && !verification.complete, "strict segment verification:" + i);
                byte[] profileBytes = File.ReadAllBytes(Path.Combine(output, result.acquisitions[i].directory, "profile.json"));
                using var profile = JsonDocument.Parse(profileBytes);
                Check(segment.ordinal == i + 1 && segment.profile_sha256 == Convert.ToHexStringLower(SHA256.HashData(profileBytes)) &&
                    starts[i].GetProperty("profile_sha256").GetString() == segment.profile_sha256, "number and exact saved/live profile hash:" + i);
                var schema = starts[i].GetProperty("fields"); var declared = profile.RootElement.GetProperty("fields");
                Check(schema.GetArrayLength() == values[i].Length && schema.EnumerateArray().Select(f => (f.GetProperty("name").GetString(), f.GetProperty("type").GetString()))
                    .SequenceEqual(declared.EnumerateArray().Select(f => (f.GetProperty("name").GetString(), f.GetProperty("type").GetString()))), "exact segment field schema:" + i);
                var frames = Frames(directory); var fields = frames[0].GetProperty("fields");
                Check(fields.EnumerateObject().Count() == values[i].Length && fields.EnumerateObject().Select(f => f.Value.GetProperty("value").GetInt32()).SequenceEqual(values[i]), "fresh actor rows without stale carryover:" + i);
                Check(frames.All(f => f.GetProperty("fields").EnumerateObject().Count() == values[i].Length), "only current schema in every frame:" + i);
                if (i < 3)
                {
                    Check(frames[1].GetProperty("fields").EnumerateObject().All(f => f.Value.GetProperty("status").GetString() == "unknown" && f.Value.GetProperty("value").ValueKind == JsonValueKind.Null), "invalid epoch values stay unknown:" + i);
                    var gap = result.intervals_without_recorded_frames[i + 1];
                    Check(gap.start_ticks == segment.last_frame_end_ticks && gap.end_ticks == result.segments[i + 1].first_frame_start_ticks, "gap bounds rotation:" + i);
                }
            }
            Check(result.fields.Length == 3 && result.fields[0].observed == 4 && result.fields[0].unknown == 3 &&
                result.fields[1].observed == 3 && result.fields[1].unknown == 2 && result.fields[2].observed == 1 && result.fields[2].unknown == 1, "coverage counts names only and absent rows accrue no unknowns");
            Check(JsonSerializer.SerializeToElement(result.limits).GetProperty("maximum_coverage_fields").GetInt32() == 8 * FieldStream.MaximumFields &&
                JsonSerializer.SerializeToElement(result.limits).GetProperty("allow_field_shape_changes").GetBoolean(), "explicit opt-in and bounded union metadata");
            memory = new(); var rejected = Observe(memory, Path.Combine(root, "default"), frame: (_, f) => { if (f.Sequence == 0) memory.Actors(0, 1, 2); });
            Check(rejected.stop_reason == "field_shape_changed" && rejected.segments.Length == 1 && rejected.acquisitions.Length == 2 && rejected.fields.Length == 2, "default rejection before changed profile recording or coverage");
            Check(FieldRecordingVerification.Verify(Path.Combine(root, "default", "segment-0001")).valid, "default rejection retains valid segment");

            // Fixed recipe types cannot change through actor movement. Exercise the admission boundary
            // directly for an externally supplied schema, including a name absent in the prior segment.
            FieldStream.Field Field(string name, string type = "i32") => new(name, type, Memory.Address, 4, 1, null, null, []);
            var coverage = new Dictionary<string, ObserveFields.Coverage>(StringComparer.Ordinal);
            Check(ObserveFields.AdmitFields(coverage, [Field("actor"), Field("gone")], true, 1024) is null &&
                ObserveFields.AdmitFields(coverage, [Field("actor")], true, 1024) is null, "name removal preserves historical declared-name union");
            Check(ObserveFields.AdmitFields(coverage, [Field("new"), Field("gone", "f32")], true, 1024) == "field_type_changed" &&
                coverage.Count == 2 && coverage["gone"].type == "i32" && !coverage.ContainsKey("new"), "same-name type reuse rejects entire schema atomically");
            Check(ObserveFields.AdmitFields(coverage, [Field("actor", "f32"), Field("gone")], false, 1024) == "field_shape_changed", "legacy type rejection unchanged");
            coverage.Clear();
            for (int attempt = 0; attempt < 8; attempt++)
                Check(ObserveFields.AdmitFields(coverage, Enumerable.Range(0, 128).Select(i => Field("f" + attempt + "_" + i)).ToArray(), true, 1024) is null, "maximum union attempt:" + attempt);
            Check(coverage.Count == 1024 && ObserveFields.AdmitFields(coverage, [Field("overflow")], true, 1024) == "field_coverage_limit" && coverage.Count == 1024, "coverage union cannot exceed attempt-times-profile bound");
            memory = new(); var callLimit = Observe(memory, Path.Combine(root, "read-limit"), true, limits: new(ReadCalls: 2, RetryMilliseconds: 0));
            Check(!callLimit.complete && callLimit.read_calls == 2 && memory.Reads == 2 && callLimit.segments.Length == 0, "opt-in preserves acquisition physical call cap");
            memory = new();
            void Rotate(int segment, FieldStream.AcceptedFrame frame)
            { if (frame.Sequence == 0) { if (segment % 2 == 1) memory.Actors(0, 1, 2); else memory.Actors(2); } }
            var sharedCalls = Observe(memory, Path.Combine(root, "shared-calls"), true, Rotate, limits: new(ReadCalls: 60, RetryMilliseconds: 0));
            Check(!sharedCalls.complete && sharedCalls.read_calls == 60 && memory.Reads == 60 && sharedCalls.acquisitions.Length >= 2 && sharedCalls.segments.Length >= 1,
                "physical call budget cannot reset at reacquisition");
            foreach (var segment in sharedCalls.segments)
                Check(FieldRecordingVerification.Verify(Path.Combine(root, "shared-calls", segment.directory)).valid, "call-limited segment strictly verifies");
            memory = new(); var evidenceLimit = Observe(memory, Path.Combine(root, "evidence-limit"), true, Rotate,
                limits: new(EvidenceBytes: 131072, RetryMilliseconds: 0));
            Check(evidenceLimit.stop_reason == "session_evidence_limit" && evidenceLimit.acquisitions.Length == 1 && evidenceLimit.acquisition_evidence_bytes <= 131072,
                "acquisition evidence budget shared across rotations");
            memory = new(); var outputLimit = Observe(memory, Path.Combine(root, "output-limit"), true, limits: new(JsonBytes: 8192, RetryMilliseconds: 0));
            Check(!outputLimit.complete && outputLimit.stop_reason == "output_byte_limit" && outputLimit.recorded_json_bytes <= 8192 && outputLimit.segments.Single().frames == 0 &&
                FieldRecordingVerification.Verify(Path.Combine(root, "output-limit", "segment-0001")).valid, "opt-in output budget refuses frames and retains strictly valid artifact");
            memory = new(); using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            var preCancelled = Observe(memory, Path.Combine(root, "pre-cancel"), true, token: cancelled.Token);
            Check(preCancelled.stop_reason == "cancelled" && memory.Reads == 0 && preCancelled.segments.Length == 0, "opt-in pre-cancel makes no reads");
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
