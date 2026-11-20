using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace OverwatchDecoder.Observer;

/// <summary>Wire compatibility against the former DOM serializer, using identical immutable sample data.</summary>
public static class FieldSerializationTests
{
    internal sealed record Sample(FieldStream.Frame Frame, FieldStream.Profile Profile,
        Dictionary<string, FieldStream.FieldResult> Fields, PointerPaths.State[] Paths,
        Dictionary<string, ulong?> Addresses, Dictionary<string, bool> Attempted);

    internal static string Direct(Sample sample) => FieldStream.SerializeFrame(sample.Frame, sample.Profile,
        sample.Fields, sample.Paths, sample.Addresses, sample.Attempted);

    internal static bool Equivalent(JsonElement left, JsonElement right)
    {
        if (left.ValueKind != right.ValueKind) return false;
        if (left.ValueKind == JsonValueKind.Object)
        {
            var a = left.EnumerateObject().ToArray(); var b = right.EnumerateObject().ToArray();
            return a.Length == b.Length && a.Zip(b).All(pair => pair.First.Name == pair.Second.Name && Equivalent(pair.First.Value, pair.Second.Value));
        }
        if (left.ValueKind == JsonValueKind.Array)
            return left.GetArrayLength() == right.GetArrayLength() && left.EnumerateArray().Zip(right.EnumerateArray()).All(pair => Equivalent(pair.First, pair.Second));
        // Preserve exact numeric tokens, including long precision, exponent spelling and signed zero.
        // JSON string escaping may differ; the decoded string must be identical.
        return left.ValueKind == JsonValueKind.String ? left.GetString() == right.GetString() : left.GetRawText() == right.GetRawText();
    }

    // This deliberately retains the previous anonymous envelope and DOM enrichment as a compatibility oracle.
    // It is test code only; the recorder never calls it.
    internal static string Legacy(Sample sample)
    {
        var f = sample.Frame;
        var frame = new
        {
            f.schema, f.kind, f.source, f.interpretation, f.visibility,
            f.runtime_semantics_validated, f.public_state_eligible, f.atomic,
            f.target, f.profile_sha256, f.sequence, f.scheduled_slot,
            f.scheduled_ticks, f.start_ticks, f.end_ticks, f.jitter_ticks,
            f.skipped_intervals_before, f.skipped_intervals_total,
            f.utc_origin, f.utc_origin_before_ticks, f.monotonic_origin_ticks,
            f.monotonic_frequency, f.requested_interval_ms, f.scheduler_backend, f.hard_realtime,
            f.guards_before, f.guards_after, fields = sample.Fields
        };
        if (!sample.Profile.V2) return JsonSerializer.Serialize(frame);
        var enriched = JsonSerializer.SerializeToNode(frame)!.AsObject();
        enriched["private_address_trace"] = true;
        enriched["path_traces"] = JsonSerializer.SerializeToNode(sample.Paths.Select((path, id) => path.Evidence(id)));
        foreach (var field in sample.Profile.Fields)
        {
            var item = enriched["fields"]![field.Name]!.AsObject();
            item["path_id"] = field.PathId;
            item["read_address_hex"] = sample.Addresses[field.Name] is { } address ? PointerPaths.Hex(address) : null;
            item["read_attempted"] = sample.Attempted[field.Name];
            if (!sample.Attempted[field.Name]) { item["read_start_ticks"] = null; item["read_end_ticks"] = null; }
        }
        return enriched.ToJsonString();
    }

    internal static Sample Fixture(bool v2, string mode, int guardCount = 2)
    {
        const long tick = 9_123_456_789_012_345; // Above 2^53: integer timestamps must not pass through doubles.
        var identity = new TargetIdentity(123, "fixture-☃&.exe", "synthetic", tick, new string('a', 64), "x64");
        int[] ids = Enumerable.Range(0, guardCount).ToArray();
        var guards = ids.Select(i => new FieldStream.Guard(0x1000UL + (ulong)i * 64, BitConverter.GetBytes(i))).ToArray();
        var before = ids.Select(i => new FieldStream.GuardResult(true, tick + i * 10, tick + i * 10 + 4, null)).ToArray();
        var after = ids.Select(i => new FieldStream.GuardResult(true, tick + 1500 + i * 10, tick + 1504 + i * 10, null)).ToArray();
        var hop = new PointerPaths.Hop(16, [new(0, [1, 2, 3, 4])]);
        var path = new PointerPaths.Path("storage", 0x1000, ids, [hop]);
        var state = new PointerPaths.State(path) { Leaf = 0x2000 };
        var h = state.Hops[0]; h.Slot = 0x1010; h.Node = 0x2000; h.Pointer = BitConverter.GetBytes(0x2000UL);
        h.Before = new(true, "0000000000001010", "0020000000000000", tick + 1000, tick + 1004, null);
        h.After = new(true, "0000000000001010", "0020000000000000", tick + 1410, tick + 1414, null);
        h.Pre = [new(true, new(true, "0000000000002000", "01020304", tick + 1010, tick + 1014, null))];
        h.Post = [new(true, new(true, "0000000000002000", "01020304", tick + 1400, tick + 1404, null))];
        object[] values = [0, 255, int.MinValue, (double)float.Epsilon, double.Epsilon, double.MaxValue, -0d,
            new double[] { -0d, (double)float.MaxValue, (double)-float.Epsilon },
            new double[] { 0, .25, -.5, 1 }, Math.PI];
        string[] types = ["u8", "u8", "i32", "f32", "f64", "f64", "f64", "f32x3", "f32x4", "f64"];
        var declarations = new List<FieldStream.Field>();
        var fields = new Dictionary<string, FieldStream.FieldResult>(StringComparer.Ordinal);
        var addresses = new Dictionary<string, ulong?>(); var attempted = new Dictionary<string, bool>();
        for (int i = 0; i < values.Length; i++)
        {
            string name = "field_" + i; int? pathId = v2 && i > 0 ? 0 : null;
            int components = types[i] is "f32x3" ? 3 : types[i] is "f32x4" ? 4 : 1;
            int width = types[i] is "u8" ? 1 : types[i] is "f64" ? 8 : components * 4;
            declarations.Add(new(name, types[i], 0x8000, width, components, null, null, ids, pathId, (uint)(64 + i * 16)));
            fields[name] = new(types[i], "observed", values[i], null, tick + 1100 + i * 10, tick + 1104 + i * 10, ids);
            addresses[name] = pathId is null ? 0x8000UL : 0x2040UL + (ulong)i * 16; attempted[name] = true;
        }
        if (mode is "null_path" or "failed_pointer" or "cancelled")
        {
            state.Leaf = null; state.Error = mode == "null_path" ? "pointer_null" : mode == "failed_pointer" ? "unreadable_range" : "cancelled";
            h.Node = null; h.Pointer = mode == "null_path" ? new byte[8] : null;
            h.Before = mode == "cancelled" ? PointerPaths.ReadEvidence.Missing :
                new(true, "0000000000001010", mode == "null_path" ? "0000000000000000" : null, tick + 1000, tick + 1004,
                    mode == "failed_pointer" ? "unreadable_range" : null);
            h.After = mode == "cancelled" ? PointerPaths.ReadEvidence.Missing : h.Before with { start_ticks = tick + 1410, end_ticks = tick + 1414 };
            h.Pre = [new(false, PointerPaths.ReadEvidence.Missing)]; h.Post = [new(false, PointerPaths.ReadEvidence.Missing)];
            foreach (var field in declarations.Where(f => f.PathId is not null || mode == "cancelled"))
            {
                fields[field.Name] = fields[field.Name] with { status = "unknown", value = null, reason = state.Error };
                addresses[field.Name] = null; attempted[field.Name] = false;
                // The control-stop interval exists in the internal result but must become null for an unattempted v2 read.
            }
            if (mode == "cancelled")
                for (int i = 0; i < after.Length; i++) after[i] = after[i] with { ok = false, error = "cancelled" };
        }
        else if (mode == "changed_after")
        {
            state.Error = "pointer_changed";
            h.After = h.After with { bytes_hex = "0030000000000000" };
            foreach (var field in declarations.Where(f => f.PathId is not null))
                fields[field.Name] = fields[field.Name] with { status = "unknown", value = null, reason = "pointer_changed" };
        }
        else if (mode == "failed_field")
            fields["field_7"] = fields["field_7"] with { status = "unknown", value = null, reason = "non_finite" };
        else if (mode != "observed") throw new InvalidOperationException("Unknown serialization fixture mode.");
        var profile = new FieldStream.Profile(identity, new string('b', 64), guards, declarations.ToArray(), 0, [], v2 ? [path] : null);
        var frame = new FieldStream.Frame
        {
            schema = v2 ? "overwatch-decoder.field-stream/2" : "overwatch-decoder.field-stream/1", target = Snapshots.PublicIdentity(identity), profile_sha256 = profile.Hash,
            sequence = 123, scheduled_slot = 130, scheduled_ticks = tick - 7, start_ticks = tick, end_ticks = tick + 2500,
            jitter_ticks = 7, skipped_intervals_before = 2, skipped_intervals_total = 7,
            utc_origin = new DateTimeOffset(2026, 10, 31, 0, 0, 0, TimeSpan.Zero), utc_origin_before_ticks = tick - 1_300_001,
            monotonic_origin_ticks = tick - 1_300_000, monotonic_frequency = 10_000_000, requested_interval_ms = 10,
            scheduler_backend = "synthetic", guards_before = before, guards_after = after, fields = fields
        };
        return new(frame, profile, fields, v2 ? [state] : [], addresses, attempted);
    }

    public static int Run()
    {
        int assertions = 0;
        void Check(bool ok, string name)
        { if (!ok) throw new ObservationException("self_test_failed", "field-serialization:" + name); assertions++; }
        // Frozen v1/v2 typed-serializer output with the Overwatch Decoder schema names.
        // Reversing only the schema prefix reproduced every previous pinned hash.
        // Unlike the DOM oracle below, these pin exact v1 AND v2 UTF-8 bytes.
        var pinned = new Dictionary<string, string>
        {
            ["v1:observed"] = "4364064b81bc9a790acb74beb883f7fa61035e6ac318523e1951d0a52a4345c3",
            ["v1:null_path"] = "4364064b81bc9a790acb74beb883f7fa61035e6ac318523e1951d0a52a4345c3",
            ["v1:failed_pointer"] = "4364064b81bc9a790acb74beb883f7fa61035e6ac318523e1951d0a52a4345c3",
            ["v1:cancelled"] = "e3fea1208e04cb5d187945494a50c9b4706e77237403cece69c72a9a3bcecf42",
            ["v1:changed_after"] = "4364064b81bc9a790acb74beb883f7fa61035e6ac318523e1951d0a52a4345c3",
            ["v1:failed_field"] = "40d89a9020e1c3d5dbad534c1324ec4c1800386671730869f1f62007ca8345f3",
            ["v2:observed"] = "d3335c89fb820a8ce17ba3e7855adab5f3cedf1ebacfb559bacd0d81a75e22c4",
            ["v2:null_path"] = "dd2bd21575ba6f4849e164d18cb4be9ca6e89fcb84a13638214012d051844d7b",
            ["v2:failed_pointer"] = "ff799d9b6f9c01289390d39ab207d88fdb7b615315b7d9c4b2098bd8c1da6fcf",
            ["v2:cancelled"] = "45abc0235b64c9a25dfce2768e26d7d7a37eb37e7b21254c279072c1b514b052",
            ["v2:changed_after"] = "812ae4d7d1d4ce82fd085e6930d4ae6481de01332d262eb9eaf07b8fa102b420",
            ["v2:failed_field"] = "aa5687e080bf08d7570fc400b828bbaaef063a0583de22f46e8da81032b2ee7e"
        };
        foreach (bool v2 in new[] { false, true })
        foreach (string mode in new[] { "observed", "null_path", "failed_pointer", "cancelled", "changed_after", "failed_field" })
        {
            var sample = Fixture(v2, mode); string expected = Legacy(sample), actual = Direct(sample);
            Check(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(actual))) == pinned[$"v{(v2 ? 2 : 1)}:{mode}"], "frozen v1/v2 exact wire bytes");
            using var doc = JsonDocument.Parse(actual); using var original = JsonDocument.Parse(expected); var frame = doc.RootElement;
            Check(Equivalent(original.RootElement, frame), $"v{(v2 ? 2 : 1)} {mode} exact wire structure and values");
            if (!v2) Check(actual == expected, "v1 exact legacy bytes");
            // The old v2 DOM wrote the UTC '+' as \u002B. Direct typed DateTimeOffset serialization
            // writes '+', preserving the timestamp string while reducing the measured UTF8 line by five bytes.
            Check(Encoding.UTF8.GetByteCount(actual) + (v2 ? 5 : 0) == Encoding.UTF8.GetByteCount(expected), "only UTC escape spelling changes byte count");
            Check(frame.GetProperty("start_ticks").GetInt64() == sample.Frame.start_ticks, "large integer timestamp exact");
            Check(frame.TryGetProperty("private_address_trace", out _) == v2 && frame.TryGetProperty("path_traces", out _) == v2 &&
                !frame.TryGetProperty("Trace", out _), "v2 metadata flattened and absent from v1");
            var independent = frame.GetProperty("fields").GetProperty("field_0");
            if (v2) Check(independent.GetProperty("path_id").ValueKind == JsonValueKind.Null, "fixed address has null path id");
            var dependent = frame.GetProperty("fields").GetProperty("field_7");
            bool read = sample.Attempted["field_7"];
            if (v2)
            {
                Check(dependent.GetProperty("read_attempted").GetBoolean() == read, "read-attempt flag exact");
                Check((dependent.GetProperty("read_start_ticks").ValueKind == JsonValueKind.Null) == !read &&
                    (dependent.GetProperty("read_end_ticks").ValueKind == JsonValueKind.Null) == !read, "unattempted interval null");
            }
            Check(sample.Frame.Trace is null && sample.Fields["field_7"].read_start_ticks.HasValue,
                "serialization never mutates the internal result");
        }
        var large = Fixture(true, "observed", 90);
        using var largeDirect = JsonDocument.Parse(Direct(large)); using var largeLegacy = JsonDocument.Parse(Legacy(large));
        Check(Equivalent(largeDirect.RootElement, largeLegacy.RootElement), "large guarded frame remains equivalent");
        foreach (var utc in new[] { DateTimeOffset.MinValue, DateTimeOffset.MaxValue,
            new DateTimeOffset(2026, 10, 31, 1, 2, 3, TimeSpan.FromHours(-6)).AddTicks(1234567),
            new DateTimeOffset(2026, 10, 31, 1, 2, 3, TimeSpan.FromHours(14)).AddTicks(10000) })
        {
            var sample = Fixture(true, "observed"); sample = sample with { Frame = sample.Frame with { utc_origin = utc } };
            using var direct = JsonDocument.Parse(Direct(sample)); using var legacy = JsonDocument.Parse(Legacy(sample));
            Check(Equivalent(direct.RootElement, legacy.RootElement), "UTC offset and fractional precision unchanged");
        }
        foreach (double value in new[] { -double.MaxValue, -double.Epsilon })
        {
            var sample = Fixture(true, "observed"); sample.Fields["field_9"] = sample.Fields["field_9"] with { value = value };
            using var direct = JsonDocument.Parse(Direct(sample)); using var legacy = JsonDocument.Parse(Legacy(sample));
            Check(Equivalent(direct.RootElement, legacy.RootElement), "negative finite extreme and subnormal tokens unchanged");
        }
        return assertions;
    }
}
