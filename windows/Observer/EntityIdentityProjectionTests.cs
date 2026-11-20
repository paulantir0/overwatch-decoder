using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

internal static class EntityIdentityProjectionTests
{
    private sealed class Memory : IMemorySource
    {
        internal byte[] Data = new byte[1024];
        public TargetIdentity Identity { get; } = new(70, "fixture.exe", "private-fixture-path", 90, new string('a', 64), "x64");
        public void EnsureAlive() { }
        public void Dispose() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public byte[] Read(ulong address, int size) => Data.AsSpan(checked((int)(address - 0x1000)), size).ToArray();
        internal Memory()
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Data, 0x80001234);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.AsSpan(256), 77);
            foreach (int offset in new[] { 16, 20, 24, 272, 276, 280 }) BitConverter.GetBytes((float)offset).CopyTo(Data, offset);
        }
    }

    private static FieldStream.Profile Profile(Memory memory, params int[] order)
    {
        var declarations = new[] { new { address = 0x1000, bytes_hex = Convert.ToHexStringLower(memory.Data[..4]) },
            new { address = 0x1100, bytes_hex = Convert.ToHexStringLower(memory.Data[256..260]) } };
        object Field(string name, string type, ulong address, int[] guards) => new { name, type, address, guards = guards.Select(i => declarations[i]).ToArray() };
        var fields = new List<object> { Field("self_handle_candidate_i32", "i32", 0x1000, [0]) };
        for (int n = 0; n < order.Length; n++)
        {
            ulong address = 0x1000UL + (ulong)order[n] * 256;
            string prefix = "actor_" + n.ToString("D4");
            fields.Add(Field(prefix + "_handle_candidate_i32", "i32", address, [order[n]]));
            fields.Add(Field(prefix + "_position_candidate", "f32x3", address + 16, [order[n]]));
        }
        byte[] raw = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schema = "overwatch-decoder.field-profile/1", target = Snapshots.PublicIdentity(memory.Identity),
            guards = Array.Empty<object>(), fields
        });
        return FieldStream.ParseProfileBytes(raw);
    }

    private static Dictionary<string, FieldStream.FieldResult> Values(FieldStream.Profile profile) => profile.Fields.ToDictionary(f => f.Name, f =>
        new FieldStream.FieldResult(f.Type, "observed", f.Type == "i32"
            ? (object)unchecked((int)BinaryPrimitives.ReadUInt32LittleEndian(profile.Guards[f.Guards[0]].Expected)) : new double[] { 1, 2, 3 }, null, 1, 2, f.Guards), StringComparer.Ordinal);

    private static JsonElement Project(FieldStream.Profile profile, IReadOnlyDictionary<string, FieldStream.FieldResult> values, bool json = false)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject(); var plan = EntityIdentityProjection.Create(profile);
            if (json) plan?.Write(writer, JsonSerializer.SerializeToElement(values)); else plan?.Write(writer, values);
            writer.WriteEndObject();
        }
        return JsonSerializer.Deserialize<JsonElement>(buffer.ToArray());
    }

    public static int Run()
    {
        int checks = 0;
        void Check(bool ok, string why)
        { if (!ok) throw new ObservationException("self_test_failed", "entity-identity:" + why); checks++; }
        JsonElement Map(FieldStream.Profile profile, Dictionary<string, FieldStream.FieldResult>? values = null) => Project(profile, values ?? Values(profile)).GetProperty("entity_identity");
        JsonElement Actor(JsonElement map, int index) => map.GetProperty("actors")[index];
        string? Key(JsonElement map, int index) => Actor(map, index).GetProperty("object_key").GetString();
        var memory = new Memory(); var profile = Profile(memory, 0, 1); var values = Values(profile); var map = Map(profile);
        Check(map.GetProperty("self_status").GetString() == "observed" && Actor(map, 0).GetProperty("is_self").GetBoolean() && !Actor(map, 1).GetProperty("is_self").GetBoolean(), "exact self source and full handle join");
        Check(Actor(map, 0).GetProperty("handle").GetUInt32() == 0x80001234 && Key(map, 0) != Key(map, 1), "unsigned full handle and distinct objects");
        Check(!map.GetProperty("continuity_across_gaps").GetBoolean() && !map.GetProperty("participant_identity_validated").GetBoolean() && !map.GetProperty("public_state_eligible").GetBoolean(), "object evidence is not participant identity or continuity");
        var swapped = Profile(memory, 1, 0); var moved = Map(swapped);
        Check(Key(map, 0) == Key(moved, 1) && Key(map, 1) == Key(moved, 0) && Actor(moved, 1).GetProperty("is_self").GetBoolean(), "ordinal reassignment preserves key and follows self");
        Check(Key(Map(profile with { Hash = "other-profile" }), 0) == Key(map, 0), "profile rotation does not rename an unchanged binding");
        foreach (var target in new[] { profile.Target with { Pid = 71 }, profile.Target with { CreationFileTime = 91 }, profile.Target with { ExecutableSha256 = new string('b', 64) } })
            Check(Key(Map(profile with { Target = target }), 0) != Key(map, 0), "process/build scope separates keys");
        var relocated = profile with { Fields = profile.Fields.Select(f => f.Name == "actor_0000_position_candidate" ? f with { Address = f.Address + 64 } : f).ToArray() };
        Check(Key(Map(relocated), 0) != Key(map, 0), "replaced position storage separates object binding");
        var replacement = new Memory(); BinaryPrimitives.WriteUInt32LittleEndian(replacement.Data, 0x80001235);
        Check(Key(Map(Profile(replacement, 0, 1)), 0) != Key(map, 0), "new full handle separates generation");
        foreach (string failed in new[] { "actor_0000_handle_candidate_i32", "actor_0000_position_candidate" })
        {
            var invalid = Values(profile); invalid[failed] = invalid[failed] with { status = "unknown", value = null, reason = "guard_mismatch_before" };
            var result = Map(profile, invalid);
            Check(Key(result, 0) is null && Actor(result, 0).GetProperty("is_self").ValueKind == JsonValueKind.Null && result.GetProperty("self_object_key").ValueKind == JsonValueKind.Null, "unknown cannot retain self/identity:" + failed);
            Check(Key(result, 1) == Key(map, 1) && Actor(result, 1).GetProperty("is_self").ValueKind == JsonValueKind.Null, "known other identity does not invent self exclusion");
        }
        var unobserved = Values(profile); unobserved["self_handle_candidate_i32"] = unobserved["self_handle_candidate_i32"] with { status = "unknown", value = null };
        Check(Map(profile, unobserved).GetProperty("actors").EnumerateArray().All(a => a.GetProperty("is_self").ValueKind == JsonValueKind.Null), "unknown self leaves every association unknown");
        var mismatch = Values(profile); mismatch["actor_0000_handle_candidate_i32"] = mismatch["actor_0000_handle_candidate_i32"] with { value = 999 };
        Check(Key(Map(profile, mismatch), 0) is null, "inconsistent sampled handle rejected");
        var duplicated = new Memory(); duplicated.Data[..4].CopyTo(duplicated.Data, 256);
        var ambiguous = Map(Profile(duplicated, 0, 1));
        Check(ambiguous.GetProperty("actors").EnumerateArray().All(a => a.GetProperty("object_key").ValueKind == JsonValueKind.Null && a.GetProperty("reason").GetString() == "ambiguous_handle"), "duplicate handle cannot identify either object");
        foreach (bool handle in new[] { true, false })
        {
            string name = handle ? "actor_0000_handle_candidate_i32" : "actor_0000_position_candidate";
            var unguarded = profile with { Fields = profile.Fields.Select(f => f.Name == name ? f with { Guards = [] } : f).ToArray() };
            Check(Key(Map(unguarded, values), 0) is null, "identity and position both require handle guard");
            var pointer = profile with { Fields = profile.Fields.Select(f => f.Name == name ? f with { PathId = 0 } : f).ToArray() };
            Check(Key(Map(pointer, values), 0) is null, "pointer path source cannot masquerade as fixed identity");
        }
        var legacy = profile with { Fields = profile.Fields.Where(f => !f.Name.EndsWith("handle_candidate_i32", StringComparison.Ordinal)).ToArray() };
        Check(EntityIdentityProjection.Create(legacy) is null && Project(legacy, values).GetRawText() == "{}", "legacy profiles receive no invented map");
        Check(Project(profile, values).GetRawText() == Project(profile, values, json: true).GetRawText(), "typed live and parsed offline projection parity");
        Check(!map.GetRawText().Contains("private-fixture-path", StringComparison.Ordinal) && !map.GetRawText().Contains("address", StringComparison.Ordinal), "private source addresses and paths are not exported");
        var hero = profile with { Fields = [.. profile.Fields,
            new("actor_0000_hero_0000_resource_low_i32", "i32", 0x1200, 4, 1, null, null, [0]),
            new("actor_0000_hero_0000_resource_high_i32", "i32", 0x1204, 4, 1, null, null, [0])] };
        var heroValues = Values(hero);
        heroValues["actor_0000_hero_0000_resource_low_i32"] = new("i32", "observed", -2, null, 3, 4, [0]);
        heroValues["actor_0000_hero_0000_resource_high_i32"] = new("i32", "observed", unchecked((int)0xabcdef01), null, 5, 6, [0]);
        Check(Actor(Map(hero, heroValues), 0).GetProperty("hero_resource_candidate").GetString() == "0xabcdef01fffffffe", "optional resource preserves both unsigned bit patterns");
        Check(!Actor(Map(hero, heroValues), 1).TryGetProperty("hero_resource_candidate", out _), "missing optional hero does not remove or relabel actor");
        heroValues["actor_0000_hero_0000_resource_high_i32"] = heroValues["actor_0000_hero_0000_resource_high_i32"] with { status = "unknown", value = null };
        Check(Actor(Map(hero, heroValues), 0).GetProperty("hero_resource_candidate").ValueKind == JsonValueKind.Null && Key(Map(hero, heroValues), 0) == Key(map, 0), "partial resource remains unknown while independent object survives");

        // Real recording/verifier/export pipeline, including an observed frame then guard invalidation.
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-identity-test-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            string input = Path.Combine(root, "profile.json"), recording = Path.Combine(root, "recording"), output = Path.Combine(root, "export.jsonl");
            File.WriteAllBytes(input, profile.Raw); using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var liveText = new StringWriter(); var live = new LiveFieldOutput(liveText, "fixture");
            FieldRecording.RecordBounded(memory, input, recording, 10, TimeSpan.FromSeconds(5), stop.Token, new(), acceptedFrame: frame =>
            {
                Check(live.Frame(1, profile, frame), "bounded live frame accepted");
                if (frame.Sequence == 0) memory.Data[0] ^= 1; else stop.Cancel();
            });
            var result = FieldExport.Export(recording, output);
            var frames = File.ReadLines(output).Select(line => JsonSerializer.Deserialize<JsonElement>(line)).Where(e => e.GetProperty("kind").GetString() == "frame").ToArray();
            var liveFrames = liveText.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => JsonSerializer.Deserialize<JsonElement>(line)).ToArray();
            Check(result.frames == 2 && frames.Length == 2 && liveFrames.Length == 2, "recording, live and verified export preserve both frames");
            for (int i = 0; i < frames.Length; i++)
                Check(frames[i].GetProperty("entity_identity").GetRawText() == liveFrames[i].GetProperty("entity_identity").GetRawText(), "live/export identity exact parity:" + i);
            Check(Key(frames[0].GetProperty("entity_identity"), 0) == Key(map, 0) && Key(frames[1].GetProperty("entity_identity"), 0) is null, "pipeline invalidation emits null without carrying prior identity");
            Check(live.Bytes < LiveFieldOutput.MaximumLineBytes && result.output_utf8_bytes < 32 * 1024, "fixture projection remains bounded");
        }
        finally { Directory.Delete(root, recursive: true); }
        return checks;
    }
}
