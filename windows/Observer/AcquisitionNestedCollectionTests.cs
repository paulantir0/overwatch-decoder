using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Nested retained scopes over synthetic actors and occupied pool slots only.</summary>
public static class AcquisitionNestedCollectionTests
{
    private static object[] E(params object[] values) => values;
    private static object V(string name) => E("var", name);
    private sealed class Memory : IMemorySource
    {
        internal const ulong Base = 65536;
        internal readonly byte[] Data = new byte[32768];
        internal int Reads; internal Action? Alive;
        private ulong epoch;
        public TargetIdentity Identity { get; } = new(64, "fixture.exe", "fixture", 14, new string('b', 64), "x64");
        internal void Put(int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(Data.AsSpan(offset, 8), value);
        internal Memory() { Reset([0, 1], [0, 1], [2]); }
        internal void Reset(int[] actors, int[] aPools, int[] bPools)
        {
            Data.AsSpan().Clear(); Put(0, ++epoch); Put(8, (ulong)actors.Length);
            for (int i = 0; i < actors.Length; i++) Put(32 + i * 8, Base + (ulong)(256 + actors[i] * 512));
            int[][] pools = [aPools, bPools];
            for (int actor = 0; actor < 2; actor++)
            {
                int address = 256 + actor * 512; Put(address, (ulong)((actor + 1) * 100)); Put(address + 8, (ulong)pools[actor].Length);
                for (int i = 0; i < pools[actor].Length; i++) Put(address + 32 + i * 8, Base + (ulong)(2048 + pools[actor][i] * 64));
            }
            int[] values = [11, 12, 21, 22, 13];
            for (int pool = 0; pool < values.Length; pool++) { Put(2048 + pool * 64, (ulong)(1000 + pool)); Put(2056 + pool * 64, (ulong)values[pool]); }
        }
        public byte[] Read(ulong address, int size)
        {
            Reads++;
            if (address < Base || address - Base > (ulong)(Data.Length - size)) throw new ObservationException("unreadable_range", "Fixture range.");
            return Data.AsSpan((int)(address - Base), size).ToArray();
        }
        public void EnsureAlive() => Alive?.Invoke();
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static JsonObject Recipe(Memory memory) => JsonSerializer.SerializeToNode(new
    {
        schema = "overwatch-decoder.acquisition-recipe/1",
        target = new { image_name = memory.Identity.ImageName, executable_sha256 = memory.Identity.ExecutableSha256, architecture = "x64" },
        seconds = 30, constants = new { pool = 0, value_offset = 0 }, functions = new { }, global_guards = "global",
        stages = new[] { new { name = "inventory", steps = new object[] {
            new { op = "read", name = "root", address = E("rva", 0, 16), size = 16 },
            new { op = "guard", set = "global", value = V("root") },
            new { op = "scan", name = "actors", count = E("load", V("root"), 8, 8), index = "ai", keep = new[] { "actor", "ag", "pools", "value_offset" }, steps = new object[] {
                new { op = "read", name = "entry", address = E("rva", E("add", 32, E("mul", V("ai"), 8)), 8), size = 8 },
                new { op = "guard", set = "ag", value = V("entry") },
                new { op = "let", name = "actor", value = E("load", V("entry"), 0, 8) },
                new { op = "read", name = "header", address = V("actor"), size = 16 },
                new { op = "guard", set = "ag", value = V("header") },
                new { op = "let", name = "value_offset", value = 8 },
                new { op = "scan", name = "pools", count = E("load", V("header"), 8, 8), index = "pi", keep = new[] { "pool", "pg" }, steps = new object[] {
                    new { op = "let", name = "pg", value = V("ag") },
                    new { op = "read", name = "pool_entry", address = E("add", V("actor"), E("add", 32, E("mul", V("pi"), 8))), size = 8 },
                    new { op = "guard", set = "pg", value = V("pool_entry") },
                    new { op = "let", name = "pool", value = E("load", V("pool_entry"), 0, 8) },
                    new { op = "read", name = "pool_header", address = V("pool"), size = 8 },
                    new { op = "guard", set = "pg", value = V("pool_header") }
                } }
            } }
        } } },
        fields = new[] { new { name = "ordinary", type = "i32", address = E("rva", 0, 4) } },
        field_collections = new[] { new { rows = "actors", prefix = "actor", fields = new[] {
            new { name = "identity", type = "i32", address = V("actor"), guards = "ag" }
        }, field_collections = new[] { new { rows = "pools", prefix = "pool", fields = new[] {
            new { name = "value", type = "i32", address = E("add", V("pool"), V("value_offset")), guards = "pg" }
        } } } } }
    })!.AsObject();
    public static int Run()
    {
        int assertions = 0, number = 0;
        void Check(bool ok, string label)
        { if (!ok) throw new ObservationException("self_test_failed", "acquisition-nested-collection:" + label); assertions++; }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-nested-collections-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string output = "";
        Acquisition.Result Acquire(Memory memory, JsonObject recipe, Action<string>? stage = null, CancellationToken token = default, Acquisition.Limits? limits = null)
        {
            output = Path.Combine(root, (++number).ToString());
            return Acquisition.RunBounded(memory, new(Memory.Base, (ulong)memory.Data.Length, memory.Identity.ImageName),
                JsonSerializer.SerializeToUtf8Bytes(recipe), output, token, stage, limits ?? new());
        }
        void Reject(Memory memory, JsonObject recipe, string code, Action<string>? stage = null, CancellationToken token = default, Acquisition.Limits? limits = null)
        {
            try { Acquire(memory, recipe, stage, token, limits); Check(false, "accepted invalid recipe:" + code); }
            catch (ObservationException e) { Check(e.Code == code, "rejection:" + code + ":actual:" + e.Code); }
            Check(!File.Exists(Path.Combine(output, "profile.json")), "rejection publishes no profile:" + code);
        }
        JsonObject Clone(JsonObject recipe) => (JsonObject)recipe.DeepClone();
        JsonNode Outer(JsonObject recipe) => recipe["field_collections"]![0]!;
        JsonNode Inner(JsonObject recipe) => Outer(recipe)["field_collections"]![0]!;
        JsonObject Profile() => JsonNode.Parse(File.ReadAllBytes(Path.Combine(output, "profile.json")))!.AsObject();
        JsonElement Frame(Memory memory, string profilePath)
        {
            using var cancel = new CancellationTokenSource(); using var writer = new StringWriter();
            FieldStream.RunBounded(memory, profilePath, 10, TimeSpan.FromSeconds(10), writer, cancel.Token, new(), _ => cancel.Cancel());
            return JsonSerializer.Deserialize<JsonElement>(writer.ToString().Split('\n')[0]).GetProperty("fields");
        }
        try
        {
            var memory = new Memory(); var recipe = Recipe(memory); var result = Acquire(memory, recipe); var profile = Profile();
            Check(result.complete && result.fields == 6 && result.guard_declarations == 17, "ordinary and nested direct/child fields with exact guard declarations");
            Check(profile["fields"]!.AsArray().Select(f => f!["name"]!.GetValue<string>()).SequenceEqual(new[] {
                "ordinary", "actor_0000_identity", "actor_0000_pool_0000_value", "actor_0000_pool_0001_value", "actor_0001_identity", "actor_0001_pool_0000_value" }), "deterministic ordinary/direct/depth-first child order");
            string firstProfile = Path.Combine(output, "profile.json");
            Check(Frame(memory, firstProfile).EnumerateObject().Skip(1).Select(f => f.Value.GetProperty("value").GetInt32()).SequenceEqual([100, 11, 12, 200, 21]), "root plus parent plus child scope resolves exact associations");
            memory.Put(2048, 9000); var invalidated = Frame(memory, firstProfile);
            Check(invalidated.GetProperty("actor_0000_pool_0000_value").GetProperty("status").GetString() == "unknown" &&
                invalidated.GetProperty("actor_0000_pool_0000_value").GetProperty("value").ValueKind == JsonValueKind.Null &&
                invalidated.GetProperty("actor_0000_pool_0001_value").GetProperty("value").GetInt32() == 12 &&
                invalidated.GetProperty("actor_0001_pool_0000_value").GetProperty("value").GetInt32() == 21, "pool guard reuse rejects only dependent values without stale association");
            memory.Reset([1, 0], [1], [2, 3]); result = Acquire(memory, recipe); profile = Profile();
            Check(result.fields == 6 && Frame(memory, Path.Combine(output, "profile.json")).EnumerateObject().Skip(1).Select(f => f.Value.GetProperty("value").GetInt32())
                .SequenceEqual([200, 21, 22, 100, 12]), "actor reorder and variable pool add/remove reacquire exact new values");
            Check(Frame(memory, firstProfile).EnumerateObject().All(f => f.Value.GetProperty("status").GetString() == "unknown" && f.Value.GetProperty("value").ValueKind == JsonValueKind.Null), "old epoch does not carry values into new actor/pool layout");
            memory.Reset([0, 1], [4, 1, 0], [3]); result = Acquire(memory, recipe);
            string currentProfile = Path.Combine(output, "profile.json");
            Check(result.fields == 7 && Frame(memory, currentProfile).EnumerateObject().Skip(1).Select(f => f.Value.GetProperty("value").GetInt32()).SequenceEqual([100, 13, 12, 11, 200, 22]), "occupied pool reorder with changing count changes schema without padding");
            using (var cancel = new CancellationTokenSource())
            {
                string recording = Path.Combine(root, "recording");
                FieldRecording.RecordBounded(memory, currentProfile, recording, 10, TimeSpan.FromSeconds(10), cancel.Token, new(), _ => cancel.Cancel());
                Check(FieldRecordingVerification.Verify(recording).valid, "nested output retains strict recording verification");
            }
            var traces = File.ReadLines(Path.Combine(output, "evidence.jsonl")).Select(line => JsonSerializer.Deserialize<JsonElement>(line))
                .Where(row => row.GetProperty("kind").GetString() == "field_collection").ToArray();
            Check(traces.Length == 3 && traces[0].GetProperty("prefix").GetString() == "actor_0000_pool" && traces[0].GetProperty("depth").GetInt32() == 2 &&
                traces[^1].GetProperty("expanded_fields").GetInt32() == 6 && traces.All(t => t.GetProperty("identity").GetString() == "ordinal_within_acquisition_only"), "nested trace binds parent ordinal and aggregate expanded range");

            memory.Reset([0, 1], [0, 1], [2]);
            var noDirect = Clone(recipe); Outer(noDirect)["fields"] = new JsonArray();
            Check(Acquire(memory, noDirect).fields == 4, "collection direct fields may be empty with nonempty children");
            var flat = Clone(recipe); Outer(flat).AsObject().Remove("field_collections");
            Check(Acquire(memory, flat).fields == 3 && Profile()["fields"]!.AsArray().Select(f => f!["name"]!.GetValue<string>())
                .SequenceEqual(["ordinary", "actor_0000_identity", "actor_0001_identity"]), "legacy flat collection keeps its original field names and order");
            var wrong = Clone(noDirect); Outer(wrong).AsObject().Remove("field_collections"); Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); Inner(wrong)["unexpected"] = true; Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); Inner(wrong)["field_collections"] = new JsonArray(); Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); Inner(wrong).AsObject().Remove("fields"); Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); Inner(wrong)["fields"] = new JsonArray(); Reject(memory, wrong, "invalid_acquisition_recipe");
            byte[] duplicateKeys = System.Text.Encoding.UTF8.GetBytes(recipe.ToJsonString().Replace("\"prefix\":\"pool\"", "\"prefix\":\"pool\",\"prefix\":\"pool\"", StringComparison.Ordinal));
            int beforeDuplicate = memory.Reads; string duplicateOutput = Path.Combine(root, (++number).ToString());
            try
            {
                Acquisition.RunBytes(memory, new(Memory.Base, (ulong)memory.Data.Length, memory.Identity.ImageName), duplicateKeys, duplicateOutput, default);
                Check(false, "duplicate nested collection key accepted");
            }
            catch (ObservationException e) { Check(e.Code == "invalid_acquisition_recipe" && memory.Reads == beforeDuplicate, "duplicate nested keys rejected before source reads"); }
            wrong = Clone(recipe); Inner(wrong)["rows"] = "missing"; Reject(memory, wrong, "acquisition_missing_rows");
            wrong = Clone(recipe); Inner(wrong)["rows"] = "actor"; Reject(memory, wrong, "acquisition_missing_rows");
            memory.Reset([0, 1], [0], []); Reject(memory, recipe, "acquisition_empty_field_collection"); memory.Reset([0, 1], [0, 1], [2]);
            var optionalPools = Clone(recipe); Inner(optionalPools)["allow_empty"] = true;
            memory.Reset([0, 1], [0], []);
            Check(Acquire(memory, optionalPools).fields == 4 && Profile()["fields"]!.AsArray().Select(f => f!["name"]!.GetValue<string>())
                .SequenceEqual(["ordinary", "actor_0000_identity", "actor_0000_pool_0000_value", "actor_0001_identity"]),
                "optional empty pools preserve both actors and the occupied sibling pool without padding");
            memory.Reset([0, 1], [], []);
            Check(Acquire(memory, optionalPools).fields == 3, "all optional pools may be empty while actor fields remain");
            var optionalTraces = File.ReadLines(Path.Combine(output, "evidence.jsonl")).Select(line => JsonSerializer.Deserialize<JsonElement>(line))
                .Where(row => row.GetProperty("kind").GetString() == "field_collection" && row.GetProperty("depth").GetInt32() == 2).ToArray();
            Check(optionalTraces.Length == 2 && optionalTraces.All(t => t.GetProperty("allow_empty").GetBoolean() &&
                t.GetProperty("retained_rows").GetInt32() == 0 && t.GetProperty("expanded_fields").GetInt32() == 0),
                "empty optional collections retain explicit evidence");
            string emptyPoolsProfile = Path.Combine(output, "profile.json");
            memory.Put(256, 9999);
            Check(Frame(memory, emptyPoolsProfile).GetProperty("actor_0000_identity").GetProperty("status").GetString() == "unknown",
                "optional pools do not weaken parent identity guards");
            memory.Reset([0, 1], [], []);
            wrong = Clone(optionalPools); Inner(wrong)["allow_empty"] = false; Reject(memory, wrong, "acquisition_empty_field_collection");
            wrong = Clone(optionalPools); Inner(wrong)["rows"] = "missing"; Reject(memory, wrong, "acquisition_missing_rows");
            foreach (JsonNode? invalid in new JsonNode?[] { JsonValue.Create("true"), JsonValue.Create(1), null })
            {
                wrong = Clone(optionalPools); Inner(wrong)["allow_empty"] = invalid;
                int readsBefore = memory.Reads; Reject(memory, wrong, "invalid_acquisition_recipe");
                Check(memory.Reads == readsBefore, "invalid optional flag rejected before source reads");
            }
            memory.Reset([], [], []); Reject(memory, optionalPools, "acquisition_empty_field_collection");
            var optionalActors = Clone(optionalPools); Outer(optionalActors)["allow_empty"] = true;
            Check(Acquire(memory, optionalActors).fields == 1, "optional top-level collection keeps ordinary sibling fields");
            wrong = Clone(optionalActors); wrong["fields"] = new JsonArray(); Reject(memory, wrong, "invalid_field_profile");
            Reject(memory, optionalActors, "acquisition_guard_mismatch", stage => { if (stage == "final_guard_check") memory.Put(0, 9999); });
            memory.Reset([0, 1], [0, 1], [2]);
            wrong = Clone(recipe); Inner(wrong)["fields"]![0]!["guards"] = "missing"; Reject(memory, wrong, "acquisition_missing_guard_set");
            wrong = Clone(recipe); Inner(wrong)["prefix"] = new string('p', 64); Reject(memory, wrong, "acquisition_field_name_limit");
            wrong = Clone(recipe); Outer(wrong)["field_collections"]!.AsArray().Add(Inner(wrong).DeepClone()); Reject(memory, wrong, "acquisition_duplicate_field_name");
            wrong = Clone(recipe); Outer(wrong)["fields"]!.AsArray().Add(new JsonObject {
                ["name"] = "pool_0000_value", ["type"] = "i32", ["address"] = new JsonArray("var", "actor") });
            Reject(memory, wrong, "acquisition_duplicate_field_name");
            wrong = Clone(recipe); wrong["fields"]!.AsArray().Add(new JsonObject { ["name"] = "actor_0000_pool_0000_value", ["type"] = "i32", ["address"] = 1 });
            Reject(memory, wrong, "acquisition_duplicate_field_name");
            JsonObject Wrap(JsonNode node) => new() { ["rows"] = "actors", ["prefix"] = "a", ["fields"] = new JsonArray(), ["field_collections"] = new JsonArray(node) };
            var deep = Clone(noDirect); deep["field_collections"] = new JsonArray(Wrap(Wrap(Outer(deep).DeepClone())));
            Check(Acquire(memory, deep).fields == 13, "four collection levels are admitted");
            wrong = Clone(deep); wrong["field_collections"] = new JsonArray(Wrap(Outer(wrong).DeepClone())); int before = memory.Reads;
            Reject(memory, wrong, "acquisition_field_collection_depth"); Check(memory.Reads == before, "excess depth rejected before source reads");
            wrong = Clone(noDirect); var templates = Inner(wrong)["fields"]!.AsArray(); var template = templates[0]!.DeepClone(); templates.Clear();
            for (int i = 0; i < 54; i++) { var field = template.DeepClone(); field["name"] = "v" + i; templates.Add(field); }
            Reject(memory, wrong, "acquisition_field_limit");
            memory.Reset([0, 1], [0], [2]); var exact = Clone(noDirect); exact["fields"] = new JsonArray(); templates = Inner(exact)["fields"]!.AsArray(); template = templates[0]!.DeepClone(); templates.Clear();
            for (int i = 0; i < 64; i++) { var field = template.DeepClone(); field["name"] = "v" + i; field.AsObject().Remove("guards"); templates.Add(field); }
            Check(Acquire(memory, exact).fields == 128, "128 nested fields admitted without pruning");
            wrong = Clone(exact); foreach (var field in Inner(wrong)["fields"]!.AsArray()) field!["guards"] = "pg";
            Reject(memory, wrong, "field_profile_limit");
            wrong["profile_schema"] = "overwatch-decoder.field-profile/4";
            var timer = Inner(wrong)["fields"]![0]!; timer["type"] = "f32"; timer["codec"] = TimerCodec.Name;
            timer["clock_address"] = new JsonArray("rva", 16, 8); timer["counter_scale_f32_hex"] = "0000803f";
            Check(Acquire(memory, wrong).guard_declarations == 513, "v4 declaration accounting unchanged for nested repeated guards");
            wrong = Clone(recipe); wrong["global_guards"] = "wide_global";
            foreach (var field in Outer(wrong)["fields"]!.AsArray()) field!.AsObject().Remove("guards");
            foreach (var field in Inner(wrong)["fields"]!.AsArray()) field!.AsObject().Remove("guards");
            wrong["stages"]!.AsArray().Add(JsonSerializer.SerializeToNode(new { name = "wide", steps = new object[] {
                new { op = "scan", name = "wide_rows", count = 256, index = "wide_i", keep = new[] { "wide_g" }, steps = new object[] {
                    new { op = "read", name = "wide", address = E("rva", E("add", 4096, E("mul", V("wide_i"), 64)), 64), size = 64 },
                    new { op = "guard", set = "wide_g", value = V("wide") } } },
                new { op = "collect_guards", rows = "wide_rows", from = "wide_g", set = "wide_global" }
            } }));
            Reject(memory, wrong, "field_profile_limit");
            memory.Reset([0, 1], [0, 1], [2]);
            Reject(memory, recipe, "acquisition_guard_mismatch", stage => { if (stage == "final_guard_check") memory.Put(2048, 9999); });
            memory.Reset([0, 1], [0, 1], [2]);
            using (var cancel = new CancellationTokenSource())
            {
                int checks = 0;
                Reject(memory, recipe, "cancelled", stage => { if (stage == "field_collection_output") memory.Alive = () => { if (++checks == 6) cancel.Cancel(); }; }, cancel.Token);
                Check(checks == 6, "cancellation checked within recursive expansion"); memory.Alive = null;
            }
            // Spend exactly 1,999,994 instructions in recipe steps. The ordinary field,
            // outer node/row/field and child node/row use the six remaining slots.
            // The first nested field must fail before adding it or performing guard reads.
            var instructionBound = Clone(recipe); var burnSteps = new JsonArray();
            for (int i = 0; i < 512; i++) burnSteps.Add(new JsonObject { ["op"] = "let", ["name"] = "burn", ["value"] = 0 });
            var budgetSteps = new JsonArray(new JsonObject { ["op"] = "scan", ["name"] = "burn_rows", ["count"] = 3906,
                ["index"] = "burn_i", ["keep"] = new JsonArray("burn"), ["steps"] = burnSteps });
            for (int i = 0; i < 86; i++) budgetSteps.Add(new JsonObject { ["op"] = "let", ["name"] = "burn", ["value"] = 0 });
            instructionBound["stages"]!.AsArray().Add(new JsonObject { ["name"] = "instruction_boundary", ["steps"] = budgetSteps });
            int readsBeforeBound = memory.Reads;
            Reject(memory, instructionBound, "acquisition_instruction_limit");
            using (var failure = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(output, "manifest.json"))))
                Check(failure.RootElement.GetProperty("fields").GetInt32() == 2 && memory.Reads - readsBeforeBound == 11,
                    "nested nodes and rows charge shared instruction budget without new reads");
            Reject(memory, recipe, "acquisition_read_limit", limits: new(ReadCalls: 5));
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
