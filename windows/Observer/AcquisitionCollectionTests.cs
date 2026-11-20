using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Retained-row field output against synthetic movable records only.</summary>
public static class AcquisitionCollectionTests
{
    private static object[] E(params object[] values) => values;
    private static object V(string name) => E("var", name);
    private sealed class Memory : IMemorySource
    {
        internal ulong Base = 65536;
        internal byte[] Data = new byte[4096];
        internal int Reads;
        public TargetIdentity Identity { get; } = new(17, "fixture.exe", "fixture", 11, new string('a', 64), "x64");
        internal Memory() { Reset(); }
        internal void Reset(bool reversed = false)
        {
            Data.AsSpan().Clear(); Put(0, 123); Put(32, Base + (reversed ? 256UL : 128UL));
            Put(40, Base + (reversed ? 128UL : 256UL)); Put(128, 111); Put(136, 7); Put(256, 222); Put(264, 42);
        }
        internal void Put(int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(Data.AsSpan(offset, 8), value);
        public byte[] Read(ulong address, int size)
        {
            Reads++;
            if (address < Base || address - Base > (ulong)(Data.Length - size)) throw new ObservationException("unreadable_range", "Fixture range.");
            return Data.AsSpan((int)(address - Base), size).ToArray();
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static JsonObject Recipe(Memory memory)
    {
        var r = new
        {
            schema = "overwatch-decoder.acquisition-recipe/1",
            target = new { image_name = memory.Identity.ImageName, executable_sha256 = memory.Identity.ExecutableSha256, architecture = "x64" },
            seconds = 30, constants = new { selected = 1 }, functions = new { },
            stages = new[] { new { name = "inventory", steps = new object[] {
                new { op = "read", name = "root", address = E("rva", 0, 8), size = 8 },
                new { op = "guard", set = "global", value = V("root") },
                new { op = "scan", name = "entities", count = 2, index = "index", keep = new[] { "selected", "entity_guards" }, steps = new object[] {
                    new { op = "read", name = "entry", address = E("rva", E("add", 32, E("mul", V("index"), 8)), 8), size = 8 },
                    new { op = "guard", set = "entity_guards", value = V("entry") },
                    new { op = "let", name = "selected", value = E("load", V("entry"), 0, 8) },
                    new { op = "read", name = "header", address = V("selected"), size = 8 },
                    new { op = "guard", set = "entity_guards", value = V("header") }
                } }
            } } },
            global_guards = "global", fields = Array.Empty<object>(),
            field_collections = new[] { new { rows = "entities", prefix = "entity", fields = new[] {
                new { name = "value", type = "i32", address = E("add", V("selected"), 8), guards = "entity_guards", min = 0, max = 100 }
            } } }
        };
        return JsonSerializer.SerializeToNode(r)!.AsObject();
    }
    public static int Run()
    {
        int assertions = 0, attempt = 0;
        void Check(bool ok, string label)
        { if (!ok) throw new ObservationException("self_test_failed", "acquisition-collection:" + label); assertions++; }
        string directory = Path.Combine(Path.GetTempPath(), "overwatch-decoder-acquisition-collections-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string Current() => Path.Combine(directory, attempt.ToString());
        Acquisition.Result Acquire(Memory memory, JsonObject recipe, Action<string>? stage = null,
            CancellationToken token = default, Acquisition.Limits? limits = null)
        {
            return Acquisition.RunBounded(memory, new(memory.Base, (ulong)memory.Data.Length, memory.Identity.ImageName),
                JsonSerializer.SerializeToUtf8Bytes(recipe), Path.Combine(directory, (++attempt).ToString()), token, stage, limits ?? new());
        }
        void Reject(Memory memory, JsonObject recipe, string code, Action<string>? stage = null,
            CancellationToken token = default, Acquisition.Limits? limits = null)
        {
            try { Acquire(memory, recipe, stage, token, limits); throw new Exception("Expected rejection: " + code); }
            catch (ObservationException e) { Check(e.Code == code, "rejection " + code + " actual " + e.Code); }
            Check(!File.Exists(Path.Combine(Current(), "profile.json")), "failure publishes no profile");
        }
        JsonObject Clone(JsonObject recipe) => (JsonObject)recipe.DeepClone();
        JsonNode Scan(JsonObject recipe) => recipe["stages"]![0]!["steps"]![2]!;
        JsonNode Collection(JsonObject recipe) => recipe["field_collections"]![0]!;
        try
        {
            var memory = new Memory(); var recipe = Recipe(memory);
            var result = Acquire(memory, recipe);
            Check(result.complete && result.fields == 2 && result.guard_declarations == 5, "two collection fields admitted");
            using var profile = JsonDocument.Parse(File.ReadAllText(Path.Combine(Current(), "profile.json")));
            var fields = profile.RootElement.GetProperty("fields");
            Check(fields[0].GetProperty("name").GetString() == "entity_0000_value" && fields[1].GetProperty("name").GetString() == "entity_0001_value", "deterministic ordinal names");
            Check(fields[0].GetProperty("address").GetUInt64() == memory.Base + 136 && fields[1].GetProperty("address").GetUInt64() == memory.Base + 264, "row overlays root variable");
            Check(fields[0].GetProperty("guards").GetArrayLength() == 2 && fields[1].GetProperty("guards").GetArrayLength() == 2, "each row guards retained");
            string firstProfile = Path.Combine(Current(), "profile.json");
            using (var cancel = new CancellationTokenSource())
            using (var output = new StringWriter())
            {
                memory.Put(256, 333);
                FieldStream.RunBounded(memory, firstProfile, 10, TimeSpan.FromSeconds(1), output, cancel.Token, new(), _ => cancel.Cancel());
                var frame = JsonSerializer.Deserialize<JsonElement>(output.ToString().Split('\n')[0]).GetProperty("fields");
                Check(frame.GetProperty("entity_0000_value").GetProperty("value").GetInt32() == 7, "first identity remains observed");
                Check(frame.GetProperty("entity_0001_value").GetProperty("status").GetString() == "unknown", "second identity guard rejects reuse");
            }
            memory.Base += 8192; memory.Reset(true); result = Acquire(memory, recipe);
            using (var relocated = JsonDocument.Parse(File.ReadAllText(Path.Combine(Current(), "profile.json"))))
            {
                var f = relocated.RootElement.GetProperty("fields");
                Check(f[0].GetProperty("address").GetUInt64() == memory.Base + 264 && f[1].GetProperty("address").GetUInt64() == memory.Base + 136, "relocation and reorder reacquired");
                Check(f[0].GetProperty("name").GetString() == "entity_0000_value", "ordinal does not imply durable identity");
            }
            // Existing ordinary fields retain names and coexist before expanded fields.
            var mixed = Clone(recipe); mixed["fields"]!.AsArray().Add(new JsonObject { ["name"] = "root_value", ["type"] = "i32", ["address"] = new JsonArray("rva", 0, 4) });
            Check(Acquire(memory, mixed).fields == 3, "ordinary fields coexist");
            var wrong = Clone(recipe); Collection(wrong)["rows"] = "missing"; Reject(memory, wrong, "acquisition_missing_rows");
            wrong = Clone(recipe); Collection(wrong)["rows"] = "selected"; Reject(memory, wrong, "acquisition_missing_rows");
            wrong = Clone(recipe); Scan(wrong)["count"] = 0; Reject(memory, wrong, "acquisition_empty_field_collection");
            wrong = Clone(recipe); Scan(wrong)["count"] = FieldStream.MaximumFields + 1; Scan(wrong)["steps"]![0]!["address"] = new JsonArray("rva", 32, 8); Reject(memory, wrong, "acquisition_field_limit");
            wrong = Clone(recipe); Collection(wrong)["fields"]![0]!["guards"] = "missing"; Reject(memory, wrong, "acquisition_missing_guard_set");
            wrong = Clone(recipe); Collection(wrong)["prefix"] = new string('a', 64); Reject(memory, wrong, "acquisition_field_name_limit");
            wrong = Clone(mixed); wrong["fields"]![0]!["name"] = "entity_0000_value"; Reject(memory, wrong, "acquisition_duplicate_field_name");
            wrong = Clone(recipe); wrong["field_collections"]!.AsArray().Add(Collection(wrong).DeepClone()); Reject(memory, wrong, "acquisition_duplicate_field_name");
            wrong = Clone(recipe); Collection(wrong)["fields"] = new JsonArray(); Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); Collection(wrong)["unexpected"] = true; Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); wrong["field_collections"] = new JsonArray(); Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); wrong.Remove("field_collections"); Reject(memory, wrong, "invalid_acquisition_recipe");
            wrong = Clone(recipe); var templates = Collection(wrong)["fields"]!.AsArray(); var template = templates[0]!.DeepClone(); templates.Clear();
            for (int i = 0; i < 64; i++) { var t = template.DeepClone(); t["name"] = "v" + i; templates.Add(t); }
            var atLimit = Clone(wrong);
            foreach (var field in Collection(atLimit)["fields"]!.AsArray()) field!.AsObject().Remove("guards");
            Check(Acquire(memory, atLimit).fields == 128, "128 expanded fields admitted with global guards");
            Reject(memory, wrong, "field_profile_limit"); // 128 fields, 257 guard declarations: no dropping duplicates to fit.
            wrong = Clone(recipe); wrong["global_guards"] = "wide_global";
            Collection(wrong)["fields"]![0]!.AsObject().Remove("guards");
            wrong["stages"]!.AsArray().Add(JsonSerializer.SerializeToNode(new { name = "wide_guards", steps = new object[] {
                new { op = "scan", name = "wide_rows", count = 256, index = "wide_index", keep = new[] { "wide_guard" }, steps = new object[] {
                    new { op = "read", name = "wide", address = E("rva", E("add", 512, E("mul", V("wide_index"), 8)), 64), size = 64 },
                    new { op = "guard", set = "wide_guard", value = V("wide") } } },
                new { op = "collect_guards", rows = "wide_rows", from = "wide_guard", set = "wide_global" }
            } }));
            Reject(memory, wrong, "field_profile_limit"); // 256 distinct 64-byte guards plus fields exceed physical frame bytes.
            using (var cancel = new CancellationTokenSource())
                Reject(memory, recipe, "cancelled", name => { if (name == "field_collection_output") cancel.Cancel(); }, cancel.Token);
            Reject(memory, recipe, "acquisition_guard_mismatch", name => { if (name == "final_guard_check") memory.Put(128, 999); });
            memory.Reset(); Reject(memory, recipe, "acquisition_read_limit", limits: new(ReadCalls: 5));
        }
        finally { Directory.Delete(directory, true); }
        return assertions;
    }
}
