using System.Buffers.Binary;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Owned fixture layouts only. No target-application constants or private recipes.</summary>
public static class AcquisitionTests
{
    private static object[] E(params object[] values) => values;
    private static object V(string name) => E("var", name);
    private static object Load(string name, int offset, int width) => E("load", V(name), offset, width);
    private static object Slice(string name, int offset, int width) => E("slice", V(name), offset, width);
    private static readonly ulong Magic = BinaryPrimitives.ReadUInt64LittleEndian(PointerFixture.Magic);
    private sealed class Memory : IMemorySource
    {
        internal ulong Base = 65536; internal int Reads; internal Action<Memory, ulong, int>? Before;
        internal byte[] Data = new byte[8192]; internal string? Failure; internal bool Short;
        public TargetIdentity Identity { get; internal set; } = new(17, "fixture.exe", "fixture", 11, new string('a', 64), "x64");
        internal Memory() { Reset(); }
        internal void Reset() { Data.AsSpan().Clear(); U64(0, Magic); U64(8, Base + 4096); U64(4096, Magic); U64(4104, 7); U64(6144, Magic); U64(6152, 42); }
        internal void U64(int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(Data.AsSpan(offset, 8), value);
        public byte[] Read(ulong address, int size)
        {
            Reads++; Before?.Invoke(this, address, size);
            if (Failure is not null) throw new ObservationException(Failure, "Fixture failure.");
            if (address < Base || (ulong)size > (ulong)Data.Length || address - Base > (ulong)(Data.Length - size)) throw new ObservationException("unreadable_range", "Fixture range.");
            return Data.AsSpan((int)(address - Base), Short ? Math.Max(0, size - 1) : size).ToArray();
        }
        public void EnsureAlive() { if (Failure == "process_exited") throw new ObservationException(Failure, "Fixture exited."); }
        public IEnumerable<MemoryRegion> Regions() => [new(Base, (ulong)Data.Length, 0x1000, 4, 0)];
        public void Dispose() { }
    }
    internal static JsonObject Recipe(TargetIdentity identity, ulong? absoluteRoot = null)
    {
        object rootAddress = absoluteRoot.HasValue ? absoluteRoot.Value : E("rva", 0, 16);
        object RootRead() => new { op = "read", name = "root", address = rootAddress, size = 16 };
        object Check(string name) => new { op = "require", test = E("eq", Load(name, 0, 8), Magic) };
        object Capture(string name, int offset, int width) => new { op = "guard", set = "global", value = Slice(name, offset, width) };
        var recipe = new
        {
            schema = "overwatch-decoder.acquisition-recipe/1", target = new { image_name = identity.ImageName, executable_sha256 = identity.ExecutableSha256, architecture = identity.Architecture }, seconds = 30,
            constants = new { }, functions = new { reverse = new { parameters = new[] { "x" }, expression = E("ror", E("ror", V("x"), 19), 45) } },
            stages = new object[]
            {
                new { name = "root", steps = new object[] { RootRead(), Check("root"), Capture("root", 0, 8), Capture("root", 8, 8),
                    new { op = "let", name = "destination", value = E("call", "reverse", Load("root", 8, 8)) } } },
                new { name = "leaf", steps = new object[] { new { op = "check", set = "global" },
                    new { op = "scan", name = "choices", count = 2, index = "slot", keep = new[] { "leaf", "selected_address", "global" }, steps = new object[] {
                        new { op = "filter", test = E("eq", V("slot"), 1) },
                        new { op = "let", name = "selected_address", value = V("destination") },
                        new { op = "read", name = "leaf", address = V("selected_address"), size = 12 }, Check("leaf"), Capture("leaf", 0, 8) } },
                    new { op = "one", rows = "choices" } } }
            }, global_guards = "global", fields = new[] { new { name = "candidate", type = "i32", address = E("add", V("selected_address"), 8), min = 0, max = 100 } }
        };
        return JsonSerializer.SerializeToNode(recipe)!.AsObject();
    }
    public static int Run()
    {
        int count = 0;
        void Check(bool ok, string name) { if (!ok) throw new ObservationException("self_test_failed", "acquisition:" + name); count++; }
        string directory = Path.Combine(Path.GetTempPath(), "overwatch-decoder-acquisition-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        int attempt = 0;
        Acquisition.Result Acquire(Memory memory, JsonObject recipe, Action<string>? stage = null, CancellationToken token = default)
        { return Acquisition.RunBytes(memory, new(memory.Base, (ulong)memory.Data.Length, memory.Identity.ImageName), JsonSerializer.SerializeToUtf8Bytes(recipe), Path.Combine(directory, (++attempt).ToString()), token, stage); }
        string Current() => Path.Combine(directory, attempt.ToString());
        void Reject(string code, Memory memory, JsonObject recipe, Action<string>? stage = null, CancellationToken token = default)
        {
            try { Acquire(memory, recipe, stage, token); throw new ObservationException("self_test_failed", "acquisition:expected:" + code); }
            catch (ObservationException e) { Check(e.Code == code, "reject:" + code + ":" + e.Code); }
            Check(!File.Exists(Path.Combine(Current(), "profile.json")), "rejected attempt has no profile");
        }
        try
        {
            using var memory = new Memory(); JsonObject recipe = Recipe(memory.Identity);
            var result = Acquire(memory, recipe, stage => { if (stage == "final_guard_check") Check(!Directory.Exists(Current()), "result directory unpublished during final validation"); }); Check(result.complete && result.fields == 1 && result.guard_declarations == 3 && result.rows_rejected == 1, "finite unique selection and guards");
            byte[] profile = File.ReadAllBytes(Path.Combine(Current(), "profile.json")); var parsed = FieldStream.ParseProfileBytes(profile);
            Check(parsed.Fields[0].Address == memory.Base + 4104 && parsed.Guards.Length == 3, "derived address and complete guard set");
            Check(JsonNode.DeepEquals(JsonNode.Parse(File.ReadAllBytes(Path.Combine(Current(), "manifest.json"))), JsonSerializer.SerializeToNode(result)), "returned result equals saved manifest");
            using (var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Current(), "manifest.json")))) Check(manifest.RootElement.GetProperty("target").GetProperty("pid").GetInt32() == memory.Identity.Pid && result.evidence_sha256?.Length == 64, "artifact identity and evidence digest");
            string firstDir = Current(); memory.U64(8, memory.Base + 6144); Acquire(memory, recipe);
            Check(FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(Current(), "profile.json"))).Fields[0].Address == memory.Base + 6152, "same recipe follows relocated storage");
            memory.Base += 16384; memory.Identity = memory.Identity with { Pid = 18, CreationFileTime = 12 }; memory.Reset(); Acquire(memory, recipe);
            Check(FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(Current(), "profile.json"))).Target.Pid == 18 && FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(Current(), "profile.json"))).Fields[0].Address == memory.Base + 4104, "same build recipe new identity and relocated module root");
            Check(File.ReadAllBytes(Path.Combine(firstDir, "profile.json")).SequenceEqual(profile), "old profile never rewritten");
            int prior = memory.Reads; var wrong = (JsonObject)recipe.DeepClone(); wrong["target"]!["executable_sha256"] = new string('b', 64); Reject("identity_mismatch", memory, wrong); Check(memory.Reads == prior, "wrong build rejected before reads");
            wrong = (JsonObject)recipe.DeepClone(); wrong["target"]!["architecture"] = "x86"; Reject("invalid_acquisition_recipe", memory, wrong); Check(memory.Reads == prior, "wrong architecture rejected before reads");
            wrong = (JsonObject)recipe.DeepClone(); wrong["unknown"] = true; Reject("invalid_acquisition_recipe", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["functions"]!["reverse"]!["expression"] = new JsonArray("call", "reverse", new JsonArray("var", "x")); Reject("invalid_acquisition_recipe", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["stages"]![1]!["steps"]![1]!["count"] = Acquisition.MaximumEnumeration + 1; Reject("acquisition_enumeration_limit", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["stages"]![1]!["steps"]![1]!["steps"]![0]!["test"] = 1; Reject("acquisition_selection_not_unique", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["stages"]![1]!["steps"]![1]!["steps"]![0]!["test"] = 0; Reject("acquisition_selection_not_unique", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["fields"]![0]!["guards"] = "absent"; Reject("acquisition_missing_guard_set", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["stages"]![0]!["steps"]![0]!["address"] = new JsonArray("rva", 8192, 1); Reject("acquisition_module_bounds", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["stages"]![0]!["steps"]![0]!["size"] = 1048577; Reject("acquisition_read_bounds", memory, wrong);
            wrong = (JsonObject)recipe.DeepClone(); wrong["stages"]![0]!["steps"]![0]!["address"] = new JsonArray("add", ulong.MaxValue, 1UL); Reject("invalid_acquisition_recipe", memory, wrong);
            using (var cancel = new CancellationTokenSource()) { cancel.Cancel(); prior = memory.Reads; Reject("cancelled", memory, recipe, token: cancel.Token); Check(memory.Reads == prior, "pre-cancel no reads"); }
            using (var cancel = new CancellationTokenSource()) { Reject("cancelled", memory, recipe, stage => { if (stage == "leaf") cancel.Cancel(); }, cancel.Token); }
            memory.Short = true; Reject("partial_read", memory, recipe); memory.Short = false;
            memory.Failure = "permission_denied"; Reject("permission_denied", memory, recipe); memory.Failure = null;
            using (var failed = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Current(), "manifest.json")))) Check(!failed.RootElement.GetProperty("complete").GetBoolean() && failed.RootElement.GetProperty("error").GetString() == "permission_denied", "failed attempt published with failure manifest");
            memory.Failure = "process_exited"; Reject("process_exited", memory, recipe); memory.Failure = null;
            Reject("identity_mismatch", memory, recipe, stage => { if (stage == "leaf") memory.Identity = memory.Identity with { CreationFileTime = 14 }; });
            Reject("acquisition_guard_mismatch", memory, recipe, stage => { if (stage == "final_guard_check") memory.U64(8, memory.Base + 6144); }); memory.Reset();
            memory.Before = (m, a, n) => { if (a == m.Base + 4096 && n == 12) m.U64(8, m.Base + 6144); };
            Reject("acquisition_guard_mismatch", memory, recipe); memory.Before = null; memory.Reset();
            string existing = Path.Combine(directory, "existing"); Directory.CreateDirectory(existing);
            try { Acquisition.RunBytes(memory, new(memory.Base, 8192, memory.Identity.ImageName), JsonSerializer.SerializeToUtf8Bytes(recipe), existing, default); Check(false, "existing output accepted"); }
            catch (ObservationException e) { Check(e.Code == "output_exists", "existing directory rejected"); }
            Check(!Directory.EnumerateFileSystemEntries(existing).Any(), "existing directory untouched");
            // A 32-byte logical guard spanning a 4-KiB page remains one unsplit v1 guard.
            var crossing = (JsonObject)recipe.DeepClone(); var steps = crossing["stages"]![1]!["steps"]!.AsArray();
            steps.Add(new JsonObject { ["op"] = "read", ["name"] = "boundary", ["address"] = new JsonArray("rva", 4080, 32), ["size"] = 32 });
            steps.Add(new JsonObject { ["op"] = "guard", ["set"] = "global", ["value"] = new JsonArray("var", "boundary") }); Acquire(memory, crossing);
            Check(FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(Current(), "profile.json"))).Guards.Any(g => g.Address == memory.Base + 4080 && g.Expected.Length == 32), "cross-page guard preserved");
            var timerRecipe = (JsonObject)crossing.DeepClone(); timerRecipe["profile_schema"] = "overwatch-decoder.field-profile/4";
            var timerField = timerRecipe["fields"]![0]!.AsObject(); timerField["type"] = "f32"; timerField["codec"] = TimerCodec.Name;
            timerField["clock_address"] = new JsonArray("add", new JsonArray("var", "selected_address"), 24); timerField["counter_scale_f32_hex"] = "6f12833a";
            TimerTests.State(1000, 12, 1).CopyTo(memory.Data, 4104); memory.U64(4120, 2000); Acquire(memory, timerRecipe);
            var timerProfile = FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(Current(), "profile.json")));
            Check(timerProfile.V4 && timerProfile.Fields[0].Address == memory.Base + 4104 && timerProfile.Fields[0].Timer?.Clock == memory.Base + 4120, "timer addresses resolve through existing expressions");
            Check(timerProfile.Guards.Length == 4 && timerProfile.Guards.Any(g => g.Address == memory.Base + 4080 && g.Expected.Length == 32), "timer profile preserves every cross-page acquisition guard");
            wrong = (JsonObject)timerRecipe.DeepClone(); wrong["profile_schema"] = "overwatch-decoder.field-profile/1"; prior = memory.Reads; Reject("invalid_acquisition_recipe", memory, wrong); Check(memory.Reads == prior, "timer needs explicit schema before reads");
            wrong = (JsonObject)timerRecipe.DeepClone(); wrong["fields"]![0]!["counter_scale_f32_hex"] = "0000807f"; Reject("invalid_acquisition_recipe", memory, wrong);
            memory.Reset();
            JsonObject CollectRecipe(int rows, bool duplicate)
            {
                var r = (JsonObject)recipe.DeepClone();
                r["stages"]!.AsArray().Add(new JsonObject { ["name"] = "collection", ["steps"] = new JsonArray(
                    new JsonObject { ["op"] = "scan", ["name"] = "members", ["count"] = rows, ["index"] = "member", ["keep"] = new JsonArray("global", "member"),
                        ["steps"] = new JsonArray(new JsonObject { ["op"] = "read", ["name"] = "member_header", ["address"] = new JsonArray("rva", duplicate ? JsonValue.Create(256) : new JsonArray("add", 256, new JsonArray("mul", new JsonArray("var", "member"), 8)), 8), ["size"] = 8 },
                            new JsonObject { ["op"] = "guard", ["set"] = "global", ["value"] = new JsonArray("var", "member_header") }) },
                    new JsonObject { ["op"] = "collect_guards", ["rows"] = "members", ["from"] = "global", ["set"] = "global" }) });
                return r;
            }
            var collected = CollectRecipe(3, false); Acquire(memory, collected);
            var collectedProfile = FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(Current(), "profile.json")));
            Check(collectedProfile.Guards.Length == 6 && collectedProfile.Guards.Skip(3).Select(g => g.Address).SequenceEqual(new[] { memory.Base + 256, memory.Base + 264, memory.Base + 272 }), "finite row guards merge in first occurrence order");
            var duplicates = CollectRecipe(3, true); Acquire(memory, duplicates);
            Check(FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(Current(), "profile.json"))).Guards.Length == 4, "exact duplicate guards deduplicated");
            var evidenceRows = File.ReadLines(Path.Combine(Current(), "evidence.jsonl")).Select(line => JsonNode.Parse(line)!.AsObject()).ToArray();
            long firstRead = evidenceRows.First(e => e["kind"]!.GetValue<string>() == "read" && e["address"]!.GetValue<ulong>() == memory.Base + 256)["id"]!.GetValue<long>();
            var provenance = evidenceRows.Single(e => e["kind"]!.GetValue<string>() == "guard_collection");
            Check(provenance["guards"]!.AsArray().Single(g => g!["address"]!.GetValue<ulong>() == memory.Base + 256)!["source_read_id"]!.GetValue<long>() == firstRead, "first original source read preserved through dedup");
            int duplicateReads = 0; memory.Before = (m, a, _) => { if (a == m.Base + 256 && ++duplicateReads == 2) m.Data[256] = 1; };
            Reject("acquisition_guard_conflict", memory, duplicates); memory.Before = null; memory.Reset();
            wrong = CollectRecipe(1, false); wrong["stages"]![2]!["steps"]![1]!["from"] = "absent"; Reject("acquisition_missing_guard_set", memory, wrong);
            wrong = CollectRecipe(1, false); wrong["stages"]![2]!["steps"]![1]!["from"] = "member"; Reject("acquisition_invalid_guard_set", memory, wrong);
            wrong = CollectRecipe(1, false); wrong["stages"]![2]!["steps"]![1]!["rows"] = "absent"; Reject("acquisition_missing_rows", memory, wrong);
            Reject("acquisition_guard_bounds", memory, CollectRecipe(254, false));
            // Fail rather than shrink the emitted guard coverage or read plan.
            var oversized = (JsonObject)recipe.DeepClone(); oversized["fields"]!.AsArray().Clear(); for (int i = 0; i < FieldStream.MaximumFields + 1; i++) oversized["fields"]!.AsArray().Add(new JsonObject { ["name"] = "f" + i, ["type"] = "u8", ["address"] = 65536 });
            prior = memory.Reads; Reject("invalid_acquisition_recipe", memory, oversized); Check(memory.Reads == prior, "field cap before reads");
            foreach (var limit in new[] { new Acquisition.Limits(ReadBytes: 16), new Acquisition.Limits(ReadCalls: 1) })
            {
                string path = Path.Combine(directory, "budget-" + Guid.NewGuid().ToString("N")); prior = memory.Reads;
                try { Acquisition.RunBounded(memory, new(memory.Base, 8192, memory.Identity.ImageName), JsonSerializer.SerializeToUtf8Bytes(recipe), path, default, null, limit); Check(false, "read budget accepted"); }
                catch (ObservationException e) { Check(e.Code == "acquisition_read_limit", "explicit read budget"); }
                Check(memory.Reads == prior + 1 && !File.Exists(Path.Combine(path, "profile.json")), "read budget stops before extra source call");
            }
            var largeRead = (JsonObject)recipe.DeepClone(); largeRead["stages"]![0]!["steps"]![0]!["size"] = 1048576;
            prior = memory.Reads; string budgetPath = Path.Combine(directory, "output-budget");
            try { Acquisition.RunBounded(memory, new(memory.Base, 8192, memory.Identity.ImageName), JsonSerializer.SerializeToUtf8Bytes(largeRead), budgetPath, default, null, new Acquisition.Limits(EvidenceBytes: 131072)); Check(false, "output budget accepted"); }
            catch (ObservationException e) { Check(e.Code == "acquisition_output_limit", "explicit output budget"); }
            Check(memory.Reads == prior && !File.Exists(Path.Combine(budgetPath, "profile.json")), "trace budget reserved before source read");
            using (var cancel = new CancellationTokenSource())
            {
                memory.Before = (_, _, _) => cancel.Cancel(); Reject("cancelled", memory, recipe, token: cancel.Token); memory.Before = null;
                using var line = JsonDocument.Parse(File.ReadLines(Path.Combine(Current(), "evidence.jsonl")).First(x => x.Contains("\"kind\":\"read\"")));
                Check(line.RootElement.GetProperty("returned_bytes").GetInt32() == 16, "read cancellation retains returned count");
            }
            foreach (string path in Directory.GetFiles(directory, "evidence.jsonl", SearchOption.AllDirectories))
                foreach (string line in File.ReadLines(path)) { using var doc = JsonDocument.Parse(line); var e = doc.RootElement; if (e.GetProperty("kind").GetString() == "read") Check(e.GetProperty("attempted").GetBoolean() && e.GetProperty("read_start_ticks").GetInt64() <= e.GetProperty("read_end_ticks").GetInt64(), "read evidence true bracket"); }
            return count;
        }
        finally { Directory.Delete(directory, true); }
    }
}
