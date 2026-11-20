using System.Buffers.Binary;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

// Wholly owned sparse tables. Enumeration count is independent of retained rows.
internal static class AcquisitionEnumerationTests
{
    internal static object? Metrics { get; private set; }
    private static object[] E(params object[] values) => values;
    private static object V(string name) => E("var", name);
    private sealed class Memory : IMemorySource
    {
        internal const ulong Base = 1048576;
        internal readonly int Rows;
        internal readonly byte[] Data;
        internal long Calls, Bytes; internal int LargestRead, Alive;
        internal Action? OnAlive;
        public TargetIdentity Identity { get; } = new(17, "fixture.exe", "synthetic", 11, new string('a', 64), "x64");
        internal Memory(int rows = 65536)
        {
            Rows = rows; Data = new byte[64 + rows * 16]; SetCount((uint)rows);
            foreach (int index in new[] { rows / 2, rows - 1 })
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Data.AsSpan(64 + index * 16), 1);
                BinaryPrimitives.WriteInt32LittleEndian(Data.AsSpan(72 + index * 16), index);
            }
        }
        internal void SetCount(uint count) => BinaryPrimitives.WriteUInt32LittleEndian(Data, count);
        public byte[] Read(ulong address, int size)
        {
            Calls++; Bytes += size; LargestRead = Math.Max(LargestRead, size);
            if (address < Base || address - Base > (ulong)Data.Length || size > Data.Length - (long)(address - Base))
                throw new ObservationException("unreadable_range", "Outside owned enumeration fixture.");
            return Data.AsSpan((int)(address - Base), size).ToArray();
        }
        public void EnsureAlive() { Alive++; OnAlive?.Invoke(); }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static JsonObject Recipe(Memory memory) => JsonSerializer.SerializeToNode(new
    {
        schema = "overwatch-decoder.acquisition-recipe/1", target = new { image_name = memory.Identity.ImageName,
            executable_sha256 = memory.Identity.ExecutableSha256, architecture = "x64" }, seconds = 30,
        constants = new { }, functions = new { }, global_guards = "global",
        stages = new[] { new { name = "owned_table", steps = new object[] {
            new { op = "read", name = "header", address = E("rva", 0, 8), size = 8 },
            new { op = "guard", set = "global", value = V("header") },
            new { op = "read", name = "table", address = E("rva", 64, memory.Rows * 16), size = memory.Rows * 16 },
            new { op = "scan", name = "selected", count = E("load", V("header"), 0, 4), index = "slot",
                keep = new[] { "value_address", "selected_guards" }, steps = new object[] {
                new { op = "filter", test = E("eq", E("load", V("table"), E("mul", V("slot"), 16), 4), 1) },
                new { op = "let", name = "value_address", value = E("add", E("var", "module_base"), E("add", 72, E("mul", V("slot"), 16))) },
                new { op = "let", name = "selected_guards", value = V("global") },
                new { op = "guard", set = "selected_guards", value = E("slice", V("table"), E("mul", V("slot"), 16), 4) } } },
            new { op = "require", test = E("eq", E("count", V("selected")), 2) } } } },
        fields = Array.Empty<object>(), field_collections = new[] { new { rows = "selected", prefix = "entry",
            fields = new[] { new { name = "value", type = "i32", address = V("value_address"), guards = "selected_guards" } } } }
    })!.AsObject();
    internal static int Run()
    {
        int assertions = 0, serial = 0;
        void Check(bool ok, string name) { assertions++; if (!ok) throw new ObservationException("self_test_failed", "acquisition-enumeration:" + name); }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-enumeration-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string Next() => Path.Combine(root, (++serial).ToString());
        JsonObject Scan(JsonObject recipe) => recipe["stages"]![0]!["steps"]![3]!.AsObject();
        Acquisition.Result Acquire(Memory memory, JsonObject recipe, string output, CancellationToken token = default, Acquisition.Limits? limits = null) =>
            Acquisition.RunBounded(memory, new(Memory.Base, (ulong)memory.Data.Length, memory.Identity.ImageName), JsonSerializer.SerializeToUtf8Bytes(recipe), output, token, null, limits ?? new());
        JsonElement? Reject(Memory memory, JsonObject recipe, string code, CancellationToken token = default, Acquisition.Limits? limits = null)
        {
            string output = Next();
            try { Acquire(memory, recipe, output, token, limits); Check(false, "rejected fixture admitted:" + code); }
            catch (ObservationException error) { Check(error.Code == code, "expected " + code + " got " + error.Code); }
            Check(!File.Exists(Path.Combine(output, "profile.json")), "rejection publishes no profile");
            string manifest = Path.Combine(output, "manifest.json");
            if (!File.Exists(manifest)) { Check(code == "invalid_acquisition_recipe", "only preflight limits omit attempt manifest"); return null; }
            using var saved = JsonDocument.Parse(File.ReadAllBytes(manifest));
            Check(!saved.RootElement.GetProperty("complete").GetBoolean() && saved.RootElement.GetProperty("error").GetString() == code, "failed manifest retains exact reason");
            return saved.RootElement.Clone();
        }
        try
        {
            var measurements = new List<object>();
            foreach (int capacity in new[] { 32768, 65536 })
            {
                var memory = new Memory(capacity); string output = Next();
                long allocated = GC.GetAllocatedBytesForCurrentThread(); var cpu = Process.GetCurrentProcess().TotalProcessorTime; var wall = Stopwatch.StartNew();
                var result = Acquire(memory, Recipe(memory), output);
                double cpuMs = (Process.GetCurrentProcess().TotalProcessorTime - cpu).TotalMilliseconds;
                long allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
                var profile = FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(output, "profile.json")));
                Check(result.complete && result.fields == 2 && profile.Fields.Length == 2 && profile.Guards.Length == 3, "sparse upper-half and final-row fields retained:" + capacity);
                Check(profile.Fields[0].Address == Memory.Base + 72UL + (ulong)(capacity / 2) * 16 &&
                    profile.Fields[1].Address == Memory.Base + 72UL + (ulong)(capacity - 1) * 16, "upper-half and last index reached without off-by-one:" + capacity);
                Check(result.rows_rejected == capacity - 2 && result.read_calls == 5 && result.requested_bytes == capacity * 16L + 24 &&
                    memory.Calls == result.read_calls && memory.Bytes == result.requested_bytes && memory.LargestRead == capacity * 16, "physical work exactly table snapshot plus three guard rereads:" + capacity);
                using var scan = JsonDocument.Parse(File.ReadLines(Path.Combine(output, "evidence.jsonl")).Single(line => JsonDocument.Parse(line).RootElement.GetProperty("kind").GetString() == "scan"));
                Check(scan.RootElement.GetProperty("enumerated").GetInt32() == capacity && scan.RootElement.GetProperty("retained").GetInt32() == 2, "scan evidence declares full enumeration and filtered retention");
                measurements.Add(new { enumerated = capacity, retained = 2, fields = result.fields, guards = profile.Guards.Length,
                    result.read_calls, result.requested_bytes, result.evidence_bytes, largest_read = memory.LargestRead,
                    elapsed_ms = wall.Elapsed.TotalMilliseconds, process_cpu_ms = cpuMs, current_thread_allocated_bytes = allocatedBytes });
            }
            Metrics = new { schema = "overwatch-decoder.acquisition-enumeration-fixture/1", synthetic = true, measurements,
                note = "Supplied-memory engine and file evidence on this host; allocation includes transient scopes, rejected-row exceptions and serialization. Not a native target latency or RSS guarantee." };
            var over = new Memory(); over.SetCount(65537); var rejected = Reject(over, Recipe(over), "acquisition_enumeration_limit");
            Check(over.Calls == 2 && rejected!.Value.GetProperty("rows_rejected").GetInt64() == 0, "65537 rejected before any row loop");
            var retained = new Memory(); var retainRecipe = Recipe(retained); var keep = Scan(retainRecipe)["steps"]!.AsArray(); keep.RemoveAt(0);
            Reject(retained, retainRecipe, "acquisition_retained_row_limit");
            var bounded = new Memory(); Reject(bounded, Recipe(bounded), "acquisition_read_limit", limits: new(ReadBytes: 1048576));
            Check(bounded.Calls == 1 && bounded.Bytes == 8, "remaining byte budget refuses full table before physical read");
            bounded = new(); var oversizedRead = Recipe(bounded); oversizedRead["stages"]![0]!["steps"]![2]!["size"] = 1048577;
            Reject(bounded, oversizedRead, "acquisition_read_bounds"); Check(bounded.Calls == 1, "1MiB+1 refused before source read");
            foreach (var limit in new[] { new Acquisition.Limits(ReadBytes: 67108865), new Acquisition.Limits(ReadCalls: 200001) })
            { bounded = new(); Reject(bounded, Recipe(bounded), "invalid_acquisition_recipe", limits: limit); Check(bounded.Calls == 0, "above unchanged total limit rejected before source access"); }
            var calls = new Memory(); var callsRecipe = Recipe(calls); Scan(callsRecipe)["steps"] = JsonSerializer.SerializeToNode(new object[] {
                new { op = "read", name = "byte0", address = Memory.Base + 16, size = 1 }, new { op = "read", name = "byte1", address = Memory.Base + 16, size = 1 },
                new { op = "read", name = "byte2", address = Memory.Base + 16, size = 1 }, new { op = "read", name = "byte3", address = Memory.Base + 16, size = 1 },
                new { op = "filter", test = 0 } });
            var callFailure = Reject(calls, callsRecipe, "acquisition_read_limit");
            Check(calls.Calls == 200000 && callFailure!.Value.GetProperty("read_calls").GetInt64() == 200000 && calls.Bytes < Acquisition.MaximumReadBytes, "200000 calls remains an actual physical ceiling");
            var work = new Memory(); var workRecipe = Recipe(work); var steps = new JsonArray();
            for (int i = 0; i < 32; i++) steps.Add(new JsonObject { ["op"] = "let", ["name"] = "scratch", ["value"] = 0 });
            steps.Add(new JsonObject { ["op"] = "filter", ["test"] = 0 }); Scan(workRecipe)["steps"] = steps;
            var instructionFailure = Reject(work, workRecipe, "acquisition_instruction_limit");
            Check(instructionFailure!.Value.GetProperty("rows_rejected").GetInt64() is > 60000 and < 65536 && work.Calls == 2, "2M instruction limit interrupts legal-size scan without extra reads");
            using var stop = new CancellationTokenSource(); var cancelled = new Memory(); cancelled.OnAlive = () => { if (cancelled.Alive >= 512) stop.Cancel(); };
            var cancelledResult = Reject(cancelled, Recipe(cancelled), "cancelled", stop.Token);
            Check(cancelledResult!.Value.GetProperty("rows_rejected").GetInt64() is > 0 and < 65536 && cancelled.Calls == 2, "cancellation is checked during enlarged scan");
            Check(Acquisition.MaximumRows == 4096 && Acquisition.MaximumReadBytes == 67108864 && Acquisition.MaximumReadSize == 1048576 &&
                Acquisition.MaximumEvidenceBytes == 134217728, "independent resource ceilings unchanged");
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
