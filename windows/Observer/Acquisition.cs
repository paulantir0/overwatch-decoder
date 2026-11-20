using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Finite, private data recipes. No target layouts, process writes, scripts or plugins.</summary>
public static class Acquisition
{
    public const int MaximumRecipeBytes = 1024 * 1024, MaximumStages = 32, MaximumRows = 4096;
    public const int MaximumEnumeration = 65536, MaximumReadSize = 1024 * 1024;
    public const int MaximumFieldCollectionDepth = 4;
    public const long MaximumReadBytes = 64L * 1024 * 1024, MaximumEvidenceBytes = 128L * 1024 * 1024;
    public sealed record Module(ulong Address, ulong Size, string ImageName);
    public sealed record Result(bool complete, string schema, string visibility, bool public_state_eligible,
        string recipe_sha256, string? profile_sha256, int fields, int guard_declarations,
        long read_calls, long requested_bytes, long evidence_bytes, int stages_completed, long rows_rejected,
        string? error, double elapsed_ms, object target, Module module, string revision, string? evidence_sha256);
    private sealed record Block(ulong Address, byte[] Bytes, long ReadId, int Offset = 0);
    private sealed record Guard(Block Source);
    private sealed class Scope : Dictionary<string, object> { public Scope() : base(StringComparer.Ordinal) { } public Scope(Scope other) : base(other, StringComparer.Ordinal) { } }
    private sealed class Rejected : Exception { }
    private sealed record Function(string[] Parameters, JsonElement Expression);
    internal sealed record Limits(long ReadBytes = MaximumReadBytes, long EvidenceBytes = MaximumEvidenceBytes, long ReadCalls = 200000);
    private static ObservationException Invalid(string code = "invalid_acquisition_recipe") => new(code, "Acquisition recipe, required evidence or bounds are invalid.");
    private static void Need(bool ok, string code = "invalid_acquisition_recipe") { if (!ok) throw Invalid(code); }
    private static string Name(JsonElement x) { string? s = x.GetString(); Need(s is { Length: > 0 and <= 64 } && s.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')); return s!; }
    private static string Text(JsonElement x, string key) => x.GetProperty(key).GetString() ?? throw Invalid();
    private static void Keys(JsonElement x, params string[] allowed)
    {
        Need(x.ValueKind == JsonValueKind.Object); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in x.EnumerateObject()) Need(allowed.Contains(p.Name, StringComparer.Ordinal) && seen.Add(p.Name));
    }
    public static Module MainModule(NativeMemory memory)
    {
        memory.EnsureAlive(); using var process = Process.GetProcessById(memory.Identity.Pid);
        using ProcessModule module = process.MainModule ?? throw Invalid("module_unavailable");
        var result = new Module((ulong)module.BaseAddress, (ulong)module.ModuleMemorySize, Path.GetFileName(module.FileName));
        memory.EnsureAlive(); Need(result.ImageName.Equals(memory.Identity.ImageName, StringComparison.OrdinalIgnoreCase), "module_identity_mismatch");
        return result;
    }
    public static Result Run(IMemorySource source, Module module, string recipePath, string outputDirectory, CancellationToken cancellation,
        Action<string>? stageObserver = null)
    {
        var info = new FileInfo(recipePath); Need(info.Exists && info.Length is > 0 and <= MaximumRecipeBytes);
        using var file = new FileStream(recipePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        byte[] recipe = new byte[checked((int)info.Length)]; file.ReadExactly(recipe); Need(file.ReadByte() == -1);
        return RunBytes(source, module, recipe, outputDirectory, cancellation, stageObserver);
    }
    public static Result RunBytes(IMemorySource source, Module module, byte[] recipe, string outputDirectory, CancellationToken cancellation,
        Action<string>? stageObserver = null)
        => RunBounded(source, module, recipe, outputDirectory, cancellation, stageObserver, new());
    internal static Result RunBounded(IMemorySource source, Module module, byte[] recipe, string outputDirectory, CancellationToken cancellation,
        Action<string>? stageObserver, Limits limits)
    {
        Need(limits.ReadBytes is > 0 and <= MaximumReadBytes && limits.EvidenceBytes is >= 131072 and <= MaximumEvidenceBytes && limits.ReadCalls is > 0 and <= 200000);
        Need(recipe.Length is > 0 and <= MaximumRecipeBytes); recipe = recipe.ToArray();
        try
        {
            using var document = JsonDocument.Parse(recipe, new JsonDocumentOptions { MaxDepth = 96 });
            var engine = new Engine(source, module, recipe, document.RootElement, cancellation, stageObserver, limits);
            return engine.Run(outputDirectory);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException or ArgumentOutOfRangeException or InvalidCastException)
        { throw Invalid(); }
    }
    private sealed class Engine
    {
        private readonly IMemorySource source; private readonly TargetIdentity target; private readonly Module module;
        private readonly byte[] raw; private readonly JsonElement root; private readonly CancellationToken token; private readonly Action<string>? stageObserver;
        private readonly Dictionary<string, Function> functions = new(StringComparer.Ordinal); private readonly Scope scope = new();
        private readonly Stopwatch clock = Stopwatch.StartNew(); private readonly string hash; private readonly int seconds; private readonly Limits limits;
        private FileStream? trace; private long calls, requested, evidence, expressions, instructions, rejected, slicedBytes; private int stages;
        private string stage = "validation"; private long row = -1; private int validationNodes;
        internal Engine(IMemorySource source, Module module, byte[] raw, JsonElement root, CancellationToken token, Action<string>? observer, Limits limits)
        {
            this.limits = limits;
            this.source = source; target = source.Identity; this.module = module; this.raw = raw; this.root = root; this.token = token; stageObserver = observer;
            hash = Convert.ToHexStringLower(SHA256.HashData(raw));
            Keys(root, "schema", "target", "seconds", "constants", "functions", "stages", "global_guards", "fields", "profile_schema", "field_collections");
            Need(Text(root, "schema") == "overwatch-decoder.acquisition-recipe/1");
            string profileSchema = root.TryGetProperty("profile_schema", out var schemaNode) ? schemaNode.GetString() ?? "" : "overwatch-decoder.field-profile/1";
            Need(profileSchema is "overwatch-decoder.field-profile/1" or "overwatch-decoder.field-profile/4");
            JsonElement expected = root.GetProperty("target"); Keys(expected, "image_name", "executable_sha256", "architecture");
            string digest = Text(expected, "executable_sha256"); Need(digest.Length == 64 && digest.All(Uri.IsHexDigit));
            Need(Text(expected, "architecture") == "x64" && Text(expected, "image_name").Length is > 0 and <= 128);
            Need(target.Pid > 0 && target.CreationFileTime > 0 && target.ExecutableSha256.Equals(digest, StringComparison.OrdinalIgnoreCase) && target.Architecture == "x64" &&
                target.ImageName.Equals(Text(expected, "image_name"), StringComparison.OrdinalIgnoreCase), "identity_mismatch");
            Need(module.Size > 0 && module.Address <= long.MaxValue && module.Size <= (ulong)long.MaxValue - module.Address &&
                module.ImageName.Equals(target.ImageName, StringComparison.OrdinalIgnoreCase), "module_identity_mismatch");
            seconds = root.GetProperty("seconds").GetInt32(); Need(seconds is >= 1 and <= 30);
            scope.Add("module_base", module.Address); scope.Add("module_size", module.Size);
            JsonElement constants = root.GetProperty("constants"); Need(constants.ValueKind == JsonValueKind.Object);
            foreach (var p in constants.EnumerateObject()) { Need(p.Name.Length is > 0 and <= 64 && p.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')); Need(scope.TryAdd(p.Name, p.Value.GetUInt64())); }
            Need(scope.Count <= 256);
            JsonElement funcs = root.GetProperty("functions"); Need(funcs.ValueKind == JsonValueKind.Object);
            foreach (var f in funcs.EnumerateObject())
            {
                Keys(f.Value, "parameters", "expression"); Need(f.Name.Length is > 0 and <= 64);
                string[] ps = f.Value.GetProperty("parameters").EnumerateArray().Select(Name).ToArray();
                Need(ps.Length <= 8 && ps.Distinct(StringComparer.Ordinal).Count() == ps.Length);
                Need(functions.TryAdd(f.Name, new(ps, f.Value.GetProperty("expression"))));
            }
            Need(functions.Count <= 32);
            foreach (var f in functions.Values) ValidateExpression(f.Expression, 0);
            var completedFunctions = new HashSet<string>(StringComparer.Ordinal);
            void NoCycles(string name, HashSet<string> active)
            {
                if (completedFunctions.Contains(name)) return;
                Need(active.Add(name));
                void Visit(JsonElement e) { if (e.ValueKind != JsonValueKind.Array) return; if (e[0].GetString() == "call") NoCycles(e[1].GetString()!, active); foreach (var item in e.EnumerateArray().Skip(1)) if (item.ValueKind == JsonValueKind.Array) Visit(item); }
                Visit(functions[name].Expression); active.Remove(name); completedFunctions.Add(name);
            }
            foreach (string name in functions.Keys) NoCycles(name, new(StringComparer.Ordinal));
            JsonElement list = root.GetProperty("stages"); Need(list.ValueKind == JsonValueKind.Array && list.GetArrayLength() is > 0 and <= MaximumStages);
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in list.EnumerateArray()) { Keys(s, "name", "steps"); Need(names.Add(Name(s.GetProperty("name")))); ValidateSteps(s.GetProperty("steps"), 0); }
            _ = Name(root.GetProperty("global_guards"));
            var fields = root.GetProperty("fields"); Need(fields.ValueKind == JsonValueKind.Array && fields.GetArrayLength() <= FieldStream.MaximumFields);
            void ValidateField(JsonElement f)
            {
                Keys(f, "name", "type", "address", "guards", "min", "max", "codec", "clock_address", "counter_scale_f32_hex", "pool_span", "pool_slots"); _ = Name(f.GetProperty("name"));
                Need(Text(f, "type") is "u8" or "i32" or "f32" or "f64" or "f32x3" or "f32x4" or "i32x4");
                ValidateExpression(f.GetProperty("address"), 0); if (f.TryGetProperty("guards", out var g)) _ = Name(g);
                if (f.TryGetProperty("codec", out var pc) && pc.GetString() == PoolSumCodec.Name)
                {
                    Need(profileSchema == "overwatch-decoder.field-profile/4" && Text(f, "type") == "f32" && !f.TryGetProperty("clock_address", out _) && !f.TryGetProperty("counter_scale_f32_hex", out _));
                    _ = PoolSumCodec.ParseConfig(f);
                }
                else if (f.TryGetProperty("codec", out var codec))
                {
                    Need(!f.TryGetProperty("pool_span", out _) && !f.TryGetProperty("pool_slots", out _));
                    Need(profileSchema == "overwatch-decoder.field-profile/4" && codec.GetString() == TimerCodec.Name && Text(f, "type") == "f32");
                    ValidateExpression(f.GetProperty("clock_address"), 0); string hex = Text(f, "counter_scale_f32_hex");
                    Need(hex.Length == 8 && hex.All(Uri.IsHexDigit));
                    float scale = BitConverter.Int32BitsToSingle(System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(Convert.FromHexString(hex)));
                    Need(float.IsFinite(scale) && scale > 0f);
                }
                else Need(!f.TryGetProperty("clock_address", out _) && !f.TryGetProperty("counter_scale_f32_hex", out _) && !f.TryGetProperty("pool_span", out _) && !f.TryGetProperty("pool_slots", out _));
                foreach (string bound in new[] { "min", "max" }) if (f.TryGetProperty(bound, out var v)) Need(double.IsFinite(v.GetDouble()));
            }
            foreach (var f in fields.EnumerateArray()) ValidateField(f);
            void ValidateCollections(JsonElement collections, int depth)
            {
                Need(depth <= MaximumFieldCollectionDepth, "acquisition_field_collection_depth");
                Need(collections.ValueKind == JsonValueKind.Array && collections.GetArrayLength() is > 0 and <= FieldStream.MaximumFields);
                foreach (var collection in collections.EnumerateArray())
                {
                    Need(++validationNodes <= 50000);
                    Keys(collection, "rows", "prefix", "fields", "field_collections", "allow_empty");
                    _ = Name(collection.GetProperty("rows")); _ = Name(collection.GetProperty("prefix"));
                    if (collection.TryGetProperty("allow_empty", out var allowEmpty))
                        Need(allowEmpty.ValueKind is JsonValueKind.True or JsonValueKind.False);
                    var templates = collection.GetProperty("fields");
                    Need(templates.ValueKind == JsonValueKind.Array && templates.GetArrayLength() <= FieldStream.MaximumFields);
                    bool nested = collection.TryGetProperty("field_collections", out var children);
                    Need(templates.GetArrayLength() > 0 || nested);
                    foreach (var f in templates.EnumerateArray()) ValidateField(f);
                    if (nested) ValidateCollections(children, depth + 1);
                }
            }
            if (root.TryGetProperty("field_collections", out var collections)) ValidateCollections(collections, 1);
            else Need(fields.GetArrayLength() > 0);
        }
        private void ValidateExpression(JsonElement x, int depth)
        {
            Need(depth <= 64 && ++validationNodes <= 50000);
            if (x.ValueKind == JsonValueKind.Number) { _ = x.GetUInt64(); return; }
            Need(x.ValueKind == JsonValueKind.Array && x.GetArrayLength() is >= 2 and <= 10);
            string op = x[0].GetString() ?? throw Invalid(); int n = x.GetArrayLength();
            if (op == "var") { Need(n == 2); _ = Name(x[1]); return; }
            if (op == "call")
            { Need(functions.TryGetValue(x[1].GetString() ?? "", out var f) && n == f.Parameters.Length + 2); for (int i = 2; i < n; i++) ValidateExpression(x[i], depth + 1); return; }
            if (op == "get") { Need(n == 3); ValidateExpression(x[1], depth + 1); _ = Name(x[2]); return; }
            int arity = op switch
            {
                "count" or "popcount" or "not" => 1,
                "rva" or "add" or "sub" or "mul" or "wrap_add" or "wrap_sub" or "xor" or "and" or "or" or "shl" or "shr" or "ror" or "eq" or "ne" or "lt" or "le" or "both" or "either" or "same" => 2,
                "load" or "slice" => 3, _ => throw Invalid()
            };
            Need(n == arity + 1); for (int i = 1; i < n; i++) ValidateExpression(x[i], depth + 1);
        }
        private void ValidateSteps(JsonElement list, int depth)
        {
            Need(depth <= 8 && list.ValueKind == JsonValueKind.Array && list.GetArrayLength() <= 512);
            foreach (var s in list.EnumerateArray())
            {
                Need(++validationNodes <= 50000); string op = Text(s, "op");
                switch (op)
                {
                    case "let": Keys(s, "op", "name", "value"); _ = Name(s.GetProperty("name")); ValidateExpression(s.GetProperty("value"), 0); break;
                    case "read": Keys(s, "op", "name", "address", "size"); _ = Name(s.GetProperty("name")); ValidateExpression(s.GetProperty("address"), 0); ValidateExpression(s.GetProperty("size"), 0); break;
                    case "require": case "filter": Keys(s, "op", "test"); ValidateExpression(s.GetProperty("test"), 0); Need(op != "filter" || depth > 0); break;
                    case "guard": Keys(s, "op", "set", "value"); _ = Name(s.GetProperty("set")); ValidateExpression(s.GetProperty("value"), 0); break;
                    case "check": Keys(s, "op", "set"); _ = Name(s.GetProperty("set")); break;
                    case "one": Keys(s, "op", "rows"); _ = Name(s.GetProperty("rows")); break;
                    case "collect_guards": Keys(s, "op", "rows", "from", "set"); _ = Name(s.GetProperty("rows")); _ = Name(s.GetProperty("from")); _ = Name(s.GetProperty("set")); break;
                    case "scan":
                        Keys(s, "op", "name", "count", "rows", "index", "keep", "steps"); _ = Name(s.GetProperty("name")); _ = Name(s.GetProperty("index"));
                        Need(s.TryGetProperty("count", out var c) != s.TryGetProperty("rows", out var r));
                        if (c.ValueKind != JsonValueKind.Undefined) ValidateExpression(c, 0); else _ = Name(r);
                        string[] keep = s.GetProperty("keep").EnumerateArray().Select(Name).ToArray(); Need(keep.Length is > 0 and <= 64 && keep.Distinct().Count() == keep.Length);
                        ValidateSteps(s.GetProperty("steps"), depth + 1); break;
                    default: throw Invalid();
                }
            }
        }
        private void Control()
        {
            if (token.IsCancellationRequested) throw Invalid("cancelled");
            Need(clock.Elapsed.TotalSeconds < seconds, "acquisition_time_limit");
            source.EnsureAlive(); Need(source.Identity == target, "identity_mismatch");
        }
        private void Trace(object value)
        {
            byte[] b = JsonSerializer.SerializeToUtf8Bytes(value); Need(b.Length <= 3 * 1024 * 1024 && evidence + b.Length + 1 <= limits.EvidenceBytes - 65536, "acquisition_output_limit");
            trace!.Write(b); trace.WriteByte((byte)'\n'); evidence += b.Length + 1;
        }
        private Block Read(ulong address, ulong length, string purpose)
        {
            Need(length is > 0 and <= MaximumReadSize && address <= (ulong)long.MaxValue && length <= (ulong)long.MaxValue - address, "acquisition_read_bounds");
            Control(); Need(requested + (long)length <= limits.ReadBytes && calls < limits.ReadCalls, "acquisition_read_limit");
            // Reserve the worst-case hex trace before a native attempt; no unreported budget-refused read.
            Need(evidence + 2 * (long)length + 2048 <= limits.EvidenceBytes - 65536, "acquisition_output_limit");
            long id = calls++; requested += (long)length; long start = Stopwatch.GetTimestamp(), end; byte[]? b = null; string? error = null; int? native = null;
            try { b = source.Read(address, (int)length); end = Stopwatch.GetTimestamp(); }
            catch (Exception e) when (e is not OutOfMemoryException) { end = Stopwatch.GetTimestamp(); error = e is ObservationException o ? o.Code : "source_exception"; native = (e as ObservationException)?.NativeCode; }
            if (b is not null && b.Length != (int)length) error = "partial_read";
            Trace(new { kind = "read", stage, row, id, purpose, attempted = true, address, requested_bytes = length,
                read_start_ticks = start, read_end_ticks = end, returned_bytes = b?.Length, error, native_code = native,
                bytes_hex = error is null && b is not null ? Convert.ToHexStringLower(b) : null });
            if (error is not null) throw new ObservationException(error, "Required acquisition read failed.", native);
            Need(b is not null, "partial_read"); Control(); return new(address, b!, id);
        }
        private static ulong Number(object x) => x is ulong v ? v : throw Invalid();
        private object Evaluate(JsonElement x, Scope s, int depth = 0)
        {
            Need(depth <= 64 && ++expressions <= 20_000_000, "acquisition_expression_limit");
            if (x.ValueKind == JsonValueKind.Number) return x.GetUInt64();
            string op = x[0].GetString()!;
            object A(int i) => Evaluate(x[i], s, depth + 1); ulong N(int i) => Number(A(i));
            if (op == "var") return s[Name(x[1])];
            if (op == "get") return ((Scope)A(1))[Name(x[2])];
            if (op == "call")
            {
                Function f = functions[x[1].GetString()!]; var local = new Scope(s);
                for (int i = 0; i < f.Parameters.Length; i++) local[f.Parameters[i]] = A(i + 2);
                return Evaluate(f.Expression, local, depth + 1);
            }
            if (op == "count") return (ulong)((List<Scope>)A(1)).Count;
            if (op is "load" or "slice")
            {
                var b = (Block)A(1); ulong offset = N(2), size = N(3); Need(offset <= (ulong)b.Bytes.Length && size <= (ulong)b.Bytes.Length - offset, "acquisition_slice_bounds");
                var span = b.Bytes.AsSpan((int)offset, (int)size);
                if (op == "slice") { slicedBytes += (long)size; Need(slicedBytes <= MaximumReadBytes, "acquisition_copy_limit"); return new Block(checked(b.Address + offset), span.ToArray(), b.ReadId, checked(b.Offset + (int)offset)); }
                return size switch { 1 => (ulong)span[0], 2 => (ulong)BinaryPrimitives.ReadUInt16LittleEndian(span), 4 => (ulong)BinaryPrimitives.ReadUInt32LittleEndian(span), 8 => BinaryPrimitives.ReadUInt64LittleEndian(span), _ => throw Invalid() };
            }
            if (op == "same") return ((Block)A(1)).Bytes.AsSpan().SequenceEqual(((Block)A(2)).Bytes) ? 1UL : 0UL;
            ulong a = N(1); if (op == "popcount") return (ulong)BitOperations.PopCount(a); if (op == "not") return a == 0 ? 1UL : 0UL;
            if (op == "both") return a != 0 && N(2) != 0 ? 1UL : 0UL;
            if (op == "either") return a != 0 || N(2) != 0 ? 1UL : 0UL;
            ulong b2 = N(2);
            if (op == "rva") { Need(b2 > 0 && a < module.Size && b2 <= module.Size - a, "acquisition_module_bounds"); return checked(module.Address + a); }
            if (op is "shl" or "shr" or "ror") Need(b2 < 64, "acquisition_shift_bounds");
            return op switch
            {
                "add" => checked(a + b2), "sub" => checked(a - b2), "mul" => checked(a * b2),
                "wrap_add" => unchecked(a + b2), "wrap_sub" => unchecked(a - b2), "xor" => a ^ b2, "and" => a & b2, "or" => a | b2,
                "shl" => a << (int)b2, "shr" => a >> (int)b2, "ror" => BitOperations.RotateRight(a, (int)b2),
                "eq" => a == b2 ? 1UL : 0UL, "ne" => a != b2 ? 1UL : 0UL, "lt" => a < b2 ? 1UL : 0UL, "le" => a <= b2 ? 1UL : 0UL,
                _ => throw Invalid()
            };
        }
        private static Guard[] Guards(Scope s, string name, bool required = false) { if (s.TryGetValue(name, out var value)) return (Guard[])value; Need(!required, "acquisition_missing_guard_set"); return []; }
        private void Check(Guard[] guards)
        {
            foreach (var g in guards)
            {
                Block b = Read(g.Source.Address, (ulong)g.Source.Bytes.Length, "guard_check");
                bool same = b.Bytes.AsSpan().SequenceEqual(g.Source.Bytes);
                Trace(new { kind = "guard_check", stage, row, expected_read_id = g.Source.ReadId, expected_offset = g.Source.Offset, actual_read_id = b.ReadId, matches = same });
                Need(same, "acquisition_guard_mismatch");
            }
        }
        private void CollectGuards(Scope s, JsonElement step)
        {
            string rowsName = Name(step.GetProperty("rows")), from = Name(step.GetProperty("from")), set = Name(step.GetProperty("set"));
            Need(s.TryGetValue(rowsName, out var rowsValue) && rowsValue is List<Scope>, "acquisition_missing_rows");
            var rows = (List<Scope>)rowsValue!; Need(rows.Count <= MaximumRows, "acquisition_retained_row_limit");
            var collected = new List<Guard>(); var exact = new HashSet<(ulong, string)>(); var bytes = new Dictionary<ulong, byte>(); int inputs = 0;
            void Add(Guard guard)
            {
                Need(++instructions <= 2_000_000, "acquisition_instruction_limit"); if ((instructions & 63) == 0) Control(); inputs++;
                Block source = guard.Source; Need(source.Bytes.Length is > 0 and <= FieldStream.MaximumGuardBytes, "acquisition_guard_bounds");
                if (!exact.Add((source.Address, Convert.ToHexString(source.Bytes)))) return;
                Need(collected.Count < FieldStream.MaximumGuards, "acquisition_guard_bounds");
                for (int i = 0; i < source.Bytes.Length; i++)
                { ulong address = checked(source.Address + (ulong)i); Need(!bytes.TryGetValue(address, out byte value) || value == source.Bytes[i], "acquisition_guard_conflict"); bytes[address] = source.Bytes[i]; }
                collected.Add(guard);
            }
            if (s.TryGetValue(set, out var existing))
            { Need(existing is Guard[], "acquisition_invalid_guard_set"); foreach (var guard in (Guard[])existing!) Add(guard); }
            foreach (var retained in rows)
            {
                Control(); Need(retained.TryGetValue(from, out var value), "acquisition_missing_guard_set");
                Need(value is Guard[], "acquisition_invalid_guard_set"); foreach (var guard in (Guard[])value!) Add(guard);
            }
            s[set] = collected.ToArray();
            Trace(new { kind = "guard_collection", stage, row, source_rows = rows.Count, input_guards = inputs, distinct_guards = collected.Count,
                guards = collected.Select(g => new { address = g.Source.Address, byte_count = g.Source.Bytes.Length, source_read_id = g.Source.ReadId, source_offset = g.Source.Offset }) });
        }
        private void Steps(JsonElement steps, Scope s)
        {
            foreach (var step in steps.EnumerateArray())
            {
                Need(++instructions <= 2_000_000, "acquisition_instruction_limit"); if ((instructions & 63) == 0) Control();
                string op = Text(step, "op"); object Eval(string key) => Evaluate(step.GetProperty(key), s);
                switch (op)
                {
                    case "let": s[Name(step.GetProperty("name"))] = Eval("value"); break;
                    case "read": s[Name(step.GetProperty("name"))] = Read(Number(Eval("address")), Number(Eval("size")), "recipe"); break;
                    case "require": Need(Number(Eval("test")) != 0, "acquisition_predicate_failed"); break;
                    case "filter": if (Number(Eval("test")) == 0) throw new Rejected(); break;
                    case "guard":
                        string set = Name(step.GetProperty("set")); var b = (Block)Eval("value"); Need(b.Bytes.Length is > 0 and <= FieldStream.MaximumGuardBytes, "acquisition_guard_bounds");
                        Guard[] gs = Guards(s, set);
                        if (!gs.Any(g => g.Source.Address == b.Address && g.Source.Bytes.AsSpan().SequenceEqual(b.Bytes))) { Need(gs.Length < FieldStream.MaximumGuards, "acquisition_guard_bounds"); s[set] = gs.Append(new Guard(b)).ToArray(); } break;
                    case "check": Check(Guards(s, Name(step.GetProperty("set")), true)); break;
                    case "collect_guards": CollectGuards(s, step); break;
                    case "one":
                        var rows = (List<Scope>)s[Name(step.GetProperty("rows"))]; Trace(new { kind = "selection", stage, candidates = rows.Count });
                        Need(rows.Count == 1, "acquisition_selection_not_unique"); foreach (var item in rows[0]) s[item.Key] = item.Value; break;
                    case "scan":
                        List<Scope>? input = step.TryGetProperty("rows", out var listName) ? (List<Scope>)s[Name(listName)] : null;
                        ulong count = input is null ? Number(Eval("count")) : (ulong)input.Count; Need(count <= MaximumEnumeration, "acquisition_enumeration_limit");
                        string index = Name(step.GetProperty("index")); string[] keep = step.GetProperty("keep").EnumerateArray().Select(Name).ToArray();
                        var output = new List<Scope>(); long savedRow = row;
                        for (ulong i = 0; i < count; i++)
                        {
                            Control(); row = (long)i; var local = new Scope(s); local[index] = i;
                            if (input is not null) foreach (var item in input[(int)i]) local[item.Key] = item.Value;
                            try { Steps(step.GetProperty("steps"), local); }
                            catch (Rejected) { rejected++; continue; }
                            Need(output.Count < MaximumRows, "acquisition_retained_row_limit"); var retained = new Scope(); foreach (string key in keep) retained.Add(key, local[key]); output.Add(retained);
                        }
                        row = savedRow; s[Name(step.GetProperty("name"))] = output;
                        Trace(new { kind = "scan", stage, enumerated = count, retained = output.Count }); break;
                    default: throw Invalid();
                }
                Need(s.Count <= 256, "acquisition_variable_limit");
            }
        }
        internal Result Run(string directory)
        {
            Control(); string destination = Path.GetFullPath(directory); Need(!Directory.Exists(destination) && !File.Exists(destination), "output_exists");
            string parent = Path.GetDirectoryName(destination) ?? throw Invalid("invalid_output_path"); Directory.CreateDirectory(parent);
            // Publish the whole attempt only after its manifest is durable. Never expose a profile alone.
            string output = Path.Combine(parent, ".overwatch-decoder-acquisition-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(output);
            string? TraceHash() { string path = Path.Combine(output, "evidence.jsonl"); if (!File.Exists(path)) return null; using var file = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }
            string? profileHash = null; int fields = 0, declarations = 0; string? failure = null; Result? finished = null;
            try
            {
                using (var recipeFile = new FileStream(Path.Combine(output, "recipe.json"), FileMode.CreateNew, FileAccess.Write)) recipeFile.Write(raw);
                trace = new FileStream(Path.Combine(output, "evidence.jsonl"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                Trace(new { schema = "overwatch-decoder.acquisition-evidence/1", kind = "start", target = Snapshots.PublicIdentity(target), module,
                    recipe_sha256 = hash, revision = Program.Revision, source_kind = MemorySourceProvenance.Kind(source), monotonic_frequency = Stopwatch.Frequency,
                    utc_origin = DateTimeOffset.UtcNow, monotonic_origin_ticks = Stopwatch.GetTimestamp(), visibility = "research", public_state_eligible = false, atomic = false });
                foreach (var step in root.GetProperty("stages").EnumerateArray())
                {
                    stage = Name(step.GetProperty("name")); Control(); stageObserver?.Invoke(stage);
                    Trace(new { kind = "stage_start", stage, ticks = Stopwatch.GetTimestamp() }); Steps(step.GetProperty("steps"), scope); Control(); stages++;
                    Trace(new { kind = "stage_end", stage, ticks = Stopwatch.GetTimestamp() });
                }
                var globals = Guards(scope, Name(root.GetProperty("global_guards")), true); var fieldObjects = new List<object>(); var all = globals.ToList();
                object GuardObject(Guard g) => new { address = g.Source.Address, bytes_hex = Convert.ToHexStringLower(g.Source.Bytes) };
                var fieldNames = new HashSet<string>(StringComparer.Ordinal);
                void AddField(JsonElement f, Scope values, string name)
                {
                    Control(); Need(++instructions <= 2_000_000, "acquisition_instruction_limit");
                    Need(fieldObjects.Count < FieldStream.MaximumFields, "acquisition_field_limit");
                    Need(name.Length <= 64, "acquisition_field_name_limit");
                    Need(fieldNames.Add(name), "acquisition_duplicate_field_name");
                    var fg = f.TryGetProperty("guards", out var set) ? Guards(values, Name(set), true) : [];
                    all.AddRange(fg); fields++;
                    var field = new Dictionary<string, object> { ["name"] = name, ["type"] = Text(f, "type"),
                        ["address"] = Number(Evaluate(f.GetProperty("address"), values)) };
                    if (fg.Length > 0) field["guards"] = fg.Select(GuardObject).ToArray();
                    foreach (string bound in new[] { "min", "max" }) if (f.TryGetProperty(bound, out var v)) field[bound] = v.GetDouble();
                    if (f.TryGetProperty("codec", out var codec))
                    {
                        field["codec"] = codec.GetString()!;
                        if (codec.GetString() == PoolSumCodec.Name)
                        {
                            field["pool_span"] = f.GetProperty("pool_span").GetInt32();
                            field["pool_slots"] = f.GetProperty("pool_slots").Clone();
                        }
                        else
                        {
                            field["clock_address"] = Number(Evaluate(f.GetProperty("clock_address"), values));
                            field["counter_scale_f32_hex"] = Text(f, "counter_scale_f32_hex");
                        }
                    }
                    fieldObjects.Add(field);
                }
                foreach (var f in root.GetProperty("fields").EnumerateArray()) AddField(f, scope, Text(f, "name"));
                void AddCollections(JsonElement collections, Scope values, string parentPrefix, int depth)
                {
                    Need(depth <= MaximumFieldCollectionDepth, "acquisition_field_collection_depth");
                    foreach (var collection in collections.EnumerateArray())
                    {
                        Control(); Need(++instructions <= 2_000_000, "acquisition_instruction_limit");
                        string rowsName = Name(collection.GetProperty("rows")), declaredPrefix = Name(collection.GetProperty("prefix"));
                        string prefix = parentPrefix.Length == 0 ? declaredPrefix : parentPrefix + "_" + declaredPrefix;
                        Need(values.TryGetValue(rowsName, out var value) && value is List<Scope>, "acquisition_missing_rows");
                        bool allowEmpty = collection.TryGetProperty("allow_empty", out var optional) && optional.GetBoolean();
                        var rows = (List<Scope>)value!; Need(rows.Count > 0 || allowEmpty, "acquisition_empty_field_collection");
                        var templates = collection.GetProperty("fields"); int count = templates.GetArrayLength();
                        if (count > 0) Need(rows.Count <= (FieldStream.MaximumFields - fieldObjects.Count) / count, "acquisition_field_limit");
                        int firstField = fieldObjects.Count; long savedRow = row;
                        for (int ordinal = 0; ordinal < rows.Count; ordinal++)
                        {
                            Control(); Need(++instructions <= 2_000_000, "acquisition_instruction_limit"); row = ordinal; var local = new Scope(values);
                            foreach (var item in rows[ordinal]) local[item.Key] = item.Value;
                            string rowPrefix = prefix + "_" + ordinal.ToString("D4", System.Globalization.CultureInfo.InvariantCulture);
                            Need(rowPrefix.Length <= 64, "acquisition_field_name_limit");
                            foreach (var f in templates.EnumerateArray())
                                AddField(f, local, rowPrefix + "_" + Text(f, "name"));
                            if (collection.TryGetProperty("field_collections", out var children)) AddCollections(children, local, rowPrefix, depth + 1);
                        }
                        row = savedRow;
                        Trace(new { kind = "field_collection", stage, rows = rowsName, prefix, retained_rows = rows.Count,
                            depth, allow_empty = allowEmpty, first_field = firstField, expanded_fields = fieldObjects.Count - firstField,
                            identity = "ordinal_within_acquisition_only" });
                    }
                }
                if (root.TryGetProperty("field_collections", out var collections))
                {
                    stage = "field_collection_output"; Control(); stageObserver?.Invoke(stage); Control();
                    AddCollections(collections, scope, "", 1);
                }
                declarations = all.Count; byte[] profile = JsonSerializer.SerializeToUtf8Bytes(new { schema = root.TryGetProperty("profile_schema", out var ps) ? ps.GetString()! : "overwatch-decoder.field-profile/1", target = Snapshots.PublicIdentity(target), guards = globals.Select(GuardObject).ToArray(), fields = fieldObjects });
                _ = FieldStream.ParseProfileBytes(profile); stage = "final_guard_check"; stageObserver?.Invoke(stage);
                Check(all.DistinctBy(g => (g.Source.Address, Convert.ToHexString(g.Source.Bytes))).ToArray()); Control();
                profileHash = Convert.ToHexStringLower(SHA256.HashData(profile)); Trace(new { kind = "profile_validated", profile_sha256 = profileHash, fields, guard_declarations = declarations });
                trace.Flush(true); trace.Dispose(); trace = null;
                string temporary = Path.Combine(output, "profile.partial"); using (var f = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write)) { f.Write(profile); f.Flush(true); }
                Control(); File.Move(temporary, Path.Combine(output, "profile.json"), false); Control();
            }
            catch (Exception e)
            {
                failure = e is ObservationException o ? o.Code : e is OperationCanceledException ? "cancelled" : "acquisition_failed";
                throw;
            }
            finally
            {
                trace?.Dispose(); trace = null;
                if (failure is not null && File.Exists(Path.Combine(output, "profile.json"))) File.Move(Path.Combine(output, "profile.json"), Path.Combine(output, "profile.partial"));
                finished = new Result(failure is null, "overwatch-decoder.acquisition-result/1", "research", false, hash, failure is null ? profileHash : null,
                    fields, declarations, calls, requested, evidence, stages, rejected, failure, clock.Elapsed.TotalMilliseconds, Snapshots.PublicIdentity(target), module, Program.Revision, TraceHash());
                using (var manifest = new FileStream(Path.Combine(output, "manifest.json"), FileMode.CreateNew, FileAccess.Write))
                { JsonSerializer.Serialize(manifest, finished); manifest.Flush(true); }
                Directory.Move(output, destination);
            }
            return finished!;
        }
    }
}
