using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Portable tests use an in-process byte source; no game process or live memory access.</summary>
public static class FieldStreamTests
{
    private sealed class FakeMemory : IMemorySource
    {
        public TargetIdentity Identity { get; set; } = new(321, "fixture.exe", "private-fixture-path", 9, new string('b', 64), "x64");
        public readonly Dictionary<ulong, byte> Bytes = new();
        public readonly List<(ulong address, int size)> Reads = new();
        public Action<ulong, int>? AfterRead { get; set; }
        public Func<ulong, int, string?>? Failure { get; set; }
        public int FirstReadDelayMs { get; set; }
        public bool ShortValues { get; set; }
        public void Set(ulong address, byte[] bytes)
        { for (int n = 0; n < bytes.Length; n++) Bytes[address + (ulong)n] = bytes[n]; }
        public FakeMemory()
        {
            Set(4096, BitConverter.GetBytes(1)); Set(4100, BitConverter.GetBytes(2));
            Set(4128, BitConverter.GetBytes(7));
        }
        public byte[] Read(ulong address, int size)
        {
            Reads.Add((address, size));
            if (Reads.Count == 1 && FirstReadDelayMs > 0) Thread.Sleep(FirstReadDelayMs);
            string? failure = Failure?.Invoke(address, Reads.Count);
            if (failure is not null) throw new ObservationException(failure, "Synthetic memory failure.");
            byte[] result = Enumerable.Range(0, size).Select(n => Bytes.GetValueOrDefault(address + (ulong)n)).ToArray();
            AfterRead?.Invoke(address, Reads.Count);
            return ShortValues && address == 4128 ? result[..^1] : result;
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }

    private sealed class CaptureWriter : StringWriter
    {
        public readonly List<JsonElement> Lines = new();
        public Action<JsonElement>? OnFrame { get; set; }
        private readonly StringBuilder line = new();
        public override void Write(string? value) { base.Write(value); line.Append(value); }
        public override void Write(char value)
        {
            base.Write(value);
            if (value != '\n') { line.Append(value); return; }
            using var doc = JsonDocument.Parse(line.ToString());
            JsonElement item = doc.RootElement.Clone(); Lines.Add(item); line.Clear();
            if (item.GetProperty("kind").GetString() == "frame") OnFrame?.Invoke(item);
        }
    }

    public static int Run()
    {
        int assertions = 0; string phase = "setup";
        void Check(bool value, string name)
        {
            if (!value) throw new ObservationException("self_test_failed", "field-stream:" + phase + ":" + name);
            assertions++;
        }
        void Throws(Action action, string code)
        {
            try { action(); }
            catch (ObservationException e) { Check(e.Code == code, "expected " + code + ", actual " + e.Code); return; }
            throw new ObservationException("self_test_failed", "field-stream:" + phase + ":expected " + code);
        }
        static JsonObject Guard(ulong address = 4096, string expected = "01000000") =>
            new() { ["address"] = address, ["bytes_hex"] = expected };
        static JsonObject Field(string name = "counter", string type = "i32", ulong address = 4128) =>
            new() { ["name"] = name, ["type"] = type, ["address"] = address };
        JsonObject Profile(FakeMemory source, params JsonObject[] fields) => new()
        {
            ["schema"] = "overwatch-decoder.field-profile/1", ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(source.Identity)),
            ["guards"] = new JsonArray(Guard()), ["fields"] = new JsonArray((fields.Length == 0 ? [Field()] : fields).Cast<JsonNode>().ToArray())
        };
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-field-stream-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); int inputNumber = 0;
        string Input(JsonObject profile)
        {
            string path = Path.Combine(root, "profile-" + inputNumber++ + ".json");
            File.WriteAllText(path, profile.ToJsonString()); return path;
        }
        CaptureWriter Capture(FakeMemory source, JsonObject profile, int count = 1, Action<int>? afterFrame = null,
            FieldStream.Limits? limits = null, Action<CancellationTokenSource>? configure = null)
        {
            using var cancellation = new CancellationTokenSource();
            configure?.Invoke(cancellation);
            var writer = new CaptureWriter(); int captured = 0;
            writer.OnFrame = _ => { captured++; afterFrame?.Invoke(captured); if (captured >= count) cancellation.Cancel(); };
            FieldStream.RunBounded(source, Input(profile), 10, TimeSpan.FromSeconds(30), writer, cancellation.Token, limits ?? new());
            Check(writer.Lines.Count > 0 && writer.Lines[^1].GetProperty("kind").GetString() == "summary", "terminal summary emitted");
            return writer;
        }
        JsonElement Result(CaptureWriter writer, string name, int frame = 0)
        {
            Check(writer.Lines.Count > frame + 1, "required frame " + frame + " exists before indexing");
            return writer.Lines[frame].GetProperty("fields").GetProperty(name);
        }
        void Unknown(JsonElement field, string reason)
        {
            Check(field.GetProperty("status").GetString() == "unknown", "unknown status");
            Check(field.GetProperty("value").ValueKind == JsonValueKind.Null, "unknown is null, not stale");
            Check(field.GetProperty("reason").GetString() == reason, "unknown reason " + reason);
        }
        try
        {
            phase = "scalar-vector-decode";
            var source = new FakeMemory(); source.Set(4128, BitConverter.GetBytes(-7));
            source.Set(4132, BitConverter.GetBytes(1.25f)); source.Set(4144, BitConverter.GetBytes(Math.PI));
            source.Set(4160, new[] { 1f, 2f, 3f }.SelectMany(BitConverter.GetBytes).ToArray());
            source.Set(4180, new[] { 0f, -.5f, 1f, 2f }.SelectMany(BitConverter.GetBytes).ToArray());
            var vector = Field("position_candidate", "f32x3", 4160); vector["min"] = -5; vector["max"] = 5;
            vector["guards"] = new JsonArray(Guard(4100, "02000000"));
            var profile = Profile(source, Field(), Field("single", "f32", 4132), Field("double", "f64", 4144), vector, Field("four", "f32x4", 4180));
            string path = Input(profile); using var cancel = new CancellationTokenSource();
            var decoded = new CaptureWriter { OnFrame = _ => cancel.Cancel() };
            FieldStream.Run(source, path, 10, TimeSpan.FromSeconds(30), decoded, cancel.Token);
            Check(Result(decoded, "counter").GetProperty("value").GetInt32() == -7, "signed i32");
            Check(Result(decoded, "single").GetProperty("value").GetDouble() == 1.25, "f32 bytes decoded");
            Check(Result(decoded, "double").GetProperty("value").GetDouble() == Math.PI, "f64 bytes decoded");
            Check(Result(decoded, "position_candidate").GetProperty("value").EnumerateArray().Select(x => x.GetDouble()).SequenceEqual([1d, 2d, 3d]), "three-vector");
            Check(Result(decoded, "four").GetProperty("value").EnumerateArray().Select(x => x.GetDouble()).SequenceEqual([0d, -.5d, 1d, 2d]), "four-vector");
            JsonElement frame = decoded.Lines[0];
            Check(frame.GetProperty("profile_sha256").GetString() == Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))), "exact profile digest");
            Check(frame.GetProperty("guards_before").GetArrayLength() == 2, "shared guard read once per pass");
            Check(source.Reads.Count == 9, "two before, five value, two after reads");
            foreach (JsonProperty f in frame.GetProperty("fields").EnumerateObject())
            {
                long start = f.Value.GetProperty("read_start_ticks").GetInt64(), end = f.Value.GetProperty("read_end_ticks").GetInt64();
                Check(start >= frame.GetProperty("guards_before")[1].GetProperty("end_ticks").GetInt64() && end >= start &&
                    end <= frame.GetProperty("guards_after")[0].GetProperty("start_ticks").GetInt64(), "guards bracket every field read");
            }
            foreach (JsonElement line in decoded.Lines)
            {
                Check(!line.GetProperty("public_state_eligible").GetBoolean() && !line.GetProperty("runtime_semantics_validated").GetBoolean(), "every line research only");
                Check(line.GetProperty("interpretation").GetString() == "profile_declared_research", "label interpretation explicitly declared");
                Check(line.GetProperty("target").GetProperty("pid").GetInt32() == source.Identity.Pid, "every line identity bound");
            }
            Check(!decoded.ToString().Contains(source.Identity.ImagePath, StringComparison.Ordinal), "private image path omitted");

            phase = "unsigned-byte-width-and-failures";
            source = new FakeMemory(); source.Set(4128, [0, 255, 170, 85]);
            var byteLow = Field("low", "u8", 4128); byteLow["min"] = 0; byteLow["max"] = 255;
            var byteHigh = Field("high", "u8", 4129);
            JsonObject ByteProfile(params JsonObject[] fs) => Profile(source, fs.Select(f => (JsonObject)f.DeepClone()).ToArray());
            var bytes = Capture(source, ByteProfile(byteLow, byteHigh));
            Check(Result(bytes, "low").GetProperty("value").GetRawText() == "0" &&
                Result(bytes, "high").GetProperty("value").GetRawText() == "255", "unsigned integer endpoints, not adjacent bytes");
            Check(source.Reads.Where(r => r.address is 4128 or 4129).All(r => r.size == 1) &&
                bytes.Lines[^1].GetProperty("planned_read_bytes_per_frame").GetInt32() == 10 &&
                bytes.Lines[^1].GetProperty("read_bytes").GetInt32() == 10, "one byte per value in plan and actual reads");
            source.ShortValues = true; bytes = Capture(source, ByteProfile(byteLow, byteHigh));
            Unknown(Result(bytes, "low"), "partial_read");
            Check(Result(bytes, "high").GetProperty("value").GetByte() == 255, "unrelated byte survives partial read");
            source.ShortValues = false; source.Failure = (a, _) => a == 4128 ? "unreadable_range" : null;
            bytes = Capture(source, ByteProfile(byteLow)); Unknown(Result(bytes, "low"), "unreadable_range");
            source.Failure = null; byteLow["min"] = 1; byteHigh["max"] = 254;
            bytes = Capture(source, ByteProfile(byteLow, byteHigh));
            Unknown(Result(bytes, "low"), "out_of_range"); Unknown(Result(bytes, "high"), "out_of_range");
            byteLow["min"] = 0; source.AfterRead = (a, _) => { if (a == 4128) source.Set(4096, [9, 0, 0, 0]); };
            bytes = Capture(source, ByteProfile(byteLow)); Unknown(Result(bytes, "low"), "guard_mismatch_after");
            source.AfterRead = null; int beforeReads = source.Reads.Count;
            bytes = Capture(source, ByteProfile(byteLow)); Unknown(Result(bytes, "low"), "guard_mismatch_before");
            Check(!source.Reads.Skip(beforeReads).Any(r => r.address == 4128), "failed byte pre-guard prevents value read");

            phase = "unsigned-byte-address-and-budget-boundaries";
            source = new FakeMemory(); source.Set((ulong)long.MaxValue, [255]);
            bytes = Capture(source, Profile(source, Field("last", "u8", (ulong)long.MaxValue)));
            Check(Result(bytes, "last").GetProperty("value").GetByte() == 255 &&
                source.Reads.Single(r => r.address == (ulong)long.MaxValue).size == 1, "last permitted address fits exactly one byte");
            Throws(() => Capture(source, Profile(source, Field("outside", "u8", (ulong)long.MaxValue + 1))), "invalid_field_profile");
            Throws(() => Capture(source, Profile(source, Field("too_wide", "i32", (ulong)long.MaxValue))), "invalid_field_profile");
            source = new FakeMemory(); source.Set(4128, [255]);
            bytes = Capture(source, Profile(source, Field("byte", "u8")), limits: new(ReadBytes: 9));
            Check(Result(bytes, "byte").GetProperty("value").GetByte() == 255, "exact guard-plus-one-byte budget permits frame");
            bytes = Capture(source, Profile(source, Field("byte", "u8")), limits: new(ReadBytes: 8));
            Unknown(Result(bytes, "byte"), "read_byte_limit");

            phase = "field-specific-guard-before";
            source = new FakeMemory(); var guarded = Field(); guarded["guards"] = new JsonArray(Guard(4100, "03000000"));
            var captured = Capture(source, Profile(source, guarded, Field("independent", "i32", 4132)));
            Unknown(Result(captured, "counter"), "guard_mismatch_before");
            Check(Result(captured, "independent").GetProperty("status").GetString() == "observed", "unrelated field survives local guard mismatch");
            Check(!source.Reads.Any(r => r.address == 4128), "failed pre-guard prevents field read");

            phase = "reuse-during-frame";
            source = new FakeMemory();
            source.AfterRead = (address, _) => { if (address == 4128) source.Set(4096, BitConverter.GetBytes(9)); };
            captured = Capture(source, Profile(source), 2, n => { if (n == 1) { source.AfterRead = null; source.Set(4096, BitConverter.GetBytes(1)); } });
            Unknown(Result(captured, "counter"), "guard_mismatch_after");
            Check(Result(captured, "counter", 1).GetProperty("value").GetInt32() == 7, "same-value recovery observed only after fresh successful guards");

            phase = "read-gap-and-recovery";
            source = new FakeMemory { Failure = (address, _) => address == 4128 ? "unreadable_range" : null };
            captured = Capture(source, Profile(source), 2, n => { if (n == 1) source.Failure = null; });
            Unknown(Result(captured, "counter"), "unreadable_range");
            Check(Result(captured, "counter", 1).GetProperty("value").GetInt32() == 7, "read-gap recovery");
            source = new FakeMemory { Failure = (_, call) => call == 1 ? "partial_read" : null };
            captured = Capture(source, Profile(source));
            Unknown(Result(captured, "counter"), "guard_read_before:partial_read");
            Check(!source.Reads.Any(r => r.address == 4128), "guard read gap prevents value read");

            source = new FakeMemory { ShortValues = true };
            captured = Capture(source, Profile(source));
            Unknown(Result(captured, "counter"), "partial_read");

            phase = "identity";
            source = new FakeMemory(); profile = Profile(source); source.Identity = source.Identity with { CreationFileTime = 10 };
            Throws(() => Capture(source, profile), "identity_mismatch");
            Check(source.Reads.Count == 0, "initial identity mismatch before memory reads");
            source = new FakeMemory(); profile = Profile(source);
            source.AfterRead = (address, _) => { if (address == 4128) source.Identity = source.Identity with { ExecutableSha256 = new string('c', 64) }; };
            captured = Capture(source, profile, count: 10);
            Unknown(Result(captured, "counter"), "identity_mismatch");
            Check(captured.Lines[^1].GetProperty("stop_reason").GetString() == "identity_mismatch", "mid-frame identity mismatch stops stream");
            Check(captured.Lines.Count == 2, "no subsequent frame after fatal identity mismatch");
            source = new FakeMemory { Failure = (address, _) => address == 4128 ? "permission_denied" : null };
            captured = Capture(source, Profile(source), count: 10);
            Unknown(Result(captured, "counter"), "permission_denied");
            Check(captured.Lines[^1].GetProperty("stop_reason").GetString() == "permission_denied" && source.Reads.Count == 2, "permission denial stops remaining reads");

            source = new FakeMemory { Failure = (address, _) => address == 4128 ? "process_exited" : null };
            captured = Capture(source, Profile(source), count: 10);
            Unknown(Result(captured, "counter"), "process_exited");
            Check(captured.Lines.Count == 2 && captured.Lines[^1].GetProperty("stop_reason").GetString() == "process_exited", "process exit terminal");

            phase = "nonfinite-and-range";
            source = new FakeMemory(); source.Set(4160, new[] { 1f, float.NaN, 3f }.SelectMany(BitConverter.GetBytes).ToArray());
            source.Set(4144, BitConverter.GetBytes(double.PositiveInfinity));
            var ranged = Field(); ranged["max"] = 6;
            captured = Capture(source, Profile(source, ranged, Field("vector", "f32x3", 4160), Field("double", "f64", 4144)));
            Unknown(Result(captured, "counter"), "out_of_range"); Unknown(Result(captured, "vector"), "non_finite"); Unknown(Result(captured, "double"), "non_finite");
            source.Set(4160, new[] { 1f, 20f, 3f }.SelectMany(BitConverter.GetBytes).ToArray());
            vector = Field("vector", "f32x3", 4160); vector["max"] = 10;
            captured = Capture(source, Profile(source, vector)); Unknown(Result(captured, "vector"), "out_of_range");

            phase = "profile-validation";
            source = new FakeMemory();
            void Invalid(Action<JsonObject> mutate, string code = "invalid_field_profile")
            { var bad = Profile(source); mutate(bad); Throws(() => Capture(source, bad), code); }
            Invalid(p => p["guards"] = new JsonArray());
            Invalid(p => p["unsupported"] = true);
            Invalid(p => p["fields"]![0]!["type"] = "pointer");
            Invalid(p => p["fields"]![0]!["address"] = ulong.MaxValue);
            Invalid(p => p["fields"]![0]!["name"] = "bad label");
            Invalid(p => { p["fields"]![0]!["min"] = 10; p["fields"]![0]!["max"] = 0; });
            Invalid(p => p["fields"] = new JsonArray(Field(), Field()));
            Invalid(p => p["fields"] = new JsonArray(Enumerable.Range(0, FieldStream.MaximumFields + 1).Select(i => (JsonNode)Field("f" + i)).ToArray()), "field_profile_limit");
            Invalid(p => p["guards"] = new JsonArray(Enumerable.Range(0, FieldStream.MaximumGuards + 1).Select(i => (JsonNode)Guard((ulong)(4096 + i * 4))).ToArray()), "field_profile_limit");
            Invalid(p => p["guards"] = new JsonArray(Enumerable.Range(0, FieldStream.MaximumGuards).Select(i => (JsonNode)Guard((ulong)(8192 + i * 64), new string('0', 128))).ToArray()), "field_profile_limit");
            Invalid(p => p["guards"]![0]!["bytes_hex"] = "012");
            Invalid(p => p["fields"]![0]!["guards"] = new JsonArray(Guard(4096, "02000000")));
            string duplicate = Input(Profile(source)); File.WriteAllText(duplicate, File.ReadAllText(duplicate).Replace("\"schema\":", "\"schema\":\"overwatch-decoder.field-profile/1\",\"schema\":"));
            Throws(() => FieldStream.Run(source, duplicate, 10, TimeSpan.FromSeconds(1), TextWriter.Null, default), "invalid_field_profile");
            string oversized = Path.Combine(root, "large.json"); File.WriteAllBytes(oversized, new byte[FieldStream.MaximumProfileBytes + 1]);
            Throws(() => FieldStream.Run(source, oversized, 10, TimeSpan.FromSeconds(1), TextWriter.Null, default), "field_profile_limit");

            phase = "cancellation";
            source = new FakeMemory(); captured = Capture(source, Profile(source), configure: c => c.Cancel());
            Check(source.Reads.Count == 0 && captured.Lines.Count == 1, "pre-cancel emits summary without reads");
            Check(captured.Lines[0].GetProperty("stop_reason").GetString() == "cancelled", "pre-cancel reason");
            source = new FakeMemory();
            captured = Capture(source, Profile(source), configure: c => source.AfterRead = (address, _) => { if (address == 4128) c.Cancel(); });
            Unknown(Result(captured, "counter"), "cancelled");
            Check(source.Reads.Count == 2, "mid-frame cancellation skips remaining reads");

            phase = "late-frames";
            source = new FakeMemory { FirstReadDelayMs = 120 };
            captured = Capture(source, Profile(source), count: 2);
            Check(captured.Lines.Count == 3, "sample-controlled completion survives slow start");
            Check(captured.Lines[1].GetProperty("scheduled_slot").GetInt64() >= 12, "late reads skip elapsed slots");
            Check(captured.Lines[1].GetProperty("skipped_intervals_before").GetInt64() >= 11, "skipped slots are explicit");
            Check(captured.Lines[^1].GetProperty("maximum_frame_ms").GetDouble() >= 100, "actual slow duration reported");
            source = new FakeMemory(); captured = Capture(source, Profile(source), count: 2, afterFrame: n => { if (n == 1) Thread.Sleep(70); });
            Check(captured.Lines[1].GetProperty("skipped_intervals_before").GetInt64() >= 6, "slow output does not queue catch-up reads");
            Check(captured.Lines[^1].GetProperty("maximum_write_ms").GetDouble() >= 60, "output backpressure time reported");

            phase = "resource-caps";
            source = new FakeMemory(); captured = Capture(source, Profile(source), count: 10, limits: new(ReadBytes: 8));
            Unknown(Result(captured, "counter"), "read_byte_limit");
            Check(source.Reads.Count == 2 && captured.Lines[^1].GetProperty("read_bytes").GetInt64() == 8, "read cap never exceeded");
            Check(captured.Lines[^1].GetProperty("stop_reason").GetString() == "read_byte_limit", "read cap terminal");
            source = new FakeMemory(); captured = Capture(source, Profile(source), count: 10, limits: new(OutputBytes: 8192));
            Check(captured.Lines.Count == 1 && captured.Lines[0].GetProperty("stop_reason").GetString() == "output_byte_limit", "output cap fails explicitly before oversized frame");
            Check(Encoding.UTF8.GetByteCount(captured.ToString()) <= 8192, "summary included within output cap");
            return assertions;
        }
        catch (ObservationException) { throw; }
        catch (Exception e)
        {
            var method = new StackTrace(e).GetFrame(0)?.GetMethod();
            throw new ObservationException("self_test_failed", $"field-stream:{phase}: {e.GetType().Name}; method={method?.DeclaringType?.Name}.{method?.Name}");
        }
        finally { Directory.Delete(root, true); }
    }
}
