using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Controlled in-process sources only; no target/game or network access.</summary>
public static class PointerPathTests
{
    private sealed class Memory : IMemorySource
    {
        public TargetIdentity Identity { get; set; } = new(321, "fixture.exe", "synthetic", 9, new string('b', 64), "x64");
        public readonly Dictionary<ulong, byte> Bytes = new();
        public readonly List<(ulong address, int size)> Reads = new();
        public Action<ulong>? After;
        public Func<ulong, string?>? Failure;
        public bool Partial;
        public void Set(ulong a, byte[] bytes) { for (int i = 0; i < bytes.Length; i++) Bytes[a + (ulong)i] = bytes[i]; }
        public void I(ulong a, int n) => Set(a, BitConverter.GetBytes(n));
        public void Ptr(ulong a, ulong n) => Set(a, BitConverter.GetBytes(n));
        public Memory()
        {
            I(0x800, 9); I(0x808, 99); I(0x1000, 1); Ptr(0x1010, 0x2000);
            foreach (ulong a in new ulong[] { 0x2000, 0x3000, 0x4000, 0x5000 })
            { I(a, 2); I(a + 8, a == 0x2000 ? 7 : 42); Set(a + 16, new[] { 1f, 2f, 3f }.SelectMany(BitConverter.GetBytes).ToArray()); }
        }
        public byte[] Read(ulong a, int size)
        {
            Reads.Add((a, size)); string? failure = Failure?.Invoke(a);
            if (failure is not null) throw new ObservationException(failure, "Synthetic failure");
            if (Enumerable.Range(0, size).Any(i => !Bytes.ContainsKey(a + (ulong)i))) throw new ObservationException("unreadable_range", "Synthetic missing bytes");
            byte[] bytes = Enumerable.Range(0, size).Select(i => Bytes[a + (ulong)i]).ToArray(); After?.Invoke(a);
            return Partial && a == 0x2008 ? bytes[..^1] : bytes;
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private sealed class Writer : StringWriter
    {
        public readonly List<JsonElement> Lines = new();
        public Action<JsonElement>? Frame;
        private readonly StringBuilder line = new();
        public override void Write(string? text) { base.Write(text); line.Append(text); }
        public override void Write(char c)
        {
            base.Write(c); if (c != '\n') { line.Append(c); return; }
            using var doc = JsonDocument.Parse(line.ToString()); var e = doc.RootElement.Clone(); Lines.Add(e); line.Clear();
            if (e.GetProperty("kind").GetString() == "frame") Frame?.Invoke(e);
        }
    }
    private static JsonObject Guard(string key, ulong offset, string bytes) => new() { [key] = offset, ["bytes_hex"] = bytes };
    private static JsonObject Hop(uint offset) => new() { ["pointer_offset"] = offset, ["destination_guards"] = new JsonArray(Guard("offset", 0, "02000000")) };
    private static JsonObject Profile(Memory memory) => new()
    {
        ["schema"] = "overwatch-decoder.field-profile/2", ["target"] = JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(memory.Identity)),
        ["guards"] = new JsonArray(Guard("address", 0x800, "09000000")),
        ["paths"] = new JsonArray(new JsonObject { ["name"] = "storage", ["root_address"] = 0x1000,
            ["root_guards"] = new JsonArray(Guard("offset", 0, "01000000")), ["hops"] = new JsonArray(Hop(16)) }),
        ["fields"] = new JsonArray(
            new JsonObject { ["name"] = "counter", ["type"] = "i32", ["path"] = "storage", ["offset"] = 8 },
            new JsonObject { ["name"] = "vector", ["type"] = "f32x3", ["path"] = "storage", ["offset"] = 16 },
            new JsonObject { ["name"] = "independent", ["type"] = "i32", ["address"] = 0x808 })
    };
    public static int Run()
    {
        int count = 0, input = 0; string phase = "setup";
        void Check(bool ok, string message)
        { if (!ok) throw new ObservationException("self_test_failed", "pointer-path:" + phase + ":" + message); count++; }
        void Throws(Action action, string code)
        { try { action(); } catch (ObservationException e) { Check(e.Code == code, "expected " + code + " got " + e.Code); return; } throw new ObservationException("self_test_failed", "pointer-path:" + phase + ":expected failure"); }
        string root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "overwatch-decoder-pointer-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string Input(JsonObject p) { string path = System.IO.Path.Combine(root, "p" + input++ + ".json"); File.WriteAllText(path, p.ToJsonString()); return path; }
        Writer Capture(Memory memory, JsonObject? p = null, int frames = 1, Action<int>? next = null,
            Action<CancellationTokenSource>? configure = null, FieldStream.Limits? limits = null)
        {
            using var cancel = new CancellationTokenSource(); configure?.Invoke(cancel); var w = new Writer(); int n = 0;
            w.Frame = _ => { n++; next?.Invoke(n); if (n >= frames) cancel.Cancel(); };
            FieldStream.RunBounded(memory, Input(p ?? Profile(memory)), 10, TimeSpan.FromSeconds(30), w, cancel.Token, limits ?? new());
            Check(w.Lines.Count > 0 && w.Lines[^1].GetProperty("kind").GetString() == "summary", "summary"); return w;
        }
        JsonElement Field(Writer w, string name, int index = 0)
        { Check(w.Lines.Count > index + 1, "required frame before indexing"); return w.Lines[index].GetProperty("fields").GetProperty(name); }
        void Unknown(Writer w, string name, int index = 0)
        { var f = Field(w, name, index); Check(f.GetProperty("status").GetString() == "unknown" && f.GetProperty("value").ValueKind == JsonValueKind.Null, "unknown has no stale value"); }
        void Value(Writer w, string name, int expected, int index = 0)
        { var f = Field(w, name, index); Check(f.GetProperty("status").GetString() == "observed" && f.GetProperty("value").GetInt32() == expected, "expected observed value"); }
        try
        {
            phase = "stable-shared-path"; var m = new Memory(); var w = Capture(m);
            Value(w, "counter", 7); Value(w, "independent", 99);
            Check(m.Reads.Count(r => r.address == 0x1010) == 2, "shared path one resolution and one reread");
            Check(w.Lines[0].GetProperty("schema").GetString() == "overwatch-decoder.field-stream/2" && w.Lines[0].GetProperty("private_address_trace").GetBoolean(), "version and privacy");
            Check(Field(w, "counter").GetProperty("read_address_hex").GetString() == "0000000000002008", "exact private address");
            Check(w.Lines[^1].GetProperty("read_bytes").GetInt64() == w.Lines[^1].GetProperty("planned_read_bytes_per_frame").GetInt64(), "plan includes all passes");

            phase = "unsigned-byte-path";
            m = new(); m.Set(0x2008, [0, 255, 170, 85]); var byteProfile = Profile(m);
            byteProfile["fields"] = new JsonArray(
                new JsonObject { ["name"] = "low", ["type"] = "u8", ["path"] = "storage", ["offset"] = 8 },
                new JsonObject { ["name"] = "high", ["type"] = "u8", ["path"] = "storage", ["offset"] = 9 });
            w = Capture(m, byteProfile); Value(w, "low", 0); Value(w, "high", 255);
            Check(m.Reads.Where(r => r.address is 0x2008 or 0x2009).All(r => r.size == 1), "path fields read one byte each");
            Check(w.Lines[^1].GetProperty("planned_read_bytes_per_frame").GetInt32() == 42 &&
                w.Lines[^1].GetProperty("read_bytes").GetInt32() == 42, "path byte plan and actual budget");
            m.Partial = true; w = Capture(m, byteProfile); Unknown(w, "low"); Value(w, "high", 255);
            Check(Field(w, "low").GetProperty("reason").GetString() == "partial_read", "one-byte short read is unknown");
            m.Partial = false; m.Failure = a => a == 0x2009 ? "unreadable_range" : null;
            w = Capture(m, byteProfile); Unknown(w, "high"); Value(w, "low", 0);
            m.Failure = null; byteProfile["fields"]![1]!["max"] = 254;
            w = Capture(m, byteProfile); Unknown(w, "high");
            Check(Field(w, "high").GetProperty("reason").GetString() == "out_of_range", "path byte range check");
            byteProfile["fields"]![1]!.AsObject().Remove("max");
            m.After = a => { if (a == 0x2008) m.I(0x2000, 9); };
            w = Capture(m, byteProfile); Unknown(w, "low"); Unknown(w, "high");
            Check(Field(w, "low").GetProperty("reason").GetString() == "path_guard_mismatch_after", "byte path destination guarded after read");

            phase = "unsigned-byte-path-final-address";
            m = new(); m.Ptr(0x1010, (ulong)long.MaxValue); m.Set((ulong)long.MaxValue, [255]); byteProfile = Profile(m);
            byteProfile["paths"]![0]!["hops"]![0]!["destination_guards"] = new JsonArray(Guard("offset", 0, "ff"));
            byteProfile["fields"] = new JsonArray(new JsonObject { ["name"] = "last", ["type"] = "u8", ["path"] = "storage", ["offset"] = 0 });
            w = Capture(m, byteProfile); Value(w, "last", 255);
            Check(m.Reads.Where(r => r.address == (ulong)long.MaxValue).Count() == 3 &&
                m.Reads.Where(r => r.address == (ulong)long.MaxValue).All(r => r.size == 1), "final byte holds both one-byte guards and field");
            byteProfile["fields"]![0]!["offset"] = 1;
            w = Capture(m, byteProfile); Unknown(w, "last");
            Check(Field(w, "last").GetProperty("reason").GetString() == "path_field_range" &&
                !m.Reads.Any(r => r.address > (ulong)long.MaxValue), "one byte past boundary is unknown without read");

            phase = "relocation-between-frames"; m = new(); w = Capture(m, frames: 2, next: n => { if (n == 1) m.Ptr(0x1010, 0x3000); });
            Value(w, "counter", 7); Value(w, "counter", 42, 1);
            Check(Field(w, "counter", 1).GetProperty("read_address_hex").GetString() == "0000000000003008", "new address recorded");

            phase = "midread-relocation"; m = new(); m.After = a => { if (a == 0x2008) m.Ptr(0x1010, 0x3000); }; w = Capture(m);
            Unknown(w, "counter"); Unknown(w, "vector"); Value(w, "independent", 99);
            Check(Field(w, "counter").GetProperty("reason").GetString() == "pointer_changed", "post-change reason");
            Check(!m.Reads.Any(r => r.address >= 0x3000), "postcheck never follows new pointer");

            phase = "destination-reuse"; m = new(); m.After = a => { if (a == 0x2008) m.I(0x2000, 3); }; w = Capture(m);
            Unknown(w, "counter"); Value(w, "independent", 99);
            Check(Field(w, "counter").GetProperty("reason").GetString() == "path_guard_mismatch_after", "destination guard rejected reuse");

            phase = "root-prevent-traversal"; m = new(); m.I(0x1000, 3); w = Capture(m);
            Unknown(w, "counter"); Value(w, "independent", 99); Check(!m.Reads.Any(r => r.address == 0x1010), "bad root prevents pointer read");

            phase = "null-recovery"; m = new(); m.Ptr(0x1010, 0); w = Capture(m, frames: 2, next: n => { if (n == 1) m.Ptr(0x1010, 0x3000); });
            Unknown(w, "counter"); Value(w, "counter", 42, 1); Check(!m.Reads.Any(r => r.address == 0), "no null dereference");

            phase = "gap-recovery"; m = new(); m.Failure = a => a == 0x1010 ? "unreadable_range" : null;
            w = Capture(m, frames: 2, next: n => { if (n == 1) m.Failure = null; }); Unknown(w, "counter"); Value(w, "independent", 99); Value(w, "counter", 7, 1);

            phase = "partial-field"; m = new() { Partial = true }; w = Capture(m); Unknown(w, "counter");
            Check(Field(w, "vector").GetProperty("status").GetString() == "observed", "field gap isolated from shared path");
            phase = "nonfinite-vector"; m = new(); m.Set(0x2014, BitConverter.GetBytes(float.NaN)); w = Capture(m); Unknown(w, "vector"); Value(w, "counter", 7);

            phase = "four-hop"; m = new(); m.Ptr(0x2020, 0x3000); m.Ptr(0x3020, 0x4000); m.Ptr(0x4020, 0x5000);
            var p = Profile(m); var hs = p["paths"]![0]!["hops"]!.AsArray(); hs.Add(Hop(32)); hs.Add(Hop(32)); hs.Add(Hop(32)); w = Capture(m, p); Value(w, "counter", 42);
            Check(w.Lines[0].GetProperty("path_traces")[0].GetProperty("hops").GetArrayLength() == 4, "four-hop evidence");
            phase = "intermediate-change-same-leaf"; m = new(); m.Ptr(0x2020, 0x4000); m.Ptr(0x3020, 0x4000); p = Profile(m); p["paths"]![0]!["hops"]!.AsArray().Add(Hop(32));
            m.After = a => { if (a == 0x4008) m.Ptr(0x1010, 0x3000); }; w = Capture(m, p); Unknown(w, "counter"); Value(w, "independent", 99);

            phase = "cycle"; m = new(); m.Ptr(0x1010, 0x1000); w = Capture(m); Unknown(w, "counter"); Check(Field(w, "counter").GetProperty("reason").GetString() == "pointer_cycle", "cycle reason");
            phase = "invalid-pointer"; m = new(); m.Ptr(0x1010, ulong.MaxValue); w = Capture(m); Unknown(w, "counter"); Check(!m.Reads.Any(r => r.address == ulong.MaxValue), "range prevents read");
            phase = "field-overflow"; m = new(); m.Ptr(0x1010, (ulong)long.MaxValue - 3); m.I((ulong)long.MaxValue - 3, 2); w = Capture(m); Unknown(w, "counter");
            Check(Field(w, "counter").GetProperty("reason").GetString() == "path_field_range", "checked field range");

            phase = "fatal"; m = new(); m.Failure = a => a == 0x1010 ? "permission_denied" : null; w = Capture(m); Unknown(w, "counter"); Unknown(w, "independent");
            Check(m.Reads[^1].address == 0x1010 && w.Lines[^1].GetProperty("stop_reason").GetString() == "permission_denied", "fatal stops reads");
            phase = "cancel-mid-hop"; m = new(); w = Capture(m, configure: c => m.After = a => { if (a == 0x1010) c.Cancel(); });
            Unknown(w, "counter"); Check(m.Reads[^1].address == 0x1010 && w.Lines[^1].GetProperty("stop_reason").GetString() == "cancelled", "cancel no child read");
            phase = "cancel-postcheck"; m = new(); int guardReads = 0;
            w = Capture(m, configure: c => m.After = a => { if (a == 0x2000 && ++guardReads == 2) c.Cancel(); });
            Unknown(w, "counter"); Unknown(w, "independent"); Check(m.Reads[^1].address == 0x2000, "postcheck cancellation stops before pointer reread");
            phase = "identity-changed"; m = new(); m.After = a => { if (a == 0x2008) m.Identity = m.Identity with { Pid = 999 }; }; w = Capture(m);
            Unknown(w, "counter"); Unknown(w, "independent"); Check(w.Lines[^1].GetProperty("stop_reason").GetString() == "identity_mismatch", "end identity invalidates whole frame");
            phase = "cancel-pre-start"; m = new(); w = Capture(m, configure: c => c.Cancel()); Check(m.Reads.Count == 0 && w.Lines.Count == 1, "pre-start summary only");
            phase = "budget"; m = new(); w = Capture(m, limits: new(ReadBytes: 1)); Unknown(w, "counter"); Check(m.Reads.Count == 0 && w.Lines[^1].GetProperty("stop_reason").GetString() == "read_byte_limit", "budget before read");
            phase = "slow-read-skips"; m = new(); bool delayed = false; m.After = _ => { if (!delayed) { delayed = true; Thread.Sleep(70); } }; w = Capture(m, frames: 3);
            Check(w.Lines[^1].GetProperty("skipped_intervals").GetInt64() > 0 && w.Lines[^1].GetProperty("frames").GetInt64() == 3, "slow frames skip not catch up");

            phase = "aba-limitation"; m = new(); m.After = a => { if (a == 0x2008) { m.Ptr(0x1010, 0x3000); m.Ptr(0x1010, 0x2000); } }; w = Capture(m); Value(w, "counter", 7); // Explicitly cannot prove this transition absent.
            phase = "malformed";
            foreach (Action<JsonObject> mutate in new Action<JsonObject>[] {
                x => x["fields"]![0]!["address"] = 1,
                x => x["paths"]![0]!["root_guards"] = new JsonArray(),
                x => x["paths"]![0]!["hops"]![0]!["destination_guards"] = new JsonArray(),
                x => x["fields"]![0]!["path"] = "missing",
                x => x["paths"]![0]!["hops"]![0]!["unknown"] = true,
                x => x["target"]!["architecture"] = "x86",
                x => x["paths"]![0]!["root_guards"]!.AsArray().Add(Guard("offset", 1, "ff")),
                x => x["paths"]![0]!["hops"]![0]!["destination_guards"]!.AsArray().Add(Guard("offset", 1, "ff")) })
            { m = new(); p = Profile(m); mutate(p); Throws(() => FieldStream.Run(m, Input(p), 10, TimeSpan.FromSeconds(1), new StringWriter(), default), "invalid_field_profile"); Check(m.Reads.Count == 0, "invalid profile no reads"); }
            phase = "caps"; m = new(); p = Profile(m); p["paths"]![0]!["hops"]![0]!["pointer_offset"] = PointerPaths.MaximumOffset + 1;
            Throws(() => FieldStream.Run(m, Input(p), 10, TimeSpan.FromSeconds(1), new StringWriter(), default), "field_profile_limit");
            p = Profile(m); for (int i = 0; i < 4; i++) p["paths"]![0]!["hops"]!.AsArray().Add(Hop(32));
            Throws(() => FieldStream.Run(m, Input(p), 10, TimeSpan.FromSeconds(1), new StringWriter(), default), "field_profile_limit");
            p = Profile(m); for (int i = 0; i < 32; i++) { var clone = p["paths"]![0]!.DeepClone(); clone["name"] = "p" + i; p["paths"]!.AsArray().Add(clone); }
            Throws(() => FieldStream.Run(m, Input(p), 10, TimeSpan.FromSeconds(1), new StringWriter(), default), "field_profile_limit");
            p = Profile(m); p["guards"] = new JsonArray(Guard("address", 0x800, new string('0', 128)));
            p["paths"]![0]!["root_guards"] = new JsonArray(Guard("offset", 0, new string('0', 128)));
            var large = new JsonArray(); for (int i = 0; i < 254; i++) large.Add(Guard("offset", (ulong)(i * 64), new string('0', 128)));
            p["paths"]![0]!["hops"]![0]!["destination_guards"] = large;
            Throws(() => FieldStream.Run(m, Input(p), 10, TimeSpan.FromSeconds(1), new StringWriter(), default), "field_profile_limit");
            phase = "identity"; m = new(); p = Profile(m); p["target"]!["pid"] = 999;
            Throws(() => FieldStream.Run(m, Input(p), 10, TimeSpan.FromSeconds(1), new StringWriter(), default), "identity_mismatch"); Check(m.Reads.Count == 0, "identity no reads");

            phase = "record-verify";
            string Record(string name, bool mutate = false)
            {
                var source = new Memory(); using var cancel = new CancellationTokenSource(); int values = 0;
                source.After = address =>
                {
                    if (address is not (0x2008 or 0x3008)) return;
                    values++;
                    if (mutate && values == 1) source.Ptr(0x1010, 0x3000);
                    if (values == 3) cancel.Cancel();
                };
                // A generous duration watchdog; all normal stopping is sample-controlled.
                string dir = System.IO.Path.Combine(root, name);
                FieldRecording.RecordBounded(source, Input(Profile(source)), dir, 10, TimeSpan.FromSeconds(30), cancel.Token, new(ChunkBytes: 8192)); return dir;
            }
            string recording = Record("record"); var verify = FieldRecordingVerification.Verify(recording);
            Check(verify.valid && !verify.complete && verify.frames == 3 && verify.unknown_fields == 3, "v2 stopped recording verified with final unknowns");
            var badRecord = Record("failed-path", true); var pathResult = FieldRecordingVerification.Verify(badRecord); Check(pathResult.valid && pathResult.unknown_fields == 5, "midframe changed path then recovery evidence verifies");
            foreach (var item in new (string label, string code, Action<JsonObject> change)[] {
                ("pointer", "path_postcheck_failed", x => x["path_traces"]![0]!["hops"]![0]!["pointer_after"]!["bytes_hex"] = "0030000000000000"),
                ("fieldaddress", "field_path_address_mismatch", x => x["fields"]!["counter"]!["read_address_hex"] = "0000000000003008"),
                ("missingpost", "malformed_recording", x => x["path_traces"]![0]!["hops"]![0]!.AsObject().Remove("pointer_after")),
                ("privacy", "missing_private_trace_label", x => x["private_address_trace"] = false),
                ("timeorder", "read_time_order", x => x["path_traces"]![0]!["hops"]![0]!["pointer_after"]!["start_ticks"] = 0) })
            {
                string dir = System.IO.Path.Combine(root, item.label); Copy(recording, dir); Rewrite(dir, item.change);
                var result = FieldRecordingVerification.Verify(dir); Check(!result.valid && result.status == "invalid" && result.error_code == item.code, "tampered trace rejected " + item.label + ":" + result.error_code);
            }
            phase = "recovery";
            void TruncatedMember(string layout, int member, string label)
            {
                string partial = System.IO.Path.Combine(root, "partial-" + label); Copy(layout, partial);
                string[] indexLines = File.ReadAllLines(System.IO.Path.Combine(layout, "chunks.jsonl"));
                var entry = JsonNode.Parse(indexLines[member])!.AsObject();
                long offset = entry["offset"]!.GetValue<long>(), size = entry["compressed_bytes"]!.GetValue<long>();
                long prefixLines = entry["first_line"]!.GetValue<long>();
                // The terminal member can hold only the summary. Its loss must preserve all three frames,
                // including the final cancelled unknowns, without claiming a complete recording.
                long expectedFrames = Math.Min(prefixLines, 3);
                string sample = System.IO.Path.Combine(partial, "samples.jsonl.gz");
                using (var file = File.OpenWrite(sample)) file.SetLength(offset + size - 1);
                var strict = FieldRecordingVerification.Verify(partial);
                var recovery = FieldRecordingVerification.Verify(partial, true);
                string detail = $"{label}:member={member},prefixLines={prefixLines},actual={recovery.status}/{recovery.error_code},frames={recovery.frames},chunks={recovery.verified_chunks}";
                Check(!strict.valid && !strict.complete && strict.status == "invalid" && strict.error_code == "truncated_member", "strict truncated member rejected:" + detail);
                Check(!recovery.valid && !recovery.complete && recovery.error_code == "truncated_member" &&
                    recovery.status == (member > 0 ? "recoverable_prefix" : "invalid") && recovery.recoverable == (member > 0), "recovery status:" + detail);
                Check(!recovery.terminal_summary_verified && recovery.verified_chunks == member && recovery.verified_lines == prefixLines &&
                    recovery.frames == expectedFrames && recovery.unknown_fields == (expectedFrames == 3 ? 3 : 0), "exact whole-member prefix counts:" + detail);
                Check(recovery.verified_compressed_bytes == offset && recovery.samples_prefix_sha256 == Hash(File.ReadAllBytes(sample)[..checked((int)offset)]) &&
                    recovery.index_prefix_sha256 == Hash(Encoding.UTF8.GetBytes(string.Concat(indexLines.Take(member).Select(x => x + "\n")))), "exact prefix hashes:" + detail);
                Check(recovery.unverified_compressed_bytes == size - 1 && recovery.unverified_index_bytes > 0, "damaged suffix accounted:" + detail);
            }
            // Natural boundaries depend on line lengths and checkpoint timing; use the actual index as the oracle.
            TruncatedMember(recording, File.ReadAllLines(System.IO.Path.Combine(recording, "chunks.jsonl")).Length - 1, "writer-tail");
            string split = System.IO.Path.Combine(root, "one-line-members"); Copy(recording, split); Rewrite(split, null, true);
            var splitResult = FieldRecordingVerification.Verify(split);
            Check(splitResult.valid && splitResult.frames == 3 && splitResult.verified_chunks == 4, "controlled one-line member layout verifies before corruption");
            // Deterministically cover loss of the first member, frame-bearing suffixes and the summary-only tail.
            for (int member = 0; member < 4; member++) TruncatedMember(split, member, "split-" + member);
            return count;
        }
        finally { Directory.Delete(root, true); }
    }
    private static void Copy(string from, string to)
    { Directory.CreateDirectory(to); foreach (string p in Directory.EnumerateFiles(from)) File.Copy(p, System.IO.Path.Combine(to, System.IO.Path.GetFileName(p))); }
    // Rebuild all cryptographic hashes after intentional semantic tampering, so tests exercise trace validation.
    private static void Rewrite(string directory, Action<JsonObject>? change, bool oneLinePerMember = false)
    {
        string sample = System.IO.Path.Combine(directory, "samples.jsonl.gz"), index = System.IO.Path.Combine(directory, "chunks.jsonl");
        var entries = File.ReadAllLines(index).Select(x => JsonNode.Parse(x)!.AsObject()).ToArray(); byte[] original = File.ReadAllBytes(sample);
        using var output = new MemoryStream(); var lines = new List<string>(); long jsonBytes = 0, totalLines = 0; bool changed = false;
        foreach (var entry in entries)
        {
            int offset = entry["offset"]!.GetValue<int>(), size = entry["compressed_bytes"]!.GetValue<int>();
            using var input = new MemoryStream(original, offset, size); using var gz = new GZipStream(input, CompressionMode.Decompress); using var raw = new MemoryStream(); gz.CopyTo(raw);
            byte[] decoded = raw.ToArray();
            if (!changed && change is not null)
            {
                var records = Encoding.UTF8.GetString(decoded).Split('\n'); var first = JsonNode.Parse(records[0])!.AsObject(); change(first); records[0] = first.ToJsonString(); decoded = Encoding.UTF8.GetBytes(string.Join('\n', records)); changed = true;
            }
            var parts = new List<byte[]>();
            if (oneLinePerMember)
            {
                // Keep exact UTF-8 line bytes and timestamps; only controlled gzip boundaries change.
                int start = 0;
                for (int i = 0; i < decoded.Length; i++)
                    if (decoded[i] == (byte)'\n') { parts.Add(decoded[start..(i + 1)]); start = i + 1; }
                if (start != decoded.Length) throw new InvalidDataException("Synthetic chunk has a partial line.");
            }
            else parts.Add(decoded);
            foreach (byte[] part in parts)
            {
                using var encoded = new MemoryStream(); using (var zip = new GZipStream(encoded, CompressionLevel.Fastest, true)) zip.Write(part);
                byte[] bytes = encoded.ToArray(); var row = (JsonObject)entry.DeepClone();
                row["sequence"] = lines.Count; row["first_line"] = totalLines; row["lines"] = part.Count(b => b == (byte)'\n');
                row["offset"] = output.Length; row["compressed_bytes"] = bytes.Length; row["json_bytes"] = part.Length;
                row["compressed_sha256"] = Hash(bytes); row["json_sha256"] = Hash(part); output.Write(bytes); jsonBytes += part.Length;
                totalLines += row["lines"]!.GetValue<int>(); lines.Add(row.ToJsonString());
            }
        }
        File.WriteAllBytes(sample, output.ToArray()); File.WriteAllText(index, string.Join('\n', lines) + "\n");
        string path = System.IO.Path.Combine(directory, "manifest.json"); var manifest = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        manifest["durable_chunks"] = lines.Count; manifest["durable_lines"] = totalLines;
        manifest["durable_compressed_bytes"] = output.Length; manifest["durable_json_bytes"] = jsonBytes; manifest["index_bytes"] = new FileInfo(index).Length;
        manifest["samples_sha256"] = Hash(output.ToArray()); manifest["durable_samples_prefix_sha256"] = Hash(output.ToArray());
        manifest["index_sha256"] = Hash(File.ReadAllBytes(index)); manifest["durable_index_prefix_sha256"] = Hash(File.ReadAllBytes(index)); File.WriteAllText(path, manifest.ToJsonString());
    }
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}
