using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

/// <summary>Windows-only test of ordinary native reads from a separately launched, owned child.</summary>
internal static class PointerPathNativeTests
{
    internal sealed record Result(int Assertions, int Frames, int UnknownFrames, int Relocations, int RecordingFrames, bool RecordingVerified, int ByteObservations);
    private sealed class Writer : StringWriter
    {
        internal Action<JsonElement>? Frame;
        private readonly StringBuilder line = new();
        public override void Write(string? text) { line.Append(text); }
        public override void Write(char c)
        {
            if (c != '\n') { line.Append(c); return; }
            using var doc = JsonDocument.Parse(line.ToString()); line.Clear();
            if (doc.RootElement.GetProperty("kind").GetString() == "frame") Frame?.Invoke(doc.RootElement);
        }
    }
    // Observes completed native reads only to end a test after enough samples, never supplies synthetic bytes.
    private sealed class SampleStop(NativeMemory memory, CancellationTokenSource cancel, ulong independent) : IMemorySource
    {
        private int samples;
        public TargetIdentity Identity => memory.Identity;
        public IEnumerable<MemoryRegion> Regions() => memory.Regions();
        public void EnsureAlive() => memory.EnsureAlive();
        public byte[] Read(ulong address, int size)
        {
            byte[] result = memory.Read(address, size);
            if (size == 4 && address != independent && ++samples == 3) cancel.Cancel();
            return result;
        }
        public void Dispose() { } // Caller owns the native source.
    }
    internal static Result Run(bool batched = false)
    {
        int assertions = 0, frames = 0, unknown = 0, stage = 0, relocations = 0, byteObservations = 0;
        void Check(bool ok, string name)
        { if (!ok) throw new ObservationException("self_test_failed", "native-pointer-path:" + name); assertions++; }
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException();
        var info = new ProcessStartInfo(executable) { RedirectStandardInput = true, RedirectStandardOutput = true,
            RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) info.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
        info.ArgumentList.Add("fixture-pointers"); info.ArgumentList.Add("--seconds"); info.ArgumentList.Add("60");
        using var child = Process.Start(info) ?? throw new InvalidOperationException();
        string directory = Path.Combine(Path.GetTempPath(), "overwatch-decoder-native-pointer-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            string? ready = child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
            using var descriptor = JsonDocument.Parse(ready ?? "{}"); JsonElement d = descriptor.RootElement.GetProperty("result");
            Check(d.GetProperty("schema").GetString() == "overwatch-decoder.pointer-fixture/1" && d.GetProperty("pid").GetInt32() == child.Id, "child descriptor identity");
            ulong root = d.GetProperty("root_address").GetUInt64(); using var memory = new NativeMemory(child.Id);
            Directory.CreateDirectory(directory); string path = Path.Combine(directory, "profile.json");
            File.WriteAllText(path, JsonSerializer.Serialize(new
            {
                schema = "overwatch-decoder.field-profile/2", target = Snapshots.PublicIdentity(memory.Identity),
                guards = new[] { new { address = root, bytes_hex = Convert.ToHexStringLower(PointerFixture.Magic) } },
                paths = new[] { new { name = "owned_storage", root_address = root,
                    root_guards = new[] { new { offset = 0, bytes_hex = Convert.ToHexStringLower(PointerFixture.Magic) } },
                    hops = new[] { new { pointer_offset = PointerFixture.PointerOffset,
                        destination_guards = new[] { new { offset = 0, bytes_hex = Convert.ToHexStringLower(PointerFixture.Magic) } } } } } },
                fields = new object[] { new { name = "candidate", type = "i32", path = "owned_storage", offset = PointerFixture.ValueOffset, min = 7, max = 42 },
                    new { name = "candidate_byte", type = "u8", path = "owned_storage", offset = PointerFixture.ValueOffset, min = 7, max = 42 },
                    new { name = "independent", type = "i32", address = root + PointerFixture.IndependentOffset } }
            }));
            if (batched)
            {
                var profile = JsonNode.Parse(File.ReadAllText(path))!.AsObject(); profile["schema"] = "overwatch-decoder.field-profile/3";
                profile["absolute_guard_reads"] = new JsonObject { ["algorithm"] = GuardBatches.Algorithm };
                JsonArray Split(string key, ulong origin) => new(
                    new JsonObject { [key] = origin, ["bytes_hex"] = Convert.ToHexStringLower(PointerFixture.Magic.AsSpan(0, 2)) },
                    new JsonObject { [key] = origin + 4, ["bytes_hex"] = Convert.ToHexStringLower(PointerFixture.Magic.AsSpan(4, 4)) });
                profile["guards"] = Split("address", root); profile["paths"]![0]!["root_guards"] = Split("offset", 0);
                File.WriteAllText(path, profile.ToJsonString());
            }
            void Command(string command) { child.StandardInput.WriteLine(command); child.StandardInput.Flush(); }
            using var cancel = new CancellationTokenSource(); var writer = new Writer(); var leaves = new HashSet<string>();
            writer.Frame = frame =>
            {
                if (batched)
                {
                    var pre = frame.GetProperty("guard_batches_before"); var post = frame.GetProperty("guard_batches_after");
                    Check(pre.GetArrayLength() == 1 && post.GetArrayLength() == 1 &&
                        pre[0].GetProperty("requested_bytes").GetInt32() == 8 && pre[0].GetProperty("guard_count").GetInt32() == 2 &&
                        pre[0].GetProperty("returned_bytes").GetInt32() == 8 && frame.GetProperty("guard_gap_read_bytes").GetInt32() == 4,
                        "native v3 two logical slices use one complete physical read per pass with two gap bytes");
                }
                frames++; var field = frame.GetProperty("fields").GetProperty("candidate"); var other = frame.GetProperty("fields").GetProperty("independent");
                Check(other.GetProperty("status").GetString() == "observed" && other.GetProperty("value").GetInt32() == 99, "independent field survives path transitions");
                bool observed = field.GetProperty("status").GetString() == "observed";
                var byteField = frame.GetProperty("fields").GetProperty("candidate_byte");
                Check(byteField.GetProperty("status").GetString() == field.GetProperty("status").GetString(), "native byte follows the same guarded path status");
                if (observed)
                {
                    Check(byteField.GetProperty("type").GetString() == "u8" && byteField.GetProperty("value").GetByte() == field.GetProperty("value").GetInt32(),
                        "native pointer byte matches unchanged child allocation value");
                    byteObservations++;
                }
                if (observed) leaves.Add(field.GetProperty("read_address_hex").GetString()!); else unknown++;
                if (stage == 0 && observed && field.GetProperty("value").GetInt32() == 7) { Command("b"); stage++; }
                else if (stage == 1 && observed && field.GetProperty("value").GetInt32() == 42) { relocations++; Command("null"); stage++; }
                else if (stage == 2 && !observed && field.GetProperty("reason").GetString() == "pointer_null") { Command("bad"); stage++; }
                else if (stage == 3 && !observed && field.GetProperty("reason").GetString() == "path_guard_mismatch_before") { Command("a"); stage++; }
                else if (stage == 4 && observed && field.GetProperty("value").GetInt32() == 7) { relocations++; stage++; cancel.Cancel(); }
            };
            FieldStream.Run(memory, path, 10, TimeSpan.FromSeconds(20), writer, cancel.Token);
            Check(stage == 5 && relocations == 2 && leaves.Count == 2 && unknown >= 2, "native relocation null bad-guard and recovery observed");
            using var recordCancel = new CancellationTokenSource(); using var source = new SampleStop(memory, recordCancel, root + PointerFixture.IndependentOffset);
            string recording = Path.Combine(directory, "recording");
            var manifest = JsonSerializer.SerializeToElement(FieldRecording.Record(source, path, recording, 10, TimeSpan.FromSeconds(20), recordCancel.Token));
            var verified = FieldRecordingVerification.Verify(recording);
            Check(verified.valid && !verified.complete && verified.status == "verified_stopped" && verified.frames == 3 && verified.unknown_fields == 3,
                "native compressed v2 recording verifies with final cancelled unknowns");
            Check(manifest.GetProperty("private_address_trace").GetBoolean() && manifest.GetProperty("stream_summary").GetProperty("frames").GetInt32() == 3,
                "native manifest privacy and sample count");
            if (batched)
            {
                var summary = manifest.GetProperty("stream_summary");
                Check(summary.GetProperty("published_frame_read_calls").GetInt64() == summary.GetProperty("read_calls").GetInt64() &&
                    summary.GetProperty("unpublished_frame_read_calls").GetInt32() == 0, "native v3 recorded physical counts exact");
                string sparse = Path.Combine(directory, "changes.jsonl");
                Check(FieldTimeline.Export(recording, sparse).frames == 3 && FieldSummary.Summarize(recording).GetProperty("frames").GetInt32() == 3,
                    "native v3 summary and change timeline verify the original buffers");
            }
            string compact = Path.Combine(directory, "timeline.jsonl"); var exported = FieldExport.Export(recording, compact);
            Check(exported.frames == 3 && exported.source_status == "verified_stopped" && exported.unknown_fields == 3,
                "native u8 path recording exports with original stopped status and unknowns");
            int exportedBytes = 0;
            foreach (string row in File.ReadLines(compact))
            {
                using var frame = JsonDocument.Parse(row);
                if (frame.RootElement.GetProperty("kind").GetString() != "frame") continue;
                var b = frame.RootElement.GetProperty("fields").GetProperty("candidate_byte");
                if (b.GetProperty("status").GetString() != "observed") continue;
                Check(b.GetProperty("type").GetString() == "u8" && b.GetProperty("value").GetByte() == 7, "native recorded pointer byte remains exact in compact output");
                exportedBytes++;
            }
            Check(exportedBytes == 2, "both native pre-cancellation byte frames exported");
            Command("stop"); Check(child.WaitForExit(5000) && child.ExitCode == 0, "child stops cleanly");
            return new(assertions, frames, unknown, relocations, (int)verified.frames, verified.valid, byteObservations);
        }
        finally
        {
            if (!child.HasExited) { child.Kill(); child.WaitForExit(5000); }
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }
}
