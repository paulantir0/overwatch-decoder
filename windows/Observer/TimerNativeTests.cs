using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

internal static class TimerNativeTests
{
    internal sealed record Result(int Assertions, long Frames, bool Verified);
    private sealed class Counted(NativeMemory memory, ulong guard, CancellationTokenSource stop) : IMemorySource
    {
        private int guardReads;
        public TargetIdentity Identity => memory.Identity;
        public byte[] Read(ulong address, int size)
        { byte[] bytes = memory.Read(address, size); if (address == guard && ++guardReads == 6) stop.Cancel(); return bytes; }
        public void EnsureAlive() => memory.EnsureAlive();
        public IEnumerable<MemoryRegion> Regions() => memory.Regions();
        public void Dispose() { }
    }
    private sealed class Writer(CancellationTokenSource stop) : StringWriter
    {
        private readonly StringBuilder pending = new();
        internal JsonElement? Frame { get; private set; }
        public override void Write(string? value) => pending.Append(value);
        public override void Write(char c)
        {
            if (c != '\n') { pending.Append(c); return; }
            using var doc = JsonDocument.Parse(pending.ToString()); pending.Clear();
            if (doc.RootElement.GetProperty("kind").GetString() == "frame") { Frame = doc.RootElement.Clone(); stop.Cancel(); }
        }
    }
    internal static Result Run()
    {
        int assertions = 0;
        void Check(bool ok, string why) { if (!ok) throw new ObservationException("self_test_failed", "native-timer:" + why); assertions++; }
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException();
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) info.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
        info.ArgumentList.Add("fixture-timer"); info.ArgumentList.Add("--seconds"); info.ArgumentList.Add("60");
        using var child = Process.Start(info) ?? throw new InvalidOperationException();
        string output = Path.Combine(Path.GetTempPath(), "overwatch-decoder-native-timer-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(output);
        try
        {
            string? ready = child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
            using var descriptor = JsonDocument.Parse(ready ?? "{}"); var d = descriptor.RootElement.GetProperty("result");
            Check(d.GetProperty("schema").GetString() == "overwatch-decoder.timer-fixture/1" && d.GetProperty("pid").GetInt32() == child.Id, "owned child identity");
            ulong guard = d.GetProperty("guard_address").GetUInt64(), state = d.GetProperty("state_address").GetUInt64(), clock = d.GetProperty("clock_address").GetUInt64();
            using var memory = new NativeMemory(child.Id); string profile = Path.Combine(output, "profile.json");
            File.WriteAllText(profile, TimerTests.Profile(memory.Identity, guard, state, clock).ToJsonString());
            Check(guard / 4096 != (guard + 3) / 4096, "real cross-page exact guard");
            var first = Capture(); Check(first.GetProperty("value").GetDouble() == 11, "native calculated result");
            var operands = first.GetProperty("operands");
            Check(operands.GetProperty("state").GetProperty("bytes_hex").GetString() == Convert.ToHexStringLower(TimerTests.State(1000, 12, 1)), "native raw state");
            Check(operands.GetProperty("clock").GetProperty("bytes_hex").GetString() == Convert.ToHexStringLower(BitConverter.GetBytes(2000L)), "native raw counter");
            Command("backstep"); Wait(() => BitConverter.ToInt64(memory.Read(clock, 8)) == 1985);
            Check(Capture().GetProperty("value").GetDouble() > 11, "native backstep remains visible");
            string recording = Path.Combine(output, "recording");
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                FieldRecording.Record(new Counted(memory, guard, stop), profile, recording, 10, TimeSpan.FromSeconds(30), stop.Token);
            var verified = FieldRecordingVerification.Verify(recording);
            Check(verified.valid && verified.frames == 3 && verified.unknown_fields == 1, "native strict recording: " + verified.error_code);
            FieldExport.Export(recording, Path.Combine(output, "compact.jsonl")); FieldTimeline.Export(recording, Path.Combine(output, "timeline.jsonl"));
            Check(FieldSummary.Summarize(recording).GetProperty("fields")[0].GetProperty("timing_kind").GetString() == "operand_envelope", "native summary timing");
            Command("bad"); Wait(() => memory.Read(guard, 4).All(b => b == 0));
            var unknown = Capture(); Check(unknown.GetProperty("status").GetString() == "unknown" && unknown.GetProperty("value").ValueKind == JsonValueKind.Null, "native changed guard");
            Check(!unknown.GetProperty("operands").GetProperty("state").GetProperty("attempted").GetBoolean(), "native failed guard prevents operand read");
            Command("stop"); Check(child.WaitForExit(5000), "owned fixture cleanup");
            return new(assertions, verified.frames, verified.valid);
            JsonElement Capture()
            {
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)); var writer = new Writer(stop);
                FieldStream.Run(memory, profile, 10, TimeSpan.FromSeconds(30), writer, stop.Token);
                Check(writer.Frame is not null, "native frame required before indexing"); return writer.Frame!.Value.GetProperty("fields").GetProperty("timer");
            }
            void Command(string command) { child.StandardInput.WriteLine(command); child.StandardInput.Flush(); }
            void Wait(Func<bool> predicate)
            { var wait = Stopwatch.StartNew(); while (!predicate()) { if (wait.Elapsed > TimeSpan.FromSeconds(5)) throw new ObservationException("self_test_failed", "native-timer:fixture transition timeout"); Thread.Sleep(10); } }
        }
        finally
        {
            if (!child.HasExited) { try { child.StandardInput.WriteLine("stop"); child.StandardInput.Flush(); } catch (IOException) { } if (!child.WaitForExit(2000)) { child.Kill(entireProcessTree: true); child.WaitForExit(5000); } }
            Directory.Delete(output, true);
        }
    }
}
