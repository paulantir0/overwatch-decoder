using System.IO.Compression;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

/// <summary>Portable epoch-stop tests using synthetic guards; no process reads.</summary>
public static class FieldRecordingStopTests
{
    private sealed class Fixture : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(321, "fixture.exe", "private-test-path", 9, new string('b', 64), "x64");
        public bool Bad;
        public int Reads;
        public string? ValueError;
        public Action? OnRead;
        public byte[] Read(ulong address, int size)
        {
            Reads++; OnRead?.Invoke();
            if (address != 4096 && ValueError is { } error) throw new ObservationException(error, "Synthetic failed value.");
            return BitConverter.GetBytes(address == 4096 ? Bad ? 0 : 1 : 42);
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }

    public static int Run()
    {
        int assertions = 0, id = 0;
        void Check(bool ok, string message)
        {
            if (!ok) throw new ObservationException("self_test_failed", "field-recording-stop:" + message);
            assertions++;
        }
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-epoch-stop-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        (JsonElement manifest, JsonElement[] lines) Capture(Fixture source, CancellationToken token,
            Action<FieldStream.AcceptedFrame>? callback = null, bool enabled = false, TimeSpan? duration = null)
        {
            string profile = Path.Combine(root, "profile-" + id + ".json"), directory = Path.Combine(root, "recording-" + id++);
            File.WriteAllText(profile, JsonSerializer.Serialize(new
            {
                schema = "overwatch-decoder.field-profile/1", target = Snapshots.PublicIdentity(source.Identity),
                guards = new[] { new { address = 4096, bytes_hex = "01000000" } },
                fields = new[] { new { name = "value", type = "i32", address = 4128 } }
            }));
            var result = JsonSerializer.SerializeToElement(FieldRecording.RecordBounded(source, profile, directory, 10,
                duration ?? TimeSpan.FromSeconds(2), token, new(), callback, stopOnUnknown: enabled));
            var verification = FieldRecordingVerification.Verify(directory);
            Check(verification.valid && verification.terminal_summary_verified, "strict verification " + verification.error_code);
            using var file = File.OpenRead(Path.Combine(directory, "samples.jsonl.gz"));
            using var gzip = new GZipStream(file, CompressionMode.Decompress); using var reader = new StreamReader(gzip);
            var lines = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => JsonSerializer.Deserialize<JsonElement>(line)).ToArray();
            Check(lines[^1].GetProperty("stop_reason").GetString() == result.GetProperty("stop_reason").GetString(), "stored terminal matches manifest");
            Check(result.GetProperty("stream_summary").GetProperty("stop_reason").GetString() == result.GetProperty("stop_reason").GetString(), "returned terminal matches manifest");
            return (result, lines);
        }
        static string? Reason(JsonElement result) => result.GetProperty("stop_reason").GetString();
        static string? Status(JsonElement frame) => frame.GetProperty("fields").GetProperty("value").GetProperty("status").GetString();
        try
        {
            // Guard is restored in the callback for the unknown frame. A later read would succeed.
            var source = new Fixture(); int callbacks = 0;
            var stopped = Capture(source, CancellationToken.None, frame =>
            {
                callbacks++; source.Bad = frame.Sequence == 0;
            }, enabled: true);
            Check(callbacks == 2 && stopped.lines.Length == 3, "first unknown frame preserved, no later callback");
            Check(Status(stopped.lines[0]) == "observed" && Status(stopped.lines[1]) == "unknown", "observed then unknown");
            Check(!source.Bad && Reason(stopped.manifest) == "first_unknown" && !stopped.manifest.GetProperty("complete").GetBoolean(), "restored guard does not resume epoch");
            int readsAtStop = source.Reads;
            Check(BitConverter.ToInt32(source.Read(4096, 4)) == 1 && source.Reads == readsAtStop + 1, "would match after stop");

            using var normalStop = new CancellationTokenSource(); source = new Fixture(); callbacks = 0;
            var normal = Capture(source, normalStop.Token, frame =>
            {
                callbacks++; source.Bad = frame.Sequence == 0;
                if (frame.Sequence == 2) normalStop.Cancel();
            });
            Check(callbacks == 3 && normal.lines.Length == 4 && Status(normal.lines[2]) == "observed", "default continues after restored guard");
            Check(Reason(normal.manifest) == "cancelled", "default caller reason unchanged");

            using var before = new CancellationTokenSource(); before.Cancel(); source = new Fixture(); callbacks = 0;
            var zero = Capture(source, before.Token, _ => callbacks++, enabled: true);
            Check(zero.lines.Length == 1 && callbacks == 0 && source.Reads == 0, "pre-cancel zero accepted frames and reads");
            Check(Reason(zero.manifest) == "cancelled", "zero-frame cancellation not first unknown");

            using var during = new CancellationTokenSource(); source = new Fixture { Bad = true };
            source.OnRead = () => during.Cancel();
            var cancelled = Capture(source, during.Token, enabled: true);
            Check(Reason(cancelled.manifest) == "cancelled", "caller cancelled before unknown callback wins");

            using var after = new CancellationTokenSource(); source = new Fixture { Bad = true }; callbacks = 0;
            var triggered = Capture(source, after.Token, _ => { callbacks++; after.Cancel(); }, enabled: true);
            Check(callbacks == 1 && Reason(triggered.manifest) == "first_unknown", "accepted unknown trigger precedes external callback cancellation");

            var partial = Capture(new Fixture { ValueError = "partial_read" }, CancellationToken.None, enabled: true);
            Check(partial.lines.Length == 2 && Reason(partial.manifest) == "first_unknown", "unguarded value failure also ends epoch");
            var terminal = Capture(new Fixture { ValueError = "process_exited" }, CancellationToken.None, enabled: true);
            Check(terminal.lines.Length == 2 && Reason(terminal.manifest) == "process_exited", "explicit terminal error retained");

            var duration = Capture(new Fixture(), CancellationToken.None, enabled: true, duration: TimeSpan.FromMilliseconds(30));
            Check(Reason(duration.manifest) == "duration_elapsed" && duration.manifest.GetProperty("complete").GetBoolean(), "known duration completes normally");
        }
        finally { Directory.Delete(root, true); }
        return assertions;
    }
}
