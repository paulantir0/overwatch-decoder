// Standalone synthetic runner: compile with the two capture sources and NAudio.Wasapi3.3.0.
// Portable harness: net10.0 console, DefineConstants=CAPTURE_PORTABLE_TEST, link these3sources,
// PackageReference NAudio.Wasapi3.3.0. The conditional minimal WinForms stubs exercise decoder/queue logic;
// these tests do NOT establish native registration, focus polling or audio-device support.
// Production integration: net10.0-windows + UseWindowsForms; one InputCapture on UI thread;
// emit callback must enqueue only, be thread-safe, and account for its own bounded queue drops.
// Start/Stop/Dispose input on creating UI thread. Await audio.StopAsync before closing JSONL.
// Audio captures default system render output (no microphone), may include other applications.
// Default endpoint is selected at Start; device changes/errors end this optional source.
// Top-level QPC means callback/message arrival. Audio device_qpc_100ns is separate WASAPI capture
// time and null when timestamp_error; neither establishes exact output presentation time.
// Foreground gating is checked at processing time; polling cannot reconstruct historical focus.
// Native smoke required: target/not-target typing, alt-tab with held key, mouse/wheel, stop/restart,
// callback overload, silent/playback audio, endpoint failure, finalized WAV and offset metadata.
using System.Buffers.Binary;
using System.Reflection;
using System.Text.Json;
using OverwatchDecoder.SessionRecorder;
using NAudio.Wave;

internal static class InputAudioTests
{
    private static int checks;
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; }
    private static object? Call(object instance, string name, params object[] args) => instance.GetType()
        .GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(instance, args);
    private static void Set(object instance, string name, object value) => instance.GetType()
        .GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(instance, value);
    public static async Task Main()
    {
        foreach (int header in new[] { 16, 24 })
        {
            byte[] key = new byte[header + 16]; BinaryPrimitives.WriteUInt32LittleEndian(key, 1);
            BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(4), (uint)key.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(key.AsSpan(header), 0x1d);
            BinaryPrimitives.WriteUInt16LittleEndian(key.AsSpan(header + 2), 3);
            BinaryPrimitives.WriteUInt16LittleEndian(key.AsSpan(header + 6), 0x11);
            var k = InputCapture.DecodePacket(key, header)!;
            Check(k.Type == 1 && k.Flags == 3 && k.ScanCode == 0x1d && k.VirtualKey == 0x11, "keyboard scan/up/extended");
            Check(InputCapture.DecodePacket(key.AsSpan(0, key.Length - 1), header) is null, "truncated declared length rejected");
            key[0] = 2; Check(InputCapture.DecodePacket(key, header) is null, "HID ignored");
            byte[] mouse = new byte[header + 24]; BinaryPrimitives.WriteUInt32LittleEndian(mouse.AsSpan(4), (uint)mouse.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(mouse.AsSpan(header), 3);
            BinaryPrimitives.WriteUInt16LittleEndian(mouse.AsSpan(header + 4), 0xc01);
            BinaryPrimitives.WriteInt16LittleEndian(mouse.AsSpan(header + 6), -120);
            BinaryPrimitives.WriteInt32LittleEndian(mouse.AsSpan(header + 12), -37);
            BinaryPrimitives.WriteInt32LittleEndian(mouse.AsSpan(header + 16), 12345);
            var m = InputCapture.DecodePacket(mouse, header)!;
            Check(m.Type == 0 && m.Flags == 3 && m.X == -37 && m.Y == 12345 && m.ButtonData == -120 && m.ButtonFlags == 0xc01, "mouse native alignment/signed wheel/coordinates");
        }
        Check(InputCapture.DecodePacket([], 24) is null, "empty rejected");
        Check(InputCapture.DecodePacket(new byte[48], 20) is null, "invalid architecture header rejected");
        Check(!InputCapture.CanProcess(false, 1000, 0, 0), "background never accepted");
        Check(!InputCapture.CanProcess(true, 1049, 1000, 0), "focus gain settling suppressed");
        Check(!InputCapture.CanProcess(true, 2000, 1000, 251), "stale queued input suppressed");
        Check(!InputCapture.CanProcess(true, 1050, 1000, 1), "queued event before settling boundary rejected");
        Check(InputCapture.CanProcess(true, 1050, 1000, 0), "event exactly at settling boundary accepted");
        Check(!InputCapture.CanProcess(true, 1100, 1000, 51), "old event remains rejected after settling elapsed");
        Check(InputCapture.CanProcess(true, 1300, 1000, 250), "maximum age accepted at exact event boundary");
        Check(!InputCapture.CanProcess(true, 1299, 1000, 250), "maximum age rejected one millisecond before event boundary");
        Check(!InputCapture.CanProcess(true, 999, 1000, 0), "future focus gain rejected");
        const long wrappedNow = (1L << 32) + 100;
        uint wrappedAge = unchecked((uint)wrappedNow - 0xfffffff0U);
        Check(wrappedAge == 116, "message age subtraction spans uint uptime wrap");
        Check(InputCapture.CanProcess(true, wrappedNow, (1L << 32) - 66, wrappedAge), "wrapped event exactly at focus boundary accepted");
        Check(!InputCapture.CanProcess(true, wrappedNow, (1L << 32) - 65, wrappedAge), "wrapped event before focus boundary rejected");
        Check(InputCapture.GateRejectionReason(true, 1049, 1000, 0) == "focus_settling", "settling rejection is distinct");
        Check(InputCapture.GateRejectionReason(true, 1100, 1000, 51) == "message_predates_focus_settling_boundary", "queued pre-boundary message is distinct");
        Check(InputCapture.GateRejectionReason(true, 2000, 1000, 251) == "message_age_exceeded", "old input rejection is distinct");
        Check(InputCapture.GateRejectionReason(true, 999, 1000, 0) == "focus_time_order_unknown", "invalid focus clock ordering is distinct");
        Check(InputCapture.GateRejectionReason(true, 1050, 1000, 0) is null, "diagnostics preserve accepted boundary");
        var reasonEvents = new List<JsonElement>();
        using (var diagnosed = new InputCapture(123, e => reasonEvents.Add(JsonSerializer.SerializeToElement(e))))
        {
            Call(diagnosed, "Drop", "focus_settling", new { message_age_ms = 0, receipt_uptime_ms = 1001 });
            Call(diagnosed, "Drop", "focus_settling", new { message_age_ms = 1, receipt_uptime_ms = 1002 });
            Call(diagnosed, "Drop", "raw_packet_unsupported_or_invalid", new { returned_bytes = 24 });
            Call(diagnosed, "Publish", "test", new { });
            var gap = reasonEvents[0]; var reasons = gap.GetProperty("reasons").EnumerateArray().ToArray();
            Check(gap.GetProperty("count").GetInt64() == 3 && gap.GetProperty("total").GetInt64() == 3 && diagnosed.DroppedEvents == 3, "classified losses preserve exact aggregate accounting");
            Check(gap.GetProperty("reason").GetString() == "multiple_reasons" && reasons.Length == 2 && reasons.Sum(r => r.GetProperty("count").GetInt64()) == 3, "fixed reason ledger groups counts without erasing causes");
            Check(reasons[0].GetProperty("reason").GetString() == "focus_settling" && reasons[0].GetProperty("count").GetInt64() == 2, "repeated policy discards remain recorded gaps");
            Check(reasons[0].GetProperty("first_context").GetProperty("receipt_uptime_ms").GetInt64() == 1001 && reasons[0].GetProperty("last_context").GetProperty("receipt_uptime_ms").GetInt64() == 1002, "first and last timing context retained");
            Check(reasons.All(r => r.GetProperty("first_drop_qpc_ticks").GetInt64() <= r.GetProperty("last_drop_qpc_ticks").GetInt64() && r.GetProperty("last_drop_qpc_ticks").GetInt64() <= gap.GetProperty("qpc_ticks").GetInt64()), "actual discard bounds precede deferred notification");
            Call(diagnosed, "Publish", "test", new { });
            Check(reasonEvents.Count == 3 && reasonEvents[2].GetProperty("kind").GetString() == "test", "successful gap report clears only pending evidence");
        }
        bool rejectGap = true; var retryEvents = new List<JsonElement>();
        using (var diagnosed = new InputCapture(123, e => { if (rejectGap) throw new IOException("fixture callback"); retryEvents.Add(JsonSerializer.SerializeToElement(e)); }))
        {
            Call(diagnosed, "Drop", "focus_settling", null!);
            Call(diagnosed, "Publish", "test", new { });
            rejectGap = false; Call(diagnosed, "Publish", "test", new { });
            var reasons = retryEvents[0].GetProperty("reasons").EnumerateArray().ToArray();
            Check(diagnosed.DroppedEvents == 2 && retryEvents[0].GetProperty("count").GetInt64() == 2, "failed gap emission preserves original loss and adds callback failure");
            Check(reasons.Select(r => r.GetProperty("reason").GetString()).SequenceEqual(new[] { "focus_settling", "emit_callback_failure" }), "callback failure does not reclassify original packet");
        }
        var events = new List<JsonElement>(); bool failCallback = true;
        var input = new InputCapture(123, e => { if (failCallback) throw new IOException("sink"); events.Add(JsonSerializer.SerializeToElement(e)); });
        Call(input, "Publish", "test", new { }); Check(input.DroppedEvents == 1, "callback failure accounted");
        failCallback = false; Call(input, "Publish", "test", new { });
        Check(events.Count == 2 && events[0].GetProperty("kind").GetString() == "input_dropped", "drop reported before next event");
        Check(events[1].GetProperty("qpc_frequency").GetInt64() > 0, "QPC serialized"); input.Dispose();

        var audioEvents = new List<JsonElement>();
        using var audio = new LoopbackAudioCapture(Path.GetTempPath(), e => audioEvents.Add(JsonSerializer.SerializeToElement(e)));
        Set(audio, "accepting", 1);
        for (int i = 0; i < 65; i++) audio.AcceptAudio(new byte[8], 0, i, i*1000);
        Check(audio.DroppedBytes == 8, "bounded64packet queue accounts overflow");
        var stream = new MemoryStream(); var format = WaveFormat.CreateIeeeFloatWaveFormat(48000, 2);
        var writer = new WaveFileWriter(stream, format);
        var writing = (Task)Call(audio, "WritePackets", writer, format, stream)!; Set(audio, "writerTask", writing);
        await audio.StopAsync(); await writing;
        Check(audio.BytesWritten == 512, "queued audio drained");
        Check(!stream.CanWrite, "drained audio closes caller-owned stream");
        byte[] wav = stream.ToArray(); using var read = new WaveFileReader(new MemoryStream(wav));
        Check(read.Length == 512 && read.WaveFormat.SampleRate == 48000 && read.WaveFormat.Channels == 2, "finalized WAV roundtrip");
        var chunks = audioEvents.Where(e => e.GetProperty("kind").GetString() == "audio_chunk").ToArray();
        Check(chunks.Length == 64 && chunks[^1].GetProperty("data").GetProperty("pcm_byte_offset").GetInt64() == 504, "audio offset/arrival metadata");
        bool restartRejected = false; try { audio.Start(); } catch (InvalidOperationException) { restartRejected = true; }
        Check(restartRejected, "stop before/restart rejected");
        using var silent = new LoopbackAudioCapture(Path.GetTempPath(), e => audioEvents.Add(JsonSerializer.SerializeToElement(e)));
        Set(silent, "accepting", 1); silent.AcceptAudio([255,255,255,255,255,255,255,255], 6, 17, 99);
        var silentStream = new MemoryStream();
        Set(silent, "writerTask", (Task)Call(silent, "WritePackets", new WaveFileWriter(silentStream, format), format, silentStream)!);
        await silent.StopAsync();
        using var silentReader = new WaveFileReader(new MemoryStream(silentStream.ToArray()));
        var sample = new byte[8]; Check(silentReader.Read(sample,0,8)==8 && sample.All(b=>b==0), "silent packet undefined bytes zeroed");
        var silentEvent = audioEvents.Last(e=>e.GetProperty("kind").GetString()=="audio_chunk").GetProperty("data");
        Check(silentEvent.GetProperty("device_qpc_100ns").ValueKind==JsonValueKind.Null && silentEvent.GetProperty("timestamp_error").GetBoolean(), "invalid device timestamp not asserted");
        using var bad = new LoopbackAudioCapture(Path.GetTempPath(), _ => {});
        Set(bad, "accepting", 1); bad.AcceptAudio([1,2,3], 0, 0, 0);
        var badStream = new MemoryStream();
        Set(bad, "writerTask", (Task)Call(bad, "WritePackets", new WaveFileWriter(badStream, format), format, badStream)!);
        await bad.StopAsync();
        Check(bad.BytesWritten==0 && bad.DroppedBytes==3 && bad.Error is not null, "unaligned packet fails and reports loss");
        Check(!badStream.CanWrite, "packet failure still closes caller-owned stream");
        using var failingAudio = new LoopbackAudioCapture(Path.GetTempPath(), _ => throw new IOException("sink"));
        await failingAudio.StopAsync(); Check(failingAudio.CallbackFailures == 1, "audio callback failure observable");
        await AudioStreamOwnership(format);
        Console.WriteLine($"PASS {checks} synthetic capture checks; no native Windows/audio-device operations");
    }

    private static async Task AudioStreamOwnership(WaveFormat format)
    {
        string directory = Path.Combine(Path.GetTempPath(), "overwatch-decoder-audio-ownership-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            byte[]? firstWave = null;
            for (int session = 0; session < 2; session++)
            {
                string path = Path.Combine(directory, $"session-{session}.wav");
                var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536, FileOptions.SequentialScan);
                var handle = file.SafeFileHandle;
                bool stoppedAfterClose = false;
                using var audio = new LoopbackAudioCapture(directory, e =>
                {
                    if (JsonSerializer.SerializeToElement(e).GetProperty("kind").GetString() == "audio_stopped")
                        stoppedAfterClose = handle.IsClosed;
                });
                Set(audio, "accepting", 1);
                byte[] pcm = Enumerable.Repeat((byte)(session + 1), 16 + session * 8).ToArray();
                audio.AcceptAudio(pcm, 0, 0, 0);
                Set(audio, "writerTask", (Task)Call(audio, "WritePackets", new WaveFileWriter(file, format), format, file)!);
                await audio.StopAsync();
                Check(handle.IsClosed && stoppedAfterClose, "each session closes file before audio_stopped without GC");
                using (var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                using (var reader = new WaveFileReader(exclusive))
                {
                    var actual = new byte[pcm.Length];
                    Check(reader.Length == pcm.Length && reader.Read(actual, 0, actual.Length) == actual.Length && actual.SequenceEqual(pcm),
                        "each stopped session supports exclusive reopen and exact finalized PCM");
                }
                if (session == 0) firstWave = File.ReadAllBytes(path);
                else Check(File.ReadAllBytes(Path.Combine(directory, "session-0.wav")).SequenceEqual(firstWave!), "later session preserves prior WAV");
                audio.Dispose();
                Check(handle.IsClosed && audio.Error is null, "repeated stop/dispose retains clean closed file");
            }
        }
        finally { Directory.Delete(directory, recursive: true); }

        foreach (var failures in new[] { (Header: true, Close: false), (Header: false, Close: true), (Header: true, Close: true) })
        {
            var events = new List<JsonElement>();
            using var audio = new LoopbackAudioCapture(Path.GetTempPath(), e => events.Add(JsonSerializer.SerializeToElement(e)));
            var stream = new FaultingAudioStream();
            var writer = new WaveFileWriter(stream, format);
            Set(audio, "accepting", 1); audio.AcceptAudio(new byte[8], 0, 0, 0);
            Set(audio, "writerTask", (Task)Call(audio, "WritePackets", writer, format, stream)!);
            stream.ThrowOnHeaderSeek = failures.Header; stream.ThrowOnClose = failures.Close;
            await audio.StopAsync();
            Check(stream.DisposeCalls == 1 && !stream.CanWrite, "owned stream closes exactly once even when header finalization fails");
            var operations = events.Where(e => e.GetProperty("kind").GetString() == "audio_error")
                .Select(e => e.GetProperty("data").GetProperty("operation").GetString()).ToArray();
            Check(operations.SequenceEqual(failures.Header ? (failures.Close ? new[] { "wav_finalize", "wav_close" } : new[] { "wav_finalize" }) : new[] { "wav_close" }),
                "header and close failures reported separately in order");
            Check(audio.Error == (failures.Header ? "IOException: injected header seek failure" : "IOException: injected stream close failure"),
                "first finalization or close error preserved");
            var stopped = events.Single(e => e.GetProperty("kind").GetString() == "audio_stopped").GetProperty("data");
            Check(!stopped.GetProperty("wav_finalized").GetBoolean() && stopped.GetProperty("error").GetString() == audio.Error,
                "failed finalization or close cannot publish clean stop");
            audio.Dispose(); Check(stream.DisposeCalls == 1, "repeated disposal does not retry failed finalization");
        }
    }

    private sealed class FaultingAudioStream : MemoryStream
    {
        public bool ThrowOnHeaderSeek { get; set; }
        public bool ThrowOnClose { get; set; }
        public int DisposeCalls { get; private set; }
        public override long Seek(long offset, SeekOrigin origin)
        {
            if (ThrowOnHeaderSeek) throw new IOException("injected header seek failure");
            return base.Seek(offset, origin);
        }
        public override long Position
        {
            get => base.Position;
            set
            {
                if (ThrowOnHeaderSeek) throw new IOException("injected header seek failure");
                base.Position = value;
            }
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeCalls++;
            base.Dispose(disposing);
            if (disposing && ThrowOnClose) throw new IOException("injected stream close failure");
        }
    }
}

#if CAPTURE_PORTABLE_TEST
// Test doubles are compiled ONLY by the portable synthetic harness, never the Windows recorder.
namespace System.Windows.Forms
{
    public class NativeWindow
    {
        public nint Handle { get; protected set; }
        protected void CreateHandle(CreateParams p) { }
        protected void DestroyHandle() { }
        protected virtual void WndProc(ref Message m) { }
    }
    public class CreateParams { public string? Caption { get; set; } public nint Parent { get; set; } }
    public struct Message { public int Msg; public nint LParam; }
    public class Timer : IDisposable
    {
        public int Interval { get; set; }
#pragma warning disable CS0067
        public event EventHandler? Tick;
#pragma warning restore CS0067
        public void Start() { }
        public void Stop() { }
        public void Dispose() { }
    }
}
#endif
