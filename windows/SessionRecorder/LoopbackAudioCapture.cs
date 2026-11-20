using System.Diagnostics;
using System.Threading.Channels;
using NAudio.Wave;

namespace OverwatchDecoder.SessionRecorder;

/// <summary>Optional default render-endpoint loopback, never microphone capture.</summary>
public sealed class LoopbackAudioCapture : IDisposable
{
    private const int MaximumPacketBytes = 1024 * 1024;
    private const long MaximumQueuedBytes = 8 * 1024 * 1024, MaximumWaveDataBytes = 0xe0000000;
    private readonly string outputDirectory;
    private readonly Action<object> emit;
    private readonly Channel<Packet> packets = Channel.CreateBounded<Packet>(new BoundedChannelOptions(64)
    { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false });
    private readonly object lifecycle = new();
    private WasapiRecorder? capture;
    private Task? writerTask, stopTask;
    private long bytesWritten, droppedBytes, queuedBytes, callbackFailures;
    private int started, accepting;
    private bool disposed;
    private string? error;
    private sealed record Packet(byte[] Bytes, long ArrivalTicks, int Flags, long DevicePosition, long DeviceQpc100ns);
    public long BytesWritten => Interlocked.Read(ref bytesWritten);
    public long DroppedBytes => Interlocked.Read(ref droppedBytes);
    public long CallbackFailures => Interlocked.Read(ref callbackFailures);
    public string? Error => Volatile.Read(ref error);

    public LoopbackAudioCapture(string outputDirectory, Action<object> emit)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        this.outputDirectory = Path.GetFullPath(outputDirectory);
        this.emit = emit ?? throw new ArgumentNullException(nameof(emit));
    }

    public void Start()
    {
        lock (lifecycle)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (stopTask is not null) throw new InvalidOperationException("Stopped audio capture cannot restart.");
            if (Interlocked.Exchange(ref started, 1) != 0) throw new InvalidOperationException("Audio capture is single-use.");
            // Construct without the WinForms SynchronizationContext: native stop notifications must
            // never depend on a UI thread blocked in Dispose. Capture callbacks only copy/enqueue.
            try { Task.Run(Initialize).GetAwaiter().GetResult(); }
            catch (Exception e)
            {
                Volatile.Write(ref accepting, 0); Fail("start", e); packets.Writer.TryComplete();
                if (capture is not null) { capture.Dispose(); capture = null; }
                writerTask?.GetAwaiter().GetResult();
                throw;
            }
        }
    }

    private void Initialize()
    {
        Directory.CreateDirectory(outputDirectory);
        capture = new WasapiRecorderBuilder().WithLoopbackCapture().Build();
        WaveFormat format = capture.WaveFormat;
        // CreateNew is essential: a later session must never truncate an earlier recording.
        var file = new FileStream(Path.Combine(outputDirectory, "system-audio.wav"), FileMode.CreateNew,
            FileAccess.Write, FileShare.Read, 65536, FileOptions.SequentialScan);
        WaveFileWriter writer;
        try { writer = new WaveFileWriter(file, format); } catch { file.Dispose(); throw; }
        writerTask = Task.Run(() => WritePackets(writer, format, file));
        capture.DataAvailable += (data, flags, devicePosition, qpcPosition) => AcceptAudio(data, (int)flags, devicePosition, qpcPosition);
        capture.RecordingStopped += (_, e) =>
        {
            Volatile.Write(ref accepting, 0);
            if (e.Exception is not null) Fail("capture", e.Exception);
            packets.Writer.TryComplete();
        };
        Publish("audio_started", new { source = "wasapi_default_render_loopback", microphone = false,
            scope = "system_sound_not_process_isolated", sample_rate = format.SampleRate, channels = format.Channels,
            bits_per_sample = format.BitsPerSample, block_align = format.BlockAlign,
            average_bytes_per_second = format.AverageBytesPerSecond, encoding = format.Encoding.ToString(),
            format_bytes_hex = FormatBytes(format), file = "system-audio.wav", queue_capacity_packets = 64,
            maximum_queued_bytes = MaximumQueuedBytes,
            timing = "callback QPC is arrival; separate WASAPI capture QPC uses100ns units and is invalid when timestamp_error; not exact output presentation" });
        Volatile.Write(ref accepting, 1); capture.StartRecording();
    }

    internal void AcceptAudio(ReadOnlySpan<byte> data, int flags, long devicePosition, long qpcPosition)
    {
        long ticks = Stopwatch.GetTimestamp();
        int count = data.Length;
        if (count <= 0) return;
        if (Volatile.Read(ref accepting) == 0) { Drop(count, ticks, "not_accepting"); return; }
        if (count > MaximumPacketBytes || Interlocked.Add(ref queuedBytes, count) > MaximumQueuedBytes)
        {
            if (count <= MaximumPacketBytes) Interlocked.Add(ref queuedBytes, -count);
            Drop(count, ticks, "queue_or_packet_limit"); return;
        }
        try
        {
            var copy = new byte[count]; if ((flags & 2) == 0) data.CopyTo(copy); // SILENT packet contents are undefined.
            if (packets.Writer.TryWrite(new Packet(copy, ticks, flags, devicePosition, qpcPosition))) return;
        }
        catch (Exception ex) { Fail("copy", ex); }
        Interlocked.Add(ref queuedBytes, -count); Drop(count, ticks, "queue_full_or_closed");
    }

    private async Task WritePackets(WaveFileWriter writer, WaveFormat format, Stream ownedStream)
    {
        bool failed = false;
        try
        {
            await foreach (Packet packet in packets.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                Interlocked.Add(ref queuedBytes, -packet.Bytes.Length);
                if (failed) { Drop(packet.Bytes.Length, packet.ArrivalTicks, "writer_failed"); continue; }
                try
                {
                    if (BytesWritten + packet.Bytes.Length > MaximumWaveDataBytes) throw new IOException("Bounded WAV size limit reached.");
                    if (packet.Bytes.Length % format.BlockAlign != 0) throw new InvalidDataException("Audio packet is not sample-frame aligned.");
                    long offset = BytesWritten; writer.Write(packet.Bytes, 0, packet.Bytes.Length);
                    Interlocked.Add(ref bytesWritten, packet.Bytes.Length);
                    Publish("audio_chunk", new { callback_qpc_ticks = packet.ArrivalTicks,
                        pcm_byte_offset = offset, bytes = packet.Bytes.Length,
                        sample_frames = packet.Bytes.Length / format.BlockAlign,
                        device_frame_position = packet.DevicePosition, device_qpc_100ns = (packet.Flags & 4) == 0 ? (long?)packet.DeviceQpc100ns : null,
                        timestamp_error = (packet.Flags & 4) != 0, data_discontinuity = (packet.Flags & 1) != 0, silent = (packet.Flags & 2) != 0,
                        timing = "arrival QPC and WASAPI capture QPC100ns are distinct; no exact output presentation claim" });
                }
                catch (Exception ex)
                {
                    failed = true; Volatile.Write(ref accepting, 0);
                    Drop(packet.Bytes.Length, packet.ArrivalTicks, "write_failure"); Fail("write", ex);
                }
            }
        }
        finally
        {
            try { writer.Dispose(); } catch (Exception ex) { Fail("wav_finalize", ex); }
            finally
            {
                // NAudio's stream constructor leaves the caller-owned stream open after
                // finalizing the header. Close it even if finalization failed, before stop completes.
                try { ownedStream.Dispose(); } catch (Exception ex) { Fail("wav_close", ex); }
            }
        }
    }

    public Task StopAsync()
    {
        lock (lifecycle) return stopTask ??= StopCoreAsync();
    }
    private async Task StopCoreAsync()
    {
        // Do not hold the UI synchronization context while the capture thread joins or disk drains.
        try
        {
            if (capture is not null) await Task.Run(capture.StopRecording).ConfigureAwait(false);
        }
        catch (Exception ex) { Fail("stop", ex); }
        finally
        {
            Volatile.Write(ref accepting, 0); packets.Writer.TryComplete();
            if (writerTask is not null) await writerTask.ConfigureAwait(false);
            try { capture?.Dispose(); } catch (Exception ex) { Fail("dispose", ex); }
            capture = null;
            Publish("audio_stopped", new { bytes_written = BytesWritten, dropped_bytes = DroppedBytes,
                callback_failures = CallbackFailures, error = Error, wav_finalized = Error is null });
        }
    }
    private void Drop(long count, long ticks, string reason)
    {
        Interlocked.Add(ref droppedBytes, count);
        Publish("audio_gap", new { callback_qpc_ticks = ticks, dropped_bytes = count, total_dropped_bytes = DroppedBytes,
            reason, duration_unknown = true, file_gap_policy = "omitted_bytes_not_silence_padded" });
    }
    private void Fail(string operation, Exception ex)
    {
        Interlocked.CompareExchange(ref error, ex.GetType().Name + ": " + ex.Message, null);
        Publish("audio_error", new { operation, message = ex.Message });
    }
    private void Publish(string kind, object data)
    {
        try { emit(new { kind, qpc_ticks = Stopwatch.GetTimestamp(), qpc_frequency = Stopwatch.Frequency, data }); }
        catch { Interlocked.Increment(ref callbackFailures); }
    }
    private static string FormatBytes(WaveFormat format)
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream);
        format.Serialize(writer); return Convert.ToHexStringLower(stream.ToArray());
    }
    public void Dispose()
    {
        lock (lifecycle) { if (disposed) return; disposed = true; }
        StopAsync().GetAwaiter().GetResult(); GC.SuppressFinalize(this);
    }
}
