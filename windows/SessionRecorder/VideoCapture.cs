using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OverwatchDecoder.SessionRecorder;

/// <summary>One owned FFmpeg desktop-capture child. No hooks, elevation or software encoder fallback.</summary>
public sealed class VideoCapture : IAsyncDisposable
{
    internal const int StartTimeoutMs = 15000, GracefulStopMs = 8000, KillWaitMs = 2000, DrainWaitMs = 2000;
    internal const int MaximumLineCharacters = 8192;
    internal const long MaximumLogBytes = 64L * 1024 * 1024;
    private readonly string ffmpegPath, outputDirectory, encoder;
    private readonly int displayIndex;
    private readonly Action<object> emit;
    private readonly Func<ProcessStartInfo, Process>? fixtureStart;
    private readonly object gate = new();
    private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource drainStop = new();
    private Process? process;
    private Task? stderrTask, stdoutTask, monitorTask, stopTask;
    private BoundedLog? stderrLog, progressLog, framesLog;
    private CancellationTokenRegistration cancellationRegistration;
    private string state = "created", priority = "not_attempted";
    private string? error, priorityError;
    private bool started, stopRequested, qSent, killed, progressEnd, truncated, timestampInvalid, timeBaseConfirmed;
    private long launchBefore, launchAfter, lastReceipt, sourceFrames, progressFrames;
    private long? firstPts, lastPts, epochUpper;
    private int? width, height, exitCode, processId;
    private long logBytes;

    public VideoCapture(string ffmpegPath, string outputDirectory, int displayIndex, Action<object> emit,
        string encoder = "h264_amf") : this(ffmpegPath, outputDirectory, displayIndex, emit, encoder, null) { }

    // The seam can start only a caller-supplied synthetic child in portable tests; production always checks Windows.
    internal VideoCapture(string ffmpegPath, string outputDirectory, int displayIndex, Action<object> emit,
        string encoder, Func<ProcessStartInfo, Process>? fixtureStart)
    {
        if (displayIndex is < 0 or > 255) throw new ArgumentOutOfRangeException(nameof(displayIndex));
        if (encoder is not ("h264_amf" or "h264_nvenc" or "h264_qsv")) throw new ArgumentException("Unsupported hardware encoder.", nameof(encoder));
        this.ffmpegPath = Path.GetFullPath(ffmpegPath); this.outputDirectory = Path.GetFullPath(outputDirectory);
        this.displayIndex = displayIndex; this.emit = emit ?? throw new ArgumentNullException(nameof(emit));
        this.encoder = encoder; this.fixtureStart = fixtureStart;
    }

    public object Summary => Snapshot();
    public string? Error { get { lock (gate) return error; } }
    public int? ProcessId { get { lock (gate) return processId; } }
    public bool IsRunning { get { lock (gate) return process is not null && exitCode is null; } }
    public object Snapshot()
    {
        lock (gate) return new
        {
            schema = "overwatch-decoder.video-capture/1", state, error, display_index = displayIndex, encoder,
            hardware_encoder_requested = true, hardware_runtime_verified = false, software_encoder_fallback = false,
            cpu_color_conversion = encoder == "h264_amf", gpu_readback = encoder == "h264_amf",
            video_file = "desktop.mkv", container = "matroska", requested_maximum_fps = 30, target_bitrate = 6000000,
            native_display_size_requested = true, width, height, process_id = processId, exit_code = exitCode,
            priority, priority_error = priorityError, stop_requested = stopRequested, graceful_q_sent = qSent,
            forced_kill = killed, progress_end_received = progressEnd, source_frames_logged = sourceFrames,
            encoded_progress_frames = progressFrames, first_source_pts_us = firstPts, last_source_pts_us = lastPts,
            last_progress_receipt_qpc = lastReceipt, qpc_frequency = Stopwatch.Frequency,
            process_launch_before_qpc = launchBefore, process_launch_after_qpc = launchAfter,
            source_pts_epoch_qpc_lower_bound = launchBefore == 0 ? (long?)null : launchBefore - TimestampRoundingMargin(Stopwatch.Frequency),
            source_pts_epoch_qpc_upper_bound = epochUpper, source_pts_bounds_valid = !timestampInvalid && epochUpper >= launchBefore,
            source_pts_mapping = "bounded_unknown_epoch_not_exact_first_frame", source_clock_build_verified = false, visible_calibration_required_for_tighter_sync = true,
            source_time_base_confirmed_microseconds = timeBaseConfirmed,
            synchronization = "ddagrab source PTS is relative to a private first_pts. QPC epoch lies between launch-before and min(source-frame-log receipt QPC minus source PTS), conditional on the verified FFmpeg source clock. Receipt includes unknown buffering. Use visible calibration intervals for tighter offline matching. Muxed PTS and build correspondence require verification.",
            presentation_time_exact = false, first_frame_qpc_exact = false, muxed_timestamps_verified = false,
            captured_content_may_precede_source_pts = true, duplicated_source_frames_possible = true,
            log_bytes = logBytes, logs_truncated = truncated, maximum_each_log_bytes = MaximumLogBytes,
            maximum_duration_seconds = 36000, maximum_video_bytes = 64L * 1024 * 1024 * 1024,
            media_verified = false,
            note = "Progress counts and a successful FFmpeg exit do not independently verify media. MKV clusters improve partial recovery; forced stop can lose the tail. No game state or visibility semantics are inferred."
        };
    }

    internal static ProcessStartInfo CreateStartInfo(string executable, string directory, int display, string encoder)
    {
        if (display is < 0 or > 255 || encoder is not ("h264_amf" or "h264_nvenc" or "h264_qsv")) throw new ArgumentException("Invalid capture configuration.");
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = directory
        };
        string graph = "ddagrab=output_idx=" + display.ToString(CultureInfo.InvariantCulture) + ":framerate=30:draw_mouse=1,showinfo=checksum=0";
        if (encoder == "h264_amf") graph += ",hwdownload,format=bgra,format=nv12";
        if (encoder == "h264_qsv") graph += ",hwmap=derive_device=qsv:mode=read+direct,format=qsv";
        string[] common = ["-loglevel", "info", "-nostats", "-stdin", "-n", "-copyts",
            "-stats_period", "0.5", "-progress", "pipe:1", "-f", "lavfi", "-i", graph,
            "-map", "0:v:0", "-an", "-c:v", encoder, "-pix_fmt", encoder == "h264_qsv" ? "qsv" : encoder == "h264_amf" ? "nv12" : "d3d11"];
        foreach (string item in common) info.ArgumentList.Add(item);
        string[] specific = encoder switch
        {
            "h264_amf" => ["-usage", "transcoding", "-quality", "speed", "-rc", "cbr"],
            "h264_nvenc" => ["-preset", "p1", "-rc", "cbr"],
            _ => ["-preset", "veryfast", "-look_ahead", "0"]
        };
        foreach (string item in specific) info.ArgumentList.Add(item);
        foreach (string item in new[] { "-b:v", "6000000", "-g", "60", "-bf", "0", "-fps_mode", "passthrough",
            "-enc_time_base", "1:1000000", "-avoid_negative_ts", "disabled", "-t", "36000", "-fs", "68719476736",
            "-flush_packets", "1", "-cluster_time_limit", "1000", "-f", "matroska", Path.Combine(directory, "desktop.mkv") }) info.ArgumentList.Add(item);
        return info;
    }

    public async Task StartAsync(CancellationToken cancellation = default)
    {
        cancellation.ThrowIfCancellationRequested();
        bool ownsStart = false;
        try
        {
            lock (gate)
            {
                if (started || stopRequested) throw new InvalidOperationException("Capture instances are single use.");
                if (fixtureStart is null && !OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Desktop capture requires Windows.");
                if (!File.Exists(ffmpegPath)) throw new FileNotFoundException("FFmpeg executable is unavailable.");
                started = ownsStart = true; state = "starting";
                Directory.CreateDirectory(outputDirectory);
                if (File.Exists(Path.Combine(outputDirectory, "desktop.mkv"))) throw new IOException("Video destination already exists.");
                stderrLog = new(Path.Combine(outputDirectory, "ffmpeg.stderr.log"));
                progressLog = new(Path.Combine(outputDirectory, "video-progress.jsonl"));
                framesLog = new(Path.Combine(outputDirectory, "video-frames.jsonl"));
                ProcessStartInfo info = CreateStartInfo(ffmpegPath, outputDirectory, displayIndex, encoder);
                launchBefore = Stopwatch.GetTimestamp();
                process = fixtureStart is null ? Process.Start(info) ?? throw new IOException("FFmpeg did not start.") : fixtureStart(info);
                launchAfter = Stopwatch.GetTimestamp(); processId = process.Id;
                try { process.PriorityClass = ProcessPriorityClass.BelowNormal; priority = "BelowNormal"; }
                catch (Exception e) when (e is Win32Exception or InvalidOperationException or PlatformNotSupportedException)
                { priority = "not_applied"; priorityError = e.GetType().Name; }
                stderrTask = DrainAsync(process.StandardError, true);
                stdoutTask = DrainAsync(process.StandardOutput, false);
                monitorTask = MonitorAsync(process);
                cancellationRegistration = cancellation.Register(() => { _ = StopAsync(); });
            }
            Publish("video_process_started");
            await ready.Task.WaitAsync(TimeSpan.FromMilliseconds(StartTimeoutMs), cancellation).ConfigureAwait(false);
            if (fixtureStart is null && (!File.Exists(Path.Combine(outputDirectory, "desktop.mkv")) || new FileInfo(Path.Combine(outputDirectory, "desktop.mkv")).Length == 0))
                throw new IOException("Encoding progress did not establish a nonempty video output.");
        }
        catch (Exception e) when (ownsStart)
        {
            Fail(e is OperationCanceledException ? "video_start_cancelled" : e is TimeoutException ? "video_start_timeout" : "video_start_failed");
            await StopAsync().ConfigureAwait(false);
            throw;
        }
    }

    public Task StopAsync()
    {
        lock (gate) { stopRequested = true; return stopTask ??= Task.Run(StopCoreAsync); }
    }
    private async Task StopCoreAsync()
    {
        Process? child = process;
        if (child is not null)
        {
            lock (gate) if (error is null) state = "stopping";
            if (!HasExited(child))
            {
                try
                {
                    await child.StandardInput.WriteLineAsync("q").WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
                    await child.StandardInput.FlushAsync().WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
                    lock (gate) qSent = true;
                }
                catch (Exception e) when (e is IOException or InvalidOperationException or ObjectDisposedException or TimeoutException) { }
                try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromMilliseconds(GracefulStopMs)).ConfigureAwait(false); }
                catch (TimeoutException)
                {
                    try { child.Kill(entireProcessTree: false); lock (gate) killed = true; }
                    catch (Exception e) when (e is Win32Exception or InvalidOperationException or NotSupportedException) { Fail("video_child_kill_failed"); }
                    try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromMilliseconds(KillWaitMs)).ConfigureAwait(false); }
                    catch (TimeoutException) { Fail("video_child_still_running"); }
                }
            }
            if (HasExited(child)) lock (gate) exitCode = child.ExitCode;
        }
        try { await Task.WhenAll(stderrTask ?? Task.CompletedTask, stdoutTask ?? Task.CompletedTask).WaitAsync(TimeSpan.FromMilliseconds(DrainWaitMs)).ConfigureAwait(false); }
        catch (TimeoutException) { Fail("video_drain_timeout"); }
        finally
        {
            drainStop.Cancel(); cancellationRegistration.Dispose();
            stderrLog?.Dispose(); progressLog?.Dispose(); framesLog?.Dispose();
        }
        lock (gate)
        {
            if (killed) error ??= "video_forced_stop";
            if (exitCode is not null and not 0) error ??= "video_ffmpeg_failed";
            if (sourceFrames == 0) error ??= "video_source_timestamp_evidence_missing";
            if (progressFrames == 0) error ??= "video_no_encoded_frames";
            state = error is null ? "stopped" : "failed";
        }
        ready.TrySetException(new IOException(error ?? "Video stopped before startup completed."));
        Publish("video_stopped");
    }
    private async Task MonitorAsync(Process child)
    {
        await child.WaitForExitAsync().ConfigureAwait(false);
        lock (gate) { exitCode = child.ExitCode; if (!stopRequested) error ??= "video_unexpected_exit"; }
        if (!ready.Task.IsCompleted) ready.TrySetException(new IOException("FFmpeg exited before encoding progress."));
        _ = StopAsync();
    }
    private static bool HasExited(Process child) { try { return child.HasExited; } catch (InvalidOperationException) { return true; } }
    private void Fail(string reason) { lock (gate) { error ??= reason; state = "failed"; } }
    private void Publish(string kind)
    {
        try { emit(new { kind, receipt_qpc = Stopwatch.GetTimestamp(), video = Snapshot() }); }
        catch { Fail("video_event_sink_failed"); _ = StopAsync(); }
    }

    private async Task DrainAsync(StreamReader reader, bool stderr)
    {
        char[] buffer = new char[4096]; var line = new StringBuilder(); bool dropped = false;
        var progress = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            while (true)
            {
                int count = await reader.ReadAsync(buffer.AsMemory(), drainStop.Token).ConfigureAwait(false);
                if (count == 0) break;
                for (int i = 0; i < count; i++)
                {
                    char c = buffer[i];
                    if (c == '\n')
                    {
                        if (dropped) { lock (gate) truncated = true; Fail("video_log_line_limit"); _ = StopAsync(); }
                        else Line(line.ToString().TrimEnd('\r'), stderr, progress);
                        line.Clear(); dropped = false;
                    }
                    else if (line.Length < MaximumLineCharacters) line.Append(c); else dropped = true;
                }
            }
            if (line.Length > 0 && !dropped) Line(line.ToString(), stderr, progress);
            if (dropped) { lock (gate) truncated = true; Fail("video_log_line_limit"); _ = StopAsync(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ObjectDisposedException)
        { Fail("video_log_io_error"); _ = StopAsync(); }
    }
    private void Save(BoundedLog log, object value)
    {
        long bytes = log.Write(value);
        lock (gate) logBytes += bytes;
    }
    private void Line(string line, bool stderr, Dictionary<string, string> progress)
    {
        long receipt = Stopwatch.GetTimestamp();
        try
        {
            if (stderr)
            {
                Save(stderrLog!, new { receipt_qpc = receipt, text = line });
                if (line.Contains("showinfo", StringComparison.Ordinal) && line.Contains("config in time_base: 1/1000000,", StringComparison.Ordinal))
                    lock (gate) timeBaseConfirmed = true;
                if (TryFrame(line, out var frame))
                {
                    bool confirmed; lock (gate) confirmed = timeBaseConfirmed;
                    Save(framesLog!, new { receipt_qpc = receipt, frame = frame.Ordinal, source_pts_raw = frame.PtsUs, source_pts_us = confirmed ? (long?)frame.PtsUs : null, frame.Width, frame.Height,
                        qpc_frequency = Stopwatch.Frequency, mapping = "source_pts_relative_epoch_unknown" });
                    if (!confirmed) { Fail("video_source_timebase_unsupported"); _ = StopAsync(); return; }
                    lock (gate)
                    {
                        firstPts ??= frame.PtsUs;
                        if (frame.PtsUs < 0 || lastPts > frame.PtsUs) timestampInvalid = true;
                        lastPts = frame.PtsUs; sourceFrames++; width = frame.Width; height = frame.Height;
                        long upper = EpochUpperBound(receipt, frame.PtsUs, Stopwatch.Frequency);
                        epochUpper = epochUpper is null ? upper : Math.Min(epochUpper.Value, upper);
                        if (epochUpper < launchBefore) timestampInvalid = true;
                        MarkReadyUnderLock();
                    }
                }
                return;
            }
            int equal = line.IndexOf('=');
            if (equal <= 0) return;
            string key = line[..equal], value = line[(equal + 1)..];
            if (progress.Count >= 64 && !progress.ContainsKey(key)) throw new IOException("Progress block exceeded bound.");
            progress[key] = value;
            if (key != "progress") return;
            var saved = new Dictionary<string, string>(progress, StringComparer.Ordinal); progress.Clear();
            Save(progressLog!, new { receipt_qpc = receipt, values = saved });
            lock (gate)
            {
                lastReceipt = receipt; progressEnd |= value == "end";
                if (saved.TryGetValue("frame", out string? frames) && long.TryParse(frames.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long n) && n >= 0)
                    progressFrames = Math.Max(progressFrames, n);
                MarkReadyUnderLock();
            }
            Publish("video_progress");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ObjectDisposedException or OverflowException)
        { Fail(e is OverflowException ? "video_timestamp_overflow" : "video_log_io_or_limit_error"); _ = StopAsync(); }
    }
    private void MarkReadyUnderLock()
    {
        if (progressFrames > 0 && sourceFrames > 0 && timeBaseConfirmed && !timestampInvalid && error is null)
        { state = "recording"; ready.TrySetResult(); }
    }
    internal readonly record struct SourceFrame(long Ordinal, long PtsUs, int Width, int Height);
    private static readonly Regex FramePattern = new(@"\bn:\s*(\d+)\s+pts:\s*(-?\d+)\s+.*?\bs:(\d+)x(\d+)\b", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
    internal static bool TryFrame(string line, out SourceFrame frame)
    {
        frame = default;
        if (!line.Contains("showinfo", StringComparison.Ordinal)) return false;
        Match match;
        try { match = FramePattern.Match(line); } catch (RegexMatchTimeoutException) { return false; }
        if (!match.Success || !long.TryParse(match.Groups[1].Value, out long n) || !long.TryParse(match.Groups[2].Value, out long pts) ||
            !int.TryParse(match.Groups[3].Value, out int w) || !int.TryParse(match.Groups[4].Value, out int h) || w <= 0 || h <= 0) return false;
        frame = new(n, pts, w, h); return true;
    }
    internal static long EpochUpperBound(long receiptQpc, long ptsUs, long frequency) =>
        checked(receiptQpc - (long)decimal.Floor((decimal)ptsUs * frequency / 1000000m) + TimestampRoundingMargin(frequency));
    private static long TimestampRoundingMargin(long frequency) => Math.Max(1, (long)decimal.Ceiling(2m * frequency / 1000000m));
    private sealed class BoundedLog(string path) : IDisposable
    {
        private readonly FileStream file = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read | FileShare.Delete);
        private readonly object sync = new(); private long bytes;
        internal long Write(object value)
        {
            byte[] data = JsonSerializer.SerializeToUtf8Bytes(value);
            lock (sync)
            {
                if (data.Length + 1 > MaximumLogBytes - bytes) throw new IOException("Video log bound reached.");
                file.Write(data); file.WriteByte((byte)'\n'); file.Flush(); bytes += data.Length + 1; return data.Length + 1;
            }
        }
        public void Dispose() { lock (sync) file.Dispose(); }
    }
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        if (process is not null && HasExited(process)) process.Dispose();
        drainStop.Dispose();
    }
}
