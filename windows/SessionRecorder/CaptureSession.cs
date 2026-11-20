using System.Diagnostics;
using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.SessionRecorder;

public sealed class CaptureSession
{
    private readonly CaptureSettings settings;
    private readonly string package;
    private readonly CancellationTokenSource stop = new();
    private readonly int pid, display;
    private readonly long targetStartTicks;
    private readonly DateTimeOffset utcOrigin = DateTimeOffset.UtcNow;
    private readonly long qpcOrigin = Stopwatch.GetTimestamp();
    private InputCapture? input;
    private LoopbackAudioCapture? audio;
    private VideoCapture? video;
    private RosterCapture? roster;
    private ObservationCapture? observations;
    public ObservationCapture? Observations => observations;
    public RosterCapture? Roster => roster;
    private EventJournal? journal;
    private readonly List<MemoryCapture> memory = [];
    private int stopped;
    private string? audioError;
    private readonly ConcurrentQueue<string> errors = new();
    private readonly object manifestGate = new();
    private string? telemetryError;
    private Task? telemetry;
    public string DirectoryPath { get; }
    public IReadOnlyList<MemoryCapture> Memory => memory;
    public bool Running { get; private set; }
    public long Events => journal?.Written ?? 0;
    public long DroppedEvents => journal?.Dropped ?? 0;
    public double Seconds => Stopwatch.GetElapsedTime(qpcOrigin).TotalSeconds;
    public string? JournalError => journal?.Error;
    public string? AudioError => audioError ?? audio?.Error;
    public string? FatalError => JournalError ?? input?.Error ?? telemetryError ??
        (Running && video is { IsRunning: false } ? video.Error ?? "Video recording ended unexpectedly." : null);
    public string[] Problems => errors.Concat(memory.Where(m => m.Error is not null).Select(m => m.Name + ": " + m.Error))
        .Concat(memory.Where(m => m.Required && m.Frames == 0).Select(m => m.Name + ": no memory frames were acquired"))
        .Concat(roster is not null && roster.Slices == 0 ? new[] { "Roster JSON: no completed JSON slice; partial files may exist" } : [])
        .Concat(roster?.IncompleteSlices > 0 ? new[] { $"Roster JSON: {roster.IncompleteSlices} incomplete slices; tails remain unknown" } : [])
        .Concat(roster?.Error is null ? [] : new[] { "Roster JSON: " + roster.Error })
        .Concat(observations?.HasGaps == true ? new[] { "Observations: incomplete windows or cancellation tails remain unknown" } : [])
        .Concat(observations?.Error is null ? [] : new[] { "Observations: " + observations.Error })
        .Concat(AudioError is null ? [] : new[] { "Audio: " + AudioError })
        .Concat(JournalError is null ? [] : new[] { "Events: " + JournalError })
        .Concat(DroppedEvents == 0 ? [] : new[] { $"Event queue dropped {DroppedEvents} events" })
        .Concat(audio?.DroppedBytes > 0 ? new[] { $"Audio dropped {audio.DroppedBytes} bytes" } : [])
        .Concat(input?.DroppedEvents > 0 ? new[] { $"Input discarded {input.DroppedEvents} events; see input gap records" } : [])
        .Concat(memory.Where(m => m.UnknownFields > 0 || m.AcquisitionGaps > 0).Select(m => $"{m.Name}: {m.UnknownFields} unknown fields; {m.AcquisitionGaps} acquisition gaps"))
        .Distinct().ToArray();

    public CaptureSession(CaptureSettings settings, int pid, int display, string? outputOverride = null)
    {
        this.settings = settings; this.pid = pid; this.display = display; package = AppContext.BaseDirectory;
        using var target = Process.GetProcessById(pid); targetStartTicks = target.StartTime.ToUniversalTime().Ticks;
        string root = outputOverride ?? (string.IsNullOrWhiteSpace(settings.OutputRoot)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OverwatchDecoder", "sessions") : settings.OutputRoot);
        Directory.CreateDirectory(root);
        if (new DriveInfo(Path.GetPathRoot(Path.GetFullPath(root))!).AvailableFreeSpace < 5L * 1024 * 1024 * 1024)
            throw new IOException("Recording needs at least 5 GB of free space.");
        DirectoryPath = Path.Combine(root, DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss") + "_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(DirectoryPath);
    }

    public void Emit(object item) => journal?.Emit(item);

    // Start and Stop are invoked on the WinForms thread: Raw Input owns that thread's window.
    public async Task StartAsync()
    {
        journal = new EventJournal(Path.Combine(DirectoryPath, "events.jsonl.gz"));
        Emit(new { kind = "session_start", schema = "overwatch-decoder.capture-session/1", utc_origin = utcOrigin, qpc_origin = qpcOrigin,
            qpc_frequency = Stopwatch.Frequency, target_pid = pid, target_start_utc_ticks = targetStartTicks });
        SaveManifest("starting", null);
        input = new InputCapture(pid, Emit, targetStartTicks); input.Start();
        if (settings.SystemAudio)
        {
            try { audio = new LoopbackAudioCapture(DirectoryPath, Emit); audio.Start(); }
            catch (Exception ex) { audioError = ex.Message; Emit(new { kind = "audio_unavailable", qpc_ticks = Stopwatch.GetTimestamp(), error = audioError }); }
        }
        foreach (var plan in settings.Memory)
        {
            var capture = new MemoryCapture(pid, targetStartTicks, plan, package, Path.Combine(DirectoryPath, "memory", plan.Name), Emit);
            memory.Add(capture); capture.Start(stop.Token);
        }
        video = new VideoCapture(CaptureSettings.PackagePath(package, settings.FfmpegPath), DirectoryPath, display, Emit, settings.Encoder);
        await video.StartAsync(stop.Token);
        Running = true;
        if (settings.Roster is not null)
        {
            roster = new RosterCapture(pid, targetStartTicks, settings.Roster, package, Path.Combine(DirectoryPath, "roster"), TargetAlive, Emit);
            roster.Start(stop.Token);
        }
        if (settings.Observations is not null)
        {
            observations = new ObservationCapture(pid, settings.Observations, package, Path.Combine(DirectoryPath, "observations"), TargetAlive, Emit);
            observations.Start(stop.Token);
        }
        SaveManifest("recording", null);
        telemetry = Task.Run(() => TelemetryAsync(stop.Token));
    }

    public void Marker() => Emit(new { kind = "user_marker", qpc_ticks = Stopwatch.GetTimestamp(), qpc_frequency = Stopwatch.Frequency });
    public void RequestStop() => stop.Cancel();
    public void StartupFailed(Exception error) => errors.Enqueue("Startup: " + error.Message);

    private async Task TelemetryAsync(CancellationToken token)
    {
        using var self = Process.GetCurrentProcess();
        TimeSpan cpu = self.TotalProcessorTime;
        TimeSpan? previousVideoCpu = null;
        long last = Stopwatch.GetTimestamp(); int sample = 0;
        try
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(1000, token); self.Refresh();
                long now = Stopwatch.GetTimestamp(); TimeSpan current = self.TotalProcessorTime;
                double wall = (now - last) / (double)Stopwatch.Frequency;
                double? videoCpuPercent = null; long? videoWorkingSet = null;
                if (video?.ProcessId is int videoPid)
                {
                    try
                    {
                        using var child = Process.GetProcessById(videoPid);
                        TimeSpan childCpu = child.TotalProcessorTime;
                        if (previousVideoCpu is TimeSpan previous) videoCpuPercent = (childCpu - previous).TotalSeconds / wall / Environment.ProcessorCount * 100;
                        previousVideoCpu = childCpu; videoWorkingSet = child.WorkingSet64;
                    }
                    catch (ArgumentException) { }
                    catch (InvalidOperationException) { }
                }
                Emit(new { kind = "recorder_performance", qpc_ticks = now, cpu_percent_machine = (current - cpu).TotalSeconds / wall / Environment.ProcessorCount * 100,
                    working_set_bytes = self.WorkingSet64, events = Events, dropped_events = DroppedEvents,
                    video_cpu_percent_machine = videoCpuPercent, video_working_set_bytes = videoWorkingSet,
                    memory = memory.Select(m => new { name = m.Name, state = m.State, frames = m.Frames, unknown_fields = m.UnknownFields, error = m.Error }).ToArray() });
                cpu = current; last = now;
                if (++sample % 5 == 0) SaveManifest("recording", null);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex) { telemetryError = "Telemetry: " + ex.Message; errors.Enqueue(telemetryError); }
    }

    public async Task StopAsync(string reason)
    {
        if (Interlocked.Exchange(ref stopped, 1) != 0) return;
        Running = false;
        try { input?.Stop(); input?.Dispose(); } catch (Exception ex) { errors.Enqueue("Input stop: " + ex.Message); }
        stop.Cancel();
        if (video is not null) try { await video.StopAsync(); if (video.Error is not null) errors.Enqueue("Video: " + video.Error); } catch (Exception ex) { errors.Enqueue("Video stop: " + ex.Message); }
        if (audio is not null) try { await audio.StopAsync(); audio.Dispose(); } catch (Exception ex) { errors.Enqueue("Audio stop: " + ex.Message); }
        var memoryDone = Task.WhenAll(memory.Where(m => m.Completion is not null).Select(m => m.Completion!));
        try { await memoryDone.WaitAsync(TimeSpan.FromSeconds(20)); }
        catch (TimeoutException)
        {
            SaveManifest("finalizing_memory", reason);
            await memoryDone; // Keep ownership, journal and cancellation state until workers actually finish.
        }
        if (roster?.Completion is not null) await roster.Completion;
        if (observations?.Completion is not null) await observations.Completion;
        if (telemetry is not null) await telemetry;
        Emit(new { kind = "session_stop", qpc_ticks = Stopwatch.GetTimestamp(), reason, errors = errors.ToArray() });
        if (journal is not null) await journal.DisposeAsync();
        CopyCodeReference();
        if (input?.Error is not null) errors.Enqueue("Input: " + input.Error);
        SaveManifest(Problems.Length == 0 ? "finished" : "finished_with_gaps", reason);
        if (video is not null) await video.DisposeAsync();
        stop.Dispose();
    }

    public bool TargetAlive()
    {
        try { using var target = Process.GetProcessById(pid); return !target.HasExited && target.StartTime.ToUniversalTime().Ticks == targetStartTicks; }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private void CopyCodeReference()
    {
        string from = Path.Combine(package, "code-reference");
        if (!Directory.Exists(from)) return;
        try
        {
            var files = Directory.GetFiles(from);
            if (files.Length > 64 || files.Sum(f => new FileInfo(f).Length) > 16 * 1024 * 1024) throw new InvalidDataException("Code reference package exceeds its bounds.");
            string to = Path.Combine(DirectoryPath, "code-reference"); Directory.CreateDirectory(to);
            foreach (var file in files) File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        }
        catch (Exception ex) { errors.Enqueue("Code reference: " + ex.Message); }
    }

    private void SaveManifest(string status, string? reason)
    {
        var manifest = new
        {
            schema = "overwatch-decoder.capture-session/1", status, stop_reason = reason,
            revision = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            utc_origin = utcOrigin, qpc_origin = qpcOrigin, qpc_frequency = Stopwatch.Frequency, last_update_qpc = Stopwatch.GetTimestamp(),
            target_pid = pid, target_start_utc_ticks = targetStartTicks, display_index = display, encoder = settings.Encoder,
            video = video?.Summary, audio_enabled = settings.SystemAudio, audio_error = AudioError,
            audio = audio is null ? null : new { bytes_written = audio.BytesWritten, dropped_bytes = audio.DroppedBytes, callback_failures = audio.CallbackFailures, error = AudioError },
            input = input is null ? null : new { dropped_events = input.DroppedEvents, error = input.Error },
            journal = new { file = "events.jsonl.gz", written = Events, dropped = DroppedEvents, error = JournalError },
            memory = memory.Select(m => new { name = m.Name, required = m.Required, state = m.State, frames = m.Frames, unknown_fields = m.UnknownFields, acquisition_gaps = m.AcquisitionGaps, error = m.Error, identity = m.Identity }).ToArray(),
            roster = roster?.Summary, observations = observations?.Summary,
            errors = errors.ToArray(), problems = Problems, memory_public_state_eligible = false,
            scope = "Selected display and system render audio. Raw keyboard/mouse payloads only while the selected process is foreground. No microphone, target-memory writes, injection or instruction tracing.",
            timing = "Input is timestamped at receipt. Video preserves relative frame PTS with QPC receipt bounds; calibration paint events are alignment evidence, not exact compositor presentation times. Memory reads preserve their own QPC intervals. Streams are not atomic.",
            code_reference = "Static code bytes are historical references matched by executable hash in their source manifest, not a trace of executed instructions. Verify the build match before using them."
        };
        string path = Path.Combine(DirectoryPath, "session.json"), pending = path + ".partial";
        lock (manifestGate)
        {
            File.WriteAllBytes(pending, JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(pending, path, true);
        }
    }
}
