using System.Diagnostics;
using System.Runtime.InteropServices;

namespace OverwatchDecoder.SessionRecorder;

public sealed class MainForm : Form
{
    private readonly CaptureSettings settings;
    private readonly int automaticSeconds;
    private readonly string? outputOverride;
    private readonly DemoSession? fixture;
    private readonly Label status = new() { AutoSize = true, Text = "Ready", Font = new Font("Segoe UI", 20, FontStyle.Bold) };
    private readonly Label target = new() { AutoSize = true };
    private readonly Label detail = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly Label memoryStatus = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly Label location = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly ComboBox display = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 320 };
    private readonly ComboBox encoder = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 245 };
    private readonly ComboBox observationScope = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 350 };
    private readonly CheckBox sound = new() { Text = "Record system sound", AutoSize = true };
    private readonly NumericUpDown minutes = new() { Minimum = 1, Maximum = 240, Width = 80 };
    private readonly Button start = new() { Text = "Start recording", Width = 180, Height = 42, Name = "StartRecording" };
    private readonly Button finishChunk = new() { Text = "Finish data chunk and save", Width = 230, Height = 42, Enabled = false, Name = "FinishDataChunk" };
    private readonly Button finish = new() { Text = "Stop and save", Width = 180, Height = 42, Enabled = false, Name = "StopRecording" };
    private readonly Button folder = new() { Text = "Open recordings", Width = 150, Height = 34 };
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 500 };
    private readonly NotifyIcon tray = new() { Icon = SystemIcons.Application, Visible = true, Text = "Overwatch Decoder Recorder — idle" };
    private CaptureSession? session;
    private bool busy, closing, finishing, finishingChunk, testedDisk, pendingClose;
    private string? lastDirectory;
    private long lastDiskCheck;
    private string? hotkeyError;

    public MainForm(CaptureSettings settings, int automaticSeconds, string? outputOverride, DemoSession? fixture = null)
    {
        this.settings = settings; this.automaticSeconds = automaticSeconds; this.outputOverride = outputOverride; this.fixture = fixture;
        Text = "Overwatch Decoder Recorder"; Name = "OverwatchDecoderCaptureWindow"; StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(760, 580); Size = new Size(800, 620); Font = new Font("Segoe UI", 10);
        BackColor = Color.FromArgb(247, 249, 253);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 1, RowCount = 11, AutoScroll = true };
        Controls.Add(layout);
        layout.Controls.Add(status); layout.Controls.Add(target);
        layout.Controls.Add(new Label { Text = "Video, sound, inputs and memory in one recording folder.", AutoSize = true });
        var captureOptions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        for (int i = 0; i < Screen.AllScreens.Length; i++)
        {
            var screen = Screen.AllScreens[i]; display.Items.Add($"Display {i + 1} · {screen.Bounds.Width} × {screen.Bounds.Height}");
        }
        display.SelectedIndex = 0;
        encoder.Items.AddRange(["AMD hardware (AMF)", "NVIDIA hardware (NVENC)", "Intel hardware (Quick Sync)"]);
        encoder.SelectedIndex = settings.Encoder == "h264_nvenc" ? 1 : settings.Encoder == "h264_qsv" ? 2 : 0;
        captureOptions.Controls.Add(display); captureOptions.Controls.Add(encoder);
        if (settings.Observations is not null)
        {
            observationScope.Items.AddRange([ObservationCapture.Label(ObservationScope.ControlledPractice), ObservationCapture.Label(ObservationScope.ReadOnlyUserGameplay)]);
            observationScope.SelectedIndex = settings.Observations.CaptureScope == ObservationScope.ReadOnlyUserGameplay ? 1 : 0;
            observationScope.AccessibleName = "Entity observation scope";
            observationScope.Enabled = !settings.Observations.ContinueObservationWindows;
            captureOptions.Controls.Add(observationScope);
        }
        layout.Controls.Add(captureOptions);
        var durationOptions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        sound.Checked = settings.SystemAudio; minutes.Value = settings.MaximumMinutes;
        durationOptions.Controls.Add(sound); durationOptions.Controls.Add(new Label { Text = "   Stop after (minutes):", AutoSize = true, Margin = new Padding(12, 4, 3, 0) });
        durationOptions.Controls.Add(minutes); layout.Controls.Add(durationOptions);
        layout.Controls.Add(new Label { AutoSize = true, MaximumSize = new Size(700, 0), Text = $"Records the selected display and system sound. Keyboard and mouse are recorded only while {settings.TargetProcess} is focused. No microphone recording." });
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 10) };
        bool repeatObservations = settings.Observations?.ContinueObservationWindows == true;
        buttons.Controls.Add(start);
        if (repeatObservations)
        {
            buttons.Controls.Add(finishChunk);
            finish.Text = "Stop now and save";
        }
        buttons.Controls.Add(finish); layout.Controls.Add(buttons);
        layout.Controls.Add(detail); layout.Controls.Add(memoryStatus); layout.Controls.Add(location); layout.Controls.Add(folder);
        detail.Text = repeatObservations
            ? "Finish data chunk and save keeps recording until the current data window seals.\nCtrl + Shift + F9: start / stop now     Ctrl + Shift + F10: mark a moment"
            : "Ctrl + Shift + F9: start / stop     Ctrl + Shift + F10: mark a moment\nVideo target: 30 FPS. Actual timing and gaps are saved.";
        memoryStatus.Text = settings.Memory.Length == 0 ? "Memory recording is not configured." : "Memory streams: " + string.Join(", ", settings.Memory.Select(p => p.Name + $" ({p.IntervalMs} ms target)"));
        if (settings.Observations is not null) memoryStatus.Text += "\nEntity/event observations: " + ObservationCapture.Label(settings.Observations.CaptureScope) + " · bounded windows, explicit gaps.";
        if (settings.Roster is not null) memoryStatus.Text += "\nRoster JSON configured · independent slices with unknown gaps.";
        start.Click += async (_, _) => await StartRecordingAsync(); finish.Click += async (_, _) => await StopRecordingAsync("user_stop");
        finishChunk.Click += async (_, _) => await FinishDataChunkAsync();
        folder.Click += (_, _) => OpenFolder();
        tray.DoubleClick += (_, _) => { Show(); WindowState = FormWindowState.Normal; Activate(); };
        var menu = new ContextMenuStrip();
        menu.Items.Add("Show recorder", null, (_, _) => { Show(); WindowState = FormWindowState.Normal; Activate(); });
        if (repeatObservations) menu.Items.Add("Finish data chunk and save", null, async (_, _) => await FinishDataChunkAsync());
        menu.Items.Add(finish.Text, null, async (_, _) => await StopRecordingAsync("tray_stop"));
        tray.ContextMenuStrip = menu;
        timer.Tick += async (_, _) => await RefreshStatusAsync(); timer.Start();
        Shown += async (_, _) =>
        {
            if (!RegisterHotKey(Handle, 1, 0x4006, 0x78)) hotkeyError = "Start/stop shortcut unavailable; use the buttons.";
            if (!RegisterHotKey(Handle, 2, 0x4006, 0x79)) hotkeyError = (hotkeyError + " Marker shortcut unavailable.").Trim();
            await RefreshStatusAsync();
            if (automaticSeconds > 0) await StartRecordingAsync();
        };
        FormClosing += async (_, e) =>
        {
            if (closing) return;
            if (session is not null || busy)
            {
                e.Cancel = true;
                if (busy) { pendingClose = true; session?.RequestStop(); }
                if (!busy && !finishing) { await StopRecordingAsync("window_closed"); closing = true; Close(); }
            }
        };
        FormClosed += (_, _) => { timer.Dispose(); UnregisterHotKey(Handle, 1); UnregisterHotKey(Handle, 2); tray.Visible = false; tray.Dispose(); };
    }

    private int? FindTarget()
    {
        if (fixture is not null) return fixture.Pid;
        int localSession = Process.GetCurrentProcess().SessionId;
        var matches = Process.GetProcessesByName(settings.TargetProcess);
        try
        {
            var selected = matches.Where(p => p.SessionId == localSession && !p.HasExited).ToArray();
            return selected.Length == 1 ? selected[0].Id : null;
        }
        finally { foreach (var process in matches) process.Dispose(); }
    }

    private async Task StartRecordingAsync()
    {
        if (busy || session is not null || finishing) return;
        int? pid = FindTarget();
        if (pid is null) { status.Text = "Open " + settings.TargetProcess + " first"; return; }
        busy = true; start.Enabled = false; status.Text = "Starting…";
        settings.Encoder = encoder.SelectedIndex == 1 ? "h264_nvenc" : encoder.SelectedIndex == 2 ? "h264_qsv" : "h264_amf";
        settings.MaximumMinutes = (int)minutes.Value; settings.SystemAudio = sound.Checked;
        if (settings.Observations is not null) settings.Observations.CaptureScope = observationScope.SelectedIndex == 1 ? ObservationScope.ReadOnlyUserGameplay : ObservationScope.ControlledPractice;
        display.Enabled = encoder.Enabled = sound.Enabled = minutes.Enabled = observationScope.Enabled = false;
        SyncTile? tile = null;
        try
        {
            session = new CaptureSession(settings, pid.Value, display.SelectedIndex, outputOverride);
            lastDirectory = session.DirectoryPath; location.Text = lastDirectory;
            tile = new SyncTile(Screen.AllScreens[display.SelectedIndex], session.Emit); tile.Show();
            await session.StartAsync();
            await Task.Delay(1500); tile.Close(); tile.Dispose(); tile = null;
            finish.Enabled = true; finishChunk.Enabled = settings.Observations?.ContinueObservationWindows == true; status.Text = "● Recording"; status.ForeColor = Color.FromArgb(185, 30, 45);
            tray.Text = "Overwatch Decoder Recorder — RECORDING";
            testedDisk = false; lastDiskCheck = Stopwatch.GetTimestamp();
            if (automaticSeconds == 0) WindowState = FormWindowState.Minimized;
            fixture?.Focus();
        }
        catch (Exception ex)
        {
            status.Text = "Could not start recording"; detail.Text = ex.Message;
            if (session is not null) { session.StartupFailed(ex); await session.StopAsync("startup_failed"); session = null; }
            display.Enabled = encoder.Enabled = sound.Enabled = minutes.Enabled = true;
            observationScope.Enabled = settings.Observations?.ContinueObservationWindows != true;
            if (automaticSeconds > 0) { closing = true; Close(); }
        }
        finally
        {
            tile?.Close(); tile?.Dispose(); busy = false;
            if (pendingClose) { if (session is not null) await StopRecordingAsync("window_closed"); closing = true; Close(); }
        }
    }

    private async Task FinishDataChunkAsync()
    {
        if (session is null || busy || finishing || finishingChunk) return;
        CaptureSession active = session;
        if (active.Observations?.Completion is not Task completion || settings.Observations?.ContinueObservationWindows != true)
            return;
        finishingChunk = true;
        finishChunk.Enabled = false;
        status.Text = "Finishing current data chunk";
        tray.Text = "Overwatch Decoder Recorder — finishing data chunk";
        detail.Text = "Video continues until the current data chunk is saved. Use Stop now and save for an immediate stop.";
        active.Observations.RequestFinishAfterWindow();
        string reason = "user_finish_data_chunk";
        try { await completion.WaitAsync(TimeSpan.FromSeconds(settings.Observations.WindowSeconds + 50)); }
        catch (TimeoutException) { reason = "finish_data_chunk_timeout"; }
        catch { reason = "finish_data_chunk_failed"; }
        if (ReferenceEquals(session, active) && !finishing) await StopRecordingAsync(reason);
    }

    private async Task StopRecordingAsync(string reason)
    {
        if (session is null || busy || finishing) return;
        finishing = true; finish.Enabled = finishChunk.Enabled = false; status.Text = "Saving…"; status.ForeColor = Color.FromArgb(35, 45, 65);
        try
        {
            await session.StopAsync(reason);
            string finalMemory = string.Join("\n", session.Memory.Select(m => $"{m.Name}: {m.Frames:N0} frames · {m.UnknownFields:N0} unknown fields" + (m.Error is null ? "" : " · " + m.Error)));
            memoryStatus.Text = finalMemory + (session.Roster is null ? "" : "\nRoster JSON: " + session.Roster.State + " · " + session.Roster.Slices + "/" + session.Roster.AttemptedSlices + " slices complete · " + session.Roster.FinalizedWindows + " finalized windows · " + (session.Roster.OutputBytes / 1048576) + " MiB · saved in roster/");
            if (session.Observations is not null) memoryStatus.Text += "\n" + session.Observations.ProgressLabel + " · saved in observations/";
            status.Text = session.Problems.Length == 0 ? "Saved" : "Saved with gaps";
            detail.Text = session.Problems.Length == 0 ? "Your files are in the folder below. Timing and gaps are recorded in the session metadata."
                : string.Join("\n", session.Problems.Take(3));
        }
        catch (Exception ex) { status.Text = "Check recording files"; detail.Text = ex.Message; }
        finally
        {
            session = null; finishing = finishingChunk = false; start.Enabled = true;
            display.Enabled = encoder.Enabled = sound.Enabled = minutes.Enabled = true;
            observationScope.Enabled = settings.Observations?.ContinueObservationWindows != true; tray.Text = "Overwatch Decoder Recorder — idle";
        }
        if (automaticSeconds > 0) { closing = true; Close(); }
    }

    private async Task RefreshStatusAsync()
    {
        if (IsDisposed || finishing) return;
        if (session is null)
        {
            int? pid = FindTarget(); target.Text = pid is null ? $"Waiting for {settings.TargetProcess} in this desktop session" : $"{settings.TargetProcess} · process {pid}";
            start.Enabled = pid is not null && !busy;
            if (hotkeyError is not null) detail.Text = hotkeyError;
            return;
        }
        if (busy) return;
        string elapsed = TimeSpan.FromSeconds(session.Seconds).ToString(@"hh\:mm\:ss");
        target.Text = $"Recording {elapsed} · {session.Events:N0} events · {session.DroppedEvents:N0} dropped";
        memoryStatus.Text = string.Join("\n", session.Memory.Select(m => $"{m.Name}: {m.State} · {m.Frames:N0} frames" + (m.Error is null ? "" : " · " + m.Error)));
        if (session.Roster is not null) memoryStatus.Text += "\nRoster JSON: " + session.Roster.State + " · " + session.Roster.Slices + "/" + session.Roster.AttemptedSlices + " slices complete · " + session.Roster.FinalizedWindows + " finalized windows · " + (session.Roster.OutputBytes / 1048576) + " MiB" + (session.Roster.Error is null ? "" : " · " + session.Roster.Error);
        if (session.Observations is not null) memoryStatus.Text += "\n" + session.Observations.ProgressLabel + (session.Observations.Error is null ? "" : " · " + session.Observations.Error);
        if (session.AudioError is not null) detail.Text = "System sound unavailable: " + session.AudioError;
        if (session.FatalError is not null) { await StopRecordingAsync("capture_source_failed"); return; }
        if (!session.TargetAlive()) { await StopRecordingAsync("game_exited"); return; }
        if (session.Seconds >= settings.MaximumMinutes * 60 || automaticSeconds > 0 && session.Seconds >= automaticSeconds)
        { await StopRecordingAsync("duration_elapsed"); return; }
        if (!testedDisk || Stopwatch.GetElapsedTime(lastDiskCheck).TotalSeconds >= 5)
        {
            testedDisk = true; lastDiskCheck = Stopwatch.GetTimestamp();
            if (new DriveInfo(Path.GetPathRoot(session.DirectoryPath)!).AvailableFreeSpace < 3L * 1024 * 1024 * 1024)
                await StopRecordingAsync("low_disk_space");
        }
    }

    private void OpenFolder()
    {
        string path = lastDirectory ?? outputOverride ?? (string.IsNullOrWhiteSpace(settings.OutputRoot)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OverwatchDecoder", "sessions") : settings.OutputRoot);
        Directory.CreateDirectory(path); Process.Start(new ProcessStartInfo("explorer.exe", path) { UseShellExecute = true });
    }

    private async Task HandleShortcutAsync(int id)
    {
        if (id == 2) session?.Marker();
        else if (id == 1)
        {
            if (busy) session?.RequestStop();
            else if (session is null) await StartRecordingAsync();
            else await StopRecordingAsync("hotkey_stop");
        }
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == 0x0312)
        {
            int id = m.WParam.ToInt32();
            _ = HandleShortcutAsync(id);
            return;
        }
        base.WndProc(ref m);
    }

    [DllImport("user32.dll", SetLastError = true)] private static extern bool RegisterHotKey(nint hWnd, int id, uint modifiers, uint key);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool UnregisterHotKey(nint hWnd, int id);
}
