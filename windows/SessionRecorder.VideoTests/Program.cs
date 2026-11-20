using System.Diagnostics;
using System.Text.Json;
using OverwatchDecoder.SessionRecorder;

if (args.FirstOrDefault() == "fixture")
{
    string mode = args[1];
    if (mode == "fail") { Console.Error.WriteLine("No supported hardware encoder"); return 9; }
    Console.Error.WriteLine(mode == "badtime" ? "[Parsed_showinfo_1 @ 123] config in time_base: 1/90000, frame_rate: 30/1" : "[Parsed_showinfo_1 @ 123] config in time_base: 1/1000000, frame_rate: 30/1");
    Console.Error.WriteLine("[Parsed_showinfo_1 @ 123] n:   0 pts: 1234 pts_time:0.001234 fmt:d3d11 s:1920x1080 i:P");
    Console.WriteLine("frame=1\nout_time_us=1234\nprogress=continue"); Console.Out.Flush();
    if (mode == "long") { Console.Error.WriteLine(new string('x', 10000)); Console.Error.Flush(); }
    if (mode == "early") return 0;
    if (mode == "ignore") { await Task.Delay(30000); return 0; }
    while (await Console.In.ReadLineAsync() is { } line) if (line == "q") break;
    Console.WriteLine("frame=2\nout_time_us=34567\nprogress=end"); Console.Out.Flush(); return 0;
}
int assertions = 0;
void Check(bool ok, string message) { if (!ok) throw new Exception(message); assertions++; }
JsonElement Snapshot(VideoCapture video) => JsonSerializer.SerializeToElement(video.Summary);
string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-video-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
string executable = Environment.ProcessPath!; string assembly = typeof(VideoCapture).Assembly.Location;
Func<ProcessStartInfo, Process> Child(string mode) => requested =>
{
    Check(requested.UseShellExecute == false && requested.RedirectStandardInput && requested.RedirectStandardError && requested.RedirectStandardOutput, "redirected non-shell child");
    var info = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
    if (Path.GetFileNameWithoutExtension(executable) == "dotnet") info.ArgumentList.Add(assembly);
    info.ArgumentList.Add("fixture"); info.ArgumentList.Add(mode); return Process.Start(info)!;
};
try
{
    foreach (string encoder in new[] { "h264_amf", "h264_nvenc", "h264_qsv" })
    {
        var command = VideoCapture.CreateStartInfo("ffmpeg path with spaces.exe", root, 2, encoder); var a = command.ArgumentList.ToArray();
        Check(a.Contains(encoder) && a.Contains("6000000") && a.Contains("matroska") && a.Contains("-n"), "hardware allowlist and MKV no-overwrite");
        Check(a.Any(x => x.Contains("output_idx=2:framerate=30")) && !a.Any(x => x.Contains("video_size")), "native display and explicit index/fps");
        Check(!a.Any(x => x.Contains("libx264") || x == "-start_at_zero"), "no CPU encoder fallback or zero shift");
        Check(a.Any(x => x.Contains("hwdownload,format=bgra,format=nv12")) == (encoder == "h264_amf"), "AMF explicitly uses CPU color conversion; other backends do not");
        Check(a.Contains("-copyts") && a.Contains("1:1000000") && a.Contains("passthrough") && a.Any(x => x.Contains("showinfo=checksum=0")), "preserve source timestamp evidence");
    }
    try { VideoCapture.CreateStartInfo("x", root, 0, "libx264"); Check(false, "CPU encoder accepted"); } catch (ArgumentException) { assertions++; }
    Check(VideoCapture.TryFrame("[Parsed_showinfo_0 @ x] n: 21 pts: 34567 pts_time:0.034567 fmt:d3d11 s:2560x1440 i:P", out var frame) && frame.Ordinal == 21 && frame.PtsUs == 34567 && frame.Width == 2560, "bounded original source PTS parser");
    Check(!VideoCapture.TryFrame("frame=21 pts=0", out _) && !VideoCapture.TryFrame("showinfo n:0 pts:NOPTS s:0x0", out _), "unknown log formats not invented");
    Check(VideoCapture.EpochUpperBound(50000000, 1000000, 10000000) >= 40000000 && VideoCapture.EpochUpperBound(50000000, 1000000, 10000000) <= 40000020, "conservative microsecond-QPC upper bound");
    foreach (string mode in new[] { "normal", "fail", "early", "long", "ignore", "badtime" })
    {
        var events = new List<object>();
        await using var video = new VideoCapture(executable, Path.Combine(root, mode), 0, e => { lock (events) events.Add(e); }, "h264_amf", Child(mode));
        try { await video.StartAsync(); } catch (IOException) { Check(mode is "fail" or "early" or "long" or "badtime", "startup failure stays explicit"); }
        if (mode == "normal")
        {
            try { await video.StartAsync(); Check(false, "duplicate start accepted"); }
            catch (InvalidOperationException) { Check(video.IsRunning, "rejected duplicate start does not stop existing child"); }
        }
        if (mode == "long" || mode == "early") await Task.Delay(100);
        await video.StopAsync(); await video.StopAsync(); var summary = Snapshot(video);
        Check(!video.IsRunning, "owned child stopped:" + mode);
        Check(!summary.GetProperty("first_frame_qpc_exact").GetBoolean() && !summary.GetProperty("media_verified").GetBoolean(), "no exact or verified media claim:" + mode);
        if (mode == "normal")
        {
            Check(summary.GetProperty("state").GetString() == "stopped" && summary.GetProperty("graceful_q_sent").GetBoolean() && summary.GetProperty("progress_end_received").GetBoolean(), "graceful q and final progress");
            Check(summary.GetProperty("source_frames_logged").GetInt64() == 1 && summary.GetProperty("first_source_pts_us").GetInt64() == 1234 && summary.GetProperty("width").GetInt32() == 1920, "frame metadata and native dimensions retained");
            Check(File.ReadAllLines(Path.Combine(root, mode, "video-progress.jsonl")).Length == 2 && File.ReadAllLines(Path.Combine(root, mode, "video-frames.jsonl")).Length == 1, "bounded progress and source-frame logs saved");
        }
        else Check(summary.GetProperty("state").GetString() == "failed", "failure or forced-stop state:" + mode);
        if (mode == "ignore") Check(summary.GetProperty("forced_kill").GetBoolean(), "graceful timeout kills only owned child");
        if (mode == "long") Check(summary.GetProperty("logs_truncated").GetBoolean(), "oversized line bounded and explicit");
        if (mode == "badtime")
        {
            Check(summary.GetProperty("error").GetString() == "video_source_timebase_unsupported" && !summary.GetProperty("source_time_base_confirmed_microseconds").GetBoolean(), "unknown timestamp scale rejects explicitly");
            var saved = JsonSerializer.Deserialize<JsonElement>(File.ReadLines(Path.Combine(root, mode, "video-frames.jsonl")).First());
            Check(saved.GetProperty("source_pts_us").ValueKind == JsonValueKind.Null && saved.GetProperty("source_pts_raw").GetInt64() == 1234, "unknown timestamp units retained raw without invented microseconds");
        }
    }
    using (var activeCancellation = new CancellationTokenSource())
    {
        await using var video = new VideoCapture(executable, Path.Combine(root, "active-cancel"), 0, _ => { }, "h264_amf", Child("normal"));
        await video.StartAsync(activeCancellation.Token); activeCancellation.Cancel(); await video.StopAsync();
        Check(!video.IsRunning && Snapshot(video).GetProperty("graceful_q_sent").GetBoolean(), "active cancellation stops owned child gracefully");
    }
    string existing = Path.Combine(root, "existing"); Directory.CreateDirectory(existing); File.WriteAllText(Path.Combine(existing, "desktop.mkv"), "original");
    bool childCalled = false;
    await using (var video = new VideoCapture(executable, existing, 0, _ => { }, "h264_amf", _ => { childCalled = true; throw new Exception(); }))
    { try { await video.StartAsync(); } catch (IOException) { assertions++; } Check(!childCalled && File.ReadAllText(Path.Combine(existing, "desktop.mkv")) == "original", "existing output refuses child start without overwrite"); }
    using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
    await using (var video = new VideoCapture(executable, Path.Combine(root, "cancelled"), 0, _ => { }, "h264_amf", Child("normal")))
    { try { await video.StartAsync(cancelled.Token); } catch (OperationCanceledException) { assertions++; } Check(!Directory.Exists(Path.Combine(root, "cancelled")), "pre-cancel creates no artifacts or child"); }
    Console.WriteLine(JsonSerializer.Serialize(new { ok = true, assertions, native_capture_test = "not_run", hardware_validation = false })); return 0;
}
finally { Directory.Delete(root, true); }
