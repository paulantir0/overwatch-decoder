using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using OverwatchDecoder.Observer;

namespace OverwatchDecoder.SessionRecorder;

/// <summary>Owned synthetic child for native recording verification; never controls a game.</summary>
public sealed class DemoSession : IDisposable
{
    private readonly Process child;
    private readonly string profile;
    public int Pid => child.Id;
    public string ProfileName => Path.GetFileName(profile);
    public DemoSession()
    {
        profile = Path.Combine(AppContext.BaseDirectory, "fixture-" + Guid.NewGuid().ToString("N") + ".json");
        var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        info.ArgumentList.Add("--fixture-child"); info.ArgumentList.Add(profile);
        child = Process.Start(info) ?? throw new IOException("Could not start the synthetic child.");
        var deadline = Stopwatch.StartNew();
        while (!File.Exists(profile) && !child.HasExited && deadline.Elapsed.TotalSeconds < 10) Thread.Sleep(25);
        if (!File.Exists(profile)) { Dispose(); throw new IOException("Synthetic child did not become ready."); }
    }
    public void Focus() { child.Refresh(); if (child.MainWindowHandle != 0) SetForegroundWindow(child.MainWindowHandle); }
    public void Dispose()
    {
        try { if (!child.HasExited) { child.CloseMainWindow(); if (!child.WaitForExit(2000)) child.Kill(); } }
        finally { child.Dispose(); if (File.Exists(profile)) File.Delete(profile); }
    }
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(nint hwnd);

    public static void RunChild(string profile)
    {
        nint arena = Marshal.AllocHGlobal(64);
        try
        {
            Marshal.Copy(new byte[64], 0, arena, 64);
            Marshal.Copy(Fixture.Magic, 0, arena, Fixture.Magic.Length);
            using var memory = new OverwatchDecoder.Observer.NativeMemory(Environment.ProcessId);
            var data = new
            {
                schema = "overwatch-decoder.field-profile/1", target = Snapshots.PublicIdentity(memory.Identity),
                guards = new[] { new { address = (ulong)arena, bytes_hex = Convert.ToHexString(Fixture.Magic) } },
                fields = new[] {
                    new { name = "synthetic_health", type = "i32", address = (ulong)arena + 16, min = 0, max = 100 },
                    new { name = "synthetic_ammo", type = "i32", address = (ulong)arena + 20, min = 0, max = 40 },
                    new { name = "synthetic_tick", type = "i32", address = (ulong)arena + 24, min = 0, max = 20000 }
                }
            };
            File.WriteAllBytes(profile + ".partial", JsonSerializer.SerializeToUtf8Bytes(data));
            File.Move(profile + ".partial", profile);
            using var form = new Form { Text = "Overwatch Decoder synthetic recording test", Width = 850, Height = 500,
                StartPosition = FormStartPosition.CenterScreen, TopMost = true, KeyPreview = true };
            var label = new Label { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 24), TextAlign = ContentAlignment.MiddleCenter };
            form.Controls.Add(label);
            int tick = 0, keyCount = 0, mouseCount = 0;
            form.KeyDown += (_, _) => keyCount++;
            label.MouseMove += (_, _) => mouseCount++;
            using var timer = new System.Windows.Forms.Timer { Interval = 20 };
            timer.Tick += (_, _) =>
            {
                tick++; int health = 100 - tick % 100, ammo = 40 - tick % 41;
                Marshal.WriteInt32(arena, 16, health); Marshal.WriteInt32(arena, 20, ammo); Marshal.WriteInt32(arena, 24, tick);
                if (tick % 5 == 0) label.Text = $"SYNTHETIC CHILD FIXTURE\nHealth {health}    Ammo {ammo}\nTick {tick}\nKeys {keyCount}    Mouse events {mouseCount}";
                if (tick >= 18000) form.Close();
            };
            form.Shown += (_, _) => timer.Start();
            Application.Run(form);
        }
        finally { Marshal.FreeHGlobal(arena); }
    }
}
