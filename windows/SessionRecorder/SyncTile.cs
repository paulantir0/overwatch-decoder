using System.Diagnostics;

namespace OverwatchDecoder.SessionRecorder;

/// <summary>A visible start marker whose paint intervals can be matched to video frames.</summary>
public sealed class SyncTile : Form
{
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 125 };
    private readonly Action<object> emit;
    private int sequence;
    protected override bool ShowWithoutActivation => true;
    protected override CreateParams CreateParams { get { var p = base.CreateParams; p.ExStyle |= 0x08000000; return p; } }
    public SyncTile(Screen screen, Action<object> emit)
    {
        this.emit = emit; Text = "Overwatch Decoder synchronization"; FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual; Bounds = new Rectangle(screen.Bounds.Left + 24, screen.Bounds.Top + 24, 420, 145);
        TopMost = true; ShowInTaskbar = false; DoubleBuffered = true;
        timer.Tick += (_, _) => { sequence++; Invalidate(); };
        Shown += (_, _) => timer.Start();
        FormClosed += (_, _) => timer.Dispose();
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        long before = Stopwatch.GetTimestamp();
        e.Graphics.Clear(Color.FromArgb(16, 26, 45));
        using var font = new Font("Segoe UI", 14, FontStyle.Bold);
        e.Graphics.DrawString($"Overwatch Decoder capture sync  {sequence:D4}", font, Brushes.White, 12, 10);
        for (int bit = 0; bit < 12; bit++)
            e.Graphics.FillRectangle((sequence & (1 << bit)) != 0 ? Brushes.White : Brushes.Black, 12 + bit * 33, 55, 28, 48);
        e.Graphics.DrawString("Starting your recording…", Font, Brushes.LightGray, 12, 114);
        emit(new { kind = "video_calibration_paint", sequence, qpc_before_paint = before, qpc_after_paint = Stopwatch.GetTimestamp(),
            qpc_frequency = Stopwatch.Frequency, note = "Paint submission interval; compositor presentation latency not measured." });
        base.OnPaint(e);
    }
}
