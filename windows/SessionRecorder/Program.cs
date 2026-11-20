namespace OverwatchDecoder.SessionRecorder;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => MessageBox.Show(e.Exception.Message, "Overwatch Decoder Recorder", MessageBoxButtons.OK, MessageBoxIcon.Error);
        try
        {
            if (args.Length == 2 && args[0] == "--fixture-child") { DemoSession.RunChild(args[1]); return; }
            int automaticSeconds = 0; string? output = null; bool demo = false;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--auto-record-seconds" && i + 1 < args.Length && int.TryParse(args[++i], out int seconds) && seconds is >= 1 and <= 300)
                    automaticSeconds = seconds;
                else if (args[i] == "--output-root" && i + 1 < args.Length) output = args[++i];
                else if (args[i] == "--demo") demo = true;
                else throw new ArgumentException("Supported options: --demo --auto-record-seconds 1..300 --output-root DIRECTORY");
            }
            using var fixture = demo ? new DemoSession() : null;
            var settings = CaptureSettings.Load(AppContext.BaseDirectory);
            if (fixture is not null) { settings.TargetProcess = "OverwatchDecoderDemo"; settings.Memory = [new("synthetic-child", "profile", fixture.ProfileName, true)]; }
            using var form = new MainForm(settings, automaticSeconds, output, fixture);
            Application.Run(form);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Overwatch Decoder Recorder could not start", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }
}
