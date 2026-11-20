using System.Text.Json;

namespace OverwatchDecoder.SessionRecorder;

public sealed record MemoryPlan(string Name, string Kind, string Path, bool Required = false, int IntervalMs = 20);

public sealed class CaptureSettings
{
    public string TargetProcess { get; set; } = "Overwatch";
    public string Encoder { get; set; } = "h264_amf";
    public string FfmpegPath { get; set; } = "ffmpeg.exe";
    public string OutputRoot { get; set; } = "";
    public int MaximumMinutes { get; set; } = 120;
    public bool SystemAudio { get; set; } = true;
    public MemoryPlan[] Memory { get; set; } = [];
    public RosterPlan? Roster { get; set; }
    public ObservationPlan? Observations { get; set; }

    public static CaptureSettings Load(string directory)
    {
        string path = System.IO.Path.Combine(directory, "capture-settings.json");
        if (!File.Exists(path)) throw new InvalidDataException("The recording configuration is missing. Keep the whole Overwatch Decoder Recorder folder together.");
        if (new FileInfo(path).Length > 65536) throw new InvalidDataException("Recording configuration is too large.");
        var value = JsonSerializer.Deserialize<CaptureSettings>(File.ReadAllBytes(path), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("Invalid recording configuration.");
        value.Validate(directory);
        return value;
    }

    public void Validate(string directory)
    {
        if (TargetProcess.Length is < 1 or > 64 || TargetProcess.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
            throw new InvalidDataException("Invalid target process name.");
        if (Encoder is not ("h264_amf" or "h264_nvenc" or "h264_qsv")) throw new InvalidDataException("Choose an AMD, NVIDIA or Intel hardware encoder.");
        if (MaximumMinutes is < 1 or > 240 || Memory.Length > 4) throw new InvalidDataException("Invalid recording duration or memory plan count.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var plan in Memory)
        {
            if (plan.Name.Length is < 1 or > 48 || plan.Name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_') || !names.Add(plan.Name))
                throw new InvalidDataException("Memory stream names must be distinct simple names.");
            if (plan.Kind is not ("recipe" or "profile") || plan.IntervalMs is < 20 or > 1000) throw new InvalidDataException("Unsupported memory recording plan.");
            _ = PackagePath(directory, plan.Path);
        }
        _ = PackagePath(directory, FfmpegPath);
        if (Roster is not null) RosterCapture.Validate(directory, Roster);
        if (Observations is not null) ObservationCapture.Validate(directory, Observations);
    }

    public static string PackagePath(string directory, string relative)
    {
        string root = System.IO.Path.GetFullPath(directory).TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar;
        string result = System.IO.Path.GetFullPath(System.IO.Path.Combine(root, relative));
        if (System.IO.Path.IsPathRooted(relative) || !result.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Package files must be inside the recorder folder.");
        if (!File.Exists(result)) throw new FileNotFoundException("A required recorder file is missing.", relative);
        return result;
    }
}
