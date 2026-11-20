using System.IO.Compression;
using System.Text.Json;
using OverwatchDecoder.SessionRecorder;

string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-capture-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root); int checks = 0;
void Check(bool ok, string description) { if (!ok) throw new Exception(description); checks++; }
try
{
    string events = Path.Combine(root, "events.gz");
    var journal = new EventJournal(events);
    for (int i = 0; i < 1000; i++) journal.Emit(new { sequence = i, value = "αβγ" });
    await journal.DisposeAsync(); await journal.DisposeAsync();
    Check(journal.Written == 1000 && journal.Dropped == 0 && journal.Error is null, "drains all accepted events exactly once");
    using var reader = new StreamReader(new GZipStream(File.OpenRead(events), CompressionMode.Decompress));
    for (int i = 0; i < 1000; i++)
    {
        using var row = JsonDocument.Parse(reader.ReadLine()!);
        Check(row.RootElement.GetProperty("sequence").GetInt32() == i && row.RootElement.GetProperty("value").GetString() == "αβγ", "order and UTF-8 roundtrip");
    }
    using var terminal = JsonDocument.Parse(reader.ReadLine()!);
    Check(terminal.RootElement.GetProperty("kind").GetString() == "journal_end" && reader.ReadLine() is null, "one terminal record and valid gzip trailer");
    journal.Emit(new { lost = true }); Check(journal.Dropped == 1, "late event accounted instead of reopening");
    var broken = new EventJournal(Path.Combine(root, "broken.gz")); broken.Emit(new BadEvent()); await broken.DisposeAsync();
    Check(broken.Error is not null, "serialization failure is reported");
    string exe = Path.Combine(root, "ffmpeg.exe"); File.WriteAllText(exe, "synthetic file");
    var settings = new CaptureSettings { Memory = [] }; settings.Validate(root);
    Check(CaptureSettings.PackagePath(root, "ffmpeg.exe") == exe, "contained tool path accepted");
    try { _ = CaptureSettings.PackagePath(root, "../outside.exe"); throw new Exception("escape accepted"); }
    catch (InvalidDataException) { checks++; }
    settings.Encoder = "unknown";
    try { settings.Validate(root); throw new Exception("unknown encoder accepted"); }
    catch (InvalidDataException) { checks++; }
    checks += await RosterTests.Run(root);
    checks += await ObservationTests.Run(root);
    checks += ObservationStorageTests.Run(root);
    checks += await ObservationCohortCaptureTests.Run(root);
    checks += await ObservationHandoffTests.Run(root);
    Console.WriteLine($"PASS {checks} recorder journal/config checks");
}
finally { Directory.Delete(root, true); }

sealed class BadEvent { public int Value => throw new IOException("synthetic serialization failure"); }
