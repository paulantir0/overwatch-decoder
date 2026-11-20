using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OverwatchDecoder.Observer;

public static class Program
{
    public static readonly JsonSerializerOptions Json = new()
    { WriteIndented = false, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    public static string Revision => Assembly.GetExecutingAssembly()
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

    public static int Main(string[] args)
    {
        string command = args.FirstOrDefault() ?? "help";
        try
        {
            if (command is "help" or "--help" or "-h")
            {
                Console.WriteLine("overwatch-decoder-observer: read-only Windows memory observation\n" +
                    "  version\n  self-test\n  fixture --seconds 60\n  fixture-pointers --seconds 60\n  fixture-timer --seconds 60\n" +
                    "  probe --process Overwatch | --pid PID\n" +
                    "  snapshot --process Overwatch --out NEW_DIRECTORY [--max-bytes 2147483648] [--seconds 120]\n" +
                    "  scan --process Overwatch --type i32|f32|f64 --value NUMBER --out NEW_DIRECTORY [--scope writable|readable]\n" +
                    "  refine --from CANDIDATE_DIRECTORY --value NUMBER --out NEW_DIRECTORY\n" +
                    "  acquire-fields --pid PID --recipe PRIVATE_RECIPE --out NEW_DIRECTORY\n" +
                    "  observe-fields --pid PID --recipe PRIVATE_RECIPE --out NEW_DIRECTORY [--interval-ms 10] [--seconds 600] [--jsonl true|false] [--live-evidence true|false] [--allow-field-shape-changes true|false] [--reacquire-ms 0 (off, or 1000..30000)] [--acquisition-retry-ms 250 (250..5000)] [--background-prepare true|false] [--max-acquisitions 8 (1..128)] [--max-consecutive-acquisition-failures 3 (1..16)] [--storage-cohort-bytes 0 (off, or 65536..1073741824)] [--max-storage-cohorts 256 (1..4096)]\n" +
                    "  record-candidates --from CANDIDATE_DIRECTORY --out NEW_DIRECTORY [--interval-ms 10] [--seconds 600]\n" +
                    "  stream-fields --pid PID --profile PRIVATE_PROFILE [--interval-ms 10] [--seconds 600]\n" +
                    "  record-fields --pid PID --profile PRIVATE_PROFILE --out NEW_DIRECTORY [--interval-ms 10] [--seconds 600] [--stop-on-unknown true|false] [--storage-cohort-bytes 0 (off, or 65536..1073741824)] [--max-storage-cohorts 256 (1..4096)]\n" +
                    "  verify-fields --from RECORDING_DIRECTORY [--recover-indexed-prefix true|false]\n" +
                    "  export-fields --from RECORDING_DIRECTORY --out NEW_JSONL\n" +
                    "  summarize-fields --from RECORDING_DIRECTORY\n" +
                    "  timeline-fields --from RECORDING_DIRECTORY --out NEW_JSONL\n" +
                    "  search-snapshot --from SNAPSHOT_DIRECTORY --out NEW_DIRECTORY --text TEXT [--encoding utf8|utf16]\n" +
                    "Snapshots are private research; no real-game decoder is bundled yet.");
                return 0;
            }
            if (command == "version") { Emit(command, new { revision = Revision }); return 0; }
            var options = Parse(args.Skip(1).ToArray());
            if (command == "self-test") { CheckKeys(options, []); Tests.Run(); return 0; }
            if (command == "fixture") { CheckKeys(options, ["seconds"]); Fixture.Run(Integer(options, "seconds", 60, 1, 3600)); return 0; }
            if (command == "fixture-timer") { CheckKeys(options, ["seconds"]); TimerFixture.Run(Integer(options, "seconds", 60, 1, 60)); return 0; }
            if (command == "fixture-pointers") { CheckKeys(options, ["seconds"]); PointerFixture.Run(Integer(options, "seconds", 60, 1, 60)); return 0; }
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
            if (command == "timeline-fields")
            {
                CheckKeys(options, ["from", "out"]);
                Emit(command, FieldTimeline.Export(Required(options, "from"), Required(options, "out"), cancellation.Token));
                return 0;
            }
            if (command == "summarize-fields")
            {
                CheckKeys(options, ["from"]);
                Emit(command, FieldSummary.Summarize(Required(options, "from"), cancellation.Token));
                return 0;
            }
            if (command == "export-fields")
            {
                CheckKeys(options, ["from", "out"]);
                Emit(command, FieldExport.Export(Required(options, "from"), Required(options, "out"), cancellation.Token));
                return 0;
            }
            if (command == "verify-fields")
            {
                CheckKeys(options, ["from", "recover-indexed-prefix"]);
                string recovery = options.GetValueOrDefault("recover-indexed-prefix", "false");
                if (recovery is not ("true" or "false"))
                    throw new ObservationException("invalid_arguments", "--recover-indexed-prefix must be true or false.");
                var verification = FieldRecordingVerification.Verify(Required(options, "from"),
                    recoverIndexedPrefix: recovery == "true", cancellationToken: cancellation.Token);
                Emit(command, verification);
                return verification.valid ? 0 : 7;
            }
            if (command == "acquire-fields")
            {
                CheckKeys(options, ["pid", "recipe", "out"]);
                _ = Required(options, "pid"); int acquisitionPid = Integer(options, "pid", 0, 1, int.MaxValue);
                string acquisitionRecipe = Required(options, "recipe"), acquisitionOutput = Required(options, "out");
                using var acquisitionSource = new NativeMemory(acquisitionPid);
                Emit(command, Acquisition.Run(acquisitionSource, Acquisition.MainModule(acquisitionSource), acquisitionRecipe, acquisitionOutput, cancellation.Token));
                return 0;
            }
            if (command == "observe-fields")
            {
                CheckKeys(options, ["pid", "recipe", "out", "interval-ms", "seconds", "jsonl", "live-evidence", "allow-field-shape-changes",
                    "max-acquisitions", "max-consecutive-acquisition-failures", "reacquire-ms", "background-prepare", "acquisition-retry-ms", "storage-cohort-bytes", "max-storage-cohorts"]);
                string jsonl = options.GetValueOrDefault("jsonl", "false");
                if (jsonl is not ("true" or "false")) throw new ObservationException("invalid_arguments", "--jsonl must be true or false.");
                bool liveEvidence = LiveEvidenceOption(options, jsonl == "true");
                string shapeChanges = options.GetValueOrDefault("allow-field-shape-changes", "false");
                if (shapeChanges is not ("true" or "false")) throw new ObservationException("invalid_arguments", "--allow-field-shape-changes must be true or false.");
                _ = Required(options, "pid");
                int observationPid = Integer(options, "pid", 0, 1, int.MaxValue);
                string recipe = Required(options, "recipe"), directory = Required(options, "out");
                int interval = Integer(options, "interval-ms", 10, 10, 10000);
                TimeSpan duration = TimeSpan.FromSeconds(Integer(options, "seconds", 600, 1, 36000));
                int maxAcquisitions = Integer(options, "max-acquisitions", ObserveFields.DefaultMaximumAcquisitions, 1, ObserveFields.MaximumAttempts);
                int maxConsecutiveFailures = Integer(options, "max-consecutive-acquisition-failures",
                    ObserveFields.DefaultMaximumConsecutiveAcquisitionFailures, 1, ObserveFields.MaximumConsecutiveAcquisitionFailures);
                int acquisitionRetry = AcquisitionRetryOption(options);
                StorageRotation? storage = StorageOption(options);
                int reacquire = Integer(options, "reacquire-ms", 0, 0, 30000);
                if (reacquire is > 0 and < 1000)
                    throw new ObservationException("invalid_arguments", "--reacquire-ms must be 0 or 1000..30000.");
                string preparation = options.GetValueOrDefault("background-prepare", "false");
                if (preparation is not ("true" or "false") || preparation == "true" && reacquire == 0)
                    throw new ObservationException("invalid_arguments", "--background-prepare requires true/false and a nonzero --reacquire-ms when enabled.");
                using var memory = new NativeMemory(observationPid);
                if (jsonl == "true") Console.OutputEncoding = new System.Text.UTF8Encoding(false);
                var result = ObserveFields.Run(memory, Acquisition.MainModule(memory), recipe, directory, interval, duration, cancellation.Token,
                    jsonl == "true" ? Console.Out : null, allowFieldShapeChanges: shapeChanges == "true", liveEvidence: liveEvidence,
                    maxAcquisitions: maxAcquisitions, maxConsecutiveAcquisitionFailures: maxConsecutiveFailures, reacquireMs: reacquire, backgroundPreparation: preparation == "true", acquisitionRetryMs: acquisitionRetry, storage: storage);
                if (jsonl == "false") Emit(command, result);
                return result.complete ? 0 : result.stop_reason == "permission_denied" ? 4 : result.stop_reason is "identity_mismatch" or "module_identity_mismatch" or "process_exited" ? 2 : 7;
            }
            if (command is "stream-fields" or "record-fields")
            {
                CheckKeys(options, command == "stream-fields" ? ["pid", "profile", "interval-ms", "seconds"] :
                    ["pid", "profile", "out", "interval-ms", "seconds", "stop-on-unknown", "storage-cohort-bytes", "max-storage-cohorts"]);
                string stopOnUnknown = options.GetValueOrDefault("stop-on-unknown", "false");
                if (stopOnUnknown is not ("true" or "false"))
                    throw new ObservationException("invalid_arguments", "--stop-on-unknown must be true or false.");
                string profile = Required(options, "profile");
                string? recordingDirectory = command == "record-fields" ? Required(options, "out") : null;
                StorageRotation? storage = recordingDirectory is null ? null : StorageOption(options);
                _ = Required(options, "pid");
                int intervalMs = Integer(options, "interval-ms", 10, 10, 10000);
                TimeSpan duration = TimeSpan.FromSeconds(Integer(options, "seconds", 600, 1, 36000));
                using var memory = new NativeMemory(Integer(options, "pid", 0, 1, int.MaxValue));
                Console.OutputEncoding = new System.Text.UTF8Encoding(false);
                if (recordingDirectory is not null)
                {
                    var recording = FieldRecording.Record(memory, profile, recordingDirectory, intervalMs, duration, cancellation.Token, stopOnUnknown == "true", storage);
                    Emit(command, recording);
                    return CompleteExit(recording);
                }
                var result = FieldStream.Run(memory, profile, intervalMs, duration, Console.Out, cancellation.Token);
                return CompleteExit(result);
            }
            if (command == "search-snapshot")
            {
                CheckKeys(options, ["from", "out", "text", "encoding", "max-matches"]);
                var result = SnapshotSearch.Find(Required(options, "from"), Required(options, "out"), Required(options, "text"),
                    options.GetValueOrDefault("encoding", "utf8"), Integer(options, "max-matches", 1000, 1, 100000), cancellation.Token);
                Emit(command, result);
                return CompleteExit(result);
            }
            if (command is "refine" or "record-candidates")
            {
                CheckKeys(options, command == "refine" ? ["from", "value", "out"] : ["from", "out", "interval-ms", "seconds"]);
                string input = Required(options, "from");
                using var manifest = ResearchScan.OpenManifest(input);
                using var memory = new NativeMemory(manifest.RootElement.GetProperty("target").GetProperty("pid").GetInt32());
                var result = command == "refine" ?
                    ResearchScan.Refine(memory, input, Required(options, "out"), Required(options, "value"), cancellation.Token) :
                    ResearchRecorder.Record(memory, input, Required(options, "out"), Integer(options, "interval-ms", 10, 10, 10000),
                        TimeSpan.FromSeconds(Integer(options, "seconds", 600, 1, 36000)), cancellation.Token);
                Emit(command, result);
                return CompleteExit(result);
            }
            if (command is not ("probe" or "snapshot" or "scan"))
                throw new ObservationException("invalid_arguments", "Unknown command.");
            CheckKeys(options, command switch
            {
                "probe" => ["pid", "process"],
                "scan" => ["pid", "process", "out", "type", "value", "scope", "max-candidates", "seconds"],
                _ => ["pid", "process", "out", "max-bytes", "seconds"]
            });
            int? pid = options.ContainsKey("pid") ? Integer(options, "pid", 0, 1, int.MaxValue) : null;
            using var source = new NativeMemory(NativeMemory.Resolve(options.GetValueOrDefault("process"), pid));
            if (command == "probe") { Emit(command, Snapshots.Probe(source)); return 0; }
            if (command == "scan")
            {
                string scope = options.GetValueOrDefault("scope", "writable");
                if (scope is not ("writable" or "readable")) throw new ObservationException("invalid_arguments", "Invalid scan scope.");
                var result = ResearchScan.Scan(source, Required(options, "out"), Required(options, "type"),
                    Required(options, "value"), scope == "readable", Integer(options, "max-candidates", 100000, 1, 1000000),
                    TimeSpan.FromSeconds(Integer(options, "seconds", 120, 1, 3600)), cancellation.Token);
                Emit(command, result);
                return CompleteExit(result);
            }
            if (!options.TryGetValue("out", out string? output) || string.IsNullOrWhiteSpace(output))
                throw new ObservationException("invalid_arguments", "snapshot requires --out NEW_DIRECTORY.");
            if (!long.TryParse(options.GetValueOrDefault("max-bytes", "2147483648"), out long maximum) || maximum < 1)
                throw new ObservationException("invalid_arguments", "--max-bytes must be a positive integer.");
            var summary = Snapshots.Capture(source, output, maximum,
                TimeSpan.FromSeconds(Integer(options, "seconds", 120, 1, 36000)), cancellation.Token);
            Emit(command, summary);
            return CompleteExit(summary);
        }
        catch (ObservationException e)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            { schema = "overwatch-decoder.windows/1", command, ok = false, revision = Revision,
                error = new { code = e.Code, message = e.Message, native_code = e.NativeCode } }, Json));
            return e.Code == "permission_denied" ? 4 : 2;
        }
        catch (Exception e)
        {
            // Messages from filesystem exceptions may contain private local paths.
            Console.WriteLine(JsonSerializer.Serialize(new
            { schema = "overwatch-decoder.windows/1", command, ok = false, revision = Revision,
                error = new { code = "internal_error", type = e.GetType().Name,
                    // Self-test diagnostics expose method names only, never messages or local source paths.
                    test_frames = command == "self-test" ? new System.Diagnostics.StackTrace(e, false).GetFrames()
                        .Take(8).Select(frame => frame.GetMethod()).Where(method => method is not null)
                        .Select(method => new { type = method!.DeclaringType?.FullName, method = method.Name }).ToArray() : null
                } }, Json));
            return 1;
        }
    }

    internal static StorageRotation? StorageOption(Dictionary<string, string> options)
    {
        if (!long.TryParse(options.GetValueOrDefault("storage-cohort-bytes", "0"), out long bytes))
            throw new ObservationException("invalid_arguments", "Invalid storage cohort byte limit.");
        if (bytes == 0)
        {
            if (options.ContainsKey("max-storage-cohorts"))
                throw new ObservationException("invalid_arguments", "Storage cohort count requires enabled storage rotation.");
            return null;
        }
        var storage = new StorageRotation(bytes, Integer(options, "max-storage-cohorts", 256, 1, StorageRotation.MaximumCount));
        storage.Validate(); return storage;
    }

    internal static int AcquisitionRetryOption(Dictionary<string, string> options) =>
        Integer(options, "acquisition-retry-ms", 250, 250, 5000);

    internal static bool LiveEvidenceOption(Dictionary<string, string> options, bool jsonl)
    {
        string value = options.GetValueOrDefault("live-evidence", "false");
        if (value is not ("true" or "false") || (value == "true" && !jsonl))
            throw new ObservationException("invalid_arguments", "--live-evidence must be true or false and requires --jsonl true when enabled.");
        return value == "true";
    }

    private static int CompleteExit(object result)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(result));
        return document.RootElement.GetProperty("complete").GetBoolean() ? 0 : 7;
    }

    private static string Required(Dictionary<string, string> options, string key) =>
        options.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value) ? value :
        throw new ObservationException("invalid_arguments", "Missing --" + key + " value.");

    public static void Emit(string command, object result) => Console.WriteLine(JsonSerializer.Serialize(new
    { schema = "overwatch-decoder.windows/1", command, ok = true, revision = Revision, timestamp = DateTimeOffset.UtcNow, result }, Json));

    public static Dictionary<string, string> Parse(string[] args)
    {
        var values = new Dictionary<string, string>();
        for (int i = 0; i < args.Length; i += 2)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 == args.Length ||
                args[i + 1].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(args[i][2..], args[i + 1]))
                throw new ObservationException("invalid_arguments", "Expected unique --name value pairs.");
        }
        return values;
    }

    private static int Integer(Dictionary<string, string> options, string key, int fallback, int min, int max)
    {
        if (!options.TryGetValue(key, out string? text)) return fallback;
        if (!int.TryParse(text, out int value) || value < min || value > max)
            throw new ObservationException("invalid_arguments", "Invalid --" + key + " value.");
        return value;
    }

    private static void CheckKeys(Dictionary<string, string> options, string[] allowed)
    {
        if (options.Keys.Any(k => !allowed.Contains(k)))
            throw new ObservationException("invalid_arguments", "Unrecognized option.");
    }
}
