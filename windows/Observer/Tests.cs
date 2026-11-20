using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

public static class Tests
{
    private static void Require(bool condition, string name)
    { if (!condition) throw new ObservationException("self_test_failed", name); }
    private static void Throws(Action action, string code)
    {
        try { action(); }
        catch (ObservationException e) { Require(e.Code == code, "error-code:" + code); return; }
        throw new ObservationException("self_test_failed", "Expected error: " + code);
    }

    private sealed class FakeMemory(bool fail = false, string failureCode = "unreadable_range") : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(123, "fixture.exe", "private-test-path", 1, "fixture-hash", "x64");
        public int Calls { get; private set; }
        public long ReadEnteredTicks { get; private set; }
        public long ReadExitedTicks { get; private set; }
        public IEnumerable<MemoryRegion> Regions() => [new(4096, 100, 0x1000, 0x04, 0x20000)];
        public byte[] Read(ulong address, int size)
        {
            ReadEnteredTicks = Stopwatch.GetTimestamp();
            try
            {
                Calls++;
                if (fail) throw new ObservationException(failureCode, "Synthetic fixture read failure.");
                return Enumerable.Range(0, size).Select(i => (byte)((address - 4096 + (ulong)i) % 256)).ToArray();
            }
            finally { ReadExitedTicks = Stopwatch.GetTimestamp(); }
        }
        public void EnsureAlive() { }
        public void Dispose() { }
    }

    private sealed class ScanMemory : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(124, "test.exe", "private-test-path", 2, "test-build", "x64");
        public byte[] Data { get; } = new byte[8192];
        public IEnumerable<MemoryRegion> Regions() => [new(4096, 8192, 0x1000, 0x04, 0x20000)];
        public byte[] Read(ulong address, int size)
        {
            if (address < 4096 || address + (ulong)size > 12288)
                throw new ObservationException("unreadable_range", "Out of test range.");
            return Data.AsSpan((int)(address - 4096), size).ToArray();
        }
        public void EnsureAlive() { }
        public void Dispose() { }
    }

    public static void Run()
    {
        int assertions = AcquisitionEnumerationTests.Run() + StorageCohortTests.Run() + FieldCapacityTests.Run() + AcquisitionRetryTests.Run() + IntegerVectorTests.Run() + NativeReadSetupTests.Run() + ObservePreparationTests.Run() + PoolSumTests.Run() + LiveFieldEvidenceTests.Run() + AcquisitionTests.Run() + AcquisitionCollectionTests.Run() + AcquisitionNestedCollectionTests.Run() + TimerTests.Run() + ObserveFieldsTests.Run() + ObserveFieldShapeTests.Run() + ObservationManifestTests.Run() + EntityIdentityProjectionTests.Run();
        void Check(bool condition, string name) { Require(condition, name); assertions++; }
        void CheckSnapshotTiming(JsonElement row, FakeMemory source, string name)
        {
            long start = row.GetProperty("read_start_ticks").GetInt64();
            long end = row.GetProperty("read_end_ticks").GetInt64();
            Check(start == row.GetProperty("monotonic_ticks").GetInt64(), name + ": legacy timestamp remains start");
            Check(start <= source.ReadEnteredTicks && source.ReadEnteredTicks <= source.ReadExitedTicks &&
                source.ReadExitedTicks <= end && end <= Stopwatch.GetTimestamp(), name + ": recorded interval encloses source read");
        }
        var r = new MemoryRegion(4096, 4096, 0x1000, 0x04, 0x20000);
        Check(r.Readable, "readable committed page");
        Check(!new MemoryRegion(0, 4096, 0x1000, 0x104, 0).Readable, "guard excluded");
        Check(!new MemoryRegion(0, 4096, 0x2000, 0x04, 0).Readable, "reserved excluded");
        Check(!new MemoryRegion(0, 4096, 0x1000, 0x10, 0).Readable, "execute-only excluded");
        Check(!new MemoryRegion(0, 4096, 0x1000, 0x01, 0).Readable, "no-access excluded");
        Check(r.Contains(4096, 4096) && r.Contains(8191, 1), "inclusive start exclusive end");
        Check(!r.Contains(8191, 2) && !r.Contains(4095, 1), "cross-region excluded");
        Check(!r.Contains(4096, 0) && !r.Contains(4096, -1), "nonpositive size excluded");
        Check(!r.Contains(ulong.MaxValue, 2), "integer overflow excluded");
        Throws(() => Program.Parse(["--pid"]), "invalid_arguments"); assertions++;
        Throws(() => Program.Parse(["--pid", "1", "--pid", "2"]), "invalid_arguments"); assertions++;
        Check(Program.Parse(["--out", "a path with spaces"])["out"] == "a path with spaces", "paths with spaces");
        var fake = new FakeMemory();
        string identity = JsonSerializer.Serialize(Snapshots.PublicIdentity(fake.Identity));
        Check(!identity.Contains("private-test-path", StringComparison.Ordinal), "public identity redacts path");
        string root = Path.Combine(Path.GetTempPath(), "overwatch-decoder-self-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string full = Path.Combine(root, "full");
            Snapshots.Capture(fake, full, 1000, TimeSpan.FromSeconds(10), CancellationToken.None);
            using var fullManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(full, "manifest.json")));
            Check(fullManifest.RootElement.GetProperty("complete").GetBoolean(), "snapshot completion");
            Check(!fullManifest.RootElement.GetProperty("atomic").GetBoolean(), "non-atomic declared");
            byte[] captured = File.ReadAllBytes(Path.Combine(full, "memory.bin"));
            Check(captured.Length == 100 && captured[99] == 99, "snapshot bytes match source");
            using var chunk = JsonDocument.Parse(File.ReadLines(Path.Combine(full, "chunks.jsonl")).Single());
            Check(chunk.RootElement.GetProperty("sha256").GetString() == Convert.ToHexStringLower(SHA256.HashData(captured)), "chunk digest");
            CheckSnapshotTiming(chunk.RootElement, fake, "successful snapshot");
            Check(fullManifest.RootElement.GetProperty("monotonic_frequency").GetInt64() == Stopwatch.Frequency &&
                fullManifest.RootElement.GetProperty("read_timing").GetString()!.Contains("unknown read duration", StringComparison.Ordinal),
                "snapshot timing origin and legacy limitation are explicit");
            Throws(() => Snapshots.Capture(fake, full, 1000, TimeSpan.FromSeconds(1), CancellationToken.None), "output_exists"); assertions++;
            string limited = Path.Combine(root, "limited");
            Snapshots.Capture(fake, limited, 20, TimeSpan.FromSeconds(10), CancellationToken.None);
            using var limitManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(limited, "manifest.json")));
            Check(!limitManifest.RootElement.GetProperty("complete").GetBoolean() &&
                limitManifest.RootElement.GetProperty("stop_reason").GetString() == "byte_limit", "byte limit does not claim complete");
            Check(new FileInfo(Path.Combine(limited, "memory.bin")).Length == 20, "byte budget honored");
            string failed = Path.Combine(root, "failed");
            var failedSource = new FakeMemory(true);
            Snapshots.Capture(failedSource, failed, 1000, TimeSpan.FromSeconds(10), CancellationToken.None);
            using var failedManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(failed, "manifest.json")));
            Check(!failedManifest.RootElement.GetProperty("complete").GetBoolean() &&
                failedManifest.RootElement.GetProperty("failed_chunks").GetInt32() == 1, "failed reads recorded");
            using var failedChunk = JsonDocument.Parse(File.ReadLines(Path.Combine(failed, "chunks.jsonl")).Single());
            CheckSnapshotTiming(failedChunk.RootElement, failedSource, "unreadable snapshot");
            foreach (string fatalCode in new[] { "permission_denied", "process_exited", "identity_mismatch" })
            {
                var deniedSource = new FakeMemory(true, fatalCode);
                string denied = Path.Combine(root, fatalCode);
                var deniedResult = JsonSerializer.SerializeToElement(Snapshots.Capture(deniedSource, denied, 1000,
                    TimeSpan.FromSeconds(10), CancellationToken.None));
                using var deniedChunk = JsonDocument.Parse(File.ReadLines(Path.Combine(denied, "chunks.jsonl")).Single());
                CheckSnapshotTiming(deniedChunk.RootElement, deniedSource, fatalCode + " snapshot");
                Check(deniedSource.Calls == 1 && !deniedResult.GetProperty("complete").GetBoolean() &&
                    deniedResult.GetProperty("stop_reason").GetString() == fatalCode &&
                    deniedResult.GetProperty("failed_chunks").GetInt32() == 1 &&
                    deniedChunk.RootElement.GetProperty("error").GetString() == fatalCode &&
                    !deniedChunk.RootElement.GetProperty("ok").GetBoolean() &&
                    new FileInfo(Path.Combine(denied, "memory.bin")).Length == 0,
                    fatalCode + " attempt remains a timed failure without bytes");
            }
            string cancelled = Path.Combine(root, "cancelled");
            Snapshots.Capture(fake, cancelled, 1000, TimeSpan.FromSeconds(10), new CancellationToken(true));
            using var cancelledManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(cancelled, "manifest.json")));
            Check(cancelledManifest.RootElement.GetProperty("stop_reason").GetString() == "cancelled", "cancelled snapshot recorded");

            var scanMemory = new ScanMemory();
            BitConverter.GetBytes(31).CopyTo(scanMemory.Data, 24);
            BitConverter.GetBytes(31).CopyTo(scanMemory.Data, 60);
            BitConverter.GetBytes(31).CopyTo(scanMemory.Data, 101); // Misaligned decoy.
            string scanDir = Path.Combine(root, "scan");
            ResearchScan.Scan(scanMemory, scanDir, "i32", "31", false, 100, TimeSpan.FromSeconds(10), CancellationToken.None);
            using var scanManifest = ResearchScan.OpenManifest(scanDir);
            Check(scanManifest.RootElement.GetProperty("candidates").GetInt32() == 2, "scan finds aligned candidates and excludes decoy");
            Check(!scanManifest.RootElement.GetProperty("public_state_eligible").GetBoolean(), "candidate is not gameplay truth");
            BitConverter.GetBytes(29).CopyTo(scanMemory.Data, 24);
            string refineDir = Path.Combine(root, "refined");
            ResearchScan.Refine(scanMemory, scanDir, refineDir, "29", CancellationToken.None);
            using var refineManifest = ResearchScan.OpenManifest(refineDir);
            Check(refineManifest.RootElement.GetProperty("candidates").GetInt32() == 1, "refine rejects unchanged decoy");
            var candidate = JsonSerializer.Deserialize<ResearchScan.Candidate>(File.ReadLines(Path.Combine(refineDir, "candidates.jsonl")).Single());
            Check(candidate?.address == 4120, "refine retained changing address");
            Throws(() => ResearchScan.Refine(fake, scanDir, Path.Combine(root, "wrong-target"), "29", CancellationToken.None), "identity_mismatch"); assertions++;
            string truncated = Path.Combine(root, "truncated-scan");
            ResearchScan.Scan(scanMemory, truncated, "i32", "0", false, 1, TimeSpan.FromSeconds(10), CancellationToken.None);
            using var truncManifest = ResearchScan.OpenManifest(truncated);
            Check(!truncManifest.RootElement.GetProperty("complete").GetBoolean() &&
                truncManifest.RootElement.GetProperty("stop_reason").GetString() == "candidate_limit", "truncated scan explicit");
            File.AppendAllText(Path.Combine(scanDir, "candidates.jsonl"), "tampered");
            Throws(() => ResearchScan.OpenManifest(scanDir), "digest_mismatch"); assertions++;
            Throws(() => ResearchScan.Pattern("f32", "NaN"), "invalid_arguments"); assertions++;
            Throws(() => ResearchScan.Pattern("i32", "2147483648"), "invalid_arguments"); assertions++;

            string searchDir = Path.Combine(root, "text-search");
            SnapshotSearch.Find(full, searchDir, "ABC", "utf8", 10, CancellationToken.None);
            using var searchManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(searchDir, "manifest.json")));
            Check(searchManifest.RootElement.GetProperty("matches").GetInt32() == 1, "text found in hash-verified saved bytes");
            using var textMatch = JsonDocument.Parse(File.ReadLines(Path.Combine(searchDir, "matches.jsonl")).Single());
            Check(textMatch.RootElement.GetProperty("address").GetUInt64() == 4161, "saved match maps back to captured address");
            Check(textMatch.RootElement.GetProperty("sampled_ticks").GetInt64() == chunk.RootElement.GetProperty("monotonic_ticks").GetInt64() &&
                textMatch.RootElement.GetProperty("read_start_ticks").GetInt64() == chunk.RootElement.GetProperty("read_start_ticks").GetInt64() &&
                textMatch.RootElement.GetProperty("read_end_ticks").GetInt64() == chunk.RootElement.GetProperty("read_end_ticks").GetInt64(),
                "snapshot search retains exact read interval and start alias");
            Check(searchManifest.RootElement.GetProperty("monotonic_frequency").GetInt64() == Stopwatch.Frequency,
                "snapshot search retains source clock frequency");
            string legacy = Path.Combine(root, "legacy-snapshot");
            Directory.CreateDirectory(legacy);
            File.Copy(Path.Combine(full, "memory.bin"), Path.Combine(legacy, "memory.bin"));
            var legacyManifest = JsonNode.Parse(fullManifest.RootElement.GetRawText())!.AsObject();
            legacyManifest.Remove("read_timing");
            File.WriteAllText(Path.Combine(legacy, "manifest.json"), legacyManifest.ToJsonString());
            var legacyChunk = JsonNode.Parse(chunk.RootElement.GetRawText())!.AsObject();
            legacyChunk.Remove("read_start_ticks"); legacyChunk.Remove("read_end_ticks");
            File.WriteAllText(Path.Combine(legacy, "chunks.jsonl"), legacyChunk.ToJsonString() + "\n");
            string legacySearch = Path.Combine(root, "legacy-search");
            SnapshotSearch.Find(legacy, legacySearch, "ABC", "utf8", 10, CancellationToken.None);
            using var legacyMatch = JsonDocument.Parse(File.ReadLines(Path.Combine(legacySearch, "matches.jsonl")).Single());
            Check(legacyMatch.RootElement.GetProperty("read_end_ticks").ValueKind == JsonValueKind.Null &&
                legacyMatch.RootElement.GetProperty("read_start_ticks").GetInt64() == chunk.RootElement.GetProperty("monotonic_ticks").GetInt64() &&
                legacyMatch.RootElement.GetProperty("sampled_ticks").GetInt64() == chunk.RootElement.GetProperty("monotonic_ticks").GetInt64(),
                "old snapshot search keeps start and explicitly unknown end");
            Check(legacyMatch.RootElement.GetProperty("sampled_utc").GetString() == chunk.RootElement.GetProperty("sampled_utc").GetString(),
                "old snapshot search does not reinterpret UTC record time");
            long oldStart = chunk.RootElement.GetProperty("monotonic_ticks").GetInt64();
            foreach (var invalidTiming in new[] {
                new JsonObject { ["read_start_ticks"] = oldStart + 1 },
                new JsonObject { ["read_end_ticks"] = oldStart - 1 },
                new JsonObject { ["read_end_ticks"] = "invalid" } })
            {
                var invalidChunk = legacyChunk.DeepClone().AsObject();
                foreach (var property in invalidTiming) invalidChunk[property.Key] = property.Value!.DeepClone();
                File.WriteAllText(Path.Combine(legacy, "chunks.jsonl"), invalidChunk.ToJsonString() + "\n");
                Throws(() => SnapshotSearch.Find(legacy, Path.Combine(root, "bad-timing-" + Guid.NewGuid().ToString("N")),
                    "ABC", "utf8", 10, CancellationToken.None), "invalid_manifest"); assertions++;
            }
            Check(!searchManifest.RootElement.GetProperty("public_state_eligible").GetBoolean(), "saved text remains research");
            Throws(() => SnapshotSearch.Find(full, searchDir, "ABC", "utf8", 10, CancellationToken.None), "output_exists"); assertions++;
            string cancelledSearch = Path.Combine(root, "cancelled-search");
            SnapshotSearch.Find(full, cancelledSearch, "ABC", "utf8", 10, new CancellationToken(true));
            using var cancelledSearchManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(cancelledSearch, "manifest.json")));
            Check(!cancelledSearchManifest.RootElement.GetProperty("complete").GetBoolean() &&
                cancelledSearchManifest.RootElement.GetProperty("stop_reason").GetString() == "cancelled", "cancelled search explicit");
            string gapSearch = Path.Combine(root, "gap-search");
            SnapshotSearch.Find(failed, gapSearch, "ABC", "utf8", 10, CancellationToken.None);
            using var gapSearchManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(gapSearch, "manifest.json")));
            Check(gapSearchManifest.RootElement.GetProperty("source_read_gaps").GetInt32() == 1 &&
                !gapSearchManifest.RootElement.GetProperty("snapshot_complete").GetBoolean(), "search retains source gaps");

            Encoding.Unicode.GetBytes("fixture text").CopyTo(scanMemory.Data, 32);
            Encoding.Unicode.GetBytes("fixture text").CopyTo(scanMemory.Data, 101); // Misaligned decoy.
            string unicodeSnapshot = Path.Combine(root, "unicode-snapshot");
            Snapshots.Capture(scanMemory, unicodeSnapshot, 1000, TimeSpan.FromSeconds(10), CancellationToken.None);
            string unicodeSearch = Path.Combine(root, "unicode-search");
            SnapshotSearch.Find(unicodeSnapshot, unicodeSearch, "fixture text", "utf16", 10, CancellationToken.None);
            using var unicodeMatch = JsonDocument.Parse(File.ReadLines(Path.Combine(unicodeSearch, "matches.jsonl")).Single());
            Check(unicodeMatch.RootElement.GetProperty("address").GetUInt64() == 4128, "UTF-16 search excludes odd-address decoy");
            string asciiLimitedSearch = Path.Combine(root, "ascii-limited-search");
            SnapshotSearch.Find(unicodeSnapshot, asciiLimitedSearch, "\0\0", "utf8", 1, CancellationToken.None);
            using var limitedSearchManifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(asciiLimitedSearch, "manifest.json")));
            Check(limitedSearchManifest.RootElement.GetProperty("matches").GetInt32() == 1 &&
                limitedSearchManifest.RootElement.GetProperty("stop_reason").GetString() == "match_limit" &&
                !limitedSearchManifest.RootElement.GetProperty("complete").GetBoolean(), "search match cap explicit");
            captured[66] = 0;
            File.WriteAllBytes(Path.Combine(full, "memory.bin"), captured);
            Throws(() => SnapshotSearch.Find(full, Path.Combine(root, "corrupted-search"), "ABC", "utf8", 10, CancellationToken.None), "digest_mismatch"); assertions++;
        }
        finally { Directory.Delete(root, true); }

        int samples = 0, nativeFieldFrames = 0, nativeByteObservations = 0;
        assertions += RecordingTests.Run();
        assertions += FieldStreamTests.Run();
        assertions += FieldRecordingTests.Run();
        assertions += FieldRecordingStopTests.Run();
        assertions += FieldRecordingVerificationTests.Run();
        assertions += PointerPathTests.Run();
        assertions += FieldExportTests.Run();
        assertions += FieldSummaryTests.Run();
        assertions += FieldTimelineTests.Run();
        assertions += FieldSerializationTests.Run();
        assertions += GuardBatchTests.Run();
        if (OperatingSystem.IsWindows())
        {
            string executable = Environment.ProcessPath ?? throw new InvalidOperationException();
            var info = new ProcessStartInfo(executable)
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                info.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
            info.ArgumentList.Add("fixture"); info.ArgumentList.Add("--seconds"); info.ArgumentList.Add("30");
            using var child = Process.Start(info) ?? throw new InvalidOperationException();
            try
            {
                string? ready = child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
                using var doc = JsonDocument.Parse(ready ?? "{}");
                var descriptor = doc.RootElement.GetProperty("result");
                ulong address = descriptor.GetProperty("address").GetUInt64();
                using var memory = new NativeMemory(child.Id);
                for (int n = 0; n < 100; n++)
                {
                    byte[] first = memory.Read(address, Fixture.Size);
                    byte[] second = memory.Read(address, Fixture.Size);
                    long generation = BitConverter.ToInt64(first, 8);
                    if ((generation & 1) != 0 || generation == 0 || generation != BitConverter.ToInt64(second, 8)) continue;
                    long tick = BitConverter.ToInt64(first, 32);
                    Check(first.AsSpan(0, 8).SequenceEqual(Fixture.Magic), "native child magic");
                    Check(generation == tick * 2 && BitConverter.ToInt32(first, 16) == 100 - tick % 50 &&
                        BitConverter.ToInt32(first, 20) == tick % 31, "native child state matches independent fixture rule");
                    samples++; Thread.Sleep(10);
                }
                Check(samples >= 10, "native child changing state read repeatedly");
                Throws(() => memory.Read(address, 0), "invalid_read_size"); assertions++;
                Throws(() => memory.Read(address, NativeMemory.MaxRead + 1), "invalid_read_size"); assertions++;
                Throws(() => memory.Read(0, 8), "unreadable_range"); assertions++;
                string nativeRoot = Path.Combine(Path.GetTempPath(), "overwatch-decoder-native-field-test-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(nativeRoot);
                try
                {
                    string profilePath = Path.Combine(nativeRoot, "profile.json");
                    File.WriteAllText(profilePath, JsonSerializer.Serialize(new
                    {
                        schema = "overwatch-decoder.field-profile/1", target = Snapshots.PublicIdentity(memory.Identity),
                        guards = new[] { new { address, bytes_hex = Convert.ToHexStringLower(Fixture.Magic) } },
                        fields = new[] {
                            new { name = "synthetic_health", type = "i32", address = address + 16, min = 51, max = 100 },
                            new { name = "synthetic_magic_byte", type = "u8", address, min = 66, max = 66 },
                            new { name = "synthetic_final_byte", type = "u8", address = address + Fixture.Size - 1, min = 0, max = 0 } }
                    }));
                    string recordingPath = Path.Combine(nativeRoot, "recording");
                    var recorded = JsonSerializer.SerializeToElement(FieldRecording.Record(memory, profilePath, recordingPath,
                        10, TimeSpan.FromSeconds(1), CancellationToken.None));
                    Check(recorded.GetProperty("complete").GetBoolean(), "native named recording completes");
                    using var compressed = File.OpenRead(Path.Combine(recordingPath, "samples.jsonl.gz"));
                    using var gzip = new System.IO.Compression.GZipStream(compressed, System.IO.Compression.CompressionMode.Decompress);
                    using var reader = new StreamReader(gzip);
                    var distinct = new HashSet<int>();
                    string? line;
                    while ((line = reader.ReadLine()) is not null)
                    {
                        using var frame = JsonDocument.Parse(line);
                        if (frame.RootElement.GetProperty("kind").GetString() != "frame") continue;
                        nativeFieldFrames++;
                        var field = frame.RootElement.GetProperty("fields").GetProperty("synthetic_health");
                        if (field.GetProperty("status").GetString() == "observed") distinct.Add(field.GetProperty("value").GetInt32());
                        foreach (var expected in new[] { (name: "synthetic_magic_byte", value: 66), (name: "synthetic_final_byte", value: 0) })
                        {
                            var b = frame.RootElement.GetProperty("fields").GetProperty(expected.name);
                            if (b.GetProperty("status").GetString() != "observed") continue;
                            Check(b.GetProperty("type").GetString() == "u8" && b.GetProperty("value").GetByte() == expected.value,
                                "native u8 reads existing magic and final fixture bytes exactly");
                            nativeByteObservations++;
                        }
                    }
                    Check(nativeFieldFrames == recorded.GetProperty("stream_summary").GetProperty("frames").GetInt64(),
                        "native compressed frame count agrees with manifest");
                    Check(distinct.Count >= 2 && distinct.All(value => value is >= 51 and <= 100),
                        "native named recording replays changing child values within fixture bounds");
                    Check(nativeByteObservations >= 2, "native byte fields were actually observed");
                    string compactPath = Path.Combine(nativeRoot, "timeline.jsonl");
                    var exported = FieldExport.Export(recordingPath, compactPath);
                    Check(exported.source_complete && exported.frames == nativeFieldFrames, "native byte recording verifies and exports all frames");
                    int compactBytes = 0;
                    foreach (string row in File.ReadLines(compactPath))
                    {
                        using var frame = JsonDocument.Parse(row);
                        if (frame.RootElement.GetProperty("kind").GetString() != "frame") continue;
                        foreach (var expected in new[] { (name: "synthetic_magic_byte", value: 66), (name: "synthetic_final_byte", value: 0) })
                        {
                            var b = frame.RootElement.GetProperty("fields").GetProperty(expected.name);
                            if (b.GetProperty("status").GetString() != "observed") continue;
                            Check(b.GetProperty("type").GetString() == "u8" && b.GetProperty("value").GetByte() == expected.value,
                                "native compact byte values remain exact");
                            compactBytes++;
                        }
                    }
                    Check(compactBytes == nativeByteObservations, "native compact export preserves byte observation count");
                }
                finally { Directory.Delete(nativeRoot, true); }
                child.Kill(); child.WaitForExit(5000);
                Throws(memory.EnsureAlive, "process_exited"); assertions++;
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(5000); } }
        }
        TimerNativeTests.Result? nativeTimers = null;
        if (OperatingSystem.IsWindows()) { nativeTimers = TimerNativeTests.Run(); assertions += nativeTimers.Assertions; }
        AcquisitionNativeTests.Result? nativeAcquisition = null;
        if (OperatingSystem.IsWindows()) { nativeAcquisition = AcquisitionNativeTests.Run(); assertions += nativeAcquisition.Assertions; }
        PointerPathNativeTests.Result? nativePointers = null;
        if (OperatingSystem.IsWindows()) { nativePointers = PointerPathNativeTests.Run(); assertions += nativePointers.Assertions; }
        PointerPathNativeTests.Result? nativeBatches = null;
        if (OperatingSystem.IsWindows()) { nativeBatches = PointerPathNativeTests.Run(batched: true); assertions += nativeBatches.Assertions; }
        Program.Emit("self-test", new
        { assertions, acquisition_enumeration_fixture = AcquisitionEnumerationTests.Metrics, storage_cohort_fixture = StorageCohortTests.Metrics, native_read_setup_benchmark = NativeReadSetupTests.Benchmark, native_timer_frames = nativeTimers?.Frames ?? 0, native_timer_recording_verified = nativeTimers?.Verified ?? false, native_acquisition_profiles = nativeAcquisition?.Profiles ?? 0, native_acquisition_relocations = nativeAcquisition?.Relocations ?? 0, native_observation_segments = nativeAcquisition?.ObservationSegments ?? 0, native_observation_unknowns = nativeAcquisition?.ObservationUnknowns ?? 0, native_observation_live_frames = nativeAcquisition?.LiveFrames ?? 0, native_prepared_segments = nativeAcquisition?.PreparedSegments ?? 0, native_no_change_refreshes = nativeAcquisition?.NoChangeRefreshes ?? 0, native_child_samples = samples, native_named_field_frames = nativeFieldFrames,
            native_u8_field_observations = nativeByteObservations + (nativePointers?.ByteObservations ?? 0),
            native_pointer_frames = nativePointers?.Frames ?? 0, native_pointer_unknown_frames = nativePointers?.UnknownFrames ?? 0,
            native_pointer_relocations = nativePointers?.Relocations ?? 0, native_pointer_recording_frames = nativePointers?.RecordingFrames ?? 0,
            native_pointer_recording_verified = nativePointers?.RecordingVerified ?? false,
            native_batch_frames = nativeBatches?.Frames ?? 0, native_batch_unknown_frames = nativeBatches?.UnknownFrames ?? 0,
            native_batch_recording_frames = nativeBatches?.RecordingFrames ?? 0, native_batch_recording_verified = nativeBatches?.RecordingVerified ?? false,
            native_windows_test = OperatingSystem.IsWindows() ? "passed" : "not_run_on_this_platform",
            game_validation = false, label = "SYNTHETIC FIXTURE" });
    }
}
