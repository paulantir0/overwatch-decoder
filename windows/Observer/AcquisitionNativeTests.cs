using System.Buffers.Binary;
using System.Diagnostics;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

internal static class AcquisitionNativeTests
{
    internal sealed record Result(int Assertions, int Profiles, int Relocations, int ObservationSegments, long ObservationUnknowns, int LiveFrames, int PreparedSegments, int NoChangeRefreshes);
    internal static Result Run()
    {
        int assertions = 0, profiles = 0;
        void Check(bool ok, string name) { if (!ok) throw new ObservationException("self_test_failed", "native-acquisition:" + name); assertions++; }
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException();
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) info.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
        info.ArgumentList.Add("fixture-pointers"); info.ArgumentList.Add("--seconds"); info.ArgumentList.Add("60");
        using var child = Process.Start(info) ?? throw new InvalidOperationException();
        string output = Path.Combine(Path.GetTempPath(), "overwatch-decoder-native-acquisition-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(output);
        try
        {
            string? ready = child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
            using var descriptor = JsonDocument.Parse(ready ?? "{}"); var d = descriptor.RootElement.GetProperty("result");
            Check(d.GetProperty("schema").GetString() == "overwatch-decoder.pointer-fixture/1" && d.GetProperty("pid").GetInt32() == child.Id, "owned child descriptor");
            ulong root = d.GetProperty("root_address").GetUInt64(); using var memory = new NativeMemory(child.Id); Acquisition.Module module = Acquisition.MainModule(memory);
            // The synthetic child supplies its allocation root; no automatic module-root discovery is claimed by this fixture.
            byte[] recipe = JsonSerializer.SerializeToUtf8Bytes(AcquisitionTests.Recipe(memory.Identity, root));
            ulong First = Acquire("a", 7); ulong oldLeaf = First - 8;
            Command("b"); Wait(() => BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(root + 8, 8)) != oldLeaf);
            ulong second = Acquire("b", 42); Check(second != First, "fresh profile follows native allocation relocation");
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel(); try { Acquisition.RunBytes(memory, module, recipe, Path.Combine(output, "cancelled"), cancelled.Token); Check(false, "cancel accepted"); }
                catch (ObservationException e) { Check(e.Code == "cancelled", "native pre-cancel"); }
                Check(!File.Exists(Path.Combine(output, "cancelled", "profile.json")), "cancel has no profile");
            }
            // Reuse this owned child for a sample-controlled observation lifecycle; no wall-clock sample assumptions.
            Command("a"); Wait(() => BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(root + 8, 8)) == oldLeaf);
            string recipePath = Path.Combine(output, "observe-recipe.json"); File.WriteAllBytes(recipePath, recipe);
            string observationPath = Path.Combine(output, "observation"); ObserveFields.Result observation; using var live = new StringWriter();
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
            {
                observation = ObserveFields.RunBounded(memory, module, recipePath, observationPath, 10, TimeSpan.FromSeconds(30),
                    stop.Token, new(), (segment, frame) =>
                    {
                        if (segment == 1 && frame.Sequence == 0)
                        { Command("b"); Wait(() => BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(root + 8, 8)) != oldLeaf); }
                        if (segment == 2 && frame.Sequence == 1) stop.Cancel();
                    }, liveOutput: live);
            }
            Check(!observation.complete && observation.stop_reason == "cancelled" && observation.segments.Length == 2 && observation.acquisitions.Length == 2,
                "native finite observation reacquires and cancels");
            Check(observation.segments[0].trigger == "guard_invalidation" && observation.segments[0].trigger_sequence == 1 &&
                observation.fields.Single().observed == 3 && observation.fields.Single().unknown == 1,
                "native invalid guard frame retained before new profile");
            Check(observation.segments[0].profile_sha256 != observation.segments[1].profile_sha256 &&
                FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(observationPath, "acquisition-0002", "profile.json"))).Fields[0].Address == second,
                "native observation follows allocation relocation");
            foreach (var segment in observation.segments)
            { var verified = FieldRecordingVerification.Verify(Path.Combine(observationPath, segment.directory)); Check(verified.valid && !verified.complete, "native observation segment strictly verified"); }
            foreach (var attempt in observation.acquisitions)
            {
                using var start = JsonDocument.Parse(File.ReadLines(Path.Combine(observationPath, attempt.directory, "evidence.jsonl")).First());
                Check(start.RootElement.GetProperty("source_kind").GetString() == "native_process_memory", "native provenance survives session budget adapter");
            }
            Check(observation.intervals_without_recorded_frames.Length == 3 && observation.source_kind == "native_process_memory_through_budget_source",
                "native session gaps and source provenance explicit");
            var liveRows = live.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(row =>
            { using var document = JsonDocument.Parse(row); return document.RootElement.Clone(); }).ToArray();
            var liveFrames = liveRows.Where(row => row.GetProperty("kind").GetString() == "frame").ToArray();
            Check(liveFrames.Length == 4 && liveFrames.Count(row => row.GetProperty("fields").GetProperty("candidate").GetProperty("status").GetString() == "unknown") == 1,
                "native live output retains every accepted frame and unknown");
            Check(liveFrames[0].GetProperty("fields").GetProperty("candidate").GetProperty("value").GetInt32() == 7 &&
                liveFrames[^1].GetProperty("fields").GetProperty("candidate").GetProperty("value").GetInt32() == 42 && liveRows[^1].GetProperty("kind").GetString() == "session_end",
                "native compact stream follows relocated value and explicit end");
            // Actual Windows handle and identical-profile no-adoption refresh
            // against this owned child. No target interventions.
            string preparedPath = Path.Combine(output, "prepared-observation"); ObserveFields.Result prepared;
            using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                bool compared = false;
                prepared = ObserveFields.RunBounded(memory, module, recipePath, preparedPath, 10, TimeSpan.FromSeconds(10),
                    stop.Token, new(ReacquireMilliseconds: 1000), (segment, frame) =>
                    { if (compared) stop.Cancel(); }, backgroundPreparation: true,
                    fixturePreparationStage: (_, stage) => { if (stage == "comparison") compared = true; });
            }
            Check(prepared.stop_reason == "cancelled" && prepared.segments.Length == 1 && prepared.acquisitions.Length == 2 &&
                prepared.unchanged_preparations?.Length == 1, "native identical-profile refresh retains one epoch");
            Check(prepared.unchanged_preparations![0].active_acquisition == 1 && !prepared.unchanged_preparations[0].profile_adopted &&
                !File.Exists(Path.Combine(preparedPath, "acquisition-0002", "activation.json")), "native no-adoption refresh creates no activation proof");
            foreach (var segment in prepared.segments)
                Check(FieldRecordingVerification.Verify(Path.Combine(preparedPath, segment.directory)).valid,
                    "native prepared segment strictly verifies");
            Command("bad"); Wait(() => BinaryPrimitives.ReadUInt64LittleEndian(memory.Read(second - 8, 8)) == 0);
            try { Acquisition.RunBytes(memory, module, recipe, Path.Combine(output, "bad"), default); Check(false, "bad identity accepted"); }
            catch (ObservationException e) { Check(e.Code == "acquisition_predicate_failed", "native leaf identity failure"); }
            Check(!File.Exists(Path.Combine(output, "bad", "profile.json")), "native rejection has no profile");
            Command("stop"); Check(child.WaitForExit(5000), "owned child exits normally");
            try { Acquisition.RunBytes(memory, module, recipe, Path.Combine(output, "exited"), default); Check(false, "exited process accepted"); }
            catch (ObservationException e) { Check(e.Code == "process_exited", "native process exit"); }
            return new(assertions, profiles, 1, observation.segments.Length, observation.fields.Single().unknown, liveFrames.Length, prepared.segments.Length, prepared.unchanged_preparations!.Length);
            ulong Acquire(string label, int expected)
            {
                string directory = Path.Combine(output, label); Acquisition.Result result = Acquisition.RunBytes(memory, module, recipe, directory, default); profiles++;
                Check(result.complete && result.fields == 1 && result.guard_declarations == 3, "native acquired full guard coverage");
                var profile = FieldStream.ParseProfileBytes(File.ReadAllBytes(Path.Combine(directory, "profile.json")));
                Check(BinaryPrimitives.ReadInt32LittleEndian(memory.Read(profile.Fields[0].Address, 4)) == expected, "native acquired scalar matches owned fixture");
                Check(profile.Target.Pid == child.Id && profile.Target.CreationFileTime == memory.Identity.CreationFileTime && result.evidence_sha256?.Length == 64, "native identity and artifact provenance");
                int readRecords = 0; foreach (string line in File.ReadLines(Path.Combine(directory, "evidence.jsonl")))
                { using var record = JsonDocument.Parse(line); var r = record.RootElement; if (r.GetProperty("kind").GetString() != "read") continue; readRecords++; Check(r.GetProperty("attempted").GetBoolean() && r.GetProperty("error").ValueKind == JsonValueKind.Null && r.GetProperty("returned_bytes").GetInt32() == r.GetProperty("requested_bytes").GetInt32(), "native complete read trace"); }
                Check(readRecords == result.read_calls, "native read accounting"); return profile.Fields[0].Address;
            }
            void Command(string text) { child.StandardInput.WriteLine(text); child.StandardInput.Flush(); }
            void Wait(Func<bool> predicate)
            { var clock = Stopwatch.StartNew(); while (!predicate()) { if (clock.Elapsed > TimeSpan.FromSeconds(5)) throw new ObservationException("self_test_failed", "native-acquisition:fixture transition timeout"); Thread.Sleep(10); } }
        }
        finally
        {
            if (!child.HasExited) { try { child.StandardInput.WriteLine("stop"); child.StandardInput.Flush(); } catch (IOException) { } if (!child.WaitForExit(2000)) { child.Kill(entireProcessTree: true); child.WaitForExit(5000); } }
            Directory.Delete(output, true);
        }
    }
}
