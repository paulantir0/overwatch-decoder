using System.Diagnostics;
using System.Text.Json;
using OverwatchDecoder.SessionRecorder;

static class ObservationTests
{
    public static async Task<int> Run(string root)
    {
        int checks = 0; void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
        string package = Path.Combine(root, "observation-package"), bundle = Path.Combine(package, "bundle"); Directory.CreateDirectory(bundle);
        string python = Path.Combine(package, "python.exe"), entry = Path.Combine(bundle, "run.py");
        File.WriteAllText(python, "synthetic runtime"); File.WriteAllText(entry, "synthetic entry");
        File.WriteAllBytes(Path.Combine(bundle, "inventory.json"), JsonSerializer.SerializeToUtf8Bytes(new { files = new[] { new { path = "run.py", size = new FileInfo(entry).Length, sha256 = RosterCapture.Hash(entry) } } }));
        var plan = new ObservationPlan { PythonExecutable = "python.exe", PythonSha256 = RosterCapture.Hash(python), BundleDirectory = "bundle", InventorySha256 = RosterCapture.Hash(Path.Combine(bundle, "inventory.json")), Entrypoint = "run.py", MaximumWindows = 1, MaximumOutputMiB = 128 };
        ObservationCapture.Validate(package, plan); checks++;
        Check(plan.CaptureScope == ObservationScope.ControlledPractice, "practice scope remains the default");
        var mode = JsonSerializer.Deserialize<ObservationPlan>("{\"CaptureScope\":\"read_only_user_gameplay\"}")!;
        Check(mode.CaptureScope == ObservationScope.ReadOnlyUserGameplay, "explicit user gameplay scope parses without changing defaults");
        Check(new CaptureSettings().Observations is null, "observations opt-in by default");
        var command = ObservationCapture.Command(123, plan, package, Path.Combine(root, "output with spaces"));
        Check(!command.UseShellExecute && command.ArgumentList.Contains("--pid") && command.ArgumentList.Contains("123") && command.ArgumentList.Contains("--practice-range"), "finite owned command retains process and scope");
        plan.CaptureScope = ObservationScope.ReadOnlyUserGameplay;
        var userCommand = ObservationCapture.Command(123, plan, package, "fixture-output");
        Check(userCommand.ArgumentList.Contains("--read-only-user-gameplay") && !userCommand.ArgumentList.Contains("--practice-range"), "user gameplay passes exactly its explicit read-only scope flag");
        plan.CaptureScope = (ObservationScope)99;
        try { ObservationCapture.Validate(package, plan); throw new Exception("invalid scope accepted"); } catch (InvalidDataException) { checks++; }
        plan.CaptureScope = ObservationScope.ControlledPractice;
        try { ObservationCapture.Contained(package, "../escape"); throw new Exception("escape accepted"); } catch (InvalidDataException) { checks++; }
        File.AppendAllText(entry, "mutation");
        try { ObservationCapture.Validate(package, plan); throw new Exception("mutation accepted"); } catch (InvalidDataException) { checks++; }
        File.WriteAllText(entry, "synthetic entry");
        string stream = Path.Combine(root, "tail.jsonl"); File.WriteAllText(stream, "{\"schema\":\"overwatch-decoder.private.selected-compact/1\"}");
        var tail = new ObservationReceiptTail(stream); Check(!tail.Read().Any(), "partial JSON is not emitted");
        File.AppendAllText(stream, "\n"); var receipt = JsonSerializer.SerializeToElement(tail.Read().Single());
        Check(tail.Rows == 1 && receipt.GetProperty("source_offset").GetInt64() == 0 && receipt.GetProperty("source_sha256").GetString() == RosterCapture.Hash(stream), "exact byte receipt at newline");
        tail.Complete(); checks++;
        Check(!tail.Read().Any(), "same bytes are never repeated");
        File.WriteAllText(stream, "x");
        try { _ = tail.Read().ToArray(); throw new Exception("truncation accepted"); } catch (InvalidDataException) { checks++; }
        string incoming = Path.Combine(root, "incoming-tail.jsonl");
        File.WriteAllText(incoming, "{\"schema\":\"overwatch-decoder.private.incoming-source-observation/1\",\"kind\":\"incoming_source_observation\",\"synthetic_private\":123}\n");
        var incomingTail = new ObservationReceiptTail(incoming);
        var incomingReceipt = JsonSerializer.SerializeToElement(incomingTail.Read().Single()); incomingTail.Complete();
        Check(incomingReceipt.GetProperty("source_schema").GetString() == "overwatch-decoder.private.incoming-source-observation/1"
            && incomingReceipt.GetProperty("source_sha256").GetString() == RosterCapture.Hash(incoming)
            && !incomingReceipt.TryGetProperty("synthetic_private", out _), "Incoming transport retains only exact-byte receipts, no semantic claim");
        int disposed = 0;
        string? completedOutput = null;
        var events = new List<JsonElement>();
        var capture = new ObservationCapture(123, plan, package, Path.Combine(root, "observation-success"), () => true, e => events.Add(JsonSerializer.SerializeToElement(e)), (cmd, _) =>
        {
            var args = cmd.ArgumentList.ToArray(); string output = args[Array.IndexOf(args, "--output") + 1]; completedOutput = output; Directory.CreateDirectory(output);
            string data = Path.Combine(output, "game-state.jsonl"); File.WriteAllText(data, "{\"schema\":\"overwatch-decoder.private.selected-compact/1\",\"private_raw\":123}\n");
            File.WriteAllBytes(Path.Combine(output, "result.json"), JsonSerializer.SerializeToUtf8Bytes(new { schema = "overwatch-decoder.private.combined-run/1", cli_exit_code = 0, status = "complete", error = (string?)null, cleanup_errors = Array.Empty<string>(), output_rows = 1, output_bytes = new FileInfo(data).Length, output_sha256 = RosterCapture.Hash(data) }));
            return new Child(() => disposed++, true);
        });
        capture.Start(CancellationToken.None); await capture.Completion!;
        Check(capture.Error is null && !capture.HasGaps && disposed == 1, "successful window closes owned child and verifies digest");
        Check(events.Any(e => e.GetProperty("kind").GetString() == "observation_receipt") && !JsonSerializer.Serialize(events).Contains("private_raw"), "journal carries receipts without private raw values");
        try { ObservationCapture.VerifyResult(completedOutput!, 1, 0, ObservationScope.ReadOnlyUserGameplay); throw new Exception("missing user scope accepted"); }
        catch (InvalidDataException) { checks++; }
        string resultPath = Path.Combine(completedOutput!, "result.json");
        var resultNode = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(resultPath))!;
        resultNode["capture_scope"] = "read_only_user_gameplay"; File.WriteAllText(resultPath, resultNode.ToJsonString());
        ObservationCapture.VerifyResult(completedOutput!, 1, 0, ObservationScope.ReadOnlyUserGameplay); checks++;
        try { ObservationCapture.VerifyResult(completedOutput!, 1, 0); throw new Exception("mismatched practice scope accepted"); }
        catch (InvalidDataException) { checks++; }
        var cancellation = new CancellationTokenSource();
        var canceled = new ObservationCapture(123, plan, package, Path.Combine(root, "observation-cancel"), () => true, _ => { }, (_, _) => { cancellation.Cancel(); return new Child(() => disposed++, false); });
        canceled.Start(cancellation.Token); await canceled.Completion!;
        Check(canceled.HasGaps && canceled.Error is null && disposed == 2, "cancellation closes only owned job and reports incomplete tail");
        string raced = Path.Combine(root, "manifest-race"); Directory.CreateDirectory(raced);
        string manifest = Path.Combine(raced, "manifest.json"), rotated = Path.Combine(raced, "manifest.old"); File.WriteAllText(manifest, "fixture");
        int moves = 0;
        long measured = ObservationCapture.MeasureDirectory(raced, 128, path => {
            if (path == manifest && moves++ == 0) File.Move(manifest, rotated);
        });
        Check(measured == 7 && File.Exists(rotated), "whole traversal retries actual manifest rename between enumeration and metadata");
        int attempts = 0;
        try { ObservationCapture.MeasureDirectory(raced, 128, _ => { attempts++; throw new FileNotFoundException("repeated fixture replacement"); }); throw new Exception("unbounded retry accepted"); }
        catch (FileNotFoundException) { Check(attempts == 3, "metadata race retries at most three complete traversals"); }
        try { ObservationCapture.MeasureDirectory(raced, 1); throw new Exception("quota accepted"); }
        catch (IOException error) { Check(error.Message.Contains("byte bound"), "quota violations are never treated as rename races"); }
        attempts = 0;
        try { ObservationCapture.MeasureDirectory(raced, 128, _ => { attempts++; throw new UnauthorizedAccessException("fixture denied"); }); throw new Exception("permission ignored"); }
        catch (UnauthorizedAccessException) { Check(attempts == 1, "permission failures are never retried or hidden"); }
        return checks;
    }
    private sealed class Child(Action dispose, bool exited) : IRosterChild
    { public bool HasExited => exited; public int ExitCode => 0; public void Dispose() => dispose(); }
}
