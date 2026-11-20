using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using OverwatchDecoder.SessionRecorder;

static class ObservationStorageTests
{
    public static int Run(string root)
    {
        int checks = 0, cases = 0;
        void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
        Fixture New() => new(Path.Combine(root, $"storage-{cases++}"));
        void Reject(Action action)
        {
            try { action(); } catch (Exception e) when (e is InvalidDataException or JsonException or IOException or KeyNotFoundException) { checks++; return; }
            throw new Exception("Invalid storage accepted.");
        }
        // Arrival order is independent of complete JSONL records. Provisional
        // receipts identify original bytes before a later seal can accept them.
        var f = New();
        using (var tail = new ObservationStorageTail(f.Root, 1048576))
        {
            Check(tail.Read().Count == 0 && !tail.MadeProgress, "Absent stream does not fabricate rows");
            f.Open();
            byte[] first = Fixture.Data(0); File.WriteAllBytes(f.DataPath, first[..^1]);
            Check(tail.Read().Count == 0 && tail.MadeProgress, "Open metadata and partial line stay provisional");
            File.AppendAllText(f.DataPath, "\n", new UTF8Encoding(false)); f.RecordReceipt(first);
            var receipt = JsonSerializer.SerializeToElement(tail.Read().Single());
            Check(receipt.GetProperty("source_sha256").GetString() == Fixture.Hash(first)
                && receipt.GetProperty("source_offset").GetInt64() == 0
                && !receipt.GetProperty("sealed_acceptance").GetBoolean()
                && !receipt.GetProperty("durability_verified").GetBoolean(), "Exact original-byte provisional receipt");
            Check(!receipt.TryGetProperty("fixture_private_value", out _), "Receipt does not duplicate private source values");
            f.Seal(); f.Open(); f.Add(); f.Add(); f.Seal(); f.Open(); f.Add(); f.Seal();
            var rest = Drain(tail, 1);
            Check(rest.Count == 3 && tail.Rows == 4 && tail.SealedCohorts == 3, "Three storage cohorts retain one global sequence");
            Check(JsonSerializer.SerializeToElement(rest[0]).GetProperty("source_offset").GetInt64() == 0
                && JsonSerializer.SerializeToElement(rest[1]).GetProperty("source_offset").GetInt64() > 0,
                "Offsets reset only at new storage files");
            tail.Complete(); tail.VerifyResult(f.Result(), 0, ObservationScope.ControlledPractice); checks++;
            Check(tail.OutputSha256 == Fixture.Hash(f.AllData.ToArray()), "Concatenated original data digest survives rotations");
            Reject(() => tail.Read()); Reject(() => tail.Complete());
            var bad = JsonNode.Parse(f.Result().GetRawText())!; bad["capture_scope"] = "read_only_user_gameplay";
            Reject(() => tail.VerifyResult(JsonSerializer.SerializeToElement(bad), 0, ObservationScope.ControlledPractice));
        }
        // Exact content hashes are necessary but do not alone establish that a
        // delivery receipt belongs to its corresponding original source line.
        f = New(); f.Open(); f.Add("overwatch-decoder.private.incoming-source-observation/1"); f.Seal();
        using (var tail = new ObservationStorageTail(f.Root, 1048576))
        {
            var receipt = JsonSerializer.SerializeToElement(Drain(tail).Single()); tail.Complete();
            tail.VerifyResult(f.Result(), 0, ObservationScope.ControlledPractice);
            Check(receipt.GetProperty("source_schema").GetString() == "overwatch-decoder.private.incoming-source-observation/1"
                && !receipt.TryGetProperty("fixture_private_value", out _), "Incoming cohort transport carries receipts only");
        }
        foreach (string mode in new[] { "source", "receipt_link", "duplicate_key", "chain", "ordinal", "path", "extra_key", "range", "sequence", "missing_file", "line_tail", "index_tail", "file_order", "row_count", "boolean" })
        {
            f = New(); f.Open(); f.Add(); f.Seal();
            var records = File.ReadAllLines(f.IndexPath).Select(s => JsonNode.Parse(s)!).ToArray();
            switch (mode)
            {
                case "source": File.WriteAllText(f.DataPath, File.ReadAllText(f.DataPath).Replace("private", "PRIVate")); break;
                case "receipt_link":
                    var receipt = JsonNode.Parse(File.ReadAllText(f.ReceiptPath))!; receipt["line_sha256"] = new string('a', 64);
                    File.WriteAllBytes(f.ReceiptPath, Fixture.Line(receipt));
                    records[1]["files"]![1]!["sha256"] = Fixture.Hash(File.ReadAllBytes(f.ReceiptPath)); break;
                case "duplicate_key":
                    File.WriteAllText(f.IndexPath, File.ReadAllText(f.IndexPath).Replace("\"ordinal\":1", "\"ordinal\":1,\"ordinal\":1")); break;
                case "chain": records[1]["previous_seal_sha256"] = new string('a', 64); break;
                case "ordinal": records[0]["ordinal"] = 2; break;
                case "path": records[0]["directory"] = "../escape"; break;
                case "extra_key": records[0]["unrecognized"] = true; break;
                case "range": records[1]["last_combined_sequence"] = 1; break;
                case "sequence": File.WriteAllText(f.DataPath, File.ReadAllText(f.DataPath).Replace("\"combined_sequence\":0", "\"combined_sequence\":9")); break;
                case "missing_file": File.Delete(f.ReceiptPath); break;
                case "line_tail": File.WriteAllBytes(f.DataPath, File.ReadAllBytes(f.DataPath)[..^1]); break;
                case "index_tail": File.WriteAllBytes(f.IndexPath, File.ReadAllBytes(f.IndexPath)[..^1]); break;
                case "file_order":
                    var files = records[1]["files"]!.AsArray(); var a = files[0]!.DeepClone(); var b = files[1]!.DeepClone(); files[0] = b; files[1] = a; break;
                case "row_count": records[1]["files"]![1]!["rows"] = 2; break;
                case "boolean": records[0]["ordinal"] = true; break;
            }
            if (mode is not ("duplicate_key" or "index_tail")) File.WriteAllBytes(f.IndexPath, records.SelectMany(Fixture.Line).ToArray());
            using var tail = new ObservationStorageTail(f.Root, 1048576);
            Reject(() => { Drain(tail); tail.Complete(); }); Reject(() => tail.Read());
        }
        // A same-length historical edit remains a failure even after its seal
        // was consumed. No historical list or data body is retained in memory.
        foreach (bool editIndex in new[] { false, true })
        {
            f = New(); f.Open(); f.Add(); f.Seal(); using var tail = new ObservationStorageTail(f.Root, 1048576); Drain(tail);
            string path = editIndex ? f.IndexPath : f.DataPath;
            byte[] raw = File.ReadAllBytes(path); raw[5] ^= 1; File.WriteAllBytes(path, raw);
            Reject(tail.Complete); Reject(() => tail.Read());
        }
        f = New(); f.Open(); f.Add();
        using (var tail = new ObservationStorageTail(f.Root, 1048576))
        { Drain(tail); Reject(tail.Complete); Reject(() => tail.Read()); }
        f = New(); f.Open(); f.Seal();
        using (var tail = new ObservationStorageTail(f.Root, 1048576))
        { Drain(tail); tail.Complete(); Check(tail.Rows == 0 && tail.SealedCohorts == 1, "Empty failed-start cohort preserves null sequence bounds");
            Reject(() => tail.VerifyResult(f.Result(), 0, ObservationScope.ControlledPractice)); }
        f = New(); f.Open(); f.Seal(); f.Open(); f.Add(); f.Seal();
        using (var tail = new ObservationStorageTail(f.Root, 1048576)) Reject(() => Drain(tail));
        f = New(); f.Open(); f.Add(); f.Seal(); f.Open(); f.Seal();
        using (var tail = new ObservationStorageTail(f.Root, 1048576)) Reject(() => Drain(tail));
        f = New(); f.Open(); f.Add(); f.Seal();
        using (var tail = new ObservationStorageTail(f.Root, 128)) Reject(() => Drain(tail));
        using (var tail = new ObservationStorageTail(f.Root, 1048576, maximumCohortBytes: 128)) Reject(() => Drain(tail));
        using (var tail = new ObservationStorageTail(f.Root, 1048576, maximumIndexBytes: 64)) Reject(() => Drain(tail));
        f.Open(); f.Add(); f.Seal();
        using (var tail = new ObservationStorageTail(f.Root, 1048576, maximumCohorts: 1)) Reject(() => Drain(tail));
        f = New(); f.Open(); f.Add(); f.Seal();
        string other = Path.Combine(f.Root, "linked-source"); File.Move(f.DataPath, other); File.CreateSymbolicLink(f.DataPath, other);
        using (var tail = new ObservationStorageTail(f.Root, 1048576)) Reject(() => Drain(tail));
        f = New(); f.Open(); f.Add();
        using (var tail = new ObservationStorageTail(f.Root, 1048576))
        { Drain(tail); File.WriteAllBytes(f.DataPath, []); Reject(() => tail.Read()); }
        // Independent Python producer fixture is optional for the portable test
        // suite and required by the cross-language acceptance command.
        if (Environment.GetEnvironmentVariable("OVERWATCH_DECODER_STORAGE_FIXTURE") is { Length: > 0 } external)
        {
            using var tail = new ObservationStorageTail(external, 1048576);
            Drain(tail); tail.Complete();
            using var result = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(external, "result.json")));
            tail.VerifyResult(result.RootElement, 0, ObservationScope.ControlledPractice);
            Check(tail.SealedCohorts >= 3 && tail.Rows >= 3, "Independent Python writer passes exact C# result and seal verification");
        }
        return checks;
    }

    private static List<object> Drain(ObservationStorageTail tail, int count = 1024)
    {
        var result = new List<object>();
        do { result.AddRange(tail.Read(count)); } while (tail.MadeProgress);
        return result;
    }
    internal sealed class Fixture
    {
        internal readonly string Root;
        internal string IndexPath => Path.Combine(Root, "storage-index.jsonl");
        internal string DataPath => Path.Combine(Root, $"cohort-{ordinal:D6}", "game-state.jsonl");
        internal string ReceiptPath => Path.Combine(Root, $"cohort-{ordinal:D6}", "delivery-receipts.jsonl");
        internal readonly List<byte> AllData = [];
        private int ordinal; private long rows, cohortRows, receiptBytes; private string? previous;
        internal Fixture(string root) { Root = root; Directory.CreateDirectory(root); }
        internal void Open()
        {
            ordinal++; cohortRows = 0; Directory.CreateDirectory(Path.GetDirectoryName(DataPath)!);
            File.WriteAllBytes(DataPath, []); File.WriteAllBytes(ReceiptPath, []); AppendIndex(Identity("open"));
        }
        internal void Add(string schema = "overwatch-decoder.private.selected-compact/1") { byte[] raw = Data(rows, schema); Append(DataPath, raw); RecordReceipt(raw); }
        internal void RecordReceipt(byte[] data)
        {
            byte[] receipt = Line(new { combined_sequence = rows, line_sha256 = Hash(data) });
            Append(ReceiptPath, receipt); receiptBytes += receipt.Length; AllData.AddRange(data); rows++; cohortRows++;
        }
        internal void Seal()
        {
            var value = Identity("seal");
            value["files"] = new[] { "game-state.jsonl", "delivery-receipts.jsonl" }.Select(name => {
                byte[] raw = File.ReadAllBytes(Path.Combine(Root, $"cohort-{ordinal:D6}", name));
                return new { path = name, bytes = raw.Length, rows = cohortRows, sha256 = Hash(raw) };
            }).ToArray();
            value["first_combined_sequence"] = cohortRows == 0 ? null : rows - cohortRows;
            value["last_combined_sequence"] = cohortRows == 0 ? null : rows - 1;
            byte[] line = Line(value); Append(IndexPath, line); previous = Hash(line);
        }
        private Dictionary<string, object?> Identity(string kind) => new() {
            ["schema"] = "overwatch-decoder.private.combined-storage/1", ["kind"] = kind, ["ordinal"] = ordinal,
            ["directory"] = $"cohort-{ordinal:D6}", ["previous_seal_sha256"] = previous };
        private void AppendIndex(object value) => Append(IndexPath, Line(value));
        private static void Append(string path, byte[] raw) { using var stream = new FileStream(path, FileMode.Append); stream.Write(raw); }
        internal static byte[] Data(long seq, string schema = "overwatch-decoder.private.selected-compact/1") => Line(new { schema, combined_sequence = seq, fixture_private_value = "synthetic-private" });
        internal static byte[] Line(object value) => JsonSerializer.SerializeToUtf8Bytes(value).Concat(new byte[] { 10 }).ToArray();
        internal static string Hash(byte[] value) => Convert.ToHexStringLower(SHA256.HashData(value));
        internal JsonElement Result() => JsonSerializer.SerializeToElement(new {
            schema = "overwatch-decoder.private.combined-run/2", cli_exit_code = 0, status = "complete", error = (string?)null,
            cleanup_errors = Array.Empty<string>(), capture_scope = "controlled_practice", output_rows = rows,
            output_bytes = AllData.Count, output_sha256 = Hash(AllData.ToArray()), delivery_receipt_bytes = receiptBytes,
            storage_index_bytes = new FileInfo(IndexPath).Length, storage_index_records = 2 * ordinal,
            storage_cohorts = ordinal, storage_index_sha256 = Hash(File.ReadAllBytes(IndexPath)) });
    }
}
