using System.Text.Json;

namespace OverwatchDecoder.Observer;

public static partial class FieldRecordingVerification
{
    private static void BatchControl(State state, bool attempted, string? error, bool maySkip)
    {
        if (!state.BatchFrame) return;
        if (attempted) Need(state.PhysicalStop is null, "batch_read_after_terminal");
        else if (!maySkip) Need(error is not null && FieldStream.Fatal(error), "batch_unattempted_reason");
        if (error is not null && FieldStream.Fatal(error)) state.PhysicalStop ??= error;
    }
    private static void BatchPass(JsonElement physical, JsonElement logical, FieldStream.Profile model,
        Action<long, long> times, State state)
    {
        var plan = model.Batching!;
        Need(physical.ValueKind == JsonValueKind.Array && physical.GetArrayLength() == plan.Batches.Length, "batch_count_mismatch");
        foreach (var batch in plan.Batches)
        {
            var b = physical[batch.Id];
            Keys(b, "batch_id", "attempted", "address_hex", "requested_bytes", "guard_count", "returned_bytes", "start_ticks", "end_ticks", "error");
            Need(Number(b, "batch_id") == batch.Id && Number(b, "requested_bytes") == batch.Width && Number(b, "guard_count") == batch.Guards.Length,
                "batch_plan_mismatch");
            bool attempted = Flag(b, "attempted"); string? error = b.GetProperty("error").ValueKind == JsonValueKind.Null ? null : Text(b, "error");
            BatchControl(state, attempted, error, false);
            if (!attempted)
                Need(new[] { "address_hex", "returned_bytes", "start_ticks", "end_ticks" }.All(k => b.GetProperty(k).ValueKind == JsonValueKind.Null) &&
                    error is { Length: > 0 and <= 256 }, "batch_unattempted_evidence");
            else
            {
                Need(PointerHex(b, "address_hex") == batch.Address, "batch_address_mismatch");
                times(Number(b, "start_ticks"), Number(b, "end_ticks"));
                state.MinimumReads++; state.MinimumReadBytes += batch.Width; state.GuardGapBytes += batch.GapBytes;
                if (error is null) Need(Number(b, "returned_bytes") == batch.Width, "batch_incomplete_buffer");
                else
                {
                    Need(error.Length is > 0 and <= 256, "batch_read_error");
                    if (b.GetProperty("returned_bytes").ValueKind != JsonValueKind.Null)
                        Need(error == "partial_read" && Number(b, "returned_bytes") is >= 0 and <= int.MaxValue && Number(b, "returned_bytes") != batch.Width,
                            "batch_partial_count");
                }
            }
            var overlap = new Dictionary<int, byte>();
            foreach (int id in batch.Guards)
            {
                var g = logical[id]; var expected = model.Guards[id]; int offset = checked((int)(expected.Address - batch.Address));
                Keys(g, "guard_id", "batch_id", "slice_offset", "byte_count", "bytes_hex", "ok", "error");
                Need(Number(g, "guard_id") == id && Number(g, "batch_id") == batch.Id && Number(g, "slice_offset") == offset &&
                    Number(g, "byte_count") == expected.Expected.Length, "batch_slice_mismatch");
                if (!attempted || error is not null)
                {
                    Need(!Flag(g, "ok") && g.GetProperty("bytes_hex").ValueKind == JsonValueKind.Null && Text(g, "error") == error,
                        "batch_failed_slice_retained"); continue;
                }
                string hex = Text(g, "bytes_hex");
                Need(hex.Length == expected.Expected.Length * 2 && hex.All(Uri.IsHexDigit), "batch_slice_bytes");
                byte[] bytes = Convert.FromHexString(hex); bool ok = bytes.AsSpan().SequenceEqual(expected.Expected);
                Need(Flag(g, "ok") == ok && (ok ? g.GetProperty("error").ValueKind == JsonValueKind.Null : Text(g, "error") == "guard_mismatch"),
                    "batch_slice_status");
                for (int n = 0; n < bytes.Length; n++)
                {
                    Need(!overlap.TryGetValue(offset + n, out byte previous) || previous == bytes[n], "batch_overlapping_slice_bytes");
                    overlap[offset + n] = bytes[n];
                }
            }
        }
    }

    private static void BatchSummary(JsonElement summary, GuardBatches.Plan plan, State state)
    {
        Need(state.LastTerminalReason is null || Text(summary, "stop_reason") == state.LastTerminalReason, "batch_terminal_summary_reason");
        var policy = summary.GetProperty("absolute_guard_reads"); Keys(policy, "algorithm", "maximum_span_bytes", "maximum_gap_bytes");
        Need(Text(policy, "algorithm") == plan.Policy.algorithm && Number(policy, "maximum_span_bytes") == plan.Policy.maximum_span_bytes &&
            Number(policy, "maximum_gap_bytes") == plan.Policy.maximum_gap_bytes &&
            Number(summary, "planned_read_calls_per_frame") == plan.ReadCalls &&
            Number(summary, "unbatched_planned_read_bytes_per_frame") == plan.UnbatchedBytes &&
            Number(summary, "unbatched_planned_read_calls_per_frame") == plan.UnbatchedCalls &&
            Number(summary, "planned_guard_gap_bytes_per_frame") == plan.GapBytes, "batch_summary_plan");
        Need(Number(summary, "published_frame_read_calls") == state.MinimumReads && Number(summary, "published_frame_read_bytes") == state.MinimumReadBytes &&
            Number(summary, "published_frame_guard_gap_bytes") == state.GuardGapBytes, "batch_summary_published_counts");
        long calls = Number(summary, "unpublished_frame_read_calls"), bytes = Number(summary, "unpublished_frame_read_bytes"), gaps = Number(summary, "unpublished_frame_guard_gap_bytes");
        Need(calls >= 0 && calls <= plan.ReadCalls && bytes >= calls && bytes <= plan.ReadBytes && gaps >= 0 && gaps <= plan.GapBytes && gaps <= bytes &&
            (calls != 0 || bytes == 0 && gaps == 0) &&
            Number(summary, "read_calls") == state.MinimumReads + calls && Number(summary, "read_bytes") == state.MinimumReadBytes + bytes &&
            Number(summary, "guard_gap_read_bytes") == state.GuardGapBytes + gaps, "batch_summary_total_counts");
        long frames = Number(summary, "unpublished_frames");
        Need(frames is 0 or 1 && Text(summary, "unpublished_read_accounting") == GuardBatches.UnpublishedAccounting &&
            (frames != 0 || calls == 0 && bytes == 0 && gaps == 0), "batch_accounting_qualification");
        // Before any path/field reads, every absolute batch is visited in plan order. A control stop
        // can only leave an attempted prefix. Beyond it, tail counts are bounded declarations, not traces.
        int prefix = (int)Math.Min(calls, plan.Batches.Length);
        long prefixBytes = plan.Batches.Take(prefix).Sum(b => b.Width), prefixGaps = plan.Batches.Take(prefix).Sum(b => b.GapBytes);
        Need(bytes >= prefixBytes + calls - prefix && gaps >= prefixGaps &&
            (calls >= plan.Batches.Length || bytes == prefixBytes && gaps == prefixGaps) &&
            (calls != plan.ReadCalls || bytes == plan.ReadBytes && gaps == plan.GapBytes), "batch_unpublished_prefix_bounds");
        if (frames != 0)
            Need(Text(summary, "stop_reason") is "output_byte_limit" or "recording_chunk_limit" or "free_disk_limit" or "compressed_byte_limit" or "index_byte_limit" or "storage_cohort_limit" or "storage_cohort_chunk_limit",
                "batch_unpublished_stop_reason");
    }
}
