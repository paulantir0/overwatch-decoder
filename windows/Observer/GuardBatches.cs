using System.Text.Json;

namespace OverwatchDecoder.Observer;

// Version 3 only. A physical read can contain several logical predicates, never pointer/field reads.
internal static class GuardBatches
{
    internal const string UnpublishedAccounting = "observer_declared_bounded_not_trace_verified";
    internal const string Algorithm = "consecutive_same_dependencies_v1";
    internal const int DefaultSpan = 128, DefaultGap = 32, MaximumSpan = 512, MaximumGap = 32,
        MaximumGuardsPerBatch = 32, PageBytes = 4096;
    internal sealed record Policy(int maximum_span_bytes, int maximum_gap_bytes, [property: System.Text.Json.Serialization.JsonIgnore] string AlgorithmName = Algorithm)
    { public string algorithm => AlgorithmName; }
    internal sealed record Batch(int Id, ulong Address, int Width, int GapBytes, int[] Guards);
    internal sealed record Plan(Policy Policy, Batch[] Batches, int ReadBytes, int ReadCalls,
        int UnbatchedBytes, int UnbatchedCalls, int GapBytes);
    internal sealed record Physical(int batch_id, bool attempted, string? address_hex, int requested_bytes,
        int guard_count, int? returned_bytes, long? start_ticks, long? end_ticks, string? error);
    internal sealed record Logical(int guard_id, int batch_id, int slice_offset, int byte_count,
        string? bytes_hex, bool ok, string? error);
    internal sealed record Pass(FieldStream.GuardResult[] Checks, Physical[] Batches, Logical[] Guards);

    internal static Policy ParsePolicy(JsonElement root)
    {
        var e = root.GetProperty("absolute_guard_reads");
        if (e.ValueKind != JsonValueKind.Object) throw Invalid();
        var seen = new HashSet<string>();
        foreach (var p in e.EnumerateObject())
            if (!seen.Add(p.Name) || p.Name is not ("algorithm" or "maximum_span_bytes" or "maximum_gap_bytes")) throw Invalid();
        if (e.GetProperty("algorithm").GetString() != Algorithm) throw Invalid();
        int span = e.TryGetProperty("maximum_span_bytes", out var s) ? s.GetInt32() : DefaultSpan;
        int gap = e.TryGetProperty("maximum_gap_bytes", out var g) ? g.GetInt32() : DefaultGap;
        if (span is < FieldStream.MaximumGuardBytes or > MaximumSpan || gap is < 0 or > MaximumGap) throw Limit();
        return new(span, gap);
    }
    internal static Plan Build(FieldStream.Profile profile, Policy policy)
    {
        var guards = profile.Guards;
        string Scope(int id) => string.Join(',', profile.Fields.Select((f, i) => (f, i)).Where(x => x.f.Guards.Contains(id)).Select(x => x.i)) + ":" +
            string.Join(',', profile.Paths!.Select((p, i) => (p, i)).Where(x => x.p.RootGuards.Contains(id)).Select(x => x.i));
        var batches = new List<Batch>();
        int n = 0;
        while (n < guards.Length)
        {
            var first = guards[n]; ulong start = first.Address, end = start + (ulong)first.Expected.Length;
            if (start / PageBytes != (end - 1) / PageBytes) throw Invalid();
            var ids = new List<int> { n++ }; string scope = Scope(ids[0]); int gapBytes = 0;
            while (n < guards.Length && ids.Count < MaximumGuardsPerBatch)
            {
                var next = guards[n]; ulong nextEnd = next.Address + (ulong)next.Expected.Length;
                ulong combinedEnd = Math.Max(end, nextEnd);
                ulong gap = next.Address > end ? next.Address - end : 0;
                if (next.Address < guards[n - 1].Address || Scope(n) != scope ||
                    (combinedEnd - 1) / PageBytes != start / PageBytes || combinedEnd - start > (ulong)policy.maximum_span_bytes ||
                    gap > (ulong)policy.maximum_gap_bytes) break;
                gapBytes += (int)gap; end = combinedEnd; ids.Add(n++);
            }
            batches.Add(new(batches.Count, start, checked((int)(end - start)), gapBytes, ids.ToArray()));
        }
        int originalAbsolute = 2 * guards.Sum(g => g.Expected.Length);
        int bytes = profile.ReadBytes - originalAbsolute + 2 * batches.Sum(b => b.Width);
        int calls = 2 * (batches.Count + profile.Paths!.Sum(p => p.Hops.Sum(h => h.Guards.Length) + p.Hops.Length)) + profile.Fields.Length;
        // Reserve the actual logical slices, two physical passes, path traces and ordinary field metadata.
        int serializedBound = 8192 + profile.Fields.Length * 1100 + guards.Length * 896 + batches.Count * 1024 +
            profile.Paths!.Sum(p => p.Hops.Sum(h => h.Guards.Length + 1)) * 1024;
        if (bytes > FieldStream.MaximumReadBytesPerFrame || calls > PointerPaths.MaximumCalls || serializedBound > FieldStream.MaximumLineBytes) throw Limit();
        return new(policy, batches.ToArray(), bytes, calls, profile.ReadBytes,
            calls + 2 * (guards.Length - batches.Count), batches.Sum(b => b.GapBytes) * 2);
    }
    internal static Plan Serial(FieldStream.Profile profile)
    {
        // v4 deliberately preserves single exact guards, including legacy guards crossing a page boundary.
        var batches = profile.Guards.Select((g, id) => new Batch(id, g.Address, g.Expected.Length, 0, [id])).ToArray();
        int timers = profile.Fields.Count(f => f.Timer is not null || f.Pool is not null), calls = 2 * batches.Length + profile.Fields.Length + timers;
        var plan = new Plan(new(FieldStream.MaximumGuardBytes, 0, TimerCodec.SerialGuards), batches, profile.ReadBytes, calls, profile.ReadBytes, calls, 0);
        // Exact-profile native-state envelope; arbitrary provider error strings still face the actual serialized-line cap.
        int serializedBound = TimerFrameAdmission.Estimate(profile with { Batching = plan });
        if (profile.ReadBytes > FieldStream.MaximumReadBytesPerFrame || calls > PointerPaths.MaximumCalls || serializedBound > FieldStream.MaximumLineBytes) throw Limit();
        return plan;
    }
    internal static Pass Read(FieldStream.Profile profile, PointerPaths.Reader read, ref string? terminal)
    {
        var plan = profile.Batching!;
        var physical = new Physical[plan.Batches.Length]; var logical = new Logical[profile.Guards.Length];
        var checks = new FieldStream.GuardResult[profile.Guards.Length];
        foreach (Batch b in plan.Batches)
        {
            var r = read(b.Address, b.Width, ref terminal);
            physical[b.Id] = new(b.Id, r.Attempted, r.Attempted ? PointerPaths.Hex(b.Address) : null,
                b.Width, b.Guards.Length, r.ReturnedBytes, r.Attempted ? r.Start : null, r.Attempted ? r.End : null, r.Error);
            foreach (int id in b.Guards)
            {
                var guard = profile.Guards[id]; int offset = checked((int)(guard.Address - b.Address));
                bool ok = r.Bytes is not null && r.Bytes.AsSpan(offset, guard.Expected.Length).SequenceEqual(guard.Expected);
                string? error = r.Error ?? (ok ? null : "guard_mismatch");
                logical[id] = new(id, b.Id, offset, guard.Expected.Length,
                    r.Bytes is null ? null : Convert.ToHexStringLower(r.Bytes.AsSpan(offset, guard.Expected.Length)), ok, error);
                // Internal only: v3 emits the physical interval once, not these repeated shared brackets.
                checks[id] = new(ok, r.Start, r.End, error);
            }
        }
        return new(checks, physical, logical);
    }
    private static ObservationException Invalid() => new("invalid_field_profile", "Batch profile is malformed, unsupported or crosses a guard page boundary.");
    private static ObservationException Limit() => new("field_profile_limit", "Batch profile exceeds its span, gap, read or evidence bound.");
}
