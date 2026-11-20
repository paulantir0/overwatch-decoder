using System.Buffers.Binary;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

public static partial class FieldRecordingVerification
{
    private sealed class PointerProof(FieldStream.Profile model, JsonElement[] traces)
    {
        internal FieldStream.Profile Model = model;
        internal JsonElement[] Traces = traces;
        internal ulong?[][] Slots = model.Paths!.Select(p => new ulong?[p.Hops.Length]).ToArray();
        internal ulong?[][] Nodes = model.Paths!.Select(p => new ulong?[p.Hops.Length]).ToArray();
        internal byte[]?[][] Bytes = model.Paths!.Select(p => new byte[]?[p.Hops.Length]).ToArray();
        internal ulong?[] Leaves = new ulong?[model.Paths!.Length];
        internal bool[] Good = new bool[model.Paths!.Length];
    }
    private static ulong PointerHex(JsonElement e, string key)
    {
        string hex = Text(e, key); Need(hex.Length == 16 && hex.All(Uri.IsHexDigit), "invalid_trace_address");
        return Convert.ToUInt64(hex, 16);
    }
    private static byte[]? PointerRead(JsonElement read, ulong? expected, int width, Action<long, long> times, State state)
    {
        Keys(read, "attempted", "address_hex", "bytes_hex", "start_ticks", "end_ticks", "error");
        if (state.BatchFrame)
            BatchControl(state, Flag(read, "attempted"), read.GetProperty("error").ValueKind == JsonValueKind.Null ? null : Text(read, "error"), true);
        if (!Flag(read, "attempted"))
        {
            if (state.BatchFrame && expected is not null) Need(state.PhysicalStop is not null, "batch_missing_required_path_read");
            Need(new[] { "address_hex", "bytes_hex", "start_ticks", "end_ticks" }.All(k => read.GetProperty(k).ValueKind == JsonValueKind.Null) &&
                Text(read, "error").Length is > 0 and <= 256, "invalid_unattempted_trace"); return null;
        }
        Need(expected is not null && PointerHex(read, "address_hex") == expected.Value, "pointer_trace_address_mismatch");
        times(Number(read, "start_ticks"), Number(read, "end_ticks")); state.MinimumReads++; state.MinimumReadBytes += width;
        if (read.GetProperty("error").ValueKind != JsonValueKind.Null)
        { Need(Text(read, "error").Length is > 0 and <= 256 && read.GetProperty("bytes_hex").ValueKind == JsonValueKind.Null, "failed_trace_retained_bytes"); return null; }
        string hex = Text(read, "bytes_hex"); Need(hex.Length == width * 2 && hex.All(Uri.IsHexDigit), "invalid_trace_bytes"); return Convert.FromHexString(hex);
    }
    private static ulong? PointerAddress(ulong? node, uint offset, int width) =>
        node is { } n && PointerPaths.Add(n, offset, width, out ulong a) ? a : null;
    private static bool PointerGuard(JsonElement evidence, ulong? node, PointerPaths.RelativeGuard guard, Action<long, long> times, State state)
    {
        Keys(evidence, "ok", "read"); byte[]? bytes = PointerRead(evidence.GetProperty("read"), PointerAddress(node, guard.Offset, guard.Expected.Length), guard.Expected.Length, times, state);
        bool ok = bytes is not null && bytes.AsSpan().SequenceEqual(guard.Expected);
        Need(Flag(evidence, "ok") == ok, "path_guard_status_mismatch"); return ok;
    }
    private static PointerProof PointerBefore(JsonElement frame, FieldStream.Profile model, JsonElement roots, Action<long, long> times, State state)
    {
        var list = frame.GetProperty("path_traces"); Need(list.ValueKind == JsonValueKind.Array && list.GetArrayLength() == model.Paths!.Length, "path_trace_count");
        var proof = new PointerProof(model, list.EnumerateArray().ToArray());
        for (int id = 0; id < model.Paths!.Length; id++)
        {
            var path = model.Paths[id]; var trace = proof.Traces[id]; Keys(trace, "path_id", "status", "reason", "hops");
            Need(Number(trace, "path_id") == id, "path_trace_id"); string status = Text(trace, "status");
            Need(status is "observed" or "unknown", "path_trace_status");
            Need(status == "observed" ? trace.GetProperty("reason").ValueKind == JsonValueKind.Null : Text(trace, "reason").Length is > 0 and <= 256, "path_trace_reason");
            var hops = trace.GetProperty("hops"); Need(hops.ValueKind == JsonValueKind.Array && hops.GetArrayLength() == path.Hops.Length, "path_hop_count");
            bool good = path.RootGuards.All(i => Flag(roots[i], "ok")); ulong? current = good ? path.Root : null; var seen = new HashSet<ulong> { path.Root };
            for (int n = 0; n < path.Hops.Length; n++)
            {
                var hop = path.Hops[n]; var h = hops[n]; Keys(h, "pointer_before", "guards_before", "guards_after", "pointer_after");
                var pre = h.GetProperty("guards_before"); var post = h.GetProperty("guards_after");
                Need(pre.ValueKind == JsonValueKind.Array && post.ValueKind == JsonValueKind.Array && pre.GetArrayLength() == hop.Guards.Length && post.GetArrayLength() == hop.Guards.Length, "path_guard_count");
                ulong? slot = PointerAddress(current, hop.Offset, 8); proof.Slots[id][n] = slot;
                byte[]? bytes = PointerRead(h.GetProperty("pointer_before"), slot, 8, times, state); proof.Bytes[id][n] = bytes;
                ulong? node = bytes is null ? null : BinaryPrimitives.ReadUInt64LittleEndian(bytes);
                if (node is { } value && (!PointerPaths.Add(value, 0, 1, out _) || !seen.Add(value))) node = null;
                proof.Nodes[id][n] = node;
                bool guarded = node is not null;
                for (int g = 0; g < hop.Guards.Length; g++) guarded &= PointerGuard(pre[g], node, hop.Guards[g], times, state);
                good &= bytes is not null && guarded; current = good ? node : null;
            }
            proof.Good[id] = good; proof.Leaves[id] = current;
        }
        return proof;
    }
    private static void PointerField(JsonElement value, string name, PointerProof proof, JsonElement roots, State state, bool hasRead)
    {
        var field = proof.Model.Fields.Single(f => f.Name == name);
        Need(field.PathId is { } id ? value.GetProperty("path_id").GetInt32() == id : value.GetProperty("path_id").ValueKind == JsonValueKind.Null, "field_path_mismatch");
        Need(Flag(value, "read_attempted") == hasRead, "field_attempted_mismatch");
        if (state.BatchFrame)
        {
            string? error = value.GetProperty("read_error").ValueKind == JsonValueKind.Null ? null : Text(value, "read_error");
            Need(error is null || error.Length is > 0 and <= 256, "batch_field_read_error");
            BatchControl(state, hasRead, error, true);
            Need(Text(value, "status") != "observed" || error is null, "batch_observed_read_error");
        }
        bool preGood = field.Guards.All(g => Flag(roots[g], "ok")) && (field.PathId is not { } pid || proof.Good[pid]);
        if (hasRead)
        {
            ulong? expected = field.PathId is { } pathId ? PointerAddress(proof.Leaves[pathId], field.Offset, field.Width) : field.Address;
            Need(preGood && expected is not null && PointerHex(value, "read_address_hex") == expected.Value, "field_path_address_mismatch");
            state.MinimumReads++; state.MinimumReadBytes += field.Width;
        }
        else
        {
            Need(value.GetProperty("read_address_hex").ValueKind == JsonValueKind.Null, "unattempted_field_address");
            if (state.BatchFrame && preGood && state.PhysicalStop is null)
            {
                ulong? expected = field.PathId is { } pathId ? PointerAddress(proof.Leaves[pathId], field.Offset, field.Width) : field.Address;
                Need(expected is null, "batch_missing_required_field_read");
            }
        }
        if (Text(value, "status") == "observed" && field.PathId is { } p)
            Need(proof.Good[p] && Text(proof.Traces[p], "status") == "observed", "observed_field_invalid_path");
    }
    private static void PointerAfter(PointerProof proof, JsonElement roots, Action<long, long> times, State state)
    {
        for (int id = proof.Model.Paths!.Length - 1; id >= 0; id--)
        {
            var path = proof.Model.Paths[id]; var hops = proof.Traces[id].GetProperty("hops"); bool good = proof.Good[id];
            for (int n = path.Hops.Length - 1; n >= 0; n--)
            {
                var hop = path.Hops[n]; var h = hops[n]; var post = h.GetProperty("guards_after");
                for (int g = hop.Guards.Length - 1; g >= 0; g--) good &= PointerGuard(post[g], proof.Nodes[id][n], hop.Guards[g], times, state);
                byte[]? bytes = PointerRead(h.GetProperty("pointer_after"), proof.Slots[id][n], 8, times, state);
                good &= bytes is not null && proof.Bytes[id][n] is { } before && bytes.AsSpan().SequenceEqual(before);
            }
            good &= path.RootGuards.All(i => Flag(roots[i], "ok"));
            if (Text(proof.Traces[id], "status") == "observed") Need(good, "path_postcheck_failed");
        }
    }
}
