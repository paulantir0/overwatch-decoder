using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

// Caller-provided layout only. Membership is sampled each frame, never learned as a persistent guard.
// Two full snapshots are sequential, not atomic: an A->B->A membership transition can escape detection.
// Scalars come solely from snapshot A; B validates every membership, not scalar stability.
// Arithmetic is ordered binary32 addition from positive zero (including an initial occupied slot).
// No pool roles, health semantics, target offsets, cached operands, or cross-frame carry are implied.
internal static class PoolSumCodec
{
    internal const string Name = "pool_sum_f32";
    internal sealed record Slot(int membership_offset, int scalar_offset);
    internal sealed record Config(int Span, Slot[] Slots);
    internal sealed record Evidence(TimerCodec.Operand snapshot_a, TimerCodec.Operand snapshot_b)
    {
        internal long? Start => snapshot_a.start_ticks;
        internal long? End => snapshot_b.end_ticks ?? snapshot_a.end_ticks;
        internal string? Error => snapshot_a.error ?? snapshot_b.error;
    }
    internal sealed record Wire(string type, string status, object? value, string? reason,
        long? read_start_ticks, long? read_end_ticks, int[] guard_ids,
        int? path_id, string? read_address_hex, bool read_attempted, string? read_error,
        string codec, int pool_span, Slot[] pool_slots, string read_kind, Evidence operands);
    internal static Config ParseConfig(JsonElement field)
    {
        static void Need(bool b) { if (!b) throw new ObservationException("invalid_field_profile", "Invalid bounded pool layout."); }
        int span = field.GetProperty("pool_span").GetInt32();
        Need(span is >= 8 and <= 4096);
        var slots = field.GetProperty("pool_slots"); Need(slots.ValueKind == JsonValueKind.Array && slots.GetArrayLength() is >= 1 and <= 256);
        var result = new List<Slot>(); var used = new HashSet<int>(); int previous = -1;
        foreach (var s in slots.EnumerateArray())
        {
            Need(s.ValueKind == JsonValueKind.Object); var keys = s.EnumerateObject().Select(p => p.Name).ToArray();
            Need(keys.Length == 2 && keys.Distinct().Count() == 2 && keys.Contains("membership_offset") && keys.Contains("scalar_offset"));
            int member = s.GetProperty("membership_offset").GetInt32(), scalar = s.GetProperty("scalar_offset").GetInt32();
            Need(member > previous && member >= 0 && member <= span - 4 && scalar >= 0 && scalar <= span - 4);
            foreach (int offset in new[] { member, scalar }) for (int b = 0; b < 4; b++) Need(used.Add(offset + b));
            previous = member; result.Add(new(member, scalar));
        }
        return new(span, result.ToArray());
    }
    internal static Evidence Read(FieldStream.Field field, PointerPaths.Reader read, string? blocked, ref string? terminal)
    {
        int span = field.Pool!.Span;
        if (blocked is not null) return new(TimerCodec.Missing(span, blocked), TimerCodec.Missing(span, blocked));
        var first = read(field.Address, span, ref terminal);
        var second = first.Bytes is null ? TimerCodec.Missing(span, first.Error ?? "pool_unavailable") : TimerCodec.Observed(field.Address, span, read(field.Address, span, ref terminal));
        return new(TimerCodec.Observed(field.Address, span, first), second);
    }
    internal static (object? Value, string? Error) Decode(FieldStream.Field field, Evidence evidence)
    {
        if (evidence.Error is { } error) return (null, error);
        return Evaluate(field.Pool!, Convert.FromHexString(evidence.snapshot_a.bytes_hex!), Convert.FromHexString(evidence.snapshot_b.bytes_hex!), field.Min, field.Max);
    }
    internal static (object? Value, string? Error) Evaluate(Config config, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, double? min = null, double? max = null)
    {
        if (a.Length != config.Span || b.Length != config.Span) return (null, "pool_buffer_size");
        // Check every declared membership, including zero slots, before interpreting any scalar.
        foreach (var slot in config.Slots)
            if (BinaryPrimitives.ReadUInt32LittleEndian(a[slot.membership_offset..]) != BinaryPrimitives.ReadUInt32LittleEndian(b[slot.membership_offset..]))
                return (null, "pool_membership_changed");
        float total = 0f;
        foreach (var slot in config.Slots)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(a[slot.membership_offset..]) == 0) continue;
            float scalar = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(a[slot.scalar_offset..]));
            if (!float.IsFinite(scalar)) return (null, "non_finite_operand");
            total = Add(total, scalar);
            if (!float.IsFinite(total)) return (null, "non_finite_calculation");
        }
        if (total < min || total > max) return (null, "out_of_range");
        return ((double)total, null);
    }
    [MethodImpl(MethodImplOptions.NoInlining)] private static float Add(float a, float b) => a + b;
}
