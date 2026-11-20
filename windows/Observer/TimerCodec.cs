using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

// One fixed layout/operation sequence, not an expression language. Addresses and scale are private profile data.
internal static class TimerCodec
{
    internal const string Name = "elapsed_i64_f32_v1", SerialGuards = "single_guard_v1";
    internal const int MaximumTimers = 16;
    internal sealed record Config(ulong Clock, string ScaleHex, float Scale);
    internal sealed record Operand(bool attempted, string? address_hex, int requested_bytes, int? returned_bytes,
        string? bytes_hex, long? start_ticks, long? end_ticks, string? error);
    internal sealed record SerialGuard(int guard_id, bool ok, string? error, Operand read);
    internal static SerialGuard[] GuardEvidence(GuardBatches.Pass pass) => pass.Guards.Select(g =>
    { var b = pass.Batches[g.batch_id]; return new SerialGuard(g.guard_id, g.ok, g.error,
        new(b.attempted, b.address_hex, b.requested_bytes, b.returned_bytes, g.bytes_hex, b.start_ticks, b.end_ticks, b.error)); }).ToArray();
    internal sealed record Evidence(Operand state, Operand clock)
    {
        internal long? Start => state.start_ticks;
        internal long? End => clock.end_ticks ?? state.end_ticks;
        internal string? Error => state.error ?? clock.error;
    }
    internal sealed record Wire(string type, string status, object? value, string? reason,
        long? read_start_ticks, long? read_end_ticks, int[] guard_ids,
        int? path_id, string? read_address_hex, bool read_attempted, string? read_error,
        string codec, string counter_scale_f32_hex, string read_kind, Evidence operands);
    internal static Operand Missing(int bytes, string reason) => new(false, null, bytes, null, null, null, null, reason);
    internal static Operand Observed(ulong address, int size, FieldStream.Reading r) => new(r.Attempted,
        r.Attempted ? PointerPaths.Hex(address) : null, size, r.ReturnedBytes,
        r.Bytes is null ? null : Convert.ToHexStringLower(r.Bytes), r.Attempted ? r.Start : null, r.Attempted ? r.End : null, r.Error);
    internal static Evidence Read(FieldStream.Field field, PointerPaths.Reader read, string? blocked, ref string? terminal)
    {
        if (blocked is not null) return new(Missing(16, blocked), Missing(8, blocked));
        var state = read(field.Address, 16, ref terminal);
        var clock = state.Bytes is null ? Missing(8, state.Error ?? "state_unavailable") : Observed(field.Timer!.Clock, 8, read(field.Timer!.Clock, 8, ref terminal));
        return new(Observed(field.Address, 16, state), clock);
    }
    internal static (object? Value, string? Error) Decode(FieldStream.Field field, Evidence evidence)
    {
        if (evidence.Error is { } error) return (null, error);
        return Evaluate(Convert.FromHexString(evidence.state.bytes_hex!), Convert.FromHexString(evidence.clock.bytes_hex!), field.Timer!.Scale, field.Min, field.Max);
    }
    internal static (object? Value, string? Error) Evaluate(ReadOnlySpan<byte> state, ReadOnlySpan<byte> clock, float scale, double? min, double? max)
    {
        long stamp = BinaryPrimitives.ReadInt64LittleEndian(state), counter = BinaryPrimitives.ReadInt64LittleEndian(clock);
        float baseline = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(state[8..]));
        float rate = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(state[12..]));
        if (!float.IsFinite(baseline) || !float.IsFinite(rate)) return (null, "non_finite_operand");
        long delta = unchecked(counter - stamp);
        // Direct signed integer conversion (not via double), then distinct binary32 operations. No FMA or smoothing.
        float scaled = Multiply((float)delta, scale), elapsed = Multiply(scaled, rate), remaining = Subtract(baseline, elapsed);
        if (!float.IsFinite(scaled) || !float.IsFinite(elapsed) || !float.IsFinite(remaining)) return (null, "non_finite_calculation");
        float result = remaining >= 0f ? remaining : 0f; // MAXSS zero,value equality selects value, including -0.
        if (result < min || result > max) return (null, "out_of_range");
        return ((double)result, null);
    }
    [MethodImpl(MethodImplOptions.NoInlining)] private static float Multiply(float a, float b) => a * b;
    [MethodImpl(MethodImplOptions.NoInlining)] private static float Subtract(float a, float b) => a - b;

    internal static FieldStream.Profile Parse(JsonElement root, byte[] raw)
    {
        static void Need(bool ok) { if (!ok) throw new ObservationException("invalid_field_profile", "Timer profile is malformed or unsupported."); }
        static void Keys(JsonElement e, params string[] allowed)
        { Need(e.ValueKind == JsonValueKind.Object); var seen = new HashSet<string>(); foreach (var p in e.EnumerateObject()) Need(seen.Add(p.Name) && allowed.Contains(p.Name)); }
        Keys(root, "schema", "target", "guards", "fields"); Need(root.GetProperty("schema").GetString() == "overwatch-decoder.field-profile/4");
        // Reuse exact v1 identity/guard/name/range validation. The original v4 bytes remain the saved profile/hash.
        var projected = JsonNode.Parse(raw)!.AsObject(); projected["schema"] = "overwatch-decoder.field-profile/1";
        var configs = new List<Config?>(); var pools = new List<PoolSumCodec.Config?>(); int timers = 0;
        foreach (var f in root.GetProperty("fields").EnumerateArray())
        {
            Keys(f, "name", "type", "address", "guards", "min", "max", "codec", "clock_address", "counter_scale_f32_hex", "pool_span", "pool_slots");
            Config? config = null; PoolSumCodec.Config? pool = null;
            if (f.TryGetProperty("codec", out var poolCodec) && poolCodec.GetString() == PoolSumCodec.Name)
            {
                Need(f.GetProperty("type").GetString() == "f32" && !f.TryGetProperty("clock_address", out _) && !f.TryGetProperty("counter_scale_f32_hex", out _));
                pool = PoolSumCodec.ParseConfig(f);
                Need(PointerPaths.Add(f.GetProperty("address").GetUInt64(), 0, pool.Span, out _));
                var node = projected["fields"]![configs.Count]!.AsObject(); node.Remove("codec"); node.Remove("pool_span"); node.Remove("pool_slots");
            }
            else if (f.TryGetProperty("codec", out var codec))
            {
                Need(!f.TryGetProperty("pool_span", out _) && !f.TryGetProperty("pool_slots", out _));
                Need(codec.GetString() == Name && f.GetProperty("type").GetString() == "f32");
                ulong address = f.GetProperty("address").GetUInt64(), clock = f.GetProperty("clock_address").GetUInt64();
                Need(PointerPaths.Add(address, 0, 16, out _) && PointerPaths.Add(clock, 0, 8, out _));
                string hex = f.GetProperty("counter_scale_f32_hex").GetString() ?? "";
                Need(hex.Length == 8 && hex.All(Uri.IsHexDigit)); float scale = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(Convert.FromHexString(hex)));
                Need(float.IsFinite(scale) && scale > 0f); config = new(clock, hex.ToLowerInvariant(), scale); timers++;
                var node = projected["fields"]![configs.Count]!.AsObject(); node.Remove("codec"); node.Remove("clock_address"); node.Remove("counter_scale_f32_hex");
            }
            else Need(!f.TryGetProperty("clock_address", out _) && !f.TryGetProperty("counter_scale_f32_hex", out _) && !f.TryGetProperty("pool_span", out _) && !f.TryGetProperty("pool_slots", out _));
            configs.Add(config); pools.Add(pool);
        }
        // V4 also represents an empty dynamic partition with only ordinary
        // context fields. Codec presence is optional; all existing field, guard,
        // serial-read and evidence bounds below still apply.
        if (timers > MaximumTimers) throw new ObservationException("field_profile_limit", "Timer profile exceeds its codec count bound.");
        var parsed = FieldStream.ParseTimerProjection(JsonSerializer.SerializeToUtf8Bytes(projected));
        var fields = parsed.Fields.Select((f, i) => f with { Timer = configs[i], Pool = pools[i], Width = pools[i]?.Span ?? (configs[i] is null ? f.Width : 16) }).ToArray();
        var profile = parsed with { Hash = Convert.ToHexStringLower(SHA256.HashData(raw)), Raw = raw, Fields = fields,
            ReadBytes = parsed.ReadBytes + timers * 20 + pools.Where(p => p is not null).Sum(p => 2 * p!.Span - 4), Paths = [], V4 = true };
        return profile with { Batching = GuardBatches.Serial(profile) };
    }

    // Compact products keep numerical source bytes and intervals; runtime addresses remain only in private recordings.
    internal static void CopyCompact(Utf8JsonWriter writer, JsonElement field)
    {
        if (!field.TryGetProperty("codec", out _)) return;
        foreach (string key in field.GetProperty("codec").GetString() == PoolSumCodec.Name ? new[] { "codec", "pool_span", "pool_slots", "read_kind" } : new[] { "codec", "counter_scale_f32_hex", "read_kind" })
        { writer.WritePropertyName(key); field.GetProperty(key).WriteTo(writer); }
        writer.WritePropertyName("operands"); writer.WriteStartObject();
        foreach (var operand in field.GetProperty("operands").EnumerateObject())
        {
            writer.WritePropertyName(operand.Name); writer.WriteStartObject();
            foreach (var p in operand.Value.EnumerateObject()) if (p.Name != "address_hex") { writer.WritePropertyName(p.Name); p.Value.WriteTo(writer); }
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }
}
