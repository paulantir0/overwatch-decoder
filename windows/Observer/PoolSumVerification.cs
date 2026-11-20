using System.Text.Json;

namespace OverwatchDecoder.Observer;

public static partial class FieldRecordingVerification
{
    private static void PoolField(JsonElement value, FieldStream.Field field, JsonElement pre, JsonElement post,
        string? terminal, Action<long, long> times, State state)
    {
        Keys(value, "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks", "guard_ids", "path_id",
            "read_address_hex", "read_attempted", "read_error", "codec", "pool_span", "pool_slots", "read_kind", "operands");
        Need(Text(value, "codec") == PoolSumCodec.Name && Number(value, "pool_span") == field.Pool!.Span &&
            Text(value, "read_kind") == "operand_envelope" && value.GetProperty("path_id").ValueKind == JsonValueKind.Null, "pool_configuration_mismatch");
        Need(Equal(value.GetProperty("pool_slots"), JsonSerializer.SerializeToElement(field.Pool!.Slots)), "pool_layout_mismatch");
        var operands = value.GetProperty("operands"); Keys(operands, "snapshot_a", "snapshot_b");
        string? GuardReason(JsonElement pass, string phase)
        {
            foreach (int id in field.Guards)
                if (!Flag(pass[id], "ok"))
                { string error = Text(pass[id], "error"); return error == "guard_mismatch" ? "guard_mismatch_" + phase : "guard_read_" + phase + ":" + error; }
            return null;
        }
        string? beforeError = GuardReason(pre, "before");
        var stateRead = TimerOperand(operands.GetProperty("snapshot_a"), field.Address, field.Pool!.Span, beforeError, terminal, times, state);
        var clockRead = TimerOperand(operands.GetProperty("snapshot_b"), field.Address, field.Pool!.Span, stateRead.error, terminal, times, state);
        var evidence = new PoolSumCodec.Evidence(stateRead, clockRead);
        Need(Flag(value, "read_attempted") == stateRead.attempted &&
            (stateRead.attempted ? PointerHex(value, "read_address_hex") == field.Address : value.GetProperty("read_address_hex").ValueKind == JsonValueKind.Null), "pool_attempted_mismatch");
        long? Tick(string key) => value.GetProperty(key).ValueKind == JsonValueKind.Null ? null : Number(value, key);
        Need(Tick("read_start_ticks") == evidence.Start && Tick("read_end_ticks") == evidence.End, "pool_operand_envelope");
        Need(value.GetProperty("read_error").GetString() == evidence.Error, "pool_read_error");
        (object? calculated, string? error) = PoolSumCodec.Decode(field, evidence);
        string? expectedReason = terminal ?? error ?? GuardReason(post, "after");
        Need(value.GetProperty("reason").GetString() == expectedReason && Text(value, "status") == (expectedReason is null ? "observed" : "unknown"), "pool_status_reason");
        if (expectedReason is null)
        {
            // The writer serializes the exactly rounded binary32 result as a binary64 number. Compare signed zero as well.
            double actual = value.GetProperty("value").GetDouble();
            Need(calculated is double expected && BitConverter.DoubleToInt64Bits(actual) == BitConverter.DoubleToInt64Bits(expected), "pool_calculated_value");
        }
        else Need(value.GetProperty("value").ValueKind == JsonValueKind.Null, "pool_unknown_value");
    }
}
