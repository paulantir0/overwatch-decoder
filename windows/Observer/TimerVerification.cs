using System.Text.Json;

namespace OverwatchDecoder.Observer;

public static partial class FieldRecordingVerification
{
    private static void TimerField(JsonElement value, FieldStream.Field field, JsonElement pre, JsonElement post,
        string? terminal, Action<long, long> times, State state)
    {
        Keys(value, "type", "status", "value", "reason", "read_start_ticks", "read_end_ticks", "guard_ids", "path_id",
            "read_address_hex", "read_attempted", "read_error", "codec", "counter_scale_f32_hex", "read_kind", "operands");
        Need(Text(value, "codec") == TimerCodec.Name && Text(value, "counter_scale_f32_hex") == field.Timer!.ScaleHex &&
            Text(value, "read_kind") == "operand_envelope" && value.GetProperty("path_id").ValueKind == JsonValueKind.Null, "timer_configuration_mismatch");
        var operands = value.GetProperty("operands"); Keys(operands, "state", "clock");
        string? GuardReason(JsonElement pass, string phase)
        {
            foreach (int id in field.Guards)
                if (!Flag(pass[id], "ok"))
                { string error = Text(pass[id], "error"); return error == "guard_mismatch" ? "guard_mismatch_" + phase : "guard_read_" + phase + ":" + error; }
            return null;
        }
        string? beforeError = GuardReason(pre, "before");
        var stateRead = TimerOperand(operands.GetProperty("state"), field.Address, 16, beforeError, terminal, times, state);
        var clockRead = TimerOperand(operands.GetProperty("clock"), field.Timer!.Clock, 8, stateRead.error, terminal, times, state);
        var evidence = new TimerCodec.Evidence(stateRead, clockRead);
        Need(Flag(value, "read_attempted") == stateRead.attempted &&
            (stateRead.attempted ? PointerHex(value, "read_address_hex") == field.Address : value.GetProperty("read_address_hex").ValueKind == JsonValueKind.Null), "timer_attempted_mismatch");
        long? Tick(string key) => value.GetProperty(key).ValueKind == JsonValueKind.Null ? null : Number(value, key);
        Need(Tick("read_start_ticks") == evidence.Start && Tick("read_end_ticks") == evidence.End, "timer_operand_envelope");
        Need(value.GetProperty("read_error").GetString() == evidence.Error, "timer_read_error");
        (object? calculated, string? error) = TimerCodec.Decode(field, evidence);
        string? expectedReason = terminal ?? error ?? GuardReason(post, "after");
        Need(value.GetProperty("reason").GetString() == expectedReason && Text(value, "status") == (expectedReason is null ? "observed" : "unknown"), "timer_status_reason");
        if (expectedReason is null)
        {
            // The writer serializes the exactly rounded binary32 result as a binary64 number. Compare signed zero as well.
            double actual = value.GetProperty("value").GetDouble();
            Need(calculated is double expected && BitConverter.DoubleToInt64Bits(actual) == BitConverter.DoubleToInt64Bits(expected), "timer_calculated_value");
        }
        else Need(value.GetProperty("value").ValueKind == JsonValueKind.Null, "timer_unknown_value");
    }
    private static TimerCodec.Operand TimerOperand(JsonElement e, ulong address, int width, string? dependencyError,
    string? terminal, Action<long, long> times, State state)
    {
        Keys(e, "attempted", "address_hex", "requested_bytes", "returned_bytes", "bytes_hex", "start_ticks", "end_ticks", "error");
        Need(Number(e, "requested_bytes") == width, "timer_operand_width");
        bool attempted = Flag(e, "attempted"); string? error = e.GetProperty("error").ValueKind == JsonValueKind.Null ? null : Text(e, "error");
        bool required = dependencyError is null;
        if (attempted) Need(required, "timer_read_without_prerequisite");
        if (!attempted && required) Need(error is not null && FieldStream.Fatal(error), "timer_missing_required_read");
        BatchControl(state, attempted, error, true);
        if (!attempted)
        {
            Need(new[] { "address_hex", "returned_bytes", "bytes_hex", "start_ticks", "end_ticks" }.All(k => e.GetProperty(k).ValueKind == JsonValueKind.Null), "timer_unattempted_evidence");
            Need(error is { Length: > 0 and <= 256 } && (required || error == dependencyError || error == terminal), "timer_unattempted_reason");
            return TimerCodec.Missing(width, error!);
        }
        Need(PointerHex(e, "address_hex") == address, "timer_operand_address");
        long start = Number(e, "start_ticks"), end = Number(e, "end_ticks"); times(start, end);
        state.MinimumReads++; state.MinimumReadBytes += width;
        int? returned = e.GetProperty("returned_bytes").ValueKind == JsonValueKind.Null ? null : e.GetProperty("returned_bytes").GetInt32();
        string? bytes = e.GetProperty("bytes_hex").ValueKind == JsonValueKind.Null ? null : Text(e, "bytes_hex");
        if (error is null) Need(returned == width && bytes is not null && bytes.Length == width * 2 && bytes.All(Uri.IsHexDigit), "timer_complete_buffer");
        else Need(error.Length is > 0 and <= 256 && bytes is null && (returned is null || error == "partial_read" && returned >= 0 && returned != width), "timer_failed_buffer");
        return new(true, PointerPaths.Hex(address), width, returned, bytes, start, end, error);
    }

    private static void SerialGuardPass(JsonElement pass, FieldStream.Profile profile, string? terminal, Action<long, long> times, State state)
    {
        for (int id = 0; id < profile.Guards.Length; id++)
        {
            var evidence = pass[id]; var guard = profile.Guards[id]; Keys(evidence, "guard_id", "ok", "error", "read");
            Need(Number(evidence, "guard_id") == id, "serial_guard_order");
            var read = TimerOperand(evidence.GetProperty("read"), guard.Address, guard.Expected.Length, null, terminal, times, state);
            bool ok = read.bytes_hex is not null && Convert.FromHexString(read.bytes_hex).AsSpan().SequenceEqual(guard.Expected);
            Need(Flag(evidence, "ok") == ok && evidence.GetProperty("error").GetString() == (read.error ?? (ok ? null : "guard_mismatch")), "serial_guard_match");
        }
    }
}
