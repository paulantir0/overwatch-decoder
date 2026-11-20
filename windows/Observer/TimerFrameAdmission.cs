using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

// v4 admission only; never used to produce an observation. The actual serialized-line cap remains authoritative.
internal static class TimerFrameAdmission
{
    // All built-in NativeMemory, sampler and timer error codes are ASCII and shorter than this envelope.
    // IMemorySource implementations can supply arbitrary codes: those are NOT bounded by this estimate.
    internal const int NativeCodeBytes = 64, NumericTokenBytes = 64;
    internal static int Estimate(FieldStream.Profile profile)
    {
        string error = new('e', NativeCodeBytes), reason = "guard_read_before:" + error;
        int extra = 0;
        // An intentionally impossible sizing record holds maximal optional data AND errors simultaneously.
        // This dominates success, mismatch, failed/partial read, unattempted and terminal native states.
        TimerCodec.Operand Operand(ulong address, int width, string code) => new(true, PointerPaths.Hex(address), width,
            int.MinValue, new string('f', width * 2), long.MinValue, long.MinValue, code);
        var physical = profile.Guards.Select((g, id) => new GuardBatches.Physical(id, true, PointerPaths.Hex(g.Address),
            g.Expected.Length, 1, int.MinValue, long.MinValue, long.MinValue, error)).ToArray();
        var logical = profile.Guards.Select((g, id) => new GuardBatches.Logical(id, id, 0, g.Expected.Length,
            new string('f', g.Expected.Length * 2), false, error)).ToArray();
        var checks = profile.Guards.Select(_ => new FieldStream.GuardResult(false, long.MinValue, long.MinValue, error)).ToArray();
        var pass = new GuardBatches.Pass(checks, physical, logical);
        var fields = new Dictionary<string, FieldStream.FieldResult>(StringComparer.Ordinal);
        var addresses = new Dictionary<string, ulong?>(); var attempted = new Dictionary<string, bool>();
        int numericBytes = JsonSerializer.SerializeToUtf8Bytes(double.MinValue).Length;
        foreach (var field in profile.Fields)
        {
            object value = field.Components == 1 ? double.MinValue : Enumerable.Repeat(double.MinValue, field.Components).ToArray();
            TimerCodec.Evidence? operands = field.Timer is { } timer ? new(Operand(field.Address, 16, reason), Operand(timer.Clock, 8, reason)) : null;
            fields.Add(field.Name, new(field.Type, "observed", value, reason, long.MinValue, long.MinValue, field.Guards, reason, operands, field.Pool is { } pool ? new(Operand(field.Address, pool.Span, reason), Operand(field.Address, pool.Span, reason)) : null));
            addresses.Add(field.Name, field.Address); attempted.Add(field.Name, true);
            // .NET's finite round-trip binary64 tokens need <=24 bytes (sign, 17 digits, point, exponent/sign/3 digits).
            // Reserve 64 per component, also covering every integer/byte token and future formatter slack.
            extra += (NumericTokenBytes - numericBytes) * field.Components + 1; // false is one byte longer than true
            if (field.Timer is not null || field.Pool is not null) extra += 2; // both operand attempted flags
        }
        extra += 2 * profile.Guards.Length; // before/after attempted flags
        var frame = new FieldStream.Frame
        {
            schema = profile.StreamSchema, target = Snapshots.PublicIdentity(profile.Target), profile_sha256 = profile.Hash,
            sequence = long.MinValue, scheduled_slot = long.MinValue, scheduled_ticks = long.MinValue,
            start_ticks = long.MinValue, end_ticks = long.MinValue, jitter_ticks = long.MinValue,
            skipped_intervals_before = long.MinValue, skipped_intervals_total = long.MinValue,
            utc_origin = DateTimeOffset.MaxValue, utc_origin_before_ticks = long.MinValue, monotonic_origin_ticks = long.MinValue,
            monotonic_frequency = long.MinValue, requested_interval_ms = int.MinValue,
            scheduler_backend = "windows_high_resolution_waitable_timer", guards_before = checks, guards_after = checks, fields = fields
        };
        string envelope = FieldStream.SerializeFrame(frame, profile, fields, [], addresses, attempted,
            pass, pass, long.MinValue, long.MinValue, long.MinValue, error);
        // Includes newline. Exact profile names/escaped identity, widths, IDs, timer data and wire property names are measured.
        return checked(Encoding.UTF8.GetByteCount(envelope) + 1 + extra);
    }
}
