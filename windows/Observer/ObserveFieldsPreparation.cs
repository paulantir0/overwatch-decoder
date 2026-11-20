using System.Diagnostics;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

public static partial class ObserveFields
{
    private sealed record Prepared(Attempt Attempt, long EvidenceBytes, int OriginSegment,
        string? PreparationEndSha256 = null);
    private sealed record Activation(long start_ticks, long end_ticks, int guard_count,
        bool guards_verified, string evidence_sha256);
    private sealed record ActivationRead(int guard_id, string address_hex, string bytes_hex, long start_ticks, long end_ticks);

    // One tracked worker. It owns only its acquisition directory; publication,
    // live events, counters and profile activation stay on the recording thread.
    private sealed class Preparation : IDisposable
    {
        private readonly CancellationTokenSource cancellation;
        internal readonly Task<Prepared> Work;
        internal readonly int Ordinal, OriginSegment;
        internal readonly long Started;
        internal Preparation(BudgetSource source, Acquisition.Module module, byte[] recipe, string output,
            int ordinal, int originSegment, long started, Acquisition.Limits limits, CancellationToken token,
            Action fatal, Action<int, string>? fixture)
        {
            Ordinal = ordinal; OriginSegment = originSegment; Started = started;
            cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            Work = Task.Run(() =>
            {
                string directory = "acquisition-" + ordinal.ToString("D4");
                string path = Path.Combine(output, directory), manifest = Path.Combine(path, "manifest.json");
                Acquisition.Result? result = null; string? error = null, manifestHash = null; long evidence = 0;
                try
                {
                    result = Acquisition.RunBounded(source, module, recipe, path, cancellation.Token,
                        stage => fixture?.Invoke(ordinal, stage), limits);
                    fixture?.Invoke(ordinal, "prepared");
                }
                catch (Exception e) when (e is not OutOfMemoryException) { error = PreparationError(e); }
                try
                {
                    if (File.Exists(manifest))
                    {
                        using var saved = Metadata(manifest); evidence = saved.RootElement.GetProperty("evidence_bytes").GetInt64();
                        manifestHash = FileHash(manifest);
                    }
                }
                catch (Exception e) when (e is not OutOfMemoryException)
                {
                    // A failed metadata read cannot release an unproven artifact
                    // reservation. Charge its full cap and stop on the error.
                    evidence = limits.EvidenceBytes; error ??= PreparationError(e);
                }
                if (Directory.Exists(path) && !File.Exists(manifest))
                { evidence = limits.EvidenceBytes; error ??= "preparation_manifest_missing"; }
                var attempt = new Attempt(ordinal, directory, started, Stopwatch.GetTimestamp(),
                    result?.complete == true && error is null, error, manifestHash, error is null ? result?.profile_sha256 : null);
                // Wake the current reader promptly on terminal worker failure.
                if (error is not null && !Retryable(error))
                {
                    // An enclosing recording exception may already have disposed
                    // its cancellation source; the worker error is still returned.
                    try { fatal(); } catch (ObjectDisposedException) { }
                }
                return new Prepared(attempt, evidence, originSegment);
            });
        }
        internal void Cancel() => cancellation.Cancel();
        public void Dispose() { cancellation.Dispose(); }
    }
    private static string PreparedManifestHash(string path)
    {
        using var file = File.OpenRead(path);
        if (file.Length is < 1 or > 256 * 1024)
            throw new ObservationException("profile_identity_mismatch", "Prepared manifest exceeds its bound.");
        byte[] bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes);
        if (file.ReadByte() != -1)
            throw new ObservationException("profile_identity_mismatch", "Prepared manifest changed while reading.");
        return Hash(bytes);
    }

    // Byte equality is deliberate: a claimed digest alone cannot turn a
    // changed or modified candidate into a no-adoption refresh.
    internal static bool IdenticalPreparedBytes(byte[] active, byte[] candidate, string? claimedHash)
    {
        if (Hash(candidate) != claimedHash)
            throw new ObservationException("profile_identity_mismatch", "Prepared profile changed before comparison.");
        return active.AsSpan().SequenceEqual(candidate);
    }

    private static string PreparationError(Exception e) => e switch
    {
        ObservationException o => o.Code,
        OperationCanceledException => "cancelled",
        UnauthorizedAccessException => "output_permission_denied",
        IOException => "output_io_error",
        _ => "preparation_failed"
    };

    private static (Activation Validation, string? Error, long Bytes) ValidatePrepared(BudgetSource source,
        Acquisition.Module module, Prepared candidate, string output, long availableEvidence,
        Action<int, string>? fixture)
    {
        const int maximumProof = 256 * 1024;
        if (availableEvidence < maximumProof) throw new ObservationException("session_evidence_limit", "Activation evidence budget exhausted.");
        long start = Stopwatch.GetTimestamp(); string? error = null; var reads = new List<ActivationRead>();
        FieldStream.Profile? profile = null;
        try
        {
            fixture?.Invoke(candidate.Attempt.ordinal, "activation");
            source.EnsureModule(module);
            if (PreparedManifestHash(Path.Combine(output, candidate.Attempt.directory, "manifest.json")) != candidate.Attempt.manifest_sha256)
                throw new ObservationException("profile_identity_mismatch", "Prepared acquisition manifest changed before activation.");
            profile = FieldStream.ParseProfileBytes(FieldStream.ValidatedProfileBytes(source,
                Path.Combine(output, candidate.Attempt.directory, "profile.json")));
            if (profile.Hash != candidate.Attempt.profile_sha256)
                throw new ObservationException("profile_identity_mismatch", "Prepared profile changed before activation.");
            foreach (var (guard, index) in profile.Guards.Select((guard, index) => (guard, index)))
            {
                source.EnsureAlive(); long a = Stopwatch.GetTimestamp(); byte[] bytes = source.Read(guard.Address, guard.Expected.Length);
                long b = Stopwatch.GetTimestamp();
                reads.Add(new(index, PointerPaths.Hex(guard.Address), Convert.ToHexStringLower(bytes), a, b));
                if (!bytes.AsSpan().SequenceEqual(guard.Expected))
                    throw new ObservationException("acquisition_guard_mismatch", "Prepared profile guard changed before activation.");
            }
            source.EnsureModule(module);
        }
        catch (Exception e) when (e is not OutOfMemoryException) { error = PreparationError(e); }
        long end = Stopwatch.GetTimestamp();
        byte[] proof = JsonSerializer.SerializeToUtf8Bytes(new { schema = "overwatch-decoder.profile-activation/1",
            target = Snapshots.PublicIdentity(source.Identity), profile_sha256 = candidate.Attempt.profile_sha256,
            start_ticks = start, end_ticks = end, guards = reads, passed = error is null, error });
        if (proof.Length > maximumProof) throw new ObservationException("session_evidence_limit", "Activation evidence exceeds bound.");
        WriteNew(Path.Combine(output, candidate.Attempt.directory, "activation.json"), proof);
        return (new(start, end, profile?.Guards.Length ?? 0, error is null, Hash(proof)), error, proof.Length);
    }
}
