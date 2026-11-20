using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OverwatchDecoder.Observer;

/// <summary>Finite acquisition/recording sessions. Every profile change starts a new ordinary recording.</summary>
public static partial class ObserveFields
{
    public const int DefaultMaximumAcquisitions = 8, DefaultMaximumConsecutiveAcquisitionFailures = 3;
    public const int MaximumAttempts = 128, MaximumConsecutiveAcquisitionFailures = 16;
    public const long MaximumReadCalls = 128_000_000;
    public const long MaximumArtifactBytes = 3L * 1024 * 1024 * 1024;
    internal const int ManifestMoveAttempts = 5, ManifestRetryMilliseconds = 25;
    internal sealed record Limits(int Attempts = DefaultMaximumAcquisitions, int ConsecutiveFailures = DefaultMaximumConsecutiveAcquisitionFailures,
        long ReadBytes = FieldStream.MaximumReadBytes, long ReadCalls = MaximumReadCalls,
        long EvidenceBytes = Acquisition.MaximumEvidenceBytes, long JsonBytes = FieldRecording.MaximumJsonBytes,
        long CompressedBytes = FieldRecording.MaximumCompressedBytes, long IndexBytes = FieldRecording.MaximumIndexBytes,
        int RetryMilliseconds = 250, int AllUnknownMilliseconds = 2000, int ReacquireMilliseconds = 0);
    public sealed class Coverage(string name, string type)
    {
        public string name { get; } = name; public string type { get; } = type;
        public long observed { get; internal set; } public long unknown { get; internal set; }
    }
    public sealed record Attempt(int ordinal, string directory, long start_ticks, long end_ticks, bool complete,
        string? error, string? manifest_sha256, string? profile_sha256);
    public sealed record Segment(int ordinal, int acquisition, string directory, string profile_sha256,
        long start_ticks, long end_ticks, long? first_frame_start_ticks, long? last_frame_end_ticks,
        long frames, long unknown_fields, long skipped_slots, string trigger, long? trigger_sequence,
        long? trigger_frame_start_ticks, long? trigger_frame_end_ticks, string? recording_stop_reason,
        string manifest_sha256);
    public sealed record NoChange(int acquisition, int origin_segment, int active_acquisition,
        string profile_sha256, string? manifest_sha256, string? preparation_end_sha256,
        long comparison_start_ticks, long comparison_end_ticks, bool profile_adopted = false);
    public sealed record Gap(long start_ticks, long end_ticks, string meaning);
    public sealed record ManifestPublication(bool final_manifest_saved, bool current_result_saved,
        string? error, int? native_error_code, string? operation_stop_reason);
    public sealed record Result(string schema, string session_id, string status, bool complete, string stop_reason,
        string interpretation, string visibility, bool public_state_eligible, bool atomic,
        object target, string revision, string recipe_sha256, string source_kind,
        DateTimeOffset utc_origin, long utc_origin_before_ticks, long monotonic_origin_ticks, long monotonic_frequency,
        double requested_duration_s, int requested_interval_ms, long finished_ticks, double elapsed_ms,
        long read_calls, long requested_read_bytes, long acquisition_evidence_bytes, long recorded_json_bytes,
        long compressed_bytes, long index_bytes, object limits, Attempt[] acquisitions, Segment[] segments,
        Gap[] intervals_without_recorded_frames, Coverage[] fields, string? active_operation, string? active_directory,
        long? operation_start_ticks, object? live_output, ManifestPublication manifest_publication, string note, object? preparation = null, NoChange[]? unchanged_preparations = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] object? storage_rotation = null);

    public static Result Run(IMemorySource source, Acquisition.Module module, string recipePath, string outputDirectory,
        int intervalMs, TimeSpan duration, CancellationToken cancellation = default, TextWriter? liveOutput = null,
        bool allowFieldShapeChanges = false, bool liveEvidence = false,
        int maxAcquisitions = DefaultMaximumAcquisitions,
        int maxConsecutiveAcquisitionFailures = DefaultMaximumConsecutiveAcquisitionFailures, int reacquireMs = 0, bool backgroundPreparation = false, int acquisitionRetryMs = 250, StorageRotation? storage = null) =>
        RunBounded(source, module, recipePath, outputDirectory, intervalMs, duration, cancellation,
            new(Attempts: maxAcquisitions, ConsecutiveFailures: maxConsecutiveAcquisitionFailures, ReacquireMilliseconds: reacquireMs, RetryMilliseconds: PublicRetryMilliseconds(acquisitionRetryMs)), liveOutput: liveOutput,
            allowFieldShapeChanges: allowFieldShapeChanges, liveEvidence: liveEvidence, backgroundPreparation: backgroundPreparation, storage: storage);

    internal static Result RunBounded(IMemorySource source, Acquisition.Module module, string recipePath, string outputDirectory,
        int intervalMs, TimeSpan duration, CancellationToken cancellation, Limits limits,
        Action<int, FieldStream.AcceptedFrame>? fixtureFrame = null, TextWriter? liveOutput = null, long liveMaximum = LiveFieldOutput.MaximumBytes,
        bool allowFieldShapeChanges = false, Action<string, string, int>? fixtureManifestMove = null, bool liveEvidence = false,
        bool backgroundPreparation = false, Action<int, string>? fixturePreparationStage = null, StorageRotation? storage = null)
    {
        storage?.Validate();
        if (intervalMs is < 10 or > 10000 || duration <= TimeSpan.Zero || duration > TimeSpan.FromHours(10) ||
            limits.Attempts is < 1 or > MaximumAttempts || limits.ConsecutiveFailures is < 1 or > MaximumConsecutiveAcquisitionFailures ||
            limits.ReadBytes is < 1 or > FieldStream.MaximumReadBytes || limits.ReadCalls is < 1 or > MaximumReadCalls ||
            limits.EvidenceBytes is < 131072 or > Acquisition.MaximumEvidenceBytes ||
            limits.JsonBytes is < 8192 or > FieldRecording.MaximumJsonBytes ||
            limits.CompressedBytes is < 65536 or > FieldRecording.MaximumCompressedBytes ||
            limits.IndexBytes is < 4096 or > FieldRecording.MaximumIndexBytes ||
            limits.RetryMilliseconds is < 0 or > 5000 || limits.AllUnknownMilliseconds is < 1 or > 2000 ||
            (limits.ReacquireMilliseconds != 0 && limits.ReacquireMilliseconds is < 1000 or > 30000) ||
            liveMaximum <= LiveFieldOutput.EndReserve || liveMaximum > LiveFieldOutput.MaximumBytes)
            throw new ObservationException("invalid_arguments", "Observation limits, interval or duration are invalid.");
        if (backgroundPreparation && limits.ReacquireMilliseconds == 0)
            throw new ObservationException("invalid_arguments", "Background preparation requires an explicit reacquisition interval.");
        if (liveEvidence && liveOutput is null)
            throw new ObservationException("invalid_arguments", "Live evidence requires JSONL live output.");
        string output = Path.GetFullPath(outputDirectory);
        if (Directory.Exists(output) || File.Exists(output)) throw new ObservationException("output_exists", "Observation output must be new.");
        byte[] recipe;
        using (var file = new FileStream(recipePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (file.Length is < 1 or > Acquisition.MaximumRecipeBytes) throw new ObservationException("invalid_acquisition_recipe", "Recipe exceeds its size bound.");
            recipe = new byte[checked((int)file.Length)]; file.ReadExactly(recipe);
            if (file.ReadByte() != -1) throw new ObservationException("invalid_acquisition_recipe", "Recipe changed while reading.");
        }
        TargetIdentity identity = source.Identity; string recipeHash = Hash(recipe), sessionId = Guid.NewGuid().ToString("N");
        var live = liveOutput is null ? null : new LiveFieldOutput(liveOutput, sessionId, liveMaximum, liveEvidence);
        long originBefore = Stopwatch.GetTimestamp(); DateTimeOffset utc = DateTimeOffset.UtcNow; long origin = Stopwatch.GetTimestamp();
        long deadline = checked(origin + (long)(duration.TotalSeconds * Stopwatch.Frequency));
        using var deadlineStop = new CancellationTokenSource(duration);
        using var runStop = CancellationTokenSource.CreateLinkedTokenSource(cancellation, deadlineStop.Token);
        using var budget = new BudgetSource(source, identity, runStop.Token, limits);
        var attempts = new List<Attempt>(); var segments = new List<Segment>(); var gaps = new List<Gap>();
        var coverage = new Dictionary<string, Coverage>(StringComparer.Ordinal);
        Preparation? preparation = null; Prepared? ready = null; Activation? activation = null;
        var unchanged = new List<NoChange>();
        int storageCohorts = 0;
        object? StorageStatus() => storage is null ? null : new
        {
            schema = "overwatch-decoder.field-storage-options/1", cohort_bytes = storage.CohortBytes,
            maximum_cohorts = storage.MaximumCohorts, sealed_cohorts = storageCohorts,
            recording_schema = "overwatch-decoder.field-recording/2", semantic_epoch_reset = false
        };
        long prepareAfter = 0, retryAfter = 0; string? preparationFatal = null;
        long evidenceBytes = 0, jsonBytes = 0, compressedBytes = 0, indexBytes = 0, gapStart = origin;
        string stop = "running"; int failures = 0; bool published = false;
        bool finalManifestSaved = false, currentResultSaved = false;
        string? publicationError = null, operationStop = null; int? publicationNativeCode = null;
        string? activeOperation = null, activeDirectory = null; long? operationStart = null;
        string parent = Path.GetDirectoryName(output)!; Directory.CreateDirectory(parent);
        string staging = Path.Combine(parent, ".overwatch-decoder-observation-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(staging);
        Result Manifest(string status)
        {
            long end = Stopwatch.GetTimestamp();
            bool success = status == "finished" && stop == "duration_elapsed" && coverage.Count > 0 && coverage.Values.All(f => f.observed > 0);
            return new("overwatch-decoder.field-observation/1", sessionId, status, success, stop, "profile_declared_research", "research", false, false,
                Snapshots.PublicIdentity(identity), Program.Revision, recipeHash,
                MemorySourceProvenance.IsNative(source) ? "native_process_memory_through_budget_source" : "provided_memory_source",
                utc, originBefore, origin, Stopwatch.Frequency, duration.TotalSeconds, intervalMs, end,
                (end - origin) * 1000d / Stopwatch.Frequency, budget.Calls, budget.Bytes, evidenceBytes, jsonBytes, compressedBytes, indexBytes,
                new { maximum_acquisition_attempts = limits.Attempts, maximum_consecutive_acquisition_failures = limits.ConsecutiveFailures,
                    maximum_read_calls = limits.ReadCalls, maximum_read_bytes = limits.ReadBytes, maximum_acquisition_evidence_bytes = limits.EvidenceBytes,
                    maximum_recorded_json_bytes = limits.JsonBytes, maximum_compressed_bytes = limits.CompressedBytes, maximum_index_bytes = limits.IndexBytes,
                    maximum_artifact_bytes = MaximumArtifactBytes, background_preparation = backgroundPreparation, identical_profile_refresh = backgroundPreparation, maximum_preparation_workers = backgroundPreparation ? 1 : 0, reacquire_ms = limits.ReacquireMilliseconds, retry_delay_ms = limits.RetryMilliseconds, all_unknown_stop_ms = limits.AllUnknownMilliseconds,
                    allow_field_shape_changes = allowFieldShapeChanges, maximum_coverage_fields = limits.Attempts * FieldStream.MaximumFields,
                    maximum_manifest_move_attempts = ManifestMoveAttempts, manifest_retry_delay_ms = ManifestRetryMilliseconds },
                attempts.ToArray(), segments.ToArray(), gaps.ToArray(), coverage.Values.ToArray(), activeOperation, activeDirectory, operationStart, live?.Status(),
                new(finalManifestSaved, currentResultSaved, publicationError, publicationNativeCode, operationStop),
                "Each segment is a separate standard recording/profile. Segment cancellation can mean intentional guard-triggered or periodic reacquisition. " +
                "No frames bridge acquisition gaps. Complete means the finite window ended and every declared field was observed at least once, not continuous or semantic validity. " +
                "Coverage aggregates declared field names only, across admitted segment schemas; absent fields do not accrue unknown samples. Ordinal names are not persistent entity identities. " +
                "Session frame/field counts describe sink-accepted frames, not independently reconstructed durable counts; verify segments before analysis. " +
                "Read intervals remain sequential; unknowns, missed slots and all source evidence remain in the segment. Synchronous I/O can overrun cancellation/deadline. " +
                "This session manifest links artifacts but is not a replacement for strict per-segment verification. All data remains private research.",
                preparation is null ? null : new { ordinal = preparation.Ordinal, origin_segment = preparation.OriginSegment, start_ticks = preparation.Started }, unchanged.ToArray(), StorageStatus());
        }
        void ScheduleRetry()
        {
            retryAfter = Stopwatch.GetTimestamp() + limits.RetryMilliseconds * Stopwatch.Frequency / 1000;
            prepareAfter = Math.Max(prepareAfter, retryAfter);
        }
        void WaitForRetry()
        {
            while (Control() is null)
            {
                long remaining = retryAfter - Stopwatch.GetTimestamp();
                if (remaining <= 0) return;
                int milliseconds = (int)Math.Min(5000, Math.Max(1, Math.Ceiling(remaining * 1000d / Stopwatch.Frequency)));
                if (runStop.Token.WaitHandle.WaitOne(milliseconds)) return;
            }
        }
        string? Control()
        {
            if (cancellation.IsCancellationRequested) return "cancelled";
            if (deadlineStop.IsCancellationRequested || Stopwatch.GetTimestamp() >= deadline) return "duration_elapsed";
            return null;
        }
        void Checkpoint() => WriteManifest(output, Manifest("running"), runStop.Token, fixtureManifestMove);
        Result SaveFinal()
        {
            if (!published) return Manifest("finished");
            var candidate = Manifest("finished") with { manifest_publication = new(true, true, null, null, operationStop) };
            try
            {
                // Final publication gets its own bounded retry window even after target cancellation.
                WriteManifest(output, candidate, CancellationToken.None, fixtureManifestMove);
                finalManifestSaved = currentResultSaved = true;
                return candidate;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ObservationException)
            {
                operationStop ??= stop; stop = "manifest_publication_failed"; currentResultSaved = false;
                publicationError = e is ObservationException observation ? observation.Code : e is UnauthorizedAccessException ? "output_permission_denied" : "output_io_error";
                publicationNativeCode = e is IOException or UnauthorizedAccessException ? e.HResult & 0xffff : null;
                return Manifest("finished");
            }
        }
        Prepared FinishPreparation(bool cancel)
        {
            var worker = preparation ?? throw new InvalidOperationException("No preparation worker.");
            if (cancel) worker.Cancel();
            Prepared result;
            try { result = worker.Work.GetAwaiter().GetResult(); }
            finally { worker.Dispose(); preparation = null; }
            attempts.Add(result.Attempt); evidenceBytes += result.EvidenceBytes;
            if (result.Attempt.error is { } fatal && fatal != "cancelled" && !Retryable(fatal)) preparationFatal = fatal;
            live?.Write("preparation_end", w =>
            {
                w.WriteNumber("origin_segment", result.OriginSegment);
                LiveFieldOutput.Property(w, "acquisition", result.Attempt);
                w.WriteString("outcome", result.Attempt.complete ? "ready" : result.Attempt.error == "cancelled" ? "cancelled" : "failed");
            });
            return result with { PreparationEndSha256 = live?.LastEventSha256 };
        }
        void Discard(Prepared candidate, string error, long start, long end, string? proofHash = null)
        {
            live?.Write("preparation_discard", w =>
            {
                w.WriteNumber("acquisition", candidate.Attempt.ordinal); w.WriteNumber("origin_segment", candidate.OriginSegment);
                w.WriteString("error", error); w.WriteNumber("start_ticks", start); w.WriteNumber("end_ticks", end);
                LiveFieldOutput.Property(w, "evidence_sha256", proofHash);
            });
        }
        try
        {
            WriteNew(Path.Combine(staging, "recipe.json"), recipe); WriteManifest(staging, Manifest("running"), runStop.Token, fixtureManifestMove);
            Directory.Move(staging, output); published = true;
            live?.Write("session_start", w =>
            {
                LiveFieldOutput.Property(w, "target", Snapshots.PublicIdentity(identity)); w.WriteString("recipe_sha256", recipeHash); w.WriteString("revision", Program.Revision);
                w.WriteString("source_kind", MemorySourceProvenance.Kind(source)); w.WriteString("data_classification", "private_research"); w.WriteString("interpretation", "profile_declared_research");
                w.WriteBoolean("public_state_eligible", false); w.WriteBoolean("atomic", false);
                if (liveEvidence)
                {
                    // Profiles are acquired later; v2+ recording frames may contain private addresses.
                    w.WriteNull("address_traces_included"); w.WriteBoolean("recording_frame_included", true);
                }
                else w.WriteBoolean("address_traces_included", false);
                w.WriteNumber("requested_interval_ms", intervalMs); w.WriteNumber("requested_duration_s", duration.TotalSeconds);
                w.WriteBoolean("allow_field_shape_changes", allowFieldShapeChanges);
                w.WriteBoolean("background_preparation", backgroundPreparation);
                w.WriteBoolean("identical_profile_refresh", backgroundPreparation);
                if (storage is not null) LiveFieldOutput.Property(w, "storage_rotation", StorageStatus());
                w.WriteNumber("acquisition_retry_ms", limits.RetryMilliseconds);
                LiveFieldOutput.Property(w, "utc_origin", utc); w.WriteNumber("utc_origin_before_ticks", originBefore); w.WriteNumber("monotonic_origin_ticks", origin);
                w.WriteString("note", "Live frames were accepted by the raw recording sink, not independently verified durable. Names and numeric values remain private research. UTC = utc_origin + (ticks - monotonic_origin_ticks) / monotonic_frequency seconds. No continuity across gaps or segments.");
                LiveFieldOutput.Property(w, "live_output", live.Status());
            });
            while (true)
            {
                if (live?.Error is { } liveError) { stop = liveError; break; }
                if (Control() is { } control) { stop = control; break; }
                WaitForRetry();
                if (Control() is { } afterRetry) { stop = afterRetry; break; }
                int ordinal; string attemptDirectory;
                activation = null;
                if (ready is not null)
                {
                    var candidate = ready;
                    var checkedCandidate = ValidatePrepared(budget, module, candidate, output,
                        limits.EvidenceBytes - evidenceBytes, fixturePreparationStage);
                    evidenceBytes += checkedCandidate.Bytes;
                    ready = null;
                    if (checkedCandidate.Error is { } invalid)
                    {
                        Discard(candidate, invalid, checkedCandidate.Validation.start_ticks, checkedCandidate.Validation.end_ticks,
                            checkedCandidate.Validation.evidence_sha256);
                        if (!Retryable(invalid)) { stop = invalid == "cancelled" ? Control() ?? invalid : invalid; break; }
                        if (++failures >= limits.ConsecutiveFailures) { stop = "acquisition_retry_limit"; break; }
                        ScheduleRetry(); continue;
                    }
                    activation = checkedCandidate.Validation; ordinal = candidate.Attempt.ordinal;
                    attemptDirectory = Path.Combine(output, candidate.Attempt.directory);
                    if (live?.Write("acquisition_end", w =>
                    {
                        LiveFieldOutput.Property(w, "acquisition", candidate.Attempt);
                        w.WriteBoolean("prepared", true); w.WriteNumber("origin_segment", candidate.OriginSegment);
                        LiveFieldOutput.Property(w, "preparation_end_sha256", candidate.PreparationEndSha256);
                        LiveFieldOutput.Property(w, "activation", activation);
                    }) == false) { stop = live.Error!; break; }
                }
                else
                {
                    if (attempts.Count >= limits.Attempts) { stop = "acquisition_attempt_limit"; break; }
                    if (limits.ReadBytes - budget.Bytes <= 0 || limits.ReadCalls - budget.Calls <= 0) { stop = "session_read_limit"; break; }
                    if (limits.EvidenceBytes - evidenceBytes < 131072) { stop = "session_evidence_limit"; break; }
                    ordinal = attempts.Count + 1; string attemptName = "acquisition-" + ordinal.ToString("D4");
                    attemptDirectory = Path.Combine(output, attemptName); long started = Stopwatch.GetTimestamp();
                    activeOperation = "acquisition"; activeDirectory = attemptName; operationStart = started; Checkpoint();
                    if (live?.Write("acquisition_start", w =>
                    { w.WriteNumber("acquisition", ordinal); w.WriteNumber("start_ticks", started); w.WriteBoolean("observation_gap_open", true); w.WriteNumber("gap_start_ticks", gapStart); }) == false)
                    { stop = live.Error!; break; }
                    Acquisition.Result? acquisition = null; string? error = null;
                    try
                    {
                        acquisition = Acquisition.RunBounded(budget, module, recipe, attemptDirectory, runStop.Token, null,
                            new(Math.Min(Acquisition.MaximumReadBytes, limits.ReadBytes - budget.Bytes), limits.EvidenceBytes - evidenceBytes,
                                Math.Min(200000, limits.ReadCalls - budget.Calls)));
                    }
                    catch (ObservationException e) { error = e.Code; }
                    string acquisitionManifest = Path.Combine(attemptDirectory, "manifest.json");
                    if (File.Exists(acquisitionManifest))
                    {
                        using var saved = Metadata(acquisitionManifest); evidenceBytes += saved.RootElement.GetProperty("evidence_bytes").GetInt64();
                    }
                    attempts.Add(new(ordinal, attemptName, started, Stopwatch.GetTimestamp(), acquisition?.complete == true, error,
                        File.Exists(acquisitionManifest) ? FileHash(acquisitionManifest) : null, acquisition?.profile_sha256));
                    activeOperation = activeDirectory = null; operationStart = null; Checkpoint();
                    if (live?.Write("acquisition_end", w => LiveFieldOutput.Property(w, "acquisition", attempts[^1])) == false)
                    { stop = error is not null && IdentityStop(error) ? error : live.Error!; break; }
                    if (error is not null)
                    {
                        if (IdentityStop(error)) { stop = error; break; }
                        if (Control() is { } ended) { stop = ended; break; }
                        if (!Retryable(error)) { stop = error; break; }
                        if (++failures >= limits.ConsecutiveFailures) { stop = "acquisition_retry_limit"; break; }
                        ScheduleRetry(); continue;
                    }
                }
                failures = 0;
                if (Control() is { } afterAcquisition) { stop = afterAcquisition; break; }
                if (limits.ReadBytes - budget.Bytes <= 0 || limits.ReadCalls - budget.Calls <= 0) { stop = "session_read_limit"; break; }
                long remainingJson = limits.JsonBytes - jsonBytes, remainingCompressed = limits.CompressedBytes - compressedBytes, remainingIndex = limits.IndexBytes - indexBytes;
                if (remainingJson < 8192 || remainingCompressed < 65536 || remainingIndex < 4096) { stop = "session_output_limit"; break; }
                if (storage is not null && storageCohorts >= storage.MaximumCohorts) { stop = "storage_cohort_limit"; break; }
                string profilePath = Path.Combine(attemptDirectory, "profile.json");
                var profile = FieldStream.ParseProfileBytes(FieldStream.ValidatedProfileBytes(budget, profilePath));
                if (AdmitFields(coverage, profile.Fields, allowFieldShapeChanges, limits.Attempts * FieldStream.MaximumFields) is { } shapeError)
                { stop = shapeError; break; }
                int segmentNumber = segments.Count + 1; string segmentName = "segment-" + segmentNumber.ToString("D4");
                string? trigger = null; FieldStream.AcceptedFrame? triggerFrame = null;
                long? first = null, last = null, allUnknownSince = null; long frames = 0, unknown = 0, skipped = 0;
                using var segmentStop = CancellationTokenSource.CreateLinkedTokenSource(runStop.Token);
                long segmentStart = Stopwatch.GetTimestamp();
                void Frame(FieldStream.AcceptedFrame frame)
                {
                    if (first is null)
                    {
                        first = frame.Start; gaps.Add(new(gapStart, frame.Start, "No recorded frames between session/previous segment and this segment."));
                        live?.Write("gap", w => LiveFieldOutput.Property(w, "interval", gaps[^1]));
                    }
                    last = frame.End; frames++; skipped += frame.MissedSlots; int known = 0;
                    foreach (var item in frame.Fields)
                    { if (item.Value.status == "observed") { coverage[item.Key].observed++; known++; } else { coverage[item.Key].unknown++; unknown++; } }
                    if (known > 0) allUnknownSince = null; else allUnknownSince ??= frame.Start;
                    if (frame.Terminal is not null) trigger = frame.Terminal;
                    else if (frame.GuardInvalidated) trigger = "guard_invalidation";
                    else if (allUnknownSince is { } since && (frame.End - since) * 1000d / Stopwatch.Frequency >= limits.AllUnknownMilliseconds) trigger = "all_fields_unknown";
                    if (live?.Frame(segmentNumber, profile, frame) == false && (trigger is null || !IdentityStop(trigger))) trigger = live.Error!;
                    // The frame is already recorded and delivered. Rotate only after all
                    // terminal/guard/output decisions; session controls still win below.
                    if (backgroundPreparation && preparation?.Work.IsCompleted == true)
                    {
                        var completed = FinishPreparation(false);
                        if (completed.Attempt.complete) { ready = completed; failures = 0; }
                        else if (completed.Attempt.error is { } problem)
                        {
                            if (!Retryable(problem))
                            { if (trigger is null || !IdentityStop(trigger)) trigger = problem; }
                            else if (++failures >= limits.ConsecutiveFailures) trigger = "acquisition_retry_limit";
                            ScheduleRetry();
                        }
                    }
                    if (trigger is null && Control() is null)
                    {
                        if (ready is not null)
                        {
                            if (ready.OriginSegment == segmentNumber && ready.Attempt.profile_sha256 == profile.Hash)
                            {
                                long comparisonStart = Stopwatch.GetTimestamp();
                                try
                                {
                                    fixturePreparationStage?.Invoke(ready.Attempt.ordinal, "comparison");
                                    string candidateDirectory = Path.Combine(output, ready.Attempt.directory);
                                    if (PreparedManifestHash(Path.Combine(candidateDirectory, "manifest.json")) != ready.Attempt.manifest_sha256)
                                        throw new ObservationException("profile_identity_mismatch", "Prepared manifest changed before comparison.");
                                    byte[] bytes = FieldStream.ValidatedProfileBytes(budget, Path.Combine(candidateDirectory, "profile.json"));
                                    bool same = IdenticalPreparedBytes(profile.Raw, bytes, ready.Attempt.profile_sha256);
                                    long comparisonEnd = Stopwatch.GetTimestamp();
                                    // No fields are adopted and no source epoch is reset.
                                    // Current and future frames retain the original guards.
                                    if (same && Control() is null && live?.Error is null)
                                    {
                                        var noChange = new NoChange(ready.Attempt.ordinal, segmentNumber, ordinal,
                                            profile.Hash, ready.Attempt.manifest_sha256, ready.PreparationEndSha256,
                                            comparisonStart, comparisonEnd);
                                        unchanged.Add(noChange);
                                        if (live?.Write("preparation_no_change", w =>
                                        {
                                            w.WriteNumber("acquisition", noChange.acquisition); w.WriteNumber("origin_segment", noChange.origin_segment);
                                            w.WriteNumber("active_acquisition", noChange.active_acquisition); w.WriteString("profile_sha256", noChange.profile_sha256);
                                            LiveFieldOutput.Property(w, "manifest_sha256", noChange.manifest_sha256);
                                            LiveFieldOutput.Property(w, "preparation_end_sha256", noChange.preparation_end_sha256);
                                            w.WriteNumber("comparison_start_ticks", comparisonStart); w.WriteNumber("comparison_end_ticks", comparisonEnd);
                                            w.WriteBoolean("profile_adopted", false);
                                        }) == false) trigger = live.Error!;
                                        ready = null;
                                        prepareAfter = Stopwatch.GetTimestamp() + limits.ReacquireMilliseconds * Stopwatch.Frequency / 1000;
                                    }
                                }
                                catch (Exception e) when (e is not OutOfMemoryException)
                                {
                                    trigger = PreparationError(e);
                                    if (trigger != "cancelled" && !Retryable(trigger)) preparationFatal = trigger;
                                }
                            }
                            if (ready is not null && trigger is null && Control() is null) trigger = "prepared_reacquisition";
                        }
                        else if (limits.ReacquireMilliseconds > 0 &&
                            (frame.End - segmentStart) * 1000d / Stopwatch.Frequency >= limits.ReacquireMilliseconds && frame.End >= prepareAfter)
                        {
                            if (!backgroundPreparation) trigger = "periodic_reacquisition";
                            else if (preparation is null)
                            {
                                if (attempts.Count >= limits.Attempts) trigger = "acquisition_attempt_limit";
                                else if (limits.EvidenceBytes - evidenceBytes < 131072) trigger = "session_evidence_limit";
                                else if (budget.Bytes >= limits.ReadBytes || budget.Calls >= limits.ReadCalls) trigger = "session_read_limit";
                                else
                                {
                                    int next = attempts.Count + 1; long started = Stopwatch.GetTimestamp();
                                    if (live?.Write("preparation_start", w =>
                                    {
                                        w.WriteNumber("acquisition", next); w.WriteNumber("origin_segment", segmentNumber);
                                        w.WriteNumber("start_ticks", started); w.WriteBoolean("observation_gap_open", false);
                                    }) == false) trigger = live.Error!;
                                    else preparation = new Preparation(budget, module, recipe, output, next, segmentNumber, started,
                                        new(Math.Min(Acquisition.MaximumReadBytes, limits.ReadBytes - budget.Bytes), limits.EvidenceBytes - evidenceBytes,
                                            Math.Min(200000, limits.ReadCalls - budget.Calls)), runStop.Token, () => segmentStop.Cancel(), fixturePreparationStage);
                                }
                            }
                        }
                    }
                    if (trigger is not null) { triggerFrame = frame; segmentStop.Cancel(); }
                    fixtureFrame?.Invoke(segmentNumber, frame);
                }
                double remaining = (deadline - segmentStart) / (double)Stopwatch.Frequency;
                if (remaining <= 0) { stop = "duration_elapsed"; break; }
                activeOperation = "recording"; activeDirectory = segmentName; operationStart = segmentStart;
                Checkpoint();
                if (live?.Write("segment_start", w =>
                {
                    w.WriteNumber("segment", segmentNumber); w.WriteNumber("acquisition", ordinal); w.WriteString("profile_sha256", profile.Hash);
                    w.WriteString("source_stream_schema", profile.StreamSchema); w.WriteNumber("start_ticks", segmentStart);
                    if (activation is not null) w.WriteBoolean("prepared", true);
                    w.WritePropertyName("fields"); w.WriteStartArray();
                    foreach (var field in profile.Fields)
                    {
                        w.WriteStartObject(); w.WriteString("name", field.Name); w.WriteString("type", field.Type);
                        LiveFieldOutput.Property(w, "min", field.Min); LiveFieldOutput.Property(w, "max", field.Max);
                        if (field.Timer is { } timer) { w.WriteString("codec", TimerCodec.Name); w.WriteString("counter_scale_f32_hex", timer.ScaleHex); }
                        w.WriteEndObject();
                    }
                    w.WriteEndArray();
                }) == false) { stop = live.Error!; break; }
                var recording = JsonSerializer.SerializeToElement(FieldRecording.RecordBounded(budget, profilePath, Path.Combine(output, segmentName),
                    intervalMs, TimeSpan.FromSeconds(remaining), segmentStop.Token,
                    new(remainingJson, remainingCompressed, remainingIndex), Frame, limits.ReadBytes - budget.Bytes,
                    storage: storage is null ? null : storage with { MaximumCohorts = storage.MaximumCohorts - storageCohorts },
                    cohortSealed: seal =>
                    {
                        storageCohorts++;
                        if (live?.StorageSealed(segmentNumber, ordinal, profile.Hash, storageCohorts, seal) == false)
                            throw new ObservationException(live.Error!, "Storage seal notification could not be delivered.");
                    }));
                jsonBytes += recording.GetProperty("durable_json_bytes").GetInt64(); compressedBytes += recording.GetProperty("durable_compressed_bytes").GetInt64(); indexBytes += recording.GetProperty("index_bytes").GetInt64();
                if (storage is not null) indexBytes += recording.GetProperty("storage_index_bytes").GetInt64();
                string? recordingStop = recording.GetProperty("stop_reason").GetString(), failure = recording.GetProperty("failure").GetString();
                segments.Add(new(segmentNumber, ordinal, segmentName, profile.Hash, segmentStart, Stopwatch.GetTimestamp(), first, last,
                    frames, unknown, skipped, trigger ?? recordingStop ?? "recording_failed", triggerFrame?.Sequence, triggerFrame?.Start, triggerFrame?.End,
                    recordingStop, FileHash(Path.Combine(output, segmentName, "manifest.json"))));
                activeOperation = activeDirectory = null; operationStart = null;
                if (last is { } lastFrame) gapStart = lastFrame; Checkpoint();
                live?.Write("segment_end", w =>
                {
                    LiveFieldOutput.Property(w, "segment", segments[^1]);
                    w.WriteBoolean("terminal_summary_written", recording.GetProperty("terminal_summary_written").GetBoolean());
                    LiveFieldOutput.Property(w, "failure", failure);
                    w.WriteString("recording_state", "closed_manifest_available_not_independently_verified");
                });
                if (preparation is not null)
                {
                    var completed = FinishPreparation(failure is not null || Control() is not null || live?.Error is not null ||
                        (trigger is not null && trigger != "guard_invalidation"));
                    if (completed.Attempt.complete) ready = completed;
                    else if (completed.Attempt.error is { } problem)
                    {
                        if (!Retryable(problem))
                        { if (trigger is null || !IdentityStop(trigger)) trigger = problem == "cancelled" ? Control() ?? problem : problem; }
                        else
                        {
                            if (++failures >= limits.ConsecutiveFailures) trigger = "acquisition_retry_limit";
                            ScheduleRetry();
                        }
                    }
                }
                if (failure is not null) { stop = failure; break; }
                if (trigger is not null && IdentityStop(trigger)) { stop = trigger; break; }
                if (live?.Error is { } deliveryError) { stop = deliveryError; break; }
                if (preparationFatal is not null) { stop = preparationFatal; break; }
                if (Control() is { } endedRecording) { stop = endedRecording; break; }
                if (trigger is "guard_invalidation" or "periodic_reacquisition" or "prepared_reacquisition") continue;
                stop = trigger ?? recordingStop ?? "recording_failed"; break;
            }
            if (stop == "duration_elapsed" && (coverage.Count == 0 || coverage.Values.Any(f => f.observed == 0))) stop = "fields_never_observed";
        }
        catch (ObservationException e) { stop = e.Code; }
        catch (IOException) { stop = "output_io_error"; }
        catch (UnauthorizedAccessException) { stop = "output_permission_denied"; }
        catch (Exception e) when (backgroundPreparation && e is not OutOfMemoryException) { stop = PreparationError(e); }
        // Never dispose a shared read source or publish a terminal result while a
        // preparation worker is still alive. Native synchronous I/O itself is not cancellable.
        if (preparation is not null)
        {
            var completed = FinishPreparation(true);
            if (completed.Attempt.complete) ready = completed;
            else if (completed.Attempt.error is { } error && IdentityStop(error)) stop = error;
            else if (completed.Attempt.error is { } fault && fault != "cancelled" && !Retryable(fault) && !IdentityStop(stop)) stop = fault;
        }
        if (ready is not null)
        {
            long now = Stopwatch.GetTimestamp(); Discard(ready, stop, now, now); ready = null;
        }
        // Failed staging/publication artifacts remain private evidence; cleanup must not hide the terminal result.
        gaps.Add(new(gapStart, Stopwatch.GetTimestamp(), "No recorded frames after the last segment frame (or throughout a zero-frame session)."));
        live?.Write("gap", w => LiveFieldOutput.Property(w, "interval", gaps[^1]));
        if (live?.Error is { } finalDeliveryError && stop == "duration_elapsed") stop = finalDeliveryError;
        Result final = SaveFinal();
        if (live is not null)
        {
            bool sent = live.Write("session_end", w =>
            {
                LiveFieldOutput.Property(w, "result_before_this_write", final);
                w.WriteString("delivery", "This line is a final session snapshot before its own output write; live counters exclude this line. manifest_publication identifies whether this state was saved. A subsequent refresh failure emits session_finalization_error when the writer remains available. No downstream receipt is asserted.");
            }, final: true);
            if (!sent && stop == "duration_elapsed") stop = live.Error!;
            if (publicationError is null)
            {
                final = SaveFinal();
                if (publicationError is not null)
                {
                    live.Write("session_finalization_error", w =>
                    {
                        LiveFieldOutput.Property(w, "result_before_this_write", final);
                        w.WriteString("delivery", "The post-terminal manifest refresh failed. Any prior saved finished manifest excludes this failure and later live counters. Private partial files remain evidence; no downstream receipt is asserted.");
                    }, final: true);
                    final = Manifest("finished");
                }
            }
            else final = Manifest("finished");
        }
        return final;
    }
    // Validate the whole schema before adding names: rejected profiles never alter coverage.
    internal static string? AdmitFields(Dictionary<string, Coverage> coverage, FieldStream.Field[] fields,
        bool allowFieldShapeChanges, int maximumCoverageFields)
    {
        if (coverage.Count > 0 && !allowFieldShapeChanges &&
            (coverage.Count != fields.Length || fields.Any(f => !coverage.TryGetValue(f.Name, out var old) || old.type != f.Type)))
            return "field_shape_changed";
        if (fields.Any(f => coverage.TryGetValue(f.Name, out var old) && old.type != f.Type)) return "field_type_changed";
        int additions = fields.Count(f => !coverage.ContainsKey(f.Name));
        if (additions > maximumCoverageFields - coverage.Count) return "field_coverage_limit";
        foreach (var field in fields)
            if (!coverage.ContainsKey(field.Name)) coverage.Add(field.Name, new(field.Name, field.Type));
        return null;
    }
    private static int PublicRetryMilliseconds(int value) => value is >= 250 and <= 5000 ? value :
        throw new ObservationException("invalid_arguments", "Acquisition retry delay must be 250..5000 ms.");

    private static bool Retryable(string code) => code is "acquisition_guard_mismatch" or "acquisition_predicate_failed" or
        "acquisition_selection_not_unique" or "unreadable_range" or "partial_read";
    private static bool IdentityStop(string code) => code is "permission_denied" or "process_exited" or "identity_mismatch" or "module_identity_mismatch";
    private sealed class BudgetSource(IMemorySource source, TargetIdentity identity, CancellationToken token, Limits limits) : IMemorySource, IMemorySourceProvenance
    {
        private readonly object gate = new();
        private long calls, bytes;
        internal long Calls { get { lock (gate) return calls; } }
        internal long Bytes { get { lock (gate) return bytes; } }
        public bool IsNativeProcessMemory => MemorySourceProvenance.IsNative(source);
        public TargetIdentity Identity => source.Identity;
        public byte[] Read(ulong address, int size)
        {
            lock (gate)
            {
                if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Observation was cancelled.");
                if (calls >= limits.ReadCalls || size > limits.ReadBytes - bytes) throw new ObservationException("read_byte_limit", "Session read budget exhausted.");
                calls++; bytes += size; return source.Read(address, size);
            }
        }
        public void EnsureAlive()
        {
            lock (gate)
            {
                source.EnsureAlive(); if (source.Identity != identity) throw new ObservationException("identity_mismatch", "Observation target changed.");
                if (token.IsCancellationRequested) throw new ObservationException("cancelled", "Observation was cancelled.");
            }
        }
        internal void EnsureModule(Acquisition.Module module)
        {
            lock (gate)
            {
                EnsureAlive();
                if (source is NativeMemory native && Acquisition.MainModule(native) != module)
                    throw new ObservationException("module_identity_mismatch", "Main module changed before activation.");
            }
        }
        public IEnumerable<MemoryRegion> Regions() { lock (gate) return source.Regions().ToArray(); }
        public void Dispose() { }
    }
    private static JsonDocument Metadata(string path)
    {
        var info = new FileInfo(path); if (info.Length is < 1 or > 256 * 1024) throw new ObservationException("invalid_observation_metadata", "Generated metadata exceeds its bound.");
        return JsonDocument.Parse(File.ReadAllBytes(path));
    }
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string FileHash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static void WriteNew(string path, byte[] bytes) { using var f = new FileStream(path, FileMode.CreateNew, FileAccess.Write); f.Write(bytes); f.Flush(true); }
    internal static void WriteManifest(string directory, Result result, CancellationToken cancellation = default,
        Action<string, string, int>? fixtureMove = null)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(result); if (bytes.Length > 256 * 1024) throw new ObservationException("observation_manifest_limit", "Session metadata exceeds its bound.");
        string pending = Path.Combine(directory, ".manifest-" + Guid.NewGuid().ToString("N") + ".partial");
        WriteNew(pending, bytes);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                fixtureMove?.Invoke(pending, Path.Combine(directory, "manifest.json"), attempt);
                File.Move(pending, Path.Combine(directory, "manifest.json"), true); return;
            }
            catch (Exception e) when ((e is IOException or UnauthorizedAccessException) && IsManifestReplaceRetryable(e) && attempt < ManifestMoveAttempts)
            {
                // Owned output replacement can return access-denied while a reader denies delete sharing.
                // Code 5 alone does not establish locking; persistent denial still fails within this bound.
                if (cancellation.WaitHandle.WaitOne(ManifestRetryMilliseconds)) throw;
            }
        }
    }
    private static bool IsManifestReplaceRetryable(Exception error) =>
        error.HResult is unchecked((int)0x80070005) or unchecked((int)0x80070020) or unchecked((int)0x80070021);
}
