using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace OverwatchDecoder.Observer;

/// <summary>A per-recording timer. No process priority or global timer-resolution changes.</summary>
internal sealed class PreciseWait : IDisposable
{
    internal const int MaximumChunkMs = 100;
    private const int NativeWaitTimeoutMs = 200;
    private readonly CancellationToken cancellation;
    private readonly WaitHandle cancellationSignal;
    private IOneShotTimer? timer;
    private WaitHandle[]? signals;
    private bool disposed;
    private readonly string initialBackend;
    private string? fallbackReason;
    private int? fallbackNativeCode;
    private long? fallbackTicks;
    private long nativeWaits, managedWaits;

    internal interface IOneShotTimer : IDisposable
    {
        WaitHandle Signal { get; }
        void Arm(long relativeDueTime100ns);
        void Cancel();
    }

    private sealed class NativeTimer : WaitHandle, IOneShotTimer
    {
        public NativeTimer(SafeWaitHandle handle) { SafeWaitHandle = handle; }
        public WaitHandle Signal => this;
        public void Arm(long relativeDueTime100ns)
        {
            if (!SetWaitableTimer(SafeWaitHandle, in relativeDueTime100ns, 0, nint.Zero, nint.Zero, false))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public void Cancel()
        {
            if (!CancelWaitableTimer(SafeWaitHandle)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateWaitableTimerExW", ExactSpelling = true, SetLastError = true)]
    private static extern SafeWaitHandle CreateWaitableTimerEx(nint attributes, nint name, uint flags, uint access);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWaitableTimer(SafeWaitHandle timer, in long dueTime, int period,
        nint completionRoutine, nint completionArgument, [MarshalAs(UnmanagedType.Bool)] bool resume);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelWaitableTimer(SafeWaitHandle timer);

    public static PreciseWait Create(CancellationToken cancellation)
    {
        if (!OperatingSystem.IsWindows()) return new(cancellation, null, "not_windows");
        try
        {
            // Unnamed/non-inheritable, auto-reset timer; SYNCHRONIZE | TIMER_MODIFY_STATE only.
            SafeWaitHandle handle = CreateWaitableTimerEx(nint.Zero, nint.Zero, 0x00000002, 0x00100002);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                return new(cancellation, null, "create_waitable_timer_failed", error);
            }
            var native = new NativeTimer(handle);
            try { return new(cancellation, native); }
            catch { native.Dispose(); throw; }
        }
        catch (Exception e) when (e is EntryPointNotFoundException or DllNotFoundException or PlatformNotSupportedException)
        { return new(cancellation, null, "timer_api_unavailable"); }
    }

    // Injection keeps failure, cancellation and cleanup tests independent of Windows or realtime latency.
    internal PreciseWait(CancellationToken cancellation, IOneShotTimer? timer,
        string? fallbackReason = null, int? fallbackNativeCode = null)
    {
        this.cancellation = cancellation;
        cancellationSignal = cancellation.WaitHandle; // Owned by the caller's token source, never disposed here.
        this.timer = timer;
        if (timer is not null) signals = [cancellationSignal, timer.Signal];
        this.fallbackReason = fallbackReason;
        this.fallbackNativeCode = fallbackNativeCode;
        if (fallbackReason is not null) fallbackTicks = Stopwatch.GetTimestamp();
        initialBackend = Backend;
    }

    internal string Backend => timer is null ? "managed_wait_handle" : "windows_high_resolution_waitable_timer";

    internal object Diagnostics() => new
    {
        initial_backend = initialBackend, backend = Backend,
        fallback_reason = fallbackReason, fallback_native_code = fallbackNativeCode, fallback_at_ticks = fallbackTicks,
        high_resolution_waits = nativeWaits, managed_waits = managedWaits,
        maximum_wait_chunk_ms = MaximumChunkMs, native_wait_timeout_ms = NativeWaitTimeoutMs,
        global_timer_resolution_changed = false, hard_realtime = false
    };

    internal void WaitUntil(long targetTicks)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        while (!cancellation.IsCancellationRequested)
        {
            long remaining = targetTicks - Stopwatch.GetTimestamp();
            if (remaining <= 0) return;
            if (timer is not null)
            {
                try
                {
                    timer.Arm(RelativeDueTime100ns(remaining, Stopwatch.Frequency));
                    nativeWaits++;
                    // Event-driven wakeup; the timeout is a bounded malfunction guard, not the sampling clock.
                    int signalled = WaitHandle.WaitAny(signals!, NativeWaitTimeoutMs);
                    if (signalled == 0)
                    {
                        StopTimer();
                        return;
                    }
                    if (signalled == WaitHandle.WaitTimeout) UseFallback("timer_wait_timeout", null);
                    continue; // Recheck Stopwatch even if a timer signalled early.
                }
                catch (Win32Exception e) { UseFallback("timer_operation_failed", e.NativeErrorCode); }
            }
            // Non-Windows or a reported native failure. Cancellation still wakes this wait immediately.
            remaining = targetTicks - Stopwatch.GetTimestamp();
            if (remaining <= 0 || cancellation.IsCancellationRequested) return;
            int milliseconds = (int)Math.Clamp(Math.Ceiling(remaining * 1000d / Stopwatch.Frequency), 1, MaximumChunkMs);
            managedWaits++;
            if (cancellationSignal.WaitOne(milliseconds)) return;
        }
    }

    internal static long RelativeDueTime100ns(long remainingTicks, long frequency)
    {
        if (remainingTicks <= 0 || frequency <= 0) throw new ArgumentOutOfRangeException(nameof(remainingTicks));
        // Round up to avoid knowingly waking early. Int128 avoids overflow for a distant target.
        Int128 units = ((Int128)remainingTicks * 10_000_000 + frequency - 1) / frequency;
        return -(long)Int128.Clamp(units, 1, MaximumChunkMs * 10_000);
    }

    private void UseFallback(string reason, int? nativeCode)
    {
        fallbackReason = reason; fallbackNativeCode = nativeCode; fallbackTicks = Stopwatch.GetTimestamp();
        StopTimer();
        timer?.Dispose(); timer = null; signals = null;
    }

    private void StopTimer()
    {
        try { timer?.Cancel(); }
        catch (Win32Exception) { /* Closing our owned handle below also releases the timer. */ }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        StopTimer();
        timer?.Dispose(); timer = null; signals = null;
    }
}
