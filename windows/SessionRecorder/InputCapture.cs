using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

namespace OverwatchDecoder.SessionRecorder;

/// <summary>Read-only Raw Input. Create/start/stop/dispose on one UI thread with a message pump.</summary>
public sealed class InputCapture : NativeWindow, IDisposable
{
    private const int WmInput = 0x00ff;
    private readonly int targetProcessId, threadId = Environment.CurrentManagedThreadId;
    private readonly long? expectedStartUtcTicks;
    private SafeProcessHandle? selectedProcess;
    private readonly Action<object> emit;
    private readonly System.Windows.Forms.Timer focusTimer = new() { Interval = 50 };
    private readonly HashSet<int> held = [];
    private readonly byte[] packet = new byte[256];
    private IntPtr buffer;
    private bool running, disposed, focused;
    private long focusGainMilliseconds, dropped, pendingDrops;
    private readonly Dictionary<string, PendingDrop> pendingDropReasons = new(StringComparer.Ordinal);
    private sealed class PendingDrop(long ticks, object? context)
    {
        public long Count = 1, FirstTicks = ticks, LastTicks = ticks;
        public object? FirstContext = context, LastContext = context;
    }
    public long DroppedEvents => dropped;
    public string? Error { get; private set; }

    public InputCapture(int targetProcessId, Action<object> emit, long? expectedStartUtcTicks = null)
    {
        if (targetProcessId <= 0) throw new ArgumentOutOfRangeException(nameof(targetProcessId));
        this.targetProcessId = targetProcessId;
        this.expectedStartUtcTicks = expectedStartUtcTicks;
        this.emit = emit ?? throw new ArgumentNullException(nameof(emit));
        focusTimer.Tick += (_, _) => UpdateFocus();
    }

    public void Start()
    {
        CheckThread(); ObjectDisposedException.ThrowIf(disposed, this);
        if (running) return;
        selectedProcess = OpenProcess(0x00101000, false, targetProcessId); // SYNCHRONIZE | QUERY_LIMITED_INFORMATION only.
        if (selectedProcess.IsInvalid || !GetProcessTimes(selectedProcess, out long created, out _, out _, out _) ||
            WaitForSingleObject(selectedProcess, 0) != 258 ||
            expectedStartUtcTicks is long expected && DateTime.FromFileTimeUtc(created).Ticks != expected)
            throw new InvalidOperationException("The selected process lifetime changed before input capture.");
        CreateHandle(new CreateParams { Caption = "Overwatch Decoder Raw Input", Parent = new IntPtr(-3) });
        buffer = Marshal.AllocHGlobal(packet.Length);
        var devices = Devices(0x100, Handle); // INPUTSINK only: never NOLEGACY, hooks or injection.
        if (!RegisterRawInputDevices(devices, (uint)devices.Length, (uint)Marshal.SizeOf<RawInputDevice>()))
        {
            int code = Marshal.GetLastWin32Error(); ReleaseResources();
            Error = $"RegisterRawInputDevices failed ({code}).";
            Publish("input_error", new { operation = "register", native_error = code });
            throw new System.ComponentModel.Win32Exception(code, Error);
        }
        running = true;
        Publish("input_started", new { target_pid = targetProcessId, source = "win32_raw_input", focus_poll_ms = 50,
            timing = "message_processing_qpc; foreground checked at processing time", text_reconstructed = false });
        UpdateFocus(force: true); focusTimer.Start();
    }

    public void Stop()
    {
        CheckThread();
        if (!running) return;
        running = false; focusTimer.Stop();
        var devices = Devices(1, IntPtr.Zero); // REMOVE requires null hwnd.
        if (!RegisterRawInputDevices(devices, (uint)devices.Length, (uint)Marshal.SizeOf<RawInputDevice>()))
        {
            Error = $"Raw Input unregister failed ({Marshal.GetLastWin32Error()}).";
            Publish("input_error", new { operation = "unregister", message = Error });
        }
        Reset("stop"); ReleaseResources();
        Publish("input_stopped", new { dropped_events = dropped, error = Error });
    }

    protected override void WndProc(ref Message m)
    {
        try
        {
            if (m.Msg == WmInput && running) ReadInput(m.LParam);
        }
        catch (Exception e)
        {
            Error = e.GetType().Name + ": " + e.Message; Drop("read_exception", new { error_type = e.GetType().Name });
            Publish("input_error", new { operation = "read", message = Error });
        }
        finally
        {
            // DefWindowProc cleanup is required for foreground WM_INPUT.
            base.WndProc(ref m);
        }
    }

    private void ReadInput(IntPtr raw)
    {
        UpdateFocus();
        if (!focused) return; // Do not even decode background keys or mouse payloads.
        // Discard queued input across focus gain. Message time is uptime-ms (wrapping uint).
        uint messageTime = unchecked((uint)GetMessageTime());
        long receiptMilliseconds = Environment.TickCount64;
        uint age = unchecked((uint)receiptMilliseconds - messageTime);
        string? gateReason = GateRejectionReason(focused, receiptMilliseconds, focusGainMilliseconds, age);
        if (gateReason is not null)
        {
            Drop(gateReason, new { receipt_uptime_ms = receiptMilliseconds, focus_gain_observed_uptime_ms = focusGainMilliseconds,
                message_time_ms_u32 = messageTime, message_age_ms = age, settling_ms = 50, maximum_message_age_ms = 250 });
            return;
        }
        uint size = (uint)packet.Length, headerSize = (uint)(8 + 2 * IntPtr.Size);
        uint count = GetRawInputData(raw, 0x10000003, buffer, ref size, headerSize);
        if (count == uint.MaxValue || count > packet.Length || count < headerSize)
        {
            int nativeError = Marshal.GetLastWin32Error();
            Drop("raw_input_unreadable", new { native_error = nativeError, returned_bytes = count, header_bytes = headerSize });
            Publish("input_error", new { operation = "GetRawInputData", native_error = nativeError }); return;
        }
        Marshal.Copy(buffer, packet, 0, (int)count);
        // Foreground can change during the native read: check again before publishing payload.
        UpdateFocus(); if (!focused) return;
        var decoded = DecodePacket(packet.AsSpan(0, (int)count), (int)headerSize);
        if (decoded is null) { Drop("raw_packet_unsupported_or_invalid", new { returned_bytes = count, header_bytes = headerSize }); return; }
        if (decoded.Type == 1)
        {
            if (decoded.VirtualKey == 255) return; // documented fake keyboard packet
            int key = decoded.ScanCode | (decoded.Flags & 6) << 16;
            bool up = (decoded.Flags & 1) != 0;
            bool repeat = !up && !held.Add(key); if (up) held.Remove(key);
            Publish("keyboard", new { scan_code = decoded.ScanCode, virtual_key = decoded.VirtualKey,
                is_up = up, is_down = !up, repeat, e0 = (decoded.Flags & 2) != 0, e1 = (decoded.Flags & 4) != 0,
                foreground_target = true, target_pid = targetProcessId,
                message_time_ms_u32 = messageTime, message_age_ms = age, receipt_uptime_ms = receiptMilliseconds,
                focus_gain_observed_uptime_ms = focusGainMilliseconds });
        }
        else
            Publish("mouse", new { dx = decoded.X, dy = decoded.Y, absolute = (decoded.Flags & 1) != 0,
                virtual_desktop = (decoded.Flags & 2) != 0, button_flags = decoded.ButtonFlags,
                wheel = (decoded.ButtonFlags & 0x400) != 0 ? decoded.ButtonData : 0,
                horizontal_wheel = (decoded.ButtonFlags & 0x800) != 0 ? decoded.ButtonData : 0,
                foreground_target = true, target_pid = targetProcessId,
                message_time_ms_u32 = messageTime, message_age_ms = age, receipt_uptime_ms = receiptMilliseconds,
                focus_gain_observed_uptime_ms = focusGainMilliseconds });
    }

    // Require inferred message uptime >= observed focus gain + settling interval. This is
    // receipt-time gating, not proof of which window was foreground when hardware input occurred.
    internal static bool CanProcess(bool foregroundTarget, long nowMilliseconds, long gainedMilliseconds, uint messageAge)
        => GateRejectionReason(foregroundTarget, nowMilliseconds, gainedMilliseconds, messageAge) is null;

    // Same gate and boundaries; only the refusal evidence is more specific. No raw
    // key/mouse payload is read when a focus/timestamp condition rejects a packet.
    internal static string? GateRejectionReason(bool foregroundTarget, long nowMilliseconds, long gainedMilliseconds, uint messageAge)
    {
        if (!foregroundTarget) return "not_foreground";
        if (messageAge > 250) return "message_age_exceeded";
        if (nowMilliseconds < gainedMilliseconds) return "focus_time_order_unknown";
        long elapsed = nowMilliseconds - gainedMilliseconds;
        if (elapsed < 50) return "focus_settling";
        return elapsed < 50L + messageAge ? "message_predates_focus_settling_boundary" : null;
    }

    internal sealed record RawEvent(uint Type, ushort Flags, ushort ScanCode = 0, ushort VirtualKey = 0,
        ushort ButtonFlags = 0, short ButtonData = 0, int X = 0, int Y = 0);
    internal static RawEvent? DecodePacket(ReadOnlySpan<byte> bytes, int headerSize)
    {
        if (headerSize is not (16 or 24) || bytes.Length < headerSize) return null;
        uint type = BinaryPrimitives.ReadUInt32LittleEndian(bytes), declared = BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]);
        if (declared != bytes.Length) return null;
        var b = bytes[headerSize..];
        if (type == 1 && b.Length >= 16) return new(type, BinaryPrimitives.ReadUInt16LittleEndian(b[2..]),
            BinaryPrimitives.ReadUInt16LittleEndian(b), BinaryPrimitives.ReadUInt16LittleEndian(b[6..]));
        if (type == 0 && b.Length >= 24) return new(type, BinaryPrimitives.ReadUInt16LittleEndian(b),
            ButtonFlags: BinaryPrimitives.ReadUInt16LittleEndian(b[4..]), ButtonData: BinaryPrimitives.ReadInt16LittleEndian(b[6..]),
            X: BinaryPrimitives.ReadInt32LittleEndian(b[12..]), Y: BinaryPrimitives.ReadInt32LittleEndian(b[16..]));
        return null;
    }

    private void UpdateFocus(bool force = false)
    {
        if (!running) return;
        GetWindowThreadProcessId(GetForegroundWindow(), out uint pid);
        bool now = pid == targetProcessId && selectedProcess is { IsInvalid: false, IsClosed: false } && WaitForSingleObject(selectedProcess, 0) == 258;
        if (!force && now == focused) return;
        focused = now;
        if (now) { focusGainMilliseconds = Environment.TickCount64; Reset("focus_gain"); }
        else Reset("focus_loss");
        Publish("focus", new { target_pid = targetProcessId, foreground_target = focused });
    }
    private void Reset(string reason) { held.Clear(); Publish("input_reset", new { reason }); }
    private void Drop(string reason, object? context = null)
    {
        dropped++; pendingDrops++;
        long ticks = Stopwatch.GetTimestamp();
        if (pendingDropReasons.TryGetValue(reason, out var entry)) { entry.Count++; entry.LastTicks = ticks; entry.LastContext = context; }
        else pendingDropReasons.Add(reason, new PendingDrop(ticks, context));
    }
    private void Publish(string kind, object payload)
    {
        try
        {
            if (pendingDrops != 0)
            {
                long count = pendingDrops;
                // Fixed call-site reasons bound this ledger. Snapshot before enqueue:
                // a failed emission retains the original loss plus callback failure.
                var reasons = pendingDropReasons.Select(pair => new { reason = pair.Key, count = pair.Value.Count,
                    first_drop_qpc_ticks = pair.Value.FirstTicks, last_drop_qpc_ticks = pair.Value.LastTicks,
                    first_context = pair.Value.FirstContext, last_context = pair.Value.LastContext }).ToArray();
                emit(new { kind = "input_dropped", qpc_ticks = Stopwatch.GetTimestamp(), qpc_frequency = Stopwatch.Frequency,
                    count, total = dropped, reason = reasons.Length == 1 ? reasons[0].reason : "multiple_reasons", reasons,
                    timing = "Top-level QPC is notification time; each reason records actual discard QPC. Focus gating is receipt-time policy, not proof of hardware-time focus." });
                pendingDrops -= count; pendingDropReasons.Clear();
            }
            emit(new { kind, qpc_ticks = Stopwatch.GetTimestamp(), qpc_frequency = Stopwatch.Frequency, data = payload });
        }
        catch { Drop("emit_callback_failure", new { event_kind = kind }); } // Caller must enqueue only; no user callback may escape WndProc.
    }
    private void CheckThread() { if (Environment.CurrentManagedThreadId != threadId) throw new InvalidOperationException("InputCapture requires its creating UI thread."); }
    private void ReleaseResources()
    {
        if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); buffer = IntPtr.Zero; }
        if (Handle != IntPtr.Zero) DestroyHandle();
        selectedProcess?.Dispose(); selectedProcess = null;
    }
    public void Dispose() { CheckThread(); if (disposed) return; Stop(); focusTimer.Dispose(); ReleaseResources(); disposed = true; GC.SuppressFinalize(this); }
    private static RawInputDevice[] Devices(uint flags, IntPtr hwnd) => [new(1, 2, flags, hwnd), new(1, 6, flags, hwnd)];
    [StructLayout(LayoutKind.Sequential)] private readonly struct RawInputDevice(ushort page, ushort usage, uint flags, IntPtr hwnd)
    { public readonly ushort Page = page, Usage = usage; public readonly uint Flags = flags; public readonly IntPtr Hwnd = hwnd; }
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool RegisterRawInputDevices(RawInputDevice[] devices, uint count, uint size);
    [DllImport("user32.dll", SetLastError = true)] private static extern uint GetRawInputData(IntPtr raw, uint command, IntPtr data, ref uint size, uint headerSize);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] private static extern int GetMessageTime();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
}
