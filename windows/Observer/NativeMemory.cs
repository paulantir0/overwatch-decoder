using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace OverwatchDecoder.Observer;

public sealed class ObservationException(string code, string message, int? nativeCode = null)
    : Exception(message)
{
    public string Code { get; } = code;
    public int? NativeCode { get; } = nativeCode;
}

public record MemoryRegion(ulong Address, ulong Length, uint State, uint Protection, uint Type)
{
    public bool Readable => State == 0x1000 && (Protection & 0x100) == 0 &&
        (Protection & 0xff) is 0x02 or 0x04 or 0x08 or 0x20 or 0x40 or 0x80;
    public bool Contains(ulong address, int length) => length > 0 && address >= Address &&
        (ulong)length <= Length && address - Address <= Length - (ulong)length;
}

public record TargetIdentity(int Pid, string ImageName, string ImagePath, long CreationFileTime,
    string ExecutableSha256, string Architecture);

public interface IMemorySource : IDisposable
{
    TargetIdentity Identity { get; }
    IEnumerable<MemoryRegion> Regions();
    byte[] Read(ulong address, int size);
    void EnsureAlive();
}

// Internal adapters can preserve the identity of a native backing source without
// allowing arbitrary public IMemorySource implementations to assert that provenance.
internal interface IMemorySourceProvenance
{
    bool IsNativeProcessMemory { get; }
}
internal static class MemorySourceProvenance
{
    internal static bool IsNative(IMemorySource source) => source is NativeMemory ||
        source is IMemorySourceProvenance { IsNativeProcessMemory: true };
    internal static string Kind(IMemorySource source) => IsNative(source) ? "native_process_memory" : "provided_memory_source";
}

/// <summary>Only documented query/read APIs. No debug privilege, writes or attachment.</summary>
public sealed class NativeMemory : IMemorySource, INativeReadCalls
{
    public const int MaxRead = 1024 * 1024;
    private const uint Access = 0x0400 | 0x0010; // QUERY_INFORMATION | VM_READ
    private readonly SafeProcessHandle handle;
    public TargetIdentity Identity { get; }

    [StructLayout(LayoutKind.Explicit, Size = 48)]
    private struct Mbi
    {
        [FieldOffset(0)] public ulong BaseAddress;
        [FieldOffset(8)] public ulong AllocationBase;
        [FieldOffset(16)] public uint AllocationProtect;
        [FieldOffset(24)] public ulong RegionSize;
        [FieldOffset(32)] public uint State;
        [FieldOffset(36)] public uint Protect;
        [FieldOffset(40)] public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(SafeProcessHandle process, nint address,
        [Out] byte[] buffer, nuint size, out nuint read);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nuint VirtualQueryEx(SafeProcessHandle process, nint address,
        out Mbi information, nuint length);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags,
        StringBuilder path, ref uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation,
        out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process2(SafeProcessHandle process, out ushort processMachine,
        out ushort nativeMachine);

    private static ObservationException NativeError(string operation)
    {
        int code = Marshal.GetLastWin32Error();
        return new(code == 5 ? "permission_denied" : "native_error",
            operation + " failed: " + new Win32Exception(code).Message, code);
    }

    public NativeMemory(int pid)
    {
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
            throw new ObservationException("unsupported_platform", "Requires 64-bit Windows.");
        if (pid <= 0) throw new ObservationException("invalid_pid", "PID must be positive.");
        handle = OpenProcess(Access, false, pid);
        if (handle.IsInvalid) { var e = NativeError("OpenProcess"); handle.Dispose(); throw e; }
        try
        {
            if (!GetProcessTimes(handle, out long created, out _, out _, out _))
                throw NativeError("GetProcessTimes");
            var path = new StringBuilder(32768); uint count = (uint)path.Capacity;
            if (!QueryFullProcessImageName(handle, 0, path, ref count))
                throw NativeError("QueryFullProcessImageName");
            if (!IsWow64Process2(handle, out ushort processMachine, out ushort nativeMachine))
                throw NativeError("IsWow64Process2");
            if (processMachine != 0 || nativeMachine != 0x8664)
                throw new ObservationException("unsupported_architecture", "This reader requires a native x64 target.");
            using var file = new FileStream(path.ToString(), FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            string digest = Convert.ToHexStringLower(SHA256.HashData(file));
            Identity = new(pid, Path.GetFileName(path.ToString()), path.ToString(), created, digest, "x64");
            EnsureAlive();
        }
        catch { handle.Dispose(); throw; }
    }

    public void EnsureAlive()
    {
        if (handle.IsClosed) throw new ObjectDisposedException(nameof(NativeMemory));
        if (!GetExitCodeProcess(handle, out uint code)) throw NativeError("GetExitCodeProcess");
        if (code != 259) throw new ObservationException("process_exited", "Target process has exited.");
        // The open handle continues to identify this process even if its numeric PID is reused.
        if (!GetProcessTimes(handle, out long created, out long exited, out _, out _) ||
            created != Identity.CreationFileTime)
            throw new ObservationException("identity_mismatch", "Target creation identity could not be verified.");
        if (exited != 0) throw new ObservationException("process_exited", "Target process has exited.");
    }

    public MemoryRegion Query(ulong address)
    {
        EnsureAlive();
        return QueryCore(address);
    }

    MemoryRegion INativeReadCalls.QueryRegion(ulong address) => QueryCore(address);
    private MemoryRegion QueryCore(ulong address)
    {
        if (address > long.MaxValue) throw new ObservationException("invalid_address", "Address is out of range.");
        nuint size = VirtualQueryEx(handle, (nint)address, out Mbi info, 48);
        if (size != 48) throw NativeError("VirtualQueryEx");
        if (info.RegionSize == 0 || info.BaseAddress > ulong.MaxValue - info.RegionSize)
            throw new ObservationException("invalid_region", "Invalid region range returned by Windows.");
        return new(info.BaseAddress, info.RegionSize, info.State, info.Protect, info.Type);
    }

    public IEnumerable<MemoryRegion> Regions()
    {
        ulong address = 0;
        for (int count = 0; count < 1_000_000; count++)
        {
            MemoryRegion region;
            try { region = Query(address); }
            catch (ObservationException e) when (e.NativeCode == 87 && address > 0)
            { EnsureAlive(); yield break; } // End of the application's address space.
            ulong next = checked(region.Address + region.Length);
            if (next <= address) throw new ObservationException("invalid_region", "Memory map did not advance.");
            yield return region;
            address = next;
        }
        throw new ObservationException("region_limit", "Memory map exceeded its bounded region count.");
    }

    public byte[] Read(ulong address, int size) => NativeReadSetup.Read(this, address, size);

    int INativeReadCalls.ReadBytes(ulong address, byte[] buffer)
    {
        if (!ReadProcessMemory(handle, (nint)address, buffer, (nuint)buffer.Length, out nuint read))
            throw NativeError("ReadProcessMemory");
        return checked((int)read);
    }

    public void Dispose() => handle.Dispose();

    public static int Resolve(string? processName, int? pid)
    {
        if (pid.HasValue && processName is not null)
            throw new ObservationException("invalid_arguments", "Choose either --pid or --process.");
        if (pid.HasValue) return pid.Value;
        if (string.IsNullOrWhiteSpace(processName))
            throw new ObservationException("invalid_arguments", "Supply --pid or --process.");
        var matches = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));
        try
        {
            if (matches.Length == 0) throw new ObservationException("process_not_found", "Requested process is not running.");
            if (matches.Length != 1) throw new ObservationException("ambiguous_process", "More than one process matches; specify --pid.");
            return matches[0].Id;
        }
        finally { foreach (var p in matches) p.Dispose(); }
    }
}
