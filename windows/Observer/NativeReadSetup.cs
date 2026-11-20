namespace OverwatchDecoder.Observer;

// Small seam for deterministic setup-call tests. Each query and read remains a
// real independent OS operation in NativeMemory; no map/data/lifetime cache.
internal interface INativeReadCalls
{
    void EnsureAlive();
    MemoryRegion QueryRegion(ulong address);
    int ReadBytes(ulong address, byte[] buffer);
}

internal static class NativeReadSetup
{
    internal static byte[] Read(INativeReadCalls source, ulong address, int size)
    {
        if (size <= 0 || size > NativeMemory.MaxRead)
            throw new ObservationException("invalid_read_size", "Read size must be between 1 and 1048576 bytes.");
        byte[] buffer;
        try
        {
            // The retained process handle cannot refer to a replacement PID.
            // Query fresh protection/range for EVERY read. Only the redundant
            // pre-query liveness check moves to success/failure admission below.
            MemoryRegion region = source.QueryRegion(address);
            if (!region.Readable || !region.Contains(address, size))
                throw new ObservationException("unreadable_range", "Read crosses a region boundary or touches an unreadable/guard page.");
            buffer = new byte[size];
            if (source.ReadBytes(address, buffer) != size)
                throw new ObservationException("partial_read", "Windows returned an incomplete read.");
        }
        catch
        {
            // A dead process may first fail Query/RPM. Preserve the same terminal
            // identity/lifetime classification before returning an OS read error.
            // Bytes never escape a failed post-read lifetime check.
            source.EnsureAlive();
            throw;
        }
        source.EnsureAlive();
        return buffer;
    }
}
