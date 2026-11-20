using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OverwatchDecoder.Observer;

/// <summary>Our own child process, never a claim of recovered game state.</summary>
public static class Fixture
{
    public const int Size = 64;
    public static readonly byte[] Magic = Encoding.ASCII.GetBytes("OWDWIN01");

    public static void Run(int seconds)
    {
        nint arena = Marshal.AllocHGlobal(Size);
        try
        {
            Marshal.Copy(new byte[Size], 0, arena, Size);
            Marshal.Copy(Magic, 0, arena, Magic.Length);
            Program.Emit("fixture_ready", new
            {
                label = "SYNTHETIC FIXTURE", pid = Environment.ProcessId,
                address = (ulong)arena, length = Size, decoder = "overwatch-decoder.windows-fixture/1"
            });
            Console.Out.Flush();
            var clock = Stopwatch.StartNew();
            long tick = 0;
            while (clock.Elapsed.TotalSeconds < seconds)
            {
                tick++;
                Marshal.WriteInt64(arena, 8, tick * 2 - 1);
                Marshal.WriteInt32(arena, 16, 100 - (int)(tick % 50));
                Marshal.WriteInt32(arena, 20, (int)(tick % 31));
                Marshal.WriteInt32(arena, 24, tick % 31 == 0 ? 1 : 0);
                Marshal.WriteInt64(arena, 32, tick);
                Thread.MemoryBarrier();
                Marshal.WriteInt64(arena, 8, tick * 2);
                Thread.Sleep(20);
            }
        }
        finally { Marshal.FreeHGlobal(arena); }
    }
}
